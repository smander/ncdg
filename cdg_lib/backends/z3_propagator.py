"""
Z3 Propagator Backend: CDG-aware theory propagator inside Z3's CDCL(T) loop.

Moved from propagator.py: CDGPropagator (real + stub), _extract_node_model,
_solve_individually_after_batch_unsat. Adds Z3PropagatorBackend wrapper.
"""

import hashlib
from typing import Callable, Dict, List, Optional, Set, Tuple

try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False

from cdg_lib.types import SolverOutcome, EdgeLabel
from cdg_lib.backends.base import SolverBackend, SolverCapability
from cdg_lib.backends.z3_native import parse_constraint, make_z3_vars


# ---------------------------------------------------------------------------
# CDGPropagator -- Z3 UserPropagateBase subclass
# ---------------------------------------------------------------------------

if HAS_Z3:
    class CDGPropagator(z3.UserPropagateBase):
        """
        Custom Z3 theory propagator that injects CDG graph shortcuts
        (cache, subsumption, conflict pruning) into the CDCL(T) loop.
        """

        def __init__(self, solver=None, ctx=None, *, graph=None, node_ids=None):
            super().__init__(solver, ctx)
            self._graph = graph
            self._node_ids = node_ids or []

            # activation var -> node_id mapping
            self._act_to_node: Dict[str, str] = {}
            # node_id -> activation z3 var
            self._node_to_act: Dict[str, z3.ExprRef] = {}

            # Determined during propagation: node_id -> (outcome, model_dict)
            self._determined: Dict[str, Tuple[SolverOutcome, Optional[Dict]]] = {}
            # Set of node_ids where conflict() was called
            self._conflicted: Set[str] = set()
            # Set of node_ids propagated via SIM in _on_final
            self._propagated: Set[str] = set()

            # Trail for push/pop
            self._trail: List[Tuple[Dict, Set, Set]] = []

            # Dampening: track assignment hashes to prevent infinite _on_final
            self._seen_assignment_hashes: Set[str] = set()

        def register_expressions(self, z3_solver) -> Dict[str, z3.ExprRef]:
            """
            Register activation variables and conditional assertions.

            Returns mapping: node_id -> activation_var.
            """
            if self._graph is None:
                return {}

            # Shared variable pool across all nodes
            shared_vars: Dict[str, z3.ExprRef] = {}
            activation_vars: Dict[str, z3.ExprRef] = {}

            for node_id in self._node_ids:
                node = self._graph.nodes[node_id]
                act_var = z3.Bool(f"node_active_{node_id}")
                activation_vars[node_id] = act_var
                self._act_to_node[str(act_var)] = node_id
                self._node_to_act[node_id] = act_var

                # Register the activation variable with the propagator
                self.add(act_var)

                # Build shared Z3 variables
                z3_vars = {}
                for var_name in node.variables:
                    if var_name not in shared_vars:
                        var_type = node.var_types.get(var_name, "bv16")
                        if var_type == "bv32":
                            shared_vars[var_name] = z3.BitVec(var_name, 32)
                        elif var_type == "bv64":
                            shared_vars[var_name] = z3.BitVec(var_name, 64)
                        else:
                            shared_vars[var_name] = z3.BitVec(var_name, 16)
                    z3_vars[var_name] = shared_vars[var_name]

                # Parse constraint and add conditional assertion
                constraint = parse_constraint(node.formula, z3_vars)
                if constraint is not None:
                    z3_solver.add(z3.Implies(act_var, constraint))

            return activation_vars

        # ---- Trail callbacks ----

        def push(self):
            """Snapshot state for backtracking."""
            self._trail.append((
                dict(self._determined),
                set(self._conflicted),
                set(self._propagated),
            ))

        def pop(self, num_scopes):
            """Restore state on backtrack."""
            for _ in range(num_scopes):
                if self._trail:
                    self._determined, self._conflicted, self._propagated = self._trail.pop()

        def fresh(self, ctx):
            """Clone propagator for parallel Z3 contexts."""
            p = CDGPropagator(ctx=ctx, graph=self._graph, node_ids=self._node_ids)
            return p

        # ---- Fixed callback ----

        def fixed(self, expr, value):
            """Called when Z3 fixes a registered expression to a value."""
            self._on_fixed(expr, value)

        def _on_fixed(self, expr, value):
            """CDG shortcuts when an activation variable is assigned."""
            expr_str = str(expr)
            node_id = self._act_to_node.get(expr_str)
            if node_id is None:
                return

            # Only act when the activation variable is set to True
            if not z3.is_true(value):
                return

            node = self._graph.nodes[node_id]

            # Shortcut 1: Cache lookup
            cache_key = node.formula
            if cache_key in self._graph._solve_cache:
                outcome, model = self._graph._solve_cache[cache_key]
                self._determined[node_id] = (outcome, model)
                return

            # Shortcut 2: Subsumption -- SIM neighbor SAT + matching skeleton
            for edge in self._graph._radj.get(node_id, []):
                if edge.label == EdgeLabel.SIM:
                    other = self._graph.nodes[edge.source_id]
                    if other.outcome == SolverOutcome.SAT and other.model:
                        if other.skeleton_hash == node.skeleton_hash:
                            self._determined[node_id] = (SolverOutcome.SAT, other.model)
                            return

            # Shortcut 3: Conflict pruning -- CON edge + both activated
            for edge in self._graph._adj.get(node_id, []):
                if edge.label == EdgeLabel.CON:
                    other_id = edge.target_id
                    if other_id in self._node_to_act:
                        other_act = self._node_to_act[other_id]
                        # If the other node is also activated, conflict
                        if other_id not in self._conflicted:
                            act_var = self._node_to_act[node_id]
                            self.conflict([act_var, other_act])
                            self._conflicted.add(node_id)
                            return

        # ---- Equality callback ----

        def eq(self, x, y):
            """Called when two registered expressions become equal."""
            self._on_eq(x, y)

        def _on_eq(self, x, y):
            """Placeholder for future cross-variable reasoning."""
            pass

        # ---- Final callback ----

        def final(self):
            """Called when Z3 reaches a full assignment -- cross-constraint propagation."""
            self._on_final()

        def _on_final(self):
            """SIM propagation at full assignment with dampening."""
            assignment_hash = self._compute_assignment_hash()
            if assignment_hash in self._seen_assignment_hashes:
                return
            self._seen_assignment_hashes.add(assignment_hash)

            # Propagate SAT from determined nodes to SIM neighbors
            newly_propagated = []
            for node_id, (outcome, model) in list(self._determined.items()):
                if outcome != SolverOutcome.SAT:
                    continue
                for edge in self._graph._adj.get(node_id, []):
                    if edge.label == EdgeLabel.SIM:
                        target_id = edge.target_id
                        if (target_id in self._node_ids
                                and target_id not in self._determined
                                and target_id not in self._propagated):
                            target_node = self._graph.nodes[target_id]
                            source_node = self._graph.nodes[node_id]
                            if target_node.skeleton_hash == source_node.skeleton_hash:
                                self._determined[target_id] = (SolverOutcome.SAT, model)
                                self._propagated.add(target_id)
                                newly_propagated.append(target_id)

        def _compute_assignment_hash(self) -> str:
            """Hash current determined + conflicted state for dampening."""
            parts = sorted(self._determined.keys()) + sorted(self._conflicted)
            return hashlib.md5("|".join(parts).encode()).hexdigest()

else:
    # Stub when z3 is unavailable
    class CDGPropagator:
        """Stub propagator when Z3 is not installed."""

        def __init__(self, solver=None, ctx=None, *, graph=None, node_ids=None):
            self._graph = graph
            self._node_ids = node_ids or []
            self._determined = {}
            self._conflicted = set()
            self._propagated = set()
            self._trail = []
            self._seen_assignment_hashes = set()
            self._act_to_node = {}
            self._node_to_act = {}

        def register_expressions(self, z3_solver):
            return {}

        def push(self):
            self._trail.append((
                dict(self._determined),
                set(self._conflicted),
                set(self._propagated),
            ))

        def pop(self, num_scopes):
            for _ in range(num_scopes):
                if self._trail:
                    self._determined, self._conflicted, self._propagated = self._trail.pop()

        def fresh(self, ctx=None):
            p = CDGPropagator(graph=self._graph, node_ids=self._node_ids)
            return p

        def _on_fixed(self, expr, value):
            pass

        def _on_eq(self, x, y):
            pass

        def _on_final(self):
            pass

        def _compute_assignment_hash(self):
            parts = sorted(self._determined.keys()) + sorted(self._conflicted)
            return hashlib.md5("|".join(parts).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _extract_node_model(node, z3_model) -> Optional[Dict]:
    """Extract variable values for a specific node from the Z3 model."""
    if not HAS_Z3:
        return None
    model_dict = {}
    for decl in z3_model.decls():
        var_name = str(decl)
        if var_name in node.variables:
            val = z3_model[decl]
            model_dict[var_name] = val.as_long() if hasattr(val, 'as_long') else str(val)

    # If node has variables but none appeared in the model,
    # return the full model (Z3 may have assigned default values)
    if not model_dict and node.variables:
        for decl in z3_model.decls():
            val = z3_model[decl]
            model_dict[str(decl)] = val.as_long() if hasattr(val, 'as_long') else str(val)

    return model_dict if model_dict else None


def _solve_individually_after_batch_unsat(
    graph,
    node_ids: List[str],
    single_node_solver: Callable,
) -> Dict[str, Tuple[SolverOutcome, Optional[Dict]]]:
    """Fallback: solve each node individually after batch UNSAT."""
    results = {}
    for node_id in node_ids:
        outcome, model = single_node_solver(graph, node_id)
        results[node_id] = (outcome, model)
    return results


# ---------------------------------------------------------------------------
# Z3PropagatorBackend
# ---------------------------------------------------------------------------

class Z3PropagatorBackend(SolverBackend):
    """
    Backend wrapping CDGPropagator for batch solving with graph awareness.

    Provides CUSTOM_PROPAGATION and BATCH_SOLVE capabilities beyond the
    basic Z3NativeBackend.
    """

    def capabilities(self) -> SolverCapability:
        return (
            SolverCapability.CHECK_SAT
            | SolverCapability.GET_MODEL
            | SolverCapability.PUSH_POP
            | SolverCapability.CUSTOM_PROPAGATION
            | SolverCapability.BATCH_SOLVE
        )

    def solve_node(
        self,
        formula: str,
        variables: set,
        var_types: Dict[str, str],
        timeout_ms: int = 5000,
    ) -> Tuple[SolverOutcome, Optional[Dict]]:
        """Single-node solve delegates to Z3 native path."""
        if not HAS_Z3:
            return SolverOutcome.UNKNOWN, None
        try:
            solver = z3.Solver()
            solver.set("timeout", timeout_ms)
            z3_vars = make_z3_vars(variables, var_types)
            constraint = parse_constraint(formula.strip(), z3_vars)
            if constraint is not None:
                solver.add(constraint)
            result = solver.check()
            if result == z3.sat:
                m = solver.model()
                model_dict = {
                    str(d): m[d].as_long() if hasattr(m[d], 'as_long') else str(m[d])
                    for d in m.decls()
                }
                return SolverOutcome.SAT, model_dict
            elif result == z3.unsat:
                return SolverOutcome.UNSAT, None
            else:
                return SolverOutcome.TIMEOUT, None
        except Exception:
            return SolverOutcome.UNKNOWN, None

    def solve_batch_with_graph(
        self,
        graph,
        node_ids: List[str],
        single_node_solver: Callable,
        timeout_ms: int = 10000,
    ) -> Dict[str, Tuple[SolverOutcome, Optional[Dict]]]:
        """
        Solve multiple constraints in one Z3 session using CDGPropagator.

        Args:
            graph: CDG instance with nodes and edges
            node_ids: List of node IDs to solve
            single_node_solver: Callable(graph, node_id) -> (outcome, model)
                for individual fallback (breaks circular dependency with solver.py)
            timeout_ms: Solver timeout

        Returns: {node_id: (SolverOutcome, model_dict)}
        """
        results: Dict[str, Tuple[SolverOutcome, Optional[Dict]]] = {}

        # Phase 1: Pre-filter -- resolve cache hits without Z3
        remaining = []
        for node_id in node_ids:
            node = graph.nodes[node_id]
            cache_key = node.formula
            if cache_key in graph._solve_cache:
                outcome, model = graph._solve_cache[cache_key]
                results[node_id] = (outcome, model)
                node.outcome = outcome
                node.model = model
            else:
                remaining.append(node_id)

        if not remaining:
            return results

        # Phase 2: Batch solve with propagator
        if not HAS_Z3:
            for node_id in remaining:
                outcome, model = single_node_solver(graph, node_id)
                results[node_id] = (outcome, model)
            return results

        z3_solver = z3.Solver()
        z3_solver.set(unsat_core=True)
        z3_solver.set("timeout", timeout_ms)

        propagator = CDGPropagator(z3_solver, graph=graph, node_ids=remaining)
        activation_vars = propagator.register_expressions(z3_solver)

        # Track assumptions instead of asserting them permanently
        assumptions = []
        for node_id in remaining:
            if node_id in activation_vars:
                assumptions.append(activation_vars[node_id])

        result = z3_solver.check(*assumptions)

        # Phase 4 (Optimized): UNSAT fallback with core extraction
        while result == z3.unsat:
            core = z3_solver.unsat_core()
            
            if not core:
                results.update(_solve_individually_after_batch_unsat(graph, remaining, single_node_solver))
                remaining.clear()
                break
                
            core_nids = []
            for c in core:
                nid = propagator._act_to_node.get(str(c))
                if nid:
                    core_nids.append(nid)
                    
            if not core_nids:
                results.update(_solve_individually_after_batch_unsat(graph, remaining, single_node_solver))
                remaining.clear()
                break
                
            # Solve only the conflicting nodes individually
            results.update(_solve_individually_after_batch_unsat(graph, core_nids, single_node_solver))
            
            # Remove conflicting nodes from the active batch
            for nid in core_nids:
                if nid in remaining:
                    remaining.remove(nid)
                    if nid in activation_vars and activation_vars[nid] in assumptions:
                        assumptions.remove(activation_vars[nid])
                        
            if not remaining:
                break
                
            # Re-check the surviving batch
            result = z3_solver.check(*assumptions)

        # Phase 3: Harvest results
        if result == z3.sat:
            z3_model = z3_solver.model()
            for node_id in remaining:
                if node_id in propagator._determined:
                    outcome, model = propagator._determined[node_id]
                    results[node_id] = (outcome, model)
                else:
                    model_dict = _extract_node_model(graph.nodes[node_id], z3_model)
                    results[node_id] = (SolverOutcome.SAT, model_dict)
        elif result == z3.unsat:
            if remaining:
                results.update(_solve_individually_after_batch_unsat(graph, remaining, single_node_solver))
        else:
            # Timeout/unknown -- also fall back
            for node_id in remaining:
                if node_id in propagator._determined:
                    results[node_id] = propagator._determined[node_id]
                else:
                    results[node_id] = (SolverOutcome.TIMEOUT, None)

        # Apply results to graph nodes and cache
        for node_id, (outcome, model) in results.items():
            node = graph.nodes[node_id]
            node.outcome = outcome
            node.model = model
            graph._solve_cache[node.formula] = (outcome, model)

        return results
