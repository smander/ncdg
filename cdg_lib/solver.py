"""
CDG Solver: graph-accelerated constraint solving with pluggable backends.

solve(graph, node_id, backend=None) -> (outcome, model)

The solver implements graph shortcuts (cache, subsumption, conflict pruning)
that are solver-agnostic, then delegates the actual SMT call to a backend.
"""

from typing import Optional, Dict, Tuple

from cdg_lib.types import SolverOutcome, EdgeLabel
from cdg_lib.backends import get_backend, SolverBackend


# Module-level default backend (lazy-initialized)
_default_backend: Optional[SolverBackend] = None


def set_backend(backend: SolverBackend):
    """Set the global default solver backend."""
    global _default_backend
    _default_backend = backend


def _get_backend(backend: Optional[SolverBackend] = None) -> SolverBackend:
    """Return the provided backend or the global default (auto-detected)."""
    if backend is not None:
        return backend
    global _default_backend
    if _default_backend is None:
        _default_backend = get_backend("auto")
    return _default_backend


def solve(
    graph,
    node_id: str,
    backend: Optional[SolverBackend] = None,
    predictor=None,
    tau_unsat: float = 0.95,
    con_policy: Optional[str] = None,
    path_source: str = "i",
    path_condition: Optional[list] = None,
) -> Tuple[SolverOutcome, Optional[Dict]]:
    """
    Solve the constraint at node_id with graph-accelerated shortcuts.

    Shortcuts (in order):
      1. Cache lookup (exact formula match)
      2. Subsumption shortcut (Z3-verified SAT reuse, byte-equal formula)
      3. Conflict pruning (con_policy: None | 'a' | 'b' | 'c')
      4. Reachability-gated neural UNSAT predictor (when predictor passed)
      5. Backend solve call (Z3)

    Conflict pruning policies:
      'a' - path-aware: prune if any CON-predecessor lies on the resolved path
            and has outcome UNSAT. Sound.
      'b' - any-UNSAT DEP predecessor. UNSOUND; ablation only.
      'c' - cached UNSAT lookup: prune if any CON-predecessor has byte-equal
            formula and outcome UNSAT. Sound.

    path_source resolves the path when con_policy='a':
      'i'   DEP-derived BFS (default)
      'ii'  caller-supplied path_condition; raises if None
      'iii' caller-supplied if present, else DEP-derived
    """
    node = graph.nodes[node_id]

    # Shortcut 1: Cache lookup
    cache_key = node.formula
    if cache_key in graph._solve_cache:
        outcome, model = graph._solve_cache[cache_key]
        node.outcome = outcome
        node.model = model
        return outcome, model

    # Shortcut 2: Subsumption -- accept a SIM-neighbour's SAT verdict ONLY
    # when the formulas are equivalent up to variable renaming. The paper's
    # tightened Property 2 requires this: skeleton-hash equality alone admits
    # cases like `x > 0xFFFE` (SAT on bv16) and `x > 0xFFFF` (UNSAT on bv16),
    # which share `VAR > CONST` but differ in the constant. We test full
    # syntactic equality on the formula string -- a sound subset of "equal
    # up to renaming" that suffices for cached witnesses produced by the
    # solver, where variable names are stable across calls on the same
    # graph.
    for edge in graph._radj.get(node_id, []):
        if edge.label == EdgeLabel.SIM:
            other = graph.nodes[edge.source_id]
            if other.outcome == SolverOutcome.SAT and other.model:
                if other.formula == node.formula:
                    node.outcome = SolverOutcome.SAT
                    node.model = other.model
                    graph._solve_cache[cache_key] = (SolverOutcome.SAT, other.model)
                    return SolverOutcome.SAT, other.model

    # Shortcut 3: Conflict pruning (policy-driven)
    if con_policy is not None:
        prune_outcome = _try_conflict_prune(
            graph, node_id, con_policy, path_source, path_condition
        )
        if prune_outcome is not None:
            node.outcome = prune_outcome
            # Do NOT add to _solve_cache -- pruned verdicts are not
            # Z3-verified outcomes (parallels UNSAT_PREDICTED handling).
            return prune_outcome, None

    # Shortcut 4: NEW -- reachability-gated neural UNSAT predictor
    if predictor is not None:
        from cdg_lib.neural.reachability import reachable_to_vuln
        if not reachable_to_vuln(node, graph):
            # Not vulnerability-relevant -> neural may short-circuit.
            try:
                p_unsat = predictor.predict(node, graph)
            except Exception:
                p_unsat = 0.0
            if p_unsat > tau_unsat:
                node.outcome = SolverOutcome.UNSAT_PREDICTED
                # Do NOT add to _solve_cache -- Z3-verified outcomes only.
                return SolverOutcome.UNSAT_PREDICTED, None
        # else: vuln-relevant -> fall through to Z3 (mandatory)

    # Shortcut 5: Backend (Z3) solve call
    be = _get_backend(backend)
    outcome, model = be.solve_node(
        node.formula, node.variables, node.var_types
    )
    node.outcome = outcome
    node.model = model
    graph._solve_cache[cache_key] = (outcome, model)

    # If UNSAT, extract core and add conflict edges
    if outcome == SolverOutcome.UNSAT:
        _extract_conflicts(graph, node_id)

    return outcome, model


def _try_conflict_prune(
    graph,
    node_id: str,
    policy: str,
    path_source: str,
    path_condition,
) -> Optional[SolverOutcome]:
    """Apply the requested conflict-pruning policy.

    Returns SolverOutcome.UNSAT_BY_CONFLICT if the policy fires, else None.
    Never queries Z3.
    """
    from cdg_lib.path_resolver import resolve_path

    node = graph.nodes[node_id]

    if policy == "c":
        # Byte-equal UNSAT cache via incoming CON edges.
        for edge in graph._radj.get(node_id, []):
            if edge.label != EdgeLabel.CON:
                continue
            src = graph.nodes[edge.source_id]
            if src.outcome == SolverOutcome.UNSAT and src.formula == node.formula:
                return SolverOutcome.UNSAT_BY_CONFLICT
        return None

    if policy == "b":
        # Any transitive DEP-ancestor that is UNSAT -- unsound, ablation only.
        # "Predecessor" is read as "ancestor on the DEP chain" so this matches
        # policy (a)'s path semantics and the paper's prose; the unsoundness
        # is the policy itself, not the traversal depth.
        for ancestor_id in resolve_path(graph, node_id, "i", None):
            if graph.nodes[ancestor_id].outcome == SolverOutcome.UNSAT:
                return SolverOutcome.UNSAT_BY_CONFLICT
        return None

    if policy == "a":
        path = resolve_path(graph, node_id, path_source, path_condition)
        path_set = set(path)
        for edge in graph._radj.get(node_id, []):
            if edge.label != EdgeLabel.CON:
                continue
            src_id = edge.source_id
            if src_id not in path_set:
                continue
            src = graph.nodes[src_id]
            if src.outcome == SolverOutcome.UNSAT:
                return SolverOutcome.UNSAT_BY_CONFLICT
        return None

    raise ValueError(f"Unknown con_policy: {policy!r}")


def _extract_conflicts(graph, node_id: str):
    """After UNSAT, add conflict edges from each DEP-predecessor to the UNSAT node.

    Paper Definition 2: $(c_i, c_j, \\text{CON})$ means $c_j$ is UNSAT and
    $c_i$ is its DEP-predecessor (edge direction: predecessor -> UNSAT).
    """
    for edge in graph._radj.get(node_id, []):
        if edge.label == EdgeLabel.DEP:
            graph._add_edge(edge.source_id, node_id, EdgeLabel.CON)
