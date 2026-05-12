"""
CDG Z3 User Propagator: injects graph knowledge into Z3's CDCL(T) search loop.

solve_with_propagator(graph, node_ids, timeout_ms) -> Dict[str, (SolverOutcome, model)]

This module is a thin facade re-exporting from backends.z3_propagator.
"""

from typing import Optional, Dict, List, Tuple

from cdg_lib.types import SolverOutcome, EdgeLabel
from cdg_lib.backends.z3_propagator import (
    CDGPropagator,
    Z3PropagatorBackend,
)
from cdg_lib.solver import solve as solve_single, _extract_conflicts

# Re-export CDGPropagator so existing imports work
__all__ = ["CDGPropagator", "solve_with_propagator"]


def solve_with_propagator(
    graph,
    node_ids: List[str],
    timeout_ms: int = 10000,
) -> Dict[str, Tuple[SolverOutcome, Optional[Dict]]]:
    """
    Solve multiple constraints in one Z3 session using CDG propagator.

    Phases:
      1. Pre-filter: cache hits resolved without Z3
      2. Batch solve: remaining nodes in one Z3 session with propagator
      3. Harvest: extract per-node results from Z3 model + propagator
      4. UNSAT fallback: if batch UNSAT, fall back to individual solve()
      5. Post-solve: create CON edges for UNSAT nodes

    Returns: Dict[node_id -> (SolverOutcome, model)]
    """
    backend = Z3PropagatorBackend()
    results = backend.solve_batch_with_graph(
        graph, node_ids, solve_single, timeout_ms
    )

    # Phase 5: Post-solve -- create CON edges for UNSAT nodes
    for node_id, (outcome, _) in results.items():
        if outcome == SolverOutcome.UNSAT:
            _extract_conflicts(graph, node_id)

    return results
