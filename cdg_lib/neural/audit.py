"""Soundness audit for the NS-CDG solver.

For every node marked UNSAT_PREDICTED, run Z3 directly and verify it agrees.
Returns the list of disagreements. Zero disagreements is the publishable
soundness claim for the paper.
"""

from dataclasses import dataclass
from typing import List

from cdg_lib.types import SolverOutcome
from cdg_lib.backends import get_backend


@dataclass
class AuditDisagreement:
    node_id: str
    formula: str
    predicted_verdict: SolverOutcome
    z3_verdict: SolverOutcome


def audit_soundness(graph) -> List[AuditDisagreement]:
    """Run Z3 on every UNSAT_PREDICTED node; return any disagreements."""
    backend = get_backend("auto")
    out: List[AuditDisagreement] = []
    for node_id, node in graph.nodes.items():
        if node.outcome != SolverOutcome.UNSAT_PREDICTED:
            continue
        try:
            z3_verdict, _ = backend.solve_node(
                node.formula, node.variables, node.var_types
            )
        except Exception:
            z3_verdict = SolverOutcome.UNKNOWN
        if z3_verdict != SolverOutcome.UNSAT:
            out.append(AuditDisagreement(
                node_id=node_id,
                formula=node.formula,
                predicted_verdict=node.outcome,
                z3_verdict=z3_verdict,
            ))
    return out
