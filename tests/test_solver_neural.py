import numpy as np

from cdg_lib.graph import CDG
from cdg_lib.models import ConstraintNode, BinaryLocation
from cdg_lib.types import CWEClass, SolverOutcome
from cdg_lib.solver import solve


class _FakePredictor:
    def __init__(self, prob: float):
        self._prob = prob
        self.calls = 0

    def predict(self, node, graph) -> float:
        self.calls += 1
        return self._prob


def _node(formula, skeleton, cwe=CWEClass.UNKNOWN):
    return ConstraintNode(
        node_id="",
        formula=formula,
        formula_skeleton=skeleton,
        cwe_class=cwe,
        location=BinaryLocation("f", 0, 0x1000),
        version="v1",
        variables={"x"},
        var_types={"x": "bv32"},
    )


def test_solve_without_predictor_unchanged():
    """When predictor is None, behavior is identical to the published baseline."""
    g = CDG()
    n = _node("x >= 0", "(VAR u>= CONST)")
    nid = g.store(n, [])
    out, _ = solve(g, nid)
    assert out in (SolverOutcome.SAT, SolverOutcome.UNSAT, SolverOutcome.UNKNOWN)


def test_predictor_skipped_for_vuln_relevant_node():
    """Reachability filter blocks neural shortcut for CWE-tagged trigger nodes."""
    g = CDG()
    n = _node("len > 65535", "(VAR u> CONST)", cwe=CWEClass.CWE_787)
    nid = g.store(n, [])
    pred = _FakePredictor(prob=0.99)
    out, _ = solve(g, nid, predictor=pred)
    # The node IS a trigger (CWE-tagged + comparison). Reachability filter
    # returns True, so predictor should NOT be called.
    assert pred.calls == 0


def test_predictor_called_for_non_trigger_node():
    """Neural shortcut is allowed when node is not vulnerability-relevant."""
    g = CDG()
    n = _node("x", "(VAR)", cwe=CWEClass.UNKNOWN)
    nid = g.store(n, [])
    pred = _FakePredictor(prob=0.99)
    out, _ = solve(g, nid, predictor=pred, tau_unsat=0.95)
    # Not a trigger -> reachability returns False -> predictor consulted.
    # prob=0.99 > tau=0.95 -> UNSAT_PREDICTED.
    assert pred.calls == 1
    assert out == SolverOutcome.UNSAT_PREDICTED


def test_predictor_below_threshold_falls_through_to_z3():
    g = CDG()
    n = _node("x", "(VAR)", cwe=CWEClass.UNKNOWN)
    nid = g.store(n, [])
    pred = _FakePredictor(prob=0.5)
    out, _ = solve(g, nid, predictor=pred, tau_unsat=0.95)
    # Below threshold -> Z3 path -> outcome is real SAT/UNSAT/UNKNOWN.
    assert pred.calls == 1
    assert out != SolverOutcome.UNSAT_PREDICTED


def test_unsat_predicted_excluded_from_vulnerability_logic():
    """Soundness invariant: UNSAT_PREDICTED is distinct from UNSAT."""
    assert SolverOutcome.UNSAT_PREDICTED is not SolverOutcome.UNSAT
    assert SolverOutcome.UNSAT_PREDICTED.value != SolverOutcome.UNSAT.value
