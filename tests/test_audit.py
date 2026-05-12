from cdg_lib.graph import CDG
from cdg_lib.models import ConstraintNode, BinaryLocation
from cdg_lib.types import CWEClass, SolverOutcome
from cdg_lib.neural.audit import audit_soundness, AuditDisagreement


def _node(formula, skeleton, outcome=SolverOutcome.UNKNOWN, cwe=CWEClass.UNKNOWN,
          var_types=None):
    n = ConstraintNode(
        node_id="",
        formula=formula,
        formula_skeleton=skeleton,
        cwe_class=cwe,
        location=BinaryLocation("f", 0, 0x1000),
        version="v1",
        outcome=outcome,
        variables=set(var_types or {}),
        var_types=dict(var_types or {}),
    )
    return n


def test_audit_returns_empty_when_no_predicted_nodes():
    g = CDG()
    n = _node("x", "(VAR)", outcome=SolverOutcome.SAT)
    g.store(n, [])
    diss = audit_soundness(g)
    assert diss == []


def test_audit_flags_predicted_unsat_that_is_actually_sat():
    """If neural predicted UNSAT but Z3 says SAT, flag it."""
    g = CDG()
    # `x >= 0` over bv32 is always SAT; if marked UNSAT_PREDICTED, that's a
    # soundness violation.
    n = _node("x >= 0", "(VAR u>= CONST)",
              outcome=SolverOutcome.UNSAT_PREDICTED,
              var_types={"x": "bv32"})
    g.store(n, [])
    diss = audit_soundness(g)
    assert len(diss) == 1
    assert isinstance(diss[0], AuditDisagreement)
    assert diss[0].z3_verdict == SolverOutcome.SAT
    assert diss[0].predicted_verdict == SolverOutcome.UNSAT_PREDICTED


def test_audit_passes_when_predicted_unsat_is_truly_unsat():
    """If neural predicted UNSAT and Z3 agrees, no disagreement.

    Backend uses unsigned bitvector comparisons; bv16 max value is 65535,
    so `len > 65535` over bv16 is UNSAT.

    Note: var_types defaults to bv16 in the backend's parse_constraint —
    we explicitly pass bv16 here to be unambiguous.
    """
    g = CDG()
    # Use bv16 explicitly; backend's parser also defaults to bv16.
    n = _node("len > 65535", "(VAR u> CONST)",
              outcome=SolverOutcome.UNSAT_PREDICTED,
              var_types={"len": "bv16"})
    g.store(n, [])
    diss = audit_soundness(g)
    assert len(diss) == 0


def test_audit_audit_disagreement_dataclass_has_node_id():
    g = CDG()
    n = _node("x >= 0", "(VAR u>= CONST)",
              outcome=SolverOutcome.UNSAT_PREDICTED,
              var_types={"x": "bv32"})
    nid = g.store(n, [])
    diss = audit_soundness(g)
    assert diss[0].node_id == nid
