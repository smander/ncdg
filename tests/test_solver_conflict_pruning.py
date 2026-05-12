from cdg_lib.graph import CDG
from cdg_lib.models import ConstraintNode, BinaryLocation
from cdg_lib.types import CWEClass, EdgeLabel, SolverOutcome
from cdg_lib.solver import solve


def _node(node_id, formula):
    return ConstraintNode(
        node_id=node_id,
        formula=formula,
        formula_skeleton="VAR > CONST",
        cwe_class=CWEClass.UNKNOWN,
        location=BinaryLocation("f", 0, 0),
        version="v1",
    )


def test_policy_c_returns_unsat_by_conflict_on_byte_equal_match():
    g = CDG()
    # a: pre-declared UNSAT with a CON edge to b
    a_id = g.store(_node("a", "(x > 0) and (x < 0)"))
    b_id = g.store(_node("b", "(x > 0) and (x < 0)"))
    g.nodes[a_id].outcome = SolverOutcome.UNSAT
    g._add_edge(a_id, b_id, EdgeLabel.CON)

    outcome, model = solve(g, b_id, con_policy="c")
    assert outcome == SolverOutcome.UNSAT_BY_CONFLICT
    assert model is None


def test_policy_c_does_not_fire_when_formula_differs():
    g = CDG()
    a_id = g.store(_node("a", "(x > 0) and (x < 0)"))
    b_id = g.store(_node("b", "(y > 5) and (y < 5)"))
    g.nodes[a_id].outcome = SolverOutcome.UNSAT
    g._add_edge(a_id, b_id, EdgeLabel.CON)

    outcome, _ = solve(g, b_id, con_policy="c")
    # Falls through to Z3 (or whichever backend), should not be UNSAT_BY_CONFLICT
    assert outcome != SolverOutcome.UNSAT_BY_CONFLICT


def test_policy_b_fires_when_dep_predecessor_unsat():
    g = CDG()
    a_id = g.store(_node("a", "(x > 0) and (x < 0)"))
    b_id = g.store(_node("b", "y == 1"), dep_sources=[a_id])
    g.nodes[a_id].outcome = SolverOutcome.UNSAT

    outcome, _ = solve(g, b_id, con_policy="b")
    assert outcome == SolverOutcome.UNSAT_BY_CONFLICT


def test_policy_b_ignores_path_source():
    g = CDG()
    a_id = g.store(_node("a", "false"))
    b_id = g.store(_node("b", "true"), dep_sources=[a_id])
    g.nodes[a_id].outcome = SolverOutcome.UNSAT

    o1, _ = solve(g, b_id, con_policy="b", path_source="i")
    o2, _ = solve(g, b_id, con_policy="b", path_source="ii", path_condition=[])
    o3, _ = solve(g, b_id, con_policy="b", path_source="iii")
    assert o1 == o2 == o3 == SolverOutcome.UNSAT_BY_CONFLICT


def test_policy_b_does_not_fire_without_unsat_predecessor():
    g = CDG()
    a_id = g.store(_node("a", "x == 1"))
    b_id = g.store(_node("b", "y == 1"), dep_sources=[a_id])
    g.nodes[a_id].outcome = SolverOutcome.SAT

    outcome, _ = solve(g, b_id, con_policy="b")
    assert outcome != SolverOutcome.UNSAT_BY_CONFLICT


def test_policy_a_i_fires_when_con_pred_on_dep_path():
    g = CDG()
    a_id = g.store(_node("a", "(x > 0) and (x < 0)"))
    b_id = g.store(_node("b", "y == 1"), dep_sources=[a_id])
    g.nodes[a_id].outcome = SolverOutcome.UNSAT
    g._add_edge(a_id, b_id, EdgeLabel.CON)

    outcome, _ = solve(g, b_id, con_policy="a", path_source="i")
    assert outcome == SolverOutcome.UNSAT_BY_CONFLICT


def test_policy_a_i_does_not_fire_when_con_pred_not_on_path():
    g = CDG()
    # 'a' has a CON edge to 'b' but 'a' is NOT a DEP-ancestor of 'b'
    a_id = g.store(_node("a", "(x > 0) and (x < 0)"))
    b_id = g.store(_node("b", "y == 1"))  # no dep_sources
    g.nodes[a_id].outcome = SolverOutcome.UNSAT
    g._add_edge(a_id, b_id, EdgeLabel.CON)

    outcome, _ = solve(g, b_id, con_policy="a", path_source="i")
    assert outcome != SolverOutcome.UNSAT_BY_CONFLICT


def test_policy_a_ii_uses_explicit_path():
    g = CDG()
    a_id = g.store(_node("a", "(x > 0) and (x < 0)"))
    b_id = g.store(_node("b", "y == 1"))  # no DEP edges
    g.nodes[a_id].outcome = SolverOutcome.UNSAT
    g._add_edge(a_id, b_id, EdgeLabel.CON)

    outcome, _ = solve(
        g, b_id, con_policy="a", path_source="ii", path_condition=[a_id]
    )
    assert outcome == SolverOutcome.UNSAT_BY_CONFLICT


def test_policy_a_ii_raises_without_path():
    import pytest
    g = CDG()
    a_id = g.store(_node("a", "false"))
    with pytest.raises(ValueError, match="path_source='ii'"):
        solve(g, a_id, con_policy="a", path_source="ii")


def test_policy_a_iii_explicit_wins_over_dep():
    g = CDG()
    a_id = g.store(_node("a", "(x > 0) and (x < 0)"))
    b_id = g.store(_node("b", "y == 1"))  # no DEP edges
    g.nodes[a_id].outcome = SolverOutcome.UNSAT
    g._add_edge(a_id, b_id, EdgeLabel.CON)

    outcome, _ = solve(
        g, b_id, con_policy="a", path_source="iii", path_condition=[a_id]
    )
    assert outcome == SolverOutcome.UNSAT_BY_CONFLICT


def test_policy_a_iii_falls_back_to_dep():
    g = CDG()
    a_id = g.store(_node("a", "(x > 0) and (x < 0)"))
    b_id = g.store(_node("b", "y == 1"), dep_sources=[a_id])
    g.nodes[a_id].outcome = SolverOutcome.UNSAT
    g._add_edge(a_id, b_id, EdgeLabel.CON)

    outcome, _ = solve(g, b_id, con_policy="a", path_source="iii")
    assert outcome == SolverOutcome.UNSAT_BY_CONFLICT
