from cdg_lib.graph import CDG
from cdg_lib.models import ConstraintNode, BinaryLocation
from cdg_lib.types import CWEClass, EdgeLabel
from cdg_lib.neural.reachability import reachable_to_vuln, has_trigger_pattern


def _node(formula, skeleton, cwe=CWEClass.UNKNOWN, node_id=""):
    return ConstraintNode(
        node_id=node_id,
        formula=formula,
        formula_skeleton=skeleton,
        cwe_class=cwe,
        location=BinaryLocation("f", 0, 0x1000),
        version="v1",
    )


def test_has_trigger_pattern_true_for_cwe787_with_inequality():
    n = _node("len > 65535", "(VAR > CONST)", CWEClass.CWE_787)
    assert has_trigger_pattern(n) is True


def test_has_trigger_pattern_false_for_unknown_cwe():
    n = _node("len > 65535", "(VAR > CONST)", CWEClass.UNKNOWN)
    assert has_trigger_pattern(n) is False


def test_has_trigger_pattern_false_for_equality_only():
    n = _node("x == 0", "(VAR == CONST)", CWEClass.CWE_787)
    assert has_trigger_pattern(n) is False


def test_isolated_node_with_trigger_is_reachable():
    g = CDG()
    n = _node("len > 65535", "(VAR > CONST)", CWEClass.CWE_787)
    nid = g.store(n, [])
    assert reachable_to_vuln(g.nodes[nid], g) is True


def test_isolated_node_without_trigger_is_not_reachable():
    g = CDG()
    n = _node("ip_len >= 20", "(VAR >= CONST)", CWEClass.UNKNOWN)
    nid = g.store(n, [])
    assert reachable_to_vuln(g.nodes[nid], g) is False


def test_reaches_through_dep_edge():
    g = CDG()
    a = _node("ip_len >= 20", "(VAR >= CONST)", CWEClass.UNKNOWN)
    a_id = g.store(a, [])
    b = _node("len > 65535", "(VAR > CONST)", CWEClass.CWE_787)
    g.store(b, dep_sources=[a_id])
    # a -> b via DEP. Walk from a's outgoing should reach b.
    assert reachable_to_vuln(g.nodes[a_id], g) is True


def test_does_not_reach_through_con_edge():
    """CON edges are not vuln-relevant traversals."""
    g = CDG()
    a = _node("x", "(VAR)", CWEClass.UNKNOWN)
    a_id = g.store(a, [])
    b = _node("len > 65535", "(VAR > CONST)", CWEClass.CWE_787)
    b_id = g.store(b, [])
    g._add_edge(a_id, b_id, EdgeLabel.CON)
    # Only DEP/SIM edges count; CON should NOT be a path.
    assert reachable_to_vuln(g.nodes[a_id], g) is False


def test_handles_cycles():
    g = CDG()
    a = _node("x", "(VAR)", CWEClass.UNKNOWN)
    a_id = g.store(a, [])
    b = _node("y", "(VAR)", CWEClass.UNKNOWN)
    b_id = g.store(b, dep_sources=[a_id])
    g._add_edge(b_id, a_id, EdgeLabel.DEP)  # cycle
    # No trigger anywhere — must return False without infinite loop
    assert reachable_to_vuln(g.nodes[a_id], g) is False
