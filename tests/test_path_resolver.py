import pytest
from cdg_lib.graph import CDG
from cdg_lib.models import ConstraintNode, BinaryLocation
from cdg_lib.types import CWEClass, EdgeLabel
from cdg_lib.path_resolver import resolve_path


def _node(node_id, formula="x > 0"):
    return ConstraintNode(
        node_id=node_id,
        formula=formula,
        formula_skeleton="VAR > CONST",
        cwe_class=CWEClass.UNKNOWN,
        location=BinaryLocation("f", 0, 0),
        version="v1",
    )


def test_dep_bfs_returns_predecessors_excluding_self():
    g = CDG()
    a = g.store(_node("a"))
    b = g.store(_node("b"), dep_sources=[a])
    c = g.store(_node("c"), dep_sources=[b])

    result = resolve_path(g, c, source="i")
    assert set(result) == {a, b}
    assert c not in result


def test_dep_bfs_returns_empty_when_no_predecessors():
    g = CDG()
    a = g.store(_node("a"))
    assert resolve_path(g, a, source="i") == []


def test_source_ii_returns_explicit_path():
    g = CDG()
    a = g.store(_node("a"))
    b = g.store(_node("b"))
    result = resolve_path(g, b, source="ii", path_condition=[a])
    assert result == [a]


def test_source_ii_raises_without_path():
    g = CDG()
    a = g.store(_node("a"))
    with pytest.raises(ValueError, match="path_source='ii' requires"):
        resolve_path(g, a, source="ii")


def test_source_iii_uses_explicit_when_present():
    g = CDG()
    a = g.store(_node("a"))
    b = g.store(_node("b"), dep_sources=[a])
    result = resolve_path(g, b, source="iii", path_condition=["external_x"])
    assert result == ["external_x"]


def test_source_iii_falls_back_to_dep_bfs():
    g = CDG()
    a = g.store(_node("a"))
    b = g.store(_node("b"), dep_sources=[a])
    result = resolve_path(g, b, source="iii")
    assert result == [a]


def test_unknown_source_raises():
    g = CDG()
    a = g.store(_node("a"))
    with pytest.raises(ValueError, match="Unknown path source"):
        resolve_path(g, a, source="z")
