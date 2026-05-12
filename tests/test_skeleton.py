import pytest

claripy = pytest.importorskip("claripy")

from firmware.skeleton import compute_skeleton


def test_skeleton_simple_var_const_lt():
    x = claripy.BVS("x", 32)
    expr = x < 100
    assert compute_skeleton(expr) == "(VAR u< CONST)"


def test_skeleton_simple_var_const_ge():
    y = claripy.BVS("y", 16)
    expr = y >= 0
    assert compute_skeleton(expr) == "(VAR u>= CONST)"


def test_skeleton_var_plus_var():
    a = claripy.BVS("a", 32)
    b = claripy.BVS("b", 32)
    expr = (a + b) < 256
    assert compute_skeleton(expr) == "((VAR + VAR) u< CONST)"


def test_skeleton_two_const_normalized():
    x = claripy.BVS("x", 32)
    expr1 = (x + 5) < 100
    expr2 = (x + 99) < 7
    assert compute_skeleton(expr1) == compute_skeleton(expr2)


def test_skeleton_two_vars_normalized():
    x = claripy.BVS("x", 32)
    y = claripy.BVS("y", 32)
    z = claripy.BVS("z", 32)
    assert compute_skeleton(x < y) == compute_skeleton(z < y)


def test_skeleton_nested_operators():
    x = claripy.BVS("x", 32)
    y = claripy.BVS("y", 32)
    expr = (x + y) * 2 < 1000
    skel = compute_skeleton(expr)
    assert "VAR" in skel and "CONST" in skel
    assert "+" in skel and "*" in skel and "u<" in skel


def test_skeleton_unary_not():
    x = claripy.BVS("x", 32)
    y = claripy.BVS("y", 32)
    expr = claripy.Not(claripy.And(x < 100, y > 0))
    skel = compute_skeleton(expr)
    assert skel.startswith("(! ")


def test_skeleton_logical_and():
    x = claripy.BVS("x", 32)
    y = claripy.BVS("y", 32)
    expr = claripy.And(x < 10, y > 0)
    skel = compute_skeleton(expr)
    assert "&&" in skel


def test_skeleton_unsigned_compare():
    x = claripy.BVS("x", 32)
    expr = claripy.ULT(x, 100)
    skel = compute_skeleton(expr)
    assert "u<" in skel
