import pytest

claripy = pytest.importorskip("claripy")

from firmware.skeleton import to_smtlib


def test_smtlib_simple_compare():
    x = claripy.BVS("x", 32)
    out = to_smtlib(x < 100)
    assert "x" in out or "BVS" in out
    assert "100" in out or "64" in out or "#x" in out


def test_smtlib_returns_string():
    x = claripy.BVS("x", 32)
    out = to_smtlib(x + 5 < 200)
    assert isinstance(out, str)
    assert len(out) > 0
