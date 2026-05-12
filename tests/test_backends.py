#!/usr/bin/env python3
"""
CDG Backend Test Suite: Validates multi-backend solver architecture.

Test Categories:
  MockBackend:           SAT for >=, UNKNOWN for complex
  Z3NativeBackend:       SAT/UNSAT parity with original solver.py
  SmtLibBackend(z3):     Same results as Z3NativeBackend
  SmtLibBackend(cvc5):   Same results as Z3NativeBackend (if available)
  Z3PropagatorBackend:   Batch solve matches sequential
  get_backend("auto"):   Returns best available
  Cross-backend parity:  All backends agree on outcomes

Run: python3 -m pytest tests/test_backends.py -v
"""

import sys
import os
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import pytest

from cdg_lib import (
    CDG, SolverOutcome, EdgeLabel, CWEClass, make_constraint,
)
from cdg_lib.backends import get_backend, SolverBackend, SolverCapability
from cdg_lib.backends.base import SolverCapability
from cdg_lib.backends.mock import MockBackend
from cdg_lib.backends.smtlib import (
    SmtLibBackend, _formula_to_smtlib, _parse_smtlib_value,
    find_available_smtlib_solver, SOLVER_COMMANDS,
)

try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False

HAS_CVC5 = shutil.which("cvc5") is not None
HAS_Z3_CLI = shutil.which("z3") is not None


# ============================================================
# HELPERS
# ============================================================

def _simple_sat_formula():
    """Returns (formula, variables, var_types) for 'index >= 32' -- always SAT."""
    return "index >= 32", {"index"}, {"index": "bv16"}


def _simple_unsat_formula():
    """Returns (formula, variables, var_types) for 'index > 65535' -- UNSAT for bv16."""
    return "index > 65535", {"index"}, {"index": "bv16"}


def _equality_formula():
    """Returns (formula, variables, var_types) for 'count == 42'."""
    return "count == 42", {"count"}, {"count": "bv16"}


def _build_test_graph():
    """Build a small CDG with 3 similar OOB nodes for batch testing."""
    g = CDG("test_backends")
    c1 = make_constraint(
        formula="index >= 32", skeleton="VAR >= CONST",
        cwe=CWEClass.CWE_125, func="func_a", bb=1, addr=0x1000,
        version="v1.0", variables={"index"}, var_types={"index": "bv16"},
    )
    c2 = make_constraint(
        formula="index >= 32", skeleton="VAR >= CONST",
        cwe=CWEClass.CWE_125, func="func_b", bb=2, addr=0x2000,
        version="v1.0", variables={"index"}, var_types={"index": "bv16"},
    )
    c3 = make_constraint(
        formula="length > 256", skeleton="VAR > CONST",
        cwe=CWEClass.CWE_787, func="func_c", bb=3, addr=0x3000,
        version="v1.0", variables={"length"}, var_types={"length": "bv16"},
    )
    id1 = g.store(c1)
    id2 = g.store(c2)
    id3 = g.store(c3)
    return g, [id1, id2, id3]


# ============================================================
# TEST: MockBackend
# ============================================================

class TestMockBackend:

    def test_sat_for_ge(self):
        """MockBackend returns SAT for formulas containing >=."""
        be = MockBackend()
        outcome, model = be.solve_node(*_simple_sat_formula())
        assert outcome == SolverOutcome.SAT
        assert model is not None

    def test_sat_for_gt(self):
        """MockBackend returns SAT for formulas containing >."""
        be = MockBackend()
        outcome, model = be.solve_node("length > 256", {"length"}, {"length": "bv16"})
        assert outcome == SolverOutcome.SAT

    def test_unknown_for_complex(self):
        """MockBackend returns UNKNOWN for formulas without comparison operators."""
        be = MockBackend()
        outcome, model = be.solve_node(
            "buffer_freed == 1 && buffer_accessed == 1",
            {"buffer_freed", "buffer_accessed"},
            {"buffer_freed": "bv16", "buffer_accessed": "bv16"},
        )
        assert outcome == SolverOutcome.UNKNOWN
        assert model is None

    def test_capabilities(self):
        """MockBackend only advertises CHECK_SAT."""
        be = MockBackend()
        assert be.capabilities() == SolverCapability.CHECK_SAT

    def test_solve_batch_default(self):
        """MockBackend batch solve uses default sequential loop."""
        be = MockBackend()
        nodes = [
            ("n1", "index >= 32", {"index"}, {"index": "bv16"}),
            ("n2", "count == 5", {"count"}, {"count": "bv16"}),
        ]
        results = be.solve_batch(nodes)
        assert results["n1"][0] == SolverOutcome.SAT
        assert results["n2"][0] == SolverOutcome.UNKNOWN


# ============================================================
# TEST: Z3NativeBackend
# ============================================================

@pytest.mark.skipif(not HAS_Z3, reason="Z3 not installed")
class TestZ3NativeBackend:

    def setup_method(self):
        from cdg_lib.backends.z3_native import Z3NativeBackend
        self.be = Z3NativeBackend()

    def test_sat_simple(self):
        """Z3NativeBackend solves 'index >= 32' as SAT."""
        outcome, model = self.be.solve_node(*_simple_sat_formula())
        assert outcome == SolverOutcome.SAT
        assert model is not None
        assert "index" in model
        assert model["index"] >= 32

    def test_unsat_overflow(self):
        """Z3NativeBackend solves 'index > 65535' as UNSAT (bv16 max)."""
        outcome, model = self.be.solve_node(*_simple_unsat_formula())
        assert outcome == SolverOutcome.UNSAT
        assert model is None

    def test_equality(self):
        """Z3NativeBackend solves 'count == 42' as SAT with count=42."""
        outcome, model = self.be.solve_node(*_equality_formula())
        assert outcome == SolverOutcome.SAT
        assert model["count"] == 42

    def test_bv32(self):
        """Z3NativeBackend handles bv32 variables."""
        outcome, model = self.be.solve_node(
            "msg_len >= 8", {"msg_len"}, {"msg_len": "bv32"}
        )
        assert outcome == SolverOutcome.SAT
        assert model["msg_len"] >= 8

    def test_capabilities(self):
        """Z3NativeBackend advertises CHECK_SAT | GET_MODEL | PUSH_POP."""
        caps = self.be.capabilities()
        assert SolverCapability.CHECK_SAT in caps
        assert SolverCapability.GET_MODEL in caps
        assert SolverCapability.PUSH_POP in caps

    def test_parity_with_solver_module(self):
        """Z3NativeBackend results match solver.solve() on same formula."""
        from cdg_lib import solver
        g = CDG("parity_test")
        c = make_constraint(
            formula="index >= 32", skeleton="VAR >= CONST",
            cwe=CWEClass.CWE_125, func="f", bb=1, addr=0x100,
            version="v1", variables={"index"}, var_types={"index": "bv16"},
        )
        nid = g.store(c)
        solver_outcome, _ = solver.solve(g, nid)
        be_outcome, _ = self.be.solve_node("index >= 32", {"index"}, {"index": "bv16"})
        assert solver_outcome == be_outcome


# ============================================================
# TEST: SmtLibBackend (Z3 via text pipe)
# ============================================================

@pytest.mark.skipif(not HAS_Z3_CLI, reason="Z3 CLI not on PATH")
class TestSmtLibBackendZ3:

    def setup_method(self):
        self.be = SmtLibBackend("z3")

    def teardown_method(self):
        self.be.shutdown()

    def test_sat_simple(self):
        """SmtLibBackend(z3) solves 'index >= 32' as SAT."""
        outcome, model = self.be.solve_node(*_simple_sat_formula())
        assert outcome == SolverOutcome.SAT
        assert model is not None
        assert "index" in model
        assert model["index"] >= 32

    def test_unsat_overflow(self):
        """SmtLibBackend(z3) solves 'index > 65535' as UNSAT."""
        outcome, model = self.be.solve_node(*_simple_unsat_formula())
        assert outcome == SolverOutcome.UNSAT
        assert model is None

    def test_equality(self):
        """SmtLibBackend(z3) solves 'count == 42' as SAT with count=42."""
        outcome, model = self.be.solve_node(*_equality_formula())
        assert outcome == SolverOutcome.SAT
        assert model["count"] == 42

    def test_multiple_solves_reuse_process(self):
        """SmtLibBackend reuses the subprocess across multiple solve_node calls."""
        self.be.solve_node(*_simple_sat_formula())
        pid1 = self.be._process.pid
        self.be.solve_node(*_equality_formula())
        pid2 = self.be._process.pid
        assert pid1 == pid2

    def test_shutdown_terminates_process(self):
        """SmtLibBackend.shutdown() terminates the subprocess."""
        self.be.solve_node(*_simple_sat_formula())
        assert self.be._process is not None
        self.be.shutdown()
        assert self.be._process is None


@pytest.mark.skipif(not HAS_CVC5, reason="CVC5 not on PATH")
class TestSmtLibBackendCvc5:

    def setup_method(self):
        self.be = SmtLibBackend("cvc5")

    def teardown_method(self):
        self.be.shutdown()

    def test_sat_simple(self):
        """SmtLibBackend(cvc5) solves 'index >= 32' as SAT."""
        outcome, model = self.be.solve_node(*_simple_sat_formula())
        assert outcome == SolverOutcome.SAT
        assert model is not None
        assert "index" in model
        assert model["index"] >= 32

    def test_unsat_overflow(self):
        """SmtLibBackend(cvc5) solves 'index > 65535' as UNSAT."""
        outcome, model = self.be.solve_node(*_simple_unsat_formula())
        assert outcome == SolverOutcome.UNSAT

    def test_equality(self):
        """SmtLibBackend(cvc5) solves 'count == 42' as SAT with count=42."""
        outcome, model = self.be.solve_node(*_equality_formula())
        assert outcome == SolverOutcome.SAT
        assert model["count"] == 42


# ============================================================
# TEST: SMT-LIB helper functions
# ============================================================

class TestSmtLibHelpers:

    def test_formula_to_smtlib_ge(self):
        smt = _formula_to_smtlib("index >= 32", {"index": "bv16"})
        assert smt == "(assert (bvuge index #x0020))"

    def test_formula_to_smtlib_lt(self):
        smt = _formula_to_smtlib("count < 10", {"count": "bv16"})
        assert smt == "(assert (bvult count #x000a))"

    def test_formula_to_smtlib_eq(self):
        smt = _formula_to_smtlib("x == 42", {"x": "bv16"})
        assert smt == "(assert (= x #x002a))"

    def test_formula_to_smtlib_ne(self):
        smt = _formula_to_smtlib("x != 0", {"x": "bv16"})
        assert smt == "(assert (not (= x #x0000)))"

    def test_formula_to_smtlib_bv32(self):
        smt = _formula_to_smtlib("addr >= 256", {"addr": "bv32"})
        assert smt == "(assert (bvuge addr #x00000100))"

    def test_formula_to_smtlib_complex_returns_none(self):
        """Complex formulas not matching pattern return None."""
        smt = _formula_to_smtlib("a && b", {})
        assert smt is None

    def test_parse_smtlib_value_hex(self):
        val = _parse_smtlib_value("((index #x0020))", "index")
        assert val == 32

    def test_parse_smtlib_value_binary(self):
        val = _parse_smtlib_value("((flag #b00000001))", "flag")
        assert val == 1

    def test_parse_smtlib_value_indexed_bv(self):
        """CVC5-style (_ bvN W) format."""
        val = _parse_smtlib_value("((count (_ bv42 16)))", "count")
        assert val == 42

    def test_parse_smtlib_value_no_match(self):
        val = _parse_smtlib_value("garbage", "x")
        assert val is None


# ============================================================
# TEST: Z3PropagatorBackend
# ============================================================

@pytest.mark.skipif(not HAS_Z3, reason="Z3 not installed")
class TestZ3PropagatorBackend:

    def test_batch_solve_matches_sequential(self):
        """Batch solve via propagator matches sequential results."""
        from cdg_lib.backends.z3_propagator import Z3PropagatorBackend
        from cdg_lib.solver import solve as solve_single

        g, node_ids = _build_test_graph()
        backend = Z3PropagatorBackend()

        # Solve sequentially first
        sequential = {}
        for nid in node_ids:
            sequential[nid] = solve_single(g, nid)

        # Reset graph state
        g._solve_cache.clear()
        for nid in node_ids:
            g.nodes[nid].outcome = SolverOutcome.UNKNOWN
            g.nodes[nid].model = None

        # Solve via batch
        batch = backend.solve_batch_with_graph(g, node_ids, solve_single)

        # Outcomes must match
        for nid in node_ids:
            assert batch[nid][0] == sequential[nid][0], f"Mismatch on {nid}"

    def test_capabilities(self):
        """Z3PropagatorBackend advertises CUSTOM_PROPAGATION and BATCH_SOLVE."""
        from cdg_lib.backends.z3_propagator import Z3PropagatorBackend
        be = Z3PropagatorBackend()
        caps = be.capabilities()
        assert SolverCapability.CUSTOM_PROPAGATION in caps
        assert SolverCapability.BATCH_SOLVE in caps

    def test_single_node_solve(self):
        """Z3PropagatorBackend.solve_node() works for single constraints."""
        from cdg_lib.backends.z3_propagator import Z3PropagatorBackend
        be = Z3PropagatorBackend()
        outcome, model = be.solve_node(*_simple_sat_formula())
        assert outcome == SolverOutcome.SAT
        assert model["index"] >= 32


# ============================================================
# TEST: get_backend() factory
# ============================================================

class TestGetBackend:

    def test_mock_backend(self):
        """get_backend('mock') returns MockBackend."""
        be = get_backend("mock")
        assert isinstance(be, MockBackend)

    @pytest.mark.skipif(not HAS_Z3, reason="Z3 not installed")
    def test_z3_backend(self):
        """get_backend('z3') returns Z3NativeBackend."""
        from cdg_lib.backends.z3_native import Z3NativeBackend
        be = get_backend("z3")
        assert isinstance(be, Z3NativeBackend)

    @pytest.mark.skipif(not HAS_Z3, reason="Z3 not installed")
    def test_z3_propagator_backend(self):
        """get_backend('z3_propagator') returns Z3PropagatorBackend."""
        from cdg_lib.backends.z3_propagator import Z3PropagatorBackend
        be = get_backend("z3_propagator")
        assert isinstance(be, Z3PropagatorBackend)

    @pytest.mark.skipif(not HAS_Z3_CLI, reason="Z3 CLI not on PATH")
    def test_smtlib_backend(self):
        """get_backend('smtlib:z3') returns SmtLibBackend."""
        be = get_backend("smtlib:z3")
        assert isinstance(be, SmtLibBackend)
        be.shutdown()

    def test_auto_returns_backend(self):
        """get_backend('auto') always returns some backend (never raises)."""
        be = get_backend("auto")
        assert isinstance(be, SolverBackend)

    @pytest.mark.skipif(not HAS_Z3, reason="Z3 not installed")
    def test_auto_prefers_z3(self):
        """get_backend('auto') prefers Z3NativeBackend when available."""
        from cdg_lib.backends.z3_native import Z3NativeBackend
        be = get_backend("auto")
        assert isinstance(be, Z3NativeBackend)

    def test_unknown_raises(self):
        """get_backend with unknown name raises ValueError."""
        with pytest.raises(ValueError):
            get_backend("nonexistent")


# ============================================================
# TEST: Cross-backend parity
# ============================================================

class TestCrossBackendParity:

    @pytest.mark.skipif(not HAS_Z3 or not HAS_Z3_CLI, reason="Need Z3 API and CLI")
    def test_z3_native_vs_smtlib_z3(self):
        """Z3NativeBackend and SmtLibBackend(z3) agree on outcomes."""
        from cdg_lib.backends.z3_native import Z3NativeBackend

        native = Z3NativeBackend()
        smtlib = SmtLibBackend("z3")

        formulas = [
            _simple_sat_formula(),
            _simple_unsat_formula(),
            _equality_formula(),
            ("length > 256", {"length"}, {"length": "bv16"}),
        ]

        try:
            for formula, variables, var_types in formulas:
                n_out, n_model = native.solve_node(formula, variables, var_types)
                s_out, s_model = smtlib.solve_node(formula, variables, var_types)
                assert n_out == s_out, f"Outcome mismatch on '{formula}': {n_out} vs {s_out}"
                if n_out == SolverOutcome.SAT:
                    # Both must produce models (values may differ -- both are valid)
                    assert n_model is not None, f"Native model is None for '{formula}'"
                    assert s_model is not None, f"SmtLib model is None for '{formula}'"
        finally:
            smtlib.shutdown()

    @pytest.mark.skipif(not HAS_Z3 and not HAS_Z3_CLI, reason="Need at least one solver")
    def test_all_available_backends_agree(self):
        """All available backends agree on SAT/UNSAT for simple formulas."""
        backends = [("mock", MockBackend())]

        if HAS_Z3:
            from cdg_lib.backends.z3_native import Z3NativeBackend
            backends.append(("z3_native", Z3NativeBackend()))

        if HAS_Z3_CLI:
            backends.append(("smtlib_z3", SmtLibBackend("z3")))

        if HAS_CVC5:
            backends.append(("smtlib_cvc5", SmtLibBackend("cvc5")))

        # Test SAT formula -- all real solvers should say SAT
        formula, variables, var_types = _simple_sat_formula()
        sat_outcomes = {}
        for name, be in backends:
            outcome, _ = be.solve_node(formula, variables, var_types)
            sat_outcomes[name] = outcome

        # All real solvers must say SAT (mock also says SAT for >=)
        for name, outcome in sat_outcomes.items():
            assert outcome == SolverOutcome.SAT, f"{name} disagrees: {outcome}"

        # Cleanup SmtLib backends
        for name, be in backends:
            be.shutdown()


# ============================================================
# TEST: solver.py integration with backends
# ============================================================

class TestSolverBackendIntegration:

    def test_set_and_use_backend(self):
        """solver.set_backend() changes the backend used by solve()."""
        from cdg_lib import solver

        # Save original
        original = solver._default_backend

        try:
            mock = MockBackend()
            solver.set_backend(mock)

            g = CDG("integration_test")
            c = make_constraint(
                formula="index >= 32", skeleton="VAR >= CONST",
                cwe=CWEClass.CWE_125, func="f", bb=1, addr=0x100,
                version="v1", variables={"index"}, var_types={"index": "bv16"},
            )
            nid = g.store(c)
            outcome, model = solver.solve(g, nid)

            # MockBackend returns SAT with {"index": 999}
            assert outcome == SolverOutcome.SAT
            assert model == {"index": 999}
        finally:
            solver._default_backend = original

    def test_solve_with_explicit_backend(self):
        """solver.solve() accepts an explicit backend parameter."""
        from cdg_lib import solver

        mock = MockBackend()
        g = CDG("explicit_backend_test")
        c = make_constraint(
            formula="index >= 32", skeleton="VAR >= CONST",
            cwe=CWEClass.CWE_125, func="f", bb=1, addr=0x100,
            version="v1", variables={"index"}, var_types={"index": "bv16"},
        )
        nid = g.store(c)
        outcome, model = solver.solve(g, nid, backend=mock)
        assert outcome == SolverOutcome.SAT
        assert model == {"index": 999}


# ============================================================
# TEST: propagator.py facade
# ============================================================

@pytest.mark.skipif(not HAS_Z3, reason="Z3 not installed")
class TestPropagatorFacade:

    def test_import_cdgpropagator(self):
        """CDGPropagator is importable from propagator module."""
        from cdg_lib.propagator import CDGPropagator
        assert CDGPropagator is not None

    def test_solve_with_propagator_works(self):
        """propagator.solve_with_propagator() still works via facade."""
        from cdg_lib.propagator import solve_with_propagator

        g, node_ids = _build_test_graph()
        results = solve_with_propagator(g, node_ids)
        assert len(results) == 3
        for nid in node_ids:
            assert results[nid][0] == SolverOutcome.SAT


# ============================================================
# Standalone runner
# ============================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
