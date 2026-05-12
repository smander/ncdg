"""
Tests for cdg_lib.types module.
"""

from cdg_lib.types import SolverOutcome


def test_unsat_by_conflict_exists():
    assert SolverOutcome.UNSAT_BY_CONFLICT.value == "UNSAT_BY_CONFLICT"


def test_unsat_by_conflict_distinct_from_unsat():
    assert SolverOutcome.UNSAT_BY_CONFLICT is not SolverOutcome.UNSAT
