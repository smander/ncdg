from cdg_lib.types import SolverOutcome


def test_unsat_predicted_exists():
    assert SolverOutcome.UNSAT_PREDICTED.value == "UNSAT_PREDICTED"


def test_unsat_predicted_distinct_from_unsat():
    assert SolverOutcome.UNSAT_PREDICTED is not SolverOutcome.UNSAT


def test_existing_outcomes_unchanged():
    assert SolverOutcome.SAT.value == "SAT"
    assert SolverOutcome.UNSAT.value == "UNSAT"
    assert SolverOutcome.TIMEOUT.value == "TIMEOUT"
    assert SolverOutcome.UNKNOWN.value == "UNKNOWN"
