import time
import pytest

angr = pytest.importorskip("angr")

from firmware.explorer import BoundedExplorer, ExplorerBudget, ExplorerResult


@pytest.fixture
def tiny_proj():
    """Load the committed minimal ARM64 ELF for fast tests."""
    import os
    path = os.path.join(
        os.path.dirname(__file__), "fixtures", "tiny_arm64.elf"
    )
    return angr.Project(path, auto_load_libs=False)


def test_explorer_respects_time_budget(tiny_proj):
    budget = ExplorerBudget(loop_bound=10, max_states=200, time_seconds=2)
    explorer = BoundedExplorer(tiny_proj, budget=budget)
    state = tiny_proj.factory.entry_state()

    start = time.monotonic()
    result = explorer.run(state)
    elapsed = time.monotonic() - start

    assert isinstance(result, ExplorerResult)
    assert elapsed < 5.0, "explorer ignored time budget"


def test_explorer_respects_state_budget(tiny_proj):
    budget = ExplorerBudget(loop_bound=10, max_states=5, time_seconds=30)
    explorer = BoundedExplorer(tiny_proj, budget=budget)
    state = tiny_proj.factory.entry_state()

    result = explorer.run(state)
    assert result.total_states_explored <= 50, \
        f"state cap not enforced: explored {result.total_states_explored}"


def test_explorer_returns_constraints(tiny_proj):
    budget = ExplorerBudget(loop_bound=5, max_states=20, time_seconds=10)
    explorer = BoundedExplorer(tiny_proj, budget=budget)
    state = tiny_proj.factory.entry_state()

    result = explorer.run(state)
    assert isinstance(result.constraints, list)


def test_explorer_records_termination_reason(tiny_proj):
    budget = ExplorerBudget(loop_bound=10, max_states=200, time_seconds=1)
    explorer = BoundedExplorer(tiny_proj, budget=budget)
    state = tiny_proj.factory.entry_state()

    result = explorer.run(state)
    assert result.termination_reason in {"time", "states", "completed", "memory"}
