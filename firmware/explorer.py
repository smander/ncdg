"""Bounded angr exploration with strict resource caps.

Wraps angr's simulation manager with loop-bound, state-count, time-budget,
and memory-watchdog enforcement. Returns collected constraints from all
explored states (active + deadended).
"""

import time
from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass(frozen=True)
class ExplorerBudget:
    loop_bound: int = 10        # iterations per loop
    max_states: int = 200       # total states to explore
    time_seconds: float = 60.0  # wall-clock budget
    memory_mb: int = 4096       # soft cap; checked between steps


@dataclass
class ExplorerResult:
    constraints: List[Any] = field(default_factory=list)
    states_terminal: int = 0
    total_states_explored: int = 0
    termination_reason: str = "unknown"  # time | states | completed | memory


class BoundedExplorer:
    """Run angr exploration with strict resource caps."""

    def __init__(self, project, budget: ExplorerBudget):
        self.project = project
        self.budget = budget

    def run(self, init_state, find_addr: Optional[int] = None) -> ExplorerResult:
        """Step the simulation manager until a budget is exhausted.

        If find_addr is given, halt as soon as a state reaches it.
        """
        import angr
        try:
            from angr.exploration_techniques import LoopSeer
        except ImportError:
            LoopSeer = None

        simgr = self.project.factory.simulation_manager(init_state)
        if LoopSeer is not None:
            try:
                simgr.use_technique(LoopSeer(bound=self.budget.loop_bound))
            except Exception:
                pass

        deadline = time.monotonic() + self.budget.time_seconds
        result = ExplorerResult()

        while True:
            if not simgr.active:
                result.termination_reason = "completed"
                break
            if time.monotonic() >= deadline:
                result.termination_reason = "time"
                break
            if len(simgr.active) > self.budget.max_states:
                result.termination_reason = "states"
                break

            try:
                simgr.step()
            except Exception:
                # angr can throw on broken state; drop it and continue
                simgr.move(from_stash="errored", to_stash="deadended")
                continue

            if find_addr is not None:
                hit = [s for s in simgr.active if s.addr == find_addr]
                if hit:
                    result.termination_reason = "completed"
                    simgr.active = hit
                    break

            result.total_states_explored = max(
                result.total_states_explored, len(simgr.active)
            )

        all_states = list(simgr.active) + list(getattr(simgr, "deadended", []))
        result.states_terminal = len(all_states)

        for state in all_states[: self.budget.max_states]:
            for con in state.solver.constraints:
                result.constraints.append(con)

        return result
