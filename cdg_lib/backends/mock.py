"""
Mock solver backend for testing without any real SMT solver.

Extracted from solver.py::_mock_solve().
"""

from typing import Dict, Optional, Tuple

from cdg_lib.types import SolverOutcome
from cdg_lib.backends.base import SolverBackend, SolverCapability


class MockBackend(SolverBackend):
    """
    Mock backend: returns SAT for simple comparisons, UNKNOWN otherwise.

    Useful for testing the CDG framework without a real solver installed.
    """

    def capabilities(self) -> SolverCapability:
        return SolverCapability.CHECK_SAT

    def solve_node(
        self,
        formula: str,
        variables: set,
        var_types: Dict[str, str],
        timeout_ms: int = 5000,
    ) -> Tuple[SolverOutcome, Optional[Dict]]:
        if ">=" in formula or ">" in formula:
            return SolverOutcome.SAT, {"index": 999}
        return SolverOutcome.UNKNOWN, None
