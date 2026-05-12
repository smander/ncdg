"""
CDG Solver Backend ABC: defines the contract for all solver backends.

SolverBackend subclasses translate CDG constraint formulas into solver-specific
representations and return (SolverOutcome, model) pairs.
"""

from abc import ABC, abstractmethod
from enum import Flag, auto
from typing import Dict, List, Optional, Tuple

from cdg_lib.types import SolverOutcome


class SolverCapability(Flag):
    """Capabilities advertised by a solver backend."""
    CHECK_SAT = auto()
    GET_MODEL = auto()
    PUSH_POP = auto()
    CUSTOM_PROPAGATION = auto()
    BATCH_SOLVE = auto()


class SolverBackend(ABC):
    """
    Abstract base for CDG solver backends.

    solve_node() takes primitives (formula string, variables, var_types) rather
    than a ConstraintNode, keeping backends decoupled from models.py.
    """

    @abstractmethod
    def capabilities(self) -> SolverCapability:
        """Return capability flags supported by this backend."""
        ...

    @abstractmethod
    def solve_node(
        self,
        formula: str,
        variables: set,
        var_types: Dict[str, str],
        timeout_ms: int = 5000,
    ) -> Tuple[SolverOutcome, Optional[Dict]]:
        """
        Solve a single constraint formula.

        Args:
            formula:    Constraint string, e.g. "index >= 32"
            variables:  Set of variable names appearing in the formula
            var_types:  Mapping variable name -> type ("bv16", "bv32", "bv64")
            timeout_ms: Solver timeout in milliseconds

        Returns:
            (SolverOutcome, model_dict or None)
        """
        ...

    def solve_batch(
        self,
        nodes: List[Tuple[str, str, set, Dict[str, str]]],
        timeout_ms: int = 10000,
    ) -> Dict[str, Tuple[SolverOutcome, Optional[Dict]]]:
        """
        Solve multiple constraints. Default: sequential loop.

        Each element of nodes is (node_id, formula, variables, var_types).
        Returns: {node_id: (SolverOutcome, model_dict)}.
        """
        results = {}
        for node_id, formula, variables, var_types in nodes:
            results[node_id] = self.solve_node(formula, variables, var_types, timeout_ms)
        return results

    def shutdown(self):
        """Release any resources held by the backend."""
        pass
