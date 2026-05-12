"""
CDG Solver Backends: pluggable solver implementations.

get_backend(name) factory returns the best available backend:
  - "z3"          → Z3NativeBackend (direct Python API)
  - "z3_propagator" → Z3PropagatorBackend (CDCL(T) integration)
  - "smtlib"      → SmtLibBackend (text pipe to any solver)
  - "smtlib:cvc5" → SmtLibBackend with CVC5
  - "mock"        → MockBackend (testing)
  - "auto"        → Best available: Z3 native > SMT-LIB > Mock
"""

from cdg_lib.backends.base import SolverBackend, SolverCapability
from cdg_lib.backends.mock import MockBackend

__all__ = [
    "SolverBackend", "SolverCapability", "MockBackend",
    "get_backend", "SOLVER_COMMANDS",
]

# Re-export SOLVER_COMMANDS from smtlib
from cdg_lib.backends.smtlib import SOLVER_COMMANDS


def get_backend(name: str = "auto") -> SolverBackend:
    """
    Factory: return a solver backend by name.

    Auto-detection fallback chain: Z3 native → SMT-LIB on PATH → Mock.

    Args:
        name: Backend identifier. Options:
            "auto"            - best available
            "z3"              - Z3 Python API (requires z3-solver)
            "z3_propagator"   - Z3 with CDG propagator
            "smtlib"          - SMT-LIB pipe (auto-detect solver)
            "smtlib:<solver>"  - SMT-LIB pipe with specific solver (z3, cvc5, ...)
            "mock"            - Mock backend for testing

    Returns:
        SolverBackend instance

    Raises:
        RuntimeError: if the requested backend is not available
    """
    if name == "mock":
        return MockBackend()

    if name == "z3":
        return _get_z3_native()

    if name == "z3_propagator":
        return _get_z3_propagator()

    if name.startswith("smtlib"):
        parts = name.split(":", 1)
        solver_name = parts[1] if len(parts) > 1 else None
        return _get_smtlib(solver_name)

    if name == "auto":
        return _auto_detect()

    raise ValueError(f"Unknown backend: '{name}'")


def _get_z3_native() -> SolverBackend:
    """Get Z3 native backend, raising if Z3 is unavailable."""
    try:
        import z3  # noqa: F401
    except ImportError:
        raise RuntimeError("Z3 Python bindings not installed (pip install z3-solver)")
    from cdg_lib.backends.z3_native import Z3NativeBackend
    return Z3NativeBackend()


def _get_z3_propagator() -> SolverBackend:
    """Get Z3 propagator backend."""
    try:
        import z3  # noqa: F401
    except ImportError:
        raise RuntimeError("Z3 Python bindings not installed (pip install z3-solver)")
    from cdg_lib.backends.z3_propagator import Z3PropagatorBackend
    return Z3PropagatorBackend()


def _get_smtlib(solver_name: str = None) -> SolverBackend:
    """Get SMT-LIB backend, optionally with a specific solver."""
    from cdg_lib.backends.smtlib import SmtLibBackend, find_available_smtlib_solver

    if solver_name is None:
        solver_name = find_available_smtlib_solver()
        if solver_name is None:
            raise RuntimeError(
                "No SMT-LIB solver found on PATH. "
                "Install z3, cvc5, yices2, or bitwuzla."
            )
    return SmtLibBackend(solver_name)


def _auto_detect() -> SolverBackend:
    """Auto-detect the best available backend."""
    # Try Z3 native first (fastest)
    try:
        return _get_z3_native()
    except RuntimeError:
        pass

    # Try SMT-LIB pipe
    try:
        return _get_smtlib()
    except RuntimeError:
        pass

    # Fall back to mock
    return MockBackend()
