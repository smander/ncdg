"""
CDG type definitions: enumerations for solver outcomes, edge labels, and CWE classes.
"""

from enum import Enum


class SolverOutcome(Enum):
    SAT = "SAT"
    UNSAT = "UNSAT"
    TIMEOUT = "TIMEOUT"
    UNKNOWN = "UNKNOWN"
    UNSAT_PREDICTED = "UNSAT_PREDICTED"
    UNSAT_BY_CONFLICT = "UNSAT_BY_CONFLICT"


class EdgeLabel(Enum):
    DEP = "dep"       # Derivation dependency
    CON = "con"       # Conflict (mutually unsatisfiable)
    SIM = "sim"       # Structural similarity


class CWEClass(Enum):
    CWE_125 = "CWE-125"  # Out-of-Bounds Read
    CWE_787 = "CWE-787"  # Out-of-Bounds Write
    CWE_416 = "CWE-416"  # Use-After-Free
    CWE_190 = "CWE-190"  # Integer Overflow
    UNKNOWN = "UNKNOWN"
