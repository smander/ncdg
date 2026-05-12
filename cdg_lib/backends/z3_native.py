
"""
Z3 Native Backend: direct Z3 Python API integration.

Extracted from solver.py: parse_constraint(), Z3NativeBackend.solve_node().
parse_constraint() is module-level so it can be shared with z3_propagator.py.
"""

import re
from typing import Dict, Optional, Tuple

try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False

from cdg_lib.types import SolverOutcome
from cdg_lib.backends.base import SolverBackend, SolverCapability


def make_z3_vars(variables: set, var_types: Dict[str, str]) -> dict:
    """Create Z3 BitVec variables from variable names and type mappings."""
    if not HAS_Z3:
        return {}
    z3_vars = {}
    for var_name in variables:
        var_type = var_types.get(var_name, "bv16")
        width = {"bv16": 16, "bv32": 32, "bv64": 64}.get(var_type, 16)
        z3_vars[var_name] = z3.BitVec(var_name, width)
    return z3_vars


def parse_constraint(formula: str, z3_vars: dict):
    """
    Parse a simple constraint string into a Z3 expression.

    Supports: var {>=, <=, >, <, ==, !=} const
    Uses unsigned bitvector comparisons.
    """
    if not HAS_Z3:
        return None

    m = re.match(r'(\w+)\s*(>=|<=|>|<|==|!=)\s*(\d+)', formula)
    if m:
        var_name, op, const_str = m.groups()
        const = int(const_str)
        if var_name not in z3_vars:
            z3_vars[var_name] = z3.BitVec(var_name, 16)
        var = z3_vars[var_name]

        ops = {
            '>=': lambda v, c: z3.UGE(v, c),
            '<=': lambda v, c: z3.ULE(v, c),
            '>':  lambda v, c: z3.UGT(v, c),
            '<':  lambda v, c: z3.ULT(v, c),
            '==': lambda v, c: v == c,
            '!=': lambda v, c: v != c,
        }
        return ops[op](var, const)

    return None


class Z3NativeBackend(SolverBackend):
    """
    Backend using the Z3 Python API directly.

    Provides CHECK_SAT, GET_MODEL, and PUSH_POP capabilities.
    """

    def capabilities(self) -> SolverCapability:
        return SolverCapability.CHECK_SAT | SolverCapability.GET_MODEL | SolverCapability.PUSH_POP

    def solve_node(
        self,
        formula: str,
        variables: set,
        var_types: Dict[str, str],
        timeout_ms: int = 5000,
    ) -> Tuple[SolverOutcome, Optional[Dict]]:
        if not HAS_Z3:
            return SolverOutcome.UNKNOWN, None

        try:
            solver = z3.Solver()
            solver.set("timeout", timeout_ms)

            z3_vars = make_z3_vars(variables, var_types)
            constraint = parse_constraint(formula.strip(), z3_vars)
            if constraint is not None:
                solver.add(constraint)

            result = solver.check()
            if result == z3.sat:
                m = solver.model()
                model_dict = {
                    str(d): m[d].as_long() if hasattr(m[d], 'as_long') else str(m[d])
                    for d in m.decls()
                }
                return SolverOutcome.SAT, model_dict
            elif result == z3.unsat:
                return SolverOutcome.UNSAT, None
            else:
                return SolverOutcome.TIMEOUT, None
        except Exception:
            return SolverOutcome.UNKNOWN, None
