"""
SMT-LIB Backend: text-pipe interface to any SMT-LIB v2 compatible solver.

Spawns a solver subprocess and communicates via stdin/stdout using standard
SMT-LIB v2 commands (set-logic, declare-fun, assert, check-sat, get-value,
push, pop).

Proves CDG is solver-agnostic: works with Z3, CVC5, Yices2, Bitwuzla, etc.
"""

import re
import shutil
import subprocess
from typing import Dict, Optional, Tuple

from cdg_lib.types import SolverOutcome
from cdg_lib.backends.base import SolverBackend, SolverCapability


# Registry of known solver commands
SOLVER_COMMANDS: Dict[str, list] = {
    "z3":       ["z3", "-in", "-smt2"],
    "cvc5":     ["cvc5", "--lang=smt2", "--incremental", "--produce-models"],
    "yices2":   ["yices-smt2", "--incremental"],
    "bitwuzla": ["bitwuzla", "--lang", "smt2", "--incremental"],
}


def _var_type_to_width(var_type: str) -> int:
    """Convert CDG var_type string to bitvector width."""
    return {"bv16": 16, "bv32": 32, "bv64": 64}.get(var_type, 16)


def _formula_to_smtlib(formula: str, var_types: Dict[str, str]) -> Optional[str]:
    """
    Translate a CDG constraint formula to an SMT-LIB assert expression.

    Supports: var {>=, <=, >, <, ==, !=} const
    Uses unsigned bitvector comparisons (bvuge, bvule, bvugt, bvult).
    """
    m = re.match(r'(\w+)\s*(>=|<=|>|<|==|!=)\s*(\d+)', formula.strip())
    if not m:
        return None

    var_name, op, const_str = m.groups()
    const = int(const_str)
    width = _var_type_to_width(var_types.get(var_name, "bv16"))

    # Format constant as hex with correct width
    hex_digits = width // 4
    const_hex = f"#x{const:0{hex_digits}x}"

    op_map = {
        '>=': 'bvuge',
        '<=': 'bvule',
        '>':  'bvugt',
        '<':  'bvult',
        '==': '=',
        '!=': None,  # handled specially
    }

    if op == '!=':
        return f"(assert (not (= {var_name} {const_hex})))"

    smt_op = op_map[op]
    return f"(assert ({smt_op} {var_name} {const_hex}))"


def _parse_smtlib_value(response: str, var_name: str) -> Optional[int]:
    """
    Parse a get-value response from an SMT-LIB solver.

    Handles formats:
        ((var_name #xABCD))           -- hex (Z3, CVC5)
        ((var_name #b0101...))        -- binary
        ((var_name (_ bv42 16)))      -- indexed bitvector (CVC5)
    """
    # Hex format: #xABCD
    hex_match = re.search(
        rf'\(\s*{re.escape(var_name)}\s+#x([0-9a-fA-F]+)\s*\)', response
    )
    if hex_match:
        return int(hex_match.group(1), 16)

    # Binary format: #b0101
    bin_match = re.search(
        rf'\(\s*{re.escape(var_name)}\s+#b([01]+)\s*\)', response
    )
    if bin_match:
        return int(bin_match.group(1), 2)

    # Indexed BV format: (_ bv42 16)
    idx_match = re.search(
        rf'\(\s*{re.escape(var_name)}\s+\(\s*_\s+bv(\d+)\s+\d+\s*\)\s*\)', response
    )
    if idx_match:
        return int(idx_match.group(1))

    return None


class SmtLibBackend(SolverBackend):
    """
    Backend communicating with any SMT-LIB v2 solver via subprocess pipe.

    The solver process is started lazily on first solve_node() call and
    reused across calls via push/pop.
    """

    def __init__(self, solver_name: str = "z3"):
        self._solver_name = solver_name
        self._cmd = SOLVER_COMMANDS.get(solver_name)
        if self._cmd is None:
            raise ValueError(
                f"Unknown solver '{solver_name}'. "
                f"Known: {list(SOLVER_COMMANDS.keys())}"
            )
        self._process: Optional[subprocess.Popen] = None

    def capabilities(self) -> SolverCapability:
        return SolverCapability.CHECK_SAT | SolverCapability.GET_MODEL | SolverCapability.PUSH_POP

    def _ensure_process(self):
        """Start the solver subprocess if not already running."""
        if self._process is not None and self._process.poll() is None:
            return
        self._process = subprocess.Popen(
            self._cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        # Set logic and enable models (no output expected from these)
        self._write("(set-logic QF_BV)")
        self._write("(set-option :produce-models true)")

    def _write(self, cmd: str):
        """Send a command without reading a response (fire-and-forget)."""
        if self._process is None or self._process.poll() is not None:
            return
        self._process.stdin.write(cmd + "\n")
        self._process.stdin.flush()

    def _query(self, cmd: str) -> str:
        """Send a command and read one line of response."""
        if self._process is None or self._process.poll() is not None:
            return ""
        self._process.stdin.write(cmd + "\n")
        self._process.stdin.flush()
        line = self._process.stdout.readline().strip()
        return line

    def solve_node(
        self,
        formula: str,
        variables: set,
        var_types: Dict[str, str],
        timeout_ms: int = 5000,
    ) -> Tuple[SolverOutcome, Optional[Dict]]:
        try:
            self._ensure_process()
        except (FileNotFoundError, OSError):
            return SolverOutcome.UNKNOWN, None

        # Push a scope so we can pop after solving
        self._write("(push 1)")

        # Declare variables
        for var_name in sorted(variables):
            width = _var_type_to_width(var_types.get(var_name, "bv16"))
            self._write(f"(declare-fun {var_name} () (_ BitVec {width}))")

        # Assert the constraint
        assertion = _formula_to_smtlib(formula, var_types)
        if assertion is not None:
            self._write(assertion)

        # Check satisfiability (this produces output)
        result = self._query("(check-sat)")

        outcome = SolverOutcome.UNKNOWN
        model_dict = None

        if result == "sat":
            outcome = SolverOutcome.SAT
            model_dict = {}
            for var_name in sorted(variables):
                val_response = self._query(f"(get-value ({var_name}))")
                val = _parse_smtlib_value(val_response, var_name)
                if val is not None:
                    model_dict[var_name] = val
        elif result == "unsat":
            outcome = SolverOutcome.UNSAT
        elif result in ("timeout", "unknown"):
            outcome = SolverOutcome.TIMEOUT

        # Pop scope to clean up for next call
        self._write("(pop 1)")

        return outcome, model_dict

    def shutdown(self):
        """Terminate the solver subprocess."""
        if self._process is not None:
            try:
                self._write("(exit)")
            except (BrokenPipeError, OSError):
                pass
            try:
                self._process.terminate()
                self._process.wait(timeout=2)
            except (subprocess.TimeoutExpired, OSError):
                self._process.kill()
            self._process = None

    def __del__(self):
        self.shutdown()


def find_available_smtlib_solver() -> Optional[str]:
    """Find the first available SMT-LIB solver on PATH."""
    # Prefer in order: z3, cvc5, yices2, bitwuzla
    for name in ["z3", "cvc5", "yices2", "bitwuzla"]:
        cmd = SOLVER_COMMANDS[name][0]
        if shutil.which(cmd) is not None:
            return name
    return None
