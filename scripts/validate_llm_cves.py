"""Validate LLM-generated CVE constraint pairs via Z3.

Each record must contain `vulnerable_constraint` and `patched_constraint`.
A record passes when:
  1. All required fields are present.
  2. The vulnerable and patched constraints differ.
  3. Both formulae parse as Python expressions over bv-typed variables.
  4. (Soft check) the vulnerable formula is satisfiable, the patched is not.

Records that fail any check are dropped; the kept records are written to
the output file in the same JSONL format.

Usage:
    python -m scripts.validate_llm_cves <input.jsonl> <output.jsonl>
"""

import json
import sys
from pathlib import Path
from typing import Tuple


_REQUIRED = {"cve_id", "cwe", "vulnerable_constraint", "patched_constraint", "vars"}


class _UBitVec:
    """Proxy around z3.BitVec that uses unsigned comparison operators.

    Python expressions like ``off > 0xffffffff`` on a 32-bit variable should
    be UNSAT (no 32-bit value exceeds the 32-bit maximum). Z3's default
    BitVec comparisons are *signed*, which would make that SAT (-1 signed).
    This wrapper redirects ``>``, ``>=``, ``<``, ``<=`` to Z3's unsigned
    variants (UGT, UGE, ULT, ULE).
    """

    def __init__(self, name: str, bits: int) -> None:
        try:
            import z3
            self._bv = z3.BitVec(name, bits)
            self._z3 = z3
        except ImportError:
            self._bv = None
            self._z3 = None

    def _coerce(self, other):
        if isinstance(other, _UBitVec):
            return other._bv
        return other

    def __gt__(self, other):
        return self._z3.UGT(self._bv, self._coerce(other))

    def __ge__(self, other):
        return self._z3.UGE(self._bv, self._coerce(other))

    def __lt__(self, other):
        return self._z3.ULT(self._bv, self._coerce(other))

    def __le__(self, other):
        return self._z3.ULE(self._bv, self._coerce(other))

    def __eq__(self, other):
        return self._bv == self._coerce(other)

    def __ne__(self, other):
        return self._bv != self._coerce(other)

    def __add__(self, other):
        return self._bv + self._coerce(other)

    def __radd__(self, other):
        return self._coerce(other) + self._bv

    def __sub__(self, other):
        return self._bv - self._coerce(other)

    def __rsub__(self, other):
        return self._coerce(other) - self._bv

    def __and__(self, other):
        return self._bv & self._coerce(other)

    def __or__(self, other):
        return self._bv | self._coerce(other)

    def __xor__(self, other):
        return self._bv ^ self._coerce(other)

    def __hash__(self):
        return hash(self._bv)


def _try_z3_check(constraint: str, var_specs: dict) -> str:
    """Return 'sat', 'unsat', or 'unknown' for the constraint.

    var_specs maps name -> 'bv16' / 'bv32' / 'bv64'. Unknown widths default
    to bv32. Comparisons use unsigned semantics via _UBitVec. If the parse
    fails, returns 'unknown'.
    """
    try:
        import z3
    except ImportError:
        return "unknown"
    env: dict = {}
    for name, ty in var_specs.items():
        bits = int(ty.replace("bv", "")) if ty.startswith("bv") else 32
        env[name] = _UBitVec(name, bits)
    env["True"] = True
    env["False"] = False
    try:
        expr = eval(constraint, {"__builtins__": {}}, env)
    except Exception:
        return "unknown"
    if isinstance(expr, bool):
        return "sat" if expr else "unsat"
    s = z3.Solver()
    s.add(expr)
    res = s.check()
    return str(res)


def validate_record(rec: dict) -> Tuple[bool, str]:
    """Return (ok, reason). reason is a short string when ok is False."""
    missing = _REQUIRED - set(rec.keys())
    if missing:
        return False, f"missing required field(s): {sorted(missing)}"

    vuln = rec["vulnerable_constraint"]
    patched = rec["patched_constraint"]
    if vuln == patched:
        return False, "vulnerable and patched are identical (no change)"

    vars_ = rec.get("vars", {}) or {}
    vuln_res = _try_z3_check(vuln, vars_)
    patched_res = _try_z3_check(patched, vars_)
    if vuln_res == "unknown" or patched_res == "unknown":
        return False, f"unparseable: vuln={vuln_res} patched={patched_res}"
    # Soft check: vuln should be SAT (a real bug is reachable);
    # patched should be UNSAT (real fix blocks the path).
    if vuln_res != "sat":
        return False, f"vulnerable should be SAT, got {vuln_res}"
    if patched_res != "unsat":
        return False, f"patched should be UNSAT, got {patched_res}"
    return True, ""


def validate_corpus(in_path: Path, out_path: Path) -> Tuple[int, int]:
    """Read JSONL, write only validated records. Return (kept, dropped)."""
    in_path = Path(in_path)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    kept = 0
    dropped = 0
    with in_path.open() as fin, out_path.open("w") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                dropped += 1
                continue
            ok, _ = validate_record(rec)
            if ok:
                fout.write(json.dumps(rec) + "\n")
                kept += 1
            else:
                dropped += 1
    return kept, dropped


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python -m scripts.validate_llm_cves <in.jsonl> <out.jsonl>",
              file=sys.stderr)
        sys.exit(2)
    kept, dropped = validate_corpus(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"kept {kept}, dropped {dropped}")
