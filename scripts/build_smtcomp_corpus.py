"""Build the SMT-COMP pretraining corpus.

Walks a directory of .smt2 files, extracts each (assert ...) body, computes
a canonical skeleton (constants -> CONST, variable names -> VAR), and writes
one JSON record per file to `out.jsonl`.

Usage:
    python -m scripts.build_smtcomp_corpus <smtcomp_dir> <out_jsonl>
"""

import json
import re
import sys
from pathlib import Path
from typing import Iterable, List


_HEX_CONST = re.compile(r"#x[0-9a-fA-F]+")
_BIN_CONST = re.compile(r"#b[01]+")
_DEC_CONST = re.compile(r"\b\d+\b")
# Variable references look like (declare-fun NAME ...) — capture NAMEs and
# replace them in asserts.
_DECL = re.compile(r"\(declare-fun\s+([A-Za-z_][A-Za-z0-9_]*)\s+\(\)")
# SMT-LIB bitvector / bool ops we care about (whitelist).
_OPS = {
    "bvult", "bvule", "bvugt", "bvuge",
    "bvslt", "bvsle", "bvsgt", "bvsge",
    "bvadd", "bvsub", "bvmul", "bvudiv", "bvurem",
    "bvshl", "bvlshr", "bvashr",
    "bvand", "bvor", "bvxor", "bvnot",
    "and", "or", "not", "=", "distinct",
    "concat", "extract", "zero_extend", "sign_extend",
    "ite",
}


def _extract_asserts(text: str) -> List[str]:
    """Return the body of each top-level (assert ...) form."""
    out: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        idx = text.find("(assert", i)
        if idx < 0:
            break
        # Walk balanced parens from idx
        depth = 0
        j = idx
        while j < n:
            c = text[j]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    out.append(text[idx + len("(assert"):j].strip())
                    j += 1
                    break
            j += 1
        i = j
    return out


def _compute_skeleton(asserts: Iterable[str], var_names: Iterable[str]) -> str:
    """Replace constants with CONST and known variable names with VAR.

    Order matters: hex/bin/dec constants first (they may match variable
    naming patterns otherwise), then variable names. Whitespace collapsed.
    """
    body = " AND ".join(asserts)
    body = _HEX_CONST.sub("CONST", body)
    body = _BIN_CONST.sub("CONST", body)
    body = _DEC_CONST.sub("CONST", body)
    for name in var_names:
        body = re.sub(rf"\b{re.escape(name)}\b", "VAR", body)
    body = re.sub(r"\s+", " ", body).strip()
    return body


def _extract_ops(text: str) -> List[str]:
    """Return the SMT-LIB operators appearing in the asserts."""
    seen: List[str] = []
    for op in _OPS:
        if re.search(rf"\b{re.escape(op)}\b", text):
            seen.append(op)
    return sorted(seen)


def _process_file(path: Path):
    """Parse one .smt2 file. Return record or None if no asserts."""
    text = path.read_text(errors="replace")
    asserts = _extract_asserts(text)
    if not asserts:
        return None
    var_names = _DECL.findall(text)
    skeleton = _compute_skeleton(asserts, var_names)
    ops = _extract_ops(" ".join(asserts))
    return {
        "smtlib": " AND ".join(asserts),
        "skeleton": skeleton,
        "ops": ops,
        "source": path.name,
    }


def build_corpus(src_dir: Path, out_path: Path) -> int:
    """Build the corpus. Returns the number of records written."""
    src_dir = Path(src_dir)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w") as f:
        for smt_path in sorted(src_dir.rglob("*.smt2")):
            rec = _process_file(smt_path)
            if rec is None:
                continue
            f.write(json.dumps(rec) + "\n")
            n += 1
    return n


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python -m scripts.build_smtcomp_corpus <src_dir> <out.jsonl>",
              file=sys.stderr)
        sys.exit(2)
    n = build_corpus(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"wrote {n} records to {sys.argv[2]}")
