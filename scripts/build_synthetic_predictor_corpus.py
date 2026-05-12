"""Build a synthetic labeled corpus for the UNSAT predictor.

Generates ~1000 (formula, label) pairs by augmenting the patterns that
firmware/extractor.py:_SYNTHETIC_TEMPLATES uses for the 4 CVEs. Each
pattern is replicated with varying constants:

  - SAT examples: bound below the bitvector max
      e.g., 'len > 1024' on bv16 -> SAT (values 1025..65535 exist)
  - UNSAT examples: bound at or above the bitvector max (overflow sentinel)
      e.g., 'len > 65535' on bv16 -> UNSAT
      e.g., 'ext_offset > 4294967295' on bv32 -> UNSAT

The pattern set covers the 4 target CVEs:
  - CVE-2022-30790, 30552 (CWE-787): IP/UDP fragment lengths
  - CVE-2022-34835 (CWE-787): i2c argument count
  - CVE-2022-47630 (CWE-125): X.509 extension offset

Output schema matches scripts/build_predictor_corpus.py.

Usage:
    python -m scripts.build_synthetic_predictor_corpus \
        --out data/predictor_corpus_synthetic.jsonl \
        --target-size 1000
"""

import argparse
import json
import random
from pathlib import Path
from typing import List


# Pattern templates: (variable_name, bv_width, cwe, op, sat_const_range, unsat_const)
# unsat_const is the bitvector overflow sentinel — any value > unsat_const-1 is UNSAT.
_PATTERNS = [
    # CVE-2022-30790 / CVE-2022-30552 patterns (network packet lengths)
    {"var": "ip_len", "bv": 16, "cwe": "CWE-787", "op": ">",
     "sat_range": (20, 65500), "unsat_const": 0xffff},
    {"var": "frag_offset", "bv": 16, "cwe": "CWE-787", "op": ">",
     "sat_range": (1, 65500), "unsat_const": 0xffff},
    {"var": "total_len", "bv": 16, "cwe": "CWE-787", "op": ">=",
     "sat_range": (1, 65500), "unsat_const": 0x10000},
    # CVE-2022-34835 (i2c byte count)
    {"var": "nbytes", "bv": 16, "cwe": "CWE-787", "op": ">",
     "sat_range": (1, 65500), "unsat_const": 0xffff},
    # CVE-2022-47630 (X.509 extension offset)
    {"var": "ext_offset", "bv": 32, "cwe": "CWE-125", "op": ">",
     "sat_range": (1, 0xfffffffe), "unsat_const": 0xffffffff},
    # Generic CWE-125 (out-of-bounds read on smaller buffers)
    {"var": "off", "bv": 16, "cwe": "CWE-125", "op": ">=",
     "sat_range": (1, 65500), "unsat_const": 0x10000},
    # Generic CWE-190 (integer overflow patterns)
    {"var": "x", "bv": 32, "cwe": "CWE-190", "op": ">",
     "sat_range": (1, 0xfffffffe), "unsat_const": 0xffffffff},
]


def _make_record(formula: str, var: str, bv: int, cwe: str,
                 outcome: str, skeleton: str) -> dict:
    return {
        "formula": formula,
        "skeleton": skeleton,
        "cwe": cwe,
        "vars": [var],
        "var_types": {var: f"bv{bv}"},
        "outcome": outcome,
        "embedding": None,
    }


def build(out_path: Path, target_size: int = 1000, seed: int = 0) -> int:
    rng = random.Random(seed)
    records: List[dict] = []
    n_per_pattern = max(1, target_size // (2 * len(_PATTERNS)))

    for pat in _PATTERNS:
        var = pat["var"]
        bv = pat["bv"]
        cwe = pat["cwe"]
        op = pat["op"]
        skeleton = f"(VAR u{op} CONST)"

        # SAT examples: bounds within the bv range
        lo, hi = pat["sat_range"]
        for _ in range(n_per_pattern):
            const = rng.randint(lo, hi)
            formula = f"{var} {op} {const}"
            records.append(_make_record(formula, var, bv, cwe, "SAT", skeleton))

        # UNSAT examples: bounds at the bv max (overflow sentinel).
        # Use op '>' with const = max-bv-value, which is UNSAT under
        # unsigned semantics regardless of the original op. We do NOT
        # generate constants larger than the bitwidth allows, since the
        # backend's regex parser would silently truncate them.
        max_bv = (1 << bv) - 1
        for _ in range(n_per_pattern):
            formula = f"{var} > {max_bv}"
            unsat_skel = "(VAR u> CONST)"
            records.append(_make_record(formula, var, bv, cwe, "UNSAT", unsat_skel))

    rng.shuffle(records)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    label_counts = {}
    for r in records:
        label_counts[r["outcome"]] = label_counts.get(r["outcome"], 0) + 1
    print(f"label distribution: {label_counts}")
    return len(records)


def _main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--target-size", type=int, default=1000)
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()
    n = build(args.out, args.target_size, args.seed)
    print(f"wrote {n} records to {args.out}")


if __name__ == "__main__":
    _main()
