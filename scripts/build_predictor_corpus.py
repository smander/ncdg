"""Build the predictor training corpus from real-angr + LLM-CVE inputs.

For real-angr traces the `outcome` field is already Z3-verified (or UNKNOWN).
For LLM-CVE pairs we emit two records: vulnerable_constraint with outcome=SAT
and patched_constraint with outcome=UNSAT (consistent with the validator's
soft check in Plan 1).

Output format: JSONL with fields:
  formula, skeleton, cwe, vars, var_types, outcome ("SAT"|"UNSAT"|"UNKNOWN"),
  embedding (None - Plan 2 fills via Embedder during training)

Usage:
    python -m scripts.build_predictor_corpus \
        --real-angr data/real_angr_traces.jsonl \
        --llm-cve data/llm_cve_pairs.jsonl \
        --out data/predictor_corpus.jsonl
"""

import argparse
import json
from pathlib import Path
from typing import List


def _load_jsonl(path: Path) -> List[dict]:
    if not path.is_file():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def _from_real_angr(rec: dict, backend=None) -> dict:
    """Convert a real-angr record to predictor format.

    If `outcome` is UNKNOWN and a Z3 backend is provided, attempt to label
    via Z3 directly. This bootstraps the predictor's training labels from
    Z3's own verdicts on the extracted constraints.
    """
    formula = rec.get("formula", "")
    var_types = rec.get("var_types", {})
    variables = set(rec.get("vars", []))
    outcome = rec.get("outcome", "UNKNOWN")
    if outcome == "UNKNOWN" and backend is not None:
        try:
            outcome_enum, _ = backend.solve_node(formula, variables, var_types)
            outcome = outcome_enum.value
        except Exception:
            outcome = "UNKNOWN"
    return {
        "formula": formula,
        "skeleton": rec.get("skeleton", ""),
        "cwe": rec.get("cwe", "UNKNOWN"),
        "vars": list(variables),
        "var_types": var_types,
        "outcome": outcome,
        "embedding": None,
    }


def _from_llm_cve(rec: dict) -> List[dict]:
    out = []
    vars_ = rec.get("vars", {}) or {}
    var_names = list(vars_.keys())
    if rec.get("vulnerable_constraint"):
        out.append({
            "formula": rec["vulnerable_constraint"],
            "skeleton": "",
            "cwe": rec.get("cwe", "UNKNOWN"),
            "vars": var_names,
            "var_types": vars_,
            "outcome": "SAT",
            "embedding": None,
        })
    if rec.get("patched_constraint"):
        out.append({
            "formula": rec["patched_constraint"],
            "skeleton": "",
            "cwe": rec.get("cwe", "UNKNOWN"),
            "vars": var_names,
            "var_types": vars_,
            "outcome": "UNSAT",
            "embedding": None,
        })
    return out


def build_corpus(real_angr_path: Path, llm_cve_path: Path, out_path: Path,
                 use_z3_labeling: bool = True) -> int:
    """Build the corpus, optionally Z3-labeling UNKNOWN outcomes."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    backend = None
    if use_z3_labeling:
        try:
            from cdg_lib.backends import get_backend
            backend = get_backend("auto")
        except Exception:
            backend = None
    records: List[dict] = []
    angr_records = _load_jsonl(real_angr_path)
    for i, rec in enumerate(angr_records):
        if backend is not None and i % 500 == 0:
            print(f"  [{i}/{len(angr_records)}] Z3-labeling real-angr records...")
        records.append(_from_real_angr(rec, backend))
    for rec in _load_jsonl(llm_cve_path):
        records.extend(_from_llm_cve(rec))
    with out_path.open("w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    # Print label distribution for visibility
    label_counts = {}
    for r in records:
        label_counts[r["outcome"]] = label_counts.get(r["outcome"], 0) + 1
    print(f"label distribution: {label_counts}")
    return len(records)


def _main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--real-angr", type=Path, default=Path("data/real_angr_traces.jsonl"))
    p.add_argument("--llm-cve", type=Path, default=Path("data/llm_cve_pairs.jsonl"))
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    n = build_corpus(args.real_angr, args.llm_cve, args.out)
    print(f"wrote {n} records to {args.out}")


if __name__ == "__main__":
    _main()
