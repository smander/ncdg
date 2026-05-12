"""Diff candidate experiment results against the baseline snapshot.

Bit-identical for numeric fields. Wall-clock keys (timing-only) are skipped.
Run after experiments/baseline/*.json has been populated.

Usage:
    python scripts/compare_results.py \\
        --baseline experiments/baseline \\
        --candidate verification_run/<timestamp>
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, List

WALL_CLOCK_KEYS = {
    "wall_clock_s", "wall_clock", "elapsed", "duration", "duration_s",
    "time_ms", "time_s", "seconds", "timing", "t0", "t1",
}


def _walk(prefix: str, base: Any, cand: Any, mismatches: List[str]) -> None:
    if isinstance(base, dict):
        if not isinstance(cand, dict):
            mismatches.append(
                f"{prefix}: type mismatch dict vs {type(cand).__name__}"
            )
            return
        for k in base:
            if k not in cand:
                mismatches.append(f"{prefix}.{k}: missing in candidate")
                continue
            if k in WALL_CLOCK_KEYS:
                continue
            _walk(f"{prefix}.{k}", base[k], cand[k], mismatches)
        return
    if isinstance(base, list):
        if not isinstance(cand, list) or len(base) != len(cand):
            cand_len = len(cand) if isinstance(cand, list) else "non-list"
            mismatches.append(
                f"{prefix}: list length {len(base)} vs {cand_len}"
            )
            return
        for i, (b, c) in enumerate(zip(base, cand)):
            _walk(f"{prefix}[{i}]", b, c, mismatches)
        return
    if base != cand:
        mismatches.append(
            f"{prefix}: baseline={base!r} candidate={cand!r}"
        )


def _compare_file(baseline_path: Path, candidate_path: Path) -> List[str]:
    if not candidate_path.is_file():
        return [f"{candidate_path.name}: MISSING in candidate"]
    base = json.loads(baseline_path.read_text())
    cand = json.loads(candidate_path.read_text())
    mismatches: List[str] = []
    _walk(baseline_path.stem, base, cand, mismatches)
    return mismatches


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline", required=True, type=Path,
                    help="Directory of baseline JSON files")
    ap.add_argument("--candidate", required=True, type=Path,
                    help="Directory of candidate JSON files")
    args = ap.parse_args()

    if not args.baseline.is_dir():
        print(f"FATAL: baseline directory missing: {args.baseline}")
        return 2
    if not args.candidate.is_dir():
        print(f"FATAL: candidate directory missing: {args.candidate}")
        return 2

    total_files = 0
    failed_files = 0

    for baseline_file in sorted(args.baseline.glob("*.json")):
        total_files += 1
        cand_file = args.candidate / baseline_file.name
        mismatches = _compare_file(baseline_file, cand_file)
        if mismatches:
            failed_files += 1
            print(f"[FAIL] {baseline_file.name}")
            for m in mismatches[:20]:
                print(f"   {m}")
            if len(mismatches) > 20:
                print(f"   ... and {len(mismatches) - 20} more")
        else:
            print(f"[PASS] {baseline_file.name}")

    print()
    print(
        f"VERIFICATION: {total_files - failed_files}/{total_files} files match"
    )
    return 0 if failed_files == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
