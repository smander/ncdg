"""Verification orchestrator: re-run paper-cited experiment scripts and capture
their JSON output into a timestamped directory.

Reproduces only the scripts whose output is cited in paper/cdg_paper.tex:
  - run_rq_speed.py        -> rq_speed_results.json (backs Table IV)
  - run_rq_alpha_sweep.py  -> rq15_results.json     (backs Table V / RQ12
                                                     alpha-sensitivity sweep)
  - run_rq_conflict.py     -> rq_conflict_results.json (backs RQ-Conflict
                                                     ablation table)

Usage: python3 -m experiments.verify
Exit code: 0 on success, non-zero if any sub-script fails.
"""

import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


SCRIPTS = [
    # (module_path, output_json_path_relative_to_repo_root)
    ("experiments.run_rq_speed",       "experiments/rq_speed_results.json"),
    ("experiments.run_rq_alpha_sweep", "experiments/rq15_results.json"),
    ("experiments.run_rq_conflict",    "experiments/rq_conflict_results.json"),
]


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_dir = repo_root / "experiments" / "verification_run" / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)

    failures = []
    for module, json_path in SCRIPTS:
        print(f"[verify] running {module} ...", flush=True)
        rc = subprocess.run(
            [sys.executable, "-m", module],
            cwd=repo_root,
            check=False,
        ).returncode
        if rc != 0:
            print(f"[verify] FAIL {module} exit={rc}", flush=True)
            failures.append(module)
            continue
        src = repo_root / json_path
        if not src.is_file():
            print(f"[verify] FAIL {module} produced no JSON at {json_path}", flush=True)
            failures.append(module)
            continue
        dst = out_dir / src.name
        shutil.copy2(src, dst)
        # Sanity: parse the JSON so a malformed output is caught here, not later
        json.loads(dst.read_text())
        print(f"[verify] captured {dst.relative_to(repo_root)}", flush=True)

    print(f"[verify] timestamp: {timestamp}")
    print(f"[verify] output:    {out_dir.relative_to(repo_root)}")
    if failures:
        print(f"[verify] FAILED scripts: {failures}")
        return 1
    print("[verify] OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
