#!/usr/bin/env bash
# Run RQ13-RQ16 (after RQ11/RQ12 already completed in prior run).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
for rq in 13 14 15 16; do
    echo "=== RQ${rq} ==="
    python -m experiments.run_rq${rq}
    echo
done
echo "Remaining RQs done."
ls -la experiments/rq*_results.json
