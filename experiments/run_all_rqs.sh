#!/usr/bin/env bash
# Run all RQ11-RQ16 evaluations and write JSON results to experiments/.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

for rq in 11 12 13 14 15 16; do
    echo "=== RQ${rq} ==="
    python -m experiments.run_rq${rq}
    echo
done

echo
echo "All RQs complete. Results in experiments/rq{11..16}_results.json:"
ls -la experiments/rq*_results.json
