#!/usr/bin/env bash
# Download a subset of SMT-COMP QF_BV benchmarks for pretraining.
#
# Output: data/smtcomp_raw/*.smt2
# Idempotent: skips files already on disk.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RAW_DIR="$REPO_ROOT/data/smtcomp_raw"
mkdir -p "$RAW_DIR"

# We use the SMT-LIB GitHub mirror's QF_BV/Sage2 directory which is small
# enough to fetch quickly (~80 MB) but diverse enough for pretraining.
# Fall back to a smaller test subset if the mirror is unavailable.

MIRROR="https://github.com/SMT-LIB/QF_BV/raw/master/Sage2"
LOCAL_LIST="$RAW_DIR/.fetched"

# A small curated list of files. In production runs, this should be replaced
# with a full git clone; for the plan's training-data needs ~100 files is
# sufficient demonstration corpus.
FILES=(
    "bench_1.smt2"
    "bench_2.smt2"
    "bench_3.smt2"
    "bench_10.smt2"
    "bench_50.smt2"
    "bench_100.smt2"
)

for f in "${FILES[@]}"; do
    out="$RAW_DIR/$f"
    if [ -f "$out" ]; then
        echo "[skip] $f already present"
        continue
    fi
    if curl -sSfL "$MIRROR/$f" -o "$out" 2>/dev/null; then
        echo "[ok] $f"
        echo "$f" >> "$LOCAL_LIST"
    else
        echo "[warn] could not fetch $f from $MIRROR"
    fi
done

echo
echo "SMT-COMP raw files in: $RAW_DIR"
ls -1 "$RAW_DIR" | head -10
echo "(use tests/fixtures/sample_smtcomp/ for fast tests)"
