#!/usr/bin/env bash
set -e

echo "============================================================"
echo "  CDG-Bench: Constraint Dependency Graph Evaluation Pipeline"
echo "============================================================"
echo ""

# Step 1: Check ARM64 binaries
echo "[1/6] Compiled binaries:"
for ver in v10 v11 v12 v13; do
    bin="/app/cdg_bench_${ver}_arm64"
    if [ -f "$bin" ]; then
        echo "  $bin"
        file "$bin" 2>/dev/null || true
    fi
done
if ! ls /app/cdg_bench_*_arm64 1>/dev/null 2>&1; then
    echo "  No compiled binaries found. Experiments will use synthetic constraints."
fi
echo ""

# Step 2: Run tests
echo "[2/6] Running pytest..."
echo "------------------------------------------------------------"
python -m pytest tests/ -v --tb=short 2>&1
TEST_EXIT=$?
echo "------------------------------------------------------------"
if [ $TEST_EXIT -eq 0 ]; then
    echo "  Tests: PASSED"
else
    echo "  Tests: FAILED (exit code $TEST_EXIT)"
    echo "  Continuing to experiments anyway..."
fi
echo ""

# Step 3: Run experiments
echo "[3/6] Running experiments..."
echo "------------------------------------------------------------"
python -m experiments.experiments 2>&1
EXP_EXIT=$?
echo "------------------------------------------------------------"
if [ $EXP_EXIT -eq 0 ]; then
    echo "  Experiments: COMPLETED"
else
    echo "  Experiments: FAILED (exit code $EXP_EXIT)"
fi
echo ""

# Step 4: Run multi-version benchmark
echo "[4/6] Running multi-version benchmark..."
echo "------------------------------------------------------------"
python -m experiments.benchmark_multiversion 2>&1
BENCH_EXIT=$?
echo "------------------------------------------------------------"
if [ $BENCH_EXIT -eq 0 ]; then
    echo "  Multi-version benchmark: COMPLETED"
else
    echo "  Multi-version benchmark: FAILED (exit code $BENCH_EXIT)"
fi
echo ""

# Step 5: Run real firmware benchmark (synthetic templates)
echo "[5/6] Running real firmware benchmark (synthetic templates)..."
echo "------------------------------------------------------------"
python -m experiments.benchmark_real_firmware 2>&1
FW_EXIT=$?
echo "------------------------------------------------------------"
if [ $FW_EXIT -eq 0 ]; then
    echo "  Real firmware benchmark (synthetic): COMPLETED"
else
    echo "  Real firmware benchmark (synthetic): FAILED (exit code $FW_EXIT)"
fi
echo ""

# Step 6: Run real firmware benchmark with angr extraction (Phase 0)
echo "[6/6] Running real firmware benchmark with angr extraction..."
echo "------------------------------------------------------------"
if [ -d "/app/firmware/binaries/uboot/v2022.04" ] || [ -d "firmware/binaries/uboot/v2022.04" ]; then
    python -m experiments.benchmark_real_firmware --use-angr 2>&1
    ANGR_EXIT=$?
    echo "------------------------------------------------------------"
    if [ $ANGR_EXIT -eq 0 ]; then
        echo "  Real firmware benchmark (angr): COMPLETED"
    else
        echo "  Real firmware benchmark (angr): FAILED (exit code $ANGR_EXIT)"
    fi
else
    echo "  Skipped — no binaries built. Run scripts/build_binaries.sh first."
    echo "------------------------------------------------------------"
fi
echo ""

# Copy results to mounted volume if available
if [ -d /app/results ]; then
    cp -f experiments/experiment_results.json /app/results/ 2>/dev/null || true
    cp -f experiments/benchmark_multiversion_results.json /app/results/ 2>/dev/null || true
    cp -f experiments/benchmark_real_firmware_results.json /app/results/ 2>/dev/null || true
    cp -f experiments/benchmark_real_firmware_angr_results.json /app/results/ 2>/dev/null || true
    echo "  Results copied to /app/results/"
fi

echo ""
echo "============================================================"
echo "  Pipeline complete."
echo "============================================================"

exit $TEST_EXIT
