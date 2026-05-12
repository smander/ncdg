#!/usr/bin/env bash
# Build the image, run the verification container, dispatch the comparator.
#
# Usage:
#     bash scripts/verify_in_docker.sh
#
# Exit codes:
#     0   verification PASSed (all baseline JSONs reproduce bit-identically
#         except wall-clock fields)
#     1   pre-flight check failed (a required host directory is missing) OR
#         comparator found a mismatch
#     2   container-side runner exited non-zero (ST probe failed, pytest
#         failed, or an experiment script crashed)
#
# Output:
#     verification_run/<timestamp>/   all candidate JSONs + pytest.xml
#
# Inputs (volume-mounted into the container, read-only):
#     models/                          fine-tuned embedder + FAISS index
#     firmware/binaries/uboot/v2022.04 vulnerable U-Boot binary
#     firmware/binaries/uboot/v2022.07 patched U-Boot binary
#     experiments/baseline/            frozen reference JSONs to diff against
set -euo pipefail

IMAGE_TAG="cdg-bench:verify"
TS="$(date +%Y%m%d_%H%M%S)"
HOST_RESULTS="$(pwd)/verification_run/${TS}"
mkdir -p "$HOST_RESULTS"

# Pre-flight: required input directories must exist on host.
required_paths=(
    "models/embedder"
    "firmware/binaries/uboot/v2022.04"
    "firmware/binaries/uboot/v2022.07"
    "experiments/baseline"
)
for p in "${required_paths[@]}"; do
    if [ ! -e "$p" ]; then
        echo "FATAL: required path missing on host: $p"
        echo "(See docs/superpowers/specs/2026-05-11-docker-reproducibility-design.md)"
        exit 1
    fi
done

echo "[1/3] Building image..."
docker build -t "$IMAGE_TAG" .

echo "[2/3] Running verification inside container..."
echo "      Output directory: $HOST_RESULTS"
docker run --rm \
    --entrypoint /app/scripts/run_full_verify.sh \
    -v "$(pwd)/models:/app/models:ro" \
    -v "$(pwd)/firmware/binaries:/app/firmware/binaries:ro" \
    -v "$HOST_RESULTS:/app/verification_out" \
    "$IMAGE_TAG"

echo "[3/3] Comparing against baseline..."
python scripts/compare_results.py \
    --baseline "$(pwd)/experiments/baseline" \
    --candidate "$HOST_RESULTS"
