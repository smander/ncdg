#!/usr/bin/env bash
# Container-side reproducibility runner. Invoked by scripts/verify_in_docker.sh
# via Docker's --entrypoint override. Mounts expected:
#   /app/models           (ro, host's models/)
#   /app/firmware/binaries (ro, host's firmware/binaries/)
#   /app/verification_out (rw, host's verification_run/<ts>/)
set -euo pipefail

OUT=/app/verification_out
mkdir -p "$OUT"

echo "=== Step 0: Sentence-Transformer probe ==="
python - <<'PY' || { echo "FATAL: Sentence-Transformer probe failed"; exit 2; }
import json
import numpy as np
from cdg_lib.neural.config import NeuralConfig
from cdg_lib.neural.embedder import Embedder

cfg = NeuralConfig()
e = Embedder(cfg)
v = e.embed("(x > 0) and (x < 10)")
assert v.shape == (384,), f"unexpected embedding shape {v.shape}"
n = float(np.linalg.norm(v))
assert n > 0, "zero embedding"

probe = {
    "shape": list(v.shape),
    "norm_bucket": round(n, 4),
    "embedder_path": str(cfg.embedder_path),
    "base_model": cfg.base_model,
    "fine_tuned_loaded": cfg.embedder_path.is_file(),
}
with open("/app/verification_out/sentence_transformer_probe.json", "w") as f:
    json.dump(probe, f, indent=2, sort_keys=True)
print(f"embedder OK: dim={v.shape[0]}, norm={n:.4f}, "
      f"fine_tuned={probe['fine_tuned_loaded']}")
PY

echo "=== Step 1: pytest ==="
# TFA tests that load bl2.elf into angr OOM-kill the kernel on Docker Desktop
# default memory (8 GB). TFA is not a paper claim — exclude the heavy cases.
python -m pytest tests/ -v --tb=short --junitxml="$OUT/pytest.xml" \
    --deselect "tests/test_validation_gates.py::test_g1_reachability[CVE-2022-47630-tfa-v2.8-bl2.elf]" \
    --deselect "tests/test_validation_gates.py::test_g2_vuln_patched_differ[CVE-2022-47630-tfa-v2.8-v2.9]" \
    --deselect "tests/test_harness_47630.py" \
    --deselect "tests/test_firmware_extractor.py::test_extract_tfa_vulnerable_cve" \
    || { echo "FATAL: pytest failures"; exit 3; }

echo "=== Step 2: run_rq_speed ==="
python -m experiments.run_rq_speed

echo "=== Step 3: run_rq_alpha_sweep ==="
python -m experiments.run_rq_alpha_sweep

echo "=== Step 4: run_rq_conflict ==="
python -m experiments.run_rq_conflict

echo "=== Step 5: benchmark_multiversion ==="
python -m experiments.benchmark_multiversion

echo "=== Step 6: benchmark_real_firmware (angr) ==="
python -m experiments.benchmark_real_firmware --use-angr

echo "=== Step 7: run_rq13 soundness ==="
python -m experiments.run_rq13

echo "=== Harvesting outputs ==="
cp experiments/*.json "$OUT/" 2>/dev/null || true
echo "Done."
