#!/usr/bin/env bash
# Full training pipeline for f_theta. Run inside the cdg-bench Docker image.
#
# Steps:
#   1. (optional) download SMT-COMP — skipped if data/smtcomp_pretrain.jsonl exists
#   2. Generate LLM-CVE corpus (offline fallback if no API key)
#   3. Validate LLM-CVE corpus
#   4. Build real-angr corpus (held-out test set)
#   5. Train the embedder
#   6. Build the FAISS index

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

mkdir -p data models

if [ ! -f data/smtcomp_pretrain.jsonl ]; then
    echo "[1/6] Building SMT-COMP corpus from local fixture..."
    python -m scripts.build_smtcomp_corpus tests/fixtures/sample_smtcomp data/smtcomp_pretrain.jsonl
fi

echo "[2/6] Generating LLM-CVE corpus..."
echo "[]" > /tmp/empty_descriptors.json
python -m scripts.generate_llm_cves /tmp/empty_descriptors.json data/llm_cve_pairs_raw.jsonl

echo "[3/6] Validating LLM-CVE corpus..."
python -m scripts.validate_llm_cves data/llm_cve_pairs_raw.jsonl data/llm_cve_pairs.jsonl

if [ ! -f data/real_angr_traces.jsonl ] && [ -d firmware/binaries/uboot ]; then
    echo "[4/6] Building real-angr corpus..."
    python -m scripts.build_real_angr_corpus data/real_angr_traces.jsonl
else
    echo "[4/6] Skipped (real-angr corpus exists or no binaries built)"
fi

echo "[5/6] Training embedder..."
python -m scripts.train_embedder \
    --finetune data/llm_cve_pairs.jsonl \
    --out models/embedder \
    --epochs 3 --batch-size 16

echo "[6/6] Building FAISS index..."
python -m scripts.build_faiss_index \
    --inputs data/llm_cve_pairs.jsonl data/smtcomp_pretrain.jsonl \
    --out models/embedder.faiss

echo
echo "Done. Artifacts in models/:"
ls -la models/
