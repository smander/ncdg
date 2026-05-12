"""Build a FAISS index over training-corpus embeddings.

Walks one or more JSONL files, embeds the formula field of each record,
and persists the index to `<out>.faiss` plus a row-aligned `<out>.meta.jsonl`.

Usage:
    python -m scripts.build_faiss_index \
        --inputs data/llm_cve_pairs.jsonl data/smtcomp_pretrain.jsonl \
        --out models/embedder.faiss
"""

import argparse
import json
from pathlib import Path
from typing import List

import numpy as np

from cdg_lib.neural.config import NeuralConfig
from cdg_lib.neural.embedder import Embedder
from cdg_lib.neural.index import FaissIndex


def _formula_field(rec: dict) -> str:
    return (
        rec.get("formula")
        or rec.get("vulnerable_constraint")
        or rec.get("smtlib")
        or ""
    )


def build_index(inputs: List[Path], out_path: Path) -> int:
    cfg = NeuralConfig()
    embedder = Embedder(cfg)
    index = FaissIndex(dim=cfg.embedding_dim)

    vectors: list = []
    metas: list = []
    for src in inputs:
        for line in Path(src).read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            text = _formula_field(rec)
            if not text:
                continue
            vec = embedder.embed(text)
            # L2-normalize for cosine via inner product
            n = np.linalg.norm(vec)
            if n > 0:
                vec = vec / n
            vectors.append(vec)
            metas.append({"source": str(src), "cve_id": rec.get("cve_id"), "version": rec.get("version")})

    if not vectors:
        raise RuntimeError("no vectors to index — corpora empty?")

    vmat = np.stack(vectors).astype(np.float32)
    index.build(vmat)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    index.save(out_path)

    meta_path = out_path.with_suffix(".meta.jsonl")
    with meta_path.open("w") as f:
        for m in metas:
            f.write(json.dumps(m) + "\n")
    return len(vectors)


def _main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--inputs", type=Path, nargs="+", required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    n = build_index(args.inputs, args.out)
    print(f"indexed {n} vectors to {args.out}")


if __name__ == "__main__":
    _main()
