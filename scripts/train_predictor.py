"""Train g_phi (UNSAT predictor GNN) on the predictor corpus.

For Plan 2 bring-up this is a per-node trainer: each example uses a
self-loop adjacency (no neighbors). When a corpus with neighborhood adj
matrices is built, this script can be extended to consume them.

Usage:
    python -m scripts.train_predictor \
        --corpus data/predictor_corpus.jsonl \
        --out models/predictor.pt \
        --epochs 5 --batch-size 32
"""

import argparse
import json
from pathlib import Path
from typing import List

import numpy as np
import torch
import torch.nn as nn

from cdg_lib.neural.config import NeuralConfig
from cdg_lib.neural.gnn_model import UnsatGNN, FEATURE_DIM
from cdg_lib.neural.embedder import Embedder
from cdg_lib.types import CWEClass


_CWE_ORDER = [CWEClass.CWE_125, CWEClass.CWE_787, CWEClass.CWE_416, CWEClass.CWE_190]


def _cwe_onehot(cwe_str: str) -> np.ndarray:
    vec = np.zeros(len(_CWE_ORDER), dtype=np.float32)
    for i, c in enumerate(_CWE_ORDER):
        if c.value == cwe_str:
            vec[i] = 1.0
            break
    return vec


def _features(rec: dict, embedder) -> np.ndarray:
    emb = embedder.embed(rec.get("formula", ""))
    if emb.shape[0] != 384:
        emb = np.zeros(384, dtype=np.float32)
    cwe = _cwe_onehot(rec.get("cwe", "UNKNOWN"))
    formula_len = float(min(len(rec.get("formula") or ""), 1000)) / 1000.0
    var_count = float(min(len(rec.get("vars") or []), 50)) / 50.0
    # is_trigger: cwe is known + formula has a comparison op
    cwe_known = rec.get("cwe", "UNKNOWN") != "UNKNOWN"
    has_cmp = any(op in (rec.get("formula") or "")
                  for op in ("<", "<=", ">", ">=", "u<", "u>", "s<", "s>"))
    trigger = 1.0 if (cwe_known and has_cmp) else 0.0
    return np.concatenate([
        emb, cwe,
        np.array([formula_len, var_count, trigger], dtype=np.float32),
    ])


def _label(outcome: str) -> float:
    """Binary label: 1.0 if UNSAT (positive class for predictor), else 0.0."""
    return 1.0 if outcome == "UNSAT" else 0.0


def train(corpus_path: Path, out_path: Path, epochs: int = 5, batch_size: int = 32):
    cfg = NeuralConfig()
    embedder = Embedder(cfg)
    records: List[dict] = [json.loads(l) for l in corpus_path.read_text().splitlines() if l.strip()]
    # Filter examples with known outcomes
    records = [r for r in records if r.get("outcome") in ("SAT", "UNSAT")]
    if not records:
        print("[warn] no labeled records; saving randomly-initialized model")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(UnsatGNN().state_dict(), str(out_path))
        return

    X = np.stack([_features(r, embedder) for r in records])
    y = np.array([_label(r["outcome"]) for r in records], dtype=np.float32)

    Xt = torch.from_numpy(X)
    yt = torch.from_numpy(y)
    n = Xt.shape[0]

    model = UnsatGNN()
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.BCELoss()
    model.train()

    for epoch in range(epochs):
        perm = torch.randperm(n)
        total_loss = 0.0
        for s in range(0, n, batch_size):
            idx = perm[s:s + batch_size]
            xb = Xt[idx]
            yb = yt[idx]
            # Self-loop adjacency: just identity
            adj = torch.eye(xb.shape[0])
            opt.zero_grad()
            target = torch.arange(xb.shape[0])
            pred = model(xb, adj, target_idx=target)
            loss = loss_fn(pred, yb)
            loss.backward()
            opt.step()
            total_loss += float(loss.item()) * xb.shape[0]
        print(f"epoch {epoch + 1}/{epochs}  loss={total_loss / n:.4f}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), str(out_path))
    print(f"saved predictor to {out_path}")


def _main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--corpus", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--epochs", type=int, default=5)
    p.add_argument("--batch-size", type=int, default=32)
    args = p.parse_args()
    train(args.corpus, args.out, args.epochs, args.batch_size)


if __name__ == "__main__":
    _main()
