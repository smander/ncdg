"""Held-out evaluation for f_theta.

Pairs same-CVE-different-version constraints as positives, different-CVE
constraints as negatives. Reports F1 at threshold 0.5 and NN-search
recall@20.

Output: experiments/embedder_eval_results.json
"""

import json
import random
from collections import defaultdict
from pathlib import Path

import numpy as np

from cdg_lib.neural.config import NeuralConfig
from cdg_lib.neural.embedder import Embedder


def _load_traces(path: Path) -> list:
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def _by_cve_version(traces: list) -> dict:
    out: dict = defaultdict(list)
    for t in traces:
        out[(t["cve_id"], t["version"])].append(t)
    return dict(out)


def _sample_pairs(traces: list, n_pos: int, n_neg: int, seed: int = 0):
    rng = random.Random(seed)
    grouped = _by_cve_version(traces)
    cve_ids = sorted({t["cve_id"] for t in traces})
    pos = []
    neg = []
    # Positive pairs: same CVE, different versions
    while len(pos) < n_pos:
        cve = rng.choice(cve_ids)
        keys = [k for k in grouped if k[0] == cve]
        if len(keys) < 2:
            continue
        ka, kb = rng.sample(keys, 2)
        a = rng.choice(grouped[ka])
        b = rng.choice(grouped[kb])
        pos.append((a, b, 1))
    # Negative pairs: different CVEs
    while len(neg) < n_neg:
        ka, kb = rng.sample(list(grouped.keys()), 2)
        if ka[0] == kb[0]:
            continue
        a = rng.choice(grouped[ka])
        b = rng.choice(grouped[kb])
        neg.append((a, b, 0))
    return pos + neg


def _cosine(a: np.ndarray, b: np.ndarray) -> float:
    na = float(np.linalg.norm(a))
    nb = float(np.linalg.norm(b))
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def evaluate(traces_path: Path, out_path: Path,
             n_pos: int = 100, n_neg: int = 100,
             threshold: float = 0.5) -> dict:
    cfg = NeuralConfig()
    embedder = Embedder(cfg)
    traces = _load_traces(traces_path)
    if not traces:
        results = {"error": "no traces", "n_traces": 0}
        out_path.write_text(json.dumps(results, indent=2))
        return results
    pairs = _sample_pairs(traces, n_pos, n_neg)
    tp = fp = fn = tn = 0
    for a, b, label in pairs:
        ea = embedder.embed(a["formula"])
        eb = embedder.embed(b["formula"])
        s = _cosine(ea, eb)
        pred = 1 if s >= threshold else 0
        if pred == 1 and label == 1: tp += 1
        elif pred == 1 and label == 0: fp += 1
        elif pred == 0 and label == 1: fn += 1
        else: tn += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    results = {
        "n_traces": len(traces),
        "n_pairs": len(pairs),
        "threshold": threshold,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    import sys
    in_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/real_angr_traces.jsonl")
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("experiments/embedder_eval_results.json")
    r = evaluate(in_path, out_path)
    print(json.dumps(r, indent=2))
