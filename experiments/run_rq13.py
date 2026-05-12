"""RQ13: OOD generalization of f_theta.

Reuses experiments/eval_embedder.py logic but stratifies the evaluation by
target binary and reports per-CVE F1.

Output: experiments/rq13_results.json
"""

import json
from pathlib import Path

from experiments.eval_embedder import _load_traces, _sample_pairs, _cosine
from cdg_lib.neural.config import NeuralConfig
from cdg_lib.neural.embedder import Embedder


def _per_cve_f1(traces, embedder, threshold=0.5, n_pos=20, n_neg=20, seed=0):
    """For each CVE family, sample pairs and compute F1.

    Positives: same-CVE, different-version pairs (within `family`).
    Negatives: cross-CVE pairs (one from family, one from any OTHER CVE).
    The negative side must source from outside the family, otherwise the
    while-loop in eval_embedder._sample_pairs spins forever (all entries
    have the same CVE).

    Uses an in-process embedding cache to avoid re-embedding the same
    formula across pair samples.
    """
    import random
    from collections import defaultdict

    cves = sorted({t["cve_id"] for t in traces})
    emb_cache: dict = {}

    def _emb(text):
        if text not in emb_cache:
            emb_cache[text] = embedder.embed(text)
        return emb_cache[text]

    by_cve_version = defaultdict(list)
    for t in traces:
        by_cve_version[(t["cve_id"], t["version"])].append(t)

    out = {}
    rng = random.Random(seed)

    for cve in cves:
        family_keys = [k for k in by_cve_version if k[0] == cve]
        if len(family_keys) < 2:
            continue
        other_keys = [k for k in by_cve_version if k[0] != cve]
        if not other_keys:
            continue

        pos = []
        for _ in range(n_pos):
            ka, kb = rng.sample(family_keys, 2)
            a = rng.choice(by_cve_version[ka])
            b = rng.choice(by_cve_version[kb])
            pos.append((a, b, 1))

        neg = []
        for _ in range(n_neg):
            ka = rng.choice(family_keys)
            kb = rng.choice(other_keys)
            a = rng.choice(by_cve_version[ka])
            b = rng.choice(by_cve_version[kb])
            neg.append((a, b, 0))

        pairs = pos + neg
        tp = fp = fn = tn = 0
        for a, b, label in pairs:
            ea = _emb(a["formula"])
            eb = _emb(b["formula"])
            s = _cosine(ea, eb)
            pred = 1 if s >= threshold else 0
            if pred == 1 and label == 1: tp += 1
            elif pred == 1 and label == 0: fp += 1
            elif pred == 0 and label == 1: fn += 1
            else: tn += 1
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        out[cve] = {"f1": f1, "precision": prec, "recall": rec, "n_pairs": len(pairs)}
    return out


def main():
    traces = _load_traces(Path("data/real_angr_traces.jsonl"))
    embedder = Embedder(NeuralConfig())
    results = {
        "n_traces": len(traces),
        "per_cve": _per_cve_f1(traces, embedder),
    }
    out = Path("experiments/rq13_results.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
