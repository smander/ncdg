"""RQ16: soundness audit.

For each (target, version, cve), build a CDG, solve every node with the
integrated predictor, then run audit_soundness() to verify every
UNSAT_PREDICTED node was correctly predicted.

Sampled to SAMPLE_SIZE nodes per CDG for tractable smoke runs.

Output: experiments/rq16_results.json
"""

import json
import random
from pathlib import Path

from cdg_lib.graph import CDG
from cdg_lib.solver import solve
from cdg_lib.neural.config import NeuralConfig
from cdg_lib.neural.embedder import Embedder
from cdg_lib.neural.predictor import UnsatPredictor
from cdg_lib.neural.audit import audit_soundness
from firmware.config import UBOOT_VERSIONS, TFA_VERSIONS
from firmware.extractor import FirmwareExtractor


SAMPLE_SIZE = 100
SEED = 0


def _resolve_binary(target_name: str, version: str):
    fname = "u-boot" if target_name == "uboot" else "bl2.elf"
    p = Path("firmware/binaries") / target_name / version / fname
    return str(p) if p.is_file() else None


def main():
    cfg = NeuralConfig()
    embedder = Embedder(cfg)
    predictor = UnsatPredictor(cfg)
    audits = []
    for target in UBOOT_VERSIONS + TFA_VERSIONS:
        binary = _resolve_binary(target.name, target.git_tag)
        if binary is None:
            continue
        extractor = FirmwareExtractor(binary_path=binary)
        for cve in target.cves:
            g = CDG()
            for n in extractor.extract_for_cve(target, cve):
                g.store(n, [])
            # Sample to keep smoke run tractable
            rng = random.Random(SEED)
            all_ids = list(g.nodes.keys())
            sample_ids = rng.sample(all_ids, SAMPLE_SIZE) if len(all_ids) > SAMPLE_SIZE else all_ids
            for nid in sample_ids:
                n = g.nodes[nid]
                if n.embedding is None:
                    n.embedding = embedder.embed(n.formula)
                solve(g, nid, predictor=predictor, tau_unsat=0.95)
            disagreements = audit_soundness(g)
            n_pred = sum(1 for n in g.nodes.values()
                         if n.outcome.value == "UNSAT_PREDICTED")
            audits.append({
                "target": target.name,
                "version": target.git_tag,
                "cve_id": cve.cve_id,
                "node_count": len(g.nodes),
                "sample_size": len(sample_ids),
                "unsat_predicted_count": n_pred,
                "disagreements": len(disagreements),
                "soundness_rate": (
                    1.0 - len(disagreements) / max(n_pred, 1)
                    if n_pred > 0 else 1.0
                ),
            })

    total_disagreements = sum(a["disagreements"] for a in audits)
    results = {
        "audits": audits,
        "total_disagreements": total_disagreements,
        "verdict": "PASS" if total_disagreements == 0 else "FAIL",
    }
    out = Path("experiments/rq16_results.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
