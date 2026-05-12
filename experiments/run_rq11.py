"""RQ11: Cross-version reuse on real binaries — symbolic vs. neural blend.

Builds two CDGs (vuln + patched), measures reuse % at three alpha settings:
  alpha = 1.0 -> pure symbolic (skeleton match)
  alpha = 0.5 -> blend
  alpha = 0.0 -> pure neural (cosine sim of embeddings)

Reuse is measured per node: a vulnerable-side node 'carries' if any
patched-side node has similarity > tau_sim with it.

Note: real-angr extractions can produce thousands of nodes per CVE.
We sample SAMPLE_SIZE nodes from each side to keep the O(N^2) reuse
measurement tractable for smoke runs. Production runs should use a
FAISS index for full coverage.

Output: experiments/rq11_results.json
"""

import json
import random
from pathlib import Path

from cdg_lib.graph import CDG
from cdg_lib.analysis import similarity
from cdg_lib.neural.config import NeuralConfig
from cdg_lib.neural.embedder import Embedder
from firmware.config import UBOOT_VERSIONS
from firmware.extractor import FirmwareExtractor


SAMPLE_SIZE = 200  # nodes per side
SEED = 0


def _resolve_binary(version: str):
    p = Path("firmware/binaries") / "uboot" / version / "u-boot"
    return str(p) if p.is_file() else None


def _build_cdg(version_tag: str, cve_id: str) -> CDG:
    target = next(v for v in UBOOT_VERSIONS if v.git_tag == version_tag)
    cve = next(c for c in target.cves if c.cve_id == cve_id)
    extractor = FirmwareExtractor(binary_path=_resolve_binary(version_tag))
    g = CDG()
    for n in extractor.extract_for_cve(target, cve):
        g.store(n, [])
    return g


def _sample_nodes(cdg: CDG, n: int):
    rng = random.Random(SEED)
    ids = list(cdg.nodes.keys())
    if len(ids) <= n:
        return [cdg.nodes[i] for i in ids]
    chosen = rng.sample(ids, n)
    return [cdg.nodes[i] for i in chosen]


def _reuse_percentage(vuln_sample, patched_sample,
                      embedder, alpha: float, tau_sim: float = 0.6) -> float:
    if not vuln_sample:
        return 0.0
    carried = 0
    for v_node in vuln_sample:
        for p_node in patched_sample:
            s = similarity(v_node, p_node, embedder=embedder, alpha=alpha)
            if s > tau_sim:
                carried += 1
                break
    return carried / len(vuln_sample)


def main():
    cve_id = "CVE-2022-34835"  # smaller extraction; faster experiment
    vuln_cdg = _build_cdg("v2022.04", cve_id)
    patched_cdg = _build_cdg("v2022.07", cve_id)
    embedder = Embedder(NeuralConfig())

    vuln_sample = _sample_nodes(vuln_cdg, SAMPLE_SIZE)
    patched_sample = _sample_nodes(patched_cdg, SAMPLE_SIZE)

    # Pre-embed the sampled nodes once
    for n in vuln_sample + patched_sample:
        if n.embedding is None:
            n.embedding = embedder.embed(n.formula)

    results = {
        "cve_id": cve_id,
        "vuln_version": "v2022.04",
        "patched_version": "v2022.07",
        "vuln_node_count": len(vuln_cdg.nodes),
        "patched_node_count": len(patched_cdg.nodes),
        "sample_size": SAMPLE_SIZE,
        "reuse_pct_symbolic_alpha_1.0": _reuse_percentage(
            vuln_sample, patched_sample, embedder, 1.0),
        "reuse_pct_blend_alpha_0.5": _reuse_percentage(
            vuln_sample, patched_sample, embedder, 0.5),
        "reuse_pct_neural_alpha_0.0": _reuse_percentage(
            vuln_sample, patched_sample, embedder, 0.0),
    }

    out = Path("experiments/rq11_results.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
