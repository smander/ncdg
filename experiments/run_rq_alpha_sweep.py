"""RQ15: alpha sensitivity sweep.

For alpha in {0, 0.25, 0.5, 0.75, 1.0}, measure cross-version reuse % on
the U-Boot CVE-2022-34835 pair.

Output: experiments/rq15_results.json
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


SAMPLE_SIZE = 100
SEED = 0


def _build_cdg(version, cve_id) -> CDG:
    target = next(v for v in UBOOT_VERSIONS if v.git_tag == version)
    cve = next(c for c in target.cves if c.cve_id == cve_id)
    binary = f"firmware/binaries/uboot/{version}/u-boot"
    extractor = FirmwareExtractor(binary_path=binary)
    g = CDG()
    for n in extractor.extract_for_cve(target, cve):
        g.store(n, [])
    return g


def _sample(cdg, n):
    rng = random.Random(SEED)
    ids = list(cdg.nodes.keys())
    chosen = rng.sample(ids, n) if len(ids) > n else ids
    return [cdg.nodes[i] for i in chosen]


def _reuse(vuln_nodes, patched_nodes, embedder, alpha) -> float:
    if not vuln_nodes:
        return 0.0
    carried = 0
    for v in vuln_nodes:
        for p in patched_nodes:
            if similarity(v, p, embedder=embedder if alpha < 1.0 else None,
                          alpha=alpha) > 0.6:
                carried += 1
                break
    return carried / len(vuln_nodes)


def main():
    cve = "CVE-2022-34835"
    vuln = _build_cdg("v2022.04", cve)
    patched = _build_cdg("v2022.07", cve)
    embedder = Embedder(NeuralConfig())
    vuln_nodes = _sample(vuln, SAMPLE_SIZE)
    patched_nodes = _sample(patched, SAMPLE_SIZE)
    for n in vuln_nodes + patched_nodes:
        if n.embedding is None:
            n.embedding = embedder.embed(n.formula)

    sweep = []
    for alpha in [0.0, 0.25, 0.5, 0.75, 1.0]:
        sweep.append({"alpha": alpha,
                      "reuse_pct": _reuse(vuln_nodes, patched_nodes, embedder, alpha)})

    results = {"cve_id": cve, "sample_size": SAMPLE_SIZE, "sweep": sweep}
    out = Path("experiments/rq15_results.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
