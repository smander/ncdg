"""RQ14: ablation - which neural component earns its keep?

Variants:
  symbolic_only    : alpha=1.0, predictor=None
  plus_f_theta     : alpha=0.5, predictor=None
  plus_g_phi       : alpha=1.0, predictor=UnsatPredictor
  full_ns_cdg      : alpha=0.5, predictor=UnsatPredictor

Reports per variant: cross-version reuse %, Z3-call reduction %, F1 detection.

Sampled to SAMPLE_SIZE nodes per side for tractable smoke runs.

Output: experiments/rq14_results.json
"""

import json
import random
from pathlib import Path

from cdg_lib.graph import CDG
from cdg_lib.solver import solve
from cdg_lib.types import SolverOutcome
from cdg_lib.analysis import similarity
from cdg_lib.neural.config import NeuralConfig
from cdg_lib.neural.embedder import Embedder
from cdg_lib.neural.predictor import UnsatPredictor
from cdg_lib.neural.reachability import has_trigger_pattern
from firmware.config import UBOOT_VERSIONS
from firmware.extractor import FirmwareExtractor


SAMPLE_SIZE = 100
SEED = 0


def _build_cdg(version: str, cve_id: str) -> CDG:
    target = next(v for v in UBOOT_VERSIONS if v.git_tag == version)
    cve = next(c for c in target.cves if c.cve_id == cve_id)
    binary = f"firmware/binaries/uboot/{version}/u-boot"
    extractor = FirmwareExtractor(binary_path=binary)
    g = CDG()
    for n in extractor.extract_for_cve(target, cve):
        g.store(n, [])
    return g


def _sample_nodes(cdg: CDG, n: int):
    """Stratified: include trigger nodes + random non-triggers."""
    triggers = [nid for nid, node in cdg.nodes.items() if has_trigger_pattern(node)]
    non_triggers = [nid for nid in cdg.nodes if nid not in set(triggers)]
    rng = random.Random(SEED)
    n_t = min(len(triggers), max(1, n // 4))
    n_nt = n - n_t
    chosen_triggers = rng.sample(triggers, n_t) if triggers else []
    chosen_non = rng.sample(non_triggers, min(n_nt, len(non_triggers)))
    chosen_ids = chosen_triggers + chosen_non
    return [cdg.nodes[i] for i in chosen_ids]


def _reuse_pct(vuln_nodes, patched_nodes, embedder, alpha: float) -> float:
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


def _z3_reduction(g: CDG, sample_ids, predictor) -> float:
    short = 0
    for nid in sample_ids:
        out, _ = solve(g, nid, predictor=predictor, tau_unsat=0.95)
        if out == SolverOutcome.UNSAT_PREDICTED:
            short += 1
        g._solve_cache.clear()
    return short / len(sample_ids) if sample_ids else 0.0


def _f1_detection(g: CDG, sample_ids) -> float:
    """Trigger-node detection F1 (ground-truth: has_trigger_pattern)."""
    tp = fp = fn = 0
    for nid in sample_ids:
        n = g.nodes[nid]
        is_trigger = has_trigger_pattern(n)
        # Detected as vulnerable if outcome == SAT and is_trigger
        detected = (n.outcome == SolverOutcome.SAT)
        if detected and is_trigger:
            tp += 1
        elif detected and not is_trigger:
            fp += 1
        elif not detected and is_trigger:
            fn += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    return 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0


def _eval_variant(vuln_cdg, vuln_nodes, vuln_ids, patched_nodes,
                  embedder, predictor, alpha) -> dict:
    return {
        "reuse_pct": _reuse_pct(vuln_nodes, patched_nodes, embedder, alpha),
        "z3_reduction_pct": _z3_reduction(vuln_cdg, vuln_ids, predictor),
        "f1_detection": _f1_detection(vuln_cdg, vuln_ids),
    }


def main():
    cfg = NeuralConfig()
    embedder = Embedder(cfg)
    predictor = UnsatPredictor(cfg)
    cve = "CVE-2022-34835"
    vuln_cdg = _build_cdg("v2022.04", cve)
    patched_cdg = _build_cdg("v2022.07", cve)
    vuln_nodes = _sample_nodes(vuln_cdg, SAMPLE_SIZE)
    patched_nodes = _sample_nodes(patched_cdg, SAMPLE_SIZE)
    vuln_ids = [n.node_id for n in vuln_nodes]
    for n in vuln_nodes + patched_nodes:
        if n.embedding is None:
            n.embedding = embedder.embed(n.formula)

    variants = {
        "symbolic_only": _eval_variant(vuln_cdg, vuln_nodes, vuln_ids,
                                        patched_nodes, None, None, alpha=1.0),
        "plus_f_theta": _eval_variant(vuln_cdg, vuln_nodes, vuln_ids,
                                       patched_nodes, embedder, None, alpha=0.5),
        "plus_g_phi": _eval_variant(vuln_cdg, vuln_nodes, vuln_ids,
                                     patched_nodes, None, predictor, alpha=1.0),
        "full_ns_cdg": _eval_variant(vuln_cdg, vuln_nodes, vuln_ids,
                                      patched_nodes, embedder, predictor, alpha=0.5),
    }
    results = {"cve_id": cve, "sample_size": SAMPLE_SIZE, "variants": variants}
    out = Path("experiments/rq14_results.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
