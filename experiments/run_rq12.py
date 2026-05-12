"""RQ12: Z3-call reduction Pareto curve over tau_unsat.

For each tau_unsat in {0.7, 0.8, 0.9, 0.95, 0.99}:
  - Solve every node in a CDG using the integrated solver (with predictor)
  - Count: total Z3 calls vs. UNSAT_PREDICTED short-circuits
  - Record the vulnerability-detection recall (how many trigger nodes had
    Z3 verdict UNSAT, vs. how many were short-circuited via UNSAT_PREDICTED)

For smoke runs we sample SAMPLE_SIZE nodes per CDG.

Output: experiments/rq12_results.json
"""

import json
import random
from pathlib import Path

from cdg_lib.graph import CDG
from cdg_lib.solver import solve
from cdg_lib.types import SolverOutcome
from cdg_lib.neural.config import NeuralConfig
from cdg_lib.neural.embedder import Embedder
from cdg_lib.neural.predictor import UnsatPredictor
from cdg_lib.neural.reachability import has_trigger_pattern
from firmware.config import UBOOT_VERSIONS
from firmware.extractor import FirmwareExtractor


SAMPLE_SIZE = 200
SEED = 0


class _Z3CallCounter:
    """Wrap the auto backend; count solve_node calls."""

    def __init__(self):
        from cdg_lib.backends import get_backend
        self.inner = get_backend("auto")
        self.calls = 0

    def solve_node(self, formula, variables, var_types):
        self.calls += 1
        return self.inner.solve_node(formula, variables, var_types)


def _build_cdg() -> CDG:
    target = next(v for v in UBOOT_VERSIONS if v.git_tag == "v2022.04")
    cve = next(c for c in target.cves if c.cve_id == "CVE-2022-34835")
    binary = "firmware/binaries/uboot/v2022.04/u-boot"
    extractor = FirmwareExtractor(binary_path=binary)
    g = CDG()
    for n in extractor.extract_for_cve(target, cve):
        g.store(n, [])
    return g


def _sample_node_ids(g: CDG, n: int):
    """Stratified sample: include all triggers + random non-triggers.

    Triggers are rare in real-angr extractions; uniform random sampling
    misses them. Stratification ensures trigger_recall is measurable.
    """
    triggers = [nid for nid, node in g.nodes.items() if has_trigger_pattern(node)]
    non_triggers = [nid for nid in g.nodes if nid not in set(triggers)]
    rng = random.Random(SEED)
    n_t = min(len(triggers), max(1, n // 4))
    n_nt = n - n_t
    chosen_triggers = rng.sample(triggers, n_t) if triggers else []
    chosen_non = rng.sample(non_triggers, min(n_nt, len(non_triggers)))
    return chosen_triggers + chosen_non


def _run_with_tau(g: CDG, predictor, tau_unsat: float, sample_ids) -> dict:
    counter = _Z3CallCounter()
    short_circuit = 0
    triggers_total = 0
    triggers_z3 = 0
    for nid in sample_ids:
        node = g.nodes[nid]
        is_trigger = has_trigger_pattern(node)
        if is_trigger:
            triggers_total += 1
        out, _ = solve(g, nid, backend=counter, predictor=predictor, tau_unsat=tau_unsat)
        if out == SolverOutcome.UNSAT_PREDICTED:
            short_circuit += 1
        if is_trigger and out == SolverOutcome.UNSAT:
            triggers_z3 += 1
        # Reset solver cache so each node is independently measured
        g._solve_cache.clear()
    total = len(sample_ids)
    return {
        "tau_unsat": tau_unsat,
        "z3_calls": counter.calls,
        "short_circuits": short_circuit,
        "z3_call_reduction_pct": short_circuit / total if total else 0.0,
        "trigger_recall": triggers_z3 / triggers_total if triggers_total else 1.0,
    }


def main():
    g = _build_cdg()
    cfg = NeuralConfig()
    embedder = Embedder(cfg)
    sample_ids = _sample_node_ids(g, SAMPLE_SIZE)
    for nid in sample_ids:
        n = g.nodes[nid]
        if n.embedding is None:
            n.embedding = embedder.embed(n.formula)
    predictor = UnsatPredictor(cfg)

    sweep = []
    for tau in [0.7, 0.8, 0.9, 0.95, 0.99]:
        sweep.append(_run_with_tau(g, predictor, tau, sample_ids))

    results = {
        "node_count": len(g.nodes),
        "sample_size": SAMPLE_SIZE,
        "sweep": sweep,
    }
    out = Path("experiments/rq12_results.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
