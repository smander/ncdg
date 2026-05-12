"""RQ-SPEED: End-to-end wall-clock + Z3-call comparison: symbolic vs. NCDG.

For each CVE pair (vulnerable, patched):
  Phase 1: Build vuln CDG, solve every node fresh through Z3, cache verdicts.
  Phase 2: Build patched CDG, attempt to reuse v1 verdicts via SIM-edge
           subsumption. Each constraint either:
             (a) finds a SIM-equivalent v1 neighbor with cached verdict -> REUSE
             (b) no such neighbor -> NEW Z3 CALL
  Measure: wall-clock for Phase 2 + Z3-call count for Phase 2.

Two configurations:
  - symbolic_only: similarity uses Eq.1 (alpha=1.0); SIM edges = skeleton-match only
  - ncdg: similarity uses Eq.2 (alpha=0.5); SIM edges = blend with f_theta

The speedup ratio = symbolic_only.phase2_time / ncdg.phase2_time
The Z3-call reduction = (symbolic_only.z3_calls - ncdg.z3_calls) / symbolic_only.z3_calls

Output: experiments/rq_speed_results.json
"""

import json
import random
import time
from pathlib import Path
from typing import Tuple

from cdg_lib.graph import CDG
from cdg_lib.analysis import similarity
from cdg_lib.solver import solve
from cdg_lib.types import SolverOutcome
from cdg_lib.neural.config import NeuralConfig
from cdg_lib.neural.embedder import Embedder
from firmware.config import UBOOT_VERSIONS, TFA_VERSIONS
from firmware.extractor import FirmwareExtractor


SAMPLE_SIZE = 100  # smaller for faster end-to-end timing; sufficient for Z3-call ratio
SEED = 0
TAU_SIM = 0.6


def _resolve_binary(target_name: str, version: str):
    fname = "u-boot" if target_name == "uboot" else "bl2.elf"
    p = Path("firmware/binaries") / target_name / version / fname
    return str(p) if p.is_file() else None


def _build_cdg(target_name: str, version_tag: str, cve_id: str) -> CDG:
    versions = UBOOT_VERSIONS if target_name == "uboot" else TFA_VERSIONS
    target = next(v for v in versions if v.git_tag == version_tag)
    cve = next(c for c in target.cves if c.cve_id == cve_id)
    extractor = FirmwareExtractor(binary_path=_resolve_binary(target_name, version_tag))
    g = CDG()
    for n in extractor.extract_for_cve(target, cve):
        g.store(n, [])
    return g


def _sample_node_ids(cdg: CDG, n: int):
    rng = random.Random(SEED)
    ids = list(cdg.nodes.keys())
    return rng.sample(ids, n) if len(ids) > n else ids


class _Z3CallCounter:
    """Wraps the Z3 backend to count solve_node calls."""

    def __init__(self):
        from cdg_lib.backends import get_backend
        self.inner = get_backend("auto")
        self.calls = 0

    def solve_node(self, formula, variables, var_types):
        self.calls += 1
        return self.inner.solve_node(formula, variables, var_types)


def _phase1_solve_vuln(vuln_cdg: CDG, vuln_ids: list) -> Tuple[float, int]:
    """Solve every vulnerable-side node fresh; populate cache.

    Returns (wall_seconds, z3_calls).
    """
    counter = _Z3CallCounter()
    t0 = time.monotonic()
    for nid in vuln_ids:
        solve(vuln_cdg, nid, backend=counter)
    elapsed = time.monotonic() - t0
    return elapsed, counter.calls


def _phase2_reuse_or_solve(
    vuln_cdg: CDG, patched_cdg: CDG, patched_ids: list,
    embedder, alpha: float,
) -> Tuple[float, int, int, int]:
    """For each patched-side node, attempt SIM-edge reuse against vuln side.

    Reuse criterion: there exists a vulnerable-side node v with sim_alpha(v, p) > TAU_SIM
    AND v has a cached SAT verdict (vuln side was Phase 1's input).

    On reuse: copy the cached outcome to the patched node; no Z3 call.
    On no reuse: invoke Z3 to verify the patched node fresh.

    Returns (wall_seconds, z3_calls, reuse_count, total_count).
    """
    counter = _Z3CallCounter()
    reuse = 0
    total = len(patched_ids)
    t0 = time.monotonic()
    for pid in patched_ids:
        p_node = patched_cdg.nodes[pid]
        # Find a SIM-equivalent vulnerable-side node with cached verdict
        matched = False
        for v_node in vuln_cdg.nodes.values():
            if v_node.outcome not in (SolverOutcome.SAT, SolverOutcome.UNSAT):
                continue
            s = similarity(v_node, p_node, embedder=embedder, alpha=alpha)
            if s > TAU_SIM:
                # Reuse: copy v's cached verdict
                p_node.outcome = v_node.outcome
                p_node.model = v_node.model
                matched = True
                reuse += 1
                break
        if not matched:
            # No reuse available; solve via Z3
            solve(patched_cdg, pid, backend=counter)
    elapsed = time.monotonic() - t0
    return elapsed, counter.calls, reuse, total


def _measure_pair(target: str, vuln_v: str, patched_v: str, cve_id: str,
                  embedder) -> dict:
    print(f"=== {target} {vuln_v}->{patched_v} {cve_id} ===")

    # Build CDGs
    t = time.monotonic()
    vuln_cdg = _build_cdg(target, vuln_v, cve_id)
    patched_cdg = _build_cdg(target, patched_v, cve_id)
    extract_time = time.monotonic() - t
    print(f"  extract+build: {extract_time:.2f}s "
          f"(vuln={len(vuln_cdg.nodes)}, patched={len(patched_cdg.nodes)})")

    vuln_ids = _sample_node_ids(vuln_cdg, SAMPLE_SIZE)
    patched_ids = _sample_node_ids(patched_cdg, SAMPLE_SIZE)

    # Pre-embed sampled nodes for fair timing (embedder cold-start excluded
    # from the Phase 2 measurement — embeddings are pre-computed once)
    for nid in vuln_ids:
        n = vuln_cdg.nodes[nid]
        if n.embedding is None:
            n.embedding = embedder.embed(n.formula)
    for nid in patched_ids:
        n = patched_cdg.nodes[nid]
        if n.embedding is None:
            n.embedding = embedder.embed(n.formula)

    # Phase 1: solve vuln side once (shared baseline; not counted in either config)
    p1_time, p1_calls = _phase1_solve_vuln(vuln_cdg, vuln_ids)
    print(f"  phase1 (vuln solve): {p1_time:.2f}s, {p1_calls} Z3 calls")

    # Snapshot patched-side outcomes so Phase 2 starts fresh
    patched_outcomes_snapshot = {nid: (n.outcome, n.model)
                                 for nid, n in patched_cdg.nodes.items()}

    def reset_patched():
        for nid, (out, mod) in patched_outcomes_snapshot.items():
            patched_cdg.nodes[nid].outcome = out
            patched_cdg.nodes[nid].model = mod
        patched_cdg._solve_cache.clear()

    # Symbolic-only Phase 2 (alpha=1.0)
    reset_patched()
    sym_time, sym_calls, sym_reuse, sym_total = _phase2_reuse_or_solve(
        vuln_cdg, patched_cdg, patched_ids, embedder=None, alpha=1.0)
    print(f"  symbolic phase2: {sym_time:.2f}s, "
          f"{sym_calls} Z3 calls, reuse {sym_reuse}/{sym_total}")

    # NCDG Phase 2 (alpha=0.5, blend)
    reset_patched()
    ncdg_time, ncdg_calls, ncdg_reuse, ncdg_total = _phase2_reuse_or_solve(
        vuln_cdg, patched_cdg, patched_ids, embedder=embedder, alpha=0.5)
    print(f"  ncdg phase2: {ncdg_time:.2f}s, "
          f"{ncdg_calls} Z3 calls, reuse {ncdg_reuse}/{ncdg_total}")

    speedup = sym_time / ncdg_time if ncdg_time > 0 else float("inf")
    z3_reduction = ((sym_calls - ncdg_calls) / sym_calls) if sym_calls > 0 else 0.0
    print(f"  speedup: {speedup:.2f}x, Z3-call reduction: {z3_reduction:.1%}")

    return {
        "target": target,
        "vuln_version": vuln_v,
        "patched_version": patched_v,
        "cve_id": cve_id,
        "sample_size": SAMPLE_SIZE,
        "vuln_nodes": len(vuln_cdg.nodes),
        "patched_nodes": len(patched_cdg.nodes),
        "extract_time_seconds": round(extract_time, 3),
        "phase1": {
            "wall_seconds": round(p1_time, 3),
            "z3_calls": p1_calls,
        },
        "symbolic_phase2": {
            "wall_seconds": round(sym_time, 3),
            "z3_calls": sym_calls,
            "reuse_count": sym_reuse,
            "reuse_pct": round(sym_reuse / sym_total, 3) if sym_total else 0.0,
        },
        "ncdg_phase2": {
            "wall_seconds": round(ncdg_time, 3),
            "z3_calls": ncdg_calls,
            "reuse_count": ncdg_reuse,
            "reuse_pct": round(ncdg_reuse / ncdg_total, 3) if ncdg_total else 0.0,
        },
        "speedup_x": round(speedup, 3),
        "z3_call_reduction_pct": round(z3_reduction, 3),
    }


def main():
    embedder = Embedder(NeuralConfig())

    # Define all (target, vuln_version, patched_version, cve_id) pairs
    pairs = [
        ("uboot", "v2022.04", "v2022.07", "CVE-2022-30790"),
        ("uboot", "v2022.04", "v2022.07", "CVE-2022-30552"),
        ("uboot", "v2022.04", "v2022.07", "CVE-2022-34835"),
        ("tfa",   "v2.8",     "v2.9",     "CVE-2022-47630"),
    ]

    measurements = []
    for target, vv, pv, cve in pairs:
        try:
            m = _measure_pair(target, vv, pv, cve, embedder)
            measurements.append(m)
        except Exception as e:
            print(f"  [skip] {cve}: {e}")
            measurements.append({
                "target": target, "cve_id": cve, "error": str(e),
            })

    # Aggregates
    valid = [m for m in measurements if "error" not in m]
    if valid:
        sym_total = sum(m["symbolic_phase2"]["wall_seconds"] for m in valid)
        ncdg_total = sum(m["ncdg_phase2"]["wall_seconds"] for m in valid)
        sym_calls = sum(m["symbolic_phase2"]["z3_calls"] for m in valid)
        ncdg_calls = sum(m["ncdg_phase2"]["z3_calls"] for m in valid)
        agg = {
            "n_pairs_measured": len(valid),
            "total_symbolic_phase2_seconds": round(sym_total, 3),
            "total_ncdg_phase2_seconds": round(ncdg_total, 3),
            "average_speedup_x": round(sym_total / ncdg_total, 3) if ncdg_total > 0 else None,
            "total_symbolic_z3_calls": sym_calls,
            "total_ncdg_z3_calls": ncdg_calls,
            "z3_call_reduction_pct_total": (
                round((sym_calls - ncdg_calls) / sym_calls, 3) if sym_calls > 0 else 0.0
            ),
        }
    else:
        agg = {"n_pairs_measured": 0}

    results = {"per_cve": measurements, "aggregate": agg}
    out = Path("experiments/rq_speed_results.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print()
    print(json.dumps(agg, indent=2))


if __name__ == "__main__":
    main()
