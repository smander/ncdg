#!/usr/bin/env python3
"""
Multi-Version CDG Benchmark
============================
Integration benchmark running the full CDG pipeline on all 4 benchmark versions
(v1.0 through v1.3) with real vulnerability evolution.

Tests:
  1. Constraint extraction per version (version-accurate)
  2. CDG construction: node/edge counts, SIM edge induction
  3. Similarity detection: cross-function similarity within each version
  4. 1->N propagation: detect V1, verify V2/V3 found via SIM edges
  5. Multi-backend solving: Z3 native, SmtLib, propagator
  6. Cross-version diff: compare consecutive versions
  7. Multi-backend parity: verify all backends agree
  8. Similarity threshold sweep: find optimal SIM threshold
  9. DEP chain analysis: backward slicing depth and scaling
  10. Solver shortcut breakdown: cache/subsumption/conflict/full-solve stats
  11. Propagation across all versions: verify ground truth
  12. UNSAT detection accuracy: expected vs actual outcomes
  13. Optimal SIM threshold via propagation F1

Usage:
  python3 -m experiments.benchmark_multiversion
"""

import sys
import os
import time
import json
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Set

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cdg_lib import (
    CDG, ConstraintNode, BinaryLocation, SolverOutcome, EdgeLabel, CWEClass,
    make_constraint, Monitor,
)
from cdg_lib import solver, analysis, propagator
from cdg_lib.backends import get_backend


# ================================================================
# VERSION CDG WRAPPER
# ================================================================

@dataclass
class VersionCDG:
    """CDG with metadata for benchmark verification."""
    cdg: CDG
    node_roles: Dict[str, str] = field(default_factory=dict)          # node_id -> role
    expected_outcomes: Dict[str, str] = field(default_factory=dict)    # node_id -> "SAT"|"UNSAT"
    vuln_triggers: Dict[str, str] = field(default_factory=dict)       # "V1" -> node_id
    version: str = ""


# ================================================================
# VERSION DEFINITIONS: Constraint-accurate per source version
# ================================================================

# Version evolution matrix (ground truth)
#  Vuln | Function           | CWE     | v1.0 | v1.1    | v1.2    | v1.3
#  V1   | msg_process_alpha  | CWE-125 | Vuln | Patched | Patched | Patched
#  V2   | msg_process_beta   | CWE-125 | Vuln | Vuln    | Patched | Patched
#  V3   | msg_process_gamma  | CWE-125 | Vuln | Vuln    | Vuln    | Patched
#  V4   | buffer_copy        | CWE-787 | Vuln | Vuln    | Vuln    | Patched
#  V5   | msg_cleanup        | CWE-416 | Safe | Safe    | Intro   | Vuln
#  V6   | calc_offset        | CWE-190 | Safe | Safe    | Safe    | Intro

VULN_MATRIX = {
    "v1.0": {"V1": True,  "V2": True,  "V3": True,  "V4": True,  "V5": False, "V6": False},
    "v1.1": {"V1": False, "V2": True,  "V3": True,  "V4": True,  "V5": False, "V6": False},
    "v1.2": {"V1": False, "V2": False, "V3": True,  "V4": True,  "V5": True,  "V6": False},
    "v1.3": {"V1": False, "V2": False, "V3": False, "V4": False, "V5": True,  "V6": True},
}

# Vulnerability definitions: (function, cwe, base_bb, base_addr)
VULN_DEFS = {
    "V1": ("msg_process_alpha", CWEClass.CWE_125, 3, 0x1000),
    "V2": ("msg_process_beta",  CWEClass.CWE_125, 5, 0x2000),
    "V3": ("msg_process_gamma", CWEClass.CWE_125, 7, 0x3000),
    "V4": ("buffer_copy",       CWEClass.CWE_787, 2, 0x4000),
    "V5": ("msg_cleanup",       CWEClass.CWE_416, 4, 0x5000),
    "V6": ("calc_offset",       CWEClass.CWE_190, 1, 0x6000),
}


def _build_vuln_chain(g: CDG, func: str, cwe: CWEClass, base_bb: int,
                      base_addr: int, version: str, vulnerable: bool,
                      vuln_id: str) -> Tuple[List[str], str]:
    """
    Build a multi-node DEP chain for a vulnerability.

    Vulnerable: path_cond -> data_flow -> trigger (all SAT on bv16)
    Patched:    path_cond -> guard -> trigger_blocked (trigger UNSAT on bv16)

    Returns: (list_of_node_ids, trigger_node_id)
    """
    node_ids = []

    if vuln_id in ("V1", "V2", "V3"):
        # CWE-125 out-of-bounds read vulnerabilities
        if vulnerable:
            # Node 1: path_cond  — msg_len >= 8 (SAT)
            n1_id = g.store(make_constraint(
                "msg_len >= 8", "VAR >= CONST", cwe,
                func, base_bb, base_addr, version,
                {"msg_len"}, {"msg_len": "bv16"}))
            node_ids.append(n1_id)

            # Node 2: data_flow — index >= 0 (SAT)
            n2_id = g.store(make_constraint(
                "index >= 0", "VAR >= CONST", cwe,
                func, base_bb + 1, base_addr + 0x10, version,
                {"index"}, {"index": "bv16"}),
                dep_sources=[n1_id])
            node_ids.append(n2_id)

            # Node 3: trigger — index >= 32 (SAT)
            n3_id = g.store(make_constraint(
                "index >= 32", "VAR >= CONST", cwe,
                func, base_bb + 2, base_addr + 0x20, version,
                {"index"}, {"index": "bv16"}),
                dep_sources=[n2_id])
            node_ids.append(n3_id)
            return node_ids, n3_id
        else:
            # Patched: guard check added, trigger made UNSAT
            # Node 1: path_cond — msg_len >= 8 (SAT, same location)
            n1_id = g.store(make_constraint(
                "msg_len >= 8", "VAR >= CONST", cwe,
                func, base_bb, base_addr, version,
                {"msg_len"}, {"msg_len": "bv16"}))
            node_ids.append(n1_id)

            # Node 2: guard — checked >= 1 (SAT, different skeleton)
            n2_id = g.store(make_constraint(
                "checked >= 1", "VAR >= CONST", cwe,
                func, base_bb + 1, base_addr + 0x10, version,
                {"checked"}, {"checked": "bv16"}),
                dep_sources=[n1_id])
            node_ids.append(n2_id)

            # Node 3: trigger_blocked — index > 65535 (UNSAT on bv16!)
            #   UGT(bv16, 0xFFFF) is impossible
            n3_id = g.store(make_constraint(
                "index > 65535", "VAR > CONST", cwe,
                func, base_bb + 2, base_addr + 0x20, version,
                {"index"}, {"index": "bv16"}),
                dep_sources=[n2_id])
            node_ids.append(n3_id)
            return node_ids, n3_id

    elif vuln_id == "V4":
        # CWE-787 buffer overflow
        if vulnerable:
            n1_id = g.store(make_constraint(
                "length >= 1", "VAR >= CONST", cwe,
                func, base_bb, base_addr, version,
                {"length"}, {"length": "bv16"}))
            node_ids.append(n1_id)

            n2_id = g.store(make_constraint(
                "length > 256", "VAR > CONST", cwe,
                func, base_bb + 1, base_addr + 0x10, version,
                {"length"}, {"length": "bv16"}),
                dep_sources=[n1_id])
            node_ids.append(n2_id)
            return node_ids, n2_id
        else:
            n1_id = g.store(make_constraint(
                "length >= 1", "VAR >= CONST", cwe,
                func, base_bb, base_addr, version,
                {"length"}, {"length": "bv16"}))
            node_ids.append(n1_id)

            # Patched: length > 65535 is UNSAT on bv16
            n2_id = g.store(make_constraint(
                "length > 65535", "VAR > CONST", cwe,
                func, base_bb + 1, base_addr + 0x10, version,
                {"length"}, {"length": "bv16"}),
                dep_sources=[n1_id])
            node_ids.append(n2_id)
            return node_ids, n2_id

    elif vuln_id == "V5":
        # CWE-416 use-after-free
        # Only present when vulnerable (v1.2, v1.3)
        n1_id = g.store(make_constraint(
            "freed >= 1", "VAR >= CONST", cwe,
            func, base_bb, base_addr, version,
            {"freed"}, {"freed": "bv16"}))
        node_ids.append(n1_id)

        n2_id = g.store(make_constraint(
            "accessed >= 1", "VAR >= CONST", cwe,
            func, base_bb + 1, base_addr + 0x10, version,
            {"accessed"}, {"accessed": "bv16"}),
            dep_sources=[n1_id])
        node_ids.append(n2_id)
        return node_ids, n2_id

    elif vuln_id == "V6":
        # CWE-190 integer overflow
        # Only present when vulnerable (v1.3)
        n1_id = g.store(make_constraint(
            "base >= 256", "VAR >= CONST", cwe,
            func, base_bb, base_addr, version,
            {"base"}, {"base": "bv16"}))
        node_ids.append(n1_id)

        n2_id = g.store(make_constraint(
            "mult >= 256", "VAR >= CONST", cwe,
            func, base_bb + 1, base_addr + 0x10, version,
            {"mult"}, {"mult": "bv16"}),
            dep_sources=[n1_id])
        node_ids.append(n2_id)
        return node_ids, n2_id

    return node_ids, ""


def build_version_cdg(version: str) -> VersionCDG:
    """Build a CDG with version-accurate constraints matching the C source."""
    g = CDG(version)
    vuln = VULN_MATRIX[version]

    node_roles = {}
    expected_outcomes = {}
    vuln_triggers = {}

    # Build vulnerability chains
    for vid, (func, cwe, base_bb, base_addr) in VULN_DEFS.items():
        is_vuln = vuln[vid]

        # V5 and V6 are only present when vulnerable
        if vid in ("V5", "V6") and not is_vuln:
            continue

        chain_ids, trigger_id = _build_vuln_chain(
            g, func, cwe, base_bb, base_addr, version, is_vuln, vid)

        if not chain_ids:
            continue

        vuln_triggers[vid] = trigger_id

        # Assign roles
        if vid in ("V1", "V2", "V3"):
            if is_vuln:
                node_roles[chain_ids[0]] = "path_cond"
                node_roles[chain_ids[1]] = "data_flow"
                node_roles[chain_ids[2]] = "trigger"
                for nid in chain_ids:
                    expected_outcomes[nid] = "SAT"
            else:
                node_roles[chain_ids[0]] = "path_cond"
                node_roles[chain_ids[1]] = "guard"
                node_roles[chain_ids[2]] = "trigger_blocked"
                expected_outcomes[chain_ids[0]] = "SAT"
                expected_outcomes[chain_ids[1]] = "SAT"
                expected_outcomes[chain_ids[2]] = "UNSAT"
        elif vid == "V4":
            if is_vuln:
                node_roles[chain_ids[0]] = "path_cond"
                node_roles[chain_ids[1]] = "trigger"
                for nid in chain_ids:
                    expected_outcomes[nid] = "SAT"
            else:
                node_roles[chain_ids[0]] = "path_cond"
                node_roles[chain_ids[1]] = "trigger_blocked"
                expected_outcomes[chain_ids[0]] = "SAT"
                expected_outcomes[chain_ids[1]] = "UNSAT"
        elif vid in ("V5", "V6"):
            node_roles[chain_ids[0]] = "data_flow"
            node_roles[chain_ids[1]] = "trigger"
            for nid in chain_ids:
                expected_outcomes[nid] = "SAT"

    # Gradient-producing auxiliary nodes
    # Alpha aux: vars={offset, limit}, types={offset:bv16, limit:bv32}, CWE-125
    aux1_id = g.store(make_constraint(
        "offset >= 0", "VAR >= CONST", CWEClass.CWE_125,
        "aux_alpha", 10, 0xA000, version,
        {"offset", "limit"}, {"offset": "bv16", "limit": "bv32"}))
    node_roles[aux1_id] = "aux_alpha"
    expected_outcomes[aux1_id] = "SAT"

    # Buffer aux: vars={offset}, types={offset:bv16}, CWE-787
    aux2_id = g.store(make_constraint(
        "offset >= 0", "VAR >= CONST", CWEClass.CWE_787,
        "aux_buffer", 11, 0xB000, version,
        {"offset"}, {"offset": "bv16"}))
    node_roles[aux2_id] = "aux_buffer"
    expected_outcomes[aux2_id] = "SAT"

    return VersionCDG(
        cdg=g,
        node_roles=node_roles,
        expected_outcomes=expected_outcomes,
        vuln_triggers=vuln_triggers,
        version=version,
    )


# ================================================================
# BENCHMARK SECTIONS
# ================================================================

def bench_cdg_construction(versions: Dict[str, VersionCDG]) -> List[dict]:
    """Section 1-2: Build CDGs, report node/edge counts."""
    print("\n  [1] CDG Construction")
    print("  " + "-" * 60)
    print(f"  {'Version':<10} {'Nodes':>6} {'DEP':>6} {'SIM':>6} {'CON':>6} {'Total':>6}")

    results = []
    for ver_name, vcdg in versions.items():
        g = vcdg.cdg
        n_nodes = g.node_count
        dep = sim = con = 0
        for nid in g.nodes:
            for edge in g._adj.get(nid, []):
                if edge.label == EdgeLabel.DEP:
                    dep += 1
                elif edge.label == EdgeLabel.SIM:
                    sim += 1
                elif edge.label == EdgeLabel.CON:
                    con += 1
        total_edges = dep + sim + con
        print(f"  {ver_name:<10} {n_nodes:>6} {dep:>6} {sim:>6} {con:>6} {total_edges:>6}")
        results.append({
            "version": ver_name, "nodes": n_nodes,
            "dep_edges": dep, "sim_edges": sim, "con_edges": con,
            "total_edges": total_edges,
        })
    return results


def bench_similarity(versions: Dict[str, VersionCDG]) -> List[dict]:
    """Section 3: Cross-function similarity within each version."""
    print("\n  [2] Similarity Detection")
    print("  " + "-" * 60)

    results = []
    for ver_name, vcdg in versions.items():
        g = vcdg.cdg
        node_ids = list(g.nodes.keys())
        pairs_checked = 0
        high_sim_pairs = []
        sim_values_seen = set()

        for i, nid1 in enumerate(node_ids):
            for nid2 in node_ids[i + 1:]:
                c1 = g.nodes[nid1]
                c2 = g.nodes[nid2]
                sim = analysis.similarity(c1, c2)
                pairs_checked += 1
                if sim > 0.0:
                    sim_values_seen.add(round(sim, 2))
                if sim > 0.5:
                    high_sim_pairs.append((
                        c1.location.function, c2.location.function, sim
                    ))

        print(f"  {ver_name}: {pairs_checked} pairs checked, "
              f"{len(high_sim_pairs)} high-similarity (>0.5), "
              f"distinct values: {sorted(sim_values_seen)}")
        for func1, func2, sim in high_sim_pairs:
            print(f"    {func1} <-> {func2}: {sim:.2f}")

        results.append({
            "version": ver_name,
            "pairs_checked": pairs_checked,
            "high_sim_count": len(high_sim_pairs),
            "distinct_sim_values": sorted(sim_values_seen),
            "high_sim_pairs": [
                {"f1": f1, "f2": f2, "sim": s} for f1, f2, s in high_sim_pairs
            ],
        })
    return results


def bench_propagation(versions: Dict[str, VersionCDG]) -> List[dict]:
    """Section 4: 1->N propagation -- detect V1, find V2/V3 via SIM edges."""
    print("\n  [3] 1-to-N Propagation (v1.0)")
    print("  " + "-" * 60)

    vcdg = versions["v1.0"]
    g = vcdg.cdg
    results = []

    # Find V1 trigger node
    v1_trigger = vcdg.vuln_triggers.get("V1")
    if v1_trigger is None:
        print("  ERROR: V1 trigger node not found")
        return results

    propagated = analysis.propagate_detection(g, v1_trigger)
    propagated_funcs = {g.nodes[nid].location.function for nid in propagated}

    expected = {"msg_process_beta", "msg_process_gamma"}
    found = propagated_funcs & expected
    missed = expected - propagated_funcs
    # Exclude the seed's own function — intra-function SIM edges are expected
    extra = propagated_funcs - expected - {"msg_process_alpha"}

    print(f"  Seed: msg_process_alpha (V1 trigger)")
    print(f"  Found via SIM: {found or '{none}'}")
    print(f"  Missed: {missed or '{none}'}")
    print(f"  Extra: {extra or '{none}'}")

    correct = found == expected and not extra
    print(f"  Propagation correct: {'YES' if correct else 'NO'}")

    results.append({
        "seed": "msg_process_alpha",
        "found": sorted(found),
        "missed": sorted(missed),
        "extra": sorted(extra),
        "correct": correct,
    })
    return results


def bench_solving(versions: Dict[str, VersionCDG]) -> List[dict]:
    """Section 5: Solve all nodes with multiple backends."""
    print("\n  [4] Multi-Backend Solving")
    print("  " + "-" * 60)

    # Discover available backends
    backend_names = []
    backends = {}

    # Z3 native
    try:
        backends["z3"] = get_backend("z3")
        backend_names.append("z3")
    except RuntimeError:
        pass

    # SMT-LIB (try to find a solver on PATH)
    try:
        backends["smtlib"] = get_backend("smtlib")
        backend_names.append("smtlib")
    except RuntimeError:
        pass

    if not backend_names:
        print("  WARNING: No real backends available, using mock")
        backends["mock"] = get_backend("mock")
        backend_names.append("mock")

    print(f"  Backends: {', '.join(backend_names)}")

    results = []
    for ver_name, vcdg in versions.items():
        g = vcdg.cdg
        ver_results = {"version": ver_name, "backends": {}}

        for be_name in backend_names:
            be = backends[be_name]
            t0 = time.time()
            outcomes = {}

            for nid in g.nodes:
                outcome, model = solver.solve(g, nid, backend=be)
                outcomes[nid] = outcome.name

            elapsed = time.time() - t0
            sat_count = sum(1 for o in outcomes.values() if o == "SAT")
            unsat_count = sum(1 for o in outcomes.values() if o == "UNSAT")
            unknown_count = sum(1 for o in outcomes.values() if o == "UNKNOWN")

            ver_results["backends"][be_name] = {
                "sat": sat_count, "unsat": unsat_count, "unknown": unknown_count,
                "time_s": round(elapsed, 4),
            }

            # Clear cache between backends to force fresh solves
            g._solve_cache.clear()
            for node in g.nodes.values():
                node.outcome = None
                node.model = None

        print(f"  {ver_name}: " + ", ".join(
            f"{be}={ver_results['backends'][be]['sat']}SAT/{ver_results['backends'][be]['unsat']}UNSAT"
            for be in backend_names
        ))
        results.append(ver_results)

    # Shutdown backends
    for be in backends.values():
        be.shutdown()

    return results


def bench_propagator_batch(versions: Dict[str, VersionCDG]) -> List[dict]:
    """Section 5b: Batch solving via Z3 user propagator."""
    print("\n  [5] Propagator Batch Solve")
    print("  " + "-" * 60)

    results = []
    for ver_name, vcdg in versions.items():
        g = vcdg.cdg

        # Clear any prior solve state
        g._solve_cache.clear()
        for node in g.nodes.values():
            node.outcome = None
            node.model = None

        node_ids = list(g.nodes.keys())
        t0 = time.time()

        try:
            batch_results = propagator.solve_with_propagator(g, node_ids)
            elapsed = time.time() - t0

            sat_count = sum(1 for o, _ in batch_results.values() if o == SolverOutcome.SAT)
            unsat_count = sum(1 for o, _ in batch_results.values() if o == SolverOutcome.UNSAT)

            print(f"  {ver_name}: {sat_count} SAT, {unsat_count} UNSAT ({elapsed:.4f}s)")
            results.append({
                "version": ver_name, "sat": sat_count, "unsat": unsat_count,
                "time_s": round(elapsed, 4),
            })
        except Exception as e:
            print(f"  {ver_name}: propagator failed: {e}")
            results.append({"version": ver_name, "error": str(e)})

    return results


def bench_cross_version_diff(versions: Dict[str, VersionCDG]) -> List[dict]:
    """Section 6: Cross-version diff -- compare consecutive versions."""
    print("\n  [6] Cross-Version Diff")
    print("  " + "-" * 60)
    print(f"  {'Transition':<15} {'Total':>6} {'Carried':>8} {'Modified':>10} {'New':>5} {'Removed':>8} {'Savings':>8}")

    ver_list = list(versions.items())
    results = []

    for i in range(len(ver_list)):
        ver_name, vcdg = ver_list[i]
        g = vcdg.cdg
        if i == 0:
            print(f"  {'v1.0 (base)':<15} {g.node_count:>6} {'—':>8} {'—':>10} {g.node_count:>5} {'—':>8} {'0%':>8}")
            results.append({
                "transition": "v1.0 (base)", "total": g.node_count,
                "carried": 0, "modified": 0, "new": g.node_count, "removed": 0,
                "savings": 0.0,
            })
        else:
            prev_name, prev_vcdg = ver_list[i - 1]
            diff = analysis.compare(prev_vcdg.cdg, g)
            carried = len(diff.unchanged_nodes)
            modified = len(diff.modified_nodes)
            new = len(diff.added_nodes)
            removed = len(diff.removed_nodes)
            total = g.node_count
            savings = carried / total if total > 0 else 0

            transition = f"{prev_name}->{ver_name}"
            print(f"  {transition:<15} {total:>6} {carried:>8} {modified:>10} {new:>5} {removed:>8} {savings:>7.0%}")
            results.append({
                "transition": transition, "total": total,
                "carried": carried, "modified": modified,
                "new": new, "removed": removed,
                "savings": savings,
            })

    avg_savings = sum(r["savings"] for r in results[1:]) / max(len(results) - 1, 1)
    print(f"\n  Average incremental savings: {avg_savings:.0%}")
    return results


def bench_backend_parity(versions: Dict[str, VersionCDG]) -> List[dict]:
    """Section 7: Verify all backends agree on every constraint."""
    print("\n  [7] Multi-Backend Parity Check")
    print("  " + "-" * 60)

    # Collect available backends
    backend_names = []
    backends = {}
    try:
        backends["z3"] = get_backend("z3")
        backend_names.append("z3")
    except RuntimeError:
        pass
    try:
        backends["smtlib"] = get_backend("smtlib")
        backend_names.append("smtlib")
    except RuntimeError:
        pass

    if len(backend_names) < 2:
        print("  SKIP: Need at least 2 backends for parity check")
        return [{"skipped": True, "reason": "insufficient backends"}]

    results = []
    total_checks = 0
    mismatches = 0

    for ver_name, vcdg in versions.items():
        g = vcdg.cdg
        for nid, node in g.nodes.items():
            outcomes = {}
            for be_name in backend_names:
                be = backends[be_name]
                outcome, _ = be.solve_node(
                    node.formula, node.variables, node.var_types
                )
                outcomes[be_name] = outcome.name

            total_checks += 1
            unique_outcomes = set(outcomes.values()) - {"UNKNOWN"}
            if len(unique_outcomes) > 1:
                mismatches += 1
                print(f"  MISMATCH {ver_name}/{node.location.function}: {outcomes}")

    parity = mismatches == 0
    print(f"  Checked: {total_checks}, Mismatches: {mismatches}, Parity: {'PASS' if parity else 'FAIL'}")

    for be in backends.values():
        be.shutdown()

    results.append({
        "total_checks": total_checks,
        "mismatches": mismatches,
        "parity": parity,
    })
    return results


# ================================================================
# NEW EXPERIMENTS (8-13)
# ================================================================

def bench_similarity_threshold_sweep(versions: Dict[str, VersionCDG]) -> List[dict]:
    """Section 8: Sweep SIM threshold 0.1->1.0, find optimal via precision/recall."""
    print("\n  [8] Similarity Threshold Sweep")
    print("  " + "-" * 60)

    # Ground truth: which node pairs should be SIM-connected
    # Two nodes should be SIM-connected if they are triggers of the same
    # vulnerability type (same skeleton) in the same version
    results = []

    for ver_name, vcdg in versions.items():
        g = vcdg.cdg
        node_ids = list(g.nodes.keys())

        # Compute all pairwise similarities
        pair_sims = {}
        for i, nid1 in enumerate(node_ids):
            for nid2 in node_ids[i + 1:]:
                sim = analysis.similarity(g.nodes[nid1], g.nodes[nid2])
                pair_sims[(nid1, nid2)] = sim

        # Ground truth: nodes with same skeleton AND same CWE should be SIM
        ground_truth_sim = set()
        for (nid1, nid2), sim in pair_sims.items():
            n1, n2 = g.nodes[nid1], g.nodes[nid2]
            if (n1.formula_skeleton == n2.formula_skeleton and
                    n1.cwe_class == n2.cwe_class and
                    n1.location.function != n2.location.function):
                ground_truth_sim.add((nid1, nid2))

        sweep_results = []
        for threshold_int in range(1, 11):
            threshold = threshold_int / 10.0
            tp = fp = fn = 0
            for pair, sim in pair_sims.items():
                is_gt = pair in ground_truth_sim
                would_edge = sim >= threshold
                if would_edge and is_gt:
                    tp += 1
                elif would_edge and not is_gt:
                    fp += 1
                elif not would_edge and is_gt:
                    fn += 1

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

            sweep_results.append({
                "threshold": threshold,
                "tp": tp, "fp": fp, "fn": fn,
                "precision": round(precision, 3),
                "recall": round(recall, 3),
                "f1": round(f1, 3),
            })

        # Find optimal
        best = max(sweep_results, key=lambda x: x["f1"])
        print(f"  {ver_name}: optimal threshold={best['threshold']:.1f}, "
              f"F1={best['f1']:.3f} (P={best['precision']:.3f}, R={best['recall']:.3f})")

        results.append({
            "version": ver_name,
            "sweep": sweep_results,
            "optimal_threshold": best["threshold"],
            "optimal_f1": best["f1"],
        })

    return results


def bench_dep_chain_analysis(versions: Dict[str, VersionCDG]) -> List[dict]:
    """Section 9: DEP chain depth analysis via backward slicing."""
    print("\n  [9] DEP Chain Analysis")
    print("  " + "-" * 60)

    results = []
    for ver_name, vcdg in versions.items():
        g = vcdg.cdg
        chain_depths = {}

        for nid in g.nodes:
            sliced = analysis.slice_back(g, nid)
            depth = sliced.node_count
            chain_depths[nid] = depth

        max_depth = max(chain_depths.values()) if chain_depths else 0
        avg_depth = sum(chain_depths.values()) / len(chain_depths) if chain_depths else 0

        print(f"  {ver_name}: max_depth={max_depth}, avg_depth={avg_depth:.1f}, "
              f"nodes={len(chain_depths)}")

        results.append({
            "version": ver_name,
            "max_depth": max_depth,
            "avg_depth": round(avg_depth, 2),
            "chain_depths": {nid: d for nid, d in chain_depths.items()},
        })

    # Synthetic scaling test: build chains of depth 1,2,3,5,10
    print("\n  DEP Chain Scaling Test:")
    scaling_results = []
    for depth in [1, 2, 3, 5, 10]:
        synth = CDG(f"synth_depth_{depth}")
        prev_id = None
        for d in range(depth):
            nid = synth.store(
                make_constraint(
                    f"x >= {d}", "VAR >= CONST", CWEClass.CWE_125,
                    "synth_func", d, 0x8000 + d * 0x10, "synth",
                    {"x"}, {"x": "bv16"}),
                dep_sources=[prev_id] if prev_id else None)
            prev_id = nid

        # Measure slice_back from last node
        t0 = time.time()
        for _ in range(100):
            analysis.slice_back(synth, prev_id)
        elapsed = (time.time() - t0) / 100

        print(f"    depth={depth:>2}: slice_back={elapsed*1000:.3f}ms")
        scaling_results.append({
            "depth": depth,
            "slice_back_ms": round(elapsed * 1000, 4),
        })

    results.append({"scaling": scaling_results})
    return results


def bench_solver_shortcut_breakdown(versions: Dict[str, VersionCDG]) -> List[dict]:
    """Section 10: Track which solver shortcut fires for each node."""
    print("\n  [10] Solver Shortcut Breakdown")
    print("  " + "-" * 60)

    results = []
    for ver_name, vcdg in versions.items():
        g = vcdg.cdg

        # Clear all solve state
        g._solve_cache.clear()
        for node in g.nodes.values():
            node.outcome = None
            node.model = None

        cache_hits = 0
        subsumption_hits = 0
        full_solves = 0
        unsat_conflicts = 0

        node_ids = list(g.nodes.keys())
        for nid in node_ids:
            node = g.nodes[nid]
            cache_key = node.formula

            # Check if cache would hit
            if cache_key in g._solve_cache:
                cache_hits += 1
                outcome, model = g._solve_cache[cache_key]
                node.outcome = outcome
                node.model = model
                continue

            # Check subsumption
            subsumed = False
            for edge in g._radj.get(nid, []):
                if edge.label == EdgeLabel.SIM:
                    other = g.nodes[edge.source_id]
                    if other.outcome == SolverOutcome.SAT and other.model:
                        if other.skeleton_hash == node.skeleton_hash:
                            subsumption_hits += 1
                            node.outcome = SolverOutcome.SAT
                            node.model = other.model
                            g._solve_cache[cache_key] = (SolverOutcome.SAT, other.model)
                            subsumed = True
                            break
            if subsumed:
                continue

            # Full solve
            full_solves += 1
            outcome, model = solver.solve(g, nid)
            if outcome == SolverOutcome.UNSAT:
                unsat_conflicts += 1

        total = len(node_ids)
        print(f"  {ver_name}: cache={cache_hits}, subsumption={subsumption_hits}, "
              f"full_solve={full_solves}, unsat_conflict={unsat_conflicts}, total={total}")

        results.append({
            "version": ver_name,
            "cache_hits": cache_hits,
            "subsumption_hits": subsumption_hits,
            "full_solves": full_solves,
            "unsat_conflicts": unsat_conflicts,
            "total": total,
        })

    return results


def bench_propagation_all_versions(versions: Dict[str, VersionCDG]) -> List[dict]:
    """Section 11: Run propagation from each SAT trigger in ALL versions."""
    print("\n  [11] Propagation Across All Versions")
    print("  " + "-" * 60)

    results = []
    for ver_name, vcdg in versions.items():
        g = vcdg.cdg
        vuln = VULN_MATRIX[ver_name]

        # First solve all nodes to set outcomes
        g._solve_cache.clear()
        for node in g.nodes.values():
            node.outcome = None
            node.model = None

        try:
            be = get_backend("z3")
        except RuntimeError:
            be = get_backend("mock")

        for nid in g.nodes:
            solver.solve(g, nid, backend=be)
        be.shutdown()

        # For each SAT trigger, propagate and compare to ground truth
        ver_results = {"version": ver_name, "propagations": []}

        for vid, trigger_id in vcdg.vuln_triggers.items():
            trigger_node = g.nodes.get(trigger_id)
            if not trigger_node or trigger_node.outcome != SolverOutcome.SAT:
                continue

            propagated = analysis.propagate_detection(g, trigger_id)
            propagated_funcs = {g.nodes[nid].location.function for nid in propagated}

            # Expected: other vulnerable functions with same skeleton (SIM-connected)
            # In v1.0: V1/V2/V3 have same "VAR >= CONST" skeleton + CWE-125
            trigger_func = trigger_node.location.function
            expected_funcs = set()
            for other_vid, other_trigger in vcdg.vuln_triggers.items():
                if other_vid == vid:
                    continue
                other_node = g.nodes.get(other_trigger)
                if other_node and other_node.outcome == SolverOutcome.SAT:
                    sim = analysis.similarity(trigger_node, other_node)
                    if sim >= 0.8:
                        expected_funcs.add(other_node.location.function)

            found = propagated_funcs & expected_funcs
            missed = expected_funcs - propagated_funcs

            print(f"  {ver_name}/{vid}: seed={trigger_func}, "
                  f"propagated={len(propagated)}, "
                  f"found={sorted(found)}, missed={sorted(missed)}")

            ver_results["propagations"].append({
                "vuln_id": vid,
                "seed_function": trigger_func,
                "propagated_count": len(propagated),
                "found": sorted(found),
                "missed": sorted(missed),
                "correct": not missed,
            })

        results.append(ver_results)

    return results


def bench_unsat_detection(versions: Dict[str, VersionCDG]) -> List[dict]:
    """Section 12: Verify every node's actual solver outcome matches expected."""
    print("\n  [12] UNSAT Detection Accuracy")
    print("  " + "-" * 60)

    results = []
    for ver_name, vcdg in versions.items():
        g = vcdg.cdg

        # Clear and re-solve
        g._solve_cache.clear()
        for node in g.nodes.values():
            node.outcome = None
            node.model = None

        try:
            be = get_backend("z3")
        except RuntimeError:
            be = get_backend("mock")

        for nid in g.nodes:
            solver.solve(g, nid, backend=be)
        be.shutdown()

        correct = 0
        wrong = 0
        details = []

        for nid, expected in vcdg.expected_outcomes.items():
            node = g.nodes.get(nid)
            if not node:
                continue
            actual = node.outcome.name if node.outcome else "NONE"
            is_correct = actual == expected

            if is_correct:
                correct += 1
            else:
                wrong += 1
                details.append({
                    "node_id": nid,
                    "function": node.location.function,
                    "expected": expected,
                    "actual": actual,
                    "formula": node.formula,
                })

        total = correct + wrong
        accuracy = correct / total if total > 0 else 0.0
        print(f"  {ver_name}: {correct}/{total} correct ({accuracy:.0%})")

        if details:
            for d in details:
                print(f"    WRONG: {d['function']}: expected={d['expected']}, "
                      f"actual={d['actual']}, formula={d['formula']}")

        results.append({
            "version": ver_name,
            "correct": correct,
            "wrong": wrong,
            "total": total,
            "accuracy": round(accuracy, 3),
            "mismatches": details,
        })

    return results


def bench_optimal_sim_threshold(versions: Dict[str, VersionCDG]) -> List[dict]:
    """Section 13: Find optimal SIM threshold by simulating propagation F1."""
    print("\n  [13] Optimal SIM Threshold (Propagation F1)")
    print("  " + "-" * 60)

    # For each threshold, simulate: if we built SIM edges at this threshold,
    # starting from each known-vuln seed, BFS over would-be SIM edges,
    # compare reached set to ground truth vulnerable functions.

    results = []
    for ver_name, vcdg in versions.items():
        g = vcdg.cdg
        vuln = VULN_MATRIX[ver_name]

        # Ground truth: which functions are vulnerable in this version
        gt_vuln_funcs = set()
        for vid, is_vuln in vuln.items():
            if is_vuln:
                func, _, _, _ = VULN_DEFS[vid]
                gt_vuln_funcs.add(func)

        node_ids = list(g.nodes.keys())

        # Precompute all pairwise similarities
        pair_sims = {}
        for i, nid1 in enumerate(node_ids):
            for nid2 in node_ids[i + 1:]:
                sim = analysis.similarity(g.nodes[nid1], g.nodes[nid2])
                if sim > 0:
                    pair_sims[(nid1, nid2)] = sim
                    pair_sims[(nid2, nid1)] = sim

        sweep_results = []
        for threshold_int in range(1, 11):
            threshold = threshold_int / 10.0

            # Build adjacency at this threshold
            adj_at_threshold: Dict[str, Set[str]] = {nid: set() for nid in node_ids}
            for (nid1, nid2), sim in pair_sims.items():
                if sim >= threshold:
                    adj_at_threshold[nid1].add(nid2)

            # BFS from each trigger of a known-vuln
            reached_funcs = set()
            for vid, trigger_id in vcdg.vuln_triggers.items():
                if not vuln.get(vid, False):
                    continue
                # BFS
                visited = set()
                queue = [trigger_id]
                while queue:
                    curr = queue.pop(0)
                    if curr in visited:
                        continue
                    visited.add(curr)
                    for neighbor in adj_at_threshold.get(curr, set()):
                        if neighbor not in visited:
                            queue.append(neighbor)
                for nid in visited:
                    reached_funcs.add(g.nodes[nid].location.function)

            # Compare to ground truth
            tp = len(reached_funcs & gt_vuln_funcs)
            fp = len(reached_funcs - gt_vuln_funcs)
            fn = len(gt_vuln_funcs - reached_funcs)

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

            sweep_results.append({
                "threshold": threshold,
                "tp": tp, "fp": fp, "fn": fn,
                "precision": round(precision, 3),
                "recall": round(recall, 3),
                "f1": round(f1, 3),
            })

        best = max(sweep_results, key=lambda x: x["f1"])
        print(f"  {ver_name}: optimal threshold={best['threshold']:.1f}, "
              f"F1={best['f1']:.3f} (P={best['precision']:.3f}, R={best['recall']:.3f})")

        results.append({
            "version": ver_name,
            "sweep": sweep_results,
            "optimal_threshold": best["threshold"],
            "optimal_f1": best["f1"],
        })

    # Overall best threshold (average F1 across versions)
    if results:
        threshold_f1s = {}
        for threshold_int in range(1, 11):
            threshold = threshold_int / 10.0
            avg_f1 = 0
            for r in results:
                for s in r["sweep"]:
                    if abs(s["threshold"] - threshold) < 0.01:
                        avg_f1 += s["f1"]
            avg_f1 /= len(results)
            threshold_f1s[threshold] = avg_f1

        best_global = max(threshold_f1s.items(), key=lambda x: x[1])
        print(f"\n  Global optimal: threshold={best_global[0]:.1f}, avg_F1={best_global[1]:.3f}")

    return results


# ================================================================
# SUMMARY TABLE
# ================================================================

def print_summary(all_results: dict):
    """Print paper-ready summary table."""
    print("\n" + "=" * 70)
    print("  MULTI-VERSION BENCHMARK SUMMARY")
    print("=" * 70)

    # Vulnerability matrix
    print("\n  Vulnerability Evolution Matrix:")
    print(f"  {'Vuln':<6} {'Function':<22} {'CWE':<10} {'v1.0':<8} {'v1.1':<8} {'v1.2':<8} {'v1.3':<8}")
    print("  " + "-" * 70)
    vuln_info = [
        ("V1", "msg_process_alpha", "CWE-125"),
        ("V2", "msg_process_beta",  "CWE-125"),
        ("V3", "msg_process_gamma", "CWE-125"),
        ("V4", "buffer_copy",       "CWE-787"),
        ("V5", "msg_cleanup",       "CWE-416"),
        ("V6", "calc_offset",       "CWE-190"),
    ]
    for vid, func, cwe in vuln_info:
        row = f"  {vid:<6} {func:<22} {cwe:<10}"
        for ver in ["v1.0", "v1.1", "v1.2", "v1.3"]:
            present = VULN_MATRIX[ver].get(vid, False)
            prev_versions = {"v1.1": "v1.0", "v1.2": "v1.1", "v1.3": "v1.2"}
            status = "Vuln"
            if not present:
                status = "Safe" if ver == "v1.0" or not VULN_MATRIX.get(prev_versions.get(ver, ""), {}).get(vid, False) else "Fixed"
            elif ver != "v1.0" and not VULN_MATRIX.get(prev_versions.get(ver, ""), {}).get(vid, False):
                status = "NEW"
            row += f" {status:<8}"
        print(row)

    # CDG metrics
    if "construction" in all_results:
        print("\n  CDG Metrics:")
        print(f"  {'Version':<10} {'Nodes':>6} {'DEP':>6} {'SIM':>6} {'CON':>6} {'Total':>6}")
        for r in all_results["construction"]:
            print(f"  {r['version']:<10} {r['nodes']:>6} {r['dep_edges']:>6} "
                  f"{r['sim_edges']:>6} {r['con_edges']:>6} {r['total_edges']:>6}")

    # UNSAT counts from solving
    if "solving" in all_results:
        print("\n  Solver Results (first backend):")
        print(f"  {'Version':<10} {'SAT':>6} {'UNSAT':>6}")
        for r in all_results["solving"]:
            be_name = list(r["backends"].keys())[0] if r["backends"] else None
            if be_name:
                be_data = r["backends"][be_name]
                print(f"  {r['version']:<10} {be_data['sat']:>6} {be_data['unsat']:>6}")

    # Cross-version savings
    if "cross_version" in all_results:
        diffs = all_results["cross_version"]
        if len(diffs) > 1:
            avg = sum(r["savings"] for r in diffs[1:]) / (len(diffs) - 1)
            print(f"\n  Cross-version avg savings: {avg:.0%}")

    # Propagation (v1.0)
    if "propagation" in all_results and all_results["propagation"]:
        prop = all_results["propagation"][0]
        print(f"\n  Propagation (v1.0): seed=alpha, found={prop.get('found', [])}, "
              f"correct={'YES' if prop.get('correct') else 'NO'}")

    # UNSAT detection accuracy
    if "unsat_detection" in all_results:
        print("\n  UNSAT Detection Accuracy:")
        for r in all_results["unsat_detection"]:
            print(f"  {r['version']}: {r['correct']}/{r['total']} ({r['accuracy']:.0%})")

    # Propagation across all versions
    if "propagation_all" in all_results:
        print("\n  Propagation (all versions):")
        for r in all_results["propagation_all"]:
            n_correct = sum(1 for p in r["propagations"] if p["correct"])
            n_total = len(r["propagations"])
            print(f"  {r['version']}: {n_correct}/{n_total} propagations correct")

    # Optimal threshold
    if "optimal_threshold" in all_results and all_results["optimal_threshold"]:
        print("\n  Optimal SIM Threshold:")
        for r in all_results["optimal_threshold"]:
            print(f"  {r['version']}: threshold={r['optimal_threshold']:.1f}, "
                  f"F1={r['optimal_f1']:.3f}")

    # Backend parity
    if "parity" in all_results and all_results["parity"]:
        p = all_results["parity"][0]
        if not p.get("skipped"):
            mismatch_count = p['mismatches']
            status = "PASS" if p['parity'] else f"FAIL ({mismatch_count} mismatches)"
            print(f"\n  Backend parity: {p['total_checks']} checks, {status}")

    print("\n" + "=" * 70)


# ================================================================
# MAIN
# ================================================================

def run_benchmark() -> dict:
    print("=" * 70)
    print("  Multi-Version CDG Benchmark")
    print("  Versions: v1.0, v1.1, v1.2, v1.3")
    print("=" * 70)

    # Build all version CDGs
    versions: Dict[str, VersionCDG] = {}
    for ver in ["v1.0", "v1.1", "v1.2", "v1.3"]:
        versions[ver] = build_version_cdg(ver)

    all_results = {}

    # Run all benchmark sections
    all_results["construction"] = bench_cdg_construction(versions)
    all_results["similarity"] = bench_similarity(versions)
    all_results["propagation"] = bench_propagation(versions)
    all_results["solving"] = bench_solving(versions)
    all_results["propagator"] = bench_propagator_batch(versions)
    all_results["cross_version"] = bench_cross_version_diff(versions)
    all_results["parity"] = bench_backend_parity(versions)

    # New experiments (8-13)
    all_results["threshold_sweep"] = bench_similarity_threshold_sweep(versions)
    all_results["dep_chain"] = bench_dep_chain_analysis(versions)
    all_results["shortcut_breakdown"] = bench_solver_shortcut_breakdown(versions)
    all_results["propagation_all"] = bench_propagation_all_versions(versions)
    all_results["unsat_detection"] = bench_unsat_detection(versions)
    all_results["optimal_threshold"] = bench_optimal_sim_threshold(versions)

    # Summary
    print_summary(all_results)

    # Save results
    output_path = os.path.join(os.path.dirname(__file__), "benchmark_multiversion_results.json")
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\n  Results saved to: {output_path}")

    return all_results


if __name__ == "__main__":
    run_benchmark()
