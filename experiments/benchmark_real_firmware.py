#!/usr/bin/env python3
"""
Real Firmware CDG Benchmark
============================
Benchmark runner that builds CDGs from real firmware CVE data (U-Boot, TF-A)
using synthetic constraint templates and evaluates CDG construction, solving,
cross-version diffing, vulnerability propagation, and backend parity.

Usage:
  python3 -m experiments.benchmark_real_firmware
"""

import sys
import os
import json
import argparse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from cdg_lib import CDG, ConstraintNode, SolverOutcome, EdgeLabel, CWEClass, make_constraint
from cdg_lib import solver, analysis
from cdg_lib.backends import get_backend
from firmware.config import UBOOT_VERSIONS, TFA_VERSIONS, FirmwareTarget
from firmware.extractor import FirmwareExtractor


# ---------------------------------------------------------------------------
# Vulnerability matrices (ground truth)
# ---------------------------------------------------------------------------

UBOOT_VULN_MATRIX: Dict[str, Dict[str, bool]] = {
    "v2022.04": {
        "CVE-2022-30790": True,
        "CVE-2022-30552": True,
        "CVE-2022-34835": True,
    },
    "v2022.07": {
        "CVE-2022-30790": False,
        "CVE-2022-30552": False,
        "CVE-2022-34835": False,
    },
}

TFA_VULN_MATRIX: Dict[str, Dict[str, bool]] = {
    "v2.8": {
        "CVE-2022-47630": True,
    },
    "v2.9": {
        "CVE-2022-47630": False,
    },
}


# ---------------------------------------------------------------------------
# VersionCDG dataclass
# ---------------------------------------------------------------------------

@dataclass
class VersionCDG:
    """CDG with firmware metadata for benchmark verification."""
    cdg: CDG
    node_roles: Dict[str, str] = field(default_factory=dict)          # node_id -> role
    expected_outcomes: Dict[str, str] = field(default_factory=dict)    # node_id -> "SAT"|"UNSAT"
    vuln_triggers: Dict[str, str] = field(default_factory=dict)        # cve_id -> last node_id
    version: str = ""
    firmware_name: str = ""


# ---------------------------------------------------------------------------
# CDG builder
# ---------------------------------------------------------------------------

def _resolve_binary_path(firmware_name: str, version_tag: str, binaries_dir: str) -> Optional[str]:
    """Return absolute path to the built binary, or None if it doesn't exist."""
    # Phase 0.1: get_ext (CVE-2022-47630 target) lives in BL2, not BL31.
    fname = "u-boot" if firmware_name == "uboot" else "bl2.elf"
    rel = os.path.join(binaries_dir, firmware_name, version_tag, fname)
    abs_path = os.path.abspath(rel)
    return abs_path if os.path.isfile(abs_path) else None


def build_firmware_cdg(firmware_name: str, version_tag: str, binary_path: Optional[str] = None) -> VersionCDG:
    """Build a CDG for a specific firmware name and version tag.

    Looks up the FirmwareTarget in UBOOT_VERSIONS or TFA_VERSIONS,
    extracts constraint nodes for each CVE (using synthetic fallback),
    stores them in a CDG with DEP chains, and returns a VersionCDG.
    """
    # Select the correct versions list
    if firmware_name.lower() in ("uboot", "u-boot"):
        versions_list = UBOOT_VERSIONS
    elif firmware_name.lower() in ("tfa", "trusted-firmware-a"):
        versions_list = TFA_VERSIONS
    else:
        raise ValueError(f"Unknown firmware_name: {firmware_name!r}")

    # Find the matching FirmwareTarget
    target: Optional[FirmwareTarget] = None
    for ft in versions_list:
        if ft.git_tag == version_tag:
            target = ft
            break
    if target is None:
        raise ValueError(
            f"No FirmwareTarget found for firmware={firmware_name!r} version={version_tag!r}"
        )

    extractor = FirmwareExtractor(binary_path=binary_path)
    cdg = CDG(name=f"{firmware_name}_{version_tag}")

    node_roles: Dict[str, str] = {}
    expected_outcomes: Dict[str, str] = {}
    vuln_triggers: Dict[str, str] = {}

    for cve_entry in target.cves:
        cve_id = cve_entry.cve_id
        nodes: List[ConstraintNode] = extractor.extract_for_cve(target, cve_entry)

        prev_id: Optional[str] = None
        last_id: Optional[str] = None

        for node in nodes:
            dep_sources = [prev_id] if prev_id is not None else []
            node_id = cdg.store(node, dep_sources=dep_sources)

            # Infer role from the node's position / formula content
            role = "path_cond"
            formula = node.formula.lower()
            # Heuristic: if the formula has a very high constant (overflow sentinel), it's blocked
            if any(sentinel in node.formula for sentinel in ("65535", "4294967295")):
                role = "trigger_blocked"
            elif "checked" in formula or "validated" in formula:
                role = "guard"
            elif prev_id is not None:
                # Second+ node: if it's the last one, likely a trigger or trigger_blocked
                role = "data_flow"

            node_roles[node_id] = role

            # Default: non-trigger nodes are always expected SAT
            expected_outcomes[node_id] = "SAT"

            prev_id = node_id
            last_id = node_id

        # The last node for this CVE is the vulnerability trigger
        if last_id is not None:
            vuln_triggers[cve_id] = last_id
            # Refine expected outcome for the trigger node
            if cve_entry.vulnerable:
                expected_outcomes[last_id] = "SAT"
            else:
                expected_outcomes[last_id] = "UNSAT"

    return VersionCDG(
        cdg=cdg,
        node_roles=node_roles,
        expected_outcomes=expected_outcomes,
        vuln_triggers=vuln_triggers,
        version=version_tag,
        firmware_name=firmware_name,
    )


# ---------------------------------------------------------------------------
# Test runner helpers
# ---------------------------------------------------------------------------

def _count_edges_by_label(cdg: CDG) -> Dict[str, int]:
    counts: Dict[str, int] = {label.value: 0 for label in EdgeLabel}
    for edge in cdg.edges:
        counts[edge.label.value] += 1
    return counts


def _solve_all_nodes(vcdg: VersionCDG, backend) -> Dict[str, str]:
    """Solve every node in the CDG and return node_id -> outcome string."""
    outcomes: Dict[str, str] = {}
    for node_id in vcdg.cdg.nodes:
        outcome, _ = solver.solve(vcdg.cdg, node_id, backend=backend)
        outcomes[node_id] = outcome.value
    return outcomes


# ---------------------------------------------------------------------------
# Seven-test runner
# ---------------------------------------------------------------------------

def _run_firmware_tests(
    firmware_name: str,
    versions: List[FirmwareTarget],
    vuln_matrix: Dict[str, Dict[str, bool]],
    use_angr: bool = False,
    binaries_dir: str = "firmware/binaries",
) -> Dict:
    """Run all 7 benchmark tests for a firmware family. Returns result dict."""
    results: Dict = {}
    version_tags = [ft.git_tag for ft in versions]

    # ------------------------------------------------------------------
    # Test 1: CDG Construction
    # ------------------------------------------------------------------
    print(f"\n[{firmware_name}] Test 1: CDG Construction")
    construction_results = {}
    vcdgs: Dict[str, VersionCDG] = {}

    for tag in version_tags:
        binary = _resolve_binary_path(firmware_name, tag, binaries_dir) if use_angr else None
        vcdg = build_firmware_cdg(firmware_name, tag, binary_path=binary)
        vcdgs[tag] = vcdg
        edge_counts = _count_edges_by_label(vcdg.cdg)
        construction_results[tag] = {
            "node_count": vcdg.cdg.node_count,
            "edge_counts": edge_counts,
            "cve_triggers": len(vcdg.vuln_triggers),
        }
        print(
            f"  {tag}: nodes={vcdg.cdg.node_count}, "
            f"DEP={edge_counts.get('dep', 0)}, "
            f"SIM={edge_counts.get('sim', 0)}, "
            f"CON={edge_counts.get('con', 0)}, "
            f"triggers={len(vcdg.vuln_triggers)}"
        )

    results["construction"] = construction_results

    # ------------------------------------------------------------------
    # Test 2: Multi-Backend Solving
    # ------------------------------------------------------------------
    print(f"\n[{firmware_name}] Test 2: Multi-Backend Solving")
    solving_results = {}

    for backend_name in ("z3", "smtlib"):
        try:
            be = get_backend(backend_name)
        except RuntimeError:
            print(f"  Backend '{backend_name}' not available — skipping.")
            continue

        backend_outcomes: Dict[str, Dict[str, str]] = {}
        sat_total = 0
        unsat_total = 0

        for tag, vcdg in vcdgs.items():
            # Build a fresh CDG so cache doesn't bleed between backends
            binary = _resolve_binary_path(firmware_name, tag, binaries_dir) if use_angr else None
            fresh_vcdg = build_firmware_cdg(firmware_name, tag, binary_path=binary)
            outcomes = _solve_all_nodes(fresh_vcdg, be)
            backend_outcomes[tag] = outcomes
            for v in outcomes.values():
                if v == "SAT":
                    sat_total += 1
                elif v == "UNSAT":
                    unsat_total += 1

        solving_results[backend_name] = {
            "sat": sat_total,
            "unsat": unsat_total,
            "per_version": backend_outcomes,
        }
        print(f"  {backend_name}: SAT={sat_total}, UNSAT={unsat_total}")

    results["solving"] = solving_results

    # ------------------------------------------------------------------
    # Test 3: UNSAT Detection Accuracy
    # ------------------------------------------------------------------
    print(f"\n[{firmware_name}] Test 3: UNSAT Detection Accuracy")
    accuracy_results = {}

    try:
        be_z3 = get_backend("z3")
    except RuntimeError:
        be_z3 = get_backend("auto")

    for tag, vcdg in vcdgs.items():
        binary = _resolve_binary_path(firmware_name, tag, binaries_dir) if use_angr else None
        fresh_vcdg = build_firmware_cdg(firmware_name, tag, binary_path=binary)
        outcomes = _solve_all_nodes(fresh_vcdg, be_z3)

        correct = 0
        total = 0
        for node_id, expected in fresh_vcdg.expected_outcomes.items():
            actual = outcomes.get(node_id, "UNKNOWN")
            if actual == expected:
                correct += 1
            total += 1

        acc = correct / total if total > 0 else 0.0
        accuracy_results[tag] = {"correct": correct, "total": total, "accuracy": acc}
        print(f"  {tag}: {correct}/{total} correct ({acc:.1%})")

    results["accuracy"] = accuracy_results

    # ------------------------------------------------------------------
    # Test 4: Cross-Version Diff
    # ------------------------------------------------------------------
    print(f"\n[{firmware_name}] Test 4: Cross-Version Diff")
    cross_version_results = {}

    for i in range(len(version_tags) - 1):
        tag_a = version_tags[i]
        tag_b = version_tags[i + 1]
        g1 = vcdgs[tag_a].cdg
        g2 = vcdgs[tag_b].cdg

        diff = analysis.compare(g1, g2)
        total_g2 = g2.node_count
        unchanged = len(diff.unchanged_nodes)
        reuse_pct = (unchanged / total_g2 * 100) if total_g2 > 0 else 0.0

        cross_version_results[f"{tag_a}_to_{tag_b}"] = {
            "added": len(diff.added_nodes),
            "removed": len(diff.removed_nodes),
            "modified": len(diff.modified_nodes),
            "unchanged": unchanged,
            "reuse_pct": reuse_pct,
        }
        print(
            f"  {tag_a} → {tag_b}: added={len(diff.added_nodes)}, "
            f"removed={len(diff.removed_nodes)}, modified={len(diff.modified_nodes)}, "
            f"unchanged={unchanged} (reuse={reuse_pct:.1f}%)"
        )

    results["cross_version"] = cross_version_results

    # ------------------------------------------------------------------
    # Test 5: Vulnerability Propagation
    # ------------------------------------------------------------------
    print(f"\n[{firmware_name}] Test 5: Vulnerability Propagation")
    propagation_results = {}

    for tag, vcdg in vcdgs.items():
        tag_prop: Dict[str, List[str]] = {}
        for cve_id, trigger_id in vcdg.vuln_triggers.items():
            variants = analysis.propagate_detection(vcdg.cdg, trigger_id)
            tag_prop[cve_id] = variants
        propagation_results[tag] = tag_prop
        total_variants = sum(len(v) for v in tag_prop.values())
        print(f"  {tag}: {len(tag_prop)} triggers, {total_variants} propagated variants")

    results["propagation"] = propagation_results

    # ------------------------------------------------------------------
    # Test 6: Solver Shortcut Breakdown
    # ------------------------------------------------------------------
    print(f"\n[{firmware_name}] Test 6: Solver Shortcut Breakdown")
    shortcut_results = {}

    try:
        be_sc = get_backend("z3")
    except RuntimeError:
        be_sc = get_backend("auto")

    for tag in version_tags:
        # Use fresh CDG so cache starts empty
        binary = _resolve_binary_path(firmware_name, tag, binaries_dir) if use_angr else None
        fresh_vcdg = build_firmware_cdg(firmware_name, tag, binary_path=binary)
        cache_hits = 0
        subsumption_hits = 0
        full_solves = 0

        for node_id in fresh_vcdg.cdg.nodes:
            node = fresh_vcdg.cdg.nodes[node_id]
            cache_key = node.formula

            # Check if it will be a cache hit (already solved)
            if cache_key in fresh_vcdg.cdg._solve_cache:
                cache_hits += 1
            else:
                # Check for subsumption
                sub_hit = False
                for edge in fresh_vcdg.cdg._radj.get(node_id, []):
                    if edge.label == EdgeLabel.SIM:
                        other = fresh_vcdg.cdg.nodes[edge.source_id]
                        if (
                            other.outcome == SolverOutcome.SAT
                            and other.model
                            and other.skeleton_hash == node.skeleton_hash
                        ):
                            sub_hit = True
                            break
                if sub_hit:
                    subsumption_hits += 1
                else:
                    full_solves += 1

            # Now actually solve to populate cache/outcomes
            solver.solve(fresh_vcdg.cdg, node_id, backend=be_sc)

        shortcut_results[tag] = {
            "cache_hits": cache_hits,
            "subsumption_hits": subsumption_hits,
            "full_solves": full_solves,
        }
        print(
            f"  {tag}: cache_hits={cache_hits}, "
            f"subsumption={subsumption_hits}, full_solves={full_solves}"
        )

    results["shortcuts"] = shortcut_results

    # ------------------------------------------------------------------
    # Test 7: Backend Parity
    # ------------------------------------------------------------------
    print(f"\n[{firmware_name}] Test 7: Backend Parity")
    parity_results = {}

    try:
        be_a = get_backend("z3")
    except RuntimeError:
        be_a = get_backend("auto")

    try:
        be_b = get_backend("smtlib")
        smtlib_available = True
    except RuntimeError:
        smtlib_available = False

    if not smtlib_available:
        print("  smtlib backend not available — skipping parity test.")
        parity_results["skipped"] = True
    else:
        mismatches_total = 0
        for tag in version_tags:
            binary = _resolve_binary_path(firmware_name, tag, binaries_dir) if use_angr else None
            # Solve with z3 on fresh CDG
            vcdg_a = build_firmware_cdg(firmware_name, tag, binary_path=binary)
            outcomes_a = _solve_all_nodes(vcdg_a, be_a)

            # Solve with smtlib on another fresh CDG
            vcdg_b = build_firmware_cdg(firmware_name, tag, binary_path=binary)
            outcomes_b = _solve_all_nodes(vcdg_b, be_b)

            mismatches = 0
            # Both CDGs have the same structure, compare by position
            node_ids_a = list(vcdg_a.cdg.nodes.keys())
            node_ids_b = list(vcdg_b.cdg.nodes.keys())
            for nid_a, nid_b in zip(node_ids_a, node_ids_b):
                if outcomes_a.get(nid_a) != outcomes_b.get(nid_b):
                    mismatches += 1
            mismatches_total += mismatches
            print(f"  {tag}: mismatches={mismatches}")

        parity_results["mismatches_total"] = mismatches_total
        parity_results["backends_compared"] = ["z3", "smtlib"]

    results["parity"] = parity_results

    return results


# ---------------------------------------------------------------------------
# Top-level benchmark
# ---------------------------------------------------------------------------

def run_real_firmware_benchmark(use_angr: bool = False, binaries_dir: str = "firmware/binaries") -> Dict:
    """Run the full benchmark for uboot and tfa firmware families."""
    print("=" * 60)
    print("Real Firmware CDG Benchmark")
    print("=" * 60)

    uboot_results = _run_firmware_tests("uboot", UBOOT_VERSIONS, UBOOT_VULN_MATRIX, use_angr=use_angr, binaries_dir=binaries_dir)
    tfa_results = _run_firmware_tests("tfa", TFA_VERSIONS, TFA_VULN_MATRIX, use_angr=use_angr, binaries_dir=binaries_dir)

    final = {"uboot": uboot_results, "tfa": tfa_results}

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    for fw, res in final.items():
        construction = res.get("construction", {})
        total_nodes = sum(v.get("node_count", 0) for v in construction.values())
        solving = res.get("solving", {})
        z3_res = solving.get("z3", {})
        sat = z3_res.get("sat", "N/A")
        unsat = z3_res.get("unsat", "N/A")
        print(
            f"  {fw}: total_nodes={total_nodes}, z3_SAT={sat}, z3_UNSAT={unsat}"
        )

    return final


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Real-firmware CDG benchmark (synthetic by default; --use-angr for real extraction)."
    )
    parser.add_argument(
        "--use-angr", action="store_true",
        help="Use real angr extraction on built binaries (default: synthetic only)",
    )
    parser.add_argument(
        "--binaries-dir", default="firmware/binaries",
        help="Directory containing built binaries (default: firmware/binaries)",
    )
    parser.add_argument(
        "--no-neural", action="store_true",
        help="Disable neural similarity (NS-CDG kill-switch). Reverts to "
             "published symbolic baseline.",
    )
    parser.add_argument(
        "--use-neural", action="store_true",
        help="Enable neural similarity + UNSAT predictor in the solver path. "
             "Mutually exclusive with --no-neural.",
    )
    args = parser.parse_args()

    if args.use_neural and args.no_neural:
        parser.error("--use-neural and --no-neural are mutually exclusive")

    results = run_real_firmware_benchmark(
        use_angr=args.use_angr,
        binaries_dir=args.binaries_dir,
    )

    output_filename = (
        "benchmark_real_firmware_angr_results.json"
        if args.use_angr
        else "benchmark_real_firmware_results.json"
    )
    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        output_filename,
    )

    def _make_serialisable(obj):
        if isinstance(obj, dict):
            return {k: _make_serialisable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_make_serialisable(v) for v in obj]
        if isinstance(obj, set):
            return sorted(_make_serialisable(v) for v in obj)
        return obj

    with open(out_path, "w") as f:
        json.dump(_make_serialisable(results), f, indent=2)

    print(f"\nResults saved to {out_path}")
