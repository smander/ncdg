"""Loader for the synthetic conflict-heavy benchmark.

Reads pair manifests, parses SMT-LIB files, and constructs a CDG with the
DEP and CON edges declared in the manifest. Pre-marks the conflict-source
node as UNSAT so the runtime CON-edge invariant holds without invoking Z3.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List

from cdg_lib.graph import CDG
from cdg_lib.models import ConstraintNode, BinaryLocation
from cdg_lib.types import CWEClass, EdgeLabel, SolverOutcome


@dataclass(frozen=True)
class PairRef:
    theme: str
    pair_id: str
    directory: Path


def list_pairs(root: Path) -> List[PairRef]:
    """Enumerate every pair_NN directory under each theme."""
    pairs: List[PairRef] = []
    for theme_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        if theme_dir.name.startswith("."):
            continue
        for pair_dir in sorted(p for p in theme_dir.iterdir() if p.is_dir()):
            if (pair_dir / "manifest.json").is_file():
                pairs.append(PairRef(theme_dir.name, pair_dir.name, pair_dir))
    return pairs


def _read_formula(path: Path) -> str:
    return path.read_text().strip()


def _cwe(label: str) -> CWEClass:
    try:
        return CWEClass(label)
    except ValueError:
        return CWEClass.UNKNOWN


def load_pair(ref: PairRef) -> CDG:
    """Build the CDG declared by ref's manifest."""
    manifest = json.loads((ref.directory / "manifest.json").read_text())
    cdg = CDG(name=f"{ref.theme}/{ref.pair_id}")
    cwe = _cwe(manifest["cwe"])

    for spec in manifest["nodes"]:
        formula = _read_formula(ref.directory / spec["file"])
        node = ConstraintNode(
            node_id=spec["id"],
            formula=formula,
            formula_skeleton=spec["skeleton"],
            cwe_class=cwe,
            location=BinaryLocation(ref.pair_id, 0, 0),
            version="synth",
        )
        cdg.nodes[node.node_id] = node
        cdg._skeleton_index[node.skeleton_hash].add(node.node_id)

    for src, tgt in manifest["dep_edges"]:
        cdg._add_edge(src, tgt, EdgeLabel.DEP)

    conflict_pair = manifest.get("conflict_pair") or []
    if len(conflict_pair) == 2:
        src_id, tgt_id = conflict_pair
        cdg.nodes[src_id].outcome = SolverOutcome.UNSAT
        cdg._add_edge(src_id, tgt_id, EdgeLabel.CON)

    if manifest.get("a_unsat_only", False):
        # (b)-trap pair: mark a UNSAT without adding a CON edge, so policy
        # (b) observes an UNSAT DEP-predecessor and incorrectly prunes b.
        a_id = manifest["nodes"][0]["id"]
        cdg.nodes[a_id].outcome = SolverOutcome.UNSAT

    return cdg
