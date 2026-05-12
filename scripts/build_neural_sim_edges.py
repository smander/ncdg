"""Compute neural SIM edges for a CDG produced from a benchmark target.

Loads a synthetic-or-angr CDG via FirmwareExtractor, embeds nodes, adds
SIM edges, and prints summary statistics.

Usage:
    python -m scripts.build_neural_sim_edges \
        --target uboot --version v2022.04 --cve CVE-2022-30790 \
        --tau-sim 0.6
"""

import argparse
import os
import sys

from cdg_lib.graph import CDG
from cdg_lib.neural.config import NeuralConfig
from cdg_lib.neural.embedder import Embedder
from firmware.config import UBOOT_VERSIONS, TFA_VERSIONS
from firmware.extractor import FirmwareExtractor


def _resolve(target_name: str, version: str):
    versions = UBOOT_VERSIONS if target_name == "uboot" else TFA_VERSIONS
    return next(v for v in versions if v.git_tag == version)


def _resolve_binary(target_name: str, version: str):
    fname = "u-boot" if target_name == "uboot" else "bl2.elf"
    p = os.path.join("firmware/binaries", target_name, version, fname)
    return p if os.path.isfile(p) else None


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--target", choices=["uboot", "tfa"], required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--cve", required=True)
    p.add_argument("--tau-sim", type=float, default=0.6)
    args = p.parse_args()

    target = _resolve(args.target, args.version)
    cve = next(c for c in target.cves if c.cve_id == args.cve)
    binary = _resolve_binary(args.target, args.version)
    extractor = FirmwareExtractor(binary_path=binary)

    g = CDG()
    nodes = extractor.extract_for_cve(target, cve)
    for n in nodes:
        g.store(n, [])

    print(f"nodes: {len(g.nodes)}")
    embedder = Embedder(NeuralConfig())
    added = g.compute_neural_sim_edges(embedder, tau_sim=args.tau_sim)
    print(f"sim edges added: {added}")
    sim_count = sum(1 for e in g.edges if e.label.value == "sim")
    print(f"total sim edges in graph: {sim_count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
