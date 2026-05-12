"""Dump real-angr-extracted constraint nodes to a JSONL.

Iterates over UBOOT_VERSIONS + TFA_VERSIONS, runs the FirmwareExtractor on
each binary, and writes one record per ConstraintNode. The result is the
held-out f_theta test set (Corpus 3 in the spec).

Records have the same field set as the LLM-CVE corpus where applicable, plus
extraction metadata.

Usage:
    python -m scripts.build_real_angr_corpus <out.jsonl>
"""

import json
import sys
from pathlib import Path

from cdg_lib.types import CWEClass


def _resolve_binary(target_name: str, version: str):
    fname = "u-boot" if target_name == "uboot" else "bl2.elf"
    p = Path("firmware/binaries") / target_name / version / fname
    return p if p.is_file() else None


def _node_to_record(node, cve_id: str, version: str, target_name: str) -> dict:
    return {
        "cve_id": cve_id,
        "version": version,
        "target": target_name,
        "formula": node.formula,
        "skeleton": node.formula_skeleton,
        "cwe": (
            node.cwe_class.value
            if isinstance(node.cwe_class, CWEClass)
            else str(node.cwe_class)
        ),
        "vars": list(node.variables),
        "var_types": dict(node.var_types),
        "function": node.location.function,
        "addr": node.location.instruction_addr,
        "outcome": node.outcome.value if hasattr(node.outcome, "value") else str(node.outcome),
    }


def build_corpus(out_path: Path) -> int:
    """Walk all binaries, extract constraints, write JSONL. Returns count."""
    from firmware.config import UBOOT_VERSIONS, TFA_VERSIONS
    from firmware.extractor import FirmwareExtractor

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w") as f:
        for target in UBOOT_VERSIONS + TFA_VERSIONS:
            binary = _resolve_binary(target.name, target.git_tag)
            if binary is None:
                continue
            extractor = FirmwareExtractor(binary_path=str(binary))
            for cve in target.cves:
                nodes = extractor.extract_for_cve(target, cve)
                for node in nodes:
                    rec = _node_to_record(node, cve.cve_id, target.git_tag, target.name)
                    f.write(json.dumps(rec) + "\n")
                    n += 1
    return n


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m scripts.build_real_angr_corpus <out.jsonl>",
              file=sys.stderr)
        sys.exit(2)
    n = build_corpus(Path(sys.argv[1]))
    print(f"wrote {n} records to {sys.argv[1]}")
