"""Per-CVE reachability harnesses.

Each CVE module under this package exposes:
    build_call_state(proj, sym) -> (state, symbolic_inputs)
    target_addr(proj, sym) -> int   # address the explorer should aim for
"""

import importlib
import os
from pathlib import Path
from typing import Callable

import yaml


class HarnessNotFound(Exception):
    pass


_CVE_TARGETS_PATH = str(
    Path(__file__).resolve().parent.parent / "cve_targets.yaml"
)


def _read_targets() -> dict:
    with open(_CVE_TARGETS_PATH) as f:
        return yaml.safe_load(f)


def load_harness(cve_id: str):
    """Return the imported harness module for cve_id.

    Raises HarnessNotFound if cve_id is missing from cve_targets.yaml or
    the named harness_module cannot be imported.
    """
    targets = _read_targets()
    entry = next(
        (c for c in targets.get("cves", []) if c.get("cve_id") == cve_id),
        None,
    )
    if entry is None:
        raise HarnessNotFound(f"{cve_id} not in cve_targets.yaml")
    module_name = entry.get("harness_module")
    if not module_name:
        raise HarnessNotFound(f"{cve_id} has no harness_module")
    try:
        return importlib.import_module(module_name)
    except ImportError as e:
        raise HarnessNotFound(f"cannot import {module_name}: {e}") from e
