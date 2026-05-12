"""Schema parity: synthetic vs. angr benchmark output must share top-level
and per-target section keys.

This locks down the JSON contract so the paper's evaluation tables stay
valid when extraction switches between synthetic templates and real-angr
extraction.
"""

import json
from pathlib import Path
import pytest


EXPECTED_TOP_KEYS = {"uboot", "tfa"}
EXPECTED_TARGET_KEYS = {
    "construction",
    "solving",
    "accuracy",
    "cross_version",
    "propagation",
    "shortcuts",
    "parity",
}


def _load(p):
    if not p.exists():
        pytest.skip(f"missing: {p}")
    return json.loads(p.read_text())


def _check_target_keys(data, label):
    for target, sections in data.items():
        missing = EXPECTED_TARGET_KEYS - set(sections.keys())
        assert not missing, \
            f"{label}: target {target!r} missing sections: {missing}"


def test_synthetic_run_has_expected_keys():
    p = Path("experiments/benchmark_real_firmware_results.json")
    data = _load(p)
    missing = EXPECTED_TOP_KEYS - set(data.keys())
    assert not missing, f"synthetic top-level missing: {missing}"
    _check_target_keys(data, "synthetic")


def test_angr_run_has_expected_keys():
    p = Path("experiments/benchmark_real_firmware_angr_results.json")
    data = _load(p)
    missing = EXPECTED_TOP_KEYS - set(data.keys())
    assert not missing, f"angr top-level missing: {missing}"
    _check_target_keys(data, "angr")


def test_synthetic_and_angr_share_schema():
    syn_p = Path("experiments/benchmark_real_firmware_results.json")
    angr_p = Path("experiments/benchmark_real_firmware_angr_results.json")
    syn = _load(syn_p)
    angr = _load(angr_p)
    assert set(syn.keys()) == set(angr.keys()), \
        f"top-level drift: syn-only={set(syn) - set(angr)}, angr-only={set(angr) - set(syn)}"
    for target in set(syn.keys()) & set(angr.keys()):
        syn_sec = set(syn[target].keys())
        angr_sec = set(angr[target].keys())
        assert syn_sec == angr_sec, \
            f"target {target!r} section drift: " \
            f"syn-only={syn_sec - angr_sec}, angr-only={angr_sec - syn_sec}"
