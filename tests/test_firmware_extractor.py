"""Tests for FirmwareExtractor - all run using synthetic fallback (no binary needed)."""

import pytest

from firmware.config import UBOOT_VERSIONS, TFA_VERSIONS
from firmware.extractor import FirmwareExtractor
from cdg_lib.types import CWEClass


@pytest.fixture
def extractor():
    """Create a FirmwareExtractor with no binary (forces synthetic fallback)."""
    return FirmwareExtractor(binary_path=None)


# ---------------------------------------------------------------------------
# test_extract_uboot_vulnerable_cve
# ---------------------------------------------------------------------------

def test_extract_uboot_vulnerable_cve(extractor):
    """Extracting the first U-Boot CVE (vulnerable) yields >= 2 nodes with CWE_787."""
    target = UBOOT_VERSIONS[0]
    cve = target.cves[0]

    nodes = extractor.extract_for_cve(target, cve)

    assert len(nodes) >= 2, "Expected at least 2 constraint nodes"
    last = nodes[-1]
    assert last.cwe_class == CWEClass.CWE_787, f"Expected CWE_787, got {last.cwe_class}"
    assert last.version == target.git_tag, "Version tag mismatch"
    assert last.location.function == cve.target_functions[0], "Function name mismatch"


# ---------------------------------------------------------------------------
# test_extract_uboot_patched_cve
# ---------------------------------------------------------------------------

def test_extract_uboot_patched_cve(extractor):
    """Extracting the first patched U-Boot CVE yields a trigger_blocked node with overflow value."""
    target = UBOOT_VERSIONS[1]
    cve = target.cves[0]

    nodes = extractor.extract_for_cve(target, cve)

    assert len(nodes) >= 2, "Expected at least 2 constraint nodes"
    last = nodes[-1]
    assert (
        "65535" in last.formula or "4294967295" in last.formula
    ), f"Expected overflow sentinel in formula, got: {last.formula!r}"


# ---------------------------------------------------------------------------
# test_extract_tfa_vulnerable_cve
# ---------------------------------------------------------------------------

def test_extract_tfa_vulnerable_cve(extractor):
    """Extracting TF-A vulnerable CVE yields >= 2 nodes, last node is CWE_125."""
    target = TFA_VERSIONS[0]
    cve = target.cves[0]

    nodes = extractor.extract_for_cve(target, cve)

    assert len(nodes) >= 2, "Expected at least 2 constraint nodes"
    last = nodes[-1]
    assert last.cwe_class == CWEClass.CWE_125, f"Expected CWE_125, got {last.cwe_class}"


# ---------------------------------------------------------------------------
# test_extract_produces_dep_chain
# ---------------------------------------------------------------------------

def test_extract_produces_dep_chain(extractor):
    """Every extracted node must have an empty node_id and non-empty formula/skeleton."""
    target = UBOOT_VERSIONS[0]
    cve = target.cves[0]

    nodes = extractor.extract_for_cve(target, cve)

    for node in nodes:
        assert node.node_id == "", f"node_id should be empty string, got: {node.node_id!r}"
        assert node.formula, "formula must be non-empty"
        assert node.formula_skeleton, "formula_skeleton must be non-empty"


# ---------------------------------------------------------------------------
# test_extract_all_for_version
# ---------------------------------------------------------------------------

def test_extract_all_for_version(extractor):
    """UBOOT_VERSIONS[0] has 3 CVEs; extract_all should return at least 6 nodes total."""
    target = UBOOT_VERSIONS[0]

    assert len(target.cves) == 3, "Expected 3 CVEs in UBOOT_VERSIONS[0]"

    nodes = extractor.extract_all(target)

    assert len(nodes) >= 6, f"Expected >= 6 nodes total, got {len(nodes)}"


# ---------------------------------------------------------------------------
# test_vulnerable_trigger_has_sat_skeleton
# ---------------------------------------------------------------------------

def test_vulnerable_trigger_has_sat_skeleton(extractor):
    """The trigger node in a vulnerable CVE must use '>=' or '>' in its formula."""
    target = UBOOT_VERSIONS[0]
    cve = target.cves[0]

    nodes = extractor.extract_for_cve(target, cve)
    trigger = nodes[-1]

    assert ">=" in trigger.formula or ">" in trigger.formula, (
        f"Trigger formula should contain '>=' or '>', got: {trigger.formula!r}"
    )


# ---------------------------------------------------------------------------
# test_patched_trigger_has_unsat_formula
# ---------------------------------------------------------------------------

def test_patched_trigger_has_unsat_formula(extractor):
    """The trigger_blocked node in a patched CVE must reference an overflow sentinel value."""
    target = UBOOT_VERSIONS[1]
    cve = target.cves[0]

    nodes = extractor.extract_for_cve(target, cve)
    trigger_blocked = nodes[-1]

    assert (
        "65535" in trigger_blocked.formula or "4294967295" in trigger_blocked.formula
    ), (
        f"Expected overflow sentinel (65535 or 4294967295) in patched trigger, "
        f"got: {trigger_blocked.formula!r}"
    )
