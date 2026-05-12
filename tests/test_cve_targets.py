import pytest
import yaml
from pathlib import Path


def test_cve_targets_yaml_loads():
    path = Path(__file__).parent.parent / "firmware" / "cve_targets.yaml"
    assert path.exists(), f"missing: {path}"
    with path.open() as f:
        data = yaml.safe_load(f)
    assert "cves" in data
    assert len(data["cves"]) == 4

    cve_ids = {c["cve_id"] for c in data["cves"]}
    assert cve_ids == {
        "CVE-2022-30790",
        "CVE-2022-30552",
        "CVE-2022-34835",
        "CVE-2022-47630",
    }


def test_cve_targets_required_fields():
    path = Path(__file__).parent.parent / "firmware" / "cve_targets.yaml"
    with path.open() as f:
        data = yaml.safe_load(f)
    required = {
        "cve_id", "function", "file_line", "patch_commit",
        "vulnerable_bb_hint", "harness_module",
    }
    for cve in data["cves"]:
        missing = required - set(cve.keys())
        assert not missing, f"{cve.get('cve_id')} missing fields: {missing}"
