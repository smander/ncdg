import pytest
from firmware.harnesses import load_harness, HarnessNotFound


def test_load_harness_returns_callable_for_known_cve():
    # Stub harness will be created in subsequent tasks; for now assert error.
    with pytest.raises(HarnessNotFound):
        load_harness("CVE-9999-99999")


def test_load_harness_uses_cve_targets_yaml(tmp_path, monkeypatch):
    """Loader should resolve harness module from cve_targets.yaml."""
    yaml_path = tmp_path / "cve_targets.yaml"
    yaml_path.write_text(
        "cves:\n"
        "  - cve_id: CVE-TEST-0001\n"
        "    harness_module: firmware.harnesses._never_exists\n"
    )
    monkeypatch.setattr(
        "firmware.harnesses._CVE_TARGETS_PATH", str(yaml_path)
    )
    with pytest.raises(HarnessNotFound):
        load_harness("CVE-TEST-0001")
