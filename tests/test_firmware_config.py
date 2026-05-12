"""Tests for firmware CVE configuration module."""
import pytest
from firmware.config import UBOOT_VERSIONS, TFA_VERSIONS, FirmwareTarget, CVEEntry
from cdg_lib.types import CWEClass


class TestUBootVersions:
    def test_uboot_has_two_entries(self):
        assert len(UBOOT_VERSIONS) == 2

    def test_uboot_git_tags(self):
        tags = [t.git_tag for t in UBOOT_VERSIONS]
        assert "v2022.04" in tags
        assert "v2022.07" in tags

    def test_uboot_v202204_has_three_cves(self):
        v202204 = next(t for t in UBOOT_VERSIONS if t.git_tag == "v2022.04")
        cve_ids = [c.cve_id for c in v202204.cves]
        assert "CVE-2022-30790" in cve_ids
        assert "CVE-2022-30552" in cve_ids
        assert "CVE-2022-34835" in cve_ids

    def test_uboot_v202207_has_three_cves(self):
        v202207 = next(t for t in UBOOT_VERSIONS if t.git_tag == "v2022.07")
        assert len(v202207.cves) == 3

    def test_uboot_v202204_cves_are_vulnerable(self):
        v202204 = next(t for t in UBOOT_VERSIONS if t.git_tag == "v2022.04")
        for cve in v202204.cves:
            assert cve.vulnerable is True

    def test_uboot_v202207_cves_are_patched(self):
        v202207 = next(t for t in UBOOT_VERSIONS if t.git_tag == "v2022.07")
        for cve in v202207.cves:
            assert cve.vulnerable is False
            assert cve.expected_outcome == "UNSAT"


class TestTFAVersions:
    def test_tfa_has_two_entries(self):
        assert len(TFA_VERSIONS) == 2

    def test_tfa_git_tags(self):
        tags = [t.git_tag for t in TFA_VERSIONS]
        assert "v2.8" in tags
        assert "v2.9" in tags

    def test_tfa_v28_has_cve_2022_47630(self):
        v28 = next(t for t in TFA_VERSIONS if t.git_tag == "v2.8")
        cve_ids = [c.cve_id for c in v28.cves]
        assert "CVE-2022-47630" in cve_ids

    def test_tfa_v28_cve_is_vulnerable(self):
        v28 = next(t for t in TFA_VERSIONS if t.git_tag == "v2.8")
        cve = next(c for c in v28.cves if c.cve_id == "CVE-2022-47630")
        assert cve.vulnerable is True

    def test_tfa_v29_cve_is_patched(self):
        v29 = next(t for t in TFA_VERSIONS if t.git_tag == "v2.9")
        cve = next(c for c in v29.cves if c.cve_id == "CVE-2022-47630")
        assert cve.vulnerable is False
        assert cve.expected_outcome == "UNSAT"


class TestCVEEntryFields:
    @pytest.mark.parametrize("firmware_list", [UBOOT_VERSIONS, TFA_VERSIONS])
    def test_all_cves_have_non_empty_target_functions(self, firmware_list):
        for target in firmware_list:
            for cve in target.cves:
                assert len(cve.target_functions) > 0, (
                    f"{cve.cve_id} has empty target_functions"
                )

    @pytest.mark.parametrize("firmware_list", [UBOOT_VERSIONS, TFA_VERSIONS])
    def test_all_cves_have_cwe_class(self, firmware_list):
        for target in firmware_list:
            for cve in target.cves:
                assert isinstance(cve.cwe_class, CWEClass), (
                    f"{cve.cve_id} has invalid cwe_class"
                )

    @pytest.mark.parametrize("firmware_list", [UBOOT_VERSIONS, TFA_VERSIONS])
    def test_all_cves_have_valid_vulnerable_flag(self, firmware_list):
        for target in firmware_list:
            for cve in target.cves:
                assert isinstance(cve.vulnerable, bool), (
                    f"{cve.cve_id} vulnerable field is not bool"
                )


class TestFirmwareTargetFields:
    @pytest.mark.parametrize("firmware_list", [UBOOT_VERSIONS, TFA_VERSIONS])
    def test_all_targets_have_non_empty_git_repo(self, firmware_list):
        for target in firmware_list:
            assert target.git_repo, f"{target.name} has empty git_repo"

    @pytest.mark.parametrize("firmware_list", [UBOOT_VERSIONS, TFA_VERSIONS])
    def test_all_targets_have_non_empty_git_tag(self, firmware_list):
        for target in firmware_list:
            assert target.git_tag, f"{target.name} has empty git_tag"

    @pytest.mark.parametrize("firmware_list", [UBOOT_VERSIONS, TFA_VERSIONS])
    def test_all_targets_have_non_empty_build_defconfig(self, firmware_list):
        for target in firmware_list:
            assert target.build_defconfig, f"{target.name} has empty build_defconfig"

    @pytest.mark.parametrize("firmware_list", [UBOOT_VERSIONS, TFA_VERSIONS])
    def test_all_targets_have_non_empty_binary_path(self, firmware_list):
        for target in firmware_list:
            assert target.binary_path, f"{target.name} has empty binary_path"
