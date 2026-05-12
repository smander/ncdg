import pytest
import os

pytest.importorskip("angr")
pytest.importorskip("claripy")

from firmware.extractor import FirmwareExtractor
from firmware.config import FirmwareTarget, CVEEntry
from cdg_lib.types import CWEClass


@pytest.fixture
def tiny_binary_path():
    return os.path.join(
        os.path.dirname(__file__), "fixtures", "tiny_arm64.elf"
    )


def test_extract_angr_returns_nodes_or_falls_back(tiny_binary_path):
    """Smoke test: extractor returns nodes (real or synthetic fallback)."""
    target = FirmwareTarget(
        name="uboot",
        git_repo="https://example.com/u-boot.git",
        git_tag="v2022.04",
        build_defconfig="qemu_arm64_defconfig",
        build_cmd="make",
        binary_path="u-boot",
        cves=[CVEEntry(
            cve_id="CVE-2022-30790",
            cwe_class=CWEClass.CWE_787,
            target_functions=["net_defragment"],
            target_file="net/net.c",
            vulnerable=True,
        )],
    )
    extractor = FirmwareExtractor(binary_path=tiny_binary_path)
    nodes = extractor.extract_for_cve(target, target.cves[0])
    assert len(nodes) > 0


def test_extract_angr_uses_location_addr(tiny_binary_path):
    """Real-angr extraction should produce deterministic addresses across runs."""
    from firmware.extractor import location_addr

    target = FirmwareTarget(
        name="uboot",
        git_repo="https://example.com/u-boot.git",
        git_tag="v2022.04",
        build_defconfig="qemu_arm64_defconfig",
        build_cmd="make",
        binary_path="u-boot",
        cves=[CVEEntry(
            cve_id="CVE-2022-30790",
            cwe_class=CWEClass.CWE_787,
            target_functions=["net_defragment"],
            target_file="net/net.c",
            vulnerable=True,
        )],
    )
    extractor = FirmwareExtractor(binary_path=tiny_binary_path)
    nodes = extractor.extract_for_cve(target, target.cves[0])
    nodes2 = extractor.extract_for_cve(target, target.cves[0])
    addrs1 = [n.location.instruction_addr for n in nodes]
    addrs2 = [n.location.instruction_addr for n in nodes2]
    assert addrs1 == addrs2
