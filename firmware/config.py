"""Firmware version configurations with CVE metadata for CDG benchmark evaluation."""

from dataclasses import dataclass, field
from typing import List

from cdg_lib.types import CWEClass


@dataclass
class CVEEntry:
    cve_id: str
    cwe_class: CWEClass
    target_functions: List[str]
    target_file: str
    vulnerable: bool
    description: str = ""
    expected_skeleton: str = ""
    expected_outcome: str = "SAT"


@dataclass
class FirmwareTarget:
    name: str
    git_repo: str
    git_tag: str
    build_defconfig: str
    build_cmd: str
    binary_path: str
    cves: List[CVEEntry] = field(default_factory=list)
    arch: str = "aarch64"


# ---------------------------------------------------------------------------
# U-Boot versions
# ---------------------------------------------------------------------------

_UBOOT_REPO = "https://github.com/u-boot/u-boot.git"
_UBOOT_DEFCONFIG = "qemu_arm64_defconfig"

UBOOT_VERSIONS: List[FirmwareTarget] = [
    FirmwareTarget(
        name="uboot",
        git_repo=_UBOOT_REPO,
        git_tag="v2022.04",
        build_defconfig=_UBOOT_DEFCONFIG,
        build_cmd="make qemu_arm64_defconfig && make -j$(nproc) CROSS_COMPILE=aarch64-linux-gnu-",
        binary_path="u-boot",
        cves=[
            CVEEntry(
                cve_id="CVE-2022-30790",
                cwe_class=CWEClass.CWE_787,
                target_functions=["net_process_received_packet"],
                target_file="net/net.c",
                vulnerable=True,
                description="U-Boot CVE-2022-30790: hole descriptor overwrite via crafted UDP fragment",
            ),
            CVEEntry(
                cve_id="CVE-2022-30552",
                cwe_class=CWEClass.CWE_787,
                target_functions=["net_process_received_packet"],
                target_file="net/net.c",
                vulnerable=True,
                description="U-Boot CVE-2022-30552: large UDP fragmented packet causes out-of-bounds write",
            ),
            CVEEntry(
                cve_id="CVE-2022-34835",
                cwe_class=CWEClass.CWE_787,
                target_functions=["do_i2c_md"],
                target_file="cmd/i2c.c",
                vulnerable=True,
                description="U-Boot CVE-2022-34835: i2c md command stack buffer overflow",
            ),
        ],
    ),
    FirmwareTarget(
        name="uboot",
        git_repo=_UBOOT_REPO,
        git_tag="v2022.07",
        build_defconfig=_UBOOT_DEFCONFIG,
        build_cmd="make qemu_arm64_defconfig && make -j$(nproc) CROSS_COMPILE=aarch64-linux-gnu-",
        binary_path="u-boot",
        cves=[
            CVEEntry(
                cve_id="CVE-2022-30790",
                cwe_class=CWEClass.CWE_787,
                target_functions=["net_process_received_packet"],
                target_file="net/net.c",
                vulnerable=False,
                description="U-Boot CVE-2022-30790: patched in v2022.07",
                expected_outcome="UNSAT",
            ),
            CVEEntry(
                cve_id="CVE-2022-30552",
                cwe_class=CWEClass.CWE_787,
                target_functions=["net_process_received_packet"],
                target_file="net/net.c",
                vulnerable=False,
                description="U-Boot CVE-2022-30552: patched in v2022.07",
                expected_outcome="UNSAT",
            ),
            CVEEntry(
                cve_id="CVE-2022-34835",
                cwe_class=CWEClass.CWE_787,
                target_functions=["do_i2c_md"],
                target_file="cmd/i2c.c",
                vulnerable=False,
                description="U-Boot CVE-2022-34835: patched in v2022.07",
                expected_outcome="UNSAT",
            ),
        ],
    ),
]


# ---------------------------------------------------------------------------
# Trusted Firmware-A (TF-A) versions
# ---------------------------------------------------------------------------

_TFA_REPO = "https://github.com/ARM-software/arm-trusted-firmware.git"
_TFA_DEFCONFIG = "qemu"
_TFA_CVE_2022_47630_FILE = "drivers/auth/mbedtls/mbedtls_x509_parser.c"

TFA_VERSIONS: List[FirmwareTarget] = [
    FirmwareTarget(
        name="tfa",
        git_repo=_TFA_REPO,
        git_tag="v2.8",
        build_defconfig=_TFA_DEFCONFIG,
        build_cmd="make PLAT=qemu CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc) all",
        binary_path="build/qemu/release/bl31/bl31.elf",
        cves=[
            CVEEntry(
                cve_id="CVE-2022-47630",
                cwe_class=CWEClass.CWE_125,
                target_functions=["get_ext", "auth_nvctr"],
                target_file=_TFA_CVE_2022_47630_FILE,
                vulnerable=True,
                description="TF-A CVE-2022-47630: out-of-bounds read in X.509 parser during Trusted Boot",
            ),
        ],
    ),
    FirmwareTarget(
        name="tfa",
        git_repo=_TFA_REPO,
        git_tag="v2.9",
        build_defconfig=_TFA_DEFCONFIG,
        build_cmd="make PLAT=qemu CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc) all",
        binary_path="build/qemu/release/bl31/bl31.elf",
        cves=[
            CVEEntry(
                cve_id="CVE-2022-47630",
                cwe_class=CWEClass.CWE_125,
                target_functions=["get_ext", "auth_nvctr"],
                target_file=_TFA_CVE_2022_47630_FILE,
                vulnerable=False,
                description="TF-A CVE-2022-47630: patched in v2.9",
                expected_outcome="UNSAT",
            ),
        ],
    ),
]
