"""Tests for FirmwareBuilder."""

import os
from unittest.mock import MagicMock, call, patch

import pytest

from firmware.builder import FirmwareBuilder
from firmware.config import FirmwareTarget


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def uboot_target():
    return FirmwareTarget(
        name="u-boot-v2022.04",
        git_repo="https://github.com/u-boot/u-boot.git",
        git_tag="v2022.04",
        build_defconfig="qemu_arm64_defconfig",
        build_cmd="make qemu_arm64_defconfig && make -j$(nproc) CROSS_COMPILE=aarch64-linux-gnu-",
        binary_path="u-boot",
    )


@pytest.fixture
def tfa_target():
    return FirmwareTarget(
        name="trusted-firmware-a-v2.8",
        git_repo="https://github.com/ARM-software/arm-trusted-firmware.git",
        git_tag="v2.8",
        build_defconfig="qemu",
        build_cmd="make PLAT=qemu CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc) all",
        binary_path="build/qemu/release/bl31/bl31.elf",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFirmwareBuilder:

    def test_builder_creates_output_dir(self, tmp_path):
        out = tmp_path / "fw_builds"
        assert not out.exists()
        FirmwareBuilder(output_dir=str(out))
        assert out.is_dir()

    def test_clone_creates_correct_path(self, tmp_path, uboot_target):
        builder = FirmwareBuilder(output_dir=str(tmp_path))
        expected_dir = str(tmp_path / f"{uboot_target.name}_{uboot_target.git_tag}")

        with patch("firmware.builder.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = builder.clone(uboot_target)

        assert result == expected_dir
        mock_run.assert_called_once_with(
            [
                "git", "clone",
                "--depth", "1",
                "--branch", uboot_target.git_tag,
                uboot_target.git_repo,
                expected_dir,
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_build_calls_make_uboot(self, tmp_path, uboot_target):
        builder = FirmwareBuilder(output_dir=str(tmp_path))
        src_dir = str(tmp_path / f"{uboot_target.name}_{uboot_target.git_tag}")

        with patch("firmware.builder.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            builder.build(uboot_target, src_dir=src_dir)

        assert mock_run.call_count == 2

        # First call must be the defconfig step
        defconfig_call = mock_run.call_args_list[0]
        assert defconfig_call == call(
            ["make", uboot_target.build_defconfig],
            cwd=src_dir,
            check=True,
            capture_output=True,
            text=True,
        )

    def test_build_calls_make_tfa(self, tmp_path, tfa_target):
        builder = FirmwareBuilder(output_dir=str(tmp_path))
        src_dir = str(tmp_path / f"{tfa_target.name}_{tfa_target.git_tag}")

        with patch("firmware.builder.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            builder.build(tfa_target, src_dir=src_dir)

        mock_run.assert_called_once_with(
            [
                "make",
                f"PLAT={tfa_target.build_defconfig}",
                "CROSS_COMPILE=aarch64-linux-gnu-",
                "all",
            ],
            cwd=src_dir,
            check=True,
            capture_output=True,
            text=True,
        )

    def test_get_binary_path(self, tmp_path, uboot_target):
        builder = FirmwareBuilder(output_dir=str(tmp_path))
        src_dir = str(tmp_path / f"{uboot_target.name}_{uboot_target.git_tag}")
        expected = os.path.join(src_dir, uboot_target.binary_path)
        assert builder.get_binary_path(uboot_target, src_dir=src_dir) == expected

    def test_is_built_false_when_no_binary(self, tmp_path, uboot_target):
        builder = FirmwareBuilder(output_dir=str(tmp_path))
        assert builder.is_built(uboot_target) is False

    def test_is_built_true_when_binary_exists(self, tmp_path, uboot_target):
        builder = FirmwareBuilder(output_dir=str(tmp_path))
        # Recreate the expected src_dir and binary on disk
        src_dir = tmp_path / f"{uboot_target.name}_{uboot_target.git_tag}"
        src_dir.mkdir(parents=True)
        binary = src_dir / uboot_target.binary_path
        binary.touch()

        assert builder.is_built(uboot_target) is True
