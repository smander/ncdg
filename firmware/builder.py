"""Firmware builder: clone and compile firmware targets for CDG benchmark evaluation."""

import os
import subprocess

from firmware.config import FirmwareTarget


class FirmwareBuilder:
    """Clone and build firmware targets from source."""

    def __init__(self, output_dir: str = "firmware_builds"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _src_dir(self, target: FirmwareTarget) -> str:
        """Return the source directory path for a given target."""
        dir_name = f"{target.name}_{target.git_tag}"
        return os.path.join(self.output_dir, dir_name)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def clone(self, target: FirmwareTarget) -> str:
        """Shallow-clone the target repository; return the source directory path."""
        src_dir = self._src_dir(target)
        subprocess.run(
            [
                "git", "clone",
                "--depth", "1",
                "--branch", target.git_tag,
                target.git_repo,
                src_dir,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return src_dir

    def build(self, target: FirmwareTarget, src_dir: str = None) -> None:
        """Build the firmware target.

        For U-Boot targets (name starts with 'u-boot'):
            1. make {defconfig}
            2. make CROSS_COMPILE=aarch64-linux-gnu-

        For TF-A targets (all others):
            make PLAT={defconfig} CROSS_COMPILE=aarch64-linux-gnu- all
        """
        if src_dir is None:
            src_dir = self._src_dir(target)

        cross_compile = "aarch64-linux-gnu-"

        if target.name.startswith("u-boot"):
            # Step 1: apply defconfig
            subprocess.run(
                ["make", target.build_defconfig],
                cwd=src_dir,
                check=True,
                capture_output=True,
                text=True,
            )
            # Step 2: compile
            subprocess.run(
                ["make", f"CROSS_COMPILE={cross_compile}"],
                cwd=src_dir,
                check=True,
                capture_output=True,
                text=True,
            )
        else:
            # TF-A (and any other targets that follow the PLAT= convention)
            subprocess.run(
                [
                    "make",
                    f"PLAT={target.build_defconfig}",
                    f"CROSS_COMPILE={cross_compile}",
                    "all",
                ],
                cwd=src_dir,
                check=True,
                capture_output=True,
                text=True,
            )

    def get_binary_path(self, target: FirmwareTarget, src_dir: str = None) -> str:
        """Return the absolute path to the compiled binary."""
        if src_dir is None:
            src_dir = self._src_dir(target)
        return os.path.join(src_dir, target.binary_path)

    def is_built(self, target: FirmwareTarget) -> bool:
        """Return True if the expected binary already exists on disk."""
        binary = self.get_binary_path(target)
        return os.path.isfile(binary)

    def clone_and_build(self, target: FirmwareTarget) -> str:
        """Clone, build, and return the path to the compiled binary."""
        src_dir = self.clone(target)
        self.build(target, src_dir=src_dir)
        return self.get_binary_path(target, src_dir=src_dir)
