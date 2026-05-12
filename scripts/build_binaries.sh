#!/usr/bin/env bash
# Build all 4 firmware versions (vulnerable + patched) for Phase 0 evaluation.
#
# Output: firmware/binaries/{target}/{version}/{binary_name}
# Requires: aarch64-linux-gnu-gcc, make, git
#
# Run inside Docker (recommended) or on a host with the cross-toolchain.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINARIES_DIR="$REPO_ROOT/firmware/binaries"
WORK_DIR="$REPO_ROOT/firmware_builds"

mkdir -p "$BINARIES_DIR" "$WORK_DIR"

build_uboot() {
    local version="$1"
    local src="$WORK_DIR/uboot_$version"
    local out="$BINARIES_DIR/uboot/$version"
    mkdir -p "$out"

    if [ ! -d "$src" ]; then
        git clone --depth 1 --branch "$version" \
            https://github.com/u-boot/u-boot.git "$src"
    fi

    pushd "$src" > /dev/null
    make qemu_arm64_defconfig
    # Phase 0.1: enable CONFIG_IP_DEFRAG so __net_defragment is linked
    # (without it the function is dead-code-eliminated; net_defragment is
    # always static inline, the addressable symbol is __net_defragment).
    # Enable I2C command (legacy + DM) so do_i2c_md is linked.
    cat >> .config <<'EOF'
CONFIG_IP_DEFRAG=y
CONFIG_NET_MAXDEFRAG=16384
CONFIG_CMD_I2C=y
CONFIG_DM_I2C=y
CONFIG_DM_I2C_GPIO=y
CONFIG_SYS_I2C_LEGACY=y
EOF
    make olddefconfig
    make -j"$(nproc)" CROSS_COMPILE=aarch64-linux-gnu- HOSTCC=gcc
    cp u-boot "$out/u-boot"
    popd > /dev/null

    echo "[OK] uboot $version → $out/u-boot"
}

build_tfa() {
    local version="$1"
    local src="$WORK_DIR/tfa_$version"
    local out="$BINARIES_DIR/tfa/$version"
    local mbedtls_dir="$WORK_DIR/mbedtls"
    mkdir -p "$out"

    if [ ! -d "$src" ]; then
        git clone --depth 1 --branch "$version" \
            https://github.com/ARM-software/arm-trusted-firmware.git "$src"
    fi

    # Phase 0.1: vendored mbedtls is needed to enable TRUSTED_BOARD_BOOT
    # which is the only way to link in the X.509 parser (CVE-2022-47630
    # target). TF-A v2.8/v2.9 documentation pins mbedtls 2.28.x.
    if [ ! -d "$mbedtls_dir" ]; then
        git clone --depth 1 --branch mbedtls-2.28.7 \
            https://github.com/ARMmbed/mbedtls.git "$mbedtls_dir"
    fi

    pushd "$src" > /dev/null
    # LDFLAGS suppresses newer-binutils warning about RWX LOAD segments which
    # TF-A v2.8/v2.9 don't tolerate (they pass --fatal-warnings to ld).
    # Build BL2 first (Trusted Boot needs it). bl31 plus bl2 plus
    # X.509 parser linked when TRUSTED_BOARD_BOOT=1 + GENERATE_COT=1.
    make PLAT=qemu CROSS_COMPILE=aarch64-linux-gnu- \
        LDFLAGS="-no-warn-rwx-segments" \
        TRUSTED_BOARD_BOOT=1 \
        GENERATE_COT=1 \
        MBEDTLS_DIR="$mbedtls_dir" \
        ARM_ROTPK_LOCATION=devel_rsa \
        ROT_KEY="$src/plat/arm/board/common/rotpk/arm_rotprivk_rsa.pem" \
        -j"$(nproc)" all || {
            echo "[WARN] tfa $version build with TBB failed; falling back to plain build"
            make PLAT=qemu CROSS_COMPILE=aarch64-linux-gnu- \
                LDFLAGS="-no-warn-rwx-segments" \
                -j"$(nproc)" all
        }
    # Copy bl31 (always built) and bl2 (only with TBB) if present.
    cp build/qemu/release/bl31/bl31.elf "$out/bl31.elf"
    [ -f build/qemu/release/bl2/bl2.elf ] && cp build/qemu/release/bl2/bl2.elf "$out/bl2.elf" || true
    popd > /dev/null

    echo "[OK] tfa $version → $out/bl31.elf"
}

build_uboot v2022.04
build_uboot v2022.07
build_tfa v2.8
build_tfa v2.9

echo
echo "All binaries built under $BINARIES_DIR"
