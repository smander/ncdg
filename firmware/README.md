# Firmware Evaluation Targets

Real-world ARM64 firmware targets for CDG benchmark evaluation.

## Targets

### U-Boot (Das U-Boot Universal Boot Loader)

| Version  | CVEs                                            | Status     |
|----------|-------------------------------------------------|------------|
| v2022.04 | CVE-2022-30790, CVE-2022-30552, CVE-2022-34835 | Vulnerable |
| v2022.07 | CVE-2022-30790, CVE-2022-30552, CVE-2022-34835 | Patched    |

- **CVE-2022-30790** (CWE-787): Heap overflow in IP defragmentation via crafted UDP fragment
- **CVE-2022-30552** (CWE-787): Out-of-bounds write from large fragmented UDP packet
- **CVE-2022-34835** (CWE-787): Stack buffer overflow in `i2c md` command

### Trusted Firmware-A (TF-A)

| Version | CVEs           | Status     |
|---------|----------------|------------|
| v2.8    | CVE-2022-47630 | Vulnerable |
| v2.9    | CVE-2022-47630 | Patched    |

- **CVE-2022-47630** (CWE-125): Out-of-bounds read in X.509 parser during Trusted Boot

## How It Works

The benchmark uses **synthetic constraint templates** that model each CVE's vulnerability pattern:

- **Vulnerable versions**: Constraints are satisfiable (SAT) -- the solver finds inputs that trigger the bug
- **Patched versions**: Trigger constraints are unsatisfiable (UNSAT) -- bitvector overflow sentinels block the vulnerability path

Cross-version constraint reuse is measured by comparing node addresses between vulnerable and patched CDGs. Addresses are computed deterministically (SHA-256) using firmware name + CVE ID, so constraints for the same vulnerability map to the same location across versions.

## Running

```bash
# Inside Docker (recommended -- z3 and cross-compiler available)
python -m experiments.benchmark_real_firmware

# Or via the full pipeline
./run.sh
```

## Building Real Firmware (Optional)

If you want to build actual firmware binaries for angr-based analysis:

```bash
# U-Boot v2022.04 (vulnerable)
git clone https://github.com/u-boot/u-boot.git && cd u-boot
git checkout v2022.04
make qemu_arm64_defconfig
make -j$(nproc) CROSS_COMPILE=aarch64-linux-gnu-

# TF-A v2.8 (vulnerable)
git clone https://github.com/ARM-software/arm-trusted-firmware.git && cd arm-trusted-firmware
git checkout v2.8
make PLAT=qemu CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc) all
```

## Building Real Binaries (Phase 0)

```bash
./scripts/build_binaries.sh
```

Builds all 4 firmware versions (U-Boot v2022.04/v2022.07 and TF-A v2.8/v2.9) into `firmware/binaries/{target}/{version}/`. Requires `aarch64-linux-gnu-gcc` and `git` (already in the project Dockerfile). Runtime: ~30-60 minutes total.

## Phase 0: Real angr Extraction (NS-CDG)

The default `extract_for_cve()` path uses synthetic constraint templates.
Real angr extraction kicks in when:

1. The cross-toolchain is installed (`aarch64-linux-gnu-gcc` — already in the project Dockerfile)
2. Binaries are built: `./scripts/build_binaries.sh`
3. The extractor is constructed with a `binary_path`: `FirmwareExtractor(binary_path="firmware/binaries/uboot/v2022.04/u-boot")`

The extractor automatically:

- Loads the per-CVE harness from `firmware/harnesses/`
- Runs `BoundedExplorer` with strict resource caps (10 loop iters, 200 states, 60s)
- Serializes constraints to SMT-LIB2 via `to_smtlib()`
- Computes canonical skeletons via `compute_skeleton()`
- Uses `location_addr(function, bb_offset)` for stable cross-version addresses
- Falls back to synthetic on any failure (missing binary, harness exception, path explosion)

Run the angr-mode benchmark:

```bash
python -m experiments.benchmark_real_firmware --use-angr
```

Output goes to `experiments/benchmark_real_firmware_angr_results.json`. Schema is identical to the synthetic baseline — locked down by `tests/test_benchmark_schema_parity.py`.

### Validation gates

`tests/test_validation_gates.py` runs G1-G5 and skips automatically when binaries are absent:

| Gate | Check |
|---|---|
| G1 | Harness reaches target address |
| G2 | Vulnerable version SAT, patched version UNSAT |
| G3 | ≥10 distinct skeletons across all CVEs |
| G4 | ≥30% cross-version reuse on real binaries |
| G5 | All Z3 outcomes in {SAT, UNSAT, UNKNOWN} |

## Module Structure

- `config.py` -- `FirmwareTarget` and `CVEEntry` dataclasses, version lists
- `builder.py` -- Clone and cross-compile firmware from source
- `extractor.py` -- Extract/synthesize constraints from firmware binaries
- `explorer.py` -- `BoundedExplorer` with budget caps for angr exploration
- `skeleton.py` -- `compute_skeleton()` and `to_smtlib()` for claripy ASTs
- `harnesses/` -- Per-CVE reachability harnesses
- `cve_targets.yaml` -- CVE metadata (function, patch commit, harness module)
