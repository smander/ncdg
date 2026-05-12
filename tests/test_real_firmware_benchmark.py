"""Tests for the real firmware CDG benchmark runner."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import pytest
from experiments.benchmark_real_firmware import (
    build_firmware_cdg,
    run_real_firmware_benchmark,
    UBOOT_VULN_MATRIX,
    TFA_VULN_MATRIX,
)
from cdg_lib.types import SolverOutcome, EdgeLabel


class TestRealFirmwareCDGConstruction:
    def test_build_uboot_v2022_04_cdg(self):
        vcdg = build_firmware_cdg("uboot", "v2022.04")
        assert vcdg.cdg.node_count >= 6
        assert len(vcdg.vuln_triggers) == 3

    def test_build_uboot_v2022_07_cdg(self):
        vcdg = build_firmware_cdg("uboot", "v2022.07")
        assert vcdg.cdg.node_count >= 6

    def test_build_tfa_v2_8_cdg(self):
        vcdg = build_firmware_cdg("tfa", "v2.8")
        assert vcdg.cdg.node_count >= 2
        assert len(vcdg.vuln_triggers) == 1

    def test_build_tfa_v2_9_cdg(self):
        vcdg = build_firmware_cdg("tfa", "v2.9")
        assert vcdg.cdg.node_count >= 2

    def test_uboot_cdg_has_dep_edges(self):
        vcdg = build_firmware_cdg("uboot", "v2022.04")
        dep_edges = [e for e in vcdg.cdg.edges if e.label == EdgeLabel.DEP]
        assert len(dep_edges) > 0


class TestRealFirmwareVulnMatrix:
    def test_uboot_matrix_structure(self):
        assert "v2022.04" in UBOOT_VULN_MATRIX
        assert "v2022.07" in UBOOT_VULN_MATRIX
        assert UBOOT_VULN_MATRIX["v2022.04"]["CVE-2022-30790"] is True
        assert UBOOT_VULN_MATRIX["v2022.07"]["CVE-2022-30790"] is False

    def test_tfa_matrix_structure(self):
        assert "v2.8" in TFA_VULN_MATRIX
        assert "v2.9" in TFA_VULN_MATRIX
        assert TFA_VULN_MATRIX["v2.8"]["CVE-2022-47630"] is True
        assert TFA_VULN_MATRIX["v2.9"]["CVE-2022-47630"] is False


class TestRealFirmwareBenchmarkRunner:
    def test_benchmark_runs_without_error(self):
        results = run_real_firmware_benchmark()
        assert "uboot" in results
        assert "tfa" in results

    def test_benchmark_uboot_has_all_sections(self):
        results = run_real_firmware_benchmark()
        uboot = results["uboot"]
        assert "construction" in uboot
        assert "solving" in uboot
        assert "cross_version" in uboot
        assert "propagation" in uboot
