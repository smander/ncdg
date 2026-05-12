import pytest
import os

angr = pytest.importorskip("angr")
claripy = pytest.importorskip("claripy")

from firmware.harnesses.cve_2022_30552 import build_call_state, target_addr


@pytest.fixture
def fake_proj():
    path = os.path.join(
        os.path.dirname(__file__), "fixtures", "tiny_arm64.elf"
    )
    return angr.Project(path, auto_load_libs=False)


def test_harness_returns_state_and_total_len(fake_proj):
    sym = list(fake_proj.loader.main_object.symbols)[0]
    state, inputs = build_call_state(fake_proj, sym)
    assert "total_len" in inputs
    assert inputs["total_len"].size() == 16


def test_harness_target_addr(fake_proj):
    sym = list(fake_proj.loader.main_object.symbols)[0]
    assert isinstance(target_addr(fake_proj, sym), int)
