import pytest
import os

angr = pytest.importorskip("angr")
claripy = pytest.importorskip("claripy")

from firmware.harnesses.cve_2022_30790 import build_call_state, target_addr


@pytest.fixture
def fake_proj():
    """Use the tiny fixture; harness should not require real U-Boot for unit-level tests."""
    path = os.path.join(
        os.path.dirname(__file__), "fixtures", "tiny_arm64.elf"
    )
    return angr.Project(path, auto_load_libs=False)


def test_harness_returns_state_and_inputs(fake_proj):
    sym = list(fake_proj.loader.main_object.symbols)[0]
    state, inputs = build_call_state(fake_proj, sym)
    assert state is not None
    assert "ip_len" in inputs
    assert "frag_offset" in inputs
    assert inputs["ip_len"].size() == 16
    assert inputs["frag_offset"].size() == 16


def test_harness_target_addr_returns_int(fake_proj):
    sym = list(fake_proj.loader.main_object.symbols)[0]
    addr = target_addr(fake_proj, sym)
    assert isinstance(addr, int)
    assert addr > 0
