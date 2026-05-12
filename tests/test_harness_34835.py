import pytest
import os

angr = pytest.importorskip("angr")
claripy = pytest.importorskip("claripy")

from firmware.harnesses.cve_2022_34835 import build_call_state, target_addr


@pytest.fixture
def fake_proj():
    path = os.path.join(
        os.path.dirname(__file__), "fixtures", "tiny_arm64.elf"
    )
    return angr.Project(path, auto_load_libs=False)


def test_harness_returns_argc_and_nbytes(fake_proj):
    sym = list(fake_proj.loader.main_object.symbols)[0]
    state, inputs = build_call_state(fake_proj, sym)
    assert "argc" in inputs
    assert "nbytes" in inputs
    assert inputs["argc"].size() == 32
    assert inputs["nbytes"].size() == 16
