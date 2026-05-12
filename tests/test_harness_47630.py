import pytest
import os

angr = pytest.importorskip("angr")
claripy = pytest.importorskip("claripy")

from firmware.harnesses.cve_2022_47630 import build_call_state, target_addr


@pytest.fixture
def fake_proj():
    path = os.path.join(
        os.path.dirname(__file__), "fixtures", "tiny_arm64.elf"
    )
    return angr.Project(path, auto_load_libs=False)


def test_harness_returns_cert_inputs(fake_proj):
    sym = list(fake_proj.loader.main_object.symbols)[0]
    state, inputs = build_call_state(fake_proj, sym)
    assert "cert_len" in inputs
    assert "ext_offset" in inputs
    assert inputs["cert_len"].size() == 32
    assert inputs["ext_offset"].size() == 32
