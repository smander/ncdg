import sys
import os
import pytest

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from cdg_lib import (
    CDG, ConstraintNode, BinaryLocation, SolverOutcome, EdgeLabel, CWEClass,
    make_constraint, Monitor, GraphDiff
)


# ============================================================
# FIXTURES: CDG-Bench vulnerability definitions
# ============================================================

@pytest.fixture
def v1_alpha():
    """V1: CWE-125 in msg_process_alpha."""
    return make_constraint(
        formula="index >= 32",
        skeleton="VAR >= CONST",
        cwe=CWEClass.CWE_125,
        func="msg_process_alpha", bb=3, addr=0x1000,
        version="v1.0",
        variables={"index"},
        var_types={"index": "bv16"},
    )

@pytest.fixture
def v2_beta():
    """V2: CWE-125 in msg_process_beta."""
    return make_constraint(
        formula="index >= 32",
        skeleton="VAR >= CONST",
        cwe=CWEClass.CWE_125,
        func="msg_process_beta", bb=5, addr=0x2000,
        version="v1.0",
        variables={"index"},
        var_types={"index": "bv16"},
    )

@pytest.fixture
def v3_gamma():
    """V3: CWE-125 in msg_process_gamma."""
    return make_constraint(
        formula="index >= 32",
        skeleton="VAR >= CONST",
        cwe=CWEClass.CWE_125,
        func="msg_process_gamma", bb=7, addr=0x3000,
        version="v1.0",
        variables={"index"},
        var_types={"index": "bv16"},
    )

@pytest.fixture
def v4_buffer():
    """V4: CWE-787 in buffer_copy."""
    return make_constraint(
        formula="length > 256",
        skeleton="VAR > CONST",
        cwe=CWEClass.CWE_787,
        func="buffer_copy", bb=2, addr=0x4000,
        version="v1.0",
        variables={"length"},
        var_types={"length": "bv16"},
    )

@pytest.fixture
def v5_uaf():
    """V5: CWE-416 Use-After-Free (introduced v1.2)."""
    return make_constraint(
        formula="buffer_freed == 1 && buffer_accessed == 1",
        skeleton="VAR == CONST && VAR2 == CONST2",
        cwe=CWEClass.CWE_416,
        func="msg_cleanup", bb=4, addr=0x5000,
        version="v1.2",
        variables={"buffer_freed", "buffer_accessed"},
        var_types={"buffer_freed": "bv16", "buffer_accessed": "bv16"},
    )

@pytest.fixture
def v6_overflow():
    """V6: CWE-190 Integer Overflow (introduced v1.3)."""
    return make_constraint(
        formula="base * multiplier * count > 65535",
        skeleton="VAR * VAR2 * VAR3 > CONST",
        cwe=CWEClass.CWE_190,
        func="calc_offset", bb=1, addr=0x6000,
        version="v1.3",
        variables={"base", "multiplier", "count"},
        var_types={"base": "bv16", "multiplier": "bv16", "count": "bv16"},
    )

@pytest.fixture
def v1_alpha_fixed():
    """V1 FIXED in v1.1: bounds check added."""
    return make_constraint(
        formula="index >= 32 && bounds_checked == 0",
        skeleton="VAR >= CONST && VAR2 == CONST2",
        cwe=CWEClass.CWE_125,
        func="msg_process_alpha", bb=3, addr=0x1000,
        version="v1.1",
        variables={"index", "bounds_checked"},
        var_types={"index": "bv16", "bounds_checked": "bv16"},
    )

@pytest.fixture
def dep_chain():
    """Dependency chain: path_cond -> header_parse -> index_extract -> oob_access."""
    c1 = make_constraint(
        formula="msg_len >= 8",
        skeleton="VAR >= CONST",
        cwe=CWEClass.UNKNOWN,
        func="msg_process_alpha", bb=1, addr=0x0F00,
        version="v1.0",
        variables={"msg_len"},
        var_types={"msg_len": "bv32"},
    )
    c2 = make_constraint(
        formula="msg_type == 1",
        skeleton="VAR == CONST",
        cwe=CWEClass.UNKNOWN,
        func="msg_process_alpha", bb=2, addr=0x0F20,
        version="v1.0",
        variables={"msg_type"},
        var_types={"msg_type": "bv16"},
    )
    c3 = make_constraint(
        formula="index >= 32",
        skeleton="VAR >= CONST",
        cwe=CWEClass.CWE_125,
        func="msg_process_alpha", bb=3, addr=0x1000,
        version="v1.0",
        variables={"index"},
        var_types={"index": "bv16"},
    )
    return c1, c2, c3

@pytest.fixture
def empty_cdg():
    """Empty CDG for testing."""
    return CDG("test")
