"""Harness for TF-A CVE-2022-47630.

CVE: out-of-bounds read in mbedtls X.509 parser during Trusted Boot.
Trigger: extension offset advances past certificate buffer end.

Symbolic inputs:
    cert_len   : bv32  — certificate buffer total length
    ext_offset : bv32  — extension offset within certificate
"""

import claripy


def build_call_state(proj, sym):
    state = proj.factory.call_state(sym.rebased_addr)

    cert_len = claripy.BVS("cert_len", 32)
    ext_offset = claripy.BVS("ext_offset", 32)

    cert_buf = 0x80000000
    state.memory.store(cert_buf, cert_len, endness="Iend_BE")
    state.memory.store(cert_buf + 4, ext_offset, endness="Iend_BE")

    # get_ext(p, end, ...) — first arg buffer pointer, second arg buffer end.
    state.regs.x0 = cert_buf
    state.regs.x1 = cert_buf + cert_len.zero_extend(32)

    state.solver.add(cert_len >= 1)
    state.solver.add(cert_len <= 16384)  # realistic certificate size

    return state, {"cert_len": cert_len, "ext_offset": ext_offset}


def target_addr(proj, sym) -> int:
    return sym.rebased_addr + 0x100  # placeholder
