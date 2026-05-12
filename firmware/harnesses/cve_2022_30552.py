"""Harness for U-Boot CVE-2022-30552.

CVE: large UDP fragmented packet causes out-of-bounds write in net_defragment.
The bug differs from CVE-2022-30790: here the trigger is total_len exceeding
the reassembly buffer, not hole-descriptor corruption.

Symbolic inputs:
    ip_len    : bv16
    total_len : bv16  — sum of fragment lengths after reassembly
"""

import claripy


def build_call_state(proj, sym):
    state = proj.factory.call_state(sym.rebased_addr)

    ip_len = claripy.BVS("ip_len", 16)
    total_len = claripy.BVS("total_len", 16)

    buf = 0x90000000
    state.memory.store(buf + 2, ip_len, endness="Iend_BE")
    state.memory.store(buf + 4, total_len, endness="Iend_BE")
    state.regs.x0 = buf

    state.solver.add(ip_len >= 20)

    return state, {"ip_len": ip_len, "total_len": total_len}


def target_addr(proj, sym) -> int:
    return sym.rebased_addr + 0x80  # placeholder, refined on real binary
