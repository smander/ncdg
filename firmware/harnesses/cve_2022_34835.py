"""Harness for U-Boot CVE-2022-34835.

CVE: stack buffer overflow in `i2c md` command via attacker-controlled
nbytes argument exceeding fixed-size stack buffer.

Symbolic inputs:
    argc   : bv32  — argv count
    nbytes : bv16  — i2c md byte count argument
"""

import claripy


def build_call_state(proj, sym):
    state = proj.factory.call_state(sym.rebased_addr)

    argc = claripy.BVS("argc", 32)
    nbytes = claripy.BVS("nbytes", 16)

    # do_i2c_md(cmdtbl, flag, argc, argv) — argc is x2 in AArch64 ABI.
    state.regs.x2 = argc.zero_extend(32)

    # nbytes typically parsed from argv[3]; we model it via memory store.
    argv_buf = 0x91000000
    state.memory.store(argv_buf, nbytes, endness="Iend_BE")
    state.regs.x3 = argv_buf

    state.solver.add(argc >= 3)

    return state, {"argc": argc, "nbytes": nbytes}


def target_addr(proj, sym) -> int:
    return sym.rebased_addr + 0xC0  # placeholder
