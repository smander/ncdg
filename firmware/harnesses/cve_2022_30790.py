"""Harness for U-Boot CVE-2022-30790.

CVE: hole-descriptor overwrite in net_defragment via crafted UDP fragment.
Vulnerable path: a fragmented IP packet with frag_offset > buffer bounds
overwrites the hole descriptor.

Symbolic inputs:
    ip_len      : bv16  — total IP length field
    frag_offset : bv16  — fragment offset field
    frag_flags  : bv8   — fragment flags (MF, DF)
"""

import claripy


def build_call_state(proj, sym):
    """Return (state, {input_name: claripy_var}).

    Wires symbolic input variables into the state where net_defragment expects
    its packet buffer. The exact memory offsets are placeholders — refine when
    real U-Boot binary symbol resolution is available.
    """
    state = proj.factory.call_state(sym.rebased_addr)

    ip_len = claripy.BVS("ip_len", 16)
    frag_offset = claripy.BVS("frag_offset", 16)
    frag_flags = claripy.BVS("frag_flags", 8)

    # Buffer pointer: place inputs at canonical offsets in a scratch region.
    buf = 0x90000000
    state.memory.store(buf + 2, ip_len, endness="Iend_BE")
    state.memory.store(buf + 6, frag_offset, endness="Iend_BE")
    state.memory.store(buf + 8, frag_flags)

    # Pass buffer pointer as first argument (AArch64 ABI: x0).
    state.regs.x0 = buf

    # Add minimal sanity constraints (matches header well-formedness).
    state.solver.add(ip_len >= 20)            # IP header minimum
    state.solver.add(ip_len <= 65535)         # bv16 max anyway, explicit

    return state, {
        "ip_len": ip_len,
        "frag_offset": frag_offset,
        "frag_flags": frag_flags,
    }


def target_addr(proj, sym) -> int:
    """Return the address inside net_defragment we want the explorer to reach.

    Heuristic: sym.rebased_addr + an offset where the hole descriptor write
    happens. Real value comes from CFG inspection on the U-Boot binary.
    Falls back to symbol entry on tiny fixtures.
    """
    base = sym.rebased_addr
    # Placeholder offset — replaced once CFG analysis on real U-Boot runs.
    return base + 0x40
