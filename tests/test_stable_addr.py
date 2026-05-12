from firmware.extractor import _stable_addr, location_addr


def test_stable_addr_deterministic():
    a = _stable_addr("uboot_CVE-2022-30790")
    b = _stable_addr("uboot_CVE-2022-30790")
    assert a == b


def test_stable_addr_different_keys():
    a = _stable_addr("uboot_CVE-2022-30790")
    b = _stable_addr("uboot_CVE-2022-30552")
    assert a != b


def test_location_addr_uses_function_and_offset():
    """Real-angr address keying: same (func, bb_offset) → same addr across versions."""
    a = location_addr("net_defragment", 0x40)
    b = location_addr("net_defragment", 0x40)
    assert a == b


def test_location_addr_different_offsets_differ():
    a = location_addr("net_defragment", 0x40)
    b = location_addr("net_defragment", 0x80)
    assert a != b


def test_location_addr_different_funcs_differ():
    a = location_addr("net_defragment", 0x40)
    b = location_addr("do_i2c_md", 0x40)
    assert a != b
