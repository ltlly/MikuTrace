"""Unit tests for the pure trace-parsing helpers in the host `tracemiku` script.

These functions re-implement core record parsing on the host side (a known
tech debt — see TODO). The tests pin their behavior and cross-check the ret
classification against the core disasm contract so the two cannot silently
diverge on real ARM64 encodings.
"""

import pathlib
import struct
import types

REPO = pathlib.Path(__file__).resolve().parent.parent
TRACEMIKU = REPO / "tracemiku"

# The host script has no .py extension; load it as a plain module by
# exec'ing its source into a fresh module namespace.
mod = types.ModuleType("tracemiku_host")
mod.__file__ = str(TRACEMIKU)
mod.__name__ = "tracemiku_host"
exec(compile(TRACEMIKU.read_text(), "tracemiku", "exec"), mod.__dict__)

RET = 0xD65F03C0  # ret
BLR = 0xD63F0110  # blr x8
BL = 0x94000002  # bl #8
NOP = 0xD503201F  # nop
MOV = 0xAA0103E0  # mov x0, x1


def test_is_ret_inst_true_for_ret():
    assert mod._is_ret_inst(RET) is True
    assert mod._is_ret_inst(NOP) is False
    assert mod._is_ret_inst(BL) is False
    assert mod._is_ret_inst(BLR) is False


def test_is_ret_inst_matches_core_mask_contract():
    # Core's call_analysis uses (inst & 0xFFFFFC1F) == 0xD63F0000 for blr and
    # the host uses (inst & 0xfffffc1f) == 0xd65f0000 for ret. These are
    # complementary masks over the same encoding space: a ret must never be
    # classified as blr and vice versa.
    for inst in (RET, BLR, BL, NOP, MOV):
        host_ret = mod._is_ret_inst(inst)
        core_blr = (inst & 0xFFFFFC1F) == 0xD63F0000
        assert not (host_ret and core_blr), f"inst {inst:#x} both ret and blr?"


def test_decode_last_inst_ret_detection():
    is_ret, asm = mod._decode_last_inst(0x100000, RET)
    assert is_ret is True
    assert "ret" in asm


def test_decode_last_inst_fallback_on_bad_encoding():
    # 0xFFFFFFFF is not a valid instruction; falls back to the mask check
    # (not ret) and an .inst literal.
    is_ret, asm = mod._decode_last_inst(0x100000, 0xFFFFFFFF)
    assert is_ret is False
    assert asm.startswith(".inst 0x")


def test_read_trace_tail_single_record(tmp_path):
    p = tmp_path / "trace.bin"
    buf = bytearray(272)
    buf[0:8] = struct.pack("<Q", 0x100000)
    buf[268:272] = struct.pack("<I", RET)
    p.write_bytes(bytes(buf))
    n, first_pc, last_pc, last_inst = mod._read_trace_tail(p)
    assert n == 1
    assert first_pc == 0x100000
    assert last_pc == 0x100000
    assert last_inst == RET


def test_read_trace_tail_multi_record(tmp_path):
    p = tmp_path / "trace.bin"
    buf = bytearray(272 * 3)
    for i in range(3):
        off = i * 272
        buf[off : off + 8] = struct.pack("<Q", 0x100000 + i * 4)
        buf[off + 268 : off + 272] = struct.pack("<I", NOP)
    buf[272 * 2 + 268 : 272 * 3] = struct.pack("<I", RET)
    p.write_bytes(bytes(buf))
    n, first_pc, last_pc, last_inst = mod._read_trace_tail(p)
    assert n == 3
    assert first_pc == 0x100000
    assert last_pc == 0x100008
    assert last_inst == RET


def test_read_trace_tail_empty_file(tmp_path):
    p = tmp_path / "trace.bin"
    p.write_bytes(b"")
    n, first_pc, last_pc, last_inst = mod._read_trace_tail(p)
    assert n == 0
    assert first_pc is None and last_pc is None and last_inst is None
