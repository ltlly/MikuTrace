"""LLIL constfold 的 memshadow LOAD fold (trace 反编译器独家)."""
from __future__ import annotations
import pytest
from viewer.decompiler.llil import (
    set_reg, reg, const, add, load, ssa_block, constfold_block,
    LLIL_CONST, LLIL_LOAD, LLIL_ADD,
)


class FakeMem:
    """Minimal memshadow stub for test."""
    def __init__(self, mapping: dict, built: bool = True):
        # mapping: dict[addr → byte]
        self.mapping = mapping
        self.built = built

    def byte_at(self, addr, t):
        if addr in self.mapping:
            return (self.mapping[addr], "r", 0)
        return (None, "??", None)


def test_load_const_addr_folds_via_memshadow():
    """load(const(0x1000), 8) + memshadow has bytes → fold to LLIL_CONST."""
    bytes_map = {0x1000 + i: (0x40 | i) for i in range(8)}
    mem = FakeMem(bytes_map)
    e = set_reg("x0", load(const(0x1000), size=8))
    blk = ssa_block(0x100, [e])
    new = constfold_block(blk, mem=mem)
    v = new.roots[0].operands[1]
    assert v.op == LLIL_CONST
    # LE: 0x40 | (0x41<<8) | (0x42<<16) | ... = 0x4746454443424140
    assert v.operands[0] == 0x4746454443424140


def test_load_const_addr_size4():
    """4-byte LE load."""
    bytes_map = {0x2000: 0x01, 0x2001: 0x02, 0x2002: 0x03, 0x2003: 0x04}
    mem = FakeMem(bytes_map)
    e = set_reg("x0", load(const(0x2000), size=4))
    blk = ssa_block(0x100, [e])
    new = constfold_block(blk, mem=mem)
    v = new.roots[0].operands[1]
    assert v.op == LLIL_CONST
    assert v.operands[0] == 0x04030201


def test_load_const_addr_missing_byte_no_fold():
    """memshadow 缺一个字节 → 不 fold."""
    bytes_map = {0x3000: 0x01, 0x3001: 0x02}   # 缺后面 6 字节 (size=8)
    mem = FakeMem(bytes_map)
    e = set_reg("x0", load(const(0x3000), size=8))
    blk = ssa_block(0x100, [e])
    new = constfold_block(blk, mem=mem)
    v = new.roots[0].operands[1]
    assert v.op == LLIL_LOAD


def test_load_non_const_addr_no_fold():
    """addr 不可推 const → 不 fold (即使 memshadow 知道很多字节)."""
    bytes_map = {0x4000 + i: i for i in range(16)}
    mem = FakeMem(bytes_map)
    e = set_reg("x0", load(reg("x9"), size=8))
    blk = ssa_block(0x100, [e])
    new = constfold_block(blk, mem=mem)
    v = new.roots[0].operands[1]
    assert v.op == LLIL_LOAD


def test_load_with_mem_arg_none_no_fold():
    """mem=None → 不 fold (向后兼容)."""
    e = set_reg("x0", load(const(0x5000), size=8))
    blk = ssa_block(0x100, [e])
    new = constfold_block(blk, mem=None)
    v = new.roots[0].operands[1]
    assert v.op == LLIL_LOAD


def test_load_addr_fold_then_mem_fold_chained():
    """LLIL_ADD(CONST, CONST) 先 fold 成 CONST, 再 LOAD 用 memshadow fold."""
    bytes_map = {0x6010 + i: (0xA0 | i) for i in range(4)}
    mem = FakeMem(bytes_map)
    e = set_reg("x0", load(add(const(0x6000), const(0x10)), size=4))
    blk = ssa_block(0x100, [e])
    new = constfold_block(blk, mem=mem)
    v = new.roots[0].operands[1]
    assert v.op == LLIL_CONST
    assert v.operands[0] == 0xA3A2A1A0


def test_chained_load_via_uidf_addr():
    """UIDF 推 reg = const, then LOAD(reg) 也能用 memshadow fold."""
    from viewer.decompiler.llil import ObservedValues, apply_uidf_to_constfold_env
    bytes_map = {0x7000 + i: (i + 0x10) for i in range(8)}
    mem = FakeMem(bytes_map)
    blk = ssa_block(0x100, [
        set_reg("x9", load(reg("x99"), size=8), pc=0x100),     # x9 ← LOAD (UIDF says const 0x7000)
        set_reg("x0", load(reg("x9"), size=8), pc=0x104),       # LOAD(x9)
    ])
    uidf = {
        (0x100, 0): ObservedValues(
            pc=0x100, reg="x9", n_hits=10, distinct_count=1,
            first=0x7000, last=0x7000, sample=[0x7000],
        )
    }
    new = constfold_block(blk, uidf=uidf, mem=mem)
    # 第二条 set_reg(x0, load(x9)) — x9 实测 const 0x7000, mem fold load → LLIL_CONST
    v2 = new.roots[1].operands[1]
    assert v2.op == LLIL_CONST
    expected = (0x10 | (0x11 << 8) | (0x12 << 16) | (0x13 << 24)
                | (0x14 << 32) | (0x15 << 40) | (0x16 << 48) | (0x17 << 56))
    assert v2.operands[0] == expected
