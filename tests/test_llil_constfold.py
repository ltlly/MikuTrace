"""Pass 3 constfold on LLIL expression tree — 单元测试."""
from __future__ import annotations
import pytest
from viewer.decompiler.llil import (
    LlilExpr, ssa_block, constfold_block, constfold_blocks,
    set_reg, reg, const, add, sub, mul, xor, and_, or_, lsl, neg,
    load, store,
    LLIL_SET_REG, LLIL_REG, LLIL_CONST, LLIL_ADD, LLIL_LOAD, LLIL_STORE,
    LLIL_SX, LLIL_ZX,
)


def test_fold_two_consts():
    """add(1, 2) → const(3)."""
    e = set_reg("x0", add(const(1), const(2)))
    blk = ssa_block(0x1000, [e])
    new = constfold_block(blk)
    val = new.roots[0].operands[1]
    assert val.op == LLIL_CONST
    assert val.operands == [3]


def test_fold_chain_through_reg():
    """set_reg(x0, 5); set_reg(x0, x0+3) → second 折成 const(8)."""
    r1 = set_reg("x0", const(5))
    use_x0 = reg("x0")
    r2 = set_reg("x0", add(use_x0, const(3)))
    blk = ssa_block(0x1000, [r1, r2])
    new = constfold_block(blk)
    v2 = new.roots[1].operands[1]
    assert v2.op == LLIL_CONST
    assert v2.operands == [8]


def test_fold_xor_chain():
    r1 = set_reg("x0", const(0xFF))
    r2 = set_reg("x0", xor(reg("x0"), const(0xAA)))
    blk = ssa_block(0x1000, [r1, r2])
    new = constfold_block(blk)
    v2 = new.roots[1].operands[1]
    assert v2.op == LLIL_CONST
    assert v2.operands == [0x55]


def test_fold_lsl():
    r1 = set_reg("x0", const(1))
    r2 = set_reg("x0", lsl(reg("x0"), const(4)))
    blk = ssa_block(0x1000, [r1, r2])
    new = constfold_block(blk)
    assert new.roots[1].operands[1].operands == [0x10]


def test_fold_neg():
    r1 = set_reg("x0", const(5))
    r2 = set_reg("x0", neg(reg("x0")))
    blk = ssa_block(0x1000, [r1, r2])
    new = constfold_block(blk)
    assert new.roots[1].operands[1].operands == [0xFFFFFFFFFFFFFFFB]


def test_fold_nested():
    """add(add(1, 2), add(3, 4)) → const(10)."""
    inner1 = add(const(1), const(2))
    inner2 = add(const(3), const(4))
    outer = add(inner1, inner2)
    e = set_reg("x0", outer)
    blk = ssa_block(0x1000, [e])
    new = constfold_block(blk)
    val = new.roots[0].operands[1]
    assert val.op == LLIL_CONST
    assert val.operands == [10]


def test_fold_unknown_reg_no_fold():
    """add(REG(x9), const(1)) — x9 没 def, 不 fold."""
    e = set_reg("x0", add(reg("x9"), const(1)))
    blk = ssa_block(0x1000, [e])
    new = constfold_block(blk)
    val = new.roots[0].operands[1]
    assert val.op == LLIL_ADD


def test_fold_load_addr_inner():
    """load(add(const(0x1000), const(0x40))) → load(const(0x1040))."""
    e = set_reg("x0", load(add(const(0x1000), const(0x40)), size=8))
    blk = ssa_block(0x1000, [e])
    new = constfold_block(blk)
    val = new.roots[0].operands[1]
    assert val.op == LLIL_LOAD
    addr = val.operands[0]
    assert addr.op == LLIL_CONST
    assert addr.operands == [0x1040]


def test_fold_load_breaks_const_chain():
    """set_reg(x0, 1); set_reg(x0, load(...)); set_reg(x1, x0+5)
    → x1 不应折 (load 出来的 x0 不 const)."""
    r1 = set_reg("x0", const(1))
    r2 = set_reg("x0", load(reg("x9"), size=8))
    r3 = set_reg("x1", add(reg("x0"), const(5)))
    blk = ssa_block(0x1000, [r1, r2, r3])
    new = constfold_block(blk)
    # r3 不应折成 const
    assert new.roots[2].operands[1].op == LLIL_ADD


def test_fold_store_addr_value():
    """store(add(const(0x1000), const(8)), const(42)) → store(const(0x1008), const(42))."""
    e = store(add(const(0x1000), const(8)),
              const(42), size=8)
    blk = ssa_block(0x1000, [e])
    new = constfold_block(blk)
    st = new.roots[0]
    assert st.op == LLIL_STORE
    addr = st.operands[0]
    assert addr.op == LLIL_CONST
    assert addr.operands == [0x1008]


def test_fold_blocks_count():
    blk1 = ssa_block(0x1000, [
        set_reg("x0", const(1)),
        set_reg("x0", add(reg("x0"), const(2))),
    ])
    blk2 = ssa_block(0x2000, [
        set_reg("x1", const(5)),
        set_reg("x1", mul(reg("x1"), const(3))),
    ])
    out, n = constfold_blocks({0x1000: blk1, 0x2000: blk2})
    assert n == 2
    assert out[0x1000].roots[1].operands[1].operands == [3]
    assert out[0x2000].roots[1].operands[1].operands == [15]


def test_fold_zx_const():
    e = set_reg("x0", LlilExpr(LLIL_ZX, size=8,
                               operands=[const(0x123456789ABCDEF0)],
                               extra={"src_size": 4}))
    blk = ssa_block(0x1000, [e])
    new = constfold_block(blk)
    val = new.roots[0].operands[1]
    assert val.op == LLIL_CONST
    assert val.operands == [0x9ABCDEF0]


def test_fold_sx_const():
    e = set_reg("x0", LlilExpr(LLIL_SX, size=8,
                               operands=[const(0xFFFFFFFF)],
                               extra={"src_size": 4}))
    blk = ssa_block(0x1000, [e])
    new = constfold_block(blk)
    val = new.roots[0].operands[1]
    assert val.op == LLIL_CONST
    assert val.operands == [0xFFFFFFFFFFFFFFFF]
