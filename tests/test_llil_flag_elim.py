"""Pass 4.5 flag elimination — 单元测试."""
from __future__ import annotations
from viewer.decompiler.llil import (
    LlilExpr, ssa_block, flag_elim_block, flag_elim_blocks,
    set_reg, reg, const, sub, if_, flag_cond,
    LLIL_SET_FLAG, LLIL_IF, LLIL_FLAG_COND, LLIL_SUB,
    LLIL_CMP_E, LLIL_CMP_NE, LLIL_CMP_SLT, LLIL_CMP_SGT,
    LLIL_CMP_UGE,
)


def _set_flag(expr):
    """SET_FLAG('cmp_result', expr)."""
    return LlilExpr(LLIL_SET_FLAG, size=expr.size,
                    operands=["cmp_result", expr], pc=0)


def test_flag_elim_eq():
    """SET_FLAG SUB + IF(eq) → IF(CMP_E)."""
    blk = ssa_block(0x1000, [
        _set_flag(sub(reg("x0"), const(5))),
        if_(flag_cond("eq"), 0x2000, 0x1004),
    ])
    new = flag_elim_block(blk)
    assert len(new.roots) == 1   # SET_FLAG 删了
    if_root = new.roots[0]
    assert if_root.op == LLIL_IF
    assert if_root.operands[0].op == LLIL_CMP_E


def test_flag_elim_ne():
    blk = ssa_block(0x1000, [
        _set_flag(sub(reg("x0"), const(0))),
        if_(flag_cond("ne"), 0x2000, 0x1004),
    ])
    new = flag_elim_block(blk)
    assert new.roots[0].operands[0].op == LLIL_CMP_NE


def test_flag_elim_lt_signed():
    blk = ssa_block(0x1000, [
        _set_flag(sub(reg("x0"), reg("x1"))),
        if_(flag_cond("lt"), 0x2000, 0x1004),
    ])
    new = flag_elim_block(blk)
    assert new.roots[0].operands[0].op == LLIL_CMP_SLT


def test_flag_elim_unsigned_hs_cs():
    """cs / hs → CMP_UGE."""
    blk = ssa_block(0x1000, [
        _set_flag(sub(reg("x0"), reg("x1"))),
        if_(flag_cond("hs"), 0x2000, 0x1004),
    ])
    new = flag_elim_block(blk)
    assert new.roots[0].operands[0].op == LLIL_CMP_UGE


def test_flag_elim_no_chain_when_intervening():
    """SET_FLAG; mov x0,#5; IF — 中间有别 op → 不合并."""
    blk = ssa_block(0x1000, [
        _set_flag(sub(reg("x0"), const(5))),
        set_reg("x0", const(5)),
        if_(flag_cond("eq"), 0x2000, 0x1004),
    ])
    new = flag_elim_block(blk)
    # IF cond 仍是 LLIL_FLAG_COND
    assert new.roots[-1].operands[0].op == LLIL_FLAG_COND


def test_flag_elim_no_set_flag_no_change():
    """没 SET_FLAG, IF 不变."""
    blk = ssa_block(0x1000, [
        if_(flag_cond("eq"), 0x2000, 0x1004),
    ])
    new = flag_elim_block(blk)
    assert len(new.roots) == 1
    assert new.roots[0].operands[0].op == LLIL_FLAG_COND


def test_flag_elim_unknown_cond_keeps_flag():
    """al / nv / 不识别 cond → 不合并."""
    blk = ssa_block(0x1000, [
        _set_flag(sub(reg("x0"), const(5))),
        if_(flag_cond("al"), 0x2000, 0x1004),
    ])
    new = flag_elim_block(blk)
    assert len(new.roots) == 2   # SET_FLAG 留下
    assert new.roots[1].operands[0].op == LLIL_FLAG_COND


def test_flag_elim_blocks_count():
    blk = ssa_block(0x1000, [
        _set_flag(sub(reg("x0"), const(5))),
        if_(flag_cond("gt"), 0x2000, 0x1004),
    ])
    out, n = flag_elim_blocks({0x1000: blk})
    assert n == 1   # 删了 1 条 SET_FLAG
