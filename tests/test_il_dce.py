"""Pass 4 dead code elimination — 单元测试."""
from __future__ import annotations
import pytest
from viewer.decompiler.il import (
    TlilOp, ssa_block, dce_block, dce_blocks,
    OP_MOV_IMM, OP_MOV_REG, OP_ADD, OP_LOAD, OP_STORE, OP_RET,
    OP_CMP, OP_BRANCH_COND, OP_CALL,
)


def _build(ops):
    return ssa_block(0x1000, ops)


def test_dce_keeps_side_effects():
    """store / call / ret 永远保留, 即使 dst 未读."""
    ops = [
        TlilOp(pc=0x1000, op=OP_STORE,
               srcs=["x0", ("mem", "sp", 0)], extra={"size": 8}),
        TlilOp(pc=0x1004, op=OP_CALL, extra={"target": 0x2000}),
        TlilOp(pc=0x1008, op=OP_RET),
    ]
    blk = _build(ops)
    new = dce_block(blk)
    assert len(new.insns) == 3   # 全保留


def test_dce_removes_unused_def():
    """mov x0,#1 但后续没用 x0 → 删."""
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[1]),  # dead
        TlilOp(pc=0x1004, op=OP_RET),
    ]
    blk = _build(ops)
    # exit_versions 默认有 x0:1 (被 SSA 标), 把它从 live 集合排除
    blk.exit_versions = {}   # 模拟跨 block 没人用 x0
    new = dce_block(blk)
    assert len(new.insns) == 1
    assert new.insns[0].base.op == OP_RET


def test_dce_keeps_used_def():
    """mov x0,#1; ret + 假设跨 block x0 live → 保留."""
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[1]),
        TlilOp(pc=0x1004, op=OP_RET),
    ]
    blk = _build(ops)
    # exit_versions x0=1 默认在 (SSA 出来的), 表示出口 live
    new = dce_block(blk)
    assert len(new.insns) == 2


def test_dce_chained_use_keeps_both():
    """mov x0,#1; add x1,x0,#2; ret + x1 跨块用 → 都保留."""
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[1]),
        TlilOp(pc=0x1004, op=OP_ADD, dst="x1", srcs=["x0", 2]),
        TlilOp(pc=0x1008, op=OP_RET),
    ]
    blk = _build(ops)
    # x1:1 在 exit_versions, x0 也是. live = both. 全保
    new = dce_block(blk)
    assert len(new.insns) == 3


def test_dce_dead_def_overwrites_live():
    """mov x0,#1 (dead); mov x0,#2 (live, 跨块 live) → 删第一条."""
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[1]),
        TlilOp(pc=0x1004, op=OP_MOV_IMM, dst="x0", srcs=[2]),
        TlilOp(pc=0x1008, op=OP_RET),
    ]
    blk = _build(ops)
    # exit x0=2 是 live, x0_v1 不在 live (被 v2 覆盖)
    new = dce_block(blk)
    # 第一条 mov x0,#1 是 dead
    op_codes = [i.base.op for i in new.insns]
    srcs = [i.base.srcs for i in new.insns if i.base.op == OP_MOV_IMM]
    assert OP_MOV_IMM in op_codes
    assert OP_RET in op_codes
    assert [2] in srcs   # x0=2 留
    assert [1] not in srcs   # x0=1 删


def test_dce_load_kept_even_if_unused():
    """load 永远保留 (mem read 可能 page-fault, 不能删)."""
    ops = [
        TlilOp(pc=0x1000, op=OP_LOAD, dst="x0",
               srcs=[("mem", "x1", 0)], extra={"size": 8}),
        TlilOp(pc=0x1004, op=OP_RET),
    ]
    blk = _build(ops)
    blk.exit_versions = {}   # x0 跨块也 dead
    new = dce_block(blk)
    # load 留, ret 留
    assert len(new.insns) == 2


def test_dce_cmp_kept():
    """cmp 没 dst 但有 flags 副作用, 永远留."""
    ops = [
        TlilOp(pc=0x1000, op=OP_CMP, srcs=["x0", 0]),
        TlilOp(pc=0x1004, op=OP_BRANCH_COND, extra={"cond": "eq", "target": 0x2000}),
    ]
    blk = _build(ops)
    new = dce_block(blk)
    assert len(new.insns) == 2


def test_dce_blocks_returns_count():
    blk1 = _build([
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[1]),  # dead
        TlilOp(pc=0x1004, op=OP_RET),
    ])
    blk1.exit_versions = {}
    blk2 = _build([
        TlilOp(pc=0x2000, op=OP_MOV_IMM, dst="x0", srcs=[2]),
        TlilOp(pc=0x2004, op=OP_MOV_IMM, dst="x0", srcs=[3]),  # 第一条 dead
        TlilOp(pc=0x2008, op=OP_RET),
    ])
    out, removed = dce_blocks({0x1000: blk1, 0x2000: blk2})
    assert removed == 2  # 2 dead defs
