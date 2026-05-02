"""Pass 2 SSA — 单元测试."""
from __future__ import annotations
import pytest
from viewer.decompiler.il import (
    TlilOp, SsaInsn, SsaBlock, ssa_block, ssa_blocks,
    OP_MOV_IMM, OP_MOV_REG, OP_ADD, OP_LOAD, OP_STORE, OP_RET,
)


def test_ssa_empty():
    blk = ssa_block(0x1000, [])
    assert blk.insns == []
    assert blk.entry_versions == {}
    assert blk.exit_versions == {}


def test_ssa_single_def():
    ops = [TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[1])]
    blk = ssa_block(0x1000, ops)
    assert len(blk.insns) == 1
    assert blk.insns[0].dst_v == 1
    assert blk.exit_versions == {"x0": 1}


def test_ssa_multiple_defs_same_reg():
    """同 reg 重复 def → version 递增."""
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[1]),
        TlilOp(pc=0x1004, op=OP_MOV_IMM, dst="x0", srcs=[2]),
        TlilOp(pc=0x1008, op=OP_MOV_IMM, dst="x0", srcs=[3]),
    ]
    blk = ssa_block(0x1000, ops)
    assert [i.dst_v for i in blk.insns] == [1, 2, 3]
    assert blk.exit_versions == {"x0": 3}


def test_ssa_use_picks_latest_version():
    """add x1, x0, ... 的 src x0 应取入口/上一 def 的 version."""
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[5]),     # x0_v1
        TlilOp(pc=0x1004, op=OP_ADD, dst="x1", srcs=["x0", 3]),  # use x0_v1
    ]
    blk = ssa_block(0x1000, ops)
    add = blk.insns[1]
    assert add.src_v[0] == 1   # x0 version
    assert add.src_v[1] == -1  # imm 不是 reg


def test_ssa_no_dst_op():
    """cmp/store/branch 没 dst → dst_v=-1."""
    from viewer.decompiler.il import OP_CMP, OP_BRANCH_COND
    ops = [
        TlilOp(pc=0x1000, op=OP_CMP, srcs=["x0", 5]),
        TlilOp(pc=0x1004, op=OP_BRANCH_COND, extra={"cond": "eq", "target": 0x2000}),
    ]
    blk = ssa_block(0x1000, ops)
    assert all(i.dst_v == -1 for i in blk.insns)


def test_ssa_entry_versions_propagate():
    """上一 block 出口 versions → 下一 block 入口."""
    entry = {"x0": 5, "sp": 1}
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_REG, dst="x1", srcs=["x0"]),
    ]
    blk = ssa_block(0x1000, ops, entry_versions=entry)
    assert blk.entry_versions == {"x0": 5, "sp": 1}
    # use x0 应该 v5 (来自 entry)
    assert blk.insns[0].src_v[0] == 5
    # x1 没在 entry → 默认 0, 第一次 def 后 v1
    assert blk.insns[0].dst_v == 1
    assert blk.exit_versions["x1"] == 1
    assert blk.exit_versions["x0"] == 5
    assert blk.exit_versions["sp"] == 1


def test_ssa_blocks_per_block_independent():
    """ssa_blocks() 每 block 独立从 0 起 (entry_versions 默认空)."""
    blocks = {
        0x1000: [TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[1])],
        0x2000: [TlilOp(pc=0x2000, op=OP_MOV_IMM, dst="x0", srcs=[2])],
    }
    out = ssa_blocks(blocks)
    assert len(out) == 2
    assert out[0x1000].insns[0].dst_v == 1
    assert out[0x2000].insns[0].dst_v == 1   # 各自从 0


def test_ssa_load_mem_src():
    """OP_LOAD srcs[0] 是 ('mem', base, disp) tuple, src_v 应 -1 (非 reg)."""
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x1", srcs=[0]),
        TlilOp(pc=0x1004, op=OP_LOAD, dst="x0",
               srcs=[("mem", "x1", 0x10)], extra={"size": 8}),
    ]
    blk = ssa_block(0x1000, ops)
    assert blk.insns[1].src_v == [-1]   # tuple 不是 reg
    # 但 base reg x1 是 use, lift 已经把 ('mem', 'x1', 0x10) 当 srcs 项,
    # 这里我们是按 srcs 字面 type 决定 src_v. base reg 信息要 pass 6 提取.
