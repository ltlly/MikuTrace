"""Pass 3 constant folding — 单元测试."""
from __future__ import annotations
import pytest
from viewer.decompiler.il import (
    TlilOp, ssa_block, constfold_block, constfold_blocks,
    OP_MOV_IMM, OP_MOV_REG, OP_ADD, OP_SUB, OP_MUL,
    OP_AND, OP_OR, OP_XOR, OP_NEG, OP_NOT, OP_LSL, OP_LSR, OP_ASR,
    OP_LOAD,
)


def _build(ops):
    """Helper: lift ops list → SsaBlock."""
    return ssa_block(0x1000, ops)


def test_constfold_mov_chain():
    """mov x0,#1; add x0,x0,#2 → 第二条折成 mov x0,#3."""
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[1]),
        TlilOp(pc=0x1004, op=OP_ADD, dst="x0", srcs=["x0", 2]),
    ]
    blk = _build(ops)
    new = constfold_block(blk)
    assert len(new.insns) == 2
    assert new.insns[1].base.op == OP_MOV_IMM
    assert new.insns[1].base.srcs == [3]
    assert new.insns[1].base.extra.get("_folded_from") == OP_ADD


def test_constfold_three_step():
    """mov x0,#1; add x0,x0,#2; add x0,x0,#10 → 全折成 13."""
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[1]),
        TlilOp(pc=0x1004, op=OP_ADD, dst="x0", srcs=["x0", 2]),
        TlilOp(pc=0x1008, op=OP_ADD, dst="x0", srcs=["x0", 10]),
    ]
    blk = _build(ops)
    new = constfold_block(blk)
    assert new.insns[2].base.op == OP_MOV_IMM
    assert new.insns[2].base.srcs == [13]


def test_constfold_xor_chain():
    """OLLVM 常见: mov x0,#0xFF; eor x0,x0,#0xAA → 0x55."""
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[0xFF]),
        TlilOp(pc=0x1004, op=OP_XOR, dst="x0", srcs=["x0", 0xAA]),
    ]
    blk = _build(ops)
    new = constfold_block(blk)
    assert new.insns[1].base.srcs == [0x55]


def test_constfold_lsl():
    """mov x0,#1; lsl x0,x0,#4 → 0x10."""
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[1]),
        TlilOp(pc=0x1004, op=OP_LSL, dst="x0", srcs=["x0", 4]),
    ]
    blk = _build(ops)
    new = constfold_block(blk)
    assert new.insns[1].base.srcs == [0x10]


def test_constfold_neg():
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[5]),
        TlilOp(pc=0x1004, op=OP_NEG, dst="x0", srcs=["x0"]),
    ]
    blk = _build(ops)
    new = constfold_block(blk)
    assert new.insns[1].base.op == OP_MOV_IMM
    # -5 in 64-bit = 0xFFFFFFFFFFFFFFFB
    assert new.insns[1].base.srcs == [0xFFFFFFFFFFFFFFFB]


def test_constfold_mov_reg_chain():
    """mov x0,#7; mov x1,x0 → mov x1,#7."""
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[7]),
        TlilOp(pc=0x1004, op=OP_MOV_REG, dst="x1", srcs=["x0"]),
    ]
    blk = _build(ops)
    new = constfold_block(blk)
    assert new.insns[1].base.op == OP_MOV_IMM
    assert new.insns[1].base.srcs == [7]


def test_constfold_unknown_src_no_fold():
    """add x0, x_unknown, #1 → 不能 fold (x_unknown 不在 env)."""
    ops = [
        TlilOp(pc=0x1000, op=OP_ADD, dst="x0", srcs=["x9", 1]),
    ]
    blk = _build(ops)
    new = constfold_block(blk)
    # 没改: src x9 v0 没 const 来源
    assert new.insns[0].base.op == OP_ADD


def test_constfold_load_breaks_chain():
    """ldr x0, [x1] 后, x0 不再 const."""
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[1]),
        TlilOp(pc=0x1004, op=OP_LOAD, dst="x0",
               srcs=[("mem", "x1", 0)], extra={"size": 8}),
        TlilOp(pc=0x1008, op=OP_ADD, dst="x2", srcs=["x0", 1]),
    ]
    blk = _build(ops)
    new = constfold_block(blk)
    # add 不应折 (x0 被 load 覆盖, 不再 const)
    assert new.insns[2].base.op == OP_ADD


def test_constfold_dst_overwrite_clears_const():
    """mov x0,#1; load x0,...; (现在 x0 不 const); add x1,x0,#2 不折."""
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[1]),
        TlilOp(pc=0x1004, op=OP_LOAD, dst="x0",
               srcs=[("mem", "x1", 0)], extra={"size": 8}),
        TlilOp(pc=0x1008, op=OP_ADD, dst="x1", srcs=["x0", 2]),
    ]
    blk = _build(ops)
    new = constfold_block(blk)
    assert new.insns[2].base.op == OP_ADD


def test_constfold_blocks_returns_count():
    """constfold_blocks() 返回 (dict, total_folded)."""
    blk1 = _build([
        TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[1]),
        TlilOp(pc=0x1004, op=OP_ADD, dst="x0", srcs=["x0", 2]),
    ])
    blk2 = _build([
        TlilOp(pc=0x2000, op=OP_MOV_IMM, dst="x1", srcs=[5]),
        TlilOp(pc=0x2004, op=OP_MUL, dst="x1", srcs=["x1", 3]),
    ])
    out, n = constfold_blocks({0x1000: blk1, 0x2000: blk2})
    assert n == 2
    assert out[0x1000].insns[1].base.srcs == [3]
    assert out[0x2000].insns[1].base.srcs == [15]
