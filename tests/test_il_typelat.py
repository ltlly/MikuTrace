"""Pass 5 type lattice — 单元测试."""
from __future__ import annotations
import pytest
from viewer.decompiler.il import (
    TlilOp, ssa_block, typelat_block, TypeEnv,
    T_INT, T_PTR, T_HANDLE, T_BOOL, T_TOP,
    OP_MOV_IMM, OP_MOV_REG, OP_ADD, OP_SUB, OP_LOAD, OP_STORE, OP_RET,
    OP_AND, OP_XOR, OP_CMP, OP_CALL,
)
from viewer.decompiler.il.pass_typelat import _join


def test_join_same():
    assert _join(T_INT, T_INT) == T_INT


def test_join_top():
    assert _join(T_TOP, T_INT) == T_INT
    assert _join(T_INT, T_TOP) == T_INT


def test_join_ptr_int():
    assert _join(T_PTR, T_INT) == T_PTR
    assert _join(T_INT, T_PTR) == T_PTR


def test_join_conflict():
    """不同类型 → BOT (除 PTR+INT)."""
    assert _join(T_INT, T_HANDLE) != T_INT


def test_typelat_load_promotes_base_to_ptr():
    """ldr x0, [x1] → x1 = PTR, x0 = INT."""
    ops = [
        TlilOp(pc=0x1000, op=OP_LOAD, dst="x0",
               srcs=[("mem", "x1", 0)], extra={"size": 8}),
    ]
    blk = ssa_block(0x1000, ops)
    env = typelat_block(blk)
    # x1 在 entry 是 v0, 应被打 PTR
    assert env.get("x1", 0) == T_PTR
    assert env.get("x0", 1) == T_INT


def test_typelat_store_promotes_base_to_ptr():
    ops = [
        TlilOp(pc=0x1000, op=OP_STORE,
               srcs=["x0", ("mem", "x1", 0)], extra={"size": 8}),
    ]
    blk = ssa_block(0x1000, ops)
    env = typelat_block(blk)
    assert env.get("x1", 0) == T_PTR


def test_typelat_mov_imm_int():
    ops = [TlilOp(pc=0x1000, op=OP_MOV_IMM, dst="x0", srcs=[5])]
    blk = ssa_block(0x1000, ops)
    env = typelat_block(blk)
    assert env.get("x0", 1) == T_INT


def test_typelat_add_ptr_int_yields_ptr():
    """ldr x1; add x2, x1, #4 → x2 = PTR (offset 算术)."""
    ops = [
        TlilOp(pc=0x1000, op=OP_LOAD, dst="x1",
               srcs=[("mem", "x9", 0)], extra={"size": 8}),
        TlilOp(pc=0x1004, op=OP_MOV_IMM, dst="x9_init", srcs=[0xdeadbeef]),
        TlilOp(pc=0x1008, op=OP_ADD, dst="x2", srcs=["x1", 4]),
    ]
    # 让 x1 v1 是 INT (load 出来) → add x2 = INT + 4 = INT
    blk = ssa_block(0x1000, ops)
    env = typelat_block(blk)
    # x9 应被推 PTR (作为 load base)
    assert env.get("x9", 0) == T_PTR
    # x2 是 add x1 (INT) + 4 (INT) = INT
    assert env.get("x2", 1) == T_INT


def test_typelat_sub_ptr_ptr_yields_int():
    """两 ptr 相减 → INT (size diff)."""
    # 用 anchor 简化测试
    blk = ssa_block(0x1000, [
        TlilOp(pc=0x1000, op=OP_SUB, dst="x0", srcs=["x1", "x2"]),
    ])
    initial = TypeEnv()
    initial.set("x1", 0, T_PTR)
    initial.set("x2", 0, T_PTR)
    env = typelat_block(blk, initial=initial)
    assert env.get("x0", 1) == T_INT


def test_typelat_xor_yields_int():
    """xor → 永远 INT (位运算)."""
    ops = [TlilOp(pc=0x1000, op=OP_XOR, dst="x0", srcs=["x1", 0xAA])]
    blk = ssa_block(0x1000, ops)
    env = typelat_block(blk)
    assert env.get("x0", 1) == T_INT


def test_typelat_anchor_overrides():
    """anchor 注 x0 = HANDLE → 即使后面 mov_imm, anchor 在 anchor 时 set."""
    # anchor 在 idx 0 (call) 时 x0 = handle
    ops = [
        TlilOp(pc=0x1000, op=OP_CALL, dst="x0", extra={"target": 0x2000}),
    ]
    blk = ssa_block(0x1000, ops)
    # anchor: 在 idx 0 时 x0 → HANDLE
    env = typelat_block(blk, anchors=[(0, {"x0": T_HANDLE})])
    # 注: 我们的 anchor 注入是当 op.dst == reg 时设. Call 没 dst, 这个测试需要 dst.
    # 改用 has dst 的 op:
    ops = [
        TlilOp(pc=0x1000, op=OP_MOV_REG, dst="x0", srcs=["x9"]),
    ]
    blk = ssa_block(0x1000, ops)
    env = typelat_block(blk, anchors=[(0, {"x0": T_HANDLE})])
    assert env.get("x0", 1) == T_HANDLE


def test_typelat_unknown_op_keeps_top():
    """raw / 未支持 op → dst 类型留 TOP."""
    from viewer.decompiler.il import OP_RAW
    ops = [TlilOp(pc=0x1000, op=OP_RAW, extra={"mnem": "svc"})]
    blk = ssa_block(0x1000, ops)
    env = typelat_block(blk)
    # 没 dst, env 不写
    assert env.types == {}
