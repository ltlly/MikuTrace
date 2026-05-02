"""Pass 1 lift (ARM64 → TLIL) — 单元测试.

§7.0 自查:
  ✓ 测试覆盖核心 op (mov/add/sub/load/store/cmp/branch), 不绑特定 SO
  ✓ 验证未识别 op 走 OP_RAW + extra['unhandled']=True (不崩, 不假装识别)
  ✓ 静态 PC LRU cache: 同 (pc, inst) 多次调用返回同 tuple
"""
from __future__ import annotations
import struct
import pytest
from viewer.decompiler.il import (
    lift_arm64, lift_static, LiftStats, TlilOp,
    OP_MOV_IMM, OP_MOV_REG, OP_ADD, OP_SUB, OP_LOAD, OP_STORE,
    OP_CMP, OP_BRANCH_COND, OP_BRANCH_UNCOND, OP_BRANCH_INDIRECT,
    OP_CALL, OP_CALL_INDIRECT, OP_RET, OP_RAW, OP_NOP,
    OPS_BRANCH,
)


# 用真 ARM64 编码; keystone 已在 deps
def _asm(s: str) -> int:
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    enc, _ = ks.asm(s)
    return int.from_bytes(bytes(enc), "little")


def test_lift_mov_imm():
    ops = lift_arm64(0x1000, _asm("mov x0, #1"))
    assert len(ops) == 1
    o = ops[0]
    assert o.op == OP_MOV_IMM
    assert o.dst == "x0"
    assert o.srcs == [1]


def test_lift_mov_reg():
    ops = lift_arm64(0x1000, _asm("mov x0, x1"))
    assert len(ops) == 1
    o = ops[0]
    assert o.op == OP_MOV_REG
    assert o.dst == "x0"
    assert o.srcs == ["x1"]


def test_lift_add_imm():
    ops = lift_arm64(0x1000, _asm("add x0, x1, #0x10"))
    assert ops[0].op == OP_ADD
    assert ops[0].dst == "x0"
    # srcs: x1 (capstone use) + 0x10 (imm)
    assert "x1" in ops[0].srcs
    assert 0x10 in ops[0].srcs


def test_lift_add_reg():
    ops = lift_arm64(0x1000, _asm("add x0, x1, x2"))
    assert ops[0].op == OP_ADD
    assert ops[0].dst == "x0"
    assert "x1" in ops[0].srcs and "x2" in ops[0].srcs


def test_lift_sub():
    ops = lift_arm64(0x1000, _asm("sub x0, x1, #4"))
    assert ops[0].op == OP_SUB


def test_lift_ldr():
    ops = lift_arm64(0x1000, _asm("ldr x0, [x1]"))
    assert ops[0].op == OP_LOAD
    assert ops[0].dst == "x0"
    # srcs[0] 是 ('mem', base, disp)
    assert ops[0].srcs[0][0] == "mem"
    assert ops[0].extra["size"] == 8


def test_lift_ldr_with_offset():
    ops = lift_arm64(0x1000, _asm("ldr x0, [x1, #0x40]"))
    assert ops[0].op == OP_LOAD
    mem = ops[0].srcs[0]
    assert mem == ("mem", "x1", 0x40)


def test_lift_str():
    ops = lift_arm64(0x1000, _asm("str x0, [x1, #8]"))
    assert ops[0].op == OP_STORE
    # srcs: [src_reg, mem_addr]
    assert ops[0].srcs[0] == "x0"
    assert ops[0].srcs[1] == ("mem", "x1", 8)


def test_lift_self_update_load_is_raw():
    """ldr x0, [x1, #0x40]! self-update — MVP 走 OP_RAW (避免错的 SSA)."""
    ops = lift_arm64(0x1000, _asm("ldr x0, [x1, #0x40]!"))
    assert ops[0].op == OP_RAW
    assert ops[0].extra.get("unhandled") is True
    assert ops[0].extra.get("note") == "self_update_load"


def test_lift_cmp():
    ops = lift_arm64(0x1000, _asm("cmp x0, #5"))
    assert ops[0].op == OP_CMP
    assert "x0" in ops[0].srcs and 5 in ops[0].srcs


def test_lift_b_uncond():
    # keystone 编 'b #0x2000' 起 PC=0 → offset 0x2000.
    # capstone 解 PC=0x1000 → target = 0x1000 + 0x2000 = 0x3000.
    ops = lift_arm64(0x1000, _asm("b #0x2000"))
    assert ops[0].op == OP_BRANCH_UNCOND
    assert ops[0].extra["target"] == 0x3000


def test_lift_b_cond():
    ops = lift_arm64(0x1000, _asm("b.eq #0x2000"))
    assert ops[0].op == OP_BRANCH_COND
    assert ops[0].extra["cond"] == "eq"
    assert ops[0].extra["target"] == 0x3000


def test_lift_bl():
    ops = lift_arm64(0x1000, _asm("bl #0x4000"))
    assert ops[0].op == OP_CALL
    assert ops[0].extra["target"] == 0x5000


def test_lift_blr():
    ops = lift_arm64(0x1000, _asm("blr x16"))
    assert ops[0].op == OP_CALL_INDIRECT
    assert ops[0].srcs == ["x16"]


def test_lift_br():
    ops = lift_arm64(0x1000, _asm("br x16"))
    assert ops[0].op == OP_BRANCH_INDIRECT


def test_lift_ret():
    ops = lift_arm64(0x1000, _asm("ret"))
    assert ops[0].op == OP_RET


def test_lift_cbz():
    ops = lift_arm64(0x1000, _asm("cbz x0, #0x2000"))
    assert ops[0].op == OP_BRANCH_COND
    assert ops[0].extra["cond"] == "eq"


def test_lift_nop():
    ops = lift_arm64(0x1000, _asm("nop"))
    assert ops[0].op == OP_NOP


def test_lift_unknown_op_is_raw():
    """svc/SIMD/未实现 → OP_RAW + extra['unhandled']=True."""
    ops = lift_arm64(0x1000, _asm("svc #0"))
    assert ops[0].op == OP_RAW
    assert ops[0].extra.get("unhandled") is True


def test_lift_cache_returns_same_tuple():
    """LRU cache: 同 (pc, inst) 返回 same tuple."""
    inst = _asm("mov x0, #1")
    a = lift_arm64(0x1000, inst)
    b = lift_arm64(0x1000, inst)
    assert a is b


def test_lift_static_aggregates():
    """lift_static dedup PCs + 出统计."""
    items = [
        (0x1000, _asm("mov x0, #1")),
        (0x1004, _asm("add x0, x0, #1")),
        (0x1008, _asm("ret")),
        (0x1000, _asm("mov x0, #1")),       # 重复 PC, dedup
    ]
    out, stats = lift_static(items)
    assert len(out) == 3
    assert stats.coverage() == 1.0    # 全识别
    assert OP_MOV_IMM in stats.by_op
    assert OP_ADD in stats.by_op
    assert OP_RET in stats.by_op


def test_branch_classification():
    """OPS_BRANCH 集合包含所有分支 op."""
    for op_name in (OP_BRANCH_UNCOND, OP_BRANCH_COND, OP_BRANCH_INDIRECT,
                     OP_CALL, OP_CALL_INDIRECT, OP_RET):
        assert op_name in OPS_BRANCH
    assert OP_MOV_IMM not in OPS_BRANCH
    assert OP_LOAD not in OPS_BRANCH


def test_tlil_op_short_repr():
    """TlilOp.short() 不崩, 输出可读."""
    o = TlilOp(pc=0x1000, op=OP_ADD, dst="x0", srcs=["x1", 0x10])
    s = o.short()
    assert "add" in s
    assert "x0" in s
    assert "x1" in s


def test_lift_stats_coverage_zero_total():
    s = LiftStats()
    assert s.coverage() == 1.0   # 空 → 100%
