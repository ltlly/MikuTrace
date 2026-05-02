"""Pass 1 lift (ARM64 → LLIL expression tree) — 单元测试 BN-style."""
from __future__ import annotations
import pytest
from viewer.decompiler.llil import (
    LlilExpr, lift_arm64, lift_static, LiftStats,
    LLIL_SET_REG, LLIL_REG, LLIL_CONST, LLIL_CONST_PTR,
    LLIL_LOAD, LLIL_STORE, LLIL_ADD, LLIL_SUB, LLIL_AND, LLIL_OR, LLIL_XOR,
    LLIL_SET_FLAG, LLIL_FLAG_COND, LLIL_CMP_E, LLIL_CMP_NE,
    LLIL_GOTO, LLIL_JUMP, LLIL_IF, LLIL_CALL, LLIL_RET,
    LLIL_NOP, LLIL_INTRINSIC,
)


def _asm(s: str) -> int:
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    enc, _ = ks.asm(s)
    return int.from_bytes(bytes(enc), "little")


# ─────────── leaf / atom ───────────

def test_lift_nop():
    [e] = lift_arm64(0x1000, _asm("nop"))
    assert e.op == LLIL_NOP


# ─────────── mov ───────────

def test_lift_mov_imm():
    [e] = lift_arm64(0x1000, _asm("mov x0, #1"))
    assert e.op == LLIL_SET_REG
    assert e.operands[0] == "x0"
    val = e.operands[1]
    assert val.op == LLIL_CONST
    assert val.operands == [1]


def test_lift_mov_reg():
    [e] = lift_arm64(0x1000, _asm("mov x0, x1"))
    assert e.op == LLIL_SET_REG
    assert e.operands[0] == "x0"
    val = e.operands[1]
    assert val.op == LLIL_REG
    assert val.operands == ["x1"]


# ─────────── arithmetic ───────────

def test_lift_add_imm():
    [e] = lift_arm64(0x1000, _asm("add x0, x1, #0x10"))
    assert e.op == LLIL_SET_REG
    assert e.operands[0] == "x0"
    add_e = e.operands[1]
    assert add_e.op == LLIL_ADD
    a, b = add_e.operands
    assert a.op == LLIL_REG and a.operands == ["x1"]
    assert b.op == LLIL_CONST and b.operands == [0x10]


def test_lift_add_reg():
    [e] = lift_arm64(0x1000, _asm("add x0, x1, x2"))
    add_e = e.operands[1]
    assert add_e.op == LLIL_ADD
    assert add_e.operands[0].operands == ["x1"]
    assert add_e.operands[1].operands == ["x2"]


def test_lift_sub():
    [e] = lift_arm64(0x1000, _asm("sub x0, x1, #4"))
    assert e.operands[1].op == LLIL_SUB


def test_lift_eor_is_xor():
    """ARM64 eor = LLIL_XOR (BN naming)."""
    [e] = lift_arm64(0x1000, _asm("eor x0, x1, x2"))
    assert e.operands[1].op == LLIL_XOR


# ─────────── memory ───────────

def test_lift_ldr():
    """ldr x0, [x1] → LLIL_SET_REG('x0', LLIL_LOAD(LLIL_REG('x1')))."""
    [e] = lift_arm64(0x1000, _asm("ldr x0, [x1]"))
    assert e.op == LLIL_SET_REG
    assert e.operands[0] == "x0"
    inner = e.operands[1]
    assert inner.op == LLIL_LOAD
    assert inner.size == 8
    addr = inner.operands[0]
    assert addr.op == LLIL_REG
    assert addr.operands == ["x1"]


def test_lift_ldr_offset():
    [e] = lift_arm64(0x1000, _asm("ldr x0, [x1, #0x40]"))
    inner = e.operands[1]
    assert inner.op == LLIL_LOAD
    addr = inner.operands[0]
    assert addr.op == LLIL_ADD
    assert addr.operands[0].operands == ["x1"]
    assert addr.operands[1].operands == [0x40]


def test_lift_str():
    [e] = lift_arm64(0x1000, _asm("str x0, [x1]"))
    assert e.op == LLIL_STORE
    assert e.size == 8
    addr, val = e.operands
    assert addr.op == LLIL_REG and addr.operands == ["x1"]
    assert val.op == LLIL_REG and val.operands == ["x0"]


def test_lift_self_update_load_intrinsic():
    [e] = lift_arm64(0x1000, _asm("ldr x0, [x1, #0x10]!"))
    assert e.op == LLIL_INTRINSIC
    assert e.extra.get("note") == "self_update_load"


# ─────────── cmp ───────────

def test_lift_cmp_set_flag():
    [e] = lift_arm64(0x1000, _asm("cmp x0, #5"))
    assert e.op == LLIL_SET_FLAG
    assert e.operands[0] == "cmp_result"
    inner = e.operands[1]
    assert inner.op == LLIL_SUB


# ─────────── branch ───────────

def test_lift_b():
    [e] = lift_arm64(0x1000, _asm("b #0x2000"))
    assert e.op == LLIL_GOTO
    assert e.operands[0] == 0x3000   # PC-relative


def test_lift_b_cond():
    [e] = lift_arm64(0x1000, _asm("b.eq #0x2000"))
    assert e.op == LLIL_IF
    cond, true_t, false_t = e.operands
    assert cond.op == LLIL_FLAG_COND
    assert cond.operands == ["eq"]
    assert true_t == 0x3000
    assert false_t == 0x1004


def test_lift_bl():
    [e] = lift_arm64(0x1000, _asm("bl #0x4000"))
    assert e.op == LLIL_CALL
    target = e.operands[0]
    assert target.op == LLIL_CONST_PTR
    assert target.operands == [0x5000]


def test_lift_blr():
    [e] = lift_arm64(0x1000, _asm("blr x16"))
    assert e.op == LLIL_CALL
    target = e.operands[0]
    assert target.op == LLIL_REG
    assert target.operands == ["x16"]


def test_lift_br():
    [e] = lift_arm64(0x1000, _asm("br x16"))
    assert e.op == LLIL_JUMP


def test_lift_ret():
    [e] = lift_arm64(0x1000, _asm("ret"))
    assert e.op == LLIL_RET


def test_lift_cbz_combines_cmp_and_if():
    """cbz xN, target = LLIL_IF(LLIL_CMP_E(reg, 0), target, fallthrough)."""
    [e] = lift_arm64(0x1000, _asm("cbz x0, #0x2000"))
    assert e.op == LLIL_IF
    cond = e.operands[0]
    assert cond.op == LLIL_CMP_E
    a, b = cond.operands
    assert a.op == LLIL_REG and a.operands == ["x0"]
    assert b.op == LLIL_CONST and b.operands == [0]


def test_lift_cbnz_uses_ne():
    [e] = lift_arm64(0x1000, _asm("cbnz x0, #0x2000"))
    cond = e.operands[0]
    assert cond.op == LLIL_CMP_NE


# ─────────── unknown ───────────

def test_lift_svc_intrinsic():
    [e] = lift_arm64(0x1000, _asm("svc #0"))
    assert e.op == LLIL_INTRINSIC


# ─────────── walking ───────────

def test_walk_yields_subexprs():
    [e] = lift_arm64(0x1000, _asm("add x0, x1, #5"))
    nodes = list(e.walk())
    # root + LLIL_ADD + LLIL_REG + LLIL_CONST = 4
    assert len(nodes) == 4
    ops = [n.op for n in nodes]
    assert LLIL_SET_REG in ops
    assert LLIL_ADD in ops
    assert LLIL_REG in ops
    assert LLIL_CONST in ops


# ─────────── batch lift ───────────

def test_lift_static_dedup():
    items = [
        (0x1000, _asm("mov x0, #1")),
        (0x1004, _asm("ret")),
        (0x1000, _asm("mov x0, #1")),    # dup
    ]
    out, stats = lift_static(items)
    assert len(out) == 2
    assert stats.coverage() == 1.0


def test_lift_static_intrinsic_counted():
    items = [
        (0x1000, _asm("svc #0")),
        (0x1004, _asm("ret")),
    ]
    out, stats = lift_static(items)
    assert stats.intrinsic == 1
    assert stats.coverage() == 0.5


# ─────────── short repr ───────────

def test_short_repr_basic():
    [e] = lift_arm64(0x1000, _asm("add x0, x1, #5"))
    s = e.short()
    assert "x0" in s
    assert "x1" in s


def test_short_repr_load():
    [e] = lift_arm64(0x1000, _asm("ldr x0, [x1]"))
    s = e.short()
    assert "x0" in s and "load" in s and "x1" in s
