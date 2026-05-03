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


# ─────────── PC-relative + 算术扩展 ───────────

def test_lift_adr():
    """adr xN, #addr → SET_REG(xN, CONST_PTR(addr))."""
    [e] = lift_arm64(0x1000, _asm("adr x0, #0x100"))
    assert e.op == LLIL_SET_REG
    assert e.operands[0] == "x0"
    val = e.operands[1]
    assert val.op == LLIL_CONST_PTR


def test_lift_adrp():
    [e] = lift_arm64(0x1000, _asm("adrp x0, #0x10000"))
    assert e.op == LLIL_SET_REG
    assert e.operands[1].op == LLIL_CONST_PTR


def test_lift_madd():
    """madd dst, rn, rm, ra → SET_REG(dst, ADD(MUL(rn,rm), ra))."""
    from viewer.decompiler.llil import LLIL_ADD, LLIL_MUL
    [e] = lift_arm64(0x1000, _asm("madd x0, x1, x2, x3"))
    assert e.op == LLIL_SET_REG
    body = e.operands[1]
    assert body.op == LLIL_ADD
    mul_e, ra = body.operands
    assert mul_e.op == LLIL_MUL
    assert ra.op == LLIL_REG and ra.operands == ["x3"]


def test_lift_msub():
    """msub dst, rn, rm, ra → SET_REG(dst, SUB(ra, MUL(rn,rm)))."""
    from viewer.decompiler.llil import LLIL_SUB, LLIL_MUL
    [e] = lift_arm64(0x1000, _asm("msub x0, x1, x2, x3"))
    body = e.operands[1]
    assert body.op == LLIL_SUB
    ra, mul_e = body.operands
    assert ra.operands == ["x3"]
    assert mul_e.op == LLIL_MUL


def test_lift_smull():
    from viewer.decompiler.llil import LLIL_MUL
    [e] = lift_arm64(0x1000, _asm("smull x0, w1, w2"))
    assert e.operands[1].op == LLIL_MUL


def test_lift_umull():
    from viewer.decompiler.llil import LLIL_MUL
    [e] = lift_arm64(0x1000, _asm("umull x0, w1, w2"))
    assert e.operands[1].op == LLIL_MUL


def test_lift_sxtw():
    from viewer.decompiler.llil import LLIL_SX
    [e] = lift_arm64(0x1000, _asm("sxtw x0, w1"))
    body = e.operands[1]
    assert body.op == LLIL_SX
    assert body.extra.get("src_size") == 4


# uxtw: ARM64 ISA 别名 → capstone disasm 成 ubfx, 留待 ubfx lift commit
# (当前 lift 表不命中, 走 intrinsic. 不 fail).


def test_lift_sxtb():
    from viewer.decompiler.llil import LLIL_SX
    [e] = lift_arm64(0x1000, _asm("sxtb w0, w1"))
    assert e.operands[1].extra.get("src_size") == 1


def test_lift_uxtb():
    from viewer.decompiler.llil import LLIL_ZX
    [e] = lift_arm64(0x1000, _asm("uxtb w0, w1"))
    assert e.operands[1].extra.get("src_size") == 1


def test_lift_sxth():
    from viewer.decompiler.llil import LLIL_SX
    [e] = lift_arm64(0x1000, _asm("sxth w0, w1"))
    assert e.operands[1].extra.get("src_size") == 2


def test_lift_uxth():
    from viewer.decompiler.llil import LLIL_ZX
    [e] = lift_arm64(0x1000, _asm("uxth w0, w1"))
    assert e.operands[1].extra.get("src_size") == 2


def test_lift_sdiv():
    from viewer.decompiler.llil import LLIL_DIVS
    [e] = lift_arm64(0x1000, _asm("sdiv x0, x1, x2"))
    assert e.operands[1].op == LLIL_DIVS


def test_lift_udiv():
    from viewer.decompiler.llil import LLIL_DIVU
    [e] = lift_arm64(0x1000, _asm("udiv x0, x1, x2"))
    assert e.operands[1].op == LLIL_DIVU


# ─────────── bitfield + sysreg ───────────

def test_lift_ubfx_lsb0_width32_yields_zx():
    """ubfx xN, xM, #0, #32 = uxtw 等价 → LLIL_ZX with src_size=4."""
    from viewer.decompiler.llil import LLIL_ZX
    [e] = lift_arm64(0x1000, _asm("ubfx x0, x1, #0, #32"))
    assert e.op == LLIL_SET_REG
    body = e.operands[1]
    assert body.op == LLIL_ZX
    assert body.extra.get("src_size") == 4


def test_lift_ubfx_general_bitfield():
    """ubfx xN, xM, #4, #8 = (xM >> 4) & 0xff (general bitfield)."""
    from viewer.decompiler.llil import LLIL_AND, LLIL_LSR
    [e] = lift_arm64(0x1000, _asm("ubfx x0, x1, #4, #8"))
    body = e.operands[1]
    assert body.op == LLIL_AND
    lsr_e, mask = body.operands
    assert lsr_e.op == LLIL_LSR
    assert mask.op == LLIL_CONST
    assert mask.operands[0] == 0xff


def test_lift_sbfx_lsb0_width16_yields_sx():
    from viewer.decompiler.llil import LLIL_SX
    [e] = lift_arm64(0x1000, _asm("sbfx x0, x1, #0, #16"))
    body = e.operands[1]
    assert body.op == LLIL_SX
    assert body.extra.get("src_size") == 2


def test_lift_mrs_tpidr_el0():
    """mrs x8, tpidr_el0 → SET_REG(x8, INTRINSIC('_ReadMSR', 'tpidr_el0'))."""
    [e] = lift_arm64(0x1000, _asm("mrs x8, tpidr_el0"))
    assert e.op == LLIL_SET_REG
    assert e.operands[0] == "x8"
    body = e.operands[1]
    assert body.op == LLIL_INTRINSIC
    assert body.extra.get("kind") == "read_sysreg"
    assert body.extra.get("sysreg") == "tpidr_el0"


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


# ─────────── w-form normalize (ARM64 wN ↔ xN 同物理 reg) ───────────

def test_lift_wreg_arith_normalizes_to_x():
    """add w0, w1, w2 — regs_def/use 已经是 'x0','x1','x2' (disasm 层 normalize)."""
    [e] = lift_arm64(0x1000, _asm("add w0, w1, w2"))
    assert e.op == LLIL_SET_REG
    assert e.operands[0] == "x0"
    body = e.operands[1]
    assert body.op == LLIL_ADD
    a, b = body.operands
    assert a.op == LLIL_REG and a.operands == ["x1"]
    assert b.op == LLIL_REG and b.operands == ["x2"]


def test_lift_wreg_mov_normalizes():
    """mov w0, #5 → SET_REG x0 const(5)."""
    [e] = lift_arm64(0x1000, _asm("mov w0, #5"))
    assert e.op == LLIL_SET_REG
    assert e.operands[0] == "x0"


def test_lift_mov_wreg_reg_zero_extends():
    """mov w0, w1 writes low 32 bits and zero-extends x0."""
    from viewer.decompiler.llil import LLIL_ZX
    [e] = lift_arm64(0x1000, _asm("mov w0, w1"))
    assert e.op == LLIL_SET_REG
    assert e.operands[0] == "x0"
    body = e.operands[1]
    assert body.op == LLIL_ZX
    assert body.extra["src_size"] == 4
    src = body.operands[0]
    assert src.op == LLIL_REG and src.operands == ["x1"]


def test_lift_mov_wreg_imm_masks_32_bits():
    """mov w0, #-1 is x0 = 0xffffffff, not 0xffffffffffffffff."""
    [e] = lift_arm64(0x1000, _asm("mov w0, #-1"))
    assert e.op == LLIL_SET_REG
    assert e.operands[0] == "x0"
    body = e.operands[1]
    assert body.op == LLIL_CONST
    assert body.operands == [0xFFFFFFFF]


def test_lift_cbz_wreg_normalizes_to_x():
    """cbz w0, target → cmp_e(reg(x0), 0) — _first_reg_token normalize 后."""
    [e] = lift_arm64(0x1000, _asm("cbz w0, #0x2000"))
    assert e.op == LLIL_IF
    cond = e.operands[0]
    a = cond.operands[0]
    assert a.op == LLIL_REG and a.operands == ["x0"]


def test_lift_tbz_wreg_normalizes_to_x():
    """tbz w8, #5, target → cond uses x8 (normalized)."""
    [e] = lift_arm64(0x1000, _asm("tbz w8, #5, #0x2000"))
    assert e.op == LLIL_IF
    cond = e.operands[0]
    # cond = cmp_e(and(reg, mask), 0); 找到 reg
    masked = cond.operands[0]
    r = masked.operands[0]
    assert r.op == LLIL_REG and r.operands == ["x8"]


def test_lift_wzr_normalizes_to_xzr():
    """mov w0, wzr → src 是 xzr (规范化)."""
    from viewer.decompiler.llil import LLIL_ZX
    [e] = lift_arm64(0x1000, _asm("mov w0, wzr"))
    assert e.op == LLIL_SET_REG
    assert e.operands[0] == "x0"
    body = e.operands[1]
    assert body.op == LLIL_ZX
    src = body.operands[0]
    assert src.op == LLIL_REG and src.operands == ["xzr"]


# ─────────── rotate (ROR — crypto round op) ───────────

def test_lift_ror_imm():
    """ror x0, x1, #5 → SET_REG(x0, ROR(x1, const(5)))."""
    from viewer.decompiler.llil import LLIL_ROR
    [e] = lift_arm64(0x1000, _asm("ror x0, x1, #5"))
    assert e.op == LLIL_SET_REG
    assert e.operands[0] == "x0"
    body = e.operands[1]
    assert body.op == LLIL_ROR
    a, b = body.operands
    assert a.op == LLIL_REG and a.operands == ["x1"]
    assert b.op == LLIL_CONST and b.operands == [5]


def test_lift_ror_reg():
    """ror x0, x1, x2 → SET_REG(x0, ROR(x1, x2))."""
    from viewer.decompiler.llil import LLIL_ROR
    [e] = lift_arm64(0x1000, _asm("ror x0, x1, x2"))
    body = e.operands[1]
    assert body.op == LLIL_ROR
    a, b = body.operands
    assert a.op == LLIL_REG and a.operands == ["x1"]
    assert b.op == LLIL_REG and b.operands == ["x2"]


# ─────────── indexed addressing (LDR/STR with [base, idx, lsl #shift]) ───────────

def test_lift_ldr_indexed_simple():
    """ldr x0, [x1, x2] → SET_REG(x0, LOAD(ADD(x1, x2)))."""
    [e] = lift_arm64(0x1000, _asm("ldr x0, [x1, x2]"))
    assert e.op == LLIL_SET_REG
    assert e.operands[0] == "x0"
    body = e.operands[1]
    assert body.op == LLIL_LOAD
    addr = body.operands[0]
    assert addr.op == LLIL_ADD
    a, b = addr.operands
    assert a.op == LLIL_REG and a.operands == ["x1"]
    assert b.op == LLIL_REG and b.operands == ["x2"]


def test_lift_ldr_indexed_lsl_shift():
    """ldr x0, [x1, x2, lsl #3] → SET_REG(x0, LOAD(ADD(x1, LSL(x2, 3))))."""
    from viewer.decompiler.llil import LLIL_LSL
    [e] = lift_arm64(0x1000, _asm("ldr x0, [x1, x2, lsl #3]"))
    addr = e.operands[1].operands[0]
    assert addr.op == LLIL_ADD
    base, idx_shifted = addr.operands
    assert base.op == LLIL_REG and base.operands == ["x1"]
    assert idx_shifted.op == LLIL_LSL
    idx, shamt = idx_shifted.operands
    assert idx.op == LLIL_REG and idx.operands == ["x2"]
    assert shamt.op == LLIL_CONST and shamt.operands == [3]


def test_lift_str_indexed_simple():
    """str x3, [x1, x2] → STORE(ADD(x1, x2), x3)."""
    [e] = lift_arm64(0x1000, _asm("str x3, [x1, x2]"))
    assert e.op == LLIL_STORE
    addr = e.operands[0]
    assert addr.op == LLIL_ADD
    src = e.operands[1]
    assert src.op == LLIL_REG and src.operands == ["x3"]


def test_lift_str_indexed_lsl_shift():
    """str x3, [x1, x2, lsl #3] (8-byte word, lsl=log2(size)=3) →
    STORE(ADD(x1, LSL(x2, 3)), x3)."""
    from viewer.decompiler.llil import LLIL_LSL
    [e] = lift_arm64(0x1000, _asm("str x3, [x1, x2, lsl #3]"))
    addr = e.operands[0]
    assert addr.op == LLIL_ADD
    _, idx_shifted = addr.operands
    assert idx_shifted.op == LLIL_LSL
    _, shamt = idx_shifted.operands
    assert shamt.operands == [3]


def test_lift_ldr_disp_only_unchanged():
    """ldr x0, [x1, #16] — 简单 disp, 行为不变 (smoke test)."""
    [e] = lift_arm64(0x1000, _asm("ldr x0, [x1, #16]"))
    addr = e.operands[1].operands[0]
    assert addr.op == LLIL_ADD
    a, b = addr.operands
    assert a.operands == ["x1"]
    assert b.op == LLIL_CONST and b.operands == [16]


# ─────────── movk (mov-keep) ───────────

def test_lift_movk_no_shift():
    """movk x0, #0xabcd — 替换 [15:0], 保留 [63:16].
    SET_REG(x0, OR(AND(x0, ~0xFFFF), 0xabcd))."""
    [e] = lift_arm64(0x1000, _asm("movk x0, #0xabcd"))
    assert e.op == LLIL_SET_REG
    assert e.operands[0] == "x0"
    val = e.operands[1]
    assert val.op == LLIL_OR
    keep, new = val.operands
    assert keep.op == LLIL_AND
    src, mask = keep.operands
    assert src.op == LLIL_REG and src.operands == ["x0"]
    assert mask.op == LLIL_CONST
    assert mask.operands == [(~0xFFFF) & ((1 << 64) - 1)]
    assert new.op == LLIL_CONST and new.operands == [0xabcd]


def test_lift_movk_lsl_16():
    """movk x0, #0x1234, lsl #16 — 替换 [31:16]."""
    [e] = lift_arm64(0x1000, _asm("movk x0, #0x1234, lsl #16"))
    val = e.operands[1]
    keep, new = val.operands
    _, mask = keep.operands
    assert mask.operands == [(~(0xFFFF << 16)) & ((1 << 64) - 1)]
    assert new.operands == [0x1234 << 16]


def test_lift_movk_lsl_48():
    """movk x0, #0xff00, lsl #48 — 替换最高 16 bits."""
    [e] = lift_arm64(0x1000, _asm("movk x0, #0xff00, lsl #48"))
    val = e.operands[1]
    keep, new = val.operands
    _, mask = keep.operands
    assert mask.operands == [(~(0xFFFF << 48)) & ((1 << 64) - 1)]
    assert new.operands == [0xff00 << 48]


def test_lift_movz_then_movk_constfold_chain():
    """movz x0, #0x1234 + movk x0, #0xabcd, lsl #16
    → 走 SSA + constfold, 最终 x0 应折成 const 0xabcd1234.
    OLLVM 大常量构造的核心场景."""
    from viewer.decompiler.llil import ssa_block, constfold_block, LLIL_CONST
    e1 = lift_arm64(0x1000, _asm("movz x0, #0x1234"))[0]
    e2 = lift_arm64(0x1004, _asm("movk x0, #0xabcd, lsl #16"))[0]
    blk = ssa_block(0x1000, [e1, e2])
    new = constfold_block(blk)
    last = new.roots[-1]
    assert last.op == LLIL_SET_REG
    rhs = last.operands[1]
    assert rhs.op == LLIL_CONST, f"expected fully folded const, got {rhs.op}"
    assert rhs.operands == [0xabcd1234]


# ─────────── _parse_mem_shift hex 兼容 ───────────

def test_parse_mem_shift_dec():
    from viewer.decompiler.llil.lift import _parse_mem_shift
    assert _parse_mem_shift("[x1, x2, lsl #3]") == 3


def test_parse_mem_shift_hex_small():
    """lsl #0x3 — 之前因字符循环把 '0' 单独 emit, 现 regex 应解出 3."""
    from viewer.decompiler.llil.lift import _parse_mem_shift
    assert _parse_mem_shift("[x1, x2, lsl #0x3]") == 3


def test_parse_mem_shift_hex_large():
    """lsl #0x10 → 16."""
    from viewer.decompiler.llil.lift import _parse_mem_shift
    assert _parse_mem_shift("[x1, x2, lsl #0x10]") == 16


def test_parse_mem_shift_no_lsl():
    from viewer.decompiler.llil.lift import _parse_mem_shift
    assert _parse_mem_shift("[x1, x2]") == 0
    assert _parse_mem_shift("[x1, #16]") == 0


def test_parse_mem_shift_dec_16():
    from viewer.decompiler.llil.lift import _parse_mem_shift
    assert _parse_mem_shift("[x1, x2, lsl #16]") == 16


def test_lift_movz_movk_movk_movk_full_64bit():
    """4-step OLLVM 大常量: movz + movk*3 → 折出 64-bit const."""
    from viewer.decompiler.llil import ssa_block, constfold_block, LLIL_CONST
    insns = [
        lift_arm64(0x1000, _asm("movz x0, #0xdead"))[0],
        lift_arm64(0x1004, _asm("movk x0, #0xbeef, lsl #16"))[0],
        lift_arm64(0x1008, _asm("movk x0, #0xcafe, lsl #32"))[0],
        lift_arm64(0x100c, _asm("movk x0, #0xbabe, lsl #48"))[0],
    ]
    blk = ssa_block(0x1000, insns)
    new = constfold_block(blk)
    rhs = new.roots[-1].operands[1]
    assert rhs.op == LLIL_CONST
    assert rhs.operands == [0xbabecafebeefdead]
