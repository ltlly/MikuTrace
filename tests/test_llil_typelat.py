"""Pass 5 typelat on LLIL — 单元测试."""
from __future__ import annotations
from viewer.decompiler.llil import (
    LlilExpr, ssa_block, typelat_block, TypeEnv, join,
    T_TOP, T_INT, T_PTR, T_HANDLE, T_BOOL, T_BOT,
    set_reg, reg, const, const_ptr, add, sub, xor, lsl,
    load, store, ret, call,
    cmp_e, flag_cond,
)


def test_join_rules():
    assert join(T_INT, T_INT) == T_INT
    assert join(T_TOP, T_INT) == T_INT
    assert join(T_PTR, T_INT) == T_PTR
    assert join(T_INT, T_PTR) == T_PTR
    assert join(T_PTR, T_HANDLE) == T_BOT


def test_load_promotes_addr_to_ptr():
    """set_reg(x0, load(reg(x1))) → x1 = PTR."""
    e = set_reg("x0", load(reg("x1"), size=8))
    blk = ssa_block(0x1000, [e])
    env = typelat_block(blk)
    assert env.get("x1", 0) == T_PTR
    assert env.get("x0", 1) == T_INT


def test_load_with_offset_promotes_base():
    """set_reg(x0, load(add(reg(x1), const(0x40)))) → x1 = PTR."""
    e = set_reg("x0", load(add(reg("x1"), const(0x40)), size=8))
    blk = ssa_block(0x1000, [e])
    env = typelat_block(blk)
    assert env.get("x1", 0) == T_PTR


def test_store_promotes_addr_to_ptr():
    e = store(reg("x1"), reg("x0"), size=8)
    blk = ssa_block(0x1000, [e])
    env = typelat_block(blk)
    assert env.get("x1", 0) == T_PTR


def test_const_ptr_marks_ptr():
    """set_reg(x0, const_ptr(0x4000)) → x0 = PTR."""
    e = set_reg("x0", const_ptr(0x4000))
    blk = ssa_block(0x1000, [e])
    env = typelat_block(blk)
    assert env.get("x0", 1) == T_PTR


def test_call_target_const_ptr():
    """LLIL_CALL(LLIL_CONST_PTR(target)) — target 推 PTR. 不影响其他 reg."""
    blk = ssa_block(0x1000, [call(const_ptr(0x2000))])
    env = typelat_block(blk)
    # call 不写 reg, env 仍空
    assert env.types == {}


def test_xor_yields_int():
    """xor → INT."""
    e = set_reg("x0", xor(reg("x9"), const(0xAA)))
    blk = ssa_block(0x1000, [e])
    env = typelat_block(blk)
    assert env.get("x0", 1) == T_INT


def test_anchor_set_handle():
    """anchor 注 x0 = HANDLE."""
    e = set_reg("x0", reg("x9"))
    blk = ssa_block(0x1000, [e])
    env = typelat_block(blk, anchors=[(0, {"x0": T_HANDLE})])
    assert env.get("x0", 1) == T_HANDLE


def test_chain_of_load():
    """ldr x0, [x1]; ldr x2, [x0] → x1 PTR, x0 PTR (作 second load 的 base)."""
    r1 = set_reg("x0", load(reg("x1"), size=8))
    r2 = set_reg("x2", load(reg("x0"), size=8))
    blk = ssa_block(0x1000, [r1, r2])
    env = typelat_block(blk)
    assert env.get("x1", 0) == T_PTR
    assert env.get("x0", 1) == T_PTR
    assert env.get("x2", 1) == T_INT


def test_sub_ptr_minus_ptr_yields_int():
    initial = TypeEnv()
    initial.set("x1", 0, T_PTR)
    initial.set("x2", 0, T_PTR)
    e = set_reg("x0", sub(reg("x1"), reg("x2")))
    blk = ssa_block(0x1000, [e])
    env = typelat_block(blk, initial=initial)
    assert env.get("x0", 1) == T_INT


def test_mov_reg_propagates_type():
    initial = TypeEnv()
    initial.set("x9", 0, T_PTR)
    e = set_reg("x0", reg("x9"))
    blk = ssa_block(0x1000, [e])
    env = typelat_block(blk, initial=initial)
    assert env.get("x0", 1) == T_PTR


def test_cmp_yields_bool():
    """LLIL_CMP_E → bool. 但因为是 sub-expr, 通常嵌在 IF 里."""
    initial = TypeEnv()
    e = set_reg("x0", cmp_e(reg("x1"), const(0)))
    blk = ssa_block(0x1000, [e])
    env = typelat_block(blk, initial=initial)
    assert env.get("x0", 1) == T_BOOL
