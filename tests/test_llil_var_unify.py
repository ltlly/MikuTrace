"""Pass 6.5 var unification — 单元测试."""
from __future__ import annotations
from viewer.decompiler.llil import (
    ssa_block, unify_vars,
    set_reg, reg, const, add, ret,
)


def test_unify_arg_regs():
    """fn 入口 (xN, 0) where N∈0..7 → arg_N."""
    blk = ssa_block(0x1000, [
        set_reg("x9", reg("x0")),     # use x0_v0 = arg_0
        set_reg("x10", reg("x3")),    # use x3_v0 = arg_3
    ])
    names = unify_vars({0x1000: blk})
    assert names[("x0", 0)] == "arg_0"
    assert names[("x3", 0)] == "arg_3"


def test_unify_callee_saved():
    """(x19..x28, 0) / (fp, 0) / (lr, 0) → cs_xN."""
    blk = ssa_block(0x1000, [
        set_reg("x9", reg("x19")),
        set_reg("x10", reg("x28")),
        set_reg("x11", reg("lr")),
    ])
    names = unify_vars({0x1000: blk})
    assert names[("x19", 0)] == "cs_x19"
    assert names[("x28", 0)] == "cs_x28"
    assert names[("lr", 0)] == "cs_lr"


def test_unify_sp_fp_self():
    """sp/fp v0 保留原名."""
    blk = ssa_block(0x1000, [
        set_reg("x9", reg("sp")),
        set_reg("x10", reg("fp")),
    ])
    names = unify_vars({0x1000: blk})
    assert names[("sp", 0)] == "sp"
    assert names[("fp", 0)] == "fp"


def test_unify_general_reg_v1():
    """普通 reg 写入后 (x8, 1) → x8_v1."""
    blk = ssa_block(0x1000, [
        set_reg("x8", const(5)),
        set_reg("x8", const(10)),
    ])
    names = unify_vars({0x1000: blk})
    assert names[("x8", 1)] == "x8_v1"
    assert names[("x8", 2)] == "x8_v2"


def test_unify_x0_after_write_not_arg():
    """x0 第一次写入后 (x0, 1) 不是 arg_0 (是新 var).

    若 x0 仅 write 没 read, v0 不出现; v1 是写入后 → x0_v1.
    """
    blk = ssa_block(0x1000, [
        set_reg("x0", const(42)),
    ])
    names = unify_vars({0x1000: blk})
    # 没 read x0 → 不出 v0
    assert names.get(("x0", 1)) == "x0_v1"


def test_unify_x0_used_after_write():
    """x0 写后再 use → v0 是 arg_0, v1 是 x0_v1."""
    blk = ssa_block(0x1000, [
        set_reg("x9", reg("x0")),    # use x0_v0 = arg_0
        set_reg("x0", const(42)),    # write → x0_v1
    ])
    names = unify_vars({0x1000: blk})
    assert names.get(("x0", 0)) == "arg_0"
    assert names.get(("x0", 1)) == "x0_v1"


def test_unify_cross_block():
    """多 block, 各自 SSA, 入口 entry_versions 命名一致."""
    blk1 = ssa_block(0x1000, [set_reg("x0", const(1))])
    blk2 = ssa_block(0x2000, [set_reg("x1", reg("x0"))])
    names = unify_vars({0x1000: blk1, 0x2000: blk2})
    # 两 block 都用 x0 v0 = arg_0
    assert names[("x0", 0)] == "arg_0"


def test_unify_empty_blocks_returns_default_args():
    """空 block — unify 仍返回 default args (arg_0..arg_7, sp, fp).
    保证 render 时这些 fallback 名一直可查."""
    blk = ssa_block(0x1000, [])
    names = unify_vars({0x1000: blk})
    assert names[("x0", 0)] == "arg_0"
    assert names[("x7", 0)] == "arg_7"
    assert names[("sp", 0)] == "sp"
    assert names[("fp", 0)] == "fp"


def test_unify_uses_walk():
    """ADD(REG(x9), const(5)) — sub-expr LLIL_REG x9 也被 unify."""
    blk = ssa_block(0x1000, [
        set_reg("x10", add(reg("x9"), const(5))),
    ])
    names = unify_vars({0x1000: blk})
    # x9 v0 → x9 不是 arg/callee-saved → x9_v0
    # 但我们规则: v0 不在 arg/cs 列表 → fallback x9_v0
    assert ("x9", 0) in names
    # x9 不在 _ARG_REGS (x0-x7) 也不在 _CALLEE_SAVED (x19-x28+fp+lr)
    # → 规则走默认: f"{r}_v{v}" = "x9_v0"
    assert names[("x9", 0)] == "x9_v0"


def test_unify_render_uses_var_names():
    """render 时 reg 替换为 var_name."""
    from viewer.decompiler.llil import (
        render_hlil, restructure, CfgInfo,
    )
    blk = ssa_block(0x1000, [
        set_reg("x10", add(reg("x0"), const(5))),
        ret(),
    ])
    names = unify_vars({0x1000: blk})
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    text = "\n".join(render_hlil(hlil, var_names=names))
    # x0 替换为 arg_0
    assert "arg_0" in text
    assert "(arg_0 + 5)" in text or "arg_0" in text
