"""LLIL_CALL render 显示 x0..x3 args (ARM64 ABI) — 单元测试."""
from __future__ import annotations
from viewer.decompiler.llil import (
    LlilExpr, ssa_block, restructure, CfgInfo, render_hlil,
    set_reg, reg, const, const_ptr, call, ret, unify_vars,
)


def test_call_no_args_when_no_var_names():
    """没 var_names dict → 简单 call(target) 输出."""
    blk = ssa_block(0x1000, [
        call(const_ptr(0x4000), pc=0x1000),
    ])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    text = "\n".join(render_hlil(hlil))
    assert "call(0x4000)" in text


def test_call_with_args_after_var_unify():
    """call 前 set_reg x0..x3 → call 输出含这些 var name."""
    blk = ssa_block(0x1000, [
        set_reg("x0", const(0x42)),       # x0_v1
        set_reg("x1", const(0x100)),      # x1_v1
        call(const_ptr(0x4000), pc=0x1000),
    ])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    var_names = unify_vars({0x1000: blk})
    text = "\n".join(render_hlil(hlil, var_names=var_names))
    # call 应该含 x0_v1, x1_v1 (写入后的 version)
    assert "call(0x4000," in text
    assert "x0_v1" in text
    assert "x1_v1" in text


def test_call_uses_arg_names_when_no_writes():
    """call 时 x0..x7 没被 set_reg 过 → 用 arg_N 名."""
    blk = ssa_block(0x1000, [
        call(const_ptr(0x4000), pc=0x1000),
    ])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    var_names = unify_vars({0x1000: blk})
    text = "\n".join(render_hlil(hlil, var_names=var_names))
    assert "arg_0" in text
    assert "arg_1" in text


def test_call_indirect_with_args():
    """call(reg(x16), ...) 间接 call 也带 args."""
    blk = ssa_block(0x1000, [
        set_reg("x0", const(0x42)),
        call(reg("x16"), pc=0x1000),
    ])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    var_names = unify_vars({0x1000: blk})
    text = "\n".join(render_hlil(hlil, var_names=var_names))
    assert "call(" in text
    assert "x0_v1" in text


def test_render_post_call_x0_uses_return_version():
    """call → x0 之后被读 → render 应显示 post-call version (kill 后 v).

    SSA call-kill 让 x0 在 call 后 bump version; render 的 cur_versions
    必须同步 bump, 否则后续 x0 引用错链到 pre-call (即 args).
    """
    from viewer.decompiler.llil import (
        ssa_block, restructure, CfgInfo, render_hlil,
        set_reg, reg, const, const_ptr, call, ret, unify_vars,
    )
    blk = ssa_block(0x1000, [
        set_reg("x0", const(0x42)),                # x0 → v1
        call(const_ptr(0x4000), pc=0x1000),        # bumps x0 → v2 (return)
        set_reg("x10", reg("x0")),                 # 读 post-call x0_v2
        ret(),
    ])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    var_names = unify_vars({0x1000: blk})
    text = "\n".join(render_hlil(hlil, var_names=var_names))
    # call 前后: args 用 v1 (pre-call); 之后 x10 = x0_v2 (post-call return)
    assert "x0_v1" in text                          # call 的 arg
    assert "x0_v2" in text                          # post-call read


def test_render_call_shows_trace_return_value():
    """call 后附 ' // → x0=0xff' 注释 (从 UIDF ret_x0 拿)."""
    from viewer.decompiler.llil import (
        ssa_block, restructure, CfgInfo, render_hlil,
        const_ptr, call, ret, ObservedValues, unify_vars,
    )
    blk = ssa_block(0x1000, [
        call(const_ptr(0x4000), pc=0x1004),
        ret(),
    ])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    var_names = unify_vars({0x1000: blk})
    uidf = {
        (0x1000, 0): ObservedValues(
            pc=0x1008, reg="ret_x0", n_hits=5,
            distinct_count=1, first=0xff, last=0xff, sample=[0xff],
        ),
    }
    text = "\n".join(render_hlil(hlil, var_names=var_names, uidf=uidf))
    assert "→ x0=0xff" in text


def test_render_call_no_uidf_no_comment():
    """没 uidf → call 行不附 return value 注释."""
    from viewer.decompiler.llil import (
        ssa_block, restructure, CfgInfo, render_hlil,
        const_ptr, call, ret,
    )
    blk = ssa_block(0x1000, [
        call(const_ptr(0x4000), pc=0x1004),
        ret(),
    ])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    text = "\n".join(render_hlil(hlil))
    assert "→ x0" not in text
