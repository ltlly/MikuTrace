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
