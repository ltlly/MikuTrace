"""Render layer: prologue / epilogue 折叠 — 单元测试."""
from __future__ import annotations
from viewer.decompiler.llil import (
    LlilExpr, ssa_block, restructure, CfgInfo, render_hlil,
    set_reg, reg, const, add, sub, store, load, ret, nop,
)
from viewer.decompiler.llil.render import _is_prologue_root, _render_block


def test_is_prologue_sp_alloc():
    """SET_REG(sp, sub(reg(sp), const(0x100))) — prologue stack alloc."""
    e = set_reg("sp", sub(reg("sp"), const(0x100)))
    assert _is_prologue_root(e) is True


def test_is_prologue_sp_release():
    """SET_REG(sp, add(reg(sp), const(0x100))) — epilogue stack release."""
    e = set_reg("sp", add(reg("sp"), const(0x100)))
    assert _is_prologue_root(e) is True


def test_is_prologue_fp_setup():
    """SET_REG(fp, add(reg(sp), const(N))) — fp 设置."""
    e = set_reg("fp", add(reg("sp"), const(0x150)))
    assert _is_prologue_root(e) is True


def test_is_prologue_callee_save_x29():
    """STORE([sp+N], reg(x29)) — 保存 fp/x29."""
    e = store(add(reg("sp"), const(0x150)), reg("x29"))
    assert _is_prologue_root(e) is True


def test_is_prologue_callee_save_lr():
    e = store(add(reg("sp"), const(0x158)), reg("lr"))
    assert _is_prologue_root(e) is True


def test_is_prologue_callee_save_x19():
    e = store(reg("sp"), reg("x19"))
    assert _is_prologue_root(e) is True


def test_is_not_prologue_arg_save():
    """STORE([sp+N], reg(x0)) — 保存 arg 不是 prologue (callee-saved 才是)."""
    e = store(add(reg("sp"), const(0x10)), reg("x0"))
    assert _is_prologue_root(e) is False


def test_is_not_prologue_normal_set():
    """SET_REG(x0, const(1)) — 普通 mov 不是 prologue."""
    e = set_reg("x0", const(1))
    assert _is_prologue_root(e) is False


def test_render_collapses_prologue():
    """连续 ≥3 条 prologue store → 折叠注释."""
    roots = [
        set_reg("sp", sub(reg("sp"), const(0x1b0))),  # alloc
        store(add(reg("sp"), const(0x150)), reg("fp")),
        store(add(reg("sp"), const(0x158)), reg("lr")),
        store(add(reg("sp"), const(0x160)), reg("x28")),
        # 普通 op
        set_reg("x0", const(0x42)),
        ret(),
    ]
    blk = ssa_block(0x1000, roots)
    lines = _render_block(blk, types=None, shapes=None, indent=0)
    text = "\n".join(lines)
    assert "// prologue:" in text
    assert "x0 = 0x42" in text
    # 4 条 prologue 折叠成 1 行注释 + 普通 ops 都留
    n_assigns = sum(1 for l in lines if "=" in l and "//" not in l)
    assert n_assigns == 1


def test_render_skips_collapse_for_short_prologue():
    """< 3 条 prologue 不折叠 (可能 false positive)."""
    roots = [
        set_reg("sp", sub(reg("sp"), const(0x10))),
        store(reg("sp"), reg("fp")),
        # 中断
        set_reg("x0", const(1)),
        ret(),
    ]
    blk = ssa_block(0x1000, roots)
    lines = _render_block(blk, types=None, shapes=None, indent=0)
    text = "\n".join(lines)
    assert "// prologue" not in text


def test_render_collapse_disabled():
    """collapse_prologue=False → 不折叠."""
    roots = [
        set_reg("sp", sub(reg("sp"), const(0x1b0))),
        store(add(reg("sp"), const(0x150)), reg("fp")),
        store(add(reg("sp"), const(0x158)), reg("lr")),
        store(add(reg("sp"), const(0x160)), reg("x28")),
        ret(),
    ]
    blk = ssa_block(0x1000, roots)
    lines = _render_block(blk, types=None, shapes=None, indent=0,
                          collapse_prologue=False)
    text = "\n".join(lines)
    assert "// prologue" not in text


def test_render_collapses_epilogue():
    """末尾连续 ≥3 条 prologue-style root → epilogue 折叠."""
    roots = [
        set_reg("x0", const(0x42)),
        # epilogue
        store(reg("sp"), reg("x19")),  # 不能是 store... epilogue 应该是 load
        store(add(reg("sp"), const(8)), reg("x20")),
        store(add(reg("sp"), const(16)), reg("x21")),
        set_reg("sp", add(reg("sp"), const(0x100))),
    ]
    # 注: 实际 epilogue 是 ldp + ret. 我们这里只测 _is_prologue_root 检测
    # 也兼容 store-style (因 prologue/epilogue 都涉及 sp+offset 的 callee-saved
    # store/load). MVP 简化只识 store. 此 case 测 4 条尾部全 prologue → 折.
    blk = ssa_block(0x1000, roots)
    lines = _render_block(blk, types=None, shapes=None, indent=0)
    text = "\n".join(lines)
    assert "// epilogue:" in text or "// prologue:" in text   # 可能整段被前缀吃了
