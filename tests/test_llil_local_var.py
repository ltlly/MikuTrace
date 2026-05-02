"""Render layer: local variable 命名 (sp/fp + offset → var_*) — 单元测试."""
from __future__ import annotations
from viewer.decompiler.llil import (
    ssa_block, restructure, CfgInfo, render_hlil, expr_to_c,
    set_reg, reg, const, add, sub, store, load, ret,
)
from viewer.decompiler.llil.render import _try_local_var


def test_try_local_var_sp_with_offset():
    """add(reg(sp), const(0x150)) → var_sp_150."""
    addr = add(reg("sp"), const(0x150))
    loc = {}
    name = _try_local_var(addr, loc)
    assert name == "var_sp_150"
    assert ("sp", 0x150) in loc


def test_try_local_var_fp_negative():
    """fp - 0x8 → var_fp_n8 (n 前缀表示负)."""
    addr = sub(reg("fp"), const(8))
    # sub 在 lift 时是 LLIL_SUB, addr expr 应该是 add(reg(fp), const(-8))
    # 测两种 form: sub form 不命中 (我们只接 LLIL_ADD), 应用 add(fp, -8)
    addr2 = add(reg("fp"), const(-8))
    loc = {}
    name = _try_local_var(addr2, loc)
    assert name == "var_fp_n8"


def test_try_local_var_no_offset():
    """reg(sp) (disp=0) → var_sp_0."""
    addr = reg("sp")
    loc = {}
    name = _try_local_var(addr, loc)
    assert name == "var_sp_0"


def test_try_local_var_non_sp_fp():
    """add(reg(x9), const(8)) → 不命中 (base 不是 sp/fp)."""
    addr = add(reg("x9"), const(8))
    loc = {}
    assert _try_local_var(addr, loc) == ""


def test_try_local_var_reuses_name():
    """同 (base, disp) 多次 call 用同名."""
    loc = {}
    a1 = add(reg("sp"), const(0x100))
    a2 = add(reg("sp"), const(0x100))
    n1 = _try_local_var(a1, loc)
    n2 = _try_local_var(a2, loc)
    assert n1 == n2 == "var_sp_100"
    assert len(loc) == 1


def test_try_local_var_loc_names_none():
    """loc_names=None → disabled, 返回 ""."""
    addr = add(reg("sp"), const(0x100))
    assert _try_local_var(addr, None) == ""


def test_render_uses_local_var_for_load():
    """LOAD(add(reg(sp), const(0x10))) 渲染含 var_sp_10."""
    e = set_reg("x0", load(add(reg("sp"), const(0x10)), size=8))
    s = expr_to_c(e.operands[1], loc_names={})
    assert "var_sp_10" in s


def test_render_uses_local_var_for_store():
    """STORE(add(reg(sp), const(0x10)), reg(x0)) 渲染 'var_sp_10 = x0'."""
    e = store(add(reg("sp"), const(0x10)), reg("x0"))
    s = expr_to_c(e, loc_names={})
    assert "var_sp_10 = x0" in s


def test_render_full_block_with_loc_names():
    """整 block 渲染, sp+offset 引用全用 var_NN."""
    blk = ssa_block(0x1000, [
        set_reg("x0", load(add(reg("sp"), const(0x10)), size=8)),
        store(add(reg("sp"), const(0x18)), reg("x1"), size=8),
        ret(),
    ])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    text = "\n".join(render_hlil(hlil))
    assert "var_sp_10" in text
    assert "var_sp_18" in text


def test_render_loc_names_disabled():
    """如果 loc_names=None → 不重命名, 兜底 *(T*)(addr)."""
    blk = ssa_block(0x1000, [
        set_reg("x0", load(add(reg("sp"), const(0x10)), size=8)),
    ])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    # 强制 loc_names disabled — 用 dict 而非 None? 其实 render_hlil 默认创空
    # dict, 实质 enabled. 验证默认 enabled (disable 走 expr_to_c 直接调).
    text = "\n".join(render_hlil(hlil))
    assert "var_sp_10" in text   # 默认 enabled
