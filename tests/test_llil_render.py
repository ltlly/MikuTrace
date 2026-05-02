"""Pass 8 render — HLIL → C-like markdown."""
from __future__ import annotations
from viewer.decompiler.llil import (
    LlilExpr, ssa_block, restructure, CfgInfo, render_hlil, expr_to_c,
    HlilSeq, HlilLoop, HlilIfElse, HlilBlock, HlilGoto, HlilRet,
    set_reg, reg, const, add, sub, xor, load, store, ret, call, const_ptr,
    flag_cond, if_, goto, cmp_e,
    typelat_block, struct_recover_block,
)


def test_expr_to_c_basic_arith():
    e = add(reg("x0"), const(5))
    s = expr_to_c(e)
    assert s == "(x0 + 5)"


def test_expr_to_c_load():
    e = load(reg("x1"), size=8)
    s = expr_to_c(e)
    assert "*(uint64_t*)" in s
    assert "x1" in s


def test_expr_to_c_xor_chain():
    e = xor(reg("x0"), const(0xAA))
    s = expr_to_c(e)
    assert s == "(x0 ^ 0xaa)"


def test_render_block_basic():
    """SET_REG x0, 1 → 'x0 = 1;'"""
    blk = ssa_block(0x1000, [set_reg("x0", const(1), pc=0x1000), ret(pc=0x1004)])
    out = restructure(CfgInfo(succs={}, preds={}, entry=0x1000),
                      {0x1000: blk})
    lines = render_hlil(out)
    text = "\n".join(lines)
    assert "x0 = 1" in text
    assert "return" in text


def test_render_ifelse():
    cond = flag_cond("eq")
    if_root = if_(cond, 0x2000, 0x3000, pc=0x1000)
    b0 = ssa_block(0x1000, [if_root])
    b1 = ssa_block(0x2000, [ret(pc=0x2000)])
    b2 = ssa_block(0x3000, [ret(pc=0x3000)])
    blocks = {0x1000: b0, 0x2000: b1, 0x3000: b2}
    cfg = CfgInfo(
        succs={0x1000: [0x2000, 0x3000]},
        preds={0x2000: [0x1000], 0x3000: [0x1000]},
        entry=0x1000,
    )
    hlil = restructure(cfg, blocks)
    text = "\n".join(render_hlil(hlil))
    assert "if (" in text
    assert "} else {" in text


def test_render_loop():
    b0 = ssa_block(0x1000, [set_reg("x0", const(0), pc=0x1000)])
    b1 = ssa_block(0x1004, [goto(0x1000, pc=0x1004)])
    cfg = CfgInfo(
        succs={0x1000: [0x1004], 0x1004: [0x1000]},
        preds={0x1000: [0x1004], 0x1004: [0x1000]},
        entry=0x1000,
        exec_count={0x1000: 5, 0x1004: 5},
    )
    hlil = restructure(cfg, {0x1000: b0, 0x1004: b1})
    text = "\n".join(render_hlil(hlil))
    assert "while" in text
    assert "iters=5" in text


def test_render_field_when_shape_known():
    """ldr x0, [x1, #0x40] + struct shape known → x1->f0x40."""
    e = set_reg("x0", load(add(reg("x1"), const(0x40)), size=8), pc=0x1000)
    blk = ssa_block(0x1000, [e, ret(pc=0x1004)])
    types = typelat_block(blk)
    shapes = struct_recover_block(blk, types)
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    lines = render_hlil(hlil, types=types, shapes=shapes)
    text = "\n".join(lines)
    assert "x1->f0x40" in text


def test_render_call():
    e = call(const_ptr(0x4000), pc=0x1000)
    blk = ssa_block(0x1000, [e, ret(pc=0x1004)])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    text = "\n".join(render_hlil(hlil))
    assert "call(" in text


def test_render_intrinsic():
    from viewer.decompiler.llil import intrinsic
    e = intrinsic("svc", op_str="#0", pc=0x1000)
    blk = ssa_block(0x1000, [e, ret(pc=0x1004)])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    text = "\n".join(render_hlil(hlil))
    assert "intrinsic" in text and "svc" in text


def test_render_return_shows_x0_value():
    """ret 显示 'return x0_vN' (BN 风格), 用 cur_versions + var_names."""
    from viewer.decompiler.llil import (
        ssa_block, restructure, CfgInfo, render_hlil,
        set_reg, reg, const, ret, unify_vars,
    )
    blk = ssa_block(0x1000, [
        set_reg("x0", const(0x42)),    # x0 → v1
        ret(),
    ])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    var_names = unify_vars({0x1000: blk})
    text = "\n".join(render_hlil(hlil, var_names=var_names))
    assert "return x0_v1" in text


def test_render_return_no_writes_uses_arg_0():
    """ret 没写 x0 → 返回入口 x0 = arg_0 (per var_unify)."""
    from viewer.decompiler.llil import (
        ssa_block, restructure, CfgInfo, render_hlil, ret, unify_vars,
    )
    blk = ssa_block(0x1000, [ret()])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    var_names = unify_vars({0x1000: blk})
    text = "\n".join(render_hlil(hlil, var_names=var_names))
    assert "return arg_0" in text


def test_render_return_no_var_names_falls_back_plain():
    """ret 没 var_names → 简单 'return' (向后兼容)."""
    from viewer.decompiler.llil import (
        ssa_block, restructure, CfgInfo, render_hlil, ret,
    )
    blk = ssa_block(0x1000, [ret()])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    text = "\n".join(render_hlil(hlil))
    assert "return" in text
    assert "return x0" not in text


def test_render_ror_uses_function_style():
    """LLIL_ROR → '_ror(x, n)' 而非 '(x ror n)' (C 没原生 rotate)."""
    from viewer.decompiler.llil import (
        ssa_block, restructure, CfgInfo, render_hlil,
        set_reg, reg, const, ror, ret, unify_vars,
    )
    blk = ssa_block(0x1000, [
        set_reg("x0", ror(reg("x1"), const(5))),
        ret(),
    ])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    var_names = unify_vars({0x1000: blk})
    text = "\n".join(render_hlil(hlil, var_names=var_names))
    assert "_ror(" in text
    assert "ror " not in text  # 不是 'x ror 5' 中缀


def test_render_rol_uses_function_style():
    from viewer.decompiler.llil import (
        ssa_block, restructure, CfgInfo, render_hlil,
        set_reg, reg, const, rol, ret,
    )
    blk = ssa_block(0x1000, [
        set_reg("x0", rol(reg("x1"), const(7))),
        ret(),
    ])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    hlil = restructure(cfg, {0x1000: blk})
    text = "\n".join(render_hlil(hlil))
    assert "_rol(" in text
