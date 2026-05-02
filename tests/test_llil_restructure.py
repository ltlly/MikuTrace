"""Pass 7 restructure on LLIL — 单元测试."""
from __future__ import annotations
from viewer.decompiler.llil import (
    LlilExpr, ssa_block, restructure, CfgInfo,
    HlilSeq, HlilLoop, HlilIfElse, HlilBlock, HlilGoto, HlilRet,
    set_reg, reg, const, ret, goto, if_, flag_cond,
)
from viewer.decompiler.llil.pass_restructure import _find_backedges


def test_no_cfg_returns_seq():
    """No entry → all blocks in HlilSeq."""
    blk = ssa_block(0x1000, [set_reg("x0", const(0)), ret()])
    blocks = {0x1000: blk}
    cfg = CfgInfo()    # entry=0
    out = restructure(cfg, blocks)
    assert isinstance(out, HlilSeq)


def test_linear_blocks_become_seq():
    """B0 → B1 → ret. 顺序拼."""
    b0 = ssa_block(0x1000, [set_reg("x0", const(1))])
    b1 = ssa_block(0x1004, [ret(pc=0x1004)])
    blocks = {0x1000: b0, 0x1004: b1}
    cfg = CfgInfo(succs={0x1000: [0x1004]},
                  preds={0x1004: [0x1000]},
                  entry=0x1000)
    out = restructure(cfg, blocks)
    # 应是 HlilSeq([HlilBlock 0x1000, HlilSeq([HlilBlock 0x1004, HlilRet])])
    assert isinstance(out, HlilSeq)


def test_branch_becomes_ifelse():
    """B0 ends with IF; if(true)→B1 else→B2. 应有 HlilIfElse."""
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
    out = restructure(cfg, blocks)
    # outer is HlilSeq([HlilBlock 0x1000, HlilIfElse(cond, then, else)])
    assert isinstance(out, HlilSeq)
    found_if = any(isinstance(s, HlilIfElse) for s in out.stmts)
    assert found_if


def test_backedge_detected():
    """B0 → B1 → B0 (loop). _find_backedges 应抓到."""
    cfg = CfgInfo(
        succs={0x1000: [0x1004], 0x1004: [0x1000]},
        preds={0x1000: [0x1004], 0x1004: [0x1000]},
        entry=0x1000,
    )
    bes = _find_backedges(cfg)
    assert (0x1004, 0x1000) in bes or (0x1000, 0x1000) in bes


def test_simple_loop_becomes_hlil_loop():
    """B0 (header) → B1 → B0. 应识别 loop."""
    b0 = ssa_block(0x1000, [set_reg("x0", const(0), pc=0x1000)])
    b1 = ssa_block(0x1004, [goto(0x1000, pc=0x1004)])
    blocks = {0x1000: b0, 0x1004: b1}
    cfg = CfgInfo(
        succs={0x1000: [0x1004], 0x1004: [0x1000]},
        preds={0x1000: [0x1004], 0x1004: [0x1000]},
        entry=0x1000,
        exec_count={0x1000: 5, 0x1004: 5},
    )
    out = restructure(cfg, blocks)
    # out 顶层是 HlilLoop or HlilSeq containing HlilLoop
    if isinstance(out, HlilSeq):
        assert any(isinstance(s, HlilLoop) for s in out.stmts) or \
               any(isinstance(getattr(s, "body", None), HlilSeq) for s in out.stmts)
    else:
        assert isinstance(out, HlilLoop)


def test_ret_block_includes_hlil_ret():
    b0 = ssa_block(0x1000, [ret(pc=0x1000)])
    cfg = CfgInfo(succs={}, preds={}, entry=0x1000)
    out = restructure(cfg, {0x1000: b0})
    # contains HlilRet
    flat = _flatten(out)
    assert any(isinstance(x, HlilRet) for x in flat)


def _flatten(stmt):
    if isinstance(stmt, HlilSeq):
        out = []
        for s in stmt.stmts:
            out.extend(_flatten(s))
        return out
    if isinstance(stmt, HlilLoop):
        return _flatten(stmt.body)
    if isinstance(stmt, HlilIfElse):
        out = _flatten(stmt.then_b)
        if stmt.else_b is not None:
            out += _flatten(stmt.else_b)
        return out
    return [stmt]
