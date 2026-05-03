"""Pass 2 SSA on LLIL expression tree — 单元测试."""
from __future__ import annotations
import pytest
from viewer.decompiler.llil import (
    LlilExpr, ssa_block, ssa_blocks, ssa_blocks_cfg,
    set_reg, reg, const, add, load, store, ret, nop,
    LLIL_SET_REG, LLIL_REG, LLIL_ADD, LLIL_CONST,
)


def test_ssa_empty():
    blk = ssa_block(0x1000, [])
    assert blk.roots == []
    assert blk.exit_versions == {}


def test_ssa_single_set():
    """set_reg(x0, const(1)) → x0 v1."""
    e = set_reg("x0", const(1), pc=0x1000)
    blk = ssa_block(0x1000, [e])
    assert blk.tag.get(e) == 1
    assert blk.exit_versions == {"x0": 1}


def test_ssa_multiple_writes_bump_version():
    e1 = set_reg("x0", const(1), pc=0x1000)
    e2 = set_reg("x0", const(2), pc=0x1004)
    e3 = set_reg("x0", const(3), pc=0x1008)
    blk = ssa_block(0x1000, [e1, e2, e3])
    assert blk.tag.get(e1) == 1
    assert blk.tag.get(e2) == 2
    assert blk.tag.get(e3) == 3
    assert blk.exit_versions == {"x0": 3}


def test_ssa_use_picks_latest_def():
    """set_reg(x0, 5); set_reg(x1, x0+3) — use x0 应取 v1."""
    write_x0 = set_reg("x0", const(5))
    use_x0 = reg("x0")
    add_e = add(use_x0, const(3))
    write_x1 = set_reg("x1", add_e, pc=0x1004)
    blk = ssa_block(0x1000, [write_x0, write_x1])
    assert blk.tag.get(use_x0) == 1   # x0 v1
    assert blk.tag.get(write_x1) == 1


def test_ssa_use_uses_entry_version():
    """entry_versions x0=5 → reg('x0') 标 v5."""
    use_x0 = reg("x0")
    e = set_reg("x1", use_x0)
    blk = ssa_block(0x1000, [e], entry_versions={"x0": 5})
    assert blk.tag.get(use_x0) == 5
    assert blk.entry_versions == {"x0": 5}
    assert blk.exit_versions["x0"] == 5
    assert blk.exit_versions["x1"] == 1


def test_ssa_nested_use():
    """set_reg('x0', load(add(reg('x1'), const(0x40)))) — 嵌套 reg use."""
    base = reg("x1")
    addr = add(base, const(0x40))
    val = load(addr, size=8)
    root = set_reg("x0", val, pc=0x1000)
    blk = ssa_block(0x1000, [root])
    assert blk.tag.get(base) == 0   # x1 entry v0 (no def yet)
    assert blk.tag.get(root) == 1   # x0 v1


def test_ssa_store_no_dst_no_bump():
    """store 没 dst, 不 bump 任何 reg version."""
    write_x0 = set_reg("x0", const(99))
    addr = reg("x1")
    val = reg("x0")
    st = store(addr, val, size=8, pc=0x1004)
    blk = ssa_block(0x1000, [write_x0, st])
    # store 不 set tag (它是 root 但不是 SET_REG)
    assert blk.tag.versions.get(id(st), 0) == 0   # 默认不存
    # 但 use 部分要标
    assert blk.tag.get(addr) == 0  # x1 v0
    assert blk.tag.get(val) == 1   # x0 v1 (上一行 def 的)


def test_ssa_blocks_independent():
    blocks = {
        0x1000: [set_reg("x0", const(1))],
        0x2000: [set_reg("x0", const(2))],
    }
    out = ssa_blocks(blocks)
    assert len(out) == 2
    e1 = out[0x1000].roots[0]
    e2 = out[0x2000].roots[0]
    assert out[0x1000].tag.get(e1) == 1
    assert out[0x2000].tag.get(e2) == 1   # 各自从 0


def test_ssa_use_before_def_in_root_uses_pre_version():
    """SET_REG x0, ADD(REG(x0), 1) — use 用 v0, dst 是 v1."""
    use_x0 = reg("x0")
    expr = add(use_x0, const(1))
    root = set_reg("x0", expr)
    blk = ssa_block(0x1000, [root], entry_versions={"x0": 5})
    # use 应该 v5 (entry version), 不是新 v6
    assert blk.tag.get(use_x0) == 5
    assert blk.tag.get(root) == 6   # 写后 v6


def test_ssa_ret_no_effect():
    """ret 不 set/use, 测试不崩."""
    blk = ssa_block(0x1000, [set_reg("x0", const(0)), ret()])
    assert len(blk.roots) == 2


# ─────────── call-kill (AAPCS64 caller-saved) ───────────

def test_ssa_call_bumps_caller_saved_regs():
    """LLIL_CALL 后 x0..x18 + lr 全 bump version. 之后读 x0 拿到新 version."""
    from viewer.decompiler.llil import call, const_ptr
    use_x0_after = reg("x0")
    blk = ssa_block(0x1000, [
        set_reg("x0", const(5)),                            # x0 → v1
        call(const_ptr(0x4000), pc=0x1004),                 # bumps x0..x18, lr
        set_reg("x10", use_x0_after),                       # uses post-call x0
    ])
    # call 前 x0 是 v1, call 后 v2 (kill)
    assert blk.tag.get(use_x0_after) == 2


def test_ssa_call_bumps_lr():
    """LLIL_CALL 后 lr 也 bump (bl 隐式写 lr=pc+4)."""
    from viewer.decompiler.llil import call, const_ptr
    use_lr = reg("lr")
    blk = ssa_block(0x1000, [
        set_reg("x9", reg("lr")),                           # use lr v0
        call(const_ptr(0x4000), pc=0x1004),                 # bumps lr
        set_reg("x10", use_lr),                             # use post-call lr
    ])
    # post-call lr v1
    assert blk.tag.get(use_lr) == 1


def test_ssa_call_preserves_callee_saved():
    """x19..x28 / fp / sp 不被 call kill, version 不变."""
    from viewer.decompiler.llil import call, const_ptr
    use_x19 = reg("x19")
    blk = ssa_block(0x1000, [
        set_reg("x19", const(7)),                           # x19 → v1
        call(const_ptr(0x4000), pc=0x1004),                 # NO kill
        set_reg("x10", use_x19),                            # still x19 v1
    ])
    assert blk.tag.get(use_x19) == 1


def test_ssa_call_kills_nzcv():
    """call 后 nzcv flag 也 kill — 后续 cmp 前 flag 不能错链."""
    from viewer.decompiler.llil import call, const_ptr, set_reg as sr
    from viewer.decompiler.llil.expr import LlilExpr, LLIL_SET_FLAG, LLIL_FLAG
    set_n = LlilExpr(LLIL_SET_FLAG, size=1, operands=["nzcv", const(0)])
    use_n = LlilExpr(LLIL_FLAG, size=1, operands=["nzcv"])
    blk = ssa_block(0x1000, [
        set_n,                                              # nzcv → v1
        call(const_ptr(0x4000), pc=0x1004),                 # bumps
        sr("x0", use_n),                                    # use post-call nzcv
    ])
    # post-call nzcv v2 (call bump)
    assert blk.tag.get(use_n) == 2


def test_ssa_call_kills_cmp_result_flag():
    """call 后 'cmp_result' 合成 flag 也 kill — flag_elim 不能跨 call 错合并.

    场景 (来自代码审计 fix): cmp x0, x1; bl foo; b.eq label
      之前 bug: cmp_result version 在 call 前后都是 1 → flag_elim 可能误把
      call 后的 IF(FLAG_COND(eq)) 跟 call 前的 SET_FLAG('cmp_result',...) 合并.
      正确: call 后 cmp_result version 应 bump.
    """
    from viewer.decompiler.llil import call, const_ptr, set_reg as sr, sub
    from viewer.decompiler.llil.expr import LlilExpr, LLIL_SET_FLAG, LLIL_FLAG
    set_cmp = LlilExpr(LLIL_SET_FLAG, size=8,
                       operands=["cmp_result", sub(reg("x0"), reg("x1"))])
    use_cmp = LlilExpr(LLIL_FLAG, size=1, operands=["cmp_result"])
    blk = ssa_block(0x1000, [
        set_cmp,                                            # cmp_result → v1
        call(const_ptr(0x4000), pc=0x1004),                 # bumps
        sr("x9", use_cmp),                                  # post-call use
    ])
    # post-call cmp_result v2 (call bump)
    assert blk.tag.get(use_cmp) == 2


# ─────────── cross-block SSA / synthetic phi ───────────


def test_ssa_blocks_cfg_single_pred_propagates_versions():
    use_x0 = reg("x0")
    blocks = {
        0x1000: [set_reg("x0", const(5))],
        0x2000: [set_reg("x1", use_x0)],
    }
    out = ssa_blocks_cfg(
        blocks,
        succs={0x1000: [0x2000], 0x2000: []},
        preds={0x2000: [0x1000]},
        entry=0x1000,
    )
    assert out[0x2000].entry_versions["x0"] == 1
    assert out[0x2000].tag.get(use_x0) == 1


def test_ssa_blocks_cfg_join_allocates_phi_version():
    use_x0 = reg("x0")
    blocks = {
        0x1000: [],
        0x2000: [set_reg("x0", const(1))],
        0x3000: [set_reg("x0", const(2))],
        0x4000: [set_reg("x1", use_x0)],
    }
    out = ssa_blocks_cfg(
        blocks,
        succs={0x1000: [0x2000, 0x3000], 0x2000: [0x4000], 0x3000: [0x4000], 0x4000: []},
        preds={0x2000: [0x1000], 0x3000: [0x1000], 0x4000: [0x2000, 0x3000]},
        entry=0x1000,
    )
    join = out[0x4000]
    assert join.phi_versions["x0"] == (1, 2)
    assert join.entry_versions["x0"] == 3
    assert join.tag.get(use_x0) == 3


def test_ssa_blocks_cfg_global_versions_do_not_collide_across_branches():
    blocks = {
        0x1000: [],
        0x2000: [set_reg("x0", const(1))],
        0x3000: [set_reg("x0", const(2))],
    }
    out = ssa_blocks_cfg(
        blocks,
        succs={0x1000: [0x2000, 0x3000], 0x2000: [], 0x3000: []},
        preds={0x2000: [0x1000], 0x3000: [0x1000]},
        entry=0x1000,
    )
    b1 = out[0x2000].roots[0]
    b2 = out[0x3000].roots[0]
    assert out[0x2000].tag.get(b1) == 1
    assert out[0x3000].tag.get(b2) == 2


def test_ssa_blocks_cfg_loop_header_refines_backedge_phi():
    """Loop header should record real backedge incoming after CFG pass.

    Shape: A -> B -> C -> B and B -> D. B reads x0 with one processed pred (A)
    and one initially pending backedge pred (C). It must allocate a synthetic
    phi entry version and then refine phi metadata to include C's exit version.
    """
    use_in_b = reg("x0")
    use_in_d = reg("x0")
    blocks = {
        0x1000: [set_reg("x0", const(1))],
        0x2000: [set_reg("x1", use_in_b)],
        0x3000: [set_reg("x0", add(reg("x0"), const(1)))],
        0x4000: [set_reg("x2", use_in_d)],
    }
    out = ssa_blocks_cfg(
        blocks,
        succs={0x1000: [0x2000], 0x2000: [0x3000, 0x4000], 0x3000: [0x2000], 0x4000: []},
        preds={0x2000: [0x1000, 0x3000], 0x3000: [0x2000], 0x4000: [0x2000]},
        entry=0x1000,
    )
    header = out[0x2000]
    backedge_x0 = out[0x3000].exit_versions["x0"]
    assert header.phi_versions["x0"] == (1, backedge_x0)
    assert header.entry_versions["x0"] > 1
    assert header.tag.get(use_in_b) == header.entry_versions["x0"]
    assert out[0x4000].tag.get(use_in_d) == header.exit_versions["x0"]


def test_ssa_blocks_cfg_loop_header_phi_for_backedge_only_def():
    """Backedge-only defs should still create loop-header phi metadata.

    x3 is first defined in loop body C, not before header B. Header B must still
    know x3 is a loop-carried value once C -> B exists.
    """
    blocks = {
        0x1000: [],
        0x2000: [],
        0x3000: [set_reg("x3", const(7))],
    }
    out = ssa_blocks_cfg(
        blocks,
        succs={0x1000: [0x2000], 0x2000: [0x3000], 0x3000: [0x2000]},
        preds={0x2000: [0x1000, 0x3000], 0x3000: [0x2000]},
        entry=0x1000,
    )
    header = out[0x2000]
    assert "x3" in header.phi_versions
    assert header.phi_versions["x3"] == (0, out[0x3000].exit_versions["x3"])
    assert header.entry_versions["x3"] > 0
