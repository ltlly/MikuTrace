"""Pass 2 SSA on LLIL expression tree — 单元测试."""
from __future__ import annotations
import pytest
from viewer.decompiler.llil import (
    LlilExpr, ssa_block, ssa_blocks,
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
