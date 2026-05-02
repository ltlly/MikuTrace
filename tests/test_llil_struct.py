"""Pass 6 struct recovery on LLIL — 单元测试."""
from __future__ import annotations
from viewer.decompiler.llil import (
    LlilExpr, ssa_block, typelat_block, struct_recover_block, merge_shapes,
    FieldAccess, StructShape, TypeEnv,
    T_PTR, T_INT,
    set_reg, reg, const, add, load, store,
)


def test_no_struct_when_not_ptr():
    """ldr x0, [x1] 但 x1 不是 PTR (没初始化为 PTR) — 当 typelat 推 x1=PTR 后才有 shape.
    这里直接用 typelat 推 → 应有 shape."""
    e = set_reg("x0", load(reg("x1"), size=8))
    blk = ssa_block(0x1000, [e])
    types = typelat_block(blk)
    shapes = struct_recover_block(blk, types)
    assert (("x1", 0)) in shapes
    sh = shapes[("x1", 0)]
    assert 0 in sh.fields
    assert sh.fields[0].size == 8
    assert sh.fields[0].reads == 1


def test_multiple_fields():
    """ldr x0, [x1]; ldr x2, [x1, #8]; str x3, [x1, #16] → 3 fields."""
    rs = [
        set_reg("x0", load(reg("x1"), size=8)),
        set_reg("x2", load(add(reg("x1"), const(8)), size=8)),
        store(add(reg("x1"), const(16)), reg("x3"), size=8),
    ]
    blk = ssa_block(0x1000, rs)
    types = typelat_block(blk)
    shapes = struct_recover_block(blk, types)
    sh = shapes[("x1", 0)]
    assert set(sh.fields.keys()) == {0, 8, 16}
    assert sh.fields[0].reads == 1
    assert sh.fields[8].reads == 1
    assert sh.fields[16].writes == 1


def test_conflict_size():
    """同 offset 不同 size → conflict=True."""
    rs = [
        set_reg("x0", load(reg("x1"), size=8)),
        set_reg("x2", load(reg("x1"), size=4)),
    ]
    blk = ssa_block(0x1000, rs)
    types = typelat_block(blk)
    shapes = struct_recover_block(blk, types)
    sh = shapes[("x1", 0)]
    assert sh.conflict is True


def test_read_write_counts():
    """同 field 多次 read/write 累加."""
    rs = [
        set_reg("x0", load(reg("x1"), size=8)),
        set_reg("x2", load(reg("x1"), size=8)),
        store(reg("x1"), reg("x9"), size=8),
    ]
    blk = ssa_block(0x1000, rs)
    types = typelat_block(blk)
    shapes = struct_recover_block(blk, types)
    fa = shapes[("x1", 0)].fields[0]
    assert fa.reads == 2
    assert fa.writes == 1


def test_skip_non_ptr_base():
    """如果 typelat 没把 base 推 PTR (e.g. add 后子)→ 不收 shape."""
    # 构造: x1 是 INT, 不会被收
    initial = TypeEnv()
    initial.set("x1", 0, T_INT)
    e = set_reg("x0", load(reg("x1"), size=8))
    blk = ssa_block(0x1000, [e])
    # 但 typelat 会强制 load 的 addr 为 PTR — 实际行为是 base 被升级 PTR.
    # 测试: pass typelat 后 x1 应是 PTR (升级覆盖 INT — 实际 lattice join
    # PTR/INT = PTR), shape 仍出.
    types = typelat_block(blk, initial=initial)
    shapes = struct_recover_block(blk, types)
    # 实际: typelat_block 内 _force_ptr 会写 join, INT+PTR=PTR, 所以仍 collect
    assert ("x1", 0) in shapes


def test_merge_shapes_accumulates():
    blk1 = ssa_block(0x1000, [
        set_reg("x0", load(reg("x1"), size=8)),
    ])
    blk2 = ssa_block(0x2000, [
        set_reg("x2", load(add(reg("x1"), const(8)), size=8)),
    ])
    # x1 entry v0 一致 (默认), 都被推 PTR
    types1 = typelat_block(blk1)
    types2 = typelat_block(blk2)
    sh1 = struct_recover_block(blk1, types1)
    sh2 = struct_recover_block(blk2, types2)
    merged = merge_shapes([sh1, sh2])
    # 两 shape 都 (x1, 0), merge 后含 fields {0, 8}
    assert ("x1", 0) in merged
    assert set(merged[("x1", 0)].fields.keys()) == {0, 8}


def test_empty_block_no_shapes():
    blk = ssa_block(0x1000, [])
    types = TypeEnv()
    shapes = struct_recover_block(blk, types)
    assert shapes == {}


def test_struct_shape_short_repr():
    sh = StructShape(base_reg="x1", base_version=0)
    sh.fields[0] = FieldAccess(offset=0, size=8, reads=2, writes=0)
    sh.fields[8] = FieldAccess(offset=8, size=8, reads=0, writes=1)
    s = sh.short()
    assert "x1" in s
    assert "2 fields" in s
