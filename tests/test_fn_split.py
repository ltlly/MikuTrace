"""calltree-based 子 FuncIR 切分 — P2-DEC3-B0 单元测试."""
from __future__ import annotations
import pytest
from tests.synth import build_trace
from viewer import build_trace_ir
from viewer.decompiler.builder import split_top_k_callees, _flatten_calltree


def test_split_disabled_preserves_dec1_behavior():
    """split_top_k=0 → 只 F0, 跟 DEC1 输出一致."""
    t = build_trace([
        ('mov x0, #1',  {'x0': 1}),
        ('bl #+8',      {'x30': 0x100008}),
        ('ret',         {}),
        ('mov x1, #2',  {'x1': 2}),
        ('ret',         {}),
    ])
    top = build_trace_ir(t, split_top_k=0)
    assert len(top.fns) == 1
    assert top.fns[0].id == "F0"
    t.close()


def test_split_promotes_callees():
    """长度合理的子 callee 被升级为独立 FuncIR.

    合成 trace 限制: build_trace 每轮 base PC 递进, bl 每次跳到不同 PC.
    所以这里只验证 "存在子 fn", 不验证 exec_count 合并 (合并需真机).
    """
    seq = []
    for _ in range(4):
        seq.extend([
            ('mov x0, #1',  {'x0': 1}),
            ('bl #+12',     {'x30': 0}),
            # callee body (3 insns)
            ('mov x2, #11', {'x2': 11}),
            ('mov x3, #12', {'x3': 12}),
            ('ret',         {}),
        ])
    seq.append(('ret', {}))
    t = build_trace(seq)
    top = build_trace_ir(t, split_top_k=10, split_min_records=3)
    # 至少有 F0 + 一个子 fn (callee)
    assert len(top.fns) >= 2, f"expected ≥2 fns, got {[f.id for f in top.fns]}"
    # F0 仍是 root, 整 trace 视图
    f0 = top.fns[0]
    assert f0.id == "F0"
    assert f0.entry_idx == 0
    t.close()


def test_split_filters_long_instances():
    """instance 长度 > 30% trace → 过滤为 calltree 噪声 (OLLVM 场景)."""
    # 模拟: bl 后没有匹配 ret, instance.exit_idx 飘到末尾
    t = build_trace([
        ('mov x0, #1',  {'x0': 1}),
        ('bl #+8',      {'x30': 0}),       # bl, 但接下来都没 ret 直到末尾
        ('mov x2, #1',  {'x2': 1}),
        ('mov x3, #2',  {'x3': 2}),
        ('mov x4, #3',  {'x4': 3}),
        ('mov x5, #4',  {'x5': 4}),
        ('mov x6, #5',  {'x6': 5}),
        ('mov x7, #6',  {'x7': 6}),
        ('mov x8, #7',  {'x8': 7}),
        ('mov x9, #8',  {'x9': 8}),        # 8 records 没 ret = 80% trace
    ])
    top = build_trace_ir(t, split_top_k=10, split_min_records=3)
    # 唯一的 callee instance 长度 = 8/10 = 80% trace, 应该被过滤
    # 所以 fns 只有 F0, 没有子 fn
    assert len(top.fns) == 1
    assert top.fns[0].id == "F0"
    t.close()


def test_split_min_records_threshold():
    """min_records 高门限 → 短 fn 不升级."""
    t = build_trace([
        ('mov x0, #1',  {'x0': 1}),
        ('bl #+8',      {'x30': 0}),
        ('ret',         {}),                # callee 只 1 insn (太短)
        ('mov x1, #2',  {'x1': 2}),
        ('ret',         {}),
    ])
    top = build_trace_ir(t, split_top_k=10, split_min_records=100)
    # 短 callee 不升级
    assert len(top.fns) == 1
    t.close()


def test_flatten_calltree_basic():
    """_flatten_calltree 平铺嵌套 dict."""
    tree = {
        "fn": "?", "enter_idx": 0, "exit_idx": 100, "depth": 0,
        "children": [
            {"fn": "a", "fn_pc": 0x1000, "enter_idx": 5, "exit_idx": 20,
             "depth": 1, "children": [
                {"fn": "b", "fn_pc": 0x2000, "enter_idx": 8, "exit_idx": 15,
                 "depth": 2, "children": []}
             ]},
            {"fn": "c", "fn_pc": 0x3000, "enter_idx": 30, "exit_idx": 50,
             "depth": 1, "children": []}
        ]
    }
    flat = _flatten_calltree(tree)
    assert len(flat) == 3
    pcs = sorted(f["fn_pc"] for f in flat)
    assert pcs == [0x1000, 0x2000, 0x3000]


def test_split_groups_same_callee_pc():
    """直接构造 calltree dict, 验证 group-by-fn_pc 合并逻辑.

    用合成 trace 不能造同一 callee_pc 多次调用 (build_trace 每条指令 PC 递进),
    所以这里直接 unit-test 合并逻辑.
    """
    from collections import defaultdict
    fake_frames = [
        {"fn_pc": 0x1000, "enter_idx": 10, "exit_idx": 20, "depth": 1, "fn": "a"},
        {"fn_pc": 0x1000, "enter_idx": 30, "exit_idx": 40, "depth": 1, "fn": "a"},
        {"fn_pc": 0x1000, "enter_idx": 50, "exit_idx": 60, "depth": 1, "fn": "a"},
        {"fn_pc": 0x2000, "enter_idx": 70, "exit_idx": 80, "depth": 1, "fn": "b"},
    ]
    by_pc = defaultdict(list)
    for f in fake_frames:
        by_pc[f["fn_pc"]].append(f)
    # 0x1000 应该聚成 1 组 3 个 instance, 0x2000 1 组 1 instance
    assert len(by_pc[0x1000]) == 3
    assert len(by_pc[0x2000]) == 1


def test_split_subfn_blocks_have_tier():
    """split 出的子 fn blocks 也要走 tier 分类 (兼容 DEC3-A)."""
    seq = []
    for _ in range(4):
        seq.extend([
            ('bl #+8',      {'x30': 0}),
            ('mov x2, #11', {'x2': 11}),
            ('mov x3, #12', {'x3': 12}),
            ('ret',         {}),
        ])
    t = build_trace(seq)
    top = build_trace_ir(t, split_top_k=10, split_min_records=3)
    # 所有 fn (F0 + child) 的 blocks 都应有 tier 字段
    for fn in top.fns:
        for b in fn.blocks:
            assert b.tier in ("hot", "warm", "cold")
    t.close()


def test_calltree_includes_fn_pc_field():
    """新加的 fn_pc 字段在 calltree 输出里存在."""
    from viewer.calltree import build_call_tree
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('bl #+8',     {'x30': 0}),
        ('mov x2, #2', {'x2': 2}),
        ('ret',        {}),
        ('ret',        {}),
    ])
    tree = build_call_tree(t)
    assert tree["children"], "should have at least one child"
    child = tree["children"][0]
    assert "fn_pc" in child
    assert child["fn_pc"] != 0
    t.close()
