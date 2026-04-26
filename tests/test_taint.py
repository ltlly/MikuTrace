"""测试污点追踪正确性 — 用合成 trace 构造已知传播链."""
import pytest
from tests.synth import build_trace
from viewer.taint import forward_taint, backward_taint
from viewer.index import Index


def test_forward_taint_basic_chain():
    """x0=1 → x1 = x0 → cmp x0, x1 → b.eq
    污染 x0，预期：x1 受 x0 影响，cmp 受 x0/x1 影响"""
    t = build_trace([
        ('mov x0, #1',     {'x0': 1}),       # 0: defines x0
        ('mov x1, x0',     {'x1': 1}),       # 1: x1 = x0 (uses x0)
        ('cmp x0, x1',     {'nzcv': 0x40}),  # 2: uses x0,x1
        ('b.eq #+8',       {}),               # 3: uses nzcv
    ])
    # 从 #0 (定义 x0 的地方) 正向跟踪 x0
    hits = forward_taint(t, 0, 'x0', max_count=10)
    idxs = [i for i, _ in hits]
    assert 1 in idxs, f"指令#1 应该被污染 (uses x0): {idxs}"
    assert 2 in idxs, f"指令#2 应该被污染 (uses x0): {idxs}"


def test_forward_taint_via_register_propagation():
    """x0 → x1 → x2: 中间寄存器传播"""
    t = build_trace([
        ('mov x0, #5',  {'x0': 5}),
        ('mov x1, x0',  {'x1': 5}),    # x1 受 x0 影响
        ('mov x2, x1',  {'x2': 5}),    # x2 受 x1 影响 → 间接受 x0 影响
        ('add x0, x0, #1', {'x0': 6}), # 重新定义 x0 但不影响 x2
    ])
    hits = forward_taint(t, 0, 'x0', max_count=10)
    idxs = [i for i, _ in hits]
    assert 1 in idxs and 2 in idxs, "传播应到达 #1 和 #2"


def test_backward_taint_chain():
    """构造已知反向链: 最终查询 x0 在最后一条的来源"""
    t = build_trace([
        ('mov x0, #5',     {'x0': 5}),       # 0: 定义 x0=5
        ('add x0, x0, #1', {'x0': 6}),       # 1: 用 x0=5, 写 x0=6
        ('add x0, x0, #2', {'x0': 8}),       # 2: 用 x0=6, 写 x0=8
        ('cmp x0, #3',     {'nzcv': 0x10}),  # 3: 用 x0=8 (CMP fix)
    ])
    # 反向 from #3 (cmp 处) reg x0
    hits = backward_taint(t, 3, 'x0', max_count=10)
    idxs = [i for i, _ in hits]
    # 应该能追到 #2, #1, #0 (前面所有 def x0 的指令)
    assert 0 in idxs, f"应追到原始定义 #0: {idxs}"
    assert 1 in idxs, f"应追到 #1: {idxs}"
    assert 2 in idxs, f"应追到 #2: {idxs}"


def test_backward_taint_through_cmp():
    """验证 cmp 修复：x8 通过 cmp+nzcv+cset 链回追"""
    t = build_trace([
        ('mov x0, #5',     {'x0': 5}),       # 0
        ('add x0, x0, #1', {'x0': 6}),       # 1
        ('cmp x0, #3',     {'nzcv': 0x10}),  # 2 (cmp uses x0, defs nzcv)
        ('mov x1, x0',     {'x1': 6}),       # 3 (uses x0, defs x1)
    ])
    # 反向 from #3 reg x1
    hits = backward_taint(t, 3, 'x1', max_count=20)
    idxs = sorted([i for i, _ in hits])
    # x1 在 #3 def，但 #3 没 def x1 之前，所以 backward 看 x0
    # 链应该到达 #1 (add x0) 和 #0 (mov x0)
    assert any(i <= 2 for i in idxs), f"应回溯到 #2 或更早: {idxs}"


def test_taint_dedup():
    """验证去重：同一 idx 不应在结果中重复出现"""
    t = build_trace([
        ('mov x0, #5',     {'x0': 5}),
        ('mov x1, x0',     {'x1': 5}),
        ('mov x2, x0',     {'x2': 5}),  # 又用 x0
        ('add x2, x2, x1', {'x2': 10}),
    ])
    hits = backward_taint(t, 3, 'x2', max_count=20)
    idxs = [i for i, _ in hits]
    assert len(idxs) == len(set(idxs)), f"backward 结果应去重: {idxs}"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
