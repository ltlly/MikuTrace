"""viewer.cfg.find_sccs / loop_sccs Tarjan SCC 直接单元.

webui_full.test_scc_finds_loops 通过 /api/loops 间接覆盖, 但走 graphviz dot
+ FastAPI client 的开销大, 而 Tarjan 是核心算法, 值得直接测.
"""
import pytest
from viewer.cfg import CFG, Block, find_sccs, loop_sccs


def _make_cfg(blocks: list[int], edges: list[tuple[int, int]]) -> CFG:
    """Synth CFG: 仅图结构, 不要走 trace. start_pc 是抽象 id."""
    c = CFG()
    for pc in blocks:
        c.blocks[pc] = Block(start_pc=pc)
    for s, d in edges:
        c.edges[(s, d)] = {"kind": "b", "count": 1}
    if blocks:
        c.entry_pc = blocks[0]
    return c


def test_find_sccs_empty():
    assert find_sccs(CFG()) == []


def test_find_sccs_single_block_no_loop():
    c = _make_cfg([1], [])
    s = find_sccs(c)
    assert s == [[1]]


def test_find_sccs_dag():
    """A→B→C 三块单顶点 SCC."""
    c = _make_cfg([1, 2, 3], [(1, 2), (2, 3)])
    sccs = find_sccs(c)
    assert sorted([sorted(s) for s in sccs]) == [[1], [2], [3]]


def test_find_sccs_simple_cycle():
    """A→B→C→A 三顶点强连通, 单 SCC."""
    c = _make_cfg([1, 2, 3], [(1, 2), (2, 3), (3, 1)])
    sccs = find_sccs(c)
    assert len(sccs) == 1
    assert sorted(sccs[0]) == [1, 2, 3]


def test_find_sccs_self_loop():
    c = _make_cfg([1], [(1, 1)])
    sccs = find_sccs(c)
    assert sccs == [[1]]


def test_find_sccs_two_components():
    """两个独立循环 (1↔2) 和 (3↔4), 加一条单向桥 1→3."""
    c = _make_cfg([1, 2, 3, 4],
                  [(1, 2), (2, 1), (3, 4), (4, 3), (1, 3)])
    sccs = find_sccs(c)
    sccs_sorted = sorted([sorted(s) for s in sccs])
    assert sccs_sorted == [[1, 2], [3, 4]]


def test_loop_sccs_excludes_trivial_singletons():
    """size=1 没自环 → 不算 loop."""
    c = _make_cfg([1, 2, 3], [(1, 2), (2, 3)])
    assert loop_sccs(c) == []


def test_loop_sccs_includes_self_loop():
    c = _make_cfg([1], [(1, 1)])
    loops = loop_sccs(c)
    assert loops == [[1]]


def test_loop_sccs_includes_multi_node_cycle():
    c = _make_cfg([1, 2, 3], [(1, 2), (2, 3), (3, 1)])
    loops = loop_sccs(c)
    assert len(loops) == 1
    assert sorted(loops[0]) == [1, 2, 3]


def test_loop_sccs_skips_tail_of_loop():
    """循环 1↔2 + 出口 2→3, 期待只有 {1,2} 一个 loop."""
    c = _make_cfg([1, 2, 3], [(1, 2), (2, 1), (2, 3)])
    loops = loop_sccs(c)
    assert len(loops) == 1
    assert sorted(loops[0]) == [1, 2]


def test_find_sccs_iterative_handles_deep_graph():
    """递归 Tarjan 在 1000+ 节点链状会栈溢出, 测代码用迭代版."""
    n = 5000
    blocks = list(range(n))
    edges = [(i, i + 1) for i in range(n - 1)]
    c = _make_cfg(blocks, edges)
    sccs = find_sccs(c)
    # 全部独立单顶点
    assert len(sccs) == n


def test_find_sccs_ignores_edges_to_unknown_blocks():
    """edges 指向 cfg.blocks 没有的 PC 应被忽略, 不崩."""
    c = _make_cfg([1, 2], [(1, 2), (2, 999)])   # 999 不在 blocks
    sccs = find_sccs(c)
    # 不崩即可, 拓扑是 [{1}, {2}]
    assert sorted([sorted(s) for s in sccs]) == [[1], [2]]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
