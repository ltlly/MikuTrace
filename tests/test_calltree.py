"""P0-1: build_call_tree from bl/ret pairs.

Pattern: scan trace, push frame on bl/blr, pop on ret, build nested tree.
Each tree node = {fn, enter_idx, exit_idx, children}.
"""
import pytest
from tests.synth import build_trace
from viewer.calltree import build_call_tree


def test_calltree_no_calls_yields_root_only():
    """Trace with no bl/ret → just a root frame covering all insns."""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('add x0, x0, #1', {'x0': 2}),
        ('nop', {}),
    ])
    tree = build_call_tree(t)
    assert tree["enter_idx"] == 0
    assert tree["exit_idx"] >= 2
    assert tree["children"] == []
    t.close()


def test_calltree_single_call():
    """bl at idx 1 → ret at idx 4: nested frame."""
    t = build_trace([
        ('mov x0, #1',     {'x0': 1}),       # 0: pre-call
        ('bl #+8',         {'lr': 0x100008}),# 1: bl → push
        ('mov x1, x0',     {'x1': 1}),       # 2: in callee
        ('mov x2, x1',     {'x2': 1}),       # 3: in callee
        ('ret',            {}),              # 4: ret → pop
        ('nop',            {}),              # 5: post-call
    ])
    tree = build_call_tree(t)
    assert len(tree["children"]) == 1
    child = tree["children"][0]
    assert child["enter_idx"] == 1
    assert child["exit_idx"] == 4
    t.close()


def test_calltree_nested_calls():
    """bl at idx 1, nested bl at 3, two rets."""
    t = build_trace([
        ('mov x0, #1',  {'x0': 1}),         # 0
        ('bl #+8',      {'lr': 0x100008}),  # 1: outer call
        ('nop',         {}),                # 2
        ('bl #+8',      {'lr': 0x100010}),  # 3: inner call
        ('mov x1, x0',  {'x1': 1}),         # 4
        ('ret',         {}),                # 5: inner ret
        ('nop',         {}),                # 6
        ('ret',         {}),                # 7: outer ret
        ('nop',         {}),                # 8
    ])
    tree = build_call_tree(t)
    assert len(tree["children"]) == 1
    outer = tree["children"][0]
    assert outer["enter_idx"] == 1
    assert outer["exit_idx"] == 7
    assert len(outer["children"]) == 1
    inner = outer["children"][0]
    assert inner["enter_idx"] == 3
    assert inner["exit_idx"] == 5
    t.close()


def test_calltree_unbalanced_extra_ret_no_crash():
    """ret without matching bl (mid-function trace) — must not crash, just stay
    at root level."""
    t = build_trace([
        ('nop', {}),
        ('ret', {}),
        ('nop', {}),
    ])
    tree = build_call_tree(t)
    # Root still covers all; extra ret silently absorbed
    assert tree["enter_idx"] == 0
    t.close()


def test_calltree_max_depth_cap():
    """max_depth caps tree depth to prevent runaway recursion display."""
    seq = [('mov x0, #1', {'x0': 1})]
    # 10 nested calls
    for i in range(10):
        seq.append(('bl #+8', {'lr': 0x100000 + i*4}))
    for i in range(10):
        seq.append(('ret', {}))
    t = build_trace(seq)
    tree = build_call_tree(t, max_depth=3)
    # Walk and check no node deeper than 3
    def depth(n):
        if not n["children"]: return 0
        return 1 + max(depth(c) for c in n["children"])
    assert depth(tree) <= 3
    t.close()


def test_calltree_includes_func_name_when_known():
    """If symbol resolves at enter PC, node["fn"] is set."""
    t = build_trace([
        ('mov x0, #1', {}),
        ('bl #+8',     {'lr': 0x100008}),
        ('ret',        {}),
    ])
    tree = build_call_tree(t)
    # Root has no fn (or "?"), child fn might be the synth's only func
    if tree["children"]:
        assert "fn" in tree["children"][0]
    t.close()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
