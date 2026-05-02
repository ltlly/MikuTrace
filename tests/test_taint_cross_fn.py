"""P1-A: taint --cross-fn-call adds frame_depth + explicit arg/ret markers
so chain output is self-documenting across bl/ret boundaries."""
import pytest
from tests.synth import build_trace
from viewer.taint import forward_taint, backward_taint, build_frame_depth_map
from viewer.index import Index


def test_build_frame_depth_map_basic():
    """idx 0:nop, 1:bl, 2:nop, 3:ret, 4:nop → depths: [0,0,1,1,0]
    (bl pushes AT bl idx so callee starts depth 1, ret pops AFTER ret so post-ret depth 0)."""
    t = build_trace([
        ('nop',     {}),                  # 0  depth 0 (root)
        ('bl #+8',  {'lr': 0x100008}),    # 1  depth 0 (bl is in caller)
        ('nop',     {}),                  # 2  depth 1 (callee body)
        ('ret',     {}),                  # 3  depth 1 (ret is in callee)
        ('nop',     {}),                  # 4  depth 0 (back in caller)
    ])
    depths = build_frame_depth_map(t)
    assert depths[0] == 0
    assert depths[1] == 0  # bl itself in caller frame
    assert depths[2] == 1
    assert depths[3] == 1  # ret itself in callee frame
    assert depths[4] == 0
    t.close()


def test_build_frame_depth_map_nested():
    t = build_trace([
        ('nop',     {}),                # 0
        ('bl #+8',  {'lr': 0x100008}),  # 1 outer call
        ('nop',     {}),                # 2 in fn1
        ('bl #+8',  {'lr': 0x100010}),  # 3 inner call
        ('nop',     {}),                # 4 in fn2
        ('ret',     {}),                # 5 ret fn2
        ('nop',     {}),                # 6 back in fn1
        ('ret',     {}),                # 7 ret fn1
        ('nop',     {}),                # 8 back in root
    ])
    depths = build_frame_depth_map(t)
    assert depths[2] == 1
    assert depths[4] == 2
    assert depths[6] == 1
    assert depths[8] == 0
    t.close()


def test_forward_taint_emits_frame_depth_when_cross_fn_call():
    """With cross_fn_call=True, output rows include frame_depth."""
    t = build_trace([
        ('mov x0, #5',  {'x0': 5}),         # 0 caller
        ('bl #+8',      {'lr': 0x100008}),  # 1 call
        ('mov x1, x0',  {'x1': 5}),         # 2 callee uses x0
        ('ret',         {}),                # 3 callee ret
        ('mov x2, x0',  {'x2': 5}),         # 4 caller uses x0
    ])
    idx = Index(t); idx.build()
    rows = forward_taint(t, 0, 'x0', max_count=10, index=idx,
                          cross_fn_call=True)
    # Each row should be (idx, why, frame_depth) when cross_fn_call=True
    assert all(len(r) == 3 for r in rows), \
        f"cross_fn_call output should have 3-tuples (idx, why, frame_depth): {rows}"
    # idx 2 (callee) → frame_depth 1
    by_idx = {r[0]: r[2] for r in rows}
    if 2 in by_idx:
        assert by_idx[2] == 1, f"callee body should be depth 1: {by_idx}"
    if 4 in by_idx:
        assert by_idx[4] == 0, f"post-ret should be depth 0: {by_idx}"
    t.close()


def test_forward_taint_default_signature_unchanged_no_cross_fn():
    """Without cross_fn_call (default False), output keeps 2-tuple shape."""
    t = build_trace([
        ('mov x0, #5',  {'x0': 5}),
        ('mov x1, x0',  {'x1': 5}),
    ])
    idx = Index(t); idx.build()
    rows = forward_taint(t, 0, 'x0', max_count=10, index=idx)
    if rows:
        assert len(rows[0]) == 2, "default should be 2-tuple (idx, why)"
    t.close()


def test_backward_taint_with_frame_depth():
    """Backward taint with cross_fn_call adds frame_depth to chain rows."""
    t = build_trace([
        ('mov x0, #5',     {'x0': 5}),       # 0
        ('bl #+8',         {'lr': 0x100008}),# 1
        ('add x0, x0, #1', {'x0': 6}),       # 2 callee def
        ('ret',            {}),              # 3
        ('mov x1, x0',     {'x1': 6}),       # 4 caller use
    ])
    idx = Index(t); idx.build()
    rows = backward_taint(t, 4, 'x0', max_count=10, index=idx,
                           cross_fn_call=True)
    assert all(len(r) == 3 for r in rows), \
        f"cross_fn_call output should have 3-tuples: {rows}"
    t.close()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
