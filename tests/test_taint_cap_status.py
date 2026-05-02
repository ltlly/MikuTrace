"""P0-5: taint cap + stopped_at_max status.

When chain hits `max_count` cap, callers need to know it was truncated
(so Web SPA shows "load all" button, CLI emits `stopped_at_max: true`).
Also tests --summary-by-fn aggregation.
"""
import pytest
from tests.synth import build_trace
from viewer.taint import forward_taint, backward_taint
from viewer.index import Index


def _build_long_chain(n: int):
    """Build a synthetic trace with a chain of n register copies x0→x1→x0→x1→..."""
    seq = [('mov x0, #1', {'x0': 1})]
    for i in range(1, n):
        if i % 2 == 1:
            seq.append(('mov x1, x0', {'x1': 1}))
        else:
            seq.append(('mov x0, x1', {'x0': 1}))
    return build_trace(seq)


def test_backward_taint_return_status_natural_end():
    """Chain of 5 defs, max=10: should NOT stop at max (chain naturally ends)."""
    t = build_trace([
        ('mov x0, #5',     {'x0': 5}),     # 0
        ('add x0, x0, #1', {'x0': 6}),     # 1
        ('add x0, x0, #2', {'x0': 8}),     # 2
        ('cmp x0, #3',     {'nzcv': 0x10}),# 3
    ])
    idx = Index(t); idx.build()
    rows, stopped = backward_taint(t, 3, 'x0', max_count=10, index=idx,
                                    return_status=True)
    assert stopped is False, f"chain naturally ended, should not be capped. rows={rows}"


def test_backward_taint_return_status_capped():
    """Long chain, max=3: should report stopped_at_max=True."""
    t = _build_long_chain(20)
    idx = Index(t); idx.build()
    rows, stopped = backward_taint(t, 19, 'x0', max_count=3, index=idx,
                                    return_status=True)
    assert len(rows) == 3
    assert stopped is True, f"len(rows)=3 == max_count, should be capped"


def test_forward_taint_return_status_capped():
    t = _build_long_chain(20)
    idx = Index(t); idx.build()
    rows, stopped = forward_taint(t, 0, 'x0', max_count=3, index=idx,
                                   return_status=True)
    assert len(rows) == 3
    assert stopped is True


def test_forward_taint_return_status_natural_end():
    t = build_trace([
        ('mov x0, #5',     {'x0': 5}),     # 0
        ('mov x1, x0',     {'x1': 5}),     # 1
        ('mov x2, x1',     {'x2': 5}),     # 2
    ])
    idx = Index(t); idx.build()
    rows, stopped = forward_taint(t, 0, 'x0', max_count=100, index=idx,
                                   return_status=True)
    assert stopped is False


def test_stopped_at_max_when_chain_exactly_equals_max():
    """Edge: chain naturally has exactly max_count items.
    Honest reporting: len==max → stopped=True (callers should re-run
    with higher cap to confirm). Predictable > false-'natural-end' which
    silently misses cap edge case."""
    t = build_trace([
        ('mov x0, #5',     {'x0': 5}),       # 0
        ('add x0, x0, #1', {'x0': 6}),       # 1
        ('add x0, x0, #2', {'x0': 8}),       # 2
        ('cmp x0, #3',     {'nzcv': 0x10}),  # 3 (uses x0; doesn't def)
    ])
    idx = Index(t); idx.build()
    rows, stopped = backward_taint(t, 3, 'x0', max_count=3, index=idx,
                                    return_status=True)
    assert len(rows) == 3
    # Existing impl uses `bool(pending) and len>=max` which gives False here
    # (pending exhausted at exactly max=3). After fix → must be True.
    assert stopped is True


def test_backward_taint_default_signature_unchanged():
    """Without return_status, signature returns plain list (backward compat)."""
    t = build_trace([
        ('mov x0, #5', {'x0': 5}),
        ('add x0, x0, #1', {'x0': 6}),
    ])
    idx = Index(t); idx.build()
    rows = backward_taint(t, 1, 'x0', max_count=10, index=idx)
    assert isinstance(rows, list)
    # ensure rows is list of (idx, why) tuples, NOT (rows, status)
    if rows:
        assert isinstance(rows[0], tuple) and isinstance(rows[0][0], int)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
