"""P1-D: ollvm_detect_vm — heuristic VM dispatcher detection.

Patterns scored:
  1. High function-entry count (function executed many times)
  2. Indirect br / blr (br xN / blr xN, not bl <imm>)
  3. ldr xN, [base, idx, lsl #3]   ← jump table indexing
  4. Self-incrementing pre-load: ldrh wN, [base, #imm]! / ldrb / etc.

Output: candidates list, ranked by confidence (0.0 ~ 1.0).
"""
import pytest
from tests.synth import build_trace
from viewer.ollvmdet import ollvm_detect_vm


def test_ollvm_detect_high_entry_count_with_indirect_br():
    """Function entered many times + indirect br → high confidence."""
    seq = []
    # Simulate dispatcher loop: 50 iterations of
    #   ldr x9, [x10, x11, lsl #3]  (table load)
    #   br x9                        (indirect jump)
    for _ in range(50):
        seq.append(('ldr x9, [x10, x11, lsl #3]', {'x9': 0x100000}))
        seq.append(('br x9', {}))
    t = build_trace(seq)
    candidates = ollvm_detect_vm(t)
    assert isinstance(candidates, list)
    # Should find a candidate with confidence > 0.3
    assert any(c["confidence"] >= 0.3 for c in candidates), \
        f"high-entry indirect br should score: {candidates}"
    t.close()


def test_ollvm_detect_no_pattern_yields_empty():
    """Plain trace without indirect branches → empty or low-confidence list."""
    seq = [('mov x0, #1', {'x0': 1}),
           ('mov x1, x0', {'x1': 1}),
           ('add x0, x0, #1', {'x0': 2}),
           ('ret', {})]
    t = build_trace(seq)
    candidates = ollvm_detect_vm(t)
    # Either empty or only low-confidence
    for c in candidates:
        assert c["confidence"] < 0.5, \
            f"plain code should not look like VM: {c}"
    t.close()


def test_ollvm_detect_returns_reason_and_hint():
    """Each candidate must include human-readable reason + hint fields."""
    seq = []
    for _ in range(50):
        seq.append(('ldr x9, [x10, x11, lsl #3]', {'x9': 0x100000}))
        seq.append(('br x9', {}))
    t = build_trace(seq)
    candidates = ollvm_detect_vm(t)
    if candidates:
        c = candidates[0]
        assert "reason" in c
        assert "hint" in c
        assert "confidence" in c
        assert "entry_count" in c
    t.close()


def test_ollvm_detect_min_entry_count_filter():
    """Functions with low entry count → skipped (under min_entries)."""
    seq = [('ldr x9, [x10, x11, lsl #3]', {'x9': 0x100000}),
           ('br x9', {})]
    # only 1 iteration
    t = build_trace(seq)
    candidates = ollvm_detect_vm(t, min_entries=10)
    assert candidates == [], f"1-entry should not score: {candidates}"
    t.close()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
