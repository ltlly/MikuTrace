"""P1-B: hash_finalize_detect — find SHA-1/MD5 output regions in trace.

Detection: 5 contiguous u32 stores OR 20 contiguous byte stores at
base+0, base+4, ..., base+16 (or base+0..19 byte-by-byte), all completed
within a short trace window (configurable Δidx).
"""
import pytest, struct, tempfile, os
from viewer.trace import Trace, TraceMeta, Module
from viewer.memshadow import MemShadow
from viewer.hashfin import hash_finalize_detect


def _make_trace_with_writes(tmp_path, writes):
    """writes: list of (idx, addr, size, value). Build minimal trace + ext_writes
    file so MemShadow loads them as kind='x'."""
    nopw = 0xd503201f
    base = 0x100000
    n = max((w[0] for w in writes), default=0) + 1
    trace_path = tmp_path / "trace.bin"
    bf = open(trace_path, "wb")
    for i in range(n):
        bf.write(struct.pack("<Q", base + i * 4))
        for _ in range(31): bf.write(struct.pack("<Q", 0))
        bf.write(struct.pack("<Q", 0x7000))
        bf.write(struct.pack("<I", 0))
        bf.write(struct.pack("<I", nopw))
    bf.close()
    # external_writes splat (size always 1 byte). For 20-byte hash output, splat
    # u32 values into 4 byte writes each.
    ef = open(tmp_path / "external_writes.bin", "wb")
    for (idx, addr, size, value) in writes:
        # splat per-byte
        for o in range(size):
            b = (value >> (o * 8)) & 0xff
            ef.write(struct.pack("<QQB", idx, addr + o, b))
    ef.close()
    meta = TraceMeta()
    meta.module = Module("synth.so", base, 0x10000)
    return Trace(trace_path, meta)


def test_hash_finalize_detect_finds_5_u32_stores(tmp_path):
    """5 u32 stores at base, base+4, ..., base+16 within window → hit."""
    base_addr = 0xa000
    # SHA-1 output bytes byte-swapped to BE format
    h_vals = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
    writes = [(i + 10, base_addr + i*4, 4, v) for i, v in enumerate(h_vals)]
    t = _make_trace_with_writes(tmp_path, writes)
    mem = MemShadow(t); mem.build()

    candidates = hash_finalize_detect(t, mem, window=100)
    assert len(candidates) >= 1, f"should find 20-byte SHA-1 output: {candidates}"
    c = candidates[0]
    assert c["addr"] == hex(base_addr)
    assert c["size"] == 20
    assert c["enter_idx"] <= 10
    assert c["exit_idx"] >= 14
    t.close()


def test_hash_finalize_detect_skips_too_long_window(tmp_path):
    """5 stores spaced >> window apart → not a hash finalize."""
    base_addr = 0xb000
    # Same SHA-1 bytes but spread across 1000 idx
    writes = [(i * 200, base_addr + i*4, 4, 0x12345678) for i in range(5)]
    t = _make_trace_with_writes(tmp_path, writes)
    mem = MemShadow(t); mem.build()
    candidates = hash_finalize_detect(t, mem, window=100)
    # Must not yield this 5-write group as a hash output (window too wide)
    for c in candidates:
        assert not (c["addr"] == hex(base_addr) and c["size"] >= 20)
    t.close()


def test_hash_finalize_detect_byte_writes(tmp_path):
    """20 byte-by-byte writes at base+0..19 within window → hit (e.g. emitted by
    byte-swap-and-store loop)."""
    base_addr = 0xc000
    writes = [(i + 5, base_addr + i, 1, (i * 7) & 0xff) for i in range(20)]
    t = _make_trace_with_writes(tmp_path, writes)
    mem = MemShadow(t); mem.build()
    candidates = hash_finalize_detect(t, mem, window=100)
    hits = [c for c in candidates if c["addr"] == hex(base_addr)]
    assert len(hits) >= 1, f"20 byte writes should be detected: {candidates}"
    assert hits[0]["size"] >= 20
    t.close()


def test_hash_finalize_detect_no_writes(tmp_path):
    """Empty trace → no candidates."""
    t = _make_trace_with_writes(tmp_path, [])
    mem = MemShadow(t); mem.build()
    candidates = hash_finalize_detect(t, mem)
    assert candidates == []
    t.close()


def test_hash_finalize_detect_partial_writes_no_hit(tmp_path):
    """Only 3 u32 stores (12 bytes) → not enough for hash output (need ≥16)."""
    base_addr = 0xd000
    writes = [(i + 5, base_addr + i*4, 4, 0xabcd) for i in range(3)]
    t = _make_trace_with_writes(tmp_path, writes)
    mem = MemShadow(t); mem.build()
    candidates = hash_finalize_detect(t, mem)
    hits = [c for c in candidates if c["addr"] == hex(base_addr)]
    assert hits == [], f"only 12 bytes shouldn't trigger: {candidates}"
    t.close()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
