"""viewer.index.Index 补丁测试: build idempotency, def_chain depth limit, 空 trace."""
import pytest
from tests.synth import build_trace
from viewer.index import Index


def test_index_build_idempotent():
    """重复 build 不应重复 append."""
    t = build_trace([
        ('mov x0, #1',  {'x0': 1}),
        ('add x0, x0, #1', {'x0': 2}),
        ('ret', {}),
    ])
    idx = Index(t)
    idx.build()
    n1 = sum(len(v) for v in idx.reg_defs.values())
    idx.build()   # 第二次
    n2 = sum(len(v) for v in idx.reg_defs.values())
    assert n1 == n2, f"重复 build 后 reg_defs 翻倍: {n1} → {n2}"


def test_index_empty_trace():
    """0 长度 trace 不应崩."""
    t = build_trace([])
    idx = Index(t)
    idx.build()
    assert idx.built is True
    assert len(idx.reg_defs) == 0


def test_index_collects_mem_writes_via_str():
    """str x0, [sp, #0x10] 应被记到 mem_writes."""
    t = build_trace([
        ('mov x0, #0x1234', {'x0': 0x1234}),
        ('str x0, [sp, #0x10]', {}),
        ('ret', {}),
    ])
    idx = Index(t)
    idx.build()
    # 至少有一条 write
    assert len(idx.mem_writes) >= 1
    # 找到 str 那条
    found = [w for w in idx.mem_writes if w[1] == 0x7000 + 0x10]
    assert found, f"str 应记到 0x7010 (sp+0x10), got writes: {idx.mem_writes}"


def test_index_collects_stp_pair_as_two_writes():
    """stp x0, x1, [sp, #-16]! 应记 2 条 mem_writes (16 字节分两段)."""
    t = build_trace([
        ('mov x0, #0xaa', {'x0': 0xaa}),
        ('mov x1, #0xbb', {'x1': 0xbb}),
        ('stp x0, x1, [sp, #-16]!', {}),
        ('ret', {}),
    ])
    idx = Index(t)
    idx.build()
    stp_writes = [w for w in idx.mem_writes if w[0] == 2]   # idx=2 是 stp
    assert len(stp_writes) == 2, (
        f"stp 应分 2 个 write, got {len(stp_writes)}: {stp_writes}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
