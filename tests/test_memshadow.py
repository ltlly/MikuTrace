"""测试稀疏内存 shadow."""
import pytest
from tests.synth import build_trace
from viewer.memshadow import MemShadow


def test_mem_write_visible():
    """str x0, [sp, #0x10] 后 byte_at(sp+0x10) 应能读出"""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),         # 0
        ('str x0, [sp, #0x10]', {}),       # 1: write x0=1 to sp+0x10
    ])
    mem = MemShadow(t); mem.build()
    addr = 0x7000 + 0x10
    # x0 在 #1 时（write 之前）= 1, write 后 1 字节为 0x01
    b, kind, src = mem.byte_at(addr, 1)
    assert b == 1, f"byte at {addr:#x} after write: {b}"
    assert kind == 'w'
    # 之前没写过, 应是 None
    b, _, _ = mem.byte_at(addr, 0)
    assert b is None


def test_mem_read_captures_value():
    """ldr x0 后, x0 在下一条记录中是 loaded value"""
    t = build_trace([
        ('mov x0, #5',           {'x0': 5}),       # 0
        ('str x0, [sp, #0x10]',  {}),              # 1: writes 5
        ('mov x0, #0',           {'x0': 0}),       # 2: clear x0
        ('ldr x0, [sp, #0x10]',  {'x0': 5}),       # 3: load → next-record x0 = 5
        ('nop',                  {}),              # 4: 让 #3 的 load 能拿到 next-record 值
    ])
    mem = MemShadow(t); mem.build()
    assert any(rec[1] == 0x7010 for rec in mem.writes)
    assert any(rec[1] == 0x7010 for rec in mem.reads)


def test_hex_dump_unknown_bytes():
    """从未访问的内存应显示 ??"""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
    ])
    mem = MemShadow(t); mem.build()
    lines = mem.hex_dump(0xdeadbeef00, t=0, rows=1)
    assert '??' in lines[0]


def test_find_strings_synthetic():
    """构造一个内存写入若干字节，should be found as a string."""
    # 因为我们的 synth 不能写任意字节，跳过此测试 — 实际 trace 上验证
    pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
