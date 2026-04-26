"""测试 def-use 索引."""
import pytest
from tests.synth import build_trace
from viewer.index import Index


def test_reg_defs_uses_basic():
    t = build_trace([
        ('mov x0, #1',     {'x0': 1}),       # 0: def x0
        ('mov x1, x0',     {'x1': 1}),       # 1: def x1, use x0
        ('add x0, x0, #1', {'x0': 2}),       # 2: def x0, use x0
        ('cmp x0, x1',     {'nzcv': 0x40}),  # 3: use x0+x1, def nzcv
    ])
    idx = Index(t); idx.build()
    assert sorted(idx.reg_defs['x0']) == [0, 2]
    assert sorted(idx.reg_defs['x1']) == [1]
    assert sorted(idx.reg_uses['x0']) == [1, 2, 3]
    assert sorted(idx.reg_uses['x1']) == [3]


def test_def_chain():
    """def_chain(idx) 返回该指令每个 use 寄存器的最近 def"""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),    # 0
        ('mov x1, x0', {'x1': 1}),    # 1: uses x0 → def at 0
        ('mov x0, #2', {'x0': 2}),    # 2: defs x0
        ('mov x2, x0', {'x2': 2}),    # 3: uses x0 → def at 2 (latest)
    ])
    idx = Index(t); idx.build()
    chain = idx.def_chain(3)
    # x0 should map to #2 (latest def before #3)
    regs = {reg: defi for reg, defi in chain}
    assert regs.get('x0') == 2, f"def chain[3].x0 should be 2: {chain}"
    chain1 = idx.def_chain(1)
    regs1 = {reg: defi for reg, defi in chain1}
    assert regs1.get('x0') == 0


def test_use_chain():
    """use_chain(idx): 该指令 def 的寄存器的下一次 use"""
    t = build_trace([
        ('mov x0, #1',  {'x0': 1}),   # 0: def x0
        ('mov x1, x0',  {'x1': 1}),   # 1: uses x0
        ('mov x0, #2',  {'x0': 2}),   # 2: defs x0 (kills #0's def)
        ('mov x2, x0',  {'x2': 2}),   # 3: uses x0 (this is #2's use, not #0's)
    ])
    idx = Index(t); idx.build()
    chain0 = idx.use_chain(0)   # x0 def at #0, next use before next def?
    # next def of x0 is #2; use before #2 is #1
    regs0 = {r: u for r, u in chain0}
    assert regs0.get('x0') == 1, f"use chain[0].x0 should be 1: {chain0}"
    chain2 = idx.use_chain(2)
    regs2 = {r: u for r, u in chain2}
    assert regs2.get('x0') == 3, f"use chain[2].x0 should be 3: {chain2}"


def test_mem_writes_reads():
    t = build_trace([
        ('str x0, [sp, #0x10]', {}),
        ('ldr x0, [sp, #0x10]', {'x0': 0}),
    ])
    idx = Index(t); idx.build()
    assert len(idx.mem_writes) == 1
    assert len(idx.mem_reads) == 1
    # write addr = sp + 0x10 = 0x7000 + 0x10 = 0x7010
    iw, addr_w, sz_w, _ = idx.mem_writes[0]
    assert iw == 0
    assert addr_w == 0x7010
    iw, addr_r, sz_r, _ = idx.mem_reads[0]
    assert iw == 1
    assert addr_r == 0x7010


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
