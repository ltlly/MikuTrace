"""跑真实 trace（之前抓到的）做端到端 sanity check."""
import pytest, pathlib
from viewer.trace import load
from viewer.disasm import decode
from viewer.index import Index
from viewer.symbols import build_from_trace
from viewer.memshadow import MemShadow
from viewer.cfg import build_cfg
from viewer.taint import forward_taint, backward_taint

TRACE_DIR = pathlib.Path(__file__).parent.parent / "traces" / "doCommand_70102"


@pytest.fixture(scope="module")
def trace():
    if not TRACE_DIR.exists():
        pytest.skip(f"need {TRACE_DIR}")
    return load(TRACE_DIR)


def test_trace_loads(trace):
    assert len(trace) > 0
    assert trace.meta.module is not None
    assert trace.meta.method == 'doCommandNative'


def test_first_record_doCommand(trace):
    """第一条记录应该是 doCommandNative+0x10 (Stalker 起步偏移)"""
    r = trace.record(0)
    base = trace.meta.module.base
    assert r.pc - base == 0x57780, f"expected entry+0x10, got +{r.pc - base:#x}"
    # x2 = cmd id = 70102 = 0x111d6
    assert r.regs[2] == 0x111d6, f"x2 should be 70102, got {r.regs[2]:#x}"


def test_first_insn_disasm(trace):
    r = trace.record(0)
    d = decode(r.pc, r.inst)
    # 实测 #0 是 stp x20, x19, [sp, #0x70]
    assert d.mnemonic == 'stp'


def test_index_builds_quickly(trace):
    import time
    idx = Index(trace)
    t0 = time.time()
    idx.build()
    elapsed = time.time() - t0
    assert elapsed < 5.0, f"index build too slow: {elapsed}s"
    assert len(idx.reg_defs) > 0


def test_symbols_resolve_doCommand(trace):
    sym = build_from_trace(trace)
    fname, foff = sym.lookup(trace.pc(0))
    assert fname == 'doCommandNative', f"expected doCommandNative, got {fname}+{foff:#x}"
    assert foff == 0x10


def test_cfg_blocks_count_reasonable(trace):
    cfg = build_cfg(trace)
    assert 50 < len(cfg.blocks) < 1000, f"blocks={len(cfg.blocks)} out of range"
    # 入口 PC 应该是 trace 第一条
    assert cfg.entry_pc == trace.pc(0)


def test_forward_taint_x2_finds_smull(trace):
    """从 #0 正向 x2 (cmd id) 应能找到几条 smull (魔数除法)"""
    hits = forward_taint(trace, 0, 'x2', max_count=200)
    assert len(hits) > 5
    # 是否有 smull 出现
    has_smull = False
    for i, _ in hits[:30]:
        r = trace.record(i); d = decode(r.pc, r.inst)
        if d.mnemonic.startswith('smull'):
            has_smull = True; break
    assert has_smull, "应该找到 smull (cmd dispatch 用 magic-multiply)"


def test_backward_taint_x8_at_4528_returns_chain(trace):
    """已知 case: 反向 #4528 x8 应该至少 5 条 (跨多个块)"""
    if len(trace) < 4528:
        pytest.skip(f"trace too short: {len(trace)}")
    hits = backward_taint(trace, 4528, 'x8', max_count=100)
    assert len(hits) >= 5, f"expected >=5 hits, got {len(hits)}"
    # 应去重
    idxs = [i for i, _ in hits]
    assert len(idxs) == len(set(idxs)), "结果去重了"
    # 第一条应该是某个早期定义（< 4528）
    assert min(idxs) < 1000, "应该追到很早的定义"


def test_memshadow_has_data(trace):
    mem = MemShadow(trace); mem.build()
    assert len(mem.writes) > 0
    assert len(mem.reads) > 0
    assert len(mem.bytes) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
