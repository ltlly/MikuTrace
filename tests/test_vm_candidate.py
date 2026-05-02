"""VM 候选区检测 (DEC3-D) 单元测试.

§7.0 普适性自查:
  - 测试合成 trace, 不绑特定 VM 变种
  - 验证: 没 VM 痕迹 → 空; 有 VM 痕迹 → 出 candidate (无具体编码假设)
  - 验证: 输出含 evidence (confidence + reasons + hex) 但 *不* 解码
"""
from __future__ import annotations
import pytest
from tests.synth import build_trace
from viewer import build_trace_ir
from viewer.decompiler import VmCandidate, detect_vm_candidates
from viewer.decompiler.vm_candidate import (
    _find_self_update_loads, _bytecode_range,
)


def test_no_vm_traces_empty():
    """普通直线代码 → 没 VM candidate (ollvmdet 不命中)."""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('add x0, x0, #1', {'x0': 2}),
        ('ret', {}),
    ])
    cands = detect_vm_candidates(t, cfg=None)
    assert cands == []
    t.close()


def test_no_vm_in_top_ir():
    """build_trace_ir 默认开 detect_vm, 普通 trace → vm_candidates 空."""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('ret', {}),
    ])
    top = build_trace_ir(t)
    assert top.vm_candidates == []
    t.close()


def test_detect_vm_disabled():
    """detect_vm=False → 不调用检测, 空."""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('ret', {}),
    ])
    top = build_trace_ir(t, detect_vm=False)
    assert top.vm_candidates == []
    t.close()


def test_self_update_load_finder_filters_non_self_update():
    """ldr without `!` → 不该被 self-update finder 拿到."""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('ldr x1, [x0]', {'x1': 0}),     # 普通 ldr, 没 !
        ('ret', {}),
    ])
    res = _find_self_update_loads(t, 0, 2, min_hits=1)
    # 即使命中, 没 ! 不该出
    for pc, hits, ms, base in res:
        assert "!" in ms
    t.close()


def test_bytecode_range_no_match():
    """读不到任何 PC 命中 → (0, 0)."""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('ret', {}),
    ])
    lo, hi = _bytecode_range(t, reader_pc=0xdeadbeef, base_reg="x9",
                             fn_idx_lo=0, fn_idx_hi=1)
    assert (lo, hi) == (0, 0)
    t.close()


def test_bytecode_range_invalid_reg():
    """base_reg 空字符串 → (0, 0)."""
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('ret', {}),
    ])
    lo, hi = _bytecode_range(t, reader_pc=0x100000, base_reg="",
                             fn_idx_lo=0, fn_idx_hi=1)
    assert (lo, hi) == (0, 0)
    t.close()


def test_vm_candidate_dataclass_defaults():
    vc = VmCandidate(dispatcher_pc=0x1000, confidence=0.5)
    assert vc.dispatcher_pc == 0x1000
    assert vc.confidence == 0.5
    assert vc.reasons == []
    assert vc.hex_dump == []
    assert vc.bytecode_addr == 0


def test_vm_candidate_in_summary_md(monkeypatch):
    """如果检测到 candidate, 应渲染到 summary.md."""
    from viewer.decompiler import VmCandidateIR, render_summary_md, TopIR
    top = TopIR(records=100, truncated=False, last_insn_is_ret=True,
                module_name="x.so", module_base=0x1000, module_size=0x100)
    top.vm_candidates = [VmCandidateIR(
        dispatcher_pc=0x12345,
        confidence=0.7,
        reasons=["indirect br/blr", "ldr [..,lsl #3]"],
        reader_pc=0x1234, reader_inst="ldrh w8, [x9, #2]!",
        reader_hits=42, reader_base_reg="x9",
        bytecode_addr=0x70000, bytecode_len=128,
        hex_dump=["00000000  41 42 43 44  ..."]
    )]
    md = render_summary_md(top)
    assert "VM Candidates" in md
    assert "0x12345" in md
    assert "0.70" in md
    assert "indirect br/blr" in md
    assert "ldrh w8, [x9, #2]!" in md
    assert "0x70000" in md
    assert "128" in md
    assert "41 42 43 44" in md


def test_vm_candidate_render_when_empty():
    """空 candidates → render summary 不爆, 不出 VM section."""
    from viewer.decompiler import render_summary_md, TopIR
    top = TopIR(records=10, truncated=False, last_insn_is_ret=True)
    md = render_summary_md(top)
    assert "VM Candidates" not in md
