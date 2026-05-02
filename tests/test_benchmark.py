"""DEC4 多模型 benchmark — 单元测试 (mock LLM, 不打活 API).

§7.0 自查:
  - 不绑定具体 model name (factory 已普适)
  - metric 全部从 IR 派生 (anchor / vm / loop), 不假设 SDK
"""
from __future__ import annotations
import pytest
from tests.synth import build_trace
from viewer import build_trace_ir
from viewer.decompiler import BenchResult, render_compare_md
from viewer.decompiler.benchmark import _score_output, run_bench_one


def test_score_output_empty_text():
    """空 text → 全 0/false."""
    from viewer.decompiler import TopIR
    top = TopIR(records=10, truncated=False, last_insn_is_ret=True)
    s = _score_output("", top, "F0")
    assert s["has_c_code"] is False
    assert s["anchor_hit"] == {}
    assert s["vm_hit"] == 0
    assert s["loop_hit"] == 0


def test_score_output_detects_c_block():
    from viewer.decompiler import TopIR
    top = TopIR(records=10, truncated=False, last_insn_is_ret=True)
    text = "Some prose\n\n```c\nvoid f() {}\n```\n"
    s = _score_output(text, top, "F0")
    assert s["has_c_code"] is True


def test_score_output_anchor_hit():
    from viewer.decompiler import TopIR, FuncIR, TypeAnchorIR
    fn = FuncIR(id="F0", name="t", pc_start=0x1000, pc_end=0x2000,
                entry_idx=0, exit_idx=10, blocks=[],
                type_anchors=[
                    TypeAnchorIR(idx=1, callee_pc=0x1000, callee_name="cmd_init"),
                    TypeAnchorIR(idx=2, callee_pc=0x2000, callee_name="lock_acquire"),
                ])
    top = TopIR(records=10, truncated=False, last_insn_is_ret=True, fns=[fn])
    text = "calls cmd_init(ctx); then lock_acquire(&m); cmd_init again."
    s = _score_output(text, top, "F0")
    # cmd_init 出现 2 次, lock_acquire 1 次
    assert s["anchor_hit"]["cmd_init"] == 2
    assert s["anchor_hit"]["lock_acquire"] == 1


def test_score_output_vm_keywords_only_when_candidates():
    """vm_hit 仅在 IR 有 vm_candidates 时计数."""
    from viewer.decompiler import TopIR, VmCandidateIR
    text = "VM dispatcher with handler bytecode opcode interpreter"
    # 没 vm_candidates → vm_hit = 0
    top = TopIR(records=10, truncated=False, last_insn_is_ret=True)
    s = _score_output(text, top, "F0")
    assert s["vm_hit"] == 0
    # 有 vm_candidates → 累计
    top.vm_candidates = [VmCandidateIR(dispatcher_pc=0x1000, confidence=1.0)]
    s = _score_output(text, top, "F0")
    assert s["vm_hit"] >= 5   # 多个关键词


def test_score_output_loop_keywords_only_when_loops():
    from viewer.decompiler import TopIR, FuncIR, LoopIR
    text = "loop iterates 256 times, while x > 0, for (i=0; ...)"
    fn_no_loop = FuncIR(id="F0", name="t", pc_start=0, pc_end=0,
                        entry_idx=0, exit_idx=0, blocks=[], loops=[])
    top = TopIR(records=10, truncated=False, last_insn_is_ret=True, fns=[fn_no_loop])
    s = _score_output(text, top, "F0")
    assert s["loop_hit"] == 0
    # 有 loop → 计数
    fn_with_loop = FuncIR(id="F0", name="t", pc_start=0, pc_end=0,
                          entry_idx=0, exit_idx=0, blocks=[],
                          loops=[LoopIR(id="L0", header="B0", body=["B0"], iters=10)])
    top.fns = [fn_with_loop]
    s = _score_output(text, top, "F0")
    assert s["loop_hit"] >= 3


def test_run_bench_one_unknown_model_returns_error_result():
    t = build_trace([('mov x0, #1', {'x0': 1}), ('ret', {})])
    top = build_trace_ir(t)
    r = run_bench_one(top, "F0", "nonexistent-model")
    assert r.ok is False
    assert "nonexistent-model" in r.error or "unknown" in r.error.lower()
    t.close()


def test_run_bench_one_unknown_fn_returns_error():
    t = build_trace([('mov x0, #1', {'x0': 1}), ('ret', {})])
    top = build_trace_ir(t)
    r = run_bench_one(top, "F999", "claude")
    assert r.ok is False
    t.close()


def test_render_compare_md_empty():
    md = render_compare_md([])
    assert "no results" in md.lower()


def test_render_compare_md_basic():
    """有 ok + error 两种结果, 表格生成."""
    results = [
        BenchResult(model="claude", fn_id="F0", ok=True, latency_ms=1500,
                    in_tokens=1000, out_tokens=500, out_chars=2000,
                    has_c_code=True, anchor_hit={"cmd_init": 2, "lock": 1},
                    vm_hit=5, loop_hit=3, output_text="..."),
        BenchResult(model="deepseek", fn_id="F0", ok=False,
                    error="DEEPSEEK_API_KEY 未设"),
    ]
    md = render_compare_md(results)
    assert "Benchmark" in md
    assert "F0" in md
    assert "claude" in md
    assert "deepseek" in md
    assert "1500ms" in md
    assert "1000→500" in md
    assert "Errors" in md
    assert "DEEPSEEK_API_KEY" in md


def test_run_bench_with_mock_model(monkeypatch):
    """mock LlmModel 验证 run_bench_one 流程."""
    from viewer.decompiler.llm_client import LlmResult
    from viewer.decompiler import benchmark as bench_mod

    class MockModel:
        name = "mock"
        model_id = "mock-1"
        def call(self, prompt, system="", max_tokens=4096):
            return LlmResult(
                c_code="```c\nvoid foo() {}\n```",
                model="mock-1", prompt_tokens=100, output_tokens=50,
                latency_ms=200,
            )
    # patch make_llm_model 让它返回 MockModel
    def fake_make(name):
        if name == "mock": return MockModel()
        raise KeyError(name)
    monkeypatch.setattr("viewer.decompiler.llm_client.make_llm_model", fake_make)
    monkeypatch.setattr("viewer.decompiler.benchmark.make_llm_model", fake_make,
                        raising=False)
    # benchmark 内部 import via .llm_client.make_llm_model — 也要 patch
    import viewer.decompiler.llm_client as lc
    monkeypatch.setattr(lc, "make_llm_model", fake_make)

    t = build_trace([('mov x0, #1', {'x0': 1}), ('ret', {})])
    top = build_trace_ir(t)
    r = run_bench_one(top, "F0", "mock")
    assert r.ok is True
    assert r.latency_ms == 200
    assert r.in_tokens == 100
    assert r.out_tokens == 50
    assert r.has_c_code is True
    t.close()
