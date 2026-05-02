"""LLM bundle / client adapter — P2-DEC2 单元测试.

不打活 API: 全部 mock LlmModel, 验证 prompt 拼装 / 截断 / factory.
"""
from __future__ import annotations
import os
import pytest
from tests.synth import build_trace
from viewer import build_trace_ir
from viewer.decompiler import (
    build_fn_decompile_prompt, build_summary_prompt, Bundle,
    SYSTEM_PROMPT_DECOMPILE, SYSTEM_PROMPT_SUMMARY,
    make_llm_model, list_llm_models, LlmResult,
    ClaudeModel, DeepSeekModel, QwenModel,
)


# ────────────────── prompt assembly ──────────────────

def test_summary_prompt_basic():
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('ret', {}),
    ])
    top = build_trace_ir(t)
    b = build_summary_prompt(top)
    assert b.fn_id is None
    assert b.system == SYSTEM_PROMPT_SUMMARY
    assert "Trace Summary" in b.user
    assert "F0" in b.user
    assert b.estimated_tokens > 0
    assert b.chars() == len(b.system) + len(b.user)
    t.close()


def test_fn_decompile_prompt_basic():
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('add x0, x0, #1', {'x0': 2}),
        ('ret', {}),
    ])
    top = build_trace_ir(t)
    b = build_fn_decompile_prompt(top, "F0")
    assert b.fn_id == "F0"
    assert b.system == SYSTEM_PROMPT_DECOMPILE
    assert "F0" in b.user
    assert "Blocks" in b.user
    assert "ARM64" in b.system
    t.close()


def test_fn_decompile_unknown_fn_raises():
    t = build_trace([('ret', {})])
    top = build_trace_ir(t)
    with pytest.raises(KeyError):
        build_fn_decompile_prompt(top, "F99")
    t.close()


def test_fn_decompile_truncates_huge_fn():
    """合成一个超大 fn (大量块), 触发截断逻辑."""
    # 直接构造 IR (不通过 trace) — 200 个块
    from viewer.decompiler import TopIR, FuncIR, BlockIR
    blocks = [
        BlockIR(id=f"B{i}", pc=0x1000 + i*4, end_pc=0x1000 + i*4,
                insns=1, exec_count=(i % 7), exits=[],
                samples={}, asm="x" * 5000)   # ~5KB asm/块 → 200块=1MB
        for i in range(200)
    ]
    fn = FuncIR(id="F0", name="huge", pc_start=0x1000, pc_end=0x1100,
                entry_idx=0, exit_idx=200, blocks=blocks)
    top = TopIR(records=200, truncated=False, last_insn_is_ret=True, fns=[fn])
    b = build_fn_decompile_prompt(top, "F0", max_user_chars=50_000)
    # 不应炸; 应有 truncated 警告
    assert "TRUNCATED" in b.user
    assert b.chars() < 100_000


def test_fn_decompile_does_not_truncate_when_small():
    t = build_trace([
        ('mov x0, #1', {'x0': 1}),
        ('ret', {}),
    ])
    top = build_trace_ir(t)
    b = build_fn_decompile_prompt(top, "F0", max_user_chars=1_000_000)
    assert "TRUNCATED" not in b.user
    t.close()


def test_bundle_to_dict_roundtrip():
    b = Bundle(system="s", user="u", fn_id="F0", estimated_tokens=10)
    d = b.to_dict()
    assert d["system"] == "s"
    assert d["user"] == "u"
    assert d["fn_id"] == "F0"
    assert d["chars"] == 2


# ────────────────── factory ──────────────────

def test_factory_known_models():
    names = list_llm_models()
    assert "claude" in names
    assert "deepseek" in names
    assert "qwen" in names


def test_factory_unknown_model_raises():
    with pytest.raises(KeyError):
        make_llm_model("gpt-9")


def test_factory_returns_correct_class():
    assert isinstance(make_llm_model("claude"), ClaudeModel)
    assert isinstance(make_llm_model("deepseek"), DeepSeekModel)
    assert isinstance(make_llm_model("qwen"), QwenModel)


def test_factory_case_insensitive():
    assert isinstance(make_llm_model("CLAUDE"), ClaudeModel)
    assert isinstance(make_llm_model(" deepseek "), DeepSeekModel)


# ────────────────── adapter without API key ──────────────────

def test_claude_no_key_returns_error_result(monkeypatch):
    """没设 ANTHROPIC_API_KEY 时, call() 不抛, 返回 LlmResult.error."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    m = ClaudeModel()
    r = m.call("test", system="sys")
    assert isinstance(r, LlmResult)
    assert r.c_code == ""
    assert r.error is not None
    assert "ANTHROPIC_API_KEY" in r.error


def test_deepseek_no_key_returns_error_result(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    m = DeepSeekModel()
    r = m.call("test")
    assert r.error is not None


def test_claude_with_fake_key_no_sdk_returns_clear_error(monkeypatch):
    """有 key 但 anthropic SDK 没装 — 应返回 'SDK 未装' 报错."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
    # 拦截 import anthropic
    import sys
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__
    def fake_import(name, *a, **kw):
        if name == "anthropic":
            raise ImportError("anthropic not installed (test)")
        return real_import(name, *a, **kw)
    monkeypatch.setattr("builtins.__import__", fake_import)
    m = ClaudeModel()
    r = m.call("test")
    # 因为 fake_import 抛 ImportError, 应进 SDK 缺失分支
    assert r.error is not None
    assert "anthropic" in r.error.lower() or "sdk" in r.error.lower()
