"""LLM 客户端 adapter — Claude / DeepSeek / Qwen 三家.

设计 §7.5: 多模型 adapter, 统一 messages-style API. SDK 全 lazy import
(anthropic / openai 不进 hard deps), 缺包时清晰报错.

API key 来源:
  Claude:   ANTHROPIC_API_KEY
  DeepSeek: DEEPSEEK_API_KEY
  Qwen:     DASHSCOPE_API_KEY 或 QWEN_BASE_URL (本地 vLLM 兼容 OpenAI API)

调用约定: 所有 model 走 messages = [{role: "user", content: ...}],
system 单独传, max_tokens 由调用方指定 (默认 4096 — Sonnet 一次出 ~3K
token C 代码够了).

返回 LlmResult: 含 c_code / 用量 / latency / raw — 用量可入 cost 帐.
"""
from __future__ import annotations
import os, time, json
from dataclasses import dataclass, field
from typing import Protocol, Optional


@dataclass
class LlmResult:
    c_code: str                    # LLM 输出文本 (典型: 一个 ```c 块)
    model: str                     # model 实际 ID
    prompt_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    raw: dict = field(default_factory=dict)
    error: Optional[str] = None    # 非 None 表示请求失败


class LlmModel(Protocol):
    """All adapters expose this. call() must be synchronous + safe to retry."""
    name: str
    model_id: str

    def call(self, prompt: str, system: str = "",
             max_tokens: int = 4096) -> LlmResult: ...


# ─────────────────────── Claude (Anthropic) ───────────────────────────

class ClaudeModel:
    """Anthropic Claude. 默认 sonnet-4-6 (设计 §7.5)."""
    name = "claude"

    def __init__(self, model_id: str = "claude-sonnet-4-6",
                 api_key: Optional[str] = None):
        self.model_id = model_id
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")

    def call(self, prompt: str, system: str = "",
             max_tokens: int = 4096) -> LlmResult:
        if not self.api_key:
            return LlmResult(c_code="", model=self.model_id,
                             error="ANTHROPIC_API_KEY 未设")
        try:
            import anthropic
        except ImportError:
            return LlmResult(c_code="", model=self.model_id,
                             error="anthropic SDK 未装. pip install anthropic")
        client = anthropic.Anthropic(api_key=self.api_key)
        t0 = time.monotonic()
        try:
            resp = client.messages.create(
                model=self.model_id,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as e:
            return LlmResult(c_code="", model=self.model_id,
                             error=f"anthropic API: {e}")
        latency = int((time.monotonic() - t0) * 1000)
        # resp.content 是 list[ContentBlock], text block 取 .text
        text = "".join(b.text for b in resp.content if getattr(b, "text", None))
        return LlmResult(
            c_code=text,
            model=self.model_id,
            prompt_tokens=getattr(resp.usage, "input_tokens", 0),
            output_tokens=getattr(resp.usage, "output_tokens", 0),
            latency_ms=latency,
            raw={"id": resp.id, "stop_reason": resp.stop_reason},
        )


# ─────────────────────── OpenAI-compatible base ───────────────────────

class _OpenAICompatModel:
    """DeepSeek / Qwen / 本地 vLLM 都 OpenAI-compatible — 共用一套 client."""
    name = "openai-compat"

    def __init__(self, model_id: str, api_key: Optional[str],
                 base_url: Optional[str]):
        self.model_id = model_id
        self.api_key = api_key
        self.base_url = base_url

    def call(self, prompt: str, system: str = "",
             max_tokens: int = 4096) -> LlmResult:
        if not self.api_key and not (self.base_url and "localhost" in self.base_url):
            return LlmResult(c_code="", model=self.model_id,
                             error=f"{self.name} API key 未设")
        try:
            from openai import OpenAI
        except ImportError:
            return LlmResult(c_code="", model=self.model_id,
                             error="openai SDK 未装. pip install openai")
        client = OpenAI(api_key=self.api_key or "EMPTY",
                        base_url=self.base_url)
        msgs: list = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        t0 = time.monotonic()
        try:
            resp = client.chat.completions.create(
                model=self.model_id,
                max_tokens=max_tokens,
                messages=msgs,
            )
        except Exception as e:
            return LlmResult(c_code="", model=self.model_id,
                             error=f"{self.name} API: {e}")
        latency = int((time.monotonic() - t0) * 1000)
        text = resp.choices[0].message.content or ""
        return LlmResult(
            c_code=text,
            model=self.model_id,
            prompt_tokens=getattr(resp.usage, "prompt_tokens", 0),
            output_tokens=getattr(resp.usage, "completion_tokens", 0),
            latency_ms=latency,
            raw={"id": resp.id, "finish_reason": resp.choices[0].finish_reason},
        )


class DeepSeekModel(_OpenAICompatModel):
    """DeepSeek API. 默认 reasoner (R1) — Deconstructing Obfuscation 2025
    实测 ARM 反混淆最强 (semantic 72.31%)."""
    name = "deepseek"

    def __init__(self, model_id: str = "deepseek-reasoner",
                 api_key: Optional[str] = None):
        super().__init__(
            model_id=model_id,
            api_key=api_key or os.environ.get("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
        )


class QwenModel(_OpenAICompatModel):
    """Qwen — 走 dashscope (云) 或本地 vLLM (设 QWEN_BASE_URL).

    本地: QWEN_BASE_URL=http://localhost:8000/v1
    云:   DASHSCOPE_API_KEY=..., 默认 base_url 用 dashscope OpenAI-compat
    """
    name = "qwen"

    def __init__(self, model_id: str = "qwen2.5-coder-32b-instruct",
                 api_key: Optional[str] = None,
                 base_url: Optional[str] = None):
        api_key = api_key or os.environ.get("DASHSCOPE_API_KEY")
        base_url = (base_url
                    or os.environ.get("QWEN_BASE_URL")
                    or "https://dashscope.aliyuncs.com/compatible-mode/v1")
        super().__init__(model_id=model_id, api_key=api_key, base_url=base_url)


# ─────────────────────── Factory ───────────────────────

_REGISTRY = {
    "claude": ClaudeModel,
    "claude-sonnet-4-6": ClaudeModel,
    "claude-opus-4-7": lambda: ClaudeModel(model_id="claude-opus-4-7"),
    "deepseek": DeepSeekModel,
    "deepseek-r1": DeepSeekModel,
    "deepseek-reasoner": DeepSeekModel,
    "deepseek-chat": lambda: DeepSeekModel(model_id="deepseek-chat"),
    "qwen": QwenModel,
    "qwen-coder": QwenModel,
}


def make_llm_model(name: str) -> LlmModel:
    """Resolve name → LlmModel instance. KeyError if unknown."""
    name = name.lower().strip()
    if name not in _REGISTRY:
        raise KeyError(
            f"unknown model: {name!r}. Known: {sorted(_REGISTRY)}"
        )
    factory = _REGISTRY[name]
    return factory()


def list_llm_models() -> list[str]:
    return sorted(_REGISTRY)
