"""LLM prompt bundle 拼装 — 把 TraceIR 切成 LLM 能消化的单次请求.

设计 §7.4 token 预算:
  trace summary  2-5KB   必含
  fn full        5-30KB  必含 (当前关注的)
  其他 fn        1-3KB   summary 级即可
  block raw      1-5KB   tool-use 按需

本文件只做"单次请求该塞什么". 不做 tool-use 协议 (那是 stage 3+ 时
做完整 agent 接口才需要).

公开入口:
  build_fn_decompile_prompt(top, fn_id, model_hint=None) -> Bundle
  build_summary_prompt(top, model_hint=None) -> Bundle

Bundle.system + Bundle.user 直接喂 LlmModel.call().
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from .ir import TopIR, FuncIR
from .render import render_summary_md, render_func_md


SYSTEM_PROMPT_DECOMPILE = """\
You are a reverse engineering assistant specialized in ARM64 Android trace
decompilation. You receive a structured TraceIR describing what the binary
ACTUALLY EXECUTED on a real device — not what static analysis guesses.

Key trace semantics you can exploit:
- exec_count on each block tells you which paths were hot vs cold.
- Branch counts are observed (taken=N). 0 not-taken edges are dead in this
  run; do NOT generate dead code for opaque predicates.
- Loop iter counts are observed (iters=N).
- bl/blr targets are concretely resolved (callee_pc + name in calls section).
  No indirect-jump guessing needed.
- samples are first-execution register snapshots; useful for inferring types.
- This is ONE execution path; alternative inputs may take different branches.

Your output:
- Pure C pseudocode wrapped in a single ```c block.
- Reference observed values where they help understanding (e.g.
  "the loop runs 256 times; key is loaded into x20 = 0x...").
- Use readable identifier names; infer types from sample values + JNI/libc
  context where present.
- Where the trace does NOT determine semantics (e.g. taken=0 branch),
  comment that explicitly rather than fabricating logic.
- Do NOT include OLLVM dispatcher boilerplate; the trace already shows the
  flattened path — output the LOGICAL control flow, not the dispatcher.
- Keep the function body under ~150 lines unless absolutely necessary.

Format expectation:
- A short prose paragraph of high-level semantics (3-6 sentences)
- Then ```c ... ``` with the pseudocode
- Then a brief note section listing assumptions / unknowns
"""


SYSTEM_PROMPT_SUMMARY = """\
You are an ARM64 Android trace triage assistant. You receive a high-level
TraceIR summary listing function calls observed in one execution. Your job
is to identify which functions are likely the most interesting for a
reverse engineer to focus on (e.g. crypto, JNI surface, hot paths).

Output format: bullet list. Each bullet:
  - <fn_id> `<name>` — one sentence why interesting

Pick at most 5 candidates. Be concrete; do not list every fn.
"""


@dataclass
class Bundle:
    """A single LLM request's wire content."""
    system: str
    user: str
    fn_id: Optional[str] = None     # None = summary-level
    estimated_tokens: int = 0       # rough chars/4

    def chars(self) -> int:
        return len(self.system) + len(self.user)

    def to_dict(self) -> dict:
        return {
            "system": self.system, "user": self.user,
            "fn_id": self.fn_id,
            "estimated_tokens": self.estimated_tokens,
            "chars": self.chars(),
        }


def _est_tokens(s: str) -> int:
    """Cheap token estimate: ~4 chars per token (英文 markdown)."""
    return max(1, len(s) // 4)


def build_summary_prompt(top: TopIR) -> Bundle:
    """Triage-level prompt: 哪些 fn 值得反编译."""
    md = render_summary_md(top)
    user = (
        "Below is the trace summary. Pick the top-5 functions worth "
        "reverse-engineering and explain why in one sentence each.\n\n"
        + md
    )
    return Bundle(
        system=SYSTEM_PROMPT_SUMMARY,
        user=user,
        fn_id=None,
        estimated_tokens=_est_tokens(SYSTEM_PROMPT_SUMMARY) + _est_tokens(user),
    )


def build_fn_decompile_prompt(top: TopIR, fn_id: str,
                              max_user_chars: int = 200_000) -> Bundle:
    """Function-level decompile prompt.

    fn_id: 'F0', ...
    max_user_chars: 截断保护. ≈50K tokens (≈200KB chars), 保护 LLM context.
                    超出会触发 logic 截断 — block list 仅保留 top-N exec_count.
    """
    fn = top.fn(fn_id)
    if fn is None:
        raise KeyError(f"fn {fn_id!r} not in TopIR (have {[f.id for f in top.fns]})")

    fn_md = render_func_md(fn)

    # 截断: 若超 max_user_chars, 保留 top-N exec_count blocks.
    if len(fn_md) > max_user_chars:
        truncated_fn = _truncate_fn_by_hot_blocks(fn, target_chars=max_user_chars // 2)
        fn_md = render_func_md(truncated_fn)
        fn_md += (f"\n\n> ⚠️ TRACE TRUNCATED: original had {len(fn.blocks)} blocks; "
                  f"only the top {len(truncated_fn.blocks)} by exec_count shown to "
                  f"fit token budget. Cold blocks dropped.\n")

    user = (
        f"Decompile this function from its execution trace. Output the "
        f"logical C pseudocode for THIS execution path.\n\n"
        + fn_md
    )

    return Bundle(
        system=SYSTEM_PROMPT_DECOMPILE,
        user=user,
        fn_id=fn_id,
        estimated_tokens=_est_tokens(SYSTEM_PROMPT_DECOMPILE) + _est_tokens(user),
    )


def _truncate_fn_by_hot_blocks(fn: FuncIR, target_chars: int) -> FuncIR:
    """返回 fn 副本, 保留 top-N exec_count 块直到总 markdown 长度接近 target."""
    from copy import copy
    sorted_blocks = sorted(fn.blocks, key=lambda b: -b.exec_count)
    kept = []
    accum = 0
    for b in sorted_blocks:
        # 估每块 markdown 长度: asm + samples + edges
        approx = len(b.asm) + 200 + 60 * len(b.exits)
        if accum + approx > target_chars and kept:
            break
        kept.append(b)
        accum += approx
    # 按 PC 顺序排回去, 保持可读性
    kept.sort(key=lambda b: b.pc)
    new = copy(fn)
    new.blocks = kept
    return new
