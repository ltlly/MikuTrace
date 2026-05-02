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


SYSTEM_PROMPT_DECOMPILE_ZH = """\
你是 ARM64 Android trace 反编译助手. 输入是一份结构化 TraceIR,
描述二进制在真机上实际执行的轨迹 — 不是静态分析的猜测.

可利用的 trace 语义:
- 每个 block 的 exec_count 表明哪些路径热, 哪些冷
- 分支计数是真值 (taken=N). 0 not-taken 边在本次执行里就是死分支,
  **不要给 opaque predicate 编造 dead code**
- 循环迭代次数是实测值 (iters=N)
- bl/blr 目标已经解析 (calls 段有 callee_pc + name), **不需要猜间接跳转**
- samples 是首次执行时的寄存器快照, 适合推断类型
- 这是 *一条* 执行路径; 不同输入可能走不同分支

输出要求:
- C 伪代码必须放在 ```c 块里
- 适当引用观测值帮理解 (例如 "循环跑 256 次, key 在 x20 = 0x...")
- 变量名要可读, 从 sample 值 + JNI/libc 上下文推类型
- 不能从 trace 决定的部分 (比如 taken=0 的分支) **明确注释说明**, 不要瞎编
- 不要保留 OLLVM dispatcher 套路 — trace 已经摊平了, 输出**逻辑**控制流即可
- 函数体保持 150 行以内, 除非真的必要

格式:
- 先一段简短的高层语义说明 (3-6 句中文)
- 然后 ```c ... ``` 伪代码块
- 最后简短列出假设 / 未知项 (用中文 bullet)

整个回答用**中文**, 但代码本身用 C 语法 (注释也用中文).
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
                              max_user_chars: int = 200_000,
                              tier: str = "hot",
                              lang: str = "en") -> Bundle:
    """Function-level decompile prompt.

    fn_id: 'F0', ...
    max_user_chars: 截断保护. ≈50K tokens (≈200KB chars), 保护 LLM context.
                    超出会触发 logic 截断 — block list 仅保留 top-N exec_count.
    tier: 默认 'hot' (DEC3-A) — warm 块 stub, 单 fn 普遍 < 60KB. 'full' 全 asm.
    """
    fn = top.fn(fn_id)
    if fn is None:
        raise KeyError(f"fn {fn_id!r} not in TopIR (have {[f.id for f in top.fns]})")

    fn_md = render_func_md(fn, tier=tier)

    # 截断: 若超 max_user_chars, 保留 top-N exec_count blocks.
    if len(fn_md) > max_user_chars:
        truncated_fn = _truncate_fn_by_hot_blocks(fn, target_chars=max_user_chars // 2)
        fn_md = render_func_md(truncated_fn, tier=tier)
        fn_md += (f"\n\n> ⚠️ TRACE TRUNCATED: original had {len(fn.blocks)} blocks; "
                  f"only the top {len(truncated_fn.blocks)} by exec_count shown to "
                  f"fit token budget. Cold blocks dropped.\n")

    # DEC3-D: VM 候选区是 trace-level evidence, 但跟 fn-level 反编译相关
    # (尤其是 LLM 已识别的 VM 函数). 把 VM section prepend 进 user, 让 LLM
    # 看到 hex 后能尝试反汇编.
    vm_context = ""
    if top.vm_candidates:
        vm_context = "## Trace-level evidence: VM Candidates\n\n"
        from .render.markdown import render_summary_md as _rs
        full_summary = _rs(top)
        # 提取 VM Candidates 段
        marker = "## VM Candidates"
        if marker in full_summary:
            start = full_summary.index(marker)
            end = full_summary.find("\n## ", start + 1)
            vm_context = (full_summary[start:end if end >= 0 else None]
                          + "\n\n---\n\n")

    user = (
        f"Decompile this function from its execution trace. Output the "
        f"logical C pseudocode for THIS execution path.\n\n"
        + vm_context
        + fn_md
    )

    sys_prompt = SYSTEM_PROMPT_DECOMPILE_ZH if lang == "zh" else SYSTEM_PROMPT_DECOMPILE
    return Bundle(
        system=sys_prompt,
        user=user,
        fn_id=fn_id,
        estimated_tokens=_est_tokens(sys_prompt) + _est_tokens(user),
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
