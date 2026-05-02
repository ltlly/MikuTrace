"""多模型反编译 benchmark — DEC4.

§7.0 严守: metric 全部从 IR 自身派生 (anchor name / VM keyword / loop token),
不绑定具体 SDK. 用户换 SDK 换 spec, metric 自动跟着变.

输出:
  - 每模型一份 LLM 输出: decompile/llm_results/<model>_<fn>.md
  - 一份对比表: decompile/bench/<fn>_compare.md (model × metric)

Metric (普适, 不假设变种):
  1. ok          — LLM 调用成功 (无 error)
  2. latency_ms  — 实测 latency
  3. in_tokens   — prompt tokens
  4. out_tokens  — output tokens
  5. out_chars   — output 文本长度
  6. has_c_code  — 含 ```c block (LLM 真出了 C, 不是空话)
  7. anchor_hit  — 输出含 type anchor name 的比例 (DEC3-B 注入的语义名)
  8. vm_hit      — 输出含 vm/dispatcher/handler/opcode/bytecode 的比例
                   (仅当 IR 有 vm_candidates)
  9. loop_hit    — 输出含 loop/iter/while/for 的比例 (仅当 IR 有 loops)
"""
from __future__ import annotations
import re
import time
from dataclasses import dataclass, field
from typing import Optional


VM_KEYWORDS = ("vm", "virtual machine", "dispatcher", "handler",
               "opcode", "bytecode", "vm_pc", "interpreter")
LOOP_KEYWORDS = ("loop", "iterat", "while", "for (", "for(")


@dataclass
class BenchResult:
    model: str                       # 'claude' / 'mimo' / ...
    fn_id: str
    ok: bool
    error: str = ""
    latency_ms: int = 0
    in_tokens: int = 0
    out_tokens: int = 0
    out_chars: int = 0
    has_c_code: bool = False
    # 关键词命中: dict[category, count]
    anchor_hit: dict[str, int] = field(default_factory=dict)
    vm_hit: int = 0
    loop_hit: int = 0
    output_text: str = ""           # 完整文本 (用于落盘)


def _score_output(text: str, top, fn_id: str) -> dict:
    """从 LLM 输出文本派生普适 metric. 不假设具体 SDK."""
    if not text:
        return {"has_c_code": False, "anchor_hit": {}, "vm_hit": 0, "loop_hit": 0}
    low = text.lower()
    has_c = bool(re.search(r"```c\b", text))
    # anchor name hit (case-sensitive 因为 sub_X 这种)
    anchor_hits: dict[str, int] = {}
    fn = top.fn(fn_id)
    if fn is not None:
        seen_names: set[str] = set()
        for a in fn.type_anchors:
            if a.callee_name:
                seen_names.add(a.callee_name)
        for nm in seen_names:
            anchor_hits[nm] = text.count(nm)
    # vm keyword
    vm_count = sum(low.count(kw) for kw in VM_KEYWORDS) if top.vm_candidates else 0
    # loop keyword
    has_loops = fn is not None and len(fn.loops) > 0
    loop_count = sum(low.count(kw) for kw in LOOP_KEYWORDS) if has_loops else 0
    return {
        "has_c_code": has_c,
        "anchor_hit": anchor_hits,
        "vm_hit": vm_count,
        "loop_hit": loop_count,
    }


def run_bench_one(top, fn_id: str, model_name: str,
                  max_tokens: int = 4096) -> BenchResult:
    """跑一个 model. 返回 BenchResult."""
    from .llm_bundle import build_fn_decompile_prompt
    from .llm_client import make_llm_model
    try:
        bundle = build_fn_decompile_prompt(top, fn_id)
    except KeyError as e:
        return BenchResult(model=model_name, fn_id=fn_id, ok=False, error=str(e))
    try:
        m = make_llm_model(model_name)
    except KeyError as e:
        return BenchResult(model=model_name, fn_id=fn_id, ok=False, error=str(e))
    res = m.call(bundle.user, system=bundle.system, max_tokens=max_tokens)
    if res.error:
        return BenchResult(
            model=model_name, fn_id=fn_id, ok=False, error=res.error,
            latency_ms=res.latency_ms,
        )
    metrics = _score_output(res.c_code, top, fn_id)
    return BenchResult(
        model=model_name, fn_id=fn_id, ok=True,
        latency_ms=res.latency_ms,
        in_tokens=res.prompt_tokens,
        out_tokens=res.output_tokens,
        out_chars=len(res.c_code),
        has_c_code=metrics["has_c_code"],
        anchor_hit=metrics["anchor_hit"],
        vm_hit=metrics["vm_hit"],
        loop_hit=metrics["loop_hit"],
        output_text=res.c_code,
    )


def run_bench(top, fn_id: str, models: list[str],
              max_tokens: int = 4096,
              progress_callback=None) -> list[BenchResult]:
    """跑多个 model, 顺序 (rate-limit-friendly).

    progress_callback(idx, total, model_name) — 可选, 给 CLI 实时打印.
    """
    results: list[BenchResult] = []
    for i, m in enumerate(models):
        if progress_callback:
            progress_callback(i, len(models), m)
        r = run_bench_one(top, fn_id, m, max_tokens=max_tokens)
        results.append(r)
    return results


def render_compare_md(results: list[BenchResult]) -> str:
    """生成对比 markdown 表."""
    if not results:
        return "# Benchmark — no results\n"
    fn_id = results[0].fn_id
    lines = [
        f"# Benchmark — fn `{fn_id}`",
        "",
        f"{len(results)} models compared. ✓ = success, ✗ = error.",
        "",
        "| model | ok | latency | in/out tok | chars | C? | anchors | vm | loop |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        ok = "✓" if r.ok else "✗"
        lat = f"{r.latency_ms}ms" if r.latency_ms else "—"
        toks = f"{r.in_tokens}→{r.out_tokens}" if r.ok else "—"
        chars = str(r.out_chars) if r.ok else "—"
        c = "✓" if r.has_c_code else ("✗" if r.ok else "—")
        # anchor hit: 总命中数 / 总 anchor 名数 (覆盖率)
        anchor_total_hits = sum(r.anchor_hit.values())
        anchor_uniq = sum(1 for v in r.anchor_hit.values() if v > 0)
        anchor_str = (f"{anchor_uniq}/{len(r.anchor_hit)} "
                      f"({anchor_total_hits} hits)" if r.anchor_hit else "—")
        vm_str = str(r.vm_hit) if r.vm_hit else "—"
        loop_str = str(r.loop_hit) if r.loop_hit else "—"
        lines.append(f"| **{r.model}** | {ok} | {lat} | {toks} | {chars} | "
                     f"{c} | {anchor_str} | {vm_str} | {loop_str} |")
    lines.append("")
    # errors detail
    errs = [r for r in results if not r.ok]
    if errs:
        lines.append("## Errors")
        lines.append("")
        for r in errs:
            lines.append(f"- **{r.model}**: {r.error}")
        lines.append("")
    # outputs reference
    lines.append("## Outputs")
    lines.append("")
    for r in results:
        if r.ok:
            lines.append(f"- **{r.model}**: see `llm_results/{r.model}_{fn_id}.md`")
    lines.append("")
    return "\n".join(lines) + "\n"
