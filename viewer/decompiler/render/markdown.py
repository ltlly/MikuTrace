"""Markdown renderer for TraceIR.

输出文件树 (设计 §4):
    decompile/
    ├── summary.md           # TopIR 概要, ~3KB
    └── fns/
        ├── F0.md            # FuncIR 完整, ~5-30KB
        └── ...

每个 markdown 文件 self-contained, LLM 直接读单文件就够上下文.
不内联跨文件大段, 用 ref-link (e.g. `[F1](F1.md)`) 让 LLM tool-use 跳.
"""
from __future__ import annotations
import pathlib
from ..ir import TopIR, FuncIR, BlockIR, LoopIR, CallIR, EdgeIR


def render_summary_md(top: TopIR) -> str:
    """Render TopIR → summary.md text."""
    lines: list[str] = []
    lines.append(f"# Trace Summary")
    lines.append("")
    lines.append(f"- records: **{top.records}**")
    lines.append(f"- module: `{top.module_name}` @ {top.module_base:#x} "
                 f"(size {top.module_size:#x})")
    if top.cmd is not None:
        lines.append(f"- cmd: **{top.cmd}**")
    if top.method:
        lines.append(f"- method: `{top.method}`")
    lines.append(f"- truncated: {top.truncated}")
    lines.append(f"- last_insn_is_ret: {top.last_insn_is_ret}")
    lines.append(f"- generated: {top.generated_at} (tracemiku {top.tracemiku_version})")
    lines.append("")
    if top.vm_candidates:
        lines.append(f"## VM Candidates ({len(top.vm_candidates)})")
        lines.append("")
        lines.append("> 来自 ollvmdet + bytecode reader 检测 (DEC3-D). "
                     "**evidence only — 不解码**, LLM 看 hex dump 自己推编码.")
        lines.append("")
        for i, vc in enumerate(top.vm_candidates):
            lines.append(f"### Candidate #{i}")
            lines.append("")
            lines.append(f"- dispatcher_pc: `{vc.dispatcher_pc:#x}`")
            lines.append(f"- confidence: **{vc.confidence:.2f}**")
            if vc.reasons:
                lines.append(f"- reasons:")
                for r in vc.reasons:
                    lines.append(f"  - {r}")
            if vc.reader_pc:
                lines.append(f"- bytecode reader: `{vc.reader_inst}` "
                             f"@ `{vc.reader_pc:#x}` (×{vc.reader_hits} hits, "
                             f"base reg = `{vc.reader_base_reg}`)")
            if vc.bytecode_addr:
                # > 64KB: 跨 mmap region, length 不可靠, 不展示原值避免误导
                if vc.bytecode_len > 65536:
                    lines.append(f"- bytecode start: `{vc.bytecode_addr:#x}` "
                                 f"(length unreliable: base reg spans "
                                 f"~{vc.bytecode_len:,} bytes — likely "
                                 f"multiple mmap regions, hex dump shows first 256B)")
                else:
                    lines.append(f"- bytecode range: `{vc.bytecode_addr:#x}` "
                                 f"+ `{vc.bytecode_len}` bytes")
            if vc.hex_dump:
                lines.append("")
                lines.append("**bytecode hex dump** (memshadow snapshot at trace end):")
                lines.append("")
                lines.append("```")
                for ln in vc.hex_dump[:16]:
                    lines.append(ln)
                lines.append("```")
            lines.append("")
        lines.append("")

    lines.append(f"## Functions ({len(top.fns)})")
    lines.append("")
    lines.append("| id | name | blocks | loops | calls | idx range |")
    lines.append("|---|---|---|---|---|---|")
    for f in top.fns:
        lines.append(f"| [{f.id}](fns/{f.id}.md) | `{f.name}` | "
                     f"{len(f.blocks)} | {len(f.loops)} | {len(f.calls)} | "
                     f"{f.entry_idx}..{f.exit_idx} |")
    lines.append("")
    return "\n".join(lines) + "\n"


def _fmt_samples(samples: dict[str, int]) -> str:
    if not samples: return ""
    parts = []
    for k in ("x0", "x1", "x2", "x3", "sp"):
        if k in samples:
            parts.append(f"{k}={samples[k]:#x}")
    return ", ".join(parts)


def _fmt_edge(e: EdgeIR) -> str:
    cnt = f" (×{e.taken_count})" if e.taken_count else ""
    return f"`{e.kind}` → **{e.dst}**{cnt}"


def render_block_md(b: BlockIR, stub: bool = False) -> str:
    """Render single BlockIR as markdown.

    stub=True: 只 PC + count + exits, 不出 asm. DEC3-A 用于冷块降低 token 预算.
    """
    lines: list[str] = []
    tier_mark = "" if b.tier == "hot" else f" ({b.tier})"
    lines.append(f"### {b.id} @ {b.pc:#x} (×{b.exec_count}){tier_mark}")
    if b.ref:
        lines.append(f"  *ref → {b.ref}*")
        return "\n".join(lines) + "\n"
    lines.append("")
    if stub:
        # 紧凑 stub: 只一行汇总. 旨在节省 token 而不是给完整信息.
        exits_short = ""
        if b.exits:
            exits_short = " → " + ",".join(e.dst for e in b.exits[:3])
            if len(b.exits) > 3:
                exits_short += "+"
        lines.append(f"- {b.insns} insns{exits_short}")
        lines.append("")
        return "\n".join(lines) + "\n"
    smp = _fmt_samples(b.samples)
    if smp:
        lines.append(f"- samples (first exec): {smp}")
    lines.append(f"- insns: {b.insns}, range: {b.pc:#x}..{b.end_pc:#x}")
    if b.exits:
        lines.append("- exits:")
        for e in b.exits:
            lines.append(f"  - {_fmt_edge(e)}")
    if b.asm:
        lines.append("")
        lines.append("```arm64")
        lines.append(b.asm)
        lines.append("```")
    lines.append("")
    return "\n".join(lines) + "\n"


def _fmt_call(c: CallIR) -> str:
    ret = ""
    if c.ret_idx is not None:
        ret = f", ret idx={c.ret_idx}"
        if c.ret_val_x0 is not None:
            ret += f" x0={c.ret_val_x0:#x}"
    callee = c.callee_name or f"sub_{c.callee_pc:x}"
    return (f"- idx={c.idx} from **{c.src_block}** → "
            f"`{callee}` ({c.callee_pc:#x}){ret}")


def _fmt_loop(L: LoopIR) -> str:
    body_short = ", ".join(L.body[:10])
    if len(L.body) > 10: body_short += f", … ({len(L.body)} total)"
    extra = ""
    if L.induction_vars:
        # 简洁列出: top-3 IV (按 score 降, builder 已排序)
        iv_lines = []
        for iv in L.induction_vars[:3]:
            step_str = f"+{int(iv.step)}" if iv.step.is_integer() else f"{iv.step:+.2f}"
            tag = ("🔁 arith" if iv.classification == "arith" else "🌀 complex")
            iv_lines.append(
                f"  - {tag} `{iv.reg}` {iv.init:#x} {step_str}/iter "
                f"× {iv.n_iters} → {iv.final:#x} (score {iv.linearity_score:.2f})"
            )
        extra = "\n" + "\n".join(iv_lines)
    elif L.induction_var:
        extra = f"\n  - induction: `{L.induction_var}`"
    return (f"- **{L.id}** header={L.header}, iters=**{L.iters}**, "
            f"body=[{body_short}]{extra}")


def render_func_md(fn: FuncIR, tier: str = "full") -> str:
    """Render FuncIR → F<id>.md text.

    tier:
      'full'    所有块完整 asm (默认, 跟 DEC1 行为一致)
      'hot'     hot 块完整 + warm 块 stub (省 60-90% token, DEC3-A)
      'summary' 没有块明细, 只 fn meta + loops + calls list
    """
    lines: list[str] = []
    lines.append(f"# {fn.id} `{fn.name}`")
    lines.append("")
    lines.append(f"- range: {fn.pc_start:#x}..{fn.pc_end:#x}")
    lines.append(f"- trace idx: {fn.entry_idx}..{fn.exit_idx}")
    lines.append(f"- exec_count: {fn.exec_count}")
    lines.append(f"- truncated: {fn.truncated}, last_insn_is_ret: {fn.last_insn_is_ret}")
    lines.append("")

    if fn.static:
        lines.append("## Static prior (BN/Ghidra)")
        lines.append("")
        if fn.static.get("signature"):
            lines.append(f"signature: `{fn.static['signature']}`")
            lines.append("")
        if fn.static.get("hlil_excerpt"):
            lines.append("```c")
            lines.append(fn.static["hlil_excerpt"])
            lines.append("```")
            lines.append("")

    if fn.loops:
        lines.append(f"## Loops ({len(fn.loops)})")
        lines.append("")
        for L in fn.loops:
            lines.append(_fmt_loop(L))
        lines.append("")

    if fn.type_anchors:
        lines.append(f"## Type anchors ({len(fn.type_anchors)})")
        lines.append("")
        lines.append("> 来自 user-provided JSON spec (DEC3-B). LLM 优先信这些"
                     "类型, 它们是真实运行时 ABI 锚点.")
        lines.append("")
        # group by callee_name 减少冗余
        from collections import defaultdict as _dd
        grouped: dict[str, list] = _dd(list)
        for a in fn.type_anchors:
            key = a.callee_name or f"sub_{a.callee_pc:x}"
            grouped[key].append(a)
        for name, anchors in grouped.items():
            a0 = anchors[0]
            params_str = ", ".join(f"{r}:{tp}" for r, tp in a0.params)
            ret_str = (f"{a0.ret_reg}:{a0.ret_type}"
                       if a0.ret_type else a0.ret_reg)
            lines.append(f"- **{name}** ({a0.callee_pc:#x}, ×{len(anchors)})"
                         f" `({params_str})` → `{ret_str}`")
            idxs = sorted(a.idx for a in anchors)[:5]
            lines.append(f"  - hit idx: {idxs}{'...' if len(anchors) > 5 else ''}")
            lines.append(f"  - source: `{a0.provenance}`")
        lines.append("")

    if fn.calls:
        lines.append(f"## Calls ({len(fn.calls)})")
        lines.append("")
        # MVP: 列表展示前 50 个; 多了说 truncated
        for c in fn.calls[:50]:
            lines.append(_fmt_call(c))
        if len(fn.calls) > 50:
            lines.append(f"- … ({len(fn.calls) - 50} more)")
        lines.append("")

    if tier == "summary":
        lines.append(f"## Blocks ({len(fn.blocks)} total)")
        lines.append("")
        hot_count = sum(1 for b in fn.blocks if b.tier == "hot")
        warm_count = sum(1 for b in fn.blocks if b.tier == "warm")
        lines.append(f"- hot: {hot_count}, warm: {warm_count}")
        lines.append("- *block detail omitted (--tier summary). "
                     "Re-render with --tier hot or --tier full.*")
        lines.append("")
        return "\n".join(lines) + "\n"

    hot_count = sum(1 for b in fn.blocks if b.tier == "hot")
    warm_count = sum(1 for b in fn.blocks if b.tier == "warm")
    if tier == "hot" and warm_count > 0:
        lines.append(f"## Blocks ({hot_count} hot + {warm_count} warm shown as stub)")
    else:
        lines.append(f"## Blocks ({len(fn.blocks)})")
    lines.append("")
    for b in fn.blocks:
        if tier == "hot" and b.tier == "warm":
            lines.append(render_block_md(b, stub=True))
        else:
            lines.append(render_block_md(b, stub=False))
    return "\n".join(lines) + "\n"


def write_decompile_dir(top: TopIR, out_dir: str | pathlib.Path,
                        tier: str = "full") -> pathlib.Path:
    """Write summary.md + fns/<id>.md into out_dir/decompile/.

    tier: 'full' | 'hot' | 'summary' — 见 render_func_md.

    Returns the decompile/ path.
    """
    out_dir = pathlib.Path(out_dir)
    dec = out_dir / "decompile"
    dec.mkdir(parents=True, exist_ok=True)
    fns_dir = dec / "fns"
    fns_dir.mkdir(exist_ok=True)
    (dec / "summary.md").write_text(render_summary_md(top), encoding="utf-8")
    for fn in top.fns:
        (fns_dir / f"{fn.id}.md").write_text(
            render_func_md(fn, tier=tier), encoding="utf-8"
        )
    return dec
