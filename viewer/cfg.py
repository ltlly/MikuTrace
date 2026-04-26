"""Reconstruct a basic-block CFG from a trace.

A basic block ends at any branch (b, b.cond, cbz, cbnz, tbz, tbnz, br, blr,
bl, ret) and starts at any instruction reached by a branch (or the trace
start). Indirect branches (br x8, blr x8) are reconstructed from the trace —
this is what makes trace-based CFGs immune to OLLVM's indirect-jump
obfuscation: we see the *actual* target executed, not what static analysis
guesses.

Output: a graph (V = blocks identified by start_pc, E = (src_pc, dst_pc, kind))
plus per-block stats (executions, length).

Layout: graphviz dot output (write_dot()) for high-quality SVG/PNG render via
`dot -Tsvg`. Also emits a textual list for terminal viewing.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict
from .trace import Trace
from .disasm import decode


@dataclass
class Block:
    start_pc: int
    insns: list[int] = field(default_factory=list)   # list of (pc) — sorted
    exits: set = field(default_factory=set)           # set of (target_pc, kind)
    executions: int = 0
    end_pc: int = 0     # PC of last (branch) instruction


@dataclass
class CFG:
    blocks: dict[int, Block] = field(default_factory=dict)   # start_pc -> Block
    edges: dict[tuple[int, int], dict] = field(default_factory=dict)  # (src,dst) -> {kind, count}
    entry_pc: int = 0


def build_cfg(t: Trace, only_module: bool = True) -> CFG:
    """Walk trace, identify block boundaries, count edges."""
    cfg = CFG()
    base = t.meta.module.base if t.meta.module else 0
    end  = t.meta.module.end  if t.meta.module else 1<<63

    # Pass 1: identify all branch-target / branch-source PCs (block starts/ends)
    block_starts: set[int] = set()
    block_ends_at: dict[int, str] = {}   # pc -> branch kind ('b','bl','br'...)
    n = len(t)
    if n == 0: return cfg
    cfg.entry_pc = t.pc(0)
    block_starts.add(cfg.entry_pc)

    prev_pc = 0
    prev_was_branch = False
    for i in range(n):
        pc = t.pc(i)
        inst = t.inst(i)
        in_so = (not only_module) or (base <= pc < end)
        if not in_so:
            prev_pc = pc; prev_was_branch = False
            continue
        d = decode(pc, inst)
        # If previous insn ended a block, this pc starts a new one
        if prev_was_branch:
            block_starts.add(pc)
        # If this insn falls non-sequentially after prev (indirect/cond branch
        # taken to elsewhere) treat as a new block start
        if i > 0 and prev_pc + 4 != pc:
            block_starts.add(pc)
        if d.is_branch:
            block_ends_at[pc] = d.mnemonic
            prev_was_branch = True
        else:
            prev_was_branch = False
        prev_pc = pc

    # Pass 2: actually populate blocks + edges
    cur: Optional[Block] = None
    prev_pc = 0
    for i in range(n):
        pc = t.pc(i)
        inst = t.inst(i)
        in_so = (not only_module) or (base <= pc < end)
        if not in_so:
            cur = None; prev_pc = pc; continue
        # Need to start a new block?
        if pc in block_starts or cur is None:
            if cur is not None and prev_pc and prev_pc + 4 == pc:
                # Fall-through edge from previous block's end to this start
                e = (cur.start_pc, pc)
                cfg.edges.setdefault(e, {"kind": "fall", "count": 0})["count"] += 1
            blk = cfg.blocks.get(pc)
            if blk is None:
                blk = Block(start_pc=pc)
                cfg.blocks[pc] = blk
            cur = blk
            cur.executions += 1
        cur.insns.append(pc)
        cur.end_pc = pc
        d = decode(pc, inst)
        if d.is_branch:
            # Edge to next executed pc
            next_pc = t.pc(i + 1) if i + 1 < n else None
            if next_pc is not None:
                kind = d.mnemonic
                e = (cur.start_pc, next_pc)
                cfg.edges.setdefault(e, {"kind": kind, "count": 0})["count"] += 1
                cur.exits.add((next_pc, kind))
            cur = None
        prev_pc = pc

    return cfg


def write_dot(cfg: CFG, out_path: str, base: int = 0,
              max_label_lines: int = 4):
    """Write a graphviz dot file. Render with: dot -Tsvg out.dot -o out.svg"""
    import io
    buf = io.StringIO()
    buf.write("digraph CFG {\n")
    buf.write('  graph [bgcolor=white, fontname="monospace"];\n')
    buf.write('  node [shape=box, fontname="monospace", fontsize=9, '
              'style=filled, fillcolor="#dceaf3"];\n')
    buf.write('  edge [fontname="monospace", fontsize=8];\n')
    for pc, blk in cfg.blocks.items():
        rel = f"+{pc-base:#x}" if base else f"{pc:#x}"
        end_rel = f"+{blk.end_pc-base:#x}" if base else f"{blk.end_pc:#x}"
        label = f"{rel}..{end_rel}\\n{len(blk.insns)} insn × {blk.executions}"
        # Color: more executions = darker red overlay
        intensity = min(blk.executions, 20) / 20
        r = int(220 - intensity * 100)
        color = f"#{r:02x}eaf3"
        buf.write(f'  "b{pc:x}" [label="{label}", fillcolor="{color}"];\n')
    for (src, dst), info in cfg.edges.items():
        kind = info["kind"]
        cnt = info["count"]
        if kind == "fall":
            attrs = 'color="#888888"'
        elif kind in ("b", "br"):
            attrs = 'color="#0066cc"'
        elif kind in ("bl", "blr"):
            attrs = 'color="#993399", style=dashed'
        elif kind == "ret":
            attrs = 'color="#cc0000", penwidth=2'
        elif kind.startswith("b."):
            attrs = 'color="#009933"'
        else:
            attrs = 'color="#666666"'
        if dst not in cfg.blocks:
            # Out-of-CFG target — synthesize stub node
            buf.write(f'  "ext{dst:x}" [label="ext {dst:#x}", fillcolor="#fff4cc", shape=oval];\n')
            buf.write(f'  "b{src:x}" -> "ext{dst:x}" [{attrs}, label="{kind} ×{cnt}"];\n')
        else:
            buf.write(f'  "b{src:x}" -> "b{dst:x}" [{attrs}, label="{kind} ×{cnt}"];\n')
    buf.write("}\n")
    with open(out_path, "w") as f: f.write(buf.getvalue())


def textual_summary(cfg: CFG, base: int = 0, top_n: int = 30) -> str:
    """Plain-text CFG summary for terminal."""
    lines = [f"CFG: {len(cfg.blocks)} blocks, {len(cfg.edges)} edges, entry={cfg.entry_pc:#x}"]
    by_exec = sorted(cfg.blocks.values(), key=lambda b: -b.executions)
    lines.append(f"\nTop {top_n} hot blocks:")
    for b in by_exec[:top_n]:
        rel = f"+{b.start_pc-base:#x}" if base else f"{b.start_pc:#x}"
        end_rel = f"+{b.end_pc-base:#x}" if base else f"{b.end_pc:#x}"
        exits = ", ".join(f"{k}->{t-base:+#x}" if base else f"{k}->{t:#x}"
                          for t,k in list(b.exits)[:3])
        lines.append(f"  {rel:>10s}..{end_rel:>10s}  {len(b.insns):3d} insns  ×{b.executions:5d}   exits: {exits}")
    return "\n".join(lines)
