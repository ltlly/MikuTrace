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
    insns: list[int] = field(default_factory=list)   # list of (pc) — sorted, unique
    exits: set = field(default_factory=set)           # set of (target_pc, kind)
    executions: int = 0
    end_pc: int = 0     # PC of last (branch) instruction
    _filled: bool = False  # True 后 insns 不再追加 (防多次执行重复)


@dataclass
class CFG:
    blocks: dict[int, Block] = field(default_factory=dict)   # start_pc -> Block
    edges: dict[tuple[int, int], dict] = field(default_factory=dict)  # (src,dst) -> {kind, count}
    entry_pc: int = 0


def find_sccs(cfg: "CFG") -> list[list[int]]:
    """Tarjan SCC: 返回 list of [block_start_pc, ...] (每个 SCC 一组).
    单顶点 SCC (无自环) 不算循环, 只有 size>=2 或自环的算 loop.
    """
    blocks = list(cfg.blocks)
    if not blocks: return []
    # adjacency: src → list of dst (only dsts within blocks)
    adj: dict[int, list[int]] = {b: [] for b in blocks}
    for (s, d) in cfg.edges:
        if s in adj and d in adj:
            adj[s].append(d)

    # Iterative Tarjan
    index_counter = [0]
    stack: list[int] = []
    on_stack: set[int] = set()
    lowlink: dict[int, int] = {}
    index: dict[int, int] = {}
    sccs: list[list[int]] = []

    for start in blocks:
        if start in index: continue
        # iterative DFS to avoid Python recursion limit on huge CFGs
        work = [(start, iter(adj[start]))]
        index[start] = index_counter[0]
        lowlink[start] = index_counter[0]
        index_counter[0] += 1
        stack.append(start); on_stack.add(start)
        while work:
            v, it = work[-1]
            try:
                w = next(it)
                if w not in index:
                    index[w] = index_counter[0]
                    lowlink[w] = index_counter[0]
                    index_counter[0] += 1
                    stack.append(w); on_stack.add(w)
                    work.append((w, iter(adj[w])))
                elif w in on_stack:
                    lowlink[v] = min(lowlink[v], index[w])
            except StopIteration:
                # all neighbors done, pop
                if lowlink[v] == index[v]:
                    scc = []
                    while True:
                        w = stack.pop(); on_stack.discard(w)
                        scc.append(w)
                        if w == v: break
                    sccs.append(scc)
                work.pop()
                if work:
                    parent = work[-1][0]
                    lowlink[parent] = min(lowlink[parent], lowlink[v])
    return sccs


def loop_sccs(cfg: "CFG") -> list[list[int]]:
    """只返回真 loop (size>1, 或 size=1 但有自环)."""
    out = []
    for scc in find_sccs(cfg):
        if len(scc) > 1:
            out.append(scc)
        elif len(scc) == 1:
            v = scc[0]
            if (v, v) in cfg.edges:
                out.append(scc)
    return out


def build_cfg(t: Trace, only_module: bool = True) -> CFG:
    """Walk trace, identify block boundaries, count edges.

    Correctness invariants (regression-tested in tests/test_cfg_bugs.py):
      - Block.insns 必须 unique (no duplicates), 即使该 block 末尾不是 branch
        而是 fall-through 进入下一个 block_start. _filled 在 cur 退场前 (不只是
        branch 退场) 都要被设上.
      - cfg.entry_pc 必须落在 module 内 (only_module=True 时); trace 第 0 条若
        在外部, entry_pc 取第一个 in-module pc 而不是 t.pc(0).
      - call_stack 跨 module 边界要平衡. 我们的 bl 调外部 SO 时 (next pc 不在
        module), 外部 ret 在 only_module 视野外 ⇒ 必须在重新回到 module 时把
        相应 frame pop 掉, 否则下一次本 module 的 ret 会 pop 错的 caller 加错
        call-return 边.

    Perf: 用 numpy zero-copy 视图直接索引 mmap, 替代 struct.unpack_from 的
    t.pc(i)/t.inst(i) 调用 — 10M trace 上 build_cfg 11s → ~6s.
    """
    cfg = CFG()
    base = t.meta.module.base if t.meta.module else 0
    end  = t.meta.module.end  if t.meta.module else 1<<63

    n = len(t)
    if n == 0: return cfg

    # mmap 上的 zero-copy numpy 视图; 索引 ~快 2x of t.pc/t.inst (struct.unpack)
    import numpy as np
    from .trace import REC_SIZE
    pc_arr = t.pc_array()
    u32 = np.frombuffer(t._mm, dtype=np.uint32, count=t.n * (REC_SIZE // 4))
    inst_arr = u32[REC_SIZE // 4 - 1::REC_SIZE // 4]

    # Pass 1: in-module mask + block_start mask. 全部向量化.
    if only_module:
        in_so_arr = (pc_arr >= np.uint64(base)) & (pc_arr < np.uint64(end))
    else:
        in_so_arr = np.ones(n, dtype=bool)

    # 检测分支指令 (位模式, 不调 capstone — 0.7s for 10M):
    #   B/BL: imm26, op=00010100 / 10010100
    #   B.cond: 01010100, 4 bit cond at [3:0]
    #   BR/BLR/RET: D63F/D61F/D65F mask 0xFFFFFC1F
    #   CBZ/CBNZ: 0x34/0x35 mask 0x7E000000 (sf+0x34000000)
    #   TBZ/TBNZ: 0x36/0x37 同上
    is_b    = (inst_arr & np.uint32(0xFC000000)) == np.uint32(0x14000000)
    is_bl   = (inst_arr & np.uint32(0xFC000000)) == np.uint32(0x94000000)
    is_blr  = (inst_arr & np.uint32(0xFFFFFC1F)) == np.uint32(0xD63F0000)
    is_br   = (inst_arr & np.uint32(0xFFFFFC1F)) == np.uint32(0xD61F0000)
    is_ret  = (inst_arr & np.uint32(0xFFFFFC1F)) == np.uint32(0xD65F0000)
    is_bcond     = (inst_arr & np.uint32(0xFF000000)) == np.uint32(0x54000000)
    is_cbz_cbnz  = (inst_arr & np.uint32(0x7E000000)) == np.uint32(0x34000000)
    is_tbz_tbnz  = (inst_arr & np.uint32(0x7E000000)) == np.uint32(0x36000000)
    is_branch_arr = is_b | is_bl | is_blr | is_br | is_ret | is_bcond | is_cbz_cbnz | is_tbz_tbnz

    # block_start mask:
    #   - prev was branch (in_so) — 落在分支后的 pc
    #   - prev not in_so — 从外部回来的入口
    #   - prev_pc+4 != pc — 非顺序到达 (间接跳转目标 / 外部回来兜底)
    #   - 全 trace 第一个 in_so pc 也要标 (entry)
    prev_branch = np.concatenate([[False], (is_branch_arr[:-1] & in_so_arr[:-1])])
    prev_in_so  = np.concatenate([[False], in_so_arr[:-1]])
    prev_pc_arr = np.concatenate([[np.uint64(0)], pc_arr[:-1]])
    discontinuous = (prev_pc_arr + np.uint64(4)) != pc_arr
    discontinuous[0] = False
    block_start_mask = in_so_arr & (prev_branch | (~prev_in_so) | discontinuous)
    if in_so_arr.any():
        first_in_so = int(np.argmax(in_so_arr))
        block_start_mask[first_in_so] = True

    block_starts: set[int] = {int(p) for p in np.unique(pc_arr[block_start_mask])}

    # entry_pc = 第一个 in-so pc
    if not in_so_arr.any(): return cfg
    cfg.entry_pc = int(pc_arr[int(np.argmax(in_so_arr))])

    # Pass 2: bookkeeping with Python loop (per-record state machine).
    # 用 numpy ndarray 索引 (~2x快 vs struct.unpack), decode() lru-cache.
    cur: Optional[Block] = None
    prev_pc = 0
    prev_was_in_so = False
    call_stack: list[int] = []   # caller block start_pcs (LIFO)

    def _add_call_return(caller_block: int, post_pc: int):
        e = (caller_block, post_pc)
        cfg.edges.setdefault(e, {"kind": "call-return", "count": 0})["count"] += 1
        if caller_block in cfg.blocks:
            cfg.blocks[caller_block].exits.add((post_pc, "call-return"))

    for i in range(n):
        pc = int(pc_arr[i])
        in_so = bool(in_so_arr[i])
        if not in_so:
            if cur is not None: cur._filled = True
            cur = None; prev_pc = pc; prev_was_in_so = False
            continue
        # 重入 module: 之前经过外部. 立即 pop 顶帧 + 加 call-return (Bug #3).
        if not prev_was_in_so and call_stack:
            caller_block = call_stack.pop()
            _add_call_return(caller_block, pc)
        # 起新块?
        if pc in block_starts or cur is None:
            if cur is not None and prev_pc and prev_pc + 4 == pc:
                e = (cur.start_pc, pc)
                cfg.edges.setdefault(e, {"kind": "fall", "count": 0})["count"] += 1
            # 切走 cur 之前先封, 防止 _filled=False 导致 insns 重复 (Bug #1).
            if cur is not None: cur._filled = True
            blk = cfg.blocks.get(pc)
            if blk is None:
                blk = Block(start_pc=pc)
                cfg.blocks[pc] = blk
            cur = blk
            cur.executions += 1
        if not cur._filled:
            cur.insns.append(pc)
            cur.end_pc = pc
        if is_branch_arr[i]:
            inst = int(inst_arr[i])
            d = decode(pc, inst)
            next_pc = int(pc_arr[i + 1]) if i + 1 < n else None
            if next_pc is not None:
                kind = d.mnemonic
                e = (cur.start_pc, next_pc)
                cfg.edges.setdefault(e, {"kind": kind, "count": 0})["count"] += 1
                cur.exits.add((next_pc, kind))
                if d.is_call:
                    call_stack.append(cur.start_pc)
                elif d.is_ret:
                    if call_stack:
                        caller_block = call_stack.pop()
                        _add_call_return(caller_block, next_pc)
            cur._filled = True
            cur = None
        prev_pc = pc; prev_was_in_so = True

    if cur is not None: cur._filled = True

    return cfg


def build_aux_indices(t: Trace, cfg: CFG):
    """从已构好的 cfg + trace mmap 一次出 (pc_inst, pc_to_block, block_idxs).

    向量化: 替代 subprocess 里 10M 行 Python loop (~3s) 用 numpy 操作 (<0.5s).

    Returns:
        pc_inst:     dict {pc: first_seen_inst}, 仅在 cfg block 范围内的 pc.
        pc_to_block: dict {pc: block_start_pc}.
        block_idxs:  dict {block_start: [trace_idx,...]} (顺序保留 trace 序).
    """
    import numpy as np
    from .trace import REC_SIZE
    n = len(t)
    if n == 0 or not cfg.blocks:
        return {}, {}, {}

    pc_arr = t.pc_array()
    u32 = np.frombuffer(t._mm, dtype=np.uint32, count=t.n * (REC_SIZE // 4))
    inst_arr = u32[REC_SIZE // 4 - 1::REC_SIZE // 4]

    # 块范围 (sorted starts + ends 平行数组), bisect_right(starts, pc) - 1 给候选
    # block index. 接着检 pc <= ends[j] 排除"间隙"指令.
    starts = sorted(cfg.blocks.keys())
    ends = [cfg.blocks[s].end_pc for s in starts]
    starts_arr = np.array(starts, dtype=np.uint64)
    ends_arr = np.array(ends, dtype=np.uint64)

    # 每条 trace insn 的候选块 idx (右侧二分; 0..len(starts))
    j_arr = np.searchsorted(starts_arr, pc_arr, side="right") - 1
    valid = (j_arr >= 0)
    # 索引 ends_arr 时 j 必须 >= 0; 用 clip + valid mask.
    j_clip = np.clip(j_arr, 0, len(starts_arr) - 1)
    in_block = valid & (pc_arr <= ends_arr[j_clip])
    bs_arr = starts_arr[j_clip]   # only meaningful where in_block

    # pc_to_block: 唯一 pc → bs (用 unique + 一次取 first occurrence 即可)
    in_block_idxs = np.flatnonzero(in_block)
    if len(in_block_idxs) == 0:
        return {}, {}, {s: [] for s in starts}
    pc_in_block = pc_arr[in_block_idxs]
    bs_in_block = bs_arr[in_block_idxs]
    # unique pc + first occurrence index — 用于 pc_inst (要 first-seen 的 inst)
    unique_pcs, first_pos = np.unique(pc_in_block, return_index=True)
    # first_pos 是相对 pc_in_block 的位置 → 映射回 inst_arr 的 trace idx
    first_trace_idx = in_block_idxs[first_pos]
    pc_inst = {int(p): int(inst_arr[int(idx)])
               for p, idx in zip(unique_pcs, first_trace_idx)}
    # 同样的 unique 给 pc_to_block (一一对应 unique_pcs)
    bs_at_first = bs_in_block[first_pos]
    pc_to_block = {int(p): int(b) for p, b in zip(unique_pcs, bs_at_first)}

    # block_idxs: 按 bs 分组. np.split 需要 sorted 输入, 用 argsort.
    order = np.argsort(bs_in_block, kind="stable")
    sorted_bs = bs_in_block[order]
    sorted_idx = in_block_idxs[order]
    # 分组边界
    if len(sorted_bs) > 0:
        change = np.flatnonzero(np.diff(sorted_bs)) + 1
        groups_idx = np.split(sorted_idx, change)
        groups_bs = np.split(sorted_bs, change)
        block_idxs = {s: [] for s in starts}
        for grp_bs, grp_idx in zip(groups_bs, groups_idx):
            if len(grp_bs):
                block_idxs[int(grp_bs[0])] = grp_idx.tolist()
    else:
        block_idxs = {s: [] for s in starts}

    return pc_inst, pc_to_block, block_idxs


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
