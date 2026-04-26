"""ASCII art CFG renderer — IDA-style boxed blocks with arrow edges.

Layout: Sugiyama-style layered (BFS depth = row, sibling order within row).
Each block is rendered as a box with its disassembly. Edges drawn between
boxes using box-drawing chars + arrows.

Limitation: complex graphs with crossing edges may overlap; the renderer
does best-effort routing.
"""
from __future__ import annotations
from collections import defaultdict
from .cfg import CFG, Block
from .trace import Trace
from .disasm import decode
from .symbols import SymbolMap


BLOCK_W = 38     # box width (incl. borders)
INSN_LIMIT = 6   # max insn lines per box (more = ellipsis)
BLOCK_H = INSN_LIMIT + 4   # title + insn lines + bottom border + footer
GAP_X = 4
GAP_Y = 3        # vertical gap between layers (room for edges)


class Canvas:
    def __init__(self, rows: int, cols: int):
        self.rows = rows; self.cols = cols
        self.cells = [[' '] * cols for _ in range(rows)]
        self.styles = [[None] * cols for _ in range(rows)]   # per-cell style

    def put(self, x: int, y: int, ch: str, style=None):
        if 0 <= y < self.rows and 0 <= x < self.cols:
            if self.cells[y][x] == ' ' or ch != ' ':
                self.cells[y][x] = ch
                if style: self.styles[y][x] = style

    def puts(self, x: int, y: int, s: str, style=None):
        for i, c in enumerate(s):
            self.put(x + i, y, c, style)

    def hline(self, x1: int, x2: int, y: int, ch: str = '─', style=None):
        a, b = min(x1, x2), max(x1, x2)
        for x in range(a, b + 1):
            # don't overwrite existing vlines/corners with dashes
            if self.cells[y][x] in (' ', ch): self.put(x, y, ch, style)

    def vline(self, x: int, y1: int, y2: int, ch: str = '│', style=None):
        a, b = min(y1, y2), max(y1, y2)
        for y in range(a, b + 1):
            if self.cells[y][x] in (' ', ch): self.put(x, y, ch, style)

    def to_text(self):
        from rich.text import Text
        out = Text()
        for y in range(self.rows):
            for x in range(self.cols):
                ch = self.cells[y][x]
                st = self.styles[y][x]
                out.append(ch, style=st or None)
            out.append('\n')
        return out


def _layer_layout(cfg: CFG) -> tuple[list[list[int]], dict[int, int]]:
    """Sugiyama-style layered layout (ghidra Decompiler-Layout 风格).

    步骤:
      1. 拓扑层级 (longest-path): 节点 depth = max(predecessor.depth) + 1
         比 BFS 更稳定 — 同层节点真正并行
      2. 对每层用 barycenter heuristic 排序 — 减少边交叉
      3. 多遍迭代 (上→下, 下→上) 收敛

    Returns (layers, depth_map). layers[i] 是层 i 的 block start_pc 列表.
    """
    if not cfg.blocks: return ([], {})

    # 反向边 map (predecessors)
    preds: dict[int, list[int]] = defaultdict(list)
    succs: dict[int, list[int]] = defaultdict(list)
    for (s, d), info in cfg.edges.items():
        if d in cfg.blocks and s in cfg.blocks:
            preds[d].append(s); succs[s].append(d)

    # 1) longest-path layering (forward)
    # 检测 back-edge: 任何 (s,d) 中 d 已经在 chain 上 → back edge
    depth: dict[int, int] = {}
    # 用 DFS 计算 dominator-style depth, back-edge 不增加 depth
    # 简化: 用 Kahn 拓扑序处理 (忽略 back edge)
    in_deg = {pc: 0 for pc in cfg.blocks}
    for d_pc, ps in preds.items():
        in_deg[d_pc] = len([p for p in ps if p != d_pc])
    queue = [pc for pc, d in in_deg.items() if d == 0]
    if not queue: queue = [cfg.entry_pc]    # cycle case
    visited: set[int] = set()
    depth[cfg.entry_pc] = 0
    while queue:
        cur = queue.pop(0)
        if cur in visited: continue
        visited.add(cur)
        cur_d = depth.get(cur, 0)
        for nxt in succs.get(cur, []):
            new_d = cur_d + 1
            if new_d > depth.get(nxt, -1):
                depth[nxt] = new_d
            queue.append(nxt)
    # unreached blocks
    max_d = max(depth.values()) if depth else 0
    for pc in cfg.blocks:
        if pc not in depth: max_d += 1; depth[pc] = max_d

    # bucket
    layers_d: dict[int, list[int]] = defaultdict(list)
    for pc, d in depth.items():
        layers_d[d].append(pc)
    layers = [layers_d[d] for d in sorted(layers_d.keys())]

    # 2) barycenter sweep (顺序 + 反向, 多轮)
    def position_in(layer: list[int], pc: int) -> float:
        try: return float(layer.index(pc))
        except ValueError: return 0.0

    for sweep in range(4):
        # forward sweep: 用 predecessor 平均位置排
        for li in range(1, len(layers)):
            prev = layers[li - 1]
            cur = layers[li]
            scores = {}
            for pc in cur:
                ps = [p for p in preds.get(pc, []) if p in prev]
                if ps:
                    scores[pc] = sum(position_in(prev, p) for p in ps) / len(ps)
                else:
                    scores[pc] = -cfg.blocks[pc].executions / 1e6  # tie: hot first
            cur.sort(key=lambda pc: scores[pc])
        # backward sweep: 用 successor 平均位置排
        for li in range(len(layers) - 2, -1, -1):
            nxt = layers[li + 1]
            cur = layers[li]
            scores = {}
            for pc in cur:
                ss = [s for s in succs.get(pc, []) if s in nxt]
                if ss:
                    scores[pc] = sum(position_in(nxt, s) for s in ss) / len(ss)
                else:
                    scores[pc] = -cfg.blocks[pc].executions / 1e6
            cur.sort(key=lambda pc: scores[pc])

    # 3) 同层节点居中: 让父子尽量对齐. 这里 layout 用 (col, row) 直接,
    # 后面 render 会按 col*BLOCK_W 放置. 我们让窄层缩进, 宽层占满.
    return (layers, depth)


def render_cfg_graph(trace: Trace, cfg: CFG, sym: SymbolMap,
                     focus_pc: int | None = None,
                     max_layers: int = 20,
                     max_per_layer: int = 8):
    """Render the CFG as ASCII art (ghidra Decompiler-Layout 风格).

    布局算法:
      1. _layer_layout (Sugiyama): 计算 layer + barycenter 排序
      2. 每层中 block 等距摆放，宽层占满整个 canvas 宽
      3. 子节点居中对齐于其父节点的中线 (尽量避免边过长)
    """
    base = trace.meta.module.base if trace.meta.module else 0
    layers, _depth = _layer_layout(cfg)
    if not layers:
        from rich.text import Text
        return Text("(no CFG)")

    # 聚焦窗口
    focus_layer = 0
    if focus_pc is not None:
        for li, lay in enumerate(layers):
            if focus_pc in lay: focus_layer = li; break
    lo = max(0, focus_layer - max_layers // 2)
    hi = min(len(layers), lo + max_layers)
    layers = layers[lo:hi]
    layers = [lay[:max_per_layer] for lay in layers]

    # 决定每层 block 的横向位置.
    # 目标: 等距布满 canvas 宽度, 而不是顶头堆叠.
    max_cols = max((len(lay) for lay in layers), default=1)
    canvas_w = max_cols * (BLOCK_W + GAP_X) + GAP_X
    canvas_h = len(layers) * (BLOCK_H + GAP_Y) + GAP_Y
    canvas = Canvas(canvas_h, canvas_w)

    pc_to_first = {}
    for i in range(len(trace)):
        pc = trace.pc(i)
        if pc not in pc_to_first:
            pc_to_first[pc] = i

    pos: dict[int, tuple[int, int, int, int]] = {}
    for ri, layer in enumerate(layers):
        n = len(layer)
        if n == 0: continue
        # 等距分布: total_used = n * BLOCK_W + (n-1) * GAP_X
        total = n * BLOCK_W + (n - 1) * GAP_X
        x_start = max(GAP_X, (canvas_w - total) // 2)
        for ci, pc in enumerate(layer):
            x = x_start + ci * (BLOCK_W + GAP_X)
            y = GAP_Y + ri * (BLOCK_H + GAP_Y)
            pos[pc] = (x + BLOCK_W // 2, y, x, y)
            _draw_block(canvas, x, y, pc, cfg.blocks[pc], trace, sym, base,
                        pc_to_first, focus=(pc == focus_pc))

    # 画边
    for (src, dst), info in cfg.edges.items():
        if src not in pos or dst not in pos: continue
        sx, sy, sl, st = pos[src]; dx, dy, dl, dt = pos[dst]
        s_bot = st + BLOCK_H - 1
        d_top = dt
        kind = info.get("kind", "?")
        style = (
            "cyan" if kind == "fall"
            else "yellow" if kind.startswith("b.")
            else "magenta" if kind in ("br","bl","blr")
            else "red" if kind == "ret"
            else "white"
        )
        _draw_edge(canvas, sx, s_bot + 1, dx, d_top - 1, kind, style)

    return canvas.to_text()


def _draw_block(canvas: Canvas, x: int, y: int, pc: int, blk: Block,
                trace: Trace, sym: SymbolMap, base: int,
                pc_to_first: dict, focus: bool = False):
    # Border
    border_style = "bright_yellow bold" if focus else "white"
    title_style = "bold black on yellow" if focus else "bright_cyan"
    # Top border
    canvas.put(x, y, '┌', border_style)
    canvas.put(x + BLOCK_W - 1, y, '┐', border_style)
    canvas.hline(x + 1, x + BLOCK_W - 2, y, '─', border_style)
    # Title bar
    fname, foff = sym.lookup(pc)
    title = f" +{pc - base:#x}  {fname}+{foff:#x} "[:BLOCK_W - 4]
    canvas.puts(x + 2, y, title, title_style)
    canvas.put(x, y, '┌', border_style)   # restore corner
    # Side borders + content
    insns = blk.insns[:INSN_LIMIT]
    first_idx = pc_to_first.get(pc, None)
    for j in range(BLOCK_H - 2):
        canvas.put(x, y + 1 + j, '│', border_style)
        canvas.put(x + BLOCK_W - 1, y + 1 + j, '│', border_style)
        # fill content
        if j < len(insns):
            ipc = insns[j]
            try:
                if first_idx is not None and first_idx + j < len(trace):
                    r = trace.record(first_idx + j)
                    if r.pc == ipc:
                        d = decode(r.pc, r.inst)
                        line = f"{d.mnemonic} {d.op_str}"[:BLOCK_W - 4]
                        canvas.puts(x + 2, y + 1 + j, line, "white")
            except Exception: pass
        elif j == len(insns) and len(blk.insns) > INSN_LIMIT:
            canvas.puts(x + 2, y + 1 + j, f"... +{len(blk.insns) - INSN_LIMIT}", "dim")
        elif j == BLOCK_H - 3:
            # footer line: exec count
            footer = f"  ×{blk.executions}  insns={len(blk.insns)}"
            canvas.puts(x + 2, y + 1 + j, footer, "bright_black")
    # Bottom border
    canvas.put(x, y + BLOCK_H - 1, '└', border_style)
    canvas.put(x + BLOCK_W - 1, y + BLOCK_H - 1, '┘', border_style)
    canvas.hline(x + 1, x + BLOCK_W - 2, y + BLOCK_H - 1, '─', border_style)


def _draw_edge(canvas: Canvas, sx: int, sy: int, dx: int, dy: int,
               kind: str, style: str = "white"):
    """Draw a simple right-angle edge: down from (sx,sy) to halfway, then
    horizontal to dx column, then down to dy with arrowhead.
    """
    if sy >= dy:
        # back-edge (loop): route around the right side with a different color
        # simplified: just draw a colored 'L' on the right
        right = canvas.cols - 2
        canvas.vline(sx, sy, sy + 1, '│', style)
        canvas.put(sx, sy, '┤', style)
        canvas.hline(sx, right, sy + 1, '─', "red")
        canvas.put(right, sy + 1, '┐', "red")
        canvas.vline(right, sy + 1, dy - 1, '│', "red")
        canvas.put(right, dy - 1, '┘', "red")
        canvas.hline(dx, right, dy - 1, '─', "red")
        canvas.put(dx, dy - 1, '┌', "red")
        canvas.vline(dx, dy - 1, dy, '│', "red")
        canvas.put(dx, dy, '▲', "red")
        return
    mid_y = (sy + dy) // 2
    # vertical down from src
    canvas.vline(sx, sy, mid_y, '│', style)
    if sx != dx:
        # turn at mid_y
        canvas.put(sx, mid_y, '└' if dx > sx else '┘', style)
        canvas.hline(min(sx, dx) + 1, max(sx, dx) - 1, mid_y, '─', style)
        canvas.put(dx, mid_y, '┐' if dx > sx else '┌', style)
    # vertical down from mid_y to dst
    canvas.vline(dx, mid_y + 1, dy - 1, '│', style)
    # arrowhead
    canvas.put(dx, dy, '▼', style)
    # label kind near arrow
    if kind not in ("fall", "?"):
        canvas.puts(dx + 1, dy - 1, kind[:6], style)
