"""traceMiku viewer v4 — 中文化、pwndbg 风格、鼠标交互、百万行优化.

布局:
    +----------------------------------------+--------------------------+
    | 指令流 (函数名+offset 在前, 当前PC高亮,  | 寄存器 (变化高亮 + 智能解 |
    | 鼠标点击跳转, 自动滚动)                  | 引用)                    |
    |                                        +--------------------------+
    |                                        | 内存 (?? 表示未访问)      |
    |                                        +--------------------------+
    |                                        | XRef/Taint/Strings/CFG/  |
    |                                        |   BlockMap (鼠标点 Tab)  |
    +----------------------------------------+--------------------------+
    | 状态栏                                                            |
    | 输入栏 (g/m/f/b/搜索时弹出, 支持中文提示)                          |
    +-------------------------------------------------------------------+
"""
from __future__ import annotations
import sys, pathlib, re, os, subprocess
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.widgets import Static, Footer, Header, Input, TabbedContent, TabPane, Label
from textual.binding import Binding
from textual.reactive import reactive
from textual.screen import Screen
from textual import events
from rich.text import Text

from .trace import load, Trace, ALL_REGS, REG_NAMES
from .disasm import decode
from .index import Index
from .cfg import build_cfg, write_dot, textual_summary
from .taint import forward_taint, backward_taint
from .symbols import build_from_trace, SymbolMap
from .memshadow import MemShadow
from .display import format_reg_line, classify, collect_modules_from_trace


# ---------- 共用工具 ----------

def fmt_addr(value: int, base: int = 0, end: int = 0) -> str:
    """统一的地址格式：模块内显示 +offset，否则全地址."""
    if base and base <= value < end:
        return f"+{value - base:08x}"
    return f"{value:#018x}"


# ---------- 指令流 ----------

class InsnStream(Static):
    """指令流面板：cursor 跟随箭头/PageUp/PageDown，鼠标点击跳转."""
    cursor = reactive(0)
    page_top = reactive(0)
    can_focus = True

    BINDINGS = [
        Binding("up,k", "step(-1)", show=False),
        Binding("down,j", "step(1)", show=False),
        Binding("pageup", "step(-20)", show=False),
        Binding("pagedown", "step(20)", show=False),
        Binding("home", "go_top", show=False),
        Binding("end", "go_end", show=False),
    ]

    def __init__(self, trace: Trace, sym: SymbolMap, **kw):
        super().__init__(**kw)
        self.t = trace
        self.sym = sym
        self._app = None

    def watch_cursor(self, _o, _n):
        self._scroll_to_cursor()
        if self._app: self._app._sync_cursor()
        self.refresh()

    def _scroll_to_cursor(self):
        h = self._visible_rows()
        if self.cursor < self.page_top:
            self.page_top = max(0, self.cursor - 2)
        elif self.cursor >= self.page_top + h:
            self.page_top = max(0, self.cursor - h + 3)

    def _visible_rows(self) -> int:
        try:
            h = self.size.height - 2
            if h > 1: return h
        except Exception:
            pass
        return 30

    def watch_page_top(self, _o, _n): self.refresh()

    def on_resize(self, e):
        self._scroll_to_cursor(); self.refresh()

    def render(self) -> Text:
        out = Text(no_wrap=True, overflow="ellipsis")
        n = len(self.t)
        base = self.t.meta.module.base if self.t.meta.module else 0
        end = self.t.meta.module.end if self.t.meta.module else 1<<63
        h = self._visible_rows()
        if self.page_top + h > n:
            self.page_top = max(0, n - h)
        # Always render exactly `h` lines so the widget height is stable
        # (avoid layout oscillation: too few lines → widget shrinks → resize → ...)
        for off in range(h):
            i = self.page_top + off
            if i >= n:
                out.append(" \n")  # blank line to keep height
                continue
            r = self.t.record(i)
            d = decode(r.pc, r.inst)
            in_so = base <= r.pc < end
            rel = fmt_addr(r.pc, base, end)
            sel = "▶" if i == self.cursor else " "
            fname, foff = self.sym.lookup(r.pc)
            func_col = (f"{fname}+{foff:#x}"[:34] if fname != "?" else "(未知)")
            line = f" {sel} #{i:6d}  {func_col:<34s}  {rel}  {d.mnemonic:<7s} {d.op_str}"
            style = ""
            if i == self.cursor: style = "bold black on green"
            elif d.is_branch and not d.is_ret: style = "magenta"
            elif d.is_ret: style = "red bold"
            elif not in_so: style = "dim"
            out.append(line + "\n", style=style or "white")
        return out

    def on_click(self, evt: events.Click):
        try:
            row = evt.y - 1
            if row < 0: return
            new_cursor = self.page_top + row
            if 0 <= new_cursor < len(self.t):
                self.cursor = new_cursor
        except Exception:
            pass

    def on_mouse_scroll_down(self, evt):
        # 滚轮下：步进 3 条
        self.cursor = max(0, min(len(self.t) - 1, self.cursor + 3))
    def on_mouse_scroll_up(self, evt):
        self.cursor = max(0, min(len(self.t) - 1, self.cursor - 3))

    def action_step(self, n: int):
        self.cursor = max(0, min(len(self.t) - 1, self.cursor + n))
    def action_go_top(self): self.cursor = 0
    def action_go_end(self): self.cursor = len(self.t) - 1


# ---------- 寄存器 ----------

class RegPanel(Static):
    """全 33 寄存器 + pwndbg 风格智能解引用 + 变化高亮."""
    can_focus = False

    def __init__(self, trace: Trace, sym: SymbolMap, mem: MemShadow, modules: list, **kw):
        super().__init__(**kw)
        self.t = trace; self.sym = sym; self.mem = mem; self.modules = modules
        self.cursor = 0

    def update_cursor(self, c: int):
        self.cursor = c; self.refresh()

    def render(self) -> Text:
        n = len(self.t)
        if self.cursor >= n: return Text("(无记录)")
        r = self.t.record(self.cursor)
        names = REG_NAMES + ["sp", "pc"]
        vals = list(r.regs) + [r.sp, r.pc]

        # 变化检测：和前一条记录对比
        changed: dict[str, bool] = {}
        if self.cursor > 0:
            prev = self.t.record(self.cursor - 1)
            prev_vals = list(prev.regs) + [prev.sp, prev.pc]
            for nm, v, pv in zip(names, vals, prev_vals):
                changed[nm] = (v != pv)

        out = Text(f"@ #{self.cursor}  ", style="bold cyan")
        out.append("(★ = 此条变化的寄存器)\n", style="dim")
        for nm, v in zip(names, vals):
            is_changed = changed.get(nm, False)
            # 标记前缀：变化的加红色 ★
            if is_changed:
                out.append("★ ", style="bright_red bold")
            else:
                out.append("  ", style="dim")
            line = format_reg_line(nm, v, self.cursor, self.t,
                                   self.sym, self.mem, self.modules, sp=r.sp)
            if is_changed:
                # pwndbg 风格：值整体高亮
                line.stylize("bright_red bold", 5, 5 + 16)  # 值的位置
            out.append_text(line); out.append("\n")
        return out


# ---------- 内存 ----------

class MemPanel(Static):
    can_focus = False

    def __init__(self, trace: Trace, mem: MemShadow, **kw):
        super().__init__(**kw)
        self.t = trace; self.mem = mem; self.cursor = 0
        self.base_addr = 0; self.rows = 12

    def update_cursor(self, c: int):
        self.cursor = c
        if self.base_addr == 0:
            r = self.t.record(c); self.base_addr = (r.sp - 0x40) & ~0xf
        self.refresh()
    def set_addr(self, addr: int):
        self.base_addr = addr & ~0xf; self.refresh()
    def on_resize(self, e):
        h = e.size.height - 3
        if h > 3: self.rows = h
        self.refresh()
    def render(self) -> Text:
        out = Text()
        if self.base_addr == 0:
            out.append("(按 m 设定查看的内存地址)\n", style="dim"); return out
        out.append(f"内存 @ {self.base_addr:#x}  (光标 #{self.cursor})\n", style="bold cyan")
        out.append("                  +0 +1 +2 +3 +4 +5 +6 +7  +8 +9 +a +b +c +d +e +f\n", style="dim")
        for line in self.mem.hex_dump(self.base_addr, self.cursor, rows=self.rows):
            if "??" in line:
                t = Text(); idx = 0
                while idx < len(line):
                    ch = line[idx:idx+2]
                    if ch == "??":
                        t.append("??", style="dim red"); idx += 2
                    else:
                        t.append(line[idx], style="white"); idx += 1
                out.append(t); out.append("\n")
            else:
                out.append(line + "\n", style="white")
        return out


# ---------- XRef ----------

class XRefTab(Static):
    can_focus = False
    def __init__(self, trace: Trace, index: Index, sym: SymbolMap, **kw):
        super().__init__(**kw); self.t = trace; self.idx = index; self.sym = sym; self.cursor = 0
    def update_cursor(self, c: int):
        self.cursor = c; self.refresh()
    def render(self) -> Text:
        n = len(self.t)
        if self.cursor >= n: return Text("(无记录)")
        r = self.t.record(self.cursor); d = decode(r.pc, r.inst)
        out = Text(f"@ #{self.cursor} ", style="bold cyan")
        fname, foff = self.sym.lookup(r.pc)
        if fname != "?": out.append(f"{fname}+{foff:#x}  ", style="bright_cyan")
        out.append(f"{d.mnemonic} {d.op_str}\n", style="white")
        out.append("\n← 输入定义链 (输入值从哪里来)\n", style="bold yellow")
        for reg, def_idx in self.idx.def_chain(self.cursor):
            dr = self.t.record(def_idx); dd = decode(dr.pc, dr.inst)
            dname, doff = self.sym.lookup(dr.pc)
            df = f"{dname}+{doff:#x}" if dname != "?" else f"{dr.pc:#x}"
            out.append(f"  {reg:>3s} ← #{def_idx:6d}  {df:<28s}  {dd.mnemonic} {dd.op_str}\n", style="white")
        out.append("\n→ 输出使用链 (输出值流向哪里)\n", style="bold yellow")
        for reg, use_idx in self.idx.use_chain(self.cursor):
            ur = self.t.record(use_idx); ud = decode(ur.pc, ur.inst)
            uname, uoff = self.sym.lookup(ur.pc)
            uf = f"{uname}+{uoff:#x}" if uname != "?" else f"{ur.pc:#x}"
            out.append(f"  {reg:>3s} → #{use_idx:6d}  {uf:<28s}  {ud.mnemonic} {ud.op_str}\n", style="white")
        if d.mem_op:
            out.append("\n内存操作\n", style="bold yellow")
            for base, ireg, disp, sz, is_w in d.mem_op:
                bv = r.reg(base) if base in ALL_REGS else 0
                iv = r.reg(ireg) if (ireg and ireg in ALL_REGS) else 0
                addr = (bv + iv + disp) & 0xffffffffffffffff
                kind = "写" if is_w else "读"
                out.append(f"  [{kind}] {addr:#018x}  size={sz}\n", style="white")
        return out


class TaintTab(Static):
    can_focus = False
    def __init__(self, trace: Trace, sym: SymbolMap, **kw):
        super().__init__(**kw); self.t = trace; self.sym = sym
        self.results = []; self.title = ""
    def set(self, title: str, results: list):
        self.title = title; self.results = results; self.refresh()
    def render(self) -> Text:
        out = Text()
        if not self.results:
            out.append("(尚未运行污点分析；按 f 正向 / b 反向)\n", style="dim"); return out
        out.append(f"{self.title} (共 {len(self.results)} 条)\n", style="bold cyan")
        for idx, why in self.results[:200]:
            r = self.t.record(idx); d = decode(r.pc, r.inst)
            fname, foff = self.sym.lookup(r.pc)
            f_ = f"{fname}+{foff:#x}" if fname != "?" else f"{r.pc:#x}"
            out.append(f" #{idx:6d}  {f_:<28s}  {d.mnemonic:<6s} {d.op_str}", style="white")
            if why: out.append(f"  ; {why}", style="dim")
            out.append("\n")
        if len(self.results) > 200:
            out.append(f"... 还有 {len(self.results)-200} 条 (已截断)\n", style="dim")
        return out


class StringsTab(Static):
    can_focus = False
    def __init__(self, trace: Trace, mem: MemShadow, **kw):
        super().__init__(**kw); self.t = trace; self.mem = mem; self.results = []
    def build(self):
        if not self.mem.built: self.mem.build()
        self.results = self.mem.find_strings(min_len=4); self.refresh()
    def render(self) -> Text:
        out = Text()
        if not self.results:
            out.append("(按 s 从内存 shadow 中提取字符串)\n", style="dim"); return out
        out.append(f"字符串 (共 {len(self.results)} 条)\n", style="bold cyan")
        for addr, s in self.results[:500]:
            out.append(f" {addr:#018x}  ", style="yellow")
            out.append(f"{s!r}\n", style="white")
        return out


class BlockMapTab(Static):
    can_focus = False
    def __init__(self, trace: Trace, sym: SymbolMap, **kw):
        super().__init__(**kw); self.t = trace; self.sym = sym
        self.cfg = None; self.cursor = 0; self.cols = 64
    def build(self):
        from .cfg import build_cfg
        self.cfg = build_cfg(self.t, only_module=True); self.refresh()
    def update_cursor(self, c: int):
        self.cursor = c
        if self.cfg is not None: self.refresh()
    def on_resize(self, e):
        self.cols = max(20, e.size.width - 4); self.refresh()
    def render(self) -> Text:
        out = Text()
        if self.cfg is None:
            out.append("(按 B 构建块导航图)\n", style="dim"); return out
        cur_pc = self.t.pc(self.cursor) if self.cursor < len(self.t) else 0
        starts = sorted(self.cfg.blocks.keys())
        cur_start = 0
        for s in starts:
            if s <= cur_pc: cur_start = s
            else: break
        base = self.t.meta.module.base if self.t.meta.module else 0
        out.append(f"块导航图: {len(self.cfg.blocks)} 块  当前=+{cur_start - base:#x}\n", style="bold cyan")
        out.append("图例: ░从未 · 1次 ▒ ≤5 ▓ ≤20 █ ≤100 ▓▓ >100  [Y]=当前光标块\n", style="dim")
        for i, s in enumerate(starts):
            blk = self.cfg.blocks[s]; ec = blk.executions
            if s == cur_start: ch, st = "[Y]", "black on bright_yellow"
            elif ec == 0:      ch, st = " ░ ", "dim"
            elif ec == 1:      ch, st = " · ", "white"
            elif ec <= 5:      ch, st = " ▒ ", "yellow"
            elif ec <= 20:     ch, st = " ▓ ", "bright_yellow"
            elif ec <= 100:    ch, st = " █ ", "red"
            else:              ch, st = "▓▓ ", "bright_red bold"
            out.append(ch, style=st)
            if (i + 1) % (self.cols // 3) == 0: out.append("\n")
        out.append("\n")
        if cur_start in self.cfg.blocks:
            b = self.cfg.blocks[cur_start]
            out.append(f"\n当前块 @ +{cur_start - base:#x}  指令数={len(b.insns)}  执行={b.executions}\n  出口: ", style="white")
            for tgt, kind in list(b.exits)[:5]:
                out.append(f"{kind}→+{tgt-base:#x} ", style="cyan")
            out.append("\n")
        return out


class CFGTab(Static):
    """交互式 CFG. 三种视图模式 (按 v 循环):
        graph (默认): IDA 风格 ASCII 图形，块 + 箭头连线
        list:        热点块列表 + 当前块详情 + 出/入边
        textual:     纯文本汇总
    """
    can_focus = True
    BINDINGS = [
        Binding("up", "block_prev", show=False),
        Binding("down", "block_next", show=False),
        Binding("enter", "jump_block_in_trace", show=False),
        Binding("right,l", "follow_first_exit", show=False),
        Binding("left,h", "go_predecessor", show=False),
        Binding("v", "cycle_view", show=False),
    ]
    VIEW_MODES = ["graph", "list", "textual"]
    def __init__(self, trace: Trace, sym: SymbolMap, **kw):
        super().__init__(**kw); self.t = trace; self.sym = sym
        self.cfg = None
        self.block_starts: list[int] = []
        self.selected = 0
        self.view_mode = "graph"
        self._app = None
        self._preds: dict[int, list[int]] = {}

    def build(self):
        from .cfg import build_cfg
        self.cfg = build_cfg(self.t, only_module=True)
        # sort blocks by execution count desc (hot first)
        self.block_starts = sorted(self.cfg.blocks.keys(),
                                   key=lambda pc: -self.cfg.blocks[pc].executions)
        self._preds = {}
        for (s, d), info in self.cfg.edges.items():
            self._preds.setdefault(d, []).append(s)
        self.refresh()

    def _selected_block_pc(self) -> int:
        if not self.block_starts: return 0
        return self.block_starts[max(0, min(self.selected, len(self.block_starts)-1))]

    def update_cursor_pc(self, pc: int):
        """Sync selection to the block containing this PC (called when main trace cursor moves)."""
        if not self.cfg: return
        starts = sorted(self.cfg.blocks.keys())
        cur_start = 0
        for s in starts:
            if s <= pc: cur_start = s
            else: break
        if cur_start in self.block_starts:
            self.selected = self.block_starts.index(cur_start)
            self.refresh()

    def action_block_prev(self):
        if self.selected > 0: self.selected -= 1; self.refresh()
    def action_block_next(self):
        if self.selected < len(self.block_starts) - 1: self.selected += 1; self.refresh()
    def action_jump_block_in_trace(self):
        if not self._app: return
        pc = self._selected_block_pc()
        # find first trace record with this PC
        for i in range(len(self.t)):
            if self.t.pc(i) == pc:
                self._app.goto_idx(i)
                self._app.status.update(f" 跳转到块 +{pc - (self.t.meta.module.base or 0):#x} (#{i})")
                return
    def action_follow_first_exit(self):
        if not self.cfg: return
        pc = self._selected_block_pc()
        b = self.cfg.blocks.get(pc)
        if not b or not b.exits: return
        # navigate to first exit's destination (in our sort order)
        nxt_pc, _kind = next(iter(b.exits))
        if nxt_pc in self.block_starts:
            self.selected = self.block_starts.index(nxt_pc)
            self.refresh()
    def action_go_predecessor(self):
        if not self.cfg: return
        pc = self._selected_block_pc()
        preds = self._preds.get(pc, [])
        if preds and preds[0] in self.block_starts:
            self.selected = self.block_starts.index(preds[0])
            self.refresh()
    def action_cycle_view(self):
        i = self.VIEW_MODES.index(self.view_mode)
        self.view_mode = self.VIEW_MODES[(i + 1) % len(self.VIEW_MODES)]
        self.refresh()
        if self._app:
            self._app.status.update(f" CFG 视图: {self.view_mode} (按 v 切换)")

    def on_click(self, evt):
        # Click on block list area to select; click on edge area to follow
        # Best-effort: row count -> selected
        try:
            row = evt.y - 1
            if 0 <= row < min(20, len(self.block_starts)):
                self.selected = row
                self.refresh()
        except Exception:
            pass

    def render(self) -> Text:
        out = Text()
        if self.cfg is None:
            out.append("(按 C 构建交互式 CFG)\n", style="dim"); return out
        base = self.t.meta.module.base if self.t.meta.module else 0
        cur_pc = self._selected_block_pc()
        # Mode dispatch
        if self.view_mode == "graph":
            from .cfg_graph import render_cfg_graph
            header = Text(f"CFG 图形视图 [{self.view_mode}]  v 切换  ↑↓ 选块  Enter 跳到主 trace\n",
                          style="bold cyan")
            body = render_cfg_graph(self.t, self.cfg, self.sym,
                                    focus_pc=cur_pc,
                                    max_layers=8, max_per_layer=4)
            header.append_text(body)
            return header
        elif self.view_mode == "textual":
            from .cfg import textual_summary
            out.append(f"CFG 文本汇总 [{self.view_mode}]  v 切换\n\n", style="bold cyan")
            out.append(textual_summary(self.cfg, base=base, top_n=50))
            return out

        # list mode (default for v3)
        out.append(f"CFG: {len(self.cfg.blocks)} 块 / {len(self.cfg.edges)} 边  | "
                   f"↑↓ 切换  Enter 跳到主 trace  → 跳到首个出边块  ← 跳到上游块  v 切换视图\n\n",
                   style="bold cyan")
        out.append("热点块列表 (执行次数排序)\n", style="bold yellow")
        for i, pc in enumerate(self.block_starts[:20]):
            b = self.cfg.blocks[pc]
            sel = "▶" if i == self.selected else " "
            fname, foff = self.sym.lookup(pc)
            f_ = f"{fname}+{foff:#x}" if fname != "?" else f"+{pc - base:#x}"
            line = f" {sel} +{pc - base:08x}  {f_:<28s}  ×{b.executions:5d}  {len(b.insns):3d} insn"
            style = "bold black on cyan" if i == self.selected else "white"
            out.append(line + "\n", style=style)
        if len(self.block_starts) > 20:
            out.append(f" ... 还有 {len(self.block_starts)-20} 块\n", style="dim")

        # Selected block detail
        b = self.cfg.blocks.get(cur_pc)
        if not b:
            return out
        out.append(f"\n┌─ 当前块 +{cur_pc - base:#x} ─ exec×{b.executions} ─ {len(b.insns)} 条 ─\n", style="bright_cyan bold")

        # Show all instructions in this block
        # Walk trace once to find first occurrence of cur_pc, then read consecutive insns
        first_idx = None
        for i in range(len(self.t)):
            if self.t.pc(i) == cur_pc:
                first_idx = i; break
        if first_idx is not None:
            for j, ipc in enumerate(b.insns[:30]):
                # find that instruction's record (rare: the basic block runs in
                # trace order, so insns in order; just use first_idx + j)
                if first_idx + j < len(self.t):
                    r = self.t.record(first_idx + j)
                    d = decode(r.pc, r.inst)
                    rel = f"+{r.pc - base:#x}" if base else f"{r.pc:#x}"
                    out.append(f"│ {rel:>10s}  {d.mnemonic:<7s} {d.op_str}\n", style="white")
            if len(b.insns) > 30:
                out.append(f"│ ... 还有 {len(b.insns)-30} 条\n", style="dim")
        out.append("└──────\n", style="bright_cyan bold")

        # Outgoing edges
        out.append("\n出边 (→ 目标块, ←/→ 跳转):\n", style="bold yellow")
        for tgt, kind in list(b.exits)[:8]:
            tb = self.cfg.blocks.get(tgt)
            tb_info = f"×{tb.executions} {len(tb.insns)} insn" if tb else "(块外)"
            tname, toff = self.sym.lookup(tgt)
            tn = f"{tname}+{toff:#x}" if tname != "?" else f"+{tgt-base:#x}"
            out.append(f"  ↓ {kind:<5s} → {tn:<28s}  {tb_info}\n", style="cyan")

        # Predecessors
        preds = self._preds.get(cur_pc, [])
        if preds:
            out.append("\n入边 (← 上游块, ← 跳转):\n", style="bold yellow")
            for p in preds[:5]:
                pb = self.cfg.blocks.get(p)
                pb_info = f"×{pb.executions}" if pb else "(块外)"
                pname, poff = self.sym.lookup(p)
                pn = f"{pname}+{poff:#x}" if pname != "?" else f"+{p-base:#x}"
                out.append(f"  ↑ {pn:<28s}  {pb_info}\n", style="green")
        return out


class StatusBar(Static): pass


class CFGFullScreen(Screen):
    """全屏 CFG 图形视图。Esc/q 返回主界面。"""
    BINDINGS = [
        Binding("escape,q", "app.pop_screen", "返回"),
        Binding("up", "block_prev"),
        Binding("down", "block_next"),
        Binding("enter", "jump_in_trace"),
        Binding("v", "cycle_view"),
        Binding("right,l", "follow_first_exit"),
        Binding("left,h", "go_predecessor"),
    ]
    CSS = """
    CFGFullScreen { layout: vertical; }
    #cfg-content { height: 1fr; padding: 0 1; border: round $accent; overflow: auto; }
    #cfg-status { height: 1; background: $accent; color: $background; padding: 0 1; }
    """
    def __init__(self, trace, sym):
        super().__init__()
        self.trace = trace; self.sym = sym
        self.cfg = None
        self.block_starts = []
        self.selected = 0
        self.view_mode = "graph"
        self._preds = {}
        self._app_ref = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with ScrollableContainer(id="cfg-content"):
            self.body = Static("(构建中…)", id="cfg-body")
            yield self.body
        self.cfg_status = Static("", id="cfg-status")
        yield self.cfg_status
        yield Footer()

    def on_mount(self):
        self.title = "CFG 全屏视图 — Esc/q 返回 | ↑↓ 切块 | Enter 跳到主trace | v 切视图 | ←→ 邻接块"
        self._build()
    def _build(self):
        from .cfg import build_cfg
        if self.cfg is None:
            self.cfg = build_cfg(self.trace, only_module=True)
            self.block_starts = sorted(self.cfg.blocks.keys(),
                                       key=lambda pc: -self.cfg.blocks[pc].executions)
            for (s, d), info in self.cfg.edges.items():
                self._preds.setdefault(d, []).append(s)
        self._refresh()
    def _selected_pc(self):
        if not self.block_starts: return 0
        return self.block_starts[max(0, min(self.selected, len(self.block_starts)-1))]
    def _refresh(self):
        cur_pc = self._selected_pc()
        if self.view_mode == "graph":
            from .cfg_graph import render_cfg_graph
            t = render_cfg_graph(self.trace, self.cfg, self.sym,
                                 focus_pc=cur_pc, max_layers=20, max_per_layer=6)
        elif self.view_mode == "list":
            t = self._render_list()
        else:
            from .cfg import textual_summary
            base = self.trace.meta.module.base if self.trace.meta.module else 0
            t = Text(textual_summary(self.cfg, base=base, top_n=80))
        self.body.update(t)
        self.cfg_status.update(
            f" 视图={self.view_mode}  ({self.selected+1}/{len(self.block_starts)})  "
            f"当前块=+{cur_pc - (self.trace.meta.module.base or 0):#x}  执行×{self.cfg.blocks[cur_pc].executions}  "
            f"|  v 切视图  ↑↓ 切块  Enter 主trace  Esc 返回"
        )
    def _render_list(self):
        out = Text()
        cur_pc = self._selected_pc()
        base = self.trace.meta.module.base if self.trace.meta.module else 0
        out.append(f"全部 {len(self.block_starts)} 个块（按热度）\n\n", style="bold cyan")
        for i, pc in enumerate(self.block_starts):
            b = self.cfg.blocks[pc]
            sel = "▶" if i == self.selected else " "
            fname, foff = self.sym.lookup(pc)
            f_ = f"{fname}+{foff:#x}" if fname != "?" else f"+{pc-base:#x}"
            line = f" {sel} +{pc-base:08x}  {f_:<30s}  ×{b.executions:5d}  {len(b.insns):3d} insn"
            style = "bold black on cyan" if i == self.selected else "white"
            out.append(line + "\n", style=style)
        # 详情
        b = self.cfg.blocks.get(cur_pc)
        if b:
            out.append(f"\n┌─ 当前块 +{cur_pc - base:#x} ─\n", style="bright_cyan bold")
            first_idx = None
            for i in range(len(self.trace)):
                if self.trace.pc(i) == cur_pc: first_idx = i; break
            if first_idx is not None:
                for j in range(min(20, len(b.insns))):
                    if first_idx + j < len(self.trace):
                        r = self.trace.record(first_idx + j)
                        d = decode(r.pc, r.inst)
                        out.append(f"│ +{r.pc-base:#x}  {d.mnemonic} {d.op_str}\n", style="white")
                if len(b.insns) > 20:
                    out.append(f"│ ... +{len(b.insns)-20}\n", style="dim")
            out.append("出边: ", style="bold yellow")
            for tgt, kind in list(b.exits)[:5]:
                tn, to_ = self.sym.lookup(tgt)
                out.append(f"  {kind}→{tn}+{to_:#x}", style="cyan")
            out.append("\n")
        return out

    def action_block_prev(self):
        if self.selected > 0: self.selected -= 1; self._refresh()
    def action_block_next(self):
        if self.selected < len(self.block_starts) - 1: self.selected += 1; self._refresh()
    def action_cycle_view(self):
        modes = ["graph", "list", "textual"]
        i = modes.index(self.view_mode)
        self.view_mode = modes[(i + 1) % len(modes)]
        self._refresh()
    def action_jump_in_trace(self):
        if not self._app_ref: return
        pc = self._selected_pc()
        for i in range(len(self.trace)):
            if self.trace.pc(i) == pc:
                self._app_ref.goto_idx(i)
                self.app.pop_screen()
                return
    def action_follow_first_exit(self):
        pc = self._selected_pc(); b = self.cfg.blocks.get(pc)
        if not b or not b.exits: return
        nxt, _ = next(iter(b.exits))
        if nxt in self.block_starts:
            self.selected = self.block_starts.index(nxt); self._refresh()
    def action_go_predecessor(self):
        pc = self._selected_pc()
        preds = self._preds.get(pc, [])
        if preds and preds[0] in self.block_starts:
            self.selected = self.block_starts.index(preds[0]); self._refresh()


# ---------- App ----------

class TraceMikuApp(App):
    CSS = """
    Screen { layout: vertical; }
    #main { height: 1fr; }
    #left  { width: 60%; height: 100%; border: round $accent; padding: 0 1; overflow: hidden; }
    #right { width: 40%; height: 100%; layout: vertical; }
    #regs  { height: 38%; border: round $accent; padding: 0 1; overflow: hidden; }
    #mem   { height: 32%; border: round $accent; padding: 0 1; overflow: hidden; }
    #tabs  { height: 30%; border: round $accent; }
    #status { height: 1; background: $accent; color: $background; }
    #cmdbar { height: 3; background: $surface; padding: 0 1; }
    #cmdbar.hidden { display: none; }
    #cmdprompt { color: $accent; min-width: 50; }
    #cmdinput { background: $surface; }
    """
    BINDINGS = [
        Binding("g", "open_goto", "跳转"),
        Binding("slash", "open_search", "搜索"),
        Binding("d", "jump_def", "定义"),
        Binding("u", "jump_use", "使用"),
        Binding("f", "open_taint('forward')", "正向污点"),
        Binding("b", "open_taint('backward')", "反向污点"),
        Binding("m", "open_mem", "内存"),
        Binding("s", "build_strings", "字符串"),
        Binding("C", "build_cfg_inline", "CFG"),
        Binding("F", "open_cfg_fullscreen", "CFG全屏"),
        Binding("B", "build_blockmap", "块图"),
        Binding("ctrl+s", "export_cfg_dot", "导出"),
        Binding("ctrl+o", "open_cfg_svg", "看SVG"),
        Binding("q", "quit_confirm", "退出"),
        Binding("escape", "close_cmd", show=False),
        Binding("?", "show_help", "?"),
    ]

    def __init__(self, trace_path: str):
        super().__init__()
        self.trace = load(trace_path)
        self.idx = Index(self.trace); self.idx.build()
        self.sym = build_from_trace(self.trace)
        self.mem = MemShadow(self.trace); self.mem.build()
        self.modules = collect_modules_from_trace(self.trace, self.mem)
        self._cmd_mode = None
        self._quit_pending = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main"):
            self.insn_view = InsnStream(self.trace, self.sym, id="left")
            self.insn_view._app = self
            yield self.insn_view
            with Vertical(id="right"):
                self.reg_view = RegPanel(self.trace, self.sym, self.mem, self.modules, id="regs")
                yield self.reg_view
                self.mem_view = MemPanel(self.trace, self.mem, id="mem"); yield self.mem_view
                with TabbedContent(id="tabs"):
                    with TabPane("交叉引用", id="tab-xref"):
                        self.xref_tab = XRefTab(self.trace, self.idx, self.sym); yield self.xref_tab
                    with TabPane("污点", id="tab-taint"):
                        self.taint_tab = TaintTab(self.trace, self.sym); yield self.taint_tab
                    with TabPane("字符串", id="tab-str"):
                        self.str_tab = StringsTab(self.trace, self.mem); yield self.str_tab
                    with TabPane("CFG", id="tab-cfg"):
                        self.cfg_tab = CFGTab(self.trace, self.sym)
                        self.cfg_tab._app = self
                        yield self.cfg_tab
                    with TabPane("块图", id="tab-bmap"):
                        self.bmap_tab = BlockMapTab(self.trace, self.sym); yield self.bmap_tab
        self.status = StatusBar("", id="status"); yield self.status
        with Horizontal(id="cmdbar", classes="hidden"):
            self.cmd_prompt = Label("", id="cmdprompt")
            yield self.cmd_prompt
            self.cmd_input = Input(placeholder="", id="cmdinput")
            yield self.cmd_input
        yield Footer()

    def on_mount(self):
        m = self.trace.meta
        title = "traceMiku 调试器"
        if m.method: title += f" — {m.method}"
        if m.cmd is not None: title += f"(cmd={m.cmd})"
        if m.module: title += f" — {m.module.name} @ 0x{m.module.base:x}"
        self.title = title
        self._sync_cursor()
        self.set_focus(self.insn_view)

    def _sync_cursor(self):
        c = self.insn_view.cursor
        self.reg_view.update_cursor(c)
        self.xref_tab.update_cursor(c)
        self.mem_view.update_cursor(c)
        self.bmap_tab.update_cursor(c)
        # If CFG is built, sync block selection to current PC
        if self.cfg_tab.cfg is not None:
            self.cfg_tab.update_cursor_pc(self.trace.pc(c))
        self.update_status()

    def update_status(self):
        c = self.insn_view.cursor
        n = len(self.trace)
        r = self.trace.record(c); d = decode(r.pc, r.inst)
        m = self.trace.meta
        rel = f"+0x{r.pc - m.module.base:x}" if m.module and m.module.base <= r.pc < m.module.end else f"{r.pc:#x}"
        fname, foff = self.sym.lookup(r.pc)
        finfo = f" [{fname}+{foff:#x}]" if fname != "?" else ""
        self.status.update(
            f" #{c}/{n}{finfo}  pc={rel}  {d.mnemonic} {d.op_str}   "
            f"(g 跳转 / 搜索 d/u 链 f/b 污点 m 内存 s 字符串 C/B CFG q 退出)"
        )

    def goto_idx(self, i: int):
        self.insn_view.cursor = max(0, min(len(self.trace) - 1, i))

    # ---- 命令栏 ----
    def _open_cmd(self, mode: str, prompt: str, prefill: str = ""):
        self._cmd_mode = mode
        self.cmd_prompt.update(prompt + " ")
        self.cmd_input.placeholder = prompt
        self.cmd_input.value = prefill
        self.query_one("#cmdbar").remove_class("hidden")
        self.set_focus(self.cmd_input)

    def action_close_cmd(self):
        self.query_one("#cmdbar").add_class("hidden")
        self._cmd_mode = None
        self._quit_pending = False
        self.set_focus(self.insn_view)

    def action_open_goto(self):
        self._open_cmd("goto",
                       "跳转 (#1234=按编号 / 0xabcd=按PC / @0xabcd=列出所有此PC的trace):")

    def action_open_search(self):
        self._open_cmd("search", "搜索反汇编 (正则, 不区分大小写):")

    def action_open_taint(self, direction: str):
        c = self.insn_view.cursor
        r = self.trace.record(c); d = decode(r.pc, r.inst)
        prefill = (d.regs_def[0] if direction == "forward" and d.regs_def else
                   d.regs_use[0] if direction == "backward" and d.regs_use else "")
        zh = "正向" if direction == "forward" else "反向"
        self._open_cmd(f"taint-{direction}",
                       f"{zh}污点追踪 (从 #{c}, 输寄存器名如 x0):", prefill)

    def action_open_mem(self):
        c = self.insn_view.cursor
        r = self.trace.record(c)
        self._open_cmd("mem", "查看内存地址 (16进制 0x... 或寄存器名 sp/x0..):", f"{r.sp:#x}")

    def action_quit_confirm(self):
        self._quit_pending = True
        self._open_cmd("quit", "确认退出？输 y 退出，其它取消:", "")

    # ---- 后台任务 ----
    def action_build_strings(self):
        self.status.update(" 正在提取字符串...")
        self.refresh()
        self.str_tab.build()
        self.status.update(f" 字符串: 共 {len(self.str_tab.results)} 条 (字符串 tab)")

    def action_build_cfg_inline(self):
        self.status.update(" 正在构建 CFG...")
        self.refresh()
        self.cfg_tab.build()
        self.cfg_tab.update_cursor_pc(self.trace.pc(self.insn_view.cursor))
        try: self.query_one("#tabs", TabbedContent).active = "tab-cfg"
        except Exception: pass
        self.status.update(f" CFG: {len(self.cfg_tab.cfg.blocks)} 块 — 按 F 进入全屏视图")

    def action_open_cfg_fullscreen(self):
        screen = CFGFullScreen(self.trace, self.sym)
        screen._app_ref = self
        # sync selected block to current cursor PC
        cur_pc = self.trace.pc(self.insn_view.cursor)
        def _select_after_mount():
            screen._build()
            starts = sorted(screen.cfg.blocks.keys())
            for s in starts:
                if s <= cur_pc: target = s
                else: break
            if target in screen.block_starts:
                screen.selected = screen.block_starts.index(target)
                screen._refresh()
        # push screen first; build will fire on_mount
        self.push_screen(screen)

    def action_build_blockmap(self):
        self.status.update(" 正在构建块导航图...")
        self.refresh()
        self.bmap_tab.build()
        self.status.update(f" 块导航图就绪 ({len(self.bmap_tab.cfg.blocks)} 块; 块图 tab)")

    def action_export_cfg_dot(self):
        cfg = self.cfg_tab.cfg or build_cfg(self.trace, only_module=True)
        if self.cfg_tab.cfg is None: self.cfg_tab.cfg = cfg
        base = self.trace.meta.module.base if self.trace.meta.module else 0
        out_dot = pathlib.Path(f"/tmp/cfg_{self.trace.meta.pid or 'trace'}.dot")
        out_svg = out_dot.with_suffix(".svg")
        write_dot(cfg, str(out_dot), base=base)
        try:
            subprocess.run(["dot", "-Tsvg", str(out_dot), "-o", str(out_svg)],
                           capture_output=True, timeout=30)
            self.status.update(f" CFG 已导出 → {out_svg} (Ctrl-O 在浏览器打开)")
        except Exception as e:
            self.status.update(f" CFG → {out_dot} (graphviz 没装? {e})")

    def action_open_cfg_svg(self):
        out_svg = pathlib.Path(f"/tmp/cfg_{self.trace.meta.pid or 'trace'}.svg")
        if not out_svg.exists():
            self.action_export_cfg_dot()
        if out_svg.exists():
            try:
                subprocess.Popen(["xdg-open", str(out_svg)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.status.update(f" 已打开 {out_svg}")
            except Exception as e:
                self.status.update(f" 打开失败: {e}")

    def action_jump_def(self):
        chain = self.idx.def_chain(self.insn_view.cursor)
        if not chain: self.status.update(" 当前指令无定义链"); return
        self.goto_idx(chain[0][1])

    def action_jump_use(self):
        chain = self.idx.use_chain(self.insn_view.cursor)
        if not chain: self.status.update(" 当前指令无使用链"); return
        self.goto_idx(chain[0][1])

    def action_show_help(self):
        self.status.update(
            " ↑↓/PgUp/PgDn 翻页 • g 跳转 • / 搜索 • d/u 跳转链 • f/b 污点 • m 内存 • s 字符串 • C/B CFG • Ctrl-S 导出 • q 退出"
        )

    # ---- 命令处理 ----
    def on_input_submitted(self, evt: Input.Submitted):
        v = evt.value.strip()
        m = self._cmd_mode
        self.action_close_cmd()
        if not v: return
        if m == "goto":     self._do_goto(v)
        elif m == "search": self._do_search(v)
        elif m == "mem":    self._do_mem(v)
        elif m == "quit":
            if v.lower() in ("y", "yes", "是"):
                self.exit()
            else:
                self.status.update(" 已取消退出")
        elif m and m.startswith("taint-"):
            self._do_taint(m.split("-")[1], v.lower())

    def _do_goto(self, v: str):
        try:
            v = v.strip()
            if v.startswith("#"):
                self.goto_idx(int(v[1:])); return
            if v.startswith("@"):
                # 列出 PC 的所有 trace 记录
                addr = int(v[1:], 16) if v[1:].startswith("0x") else int(v[1:], 16)
                hits = []
                for i in range(len(self.trace)):
                    if self.trace.pc(i) == addr:
                        hits.append(i)
                if not hits:
                    self.status.update(f" 没有 pc={addr:#x} 的记录"); return
                self.status.update(f" pc={addr:#x} 共 {len(hits)} 次执行: 编号 {hits[:10]}{' ...' if len(hits)>10 else ''}; 已跳到第一次")
                self.goto_idx(hits[0]); return
            # 尝试当成 PC
            addr = int(v, 16) if v.startswith("0x") else int(v)
            for i in range(len(self.trace)):
                if self.trace.pc(i) == addr:
                    self.goto_idx(i)
                    self.status.update(f" 跳到 pc={addr:#x} 第一次执行 (#{i})")
                    return
            # 否则当编号
            self.goto_idx(int(v))
        except Exception as e:
            self.status.update(f" 跳转失败: {e}")

    def _do_search(self, pattern: str):
        try: rx = re.compile(pattern, re.I)
        except Exception as e: self.status.update(f" 正则错误: {e}"); return
        for i in range(self.insn_view.cursor + 1, len(self.trace)):
            r = self.trace.record(i); d = decode(r.pc, r.inst)
            if rx.search(f"{d.mnemonic} {d.op_str}"):
                self.goto_idx(i); return
        self.status.update(f" 没有更多匹配 /{pattern}/")

    def _do_mem(self, v: str):
        try:
            v = v.strip().lower()
            if v in ALL_REGS:
                addr = self.trace.record(self.insn_view.cursor).reg(v)
            else:
                addr = int(v, 16) if v.startswith("0x") else int(v)
            self.mem_view.set_addr(addr)
            self.status.update(f" 内存视图 → {addr:#x}")
        except Exception as e:
            self.status.update(f" 内存解析失败: {e}")

    def _do_taint(self, direction: str, reg: str):
        c = self.insn_view.cursor
        if reg not in ALL_REGS:
            self.status.update(f" 不识别的寄存器名 {reg}"); return
        zh = "正向" if direction == "forward" else "反向"
        self.status.update(f" 正在跑 {zh}污点 {reg} 从 #{c}...")
        self.refresh()
        if direction == "forward":
            results = forward_taint(self.trace, c, reg, max_count=500)
        else:
            results = [(idx, "via " + r) for idx, r in
                       backward_taint(self.trace, c, reg, max_count=500)]
        title = f"{zh}污点 {reg} (从 #{c})"
        self.taint_tab.set(title, results)
        self.query_one("#tabs", TabbedContent).active = "tab-taint"
        if results: self.goto_idx(results[0][0])
        else: self.status.update(f" 无 {zh}污点结果 ({reg})")


def main():
    if len(sys.argv) < 2:
        print("用法: python3 -m viewer <trace目录或trace.bin文件>"); sys.exit(1)
    app = TraceMikuApp(sys.argv[1])
    app.run()


if __name__ == "__main__":
    main()
