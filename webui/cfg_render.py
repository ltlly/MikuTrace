"""Pure CFG rendering helpers — no closure variables, no side effects.

Moved from webui/server.py to reduce file size and improve testability.
Used by both /api/cfg-svg and /api/bn-cfg-svg-for-pc.
"""
from __future__ import annotations
from typing import Optional


def html_esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


# mnem 类别 → asm 颜色 (一个真理源, 两边渲染共用)
MNEM_COLORS = {
    "ret":    "#f85149",
    "call":   "#bc8cff",
    "branch": "#f7b32b",
    "":       "#d0d7de",   # default
}


def classify_mnem(text_or_mnem: str) -> str:
    """ASM 行第一个 token (mnem) → 'ret' | 'call' | 'branch' | ''.
    入参可以是整行 'sub  sp, sp, ...' 或仅 mnem 'sub'."""
    tx = text_or_mnem.lstrip()
    if not tx: return ""
    mnem = tx.split(maxsplit=1)[0].lower()
    if mnem == "ret": return "ret"
    if mnem in ("bl", "blr"): return "call"
    if mnem in ("b", "br", "cbz", "cbnz", "tbz", "tbnz") or mnem.startswith("b."):
        return "branch"
    return ""


def build_block_label(rows_html: list[str], border_color: str,
                      bg_color: str = "#161b22") -> str:
    """组 graphviz <TABLE> label. rows_html 是已经 escape 好的 <TR>...</TR>.
    返回 '<<TABLE...>...</TABLE>>' 可直接放 dot label= 后."""
    return ('<<TABLE BORDER="1" CELLBORDER="0" CELLSPACING="0" CELLPADDING="3" '
            f'COLOR="{border_color}" BGCOLOR="{bg_color}">'
            + "".join(rows_html) +
            "</TABLE>>")


# BN token cls → graphviz <FONT COLOR>. 镜像 styles.css .tok-* (一个真理源).
TOK_COLOR = {
    "key":   "#ff7b72",   "type":  "#ff7b72",   "reg":   "#79c0ff",
    "var":   "#56d4dd",   "num":   "#ffa657",   "str":   "#a5d6ff",
    "fn":    "#d2a8ff",   "data":  "#ffa657",   "field": "#f2cc60",
    "cmt":   "#8b949e",   "op":    "#d0d7de",   "sep":   "#d0d7de",
    "brace": "#ffa657",   "mnem":  "#c9d1d9",   "opcode":"#6e7681",
    "txt":   "#c9d1d9",   "label": "#ff7b72",   "tag":   "#f2cc60",
    "hex":   "#ffa657",   "other": "#d0d7de",
}


def render_tokens_html(tokens) -> str:
    """BN tokens → graphviz HTML 着色片段. skip 'meta' + 空文本 (graphviz HTML
    parser 会因空 <FONT></FONT> 报 syntax error). 纯空白 token 用 &nbsp; 防间距塌缩."""
    parts = []
    for tk in tokens:
        if tk.cls == "meta": continue
        text = tk.text
        if not text: continue                 # 空文本 token: 必跳, graphviz 不容空 <FONT>
        if not text.strip():
            parts.append(text.replace(" ", "&nbsp;"))
            continue
        col = TOK_COLOR.get(tk.cls, "#d0d7de")
        parts.append(f'<FONT COLOR="{col}">{html_esc(text)}</FONT>')
    return "".join(parts)


def format_insn_row(rel_str: str, mnem: str, ops: str,
                    pc_for_href: int, title: str,
                    tokens: list | None = None) -> str:
    """一条 insn 渲染成 <TR><TD HREF="#insn_<pc>" TITLE="...">+pc: mnem ops</TD></TR>.
    `tokens` 给定时 (BN CFG) 按 BN 词法 per-token 着色; 缺省 (trace CFG/capstone) 走
    粗粒度 mnem-color 模式."""
    if tokens:
        body = render_tokens_html(tokens)
        line = f'<FONT COLOR="#6e7681">{html_esc(rel_str)}:</FONT> {body}'
    else:
        fcol = MNEM_COLORS[classify_mnem(mnem)]
        line = (f'<FONT COLOR="#6e7681">{html_esc(rel_str)}:</FONT> '
                f'<FONT COLOR="{fcol}">{html_esc(mnem)}</FONT>')
        if ops:
            line += f' <FONT COLOR="#d0d7de">{html_esc(ops)}</FONT>'
    return (f'<TR><TD ALIGN="LEFT" HREF="#insn_{pc_for_href:x}" '
            f'TITLE="{html_esc(title)}">{line}</TD></TR>')


# BN CFG 专用: edge 颜色映射 + BB 边框色梯度 + token-based mnem/ops 切分

BN_EDGE_KIND_COLOR = {
    "true":     ("#3fb950", None),       # 绿 = cond taken
    "false":    ("#f85149", None),       # 红 = cond fall-through
    "uncond":   ("#58a6ff", None),       # 蓝 = unconditional
    "indirect": ("#d2a8ff", None),       # 紫 = indirect (OLLVM dispatcher)
    "ret":      ("#bc8cff", None),
    "call":     ("#bc8cff", "dashed"),
    "user":     ("#bc8cff", "dashed"),
    "exc":      ("#ff7b72", "dashed"),
    "syscall":  ("#ff7b72", None),
    "unres":    ("#6e7681", "dashed"),
}


def bn_bb_border_color(exec_count: int, is_current: bool) -> str:
    """BN BB 边框色: cursor 紫 / 0 灰 / 否则按 log10 梯度蓝→绿→红."""
    if is_current: return "#d2a8ff"
    if exec_count == 0: return "#30363d"
    import math
    t_lvl = min(math.log10(max(exec_count, 1)) / 3, 1.0)
    if t_lvl < 0.33:
        r = int(0x30 + t_lvl * 3 * 0x28); g = int(0x36 + t_lvl * 3 * 0x4a); bl = int(0x3d + t_lvl * 3 * 0x60)
    elif t_lvl < 0.66:
        f = (t_lvl - 0.33) * 3
        r = int(0x58 + f * 0x80); g = int(0x80 + f * 0x40); bl = int(0x9d - f * 0x60)
    else:
        f = (t_lvl - 0.66) * 3
        r = int(0xd8 + f * 0x20); g = int(0xc0 - f * 0x80); bl = int(0x3d - f * 0x20)
    clamp = lambda v: max(0, min(255, v))
    return f"#{clamp(r):02x}{clamp(g):02x}{clamp(bl):02x}"


def split_mnem_ops_from_tokens(line) -> tuple[str, str]:
    """从 HlilLine.tokens 拿精准 mnem / ops, fallback 是字符串切分.
    line 是 viewer.decompiler.backend.HlilLine."""
    mnem_tk = ""; ops_str = ""
    if line.tokens:
        seen_inst = False
        for tk in line.tokens:
            if tk.cls == "mnem" and not mnem_tk:
                mnem_tk = tk.text.strip(); seen_inst = True
            elif seen_inst and tk.cls != "mnem":
                ops_str += tk.text
    if not mnem_tk:
        parts = line.text.lstrip().split(maxsplit=1)
        mnem_tk = parts[0] if parts else ""
        ops_str = parts[1] if len(parts) > 1 else ""
    return mnem_tk, ops_str.strip()


def render_dot_to_svg(dot_text: str, timeout: int = 60) -> tuple[Optional[str], Optional[str]]:
    """Run dot subprocess, return (svg_str, None) on success or (None, err_str).
    err_str 包含 returncode != 0 时的 stderr 前 500 字符."""
    import subprocess
    try:
        r = subprocess.run(["dot", "-Tsvg"], input=dot_text, text=True,
                           capture_output=True, timeout=max(5, timeout))
    except FileNotFoundError:
        return None, "graphviz `dot` not found in PATH"
    except subprocess.TimeoutExpired:
        return None, f"dot timeout after {timeout}s"
    if r.returncode != 0:
        return None, (r.stderr or "")[:500]
    return r.stdout, None
