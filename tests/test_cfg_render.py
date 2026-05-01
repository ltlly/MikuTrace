"""Pure helpers in webui/cfg_render.py — pin 行为防 graphviz dot string 渲染回归.

这些函数被 /api/cfg-svg 和 /api/bn-cfg-svg-for-pc 大量调用. 一旦 escape / 颜色映射
出错, 整个 CFG SVG 渲染会废 (graphviz 报 syntax error 或前端着色错乱).
"""
import pytest


def test_html_esc_escapes_basics():
    from webui.cfg_render import html_esc
    assert html_esc("a&b") == "a&amp;b"
    assert html_esc("a<b") == "a&lt;b"
    assert html_esc("a>b") == "a&gt;b"
    assert html_esc('a"b') == "a&quot;b"


def test_html_esc_amp_first_avoids_double_escape():
    from webui.cfg_render import html_esc
    # 必须先 & 再 < > " — 否则 a<b → a&lt;b → a&amp;lt;b 双转义
    assert html_esc("&lt;") == "&amp;lt;"


def test_classify_mnem_categories():
    from webui.cfg_render import classify_mnem
    assert classify_mnem("ret") == "ret"
    assert classify_mnem("bl sub_xxx") == "call"
    assert classify_mnem("blr x8") == "call"
    assert classify_mnem("b sub_yy") == "branch"
    assert classify_mnem("br x16") == "branch"
    assert classify_mnem("b.eq #+8") == "branch"
    assert classify_mnem("b.ne label") == "branch"
    assert classify_mnem("cbz x0, label") == "branch"
    assert classify_mnem("cbnz w1, lab") == "branch"
    assert classify_mnem("tbz x0, #1, lab") == "branch"
    assert classify_mnem("tbnz") == "branch"


def test_classify_mnem_default_empty():
    from webui.cfg_render import classify_mnem
    assert classify_mnem("add") == ""
    assert classify_mnem("sub  sp, sp, ...") == ""
    assert classify_mnem("mov") == ""
    assert classify_mnem("") == ""
    assert classify_mnem("   ") == ""


def test_classify_mnem_case_insensitive():
    """capstone 可能给出大小写各异 (虽然实际默认小写); 防御性测试."""
    from webui.cfg_render import classify_mnem
    assert classify_mnem("RET") == "ret"
    assert classify_mnem("BL foo") == "call"


def test_mnem_colors_keys_present():
    from webui.cfg_render import MNEM_COLORS
    # classify_mnem 出的 4 种 key 必须都有 fallback 颜色
    for k in ("ret", "call", "branch", ""):
        assert k in MNEM_COLORS, f"MNEM_COLORS 缺 key {k!r}"


def test_build_block_label_wraps_table():
    from webui.cfg_render import build_block_label
    rows = ["<TR><TD>a</TD></TR>", "<TR><TD>b</TD></TR>"]
    out = build_block_label(rows, "#aaa")
    assert out.startswith("<<TABLE")
    assert out.endswith("</TABLE>>")
    assert 'COLOR="#aaa"' in out
    assert "<TR><TD>a</TD></TR>" in out
    assert "<TR><TD>b</TD></TR>" in out


def test_build_block_label_custom_bg():
    from webui.cfg_render import build_block_label
    out = build_block_label([], "#fff", bg_color="#000")
    assert 'BGCOLOR="#000"' in out


def test_format_insn_row_capstone_fallback():
    """capstone 模式 (无 BN tokens) 走 mnem-color 着色."""
    from webui.cfg_render import format_insn_row
    out = format_insn_row("+0x10", "bl", "sub_xxx", 0x6f7a000010, "title text")
    assert 'HREF="#insn_6f7a000010"' in out
    assert "TITLE=\"title text\"" in out
    assert "+0x10" in out
    assert "bl" in out
    assert "sub_xxx" in out


def test_format_insn_row_with_bn_tokens():
    """BN tokens 模式: 走 render_tokens_html, 不再用 mnem 字符串."""
    from webui.cfg_render import format_insn_row
    class Tk:
        def __init__(self, cls, text): self.cls=cls; self.text=text
    tokens = [Tk("mnem", "ret"), Tk("op", " ")]
    out = format_insn_row("+0x4", "ret", "", 0x100, "t", tokens=tokens)
    assert 'HREF="#insn_100"' in out
    assert "ret" in out


def test_render_tokens_html_skip_meta():
    """meta token 必须跳, 否则 graphviz HTML parser 因空 <FONT></FONT> 报 syntax error."""
    from webui.cfg_render import render_tokens_html
    class Tk:
        def __init__(self, cls, text): self.cls=cls; self.text=text
    out = render_tokens_html([Tk("meta", "ignored"), Tk("mnem", "ret")])
    assert "ignored" not in out
    assert "ret" in out


def test_render_tokens_html_skip_empty_text():
    """空文本 token 也要跳 (graphviz 不容空 <FONT></FONT>)."""
    from webui.cfg_render import render_tokens_html
    class Tk:
        def __init__(self, cls, text): self.cls=cls; self.text=text
    out = render_tokens_html([Tk("mnem", ""), Tk("op", "x0")])
    assert "x0" in out
    # 无空 FONT 标签
    assert "<FONT COLOR=\"#79c0ff\"></FONT>" not in out


def test_render_tokens_html_pure_whitespace_uses_nbsp():
    """空白 token (e.g., '   ') 用 &nbsp; 代替, 防 graphviz 间距塌缩."""
    from webui.cfg_render import render_tokens_html
    class Tk:
        def __init__(self, cls, text): self.cls=cls; self.text=text
    out = render_tokens_html([Tk("op", "  ")])
    assert "&nbsp;" in out


def test_render_tokens_html_escape_text():
    from webui.cfg_render import render_tokens_html
    class Tk:
        def __init__(self, cls, text): self.cls=cls; self.text=text
    out = render_tokens_html([Tk("op", "<bad>")])
    assert "&lt;bad&gt;" in out
    assert "<bad>" not in out   # 原始 < 不应直接出现 (除 FONT 标签自身)


def test_bn_edge_kind_color_known_kinds():
    from webui.cfg_render import BN_EDGE_KIND_COLOR
    # 至少这些 kind 必须有定义 (BN CFG 的核心边色)
    for kind in ("true", "false", "uncond", "indirect", "ret", "call"):
        assert kind in BN_EDGE_KIND_COLOR, f"缺 kind {kind!r}"
        color, style = BN_EDGE_KIND_COLOR[kind]
        assert color.startswith("#"), f"{kind}: color 不是 hex"


def test_bn_bb_border_color_zero_is_gray():
    from webui.cfg_render import bn_bb_border_color
    c = bn_bb_border_color(0, is_current=False)
    assert c == "#30363d"


def test_bn_bb_border_color_current_is_purple():
    from webui.cfg_render import bn_bb_border_color
    c = bn_bb_border_color(100, is_current=True)
    # cursor 块紫色 — 防御性 pin
    assert c.lower() == "#d2a8ff"


def test_bn_bb_border_color_gradient_distinct():
    """实现: log10(exec)/3 ∈ [0,1] 三段式映射. exec=1 时 log=0, 与 0-gray 同色
    (由设计 — 单次执行块视觉上不强调). exec=100 / 1000 应有不同色."""
    from webui.cfg_render import bn_bb_border_color
    c100 = bn_bb_border_color(100, False)
    c1000 = bn_bb_border_color(1000, False)
    assert c100 != "#30363d", f"exec=100 不应是 zero-gray, got {c100}"
    assert c1000 != "#30363d", f"exec=1000 不应是 zero-gray, got {c1000}"
    assert c100 != c1000, f"exec=100 vs 1000 颜色应不同, 都是 {c100}"


def test_split_mnem_ops_from_tokens_with_tokens():
    from webui.cfg_render import split_mnem_ops_from_tokens
    class Line:
        text = "mov x0, x1"
        tokens = None
    class Tk:
        def __init__(self, cls, text): self.cls=cls; self.text=text
    line = Line()
    line.tokens = [Tk("mnem", "mov"), Tk("op", " "), Tk("reg", "x0"),
                   Tk("op", ", "), Tk("reg", "x1")]
    m, ops = split_mnem_ops_from_tokens(line)
    assert m == "mov"
    assert "x0" in ops and "x1" in ops


def test_split_mnem_ops_from_tokens_fallback_string():
    """无 tokens 时走 line.text 切分."""
    from webui.cfg_render import split_mnem_ops_from_tokens
    class Line:
        tokens = None
        text = "  add  x0, x0, #1"
    m, ops = split_mnem_ops_from_tokens(Line())
    assert m == "add"
    assert "x0" in ops


def test_render_dot_to_svg_handles_missing_dot(monkeypatch):
    """graphviz `dot` 不在 PATH 时, 端点应返回 (None, err) 而非崩."""
    from webui.cfg_render import render_dot_to_svg
    def fake_run(*args, **kwargs): raise FileNotFoundError("dot")
    import subprocess as sp
    monkeypatch.setattr(sp, "run", fake_run)
    svg, err = render_dot_to_svg("digraph G { a -> b; }")
    assert svg is None
    assert err is not None
    assert "dot" in err.lower() or "not found" in err.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
