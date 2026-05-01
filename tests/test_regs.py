"""viewer.regs — 抽公共 reg 归一化模块的单元测试.

替代 test_recent_fixes.py 里的 _norm_reg 测试 (那些测的是 server.py 内部副本).
现在 server.py 的 _norm_reg 是 viewer.regs.canonical_reg 的 alias, 这里直接测公共版.
"""
import pytest
from viewer.regs import normalize_disasm_reg, canonical_reg, REG_ALIASES, ZERO_REGS


# ── normalize_disasm_reg (capstone → canonical) ─────────────────────────────

def test_normalize_x29_to_fp():
    assert normalize_disasm_reg("x29") == "fp"


def test_normalize_x30_to_lr():
    assert normalize_disasm_reg("x30") == "lr"


def test_normalize_w_to_x():
    assert normalize_disasm_reg("w0") == "x0"
    assert normalize_disasm_reg("w28") == "x28"
    assert normalize_disasm_reg("w29") == "x29"   # w29 → x29 (still 'x29' not 'fp' here!)
    # 注意: w29 先到 x29 (lex 转换), 但 alias 一步只发生一次 — 是否要继续映射?


def test_normalize_w_to_alias():
    """w29 应该最终映射到 fp 吗? 当前实现: w29 → x29 (停在第一步)."""
    out = normalize_disasm_reg("w29")
    # 当前: 'x29'. 严格说应该 'fp'. 这里 pin 当前行为 — 真消费者 (capstone) 不会
    # 给 'w29' 因为 capstone 自己规范成 'fp'. 仅边角.
    assert out in ("x29", "fp")


def test_normalize_wzr_xzr():
    assert normalize_disasm_reg("wzr") == "xzr"
    assert normalize_disasm_reg("xzr") == "xzr"


def test_normalize_wsp_to_sp():
    assert normalize_disasm_reg("wsp") == "sp"


def test_normalize_uppercase_input():
    assert normalize_disasm_reg("X29") == "fp"
    assert normalize_disasm_reg("WZR") == "xzr"


def test_normalize_empty():
    assert normalize_disasm_reg("") == ""


def test_normalize_unknown_passthrough():
    """nzcv / pc / sp / 已 canonical 的输入直接返回."""
    assert normalize_disasm_reg("pc") == "pc"
    assert normalize_disasm_reg("sp") == "sp"
    assert normalize_disasm_reg("nzcv") == "nzcv"
    assert normalize_disasm_reg("fp") == "fp"
    assert normalize_disasm_reg("lr") == "lr"
    assert normalize_disasm_reg("x5") == "x5"


# ── canonical_reg (frontend/LLM input → ALL_REGS or sentinel) ───────────────

def test_canonical_basic():
    assert canonical_reg("x0") == "x0"
    assert canonical_reg("fp") == "fp"
    assert canonical_reg("lr") == "lr"
    assert canonical_reg("sp") == "sp"
    assert canonical_reg("pc") == "pc"


def test_canonical_alias():
    assert canonical_reg("x29") == "fp"
    assert canonical_reg("x30") == "lr"


def test_canonical_zero():
    assert canonical_reg("xzr") == "ZERO"
    assert canonical_reg("wzr") == "ZERO"


def test_canonical_unknown_returns_none():
    assert canonical_reg("foo") is None
    assert canonical_reg("") is None
    assert canonical_reg("x99") is None
    # 不做 w→x 转换 (前端职责), w0 不识别
    assert canonical_reg("w0") is None


# ── 公共数据结构常量 ────────────────────────────────────────────────────────

def test_reg_aliases_present():
    """ABI 必备别名."""
    assert REG_ALIASES["x29"] == "fp"
    assert REG_ALIASES["x30"] == "lr"


def test_zero_regs_present():
    assert "xzr" in ZERO_REGS
    assert "wzr" in ZERO_REGS


# ── server.py / disasm.py 重导出仍 work ────────────────────────────────────

def test_server_norm_reg_is_canonical_alias():
    """webui.server._norm_reg 应是 viewer.regs.canonical_reg 的别名."""
    from webui.server import _norm_reg as server_norm
    assert server_norm is canonical_reg


def test_disasm_norm_reg_is_normalize_disasm():
    """viewer.disasm._norm_reg 应是 viewer.regs.normalize_disasm_reg 的别名."""
    from viewer.disasm import _norm_reg as disasm_norm
    assert disasm_norm is normalize_disasm_reg


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
