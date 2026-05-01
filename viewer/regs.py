"""ARM64 register name normalization — single source of truth for alias 处理.

ARM64 上同一个寄存器有多个写法:
  - x29 / fp:  ABI 上是 frame pointer; 工程内部 trace 存为 'fp'.
  - x30 / lr:  link register; 存为 'lr'.
  - w0..w30:   x0..x30 的低 32 位; 但内存里仍是同一寄存器, 归一化为 'x'.
  - xzr/wzr:   零寄存器 (永远读 0); 不存在于 trace, 用 'ZERO' sentinel.
  - wsp:       sp 的 32-bit alias, 归 'sp'.

两类调用点:
  - disasm 解 capstone 输出 → 用 normalize_disasm_reg (full transform: w→x +
    alias 映射 + 大小写归一).
  - webui 端点接收前端 / LLM 传入的 reg 名 → 用 canonical_reg (返 ALL_REGS 内
    canonical 名, 'ZERO' sentinel, 或 None — 让端点决定 400 还是返 0).
"""
from __future__ import annotations
from typing import Optional
from .trace import ALL_REGS


# 所有 ARM64 别名 → ALL_REGS 内对应名
REG_ALIASES = {
    "x29": "fp",
    "x30": "lr",
    "wsp": "sp",
}

# 零寄存器: 永远读 0, 不在 ALL_REGS 内. 用 'ZERO' sentinel 让上层端点直接返 0x0.
ZERO_REGS = {"xzr", "wzr"}


def normalize_disasm_reg(name: str) -> str:
    """capstone 给的 reg 名 → 工程内部 canonical 名 (存 trace 用).

    输入: 'w29', 'X30', 'WZR', 'wsp', 'fp', 'x0' …
    输出: 'fp', 'lr', 'xzr', 'sp', 'fp', 'x0' …  (空字符串 if input 空)
    """
    if not name:
        return ""
    n = name.lower()
    # w0..w30 → x0..x30 (同一物理寄存器)
    if n.startswith("w") and len(n) > 1 and n[1:].isdigit():
        return "x" + n[1:]
    if n in ZERO_REGS:
        return "xzr"
    return REG_ALIASES.get(n, n)


def canonical_reg(name: str) -> Optional[str]:
    """Validate reg name from external source (frontend/LLM).

    Returns:
        - 实际 ALL_REGS 内的 canonical 名 (e.g. 'fp', 'lr', 'x0', 'sp')
        - 'ZERO' sentinel for xzr/wzr (调用方应直接返 0x0, 不查 record)
        - None if reg name 不识别 (调用方应返 error)

    输入假定大小写已规范. 不做 w→x 转换 (前端/LLM 应先 normalize).
    """
    if name in ALL_REGS:
        return name
    if name in REG_ALIASES:
        return REG_ALIASES[name]
    if name in ZERO_REGS:
        return "ZERO"
    return None
