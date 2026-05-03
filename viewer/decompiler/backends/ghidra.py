"""Ghidra backend via pyghidra.

需要:
  pip install pyghidra
  GHIDRA_INSTALL_DIR=/home/ltlly/tools/ghidra (或安装时写 ~/.config/pyghidra)

加载策略: pyghidra.start() 启动 JVM 一次 (~10s, 全进程共享). open() 用
pyghidra.open_program() 创建临时 project + 跑 analyze. 之后 DecompInterface
长驻, 单函数 decompile ~50-200ms.

未实现: M0 只做 stub (确认 import 通就 return). 真正 hot-path 等 BN backend
跑稳后再补.
"""
from __future__ import annotations
import os, logging
from typing import Optional
from ..backend import Function, HlilLine, FieldHint, VarType


log = logging.getLogger(__name__)


class Backend:
    name = "ghidra"

    def __init__(self):
        self._unavailable_reason = ""
        self._pyghidra = None
        self._program = None
        self._decomp = None
        self._base = 0

    def is_available(self) -> bool:
        # M0 stub — open() 必抛 NotImplementedError, 所以 backend 不可用.
        # 之前返 True 让 factory 误把它当能用 backend, 用户选了直接 crash.
        # M1 实现 open 时把这块逻辑还原 (检查 pyghidra + GHIDRA_INSTALL_DIR).
        self._unavailable_reason = "ghidra backend not implemented (M0 stub)"
        return False

    def open(self, so_path: str, base: int = 0) -> None:
        raise NotImplementedError("ghidra backend M0 stub — implement in M1 phase 2")

    def close(self) -> None: pass
    def loaded_base(self) -> int: return 0
    def function_at(self, pc): return None
    def hlil_for(self, fn): return []
    def vars_for(self, fn): return []
    def field_at(self, pc, reg, offset): return None
    def xrefs_to(self, addr): return []
    def cfg_for(self, fn, mode='asm'): return [], []
    def asm_tokens_at(self, pc): return None
