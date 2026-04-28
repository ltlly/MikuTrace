"""Null backend — always available, all queries return empty.

Lets viewer run without any decompiler installed: the HLIL tab simply shows
"no backend configured" and the rest of the trace UI keeps working.
"""
from __future__ import annotations
from typing import Optional
from ..backend import DecompilerBackend, Function, HlilLine, FieldHint, VarType


class Backend:
    name = "none"
    _unavailable_reason = ""

    def is_available(self) -> bool: return True
    def open(self, so_path: str, base: int = 0) -> None: pass
    def close(self) -> None: pass
    def loaded_base(self) -> int: return 0
    def function_at(self, pc: int) -> Optional[Function]: return None
    def hlil_for(self, fn: Function) -> list[HlilLine]: return []
    def vars_for(self, fn: Function) -> list[VarType]: return []
    def field_at(self, pc, reg, offset) -> Optional[FieldHint]: return None
    def xrefs_to(self, addr: int) -> list[int]: return []
    def cfg_for(self, fn, mode="asm"): return [], []
    def asm_tokens_at(self, pc): return None
