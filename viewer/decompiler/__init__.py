"""Decompiler bridge — pluggable backend over BN/Ghidra/IDA/r2.

Usage:
    from viewer.decompiler import make_backend, DecompCache

    bk = make_backend()                        # auto-select
    bk.open("/path/to/lib.so", base=0x6d52e7a000)
    fn = bk.function_at(0x6d52e7a780)
    for line in bk.hlil_for(fn):
        print(line.text)
"""
from .backend import DecompilerBackend, Function, HlilLine, FieldHint, VarType
from .cache import DecompCache
from .factory import make_backend, list_backends

# Trace decompiler (路线 B — LLM-friendly skeleton IR).
# 设计: docs/trace-decompiler-design.md
from .ir import TopIR, FuncIR, BlockIR, LoopIR, CallIR, EdgeIR
from .builder import build_trace_ir
from .render import render_summary_md, render_func_md, write_decompile_dir

__all__ = [
    # static decompiler bridge (existing)
    "DecompilerBackend", "Function", "HlilLine", "FieldHint", "VarType",
    "DecompCache", "make_backend", "list_backends",
    # trace decompiler (new, P2-DEC1)
    "TopIR", "FuncIR", "BlockIR", "LoopIR", "CallIR", "EdgeIR",
    "build_trace_ir",
    "render_summary_md", "render_func_md", "write_decompile_dir",
]
