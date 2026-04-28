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

__all__ = [
    "DecompilerBackend", "Function", "HlilLine", "FieldHint", "VarType",
    "DecompCache", "make_backend", "list_backends",
]
