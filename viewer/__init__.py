"""traceMiku — ARM64 instruction-level trace analysis toolkit.

Public API for scripting / Jupyter / LLM consumption:

    from viewer import load, build_from_trace, Index, MemShadow, decode
    from viewer import build_cfg, forward_taint, backward_taint

    t = load("traces/run1/calls/call_001_*/")
    print(len(t), "records")
    print(t.meta.module.name)             # libsgmainso-6.8.260403.so

    sym = build_from_trace(t)             # PC → function-name lookup
    idx = Index(t); idx.build()           # cross-reference index
    mem = MemShadow(t); mem.build()       # mem-shadow for byte-level reads

    cfg = build_cfg(t)                    # block-CFG from trace
    print(cfg.block_count, "blocks")

    hits = forward_taint(t, start_idx=100, taint_reg="x0", index=idx)
    chain = backward_taint(t, idx=200, taint_reg="x0", index=idx)

See `examples/llm_cookbook.py` for ready-to-run scripts.

For the web/REST/CLI surface see `webui/server.py` and `viewer/__main__.py`.
"""
from __future__ import annotations

# ── core trace loading ──
from .trace import (
    Trace, Record, Module, TraceMeta,
    load, addr_of,
    REG_NAMES, ALL_REGS, REC_SIZE,
)

# ── disassembly ──
from .disasm import decode, Decoded, fmt as fmt_insn

# ── symbol map (function names) ──
from .symbols import (
    SymbolMap, build_from_trace, load_ida_symbols,
    auto_known_offsets,
)

# ── basic-block CFG reconstruction from trace ──
from .cfg import (
    build_cfg, CFG, Block,
    find_sccs, loop_sccs, write_dot, textual_summary,
)

# ── cross-reference index (def/use chains, mem ops) ──
from .index import Index

# ── byte-level memory shadow built from store/load events ──
from .memshadow import MemShadow

# ── taint propagation ──
from .taint import forward_taint, backward_taint

# ── decompiler backend (BN/Ghidra/IDA/r2 — optional, lazy import) ──
def make_backend(name: str | None = None):
    """Lazy load — avoids pulling BN at import time."""
    from .decompiler import make_backend as _mb
    return _mb(name)


__version__ = "0.3.0"

__all__ = [
    # trace
    "Trace", "Record", "Module", "TraceMeta",
    "load", "addr_of",
    "REG_NAMES", "ALL_REGS", "REC_SIZE",
    # disasm
    "decode", "Decoded", "fmt_insn",
    # symbols
    "SymbolMap", "build_from_trace", "load_ida_symbols", "auto_known_offsets",
    # cfg
    "build_cfg", "CFG", "Block",
    "find_sccs", "loop_sccs", "write_dot", "textual_summary",
    # index / mem / taint
    "Index", "MemShadow", "forward_taint", "backward_taint",
    # decompiler
    "make_backend",
    # version
    "__version__",
]
