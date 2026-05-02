"""traceMiku — ARM64 instruction-level trace analysis toolkit.

Public API for scripting / Jupyter / LLM consumption:

    from viewer import load, build_from_trace, Index, MemShadow, decode
    from viewer import build_cfg, forward_taint, backward_taint

    t = load("traces/run1/calls/call_001_*/")
    print(len(t), "records")
    print(t.meta.module.name)             # e.g. libtarget-1.2.3.so

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
    SymbolMap, ModuleResolver, build_from_trace, load_ida_symbols,
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


# ── trace decompiler (路线 B — LLM-friendly skeleton IR) ──
def build_trace_ir(t, sym=None, only_module: bool = True,
                   split_top_k: int = 10, split_min_records: int = 50,
                   type_spec_paths=None,
                   detect_vm: bool = True, memshadow=None):
    """Build TraceIR from a Trace. See docs/trace-decompiler-design.md §3."""
    from .decompiler import build_trace_ir as _b
    return _b(t, sym=sym, only_module=only_module,
              split_top_k=split_top_k, split_min_records=split_min_records,
              type_spec_paths=type_spec_paths,
              detect_vm=detect_vm, memshadow=memshadow)


def write_decompile_dir(top, out_dir, tier: str = "full"):
    """Write summary.md + fns/<id>.md → out_dir/decompile/.

    tier ∈ {'full','hot','summary'} — see render_func_md.
    """
    from .decompiler import write_decompile_dir as _w
    return _w(top, out_dir, tier=tier)


__version__ = "0.3.0"

__all__ = [
    # trace
    "Trace", "Record", "Module", "TraceMeta",
    "load", "addr_of",
    "REG_NAMES", "ALL_REGS", "REC_SIZE",
    # disasm
    "decode", "Decoded", "fmt_insn",
    # symbols
    "SymbolMap", "ModuleResolver",
    "build_from_trace", "load_ida_symbols", "auto_known_offsets",
    # cfg
    "build_cfg", "CFG", "Block",
    "find_sccs", "loop_sccs", "write_dot", "textual_summary",
    # index / mem / taint
    "Index", "MemShadow", "forward_taint", "backward_taint",
    # decompiler (static bridge)
    "make_backend",
    # trace decompiler (路线 B)
    "build_trace_ir", "write_decompile_dir",
    # version
    "__version__",
]
