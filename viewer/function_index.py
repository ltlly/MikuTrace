"""Unified FunctionIndex consumed by Web UI / CLI / SDK.

A function entry can come from three sources:

  - "trace-ir": top-K calltree-derived TraceIR fns (F0..Fn).
  - "symbol":  any name in the SymbolMap (with block counts when CFG is available).
  - "bn":      Binary Ninja static functions (only if a BN backend is loaded).

Stable ids:

  - trace:F0 / trace:F1 / ...
  - sym:<name>
  - bn:<hex_addr>

Legacy aliases that the parser still accepts:

  - bare 'F0' → ('trace', 'F0')   (matches existing TraceIR.fn() lookup)
  - 'cfg:<name>' → ('sym', '<name>') (handoff baseline used 'cfg:')
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional


_TRACE_PREFIX = "trace:"
_SYM_PREFIX = "sym:"
_BN_PREFIX = "bn:"
_LEGACY_CFG_PREFIX = "cfg:"


def make_trace_id(trace_ir_id: str) -> str:
    if not trace_ir_id:
        raise ValueError("trace_ir_id required")
    return _TRACE_PREFIX + trace_ir_id


def make_sym_id(name: str) -> str:
    if not name:
        raise ValueError("name required")
    return _SYM_PREFIX + name


def make_bn_id(addr: int) -> str:
    return _BN_PREFIX + hex(int(addr))


def parse_id(fn_id: str) -> tuple[str, str]:
    """Return (source, payload).

    source ∈ {'trace', 'sym', 'bn'}; payload is the post-prefix string.
    Raises ValueError on unrecognized strings, empty payloads, or non-hex
    bn: payloads.
    """
    if not fn_id:
        raise ValueError("empty fn_id")
    if fn_id.startswith(_TRACE_PREFIX):
        payload = fn_id[len(_TRACE_PREFIX):]
        if not payload:
            raise ValueError(f"empty trace payload: {fn_id!r}")
        return "trace", payload
    if fn_id.startswith(_SYM_PREFIX):
        payload = fn_id[len(_SYM_PREFIX):]
        if not payload:
            raise ValueError(f"empty sym payload: {fn_id!r}")
        return "sym", payload
    if fn_id.startswith(_BN_PREFIX):
        payload = fn_id[len(_BN_PREFIX):]
        if not payload:
            raise ValueError(f"empty bn payload: {fn_id!r}")
        try:
            int(payload, 16)
        except ValueError:
            raise ValueError(f"bn payload is not valid hex: {fn_id!r}")
        return "bn", payload
    if fn_id.startswith(_LEGACY_CFG_PREFIX):
        payload = fn_id[len(_LEGACY_CFG_PREFIX):]
        if not payload:
            raise ValueError(f"empty cfg payload: {fn_id!r}")
        return "sym", payload
    if fn_id[:1] == "F" and fn_id[1:].isdigit():
        return "trace", fn_id
    raise ValueError(f"unrecognized fn_id: {fn_id!r}")


@dataclass(frozen=True)
class FunctionEntry:
    id: str
    name: str
    source: str          # "trace-ir" | "symbol" | "bn"
    entry_pc: Optional[int] = None
    blocks: int = 0
    # Index span between fn entry and exit in the trace, *not* an exact
    # record count — callees interrupt the span. Used as a rough size
    # hint for prompt-token estimation in the UI.
    records: int = 0
    trace_ir_id: Optional[str] = None
    bn_start: Optional[int] = None
    can_llil: bool = False
    can_bn_hlil: bool = False


@dataclass
class FunctionIndex:
    entries: list[FunctionEntry] = field(default_factory=list)

    def by_id(self, fn_id: str) -> Optional[FunctionEntry]:
        """Lookup by stable id. Returns None for unknown or malformed ids
        (parse errors are swallowed; use parse_id() directly to validate)."""
        try:
            src, payload = parse_id(fn_id)
        except ValueError:
            return None
        if src == "trace":
            for e in self.entries:
                if e.source == "trace-ir" and e.trace_ir_id == payload:
                    return e
            return None
        if src == "sym":
            for e in self.entries:
                if e.source == "symbol" and e.name == payload:
                    return e
            return None
        if src == "bn":
            try:
                addr = int(payload, 16)
            except ValueError:
                return None
            for e in self.entries:
                if e.source == "bn" and e.bn_start == addr:
                    return e
            return None
        return None

    def by_name(self, name: str) -> list[FunctionEntry]:
        """All entries with this name. May contain >1 entry when two
        TraceIR sub-fns share a symbol (legitimate weak-symbol case)."""
        return [e for e in self.entries if e.name == name]

    def __iter__(self) -> Iterable[FunctionEntry]:
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)


def build(*, trace=None, sym=None, top_ir=None, cfg=None,
          bn_funcs: Optional[list[tuple[int, str]]] = None) -> FunctionIndex:
    """Aggregate function entries from available sources.

    All inputs optional. When a TraceIR fn and a symbol fn share a name,
    the trace-ir entry wins for the slot keyed by name; the symbol entry
    is dropped from the result (no duplicates).

    Args:
        trace: viewer.Trace (currently unused but reserved for future record-counting).
        sym: viewer.symbols.SymbolMap.
        top_ir: viewer.decompiler.TopIR (for trace-ir entries).
        cfg: viewer.cfg.CFG (used to compute symbol-source block counts).
        bn_funcs: list of (entry_pc, name) tuples from a BN backend.
    """
    entries: list[FunctionEntry] = []
    seen_names: set[str] = set()

    # 1) trace-ir entries
    if top_ir is not None:
        for f in getattr(top_ir, "fns", []):
            records = 0
            if getattr(f, "entry_idx", None) is not None and \
               getattr(f, "exit_idx", None) is not None:
                records = max(0, int(f.exit_idx) - int(f.entry_idx) + 1)
            entries.append(FunctionEntry(
                id=make_trace_id(f.id),
                name=f.name,
                source="trace-ir",
                entry_pc=getattr(f, "pc_start", None),
                blocks=len(f.blocks),
                records=records,
                trace_ir_id=f.id,
                can_llil=True,
            ))
            seen_names.add(f.name)

    # 2) symbol entries (with CFG block counts when cfg is given)
    if cfg is not None and sym is not None:
        block_count_by_name: dict[str, int] = {}
        first_pc_by_name: dict[str, int] = {}
        for pc in cfg.blocks:
            name, _off = sym.lookup(pc)
            if not name or name == "?":
                continue
            block_count_by_name[name] = block_count_by_name.get(name, 0) + 1
            if name not in first_pc_by_name or pc < first_pc_by_name[name]:
                first_pc_by_name[name] = pc
        for name, blocks in sorted(block_count_by_name.items(),
                                   key=lambda kv: -kv[1]):
            if name in seen_names:
                continue
            entries.append(FunctionEntry(
                id=make_sym_id(name),
                name=name,
                source="symbol",
                entry_pc=first_pc_by_name.get(name),
                blocks=blocks,
                can_llil=True,
            ))
            seen_names.add(name)
    elif sym is not None:
        for pc, name in getattr(sym, "functions", []):
            if not name or name == "?" or name in seen_names:
                continue
            entries.append(FunctionEntry(
                id=make_sym_id(name),
                name=name,
                source="symbol",
                entry_pc=pc,
                blocks=0,
                can_llil=True,
            ))
            seen_names.add(name)

    # 3) bn entries
    for addr, name in (bn_funcs or []):
        if name in seen_names:
            continue
        entries.append(FunctionEntry(
            id=make_bn_id(addr),
            name=name,
            source="bn",
            entry_pc=int(addr),
            bn_start=int(addr),
            can_bn_hlil=True,
        ))
        seen_names.add(name)

    return FunctionIndex(entries=entries)
