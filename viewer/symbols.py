"""Function name inference from a trace, plus optional IDA symbol JSON.

We build a function map by scanning the trace for branch/call/return structure:
 - Every direct `bl <target>` adds <target> as a function entry
 - The first PC of the trace is a function entry (the hooked one)
 - For each entry, the function spans until a `ret` is encountered
 - PCs between entries are labeled as part of the surrounding function

This gives us reasonable `sub_<offset>` style names for the obfuscated SO,
plus exact ranges. If meta has a known fn_addr (e.g. doCommandNative), use it.
"""
from __future__ import annotations
import json, pathlib
from collections import defaultdict
from .trace import Trace
from .disasm import decode


class SymbolMap:
    """Lookup PC -> function name + offset within."""
    def __init__(self, base: int = 0):
        self.base = base
        self.functions: list[tuple[int, str]] = []   # sorted [(start_pc, name)]
        self._sorted = True

    def add(self, pc: int, name: str):
        self.functions.append((pc, name))
        self._sorted = False

    def _ensure_sorted(self):
        if not self._sorted:
            self.functions.sort(key=lambda x: x[0])
            self._sorted = True

    def lookup(self, pc: int) -> tuple[str, int]:
        """Return (name, offset_in_func). If pc is before any known func,
        returns ("?", 0)."""
        self._ensure_sorted()
        if not self.functions: return ("?", 0)
        # binary search for largest start_pc <= pc
        lo, hi = 0, len(self.functions)
        while lo < hi:
            mid = (lo + hi) // 2
            if self.functions[mid][0] <= pc:
                lo = mid + 1
            else:
                hi = mid
        if lo == 0: return ("?", 0)
        start, name = self.functions[lo - 1]
        return (name, pc - start)


def build_from_trace(trace: Trace, base: int = 0,
                     known_offsets: dict[int, str] | None = None) -> SymbolMap:
    """Walk the trace, identify function entries (bl targets + first PC),
    return a SymbolMap with sub_<offset> names.

    Args:
        known_offsets: Optional dict of {offset: name} for the target module.
            When provided, these offsets are used to align the trace start
            and name known functions. When None, pure heuristic (bl targets + first PC).
    """
    if base == 0 and trace.meta.module:
        base = trace.meta.module.base
    sm = SymbolMap(base=base)
    seen_entries = set()
    first_pc = trace.pc(0) if len(trace) > 0 else 0

    # Walk trace, collect bl targets (direct calls only)
    n = len(trace)
    for i in range(n):
        pc = trace.pc(i)
        inst = trace.inst(i)
        d = decode(pc, inst)
        if d.is_call and d.branch_target:
            seen_entries.add(d.branch_target)
        elif d.is_branch and not d.is_ret and not d.is_call:
            # Unconditional `b <target>` — sometimes tail-call to another func
            # We don't add these as functions; they may be intra-function jumps
            pass

    m = trace.meta
    # Add hooked function entry if known
    if m.module:
        if m.fn_addr:
            seen_entries.add(m.fn_addr)
        # Align trace start to nearest known function entry
        if known_offsets:
            first_off = first_pc - m.module.base if first_pc else -1
            aligned = False
            for off in known_offsets:
                if 0 <= first_off - off <= 0x80:
                    seen_entries.add(m.module.base + off)
                    aligned = True
                    break
            # If trace starts mid-function and we couldn't align, add as own entry
            if not aligned and first_pc:
                seen_entries.add(first_pc)
        elif first_pc:
            seen_entries.add(first_pc)
    elif first_pc:
        seen_entries.add(first_pc)

    # Drop entries that are already "inside" a known entry
    # (e.g. don't add sub_57780 when doCommandNative is at 57770)
    if m.module and known_offsets:
        known_starts = sorted(known_offsets.keys())
        filtered = set()
        for pc in seen_entries:
            off = pc - m.module.base
            covered = False
            for s in known_starts:
                if s <= off < s + 0x100:
                    covered = True
                    if pc == m.module.base + s:
                        # exact match — keep it (named entry)
                        filtered.add(pc)
                    break
            if not covered:
                filtered.add(pc)
        seen_entries = filtered

    # Convert to symbol entries
    for pc in seen_entries:
        name = None
        if m.module:
            off = pc - m.module.base
            if m.fn_addr and pc == m.fn_addr:
                name = m.method or (known_offsets.get(off, "func") if known_offsets else "func")
            elif known_offsets and off in known_offsets:
                name = known_offsets[off]
        if name is None:
            if base and pc >= base:
                name = f"sub_{pc - base:x}"
            else:
                name = f"sub_{pc:x}"
        sm.add(pc, name)
    return sm


def load_ida_symbols(json_path: str | pathlib.Path, base: int = 0) -> SymbolMap:
    """Load a JSON file like:
        [{"address": "0x570b8", "name": "JNI_OnLoad"}, ...]
    Addresses are relative offsets if base > 0; otherwise absolute.
    """
    sm = SymbolMap(base=base)
    raw = json.loads(pathlib.Path(json_path).read_text())
    for entry in raw:
        addr = entry["address"]
        if isinstance(addr, str):
            addr = int(addr, 16) if addr.startswith("0x") else int(addr)
        if base and addr < (1 << 32):  # treat as offset
            addr += base
        sm.add(addr, entry["name"])
    return sm
