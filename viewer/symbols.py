"""Function name inference from a trace, plus optional IDA symbol JSON.

We build a function map by scanning the trace for branch/call/return structure:
 - Every direct `bl <target>` adds <target> as a function entry
 - The first PC of the trace is a function entry (the hooked one)
 - For each entry, the function spans until a `ret` is encountered
 - PCs between entries are labeled as part of the surrounding function

This gives us reasonable `sub_<offset>` style names for the obfuscated SO,
plus exact ranges. If meta has a known fn_addr (e.g. JNI_OnLoad), use it.
"""
from __future__ import annotations
import bisect, json, pathlib
from collections import defaultdict
from .trace import Trace, Module
from .disasm import decode


class ModuleResolver:
    """Map a PC to its module (one of trace.meta.modules).

    bisect-based, O(log N) per lookup. Vectorized variant available for
    bulk classify (a numpy uint64 array of PCs → numpy int array of module
    indices, with -1 for "not in any known module").
    """
    def __init__(self, modules: list[Module]):
        # Sort by base, keep parallel arrays for bisect
        self.modules = sorted(modules, key=lambda m: m.base)
        self._bases = [m.base for m in self.modules]
        self._ends = [m.end for m in self.modules]

    def resolve(self, pc: int) -> Module | None:
        """Single PC → Module (or None)."""
        if not self.modules: return None
        i = bisect.bisect_right(self._bases, pc) - 1
        if i < 0: return None
        m = self.modules[i]
        return m if pc < m.end else None

    def resolve_name(self, pc: int) -> str | None:
        m = self.resolve(pc)
        return m.name if m else None

    def vectorize(self, pcs):
        """numpy bulk: pcs (uint64 array) → int array of module indices,
        -1 for unmapped. ~10ms for 7M PCs."""
        import numpy as np
        if not self.modules:
            return np.full(len(pcs), -1, dtype=np.int32)
        bases = np.array(self._bases, dtype=np.uint64)
        ends = np.array(self._ends, dtype=np.uint64)
        idx = np.searchsorted(bases, pcs, side="right") - 1
        # Negative → before first module
        valid_floor = idx >= 0
        # If valid: check pc < ends[idx]
        idx_safe = np.where(valid_floor, idx, 0)
        within = pcs < ends[idx_safe]
        result = np.where(valid_floor & within, idx, -1).astype(np.int32)
        return result


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


def auto_known_offsets(trace: Trace) -> dict[int, str] | None:
    """Try to auto-discover known_offsets for the target SO.

    Lookup order:
      1. trace.meta.raw["known_offsets"] (per-call meta.json)
      2. <trace_dir>/known_offsets.json (next to trace.bin)
      3. <run_dir>/known_offsets.json (per-call dir's parent.parent if 'calls')
      4. examples/<so_basename>/known_offsets.json (project samples)

    Returns None if nothing found. Keys may be hex strings ("0x570b8") or ints;
    we normalize to int → str dict.
    """
    so_name = trace.meta.module.name if trace.meta.module else None
    candidates: list[pathlib.Path] = []

    # 1. inline in raw meta
    raw = getattr(trace.meta, "raw", None) or {}
    inline = raw.get("known_offsets")
    if isinstance(inline, dict):
        return _parse_offsets(inline)

    # 2. trace dir
    try:
        trace_dir = trace.path.parent if trace.path.is_file() else trace.path
    except Exception:
        trace_dir = None
    if trace_dir:
        candidates.append(trace_dir / "known_offsets.json")
        # 3. run dir (parent.parent if in calls/)
        if trace_dir.parent.name == "calls":
            candidates.append(trace_dir.parent.parent / "known_offsets.json")
        else:
            candidates.append(trace_dir.parent / "known_offsets.json")

    # 4. examples by SO basename
    if so_name:
        # libtarget-1.2.3.so -> libtarget
        stem = so_name.split("-")[0].split(".")[0]
        proj_root = pathlib.Path(__file__).resolve().parent.parent
        candidates.append(proj_root / "examples" / stem / "known_offsets.json")

    for p in candidates:
        try:
            if p.exists():
                return _parse_offsets(json.loads(p.read_text()))
        except Exception:
            continue
    return None


def _parse_offsets(raw: dict) -> dict[int, str]:
    out: dict[int, str] = {}
    for k, v in raw.items():
        try:
            ki = int(k, 16) if isinstance(k, str) else int(k)
            out[ki] = str(v)
        except Exception:
            continue
    return out


def build_from_trace(trace: Trace, base: int = 0,
                     known_offsets: dict[int, str] | None = None) -> SymbolMap:
    """Walk the trace, identify function entries (bl targets + first PC),
    return a SymbolMap with sub_<offset> names.

    Args:
        known_offsets: Optional dict of {offset: name} for the target module.
            When provided, these offsets are used to align the trace start
            and name known functions. When None, attempts auto-discovery
            via auto_known_offsets(trace); if still None, pure heuristic.
    """
    if known_offsets is None:
        known_offsets = auto_known_offsets(trace)
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
    # (e.g. don't add sub_1010 when myFunc is at 0x1000)
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
