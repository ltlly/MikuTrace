"""pwndbg/x64dbg-style smart value display.

Given a 64-bit value seen at a particular trace cursor, classify it and
recursively dereference up to N levels:
    0x6daecb8f70 -> [JNIEnv*]
    0x6c80144620 -> 0xb400006e... -> "myFunc"
    0x6be3eb5780 -> [myFunc+0x10] (code)
    0x111d6      -> 70102 (small int example)
    0x6c1e6bc240 -> [STACK]

Sources of info:
  - SymbolMap: code-pointer resolution
  - MemShadow: dereference values via observed reads/writes
  - module map: classify "in <target SO>/libart/etc"
  - heuristics: ascii string detection, stack region by SP, etc.
"""
from __future__ import annotations
from typing import Optional
from rich.text import Text
from .trace import Trace, ALL_REGS
from .symbols import SymbolMap
from .memshadow import MemShadow


# Approximate rough memory regions on Android arm64 (heuristic):
#  0x0..0x10000 — null + small int territory
#  0x6000000000..0x80_0000_0000 — text/data segments + heap
#  0x7f00000000..0x80_0000_0000 — typical libc/system ranges
#  Stack: anywhere relative to SP (varies by thread)
#  Java VM heap: 0xb400000000.. on Android (memtag-style tagged ptrs)


def is_in_known_module(modules: list[tuple[int, int, str]], v: int) -> tuple[str, int] | None:
    for base, end, name in modules:
        if base <= v < end:
            return (name, v - base)
    return None


def looks_like_ascii(b: bytes, min_print: float = 0.85) -> bool:
    if not b: return False
    n_print = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return (n_print / len(b)) >= min_print


def maybe_string_at(mem: MemShadow, addr: int, t: int, max_len: int = 64) -> str | None:
    """Try to read a NUL-terminated ASCII string from mem shadow."""
    out = bytearray()
    for o in range(max_len):
        b, kind, _ = mem.byte_at(addr + o, t)
        if b is None:
            if len(out) >= 4 and looks_like_ascii(bytes(out)):
                return out.decode("ascii", errors="replace")
            return None
        if b == 0:
            if len(out) >= 4 and looks_like_ascii(bytes(out)):
                return out.decode("ascii", errors="replace")
            return None
        out.append(b)
    if looks_like_ascii(bytes(out)):
        return out.decode("ascii", errors="replace") + "..."
    return None


def deref_u64(mem: MemShadow, addr: int, t: int) -> int | None:
    """Read 8 contiguous bytes via mem shadow, assemble little-endian u64.
    Returns None if any byte is unknown."""
    if addr & 7:  # require 8-byte alignment for cleanness
        # also try without alignment, but skip for speed
        pass
    val = 0
    for o in range(8):
        b, _, _ = mem.byte_at(addr + o, t)
        if b is None: return None
        val |= b << (o * 8)
    return val


def _heuristic_region(value: int) -> str | None:
    """Best-effort label for known Android process memory regions."""
    # JavaVM heap on Android (memtag/MTE) tagged pointers start with 0xb4
    if (value >> 56) == 0xb4:
        return "JavaHeap"
    # libart loads in the high 0x6d... range typically
    if 0x6d00000000 <= value < 0x6e00000000:
        return "libart?"
    # libc/linker around 0x70_00_00_00_00..0x80_00_00_00_00
    if 0x7000000000 <= value < 0x8000000000:
        return "libc?"
    return None


def classify(value: int,
             trace_cursor: int,
             trace: Trace,
             sym: SymbolMap,
             mem: MemShadow,
             modules: list[tuple[int, int, str]],
             sp: int = 0,
             max_depth: int = 3) -> Text:
    """pwndbg-style annotation: classifies a 64-bit value and recursively
    dereferences if it looks like a pointer."""
    out = Text()
    seen: set[int] = set()
    cur = value
    depth = 0
    while True:
        if cur in seen: out.append(" ↺", style="dim red"); return out
        seen.add(cur)
        # Plain zero
        if cur == 0:
            if depth == 0: out.append("  NULL", style="dim")
            return out
        # Stack region
        if sp and abs(cur - sp) < 0x20000:
            sign = "+" if cur >= sp else "-"
            out.append(f"  [SP{sign}{abs(cur-sp):#x}]", style="bright_black")
            return out
        # Code pointer in known module
        modhit = is_in_known_module(modules, cur)
        if modhit:
            mname, moff = modhit
            if trace.meta.module and mname == trace.meta.module.name:
                fname, foff = sym.lookup(cur)
                if fname != "?":
                    out.append(f"  [{fname}+{foff:#x}]", style="bright_cyan")
                else:
                    out.append(f"  [{mname}+{moff:#x}]", style="cyan")
            else:
                out.append(f"  [{mname}+{moff:#x}]", style="cyan")
            return out
        # Heuristic region (libart/libc/JavaHeap)
        hint = _heuristic_region(cur)
        # ASCII string at this address?
        s = maybe_string_at(mem, cur, trace_cursor)
        if s:
            out.append(f"  → {s!r}", style="green")
            return out
        # Dereference
        if depth < max_depth:
            nxt = deref_u64(mem, cur, trace_cursor)
            if nxt is not None and nxt != 0 and nxt != cur:
                if hint and depth == 0:
                    out.append(f"  ({hint})", style="bright_black")
                out.append(f"  → {nxt:#018x}", style="yellow")
                cur = nxt; depth += 1
                continue
        # Pointer-shaped but no shadow data
        if hint:
            out.append(f"  ({hint})", style="bright_black")
        # Small/medium int
        elif 0 < cur < 0x1000000:
            sign_ext = cur if cur < 0x80000000 else cur - 0x100000000
            if abs(sign_ext) < 0x10000:
                out.append(f"  ({sign_ext})", style="bright_black")
            else:
                out.append(f"  ({cur})", style="bright_black")
        return out


def build_jni_value_map(trace: Trace) -> dict[int, str]:
    """Build {reg_value → utf8_string} from JNI events.

    For each NewStringUTF event at trace_idx I with args.bytes=S, seed
    x1..x4 at idx I — by AAPCS the C-string ptr is x1, but wrappers may
    shift, so include neighbors as plausible matches.
    GetStringUTFChars ret value is in x0 only AFTER the call returns —
    can't capture from BL site without a separate snapshot, so skipped.
    """
    out: dict[int, str] = {}
    n = len(trace)
    for ev in trace.jni_events:
        if ev.get("id") != "NewStringUTF": continue
        idx = ev.get("trace_idx")
        if idx is None or idx < 0 or idx >= n: continue
        s = (ev.get("args") or {}).get("bytes")
        if not isinstance(s, str) or not s: continue
        r = trace.record(idx)
        for rn in ("x1", "x2", "x3", "x4"):
            v = r.reg(rn)
            if 0x10000 < v < (1 << 56):
                out.setdefault(v, s)
    return out


def format_reg_line(name: str, value: int,
                     trace_cursor: int, trace: Trace,
                     sym: SymbolMap, mem: MemShadow,
                     modules: list[tuple[int, int, str]], sp: int,
                     jni_value_map: Optional[dict[int, str]] = None) -> Text:
    """One register line in pwndbg style:
        x0 0x6daecb8f70  → [libart.so+0x...] → "..."

    jni_value_map: optional {ptr_value: utf8_string} from build_jni_value_map.
    When reg value matches, append `→ "<utf8>"` annotation.
    """
    line = Text()
    line.append(f"{name:>4s} ", style="yellow bold")
    line.append(f"{value:016x}", style="white")
    if value != 0:
        line.append_text(classify(value, trace_cursor, trace, sym, mem, modules, sp=sp))
    if jni_value_map and value in jni_value_map:
        s = jni_value_map[value]
        line.append(f"  → {s!r}", style="bright_green bold")
    return line


def collect_modules_from_trace(trace: Trace, mem: MemShadow) -> list[tuple[int, int, str]]:
    """Return list of (base, end, name). Uses meta.modules if available,
    falls back to meta.module only."""
    out = []
    if trace.meta.modules:
        for m in trace.meta.modules:
            out.append((m.base, m.end, m.name))
    elif trace.meta.module:
        m = trace.meta.module
        out.append((m.base, m.end, m.name))
    return out
