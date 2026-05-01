"""Cross-reference + memory + string indexing for a loaded Trace.

Lazy-built indexes:
 - reg_defs[reg] -> list of insn indices that write to reg (sorted)
 - reg_uses[reg] -> list of insn indices that read from reg
 - mem_writes -> list of (idx, addr, size, value) (computed from base+disp regs)
 - mem_reads  -> list of (idx, addr, size, value)
 - strings   -> dict address -> string (extracted from regs/mem accesses)

Building all of these for a 67k record trace takes ~1-2 seconds.
"""
from __future__ import annotations
import struct
from collections import defaultdict
from .trace import Trace, REG_NAMES, ALL_REGS, addr_of
from .disasm import decode


class Index:
    def __init__(self, trace: Trace):
        self.t = trace
        self.reg_defs: dict[str, list[int]] = defaultdict(list)
        self.reg_uses: dict[str, list[int]] = defaultdict(list)
        self.mem_writes: list[tuple] = []   # (idx, addr, size, value)
        self.mem_reads: list[tuple] = []
        self.mem_addr_to_writes: dict[int, list[int]] = defaultdict(list)
        self.strings: dict[int, str] = {}
        self.built = False

    def build(self, progress=None):
        """Walk the trace once, populate all indexes."""
        if self.built: return
        n = len(self.t)
        for i in range(n):
            r = self.t.record(i)
            d = decode(r.pc, r.inst)
            for reg in d.regs_def:
                self.reg_defs[reg].append(i)
            for reg in d.regs_use:
                self.reg_uses[reg].append(i)
            # Mem ops: compute address if base+disp, treat index reg as 0 for now
            for base, idx_reg, disp, sz, is_write in d.mem_op:
                if not base:
                    continue
                addr = addr_of(r, (base, idx_reg, disp, sz, is_write))
                # value: post-execution we don't have, but we can capture written value
                # from a register (e.g. str x0, [x1] writes x0). Leave value=None.
                rec = (i, addr, sz, None)
                if is_write:
                    self.mem_writes.append(rec)
                    self.mem_addr_to_writes[addr].append(i)
                else:
                    self.mem_reads.append(rec)
            # Extract printable strings from any register that points to ASCII region
            # (cheap heuristic — full scan is in build_strings)
            if progress and (i & 0xfff) == 0:
                progress(i, n)
        self.built = True

    def def_chain(self, idx: int) -> list[tuple[str, int]]:
        """For instruction idx, return (reg, prev_def_idx) for each register it
        reads (i.e. where each input value was defined)."""
        r = self.t.record(idx)
        d = decode(r.pc, r.inst)
        out = []
        for reg in d.regs_use:
            if reg not in self.reg_defs: continue
            # Find largest def index < idx
            defs = self.reg_defs[reg]
            lo, hi = 0, len(defs)
            while lo < hi:
                mid = (lo + hi) // 2
                if defs[mid] < idx: lo = mid + 1
                else: hi = mid
            if lo > 0:
                out.append((reg, defs[lo-1]))
        return out

    def use_chain(self, idx: int) -> list[tuple[str, int]]:
        """For instruction idx, return (reg, next_use_idx) — instructions that
        consume registers written by this one (until next def)."""
        r = self.t.record(idx)
        d = decode(r.pc, r.inst)
        out = []
        for reg in d.regs_def:
            # Next-use up to next def of same reg
            if reg not in self.reg_uses: continue
            uses = self.reg_uses[reg]
            defs = self.reg_defs[reg]
            # find next def after idx
            lo, hi = 0, len(defs)
            while lo < hi:
                mid = (lo + hi) // 2
                if defs[mid] <= idx: lo = mid + 1
                else: hi = mid
            next_def = defs[lo] if lo < len(defs) else 10**18
            # find first use in (idx, next_def)
            ulo, uhi = 0, len(uses)
            while ulo < uhi:
                mid = (ulo + uhi) // 2
                if uses[mid] <= idx: ulo = mid + 1
                else: uhi = mid
            for u in uses[ulo:]:
                if u >= next_def: break
                out.append((reg, u))
                break  # Just first use
        return out

    def search_strings(self, query: str, max_results: int = 200) -> list[tuple[int, str]]:
        """Search for substring across captured strings."""
        q = query.lower()
        results = []
        for addr, s in self.strings.items():
            if q in s.lower():
                results.append((addr, s))
                if len(results) >= max_results: break
        return results

    def build_strings(self, min_len: int = 4):
        """Scan all register values for pointers that look like ASCII strings.
        Cheap heuristic: take each unique register value and check if it points
        to a printable string (we can't read target memory — but if the same
        value appears as an arg to bl/blr that takes a string, we can show it).
        For now: scan immediate-loaded register values; for real string pool we
        need on-device memory snapshots.
        """
        # Without memory snapshots we can't read string content. Stub.
        pass
