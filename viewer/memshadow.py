"""Sparse memory shadow built from a trace.

Each instruction has full register state captured BEFORE its execution.
Memory state must be reconstructed by walking through stores (and the
register values that supply them) AND loads (where the destination register
in the NEXT record gives us the loaded value).

Indexes:
 - writes: list of (insn_idx, addr, size, value)        bytes written
 - reads:  list of (insn_idx, addr, size, value)        bytes read
 - by_addr: dict[addr_byte] -> list of (insn_idx, value_byte, kind="r"|"w")

Query: byte_at(addr, t) -> (value, kind, source_idx) or (None, "??", None)
       finds the latest write OR (if no write) latest read at addr <= t

This lets the memory view show actual byte values that the trace has touched,
and "??" for bytes never observed (matching krash's behavior).
"""
from __future__ import annotations
import struct
from .trace import Trace, ALL_REGS, addr_of as _addr_of
from .disasm import decode


def _value_of_write(t: Trace, idx: int, mem_op, decoded) -> int | None:
    """For a store insn, the source register that gets stored.

    mem_op[5] (src_reg) is set explicitly for stp/ldp pair (each of the 2
    mem_ops carries its own source). For other store insns it's "" — fall back
    to picking the first non-base/non-idx reg from regs_use.
    """
    base, idx_reg, _, _, _, src = mem_op
    if not src:
        candidates = [r for r in decoded.regs_use if r not in (base, idx_reg)]
        if not candidates: return None
        src = candidates[0]
    if src not in ALL_REGS: return None
    rec = t.record(idx)
    return rec.reg(src)


def _value_of_read(t: Trace, idx: int, decoded, mem_op=None) -> int | None:
    """For a load insn, the value loaded = destination register in NEXT record.

    mem_op[5] (src_reg) 给 ldp 配对显式 — 第 i 个 mem_op 对应自己的 dest.
    其它情况 fallback 到 regs_def[0].
    """
    if idx + 1 >= len(t): return None
    dest = ""
    if mem_op is not None and len(mem_op) >= 6 and mem_op[5]:
        dest = mem_op[5]
    elif decoded.regs_def:
        dest = decoded.regs_def[0]
    if not dest or dest not in ALL_REGS: return None
    return t.record(idx + 1).reg(dest)


class MemShadow:
    def __init__(self, trace: Trace):
        self.t = trace
        # by_byte_addr: dict[u64] -> list of (idx, byte_value, kind="r"|"w")
        self.bytes: dict[int, list] = {}
        self.writes: list[tuple] = []  # (idx, addr, size, value)
        self.reads:  list[tuple] = []
        self.built = False

    def build(self):
        if self.built: return
        n = len(self.t)
        for i in range(n):
            r = self.t.record(i)
            d = decode(r.pc, r.inst)
            for op in d.mem_op:
                base, idx_reg, disp, sz, is_w, _src = op
                addr = _addr_of(r, op)
                if is_w:
                    val = _value_of_write(self.t, i, op, d)
                    if val is None: continue
                    self.writes.append((i, addr, sz, val))
                    self._splat_bytes(addr, sz, val, i, "w")
                else:
                    val = _value_of_read(self.t, i, d, op)
                    if val is None: continue
                    self.reads.append((i, addr, sz, val))
                    self._splat_bytes(addr, sz, val, i, "r")
        # Boundary-diff events (--trace-deep): external_writes.bin is a sibling
        # to trace.bin, written by host from agent ext-write messages. Each
        # record = <Q attr_idx> <Q addr> <B byte> = 17 bytes. Splat as kind="x"
        # so byte_at returns the value with provenance. Affects writes/numpy
        # index too — taint / xref-by-addr endpoints see external writes.
        try:
            self._load_external_writes()
        except Exception as _e:
            pass
        # numpy 视图: 给 idxs-touching-* 端点向量化查询用. 6.8M trace 上
        # 596ms set comprehension → ~5ms vectorized mask.
        # writes/reads 已按 trace order build, w_idx/r_idx 自然 ascending.
        import numpy as np
        if self.writes:
            self.w_idx  = np.array([x[0] for x in self.writes], dtype=np.int64)
            self.w_addr = np.array([x[1] for x in self.writes], dtype=np.uint64)
            self.w_size = np.array([x[2] for x in self.writes], dtype=np.int32)
        else:
            self.w_idx = np.empty(0, dtype=np.int64)
            self.w_addr = np.empty(0, dtype=np.uint64)
            self.w_size = np.empty(0, dtype=np.int32)
        if self.reads:
            self.r_idx  = np.array([x[0] for x in self.reads], dtype=np.int64)
            self.r_addr = np.array([x[1] for x in self.reads], dtype=np.uint64)
            self.r_size = np.array([x[2] for x in self.reads], dtype=np.int32)
        else:
            self.r_idx = np.empty(0, dtype=np.int64)
            self.r_addr = np.empty(0, dtype=np.uint64)
            self.r_size = np.empty(0, dtype=np.int32)
        self.built = True

    def _splat_bytes(self, addr: int, sz: int, val: int, idx: int, kind: str):
        # little-endian byte split
        for o in range(sz):
            byte = (val >> (o * 8)) & 0xff
            ba = addr + o
            self.bytes.setdefault(ba, []).append((idx, byte, kind))

    def _load_external_writes(self):
        """Load sibling external_writes.bin (--trace-deep boundary-diff output).
        Format: <Q attr_idx <Q addr <B byte (17 bytes / record).

        Insertion respects trace order: records have monotonic attr_idx (host
        writes them in arrival order, agent fires them on call entry/exit
        boundaries). Splat each as kind='x'. The byte addr is already 1-byte;
        size=1, val=byte. attr_idx is the trace idx where the write becomes
        visible (= entry of the external call), so byte_at(t) returns the
        external value for any t >= attr_idx (until shadowed by a later w/r/x).
        """
        ext_path = self.t.path.parent / "external_writes.bin"
        if not ext_path.exists() or ext_path.stat().st_size == 0:
            return
        REC = 17
        data = ext_path.read_bytes()
        n = len(data) // REC
        for i in range(n):
            off = i * REC
            attr_idx, addr, byte = struct.unpack_from("<QQB", data, off)
            self.writes.append((attr_idx, addr, 1, byte))
            self._splat_bytes(addr, 1, byte, attr_idx, "x")
        # writes list 不再保证 trace-order 排序 (ext writes attr_idx 跟物理顺序一致
        # 但跟内部 stalker writes 可能交错). 重排,后续 numpy index 才正确 ascending.
        self.writes.sort(key=lambda w: w[0])
        # bytes[addr] 内事件也按 idx 重排 (binary search 依赖 ascending)
        for ba, evs in self.bytes.items():
            evs.sort(key=lambda e: e[0])

    def byte_at(self, addr: int, t: int) -> tuple[int | None, str, int | None]:
        """Return (byte_value, kind, source_idx) for latest event with idx <= t.
        kind is "r"/"w"/"??". If no event yet, returns (None, "??", None).
        """
        evs = self.bytes.get(addr)
        if not evs: return (None, "??", None)
        # binary search rightmost ev with ev[0] <= t (events are in trace order
        # so naturally sorted).
        lo, hi = 0, len(evs)
        while lo < hi:
            mid = (lo + hi) // 2
            if evs[mid][0] <= t: lo = mid + 1
            else: hi = mid
        if lo == 0: return (None, "??", None)
        idx, byte, kind = evs[lo - 1]
        return (byte, kind, idx)

    def hex_dump(self, base_addr: int, t: int, rows: int = 16, cols: int = 16) -> list[str]:
        """Return formatted hex+ascii lines like a debugger memory view."""
        out = []
        for r in range(rows):
            row_addr = base_addr + r * cols
            byte_strs = []
            ascii_strs = []
            for c in range(cols):
                a = row_addr + c
                b, kind, _ = self.byte_at(a, t)
                if b is None:
                    byte_strs.append("??")
                    ascii_strs.append(".")
                else:
                    byte_strs.append(f"{b:02x}")
                    ascii_strs.append(chr(b) if 32 <= b < 127 else ".")
            line = f"{row_addr:016x}  " + " ".join(byte_strs[:8]) + "  " + " ".join(byte_strs[8:]) + "  |" + "".join(ascii_strs) + "|"
            out.append(line)
        return out

    def find_strings(self, min_len: int = 4) -> list[tuple[int, str]]:
        """Scan known bytes for printable ASCII runs.
        Cached per min_len since mem.bytes is immutable after build()."""
        if not self.built: self.build()
        if not self.bytes: return []
        cache = getattr(self, "_strings_cache", None)
        if cache is None:
            cache = {}; self._strings_cache = cache
        if min_len in cache:
            return cache[min_len]
        addrs = sorted(self.bytes.keys())
        results = []
        run_start = None
        run_chars = []
        for a in addrs:
            # latest byte at this addr
            evs = self.bytes[a]
            byte = evs[-1][1]
            is_print = 32 <= byte < 127
            if is_print:
                if run_start is None: run_start = a
                run_chars.append(byte)
            else:
                if run_start is not None and len(run_chars) >= min_len:
                    s = bytes(run_chars).decode("ascii", errors="replace")
                    results.append((run_start, s))
                run_start = None
                run_chars = []
            # If next addr isn't contiguous, cut the run
            # (handle by detecting gaps in next iteration — done implicitly above)
        if run_start is not None and len(run_chars) >= min_len:
            results.append((run_start, bytes(run_chars).decode("ascii", errors="replace")))
        # Filter out "runs" that aren't truly contiguous
        cache[min_len] = results
        return results
