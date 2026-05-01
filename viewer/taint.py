"""Forward + backward taint propagation on a trace.

Index-accelerated (O(|hits| · log N) instead of O(N²)):
  - reg_defs[reg] sorted list 给 bisect 找最近 def
  - reg_uses[reg] sorted list 给 bisect 找下一个 use
  - mem_writes 按 addr 索引找最近 store

Forward(idx, taint_reg) -> list[(insn_idx, why)]:
    传播 reg/mem taint. 当 reg 被 taint, 用 reg_uses[reg] 二分跳到下一个 use.

Backward(idx, taint_reg) -> list[(insn_idx, via)]:
    走 def-chain 找产生 taint_reg 值的指令链, 用 reg_defs[reg] bisect_left.
"""
from __future__ import annotations
import bisect
from collections import defaultdict
from .trace import Trace, ALL_REGS, addr_of as _addr_of
from .disasm import decode


def forward_taint(trace: Trace, start_idx: int, taint_reg: str,
                  max_count: int = 5000, depth: int = 0,
                  index=None):
    """Forward taint with heap-based next-use lookup.

    用 min-heap 维护每个 tainted reg 的 (next_use_idx, reg, cursor) 元组,
    每次 pop 最小 idx → O(|hits| · log R) where R 是 tainted reg 数.

    实测: heap 版本对长 chain (5000 hits) 上 ~10ms, 与 slow O(N decode)
    相当 (decode 有 lru_cache); 但对超长 trace 上 N >> hits 时, heap 版本
    跳过非 use 的 record 不 decode, 大幅省时.
    """
    if index is None:
        return _forward_taint_slow(trace, start_idx, taint_reg, max_count)

    import heapq
    tainted_regs = {taint_reg}
    tainted_mem: set[int] = set()
    out = []
    seen_idx = set()

    # heap entries: (next_use_idx, reg, cursor_pos_in_uses_list)
    heap: list = []
    def push_reg(reg, lo_idx):
        uses = index.reg_uses.get(reg, [])
        pos = bisect.bisect_right(uses, lo_idx)
        if pos < len(uses):
            heapq.heappush(heap, (uses[pos], reg, pos))
    push_reg(taint_reg, start_idx)

    while heap and len(out) < max_count:
        i, reg, pos = heapq.heappop(heap)
        # 推进 cursor: 这个 reg 下一个 use 入 heap
        uses = index.reg_uses.get(reg, [])
        if pos + 1 < len(uses):
            heapq.heappush(heap, (uses[pos+1], reg, pos+1))
        if i in seen_idx: continue
        # decode 此条
        r = trace.record(i); d = decode(r.pc, r.inst)
        used = tainted_regs & set(d.regs_use)
        load_tainted = False
        for op in d.mem_op:
            if op[4]: continue
            if _addr_of(r, op) in tainted_mem:
                load_tainted = True; break
        if not (used or load_tainted): continue
        why = []
        if used: why.append("regs:" + ",".join(sorted(used)))
        if load_tainted: why.append("mem")
        out.append((i, " ".join(why)))
        seen_idx.add(i)
        # propagate: 新 def 进 taint set + heap
        for nr in d.regs_def:
            if nr not in tainted_regs:
                tainted_regs.add(nr)
                push_reg(nr, i)
        for op in d.mem_op:
            if op[4]: tainted_mem.add(_addr_of(r, op))
    return out


def _forward_taint_slow(trace, start_idx, taint_reg, max_count):
    """老的 O(N) 实现, 没 index 时 fallback."""
    n = len(trace)
    tainted_regs = {taint_reg}
    tainted_mem: set[int] = set()
    out = []
    for i in range(start_idx + 1, n):
        if len(out) >= max_count: break
        r = trace.record(i); d = decode(r.pc, r.inst)
        used_tainted_reg = tainted_regs & set(d.regs_use)
        load_tainted = False
        for op in d.mem_op:
            if op[4]: continue
            a = _addr_of(r, op)
            if a in tainted_mem:
                load_tainted = True; break
        if not (used_tainted_reg or load_tainted): continue
        why = []
        if used_tainted_reg: why.append("regs:" + ",".join(sorted(used_tainted_reg)))
        if load_tainted: why.append("mem")
        out.append((i, " ".join(why)))
        for reg in d.regs_def: tainted_regs.add(reg)
        for op in d.mem_op:
            if op[4]: tainted_mem.add(_addr_of(r, op))
    return out


def backward_taint(trace: Trace, idx: int, taint_reg: str,
                   max_count: int = 5000, depth: int = 0,
                   index=None):
    """Index-accelerated backward taint.

    用 reg_defs[reg] bisect_left 找最近 def, mem_addr_to_writes 找 mem store.
    O(|chain| · log N) vs 旧 O(N²).
    """
    if index is None:
        return _backward_taint_slow(trace, idx, taint_reg, max_count)

    out = []
    visited = set()
    pending: list[tuple[int, str]] = []
    # 处理起点: 如果 idx 自己 def 了 taint_reg, 算它是源, 然后找它的 inputs
    r0 = trace.record(idx); d0 = decode(r0.pc, r0.inst)
    if taint_reg in d0.regs_def:
        out.append((idx, taint_reg))
        visited.add((idx, taint_reg))
        for u in d0.regs_use:
            pending.append((idx, u))
        # mem load 也要追溯 store
        for op in d0.mem_op:
            if op[4]: continue
            a = _addr_of(r0, op)
            pending.append(("MEM", idx, a))
    else:
        pending.append((idx, taint_reg))

    while pending and len(out) < max_count:
        item = pending.pop(0)
        if item[0] == "MEM":
            _, before_idx, addr = item
            writes = index.mem_addr_to_writes.get(addr, [])
            pos = bisect.bisect_left(writes, before_idx) - 1
            if pos < 0: continue
            j = writes[pos]
            r = trace.record(j); d = decode(r.pc, r.inst)
            if d.regs_use:
                pending.append((j, d.regs_use[0]))
            continue
        cur_idx, want_reg = item
        if (cur_idx, want_reg) in visited: continue
        visited.add((cur_idx, want_reg))
        defs = index.reg_defs.get(want_reg, [])
        pos = bisect.bisect_left(defs, cur_idx) - 1
        if pos < 0: continue
        j = defs[pos]
        out.append((j, want_reg))
        r = trace.record(j); d = decode(r.pc, r.inst)
        for u in d.regs_use:
            pending.append((j, u))
        for op in d.mem_op:
            if op[4]: continue
            a = _addr_of(r, op)
            pending.append(("MEM", j, a))

    seen_idx = set(); dedup = []
    for ix, reg in sorted(out):
        if ix in seen_idx: continue
        seen_idx.add(ix); dedup.append((ix, reg))
    return dedup


def _backward_taint_slow(trace, idx, taint_reg, max_count):
    """老的 O(N²) 实现, 没 index 时 fallback."""
    out = []
    visited = set()
    r0 = trace.record(idx); d0 = decode(r0.pc, r0.inst)
    if taint_reg in d0.regs_def:
        out.append((idx, taint_reg)); visited.add((idx, taint_reg))
        pending = [(idx, u) for u in d0.regs_use]
    else:
        pending = [(idx, taint_reg)]
    while pending and len(out) < max_count:
        cur_idx, want_reg = pending.pop(0)
        if (cur_idx, want_reg) in visited: continue
        visited.add((cur_idx, want_reg))
        for j in range(cur_idx - 1, -1, -1):
            r = trace.record(j); d = decode(r.pc, r.inst)
            if want_reg in d.regs_def:
                out.append((j, want_reg))
                for u in d.regs_use: pending.append((j, u))
                break
    seen_idx = set(); dedup = []
    for ix, reg in sorted(out):
        if ix in seen_idx: continue
        seen_idx.add(ix); dedup.append((ix, reg))
    return dedup
