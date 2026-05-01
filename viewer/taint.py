"""Forward + backward taint propagation on a trace + data-only chase.

Index-accelerated (O(|hits| · log N) instead of O(N²)):
  - reg_defs[reg] sorted list 给 bisect 找最近 def
  - reg_uses[reg] sorted list 给 bisect 找下一个 use
  - mem_writes 按 addr 索引找最近 store

Forward(idx, taint_reg) -> list[(insn_idx, why)]:
    传播 reg/mem taint. 当 reg 被 taint, 用 reg_uses[reg] 二分跳到下一个 use.

Backward(idx, taint_reg) -> list[(insn_idx, via)]:
    走 def-chain 找产生 taint_reg 值的指令链, 用 reg_defs[reg] bisect_left.

Both forward/backward accept:
    exclude_regs: set[str] of regs to skip propagation through (default {sp,fp,lr})
                  — frame pointer / stack pointer chains otherwise dominate.
    data_only:    bool. When True, on `ldr dst, [base, #imm]` (load), do NOT
                  propagate through `base` reg — only follow the mem store chain.
                  This is the AI-逆向 mode: only real data flow, no addressing noise.

data_chase(idx, taint_reg) -> list[ChaseStep]:
    Single-path data chase, the workflow LLM agents need most. Walks one
    chain backward from a register, following mov/ldr/str across functions,
    skipping frame pointer noise.
"""
from __future__ import annotations
import bisect
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional
from .trace import Trace, ALL_REGS, addr_of as _addr_of
from .disasm import decode


# Default frame regs that LLM agents almost always want to skip during
# taint propagation. Override via exclude_regs= param.
DEFAULT_FRAME_REGS = frozenset({"sp", "fp", "lr"})


def _propagation_regs(d, mem_addressing_regs, *, exclude_regs, data_only):
    """Filter d.regs_use to the set we should actually propagate through.

    - Always exclude `exclude_regs`.
    - In data_only mode, also exclude regs that are only used as addressing
      operands (base/index of a mem op), so we follow the mem chain instead
      of the address-arithmetic chain.
    """
    out = []
    for u in d.regs_use:
        if u in exclude_regs:
            continue
        if data_only and u in mem_addressing_regs:
            continue
        out.append(u)
    return out


def _addressing_regs(d):
    """Set of regs used purely as base/index of mem ops in this insn."""
    s = set()
    for op in d.mem_op:
        if op[0]: s.add(op[0])
        if op[1]: s.add(op[1])
    return s


def forward_taint(trace: Trace, start_idx: int, taint_reg: str,
                  max_count: int = 5000, depth: int = 0,
                  index=None,
                  exclude_regs: Optional[set] = None,
                  data_only: bool = False):
    """Forward taint with heap-based next-use lookup.

    用 min-heap 维护每个 tainted reg 的 (next_use_idx, reg, cursor) 元组,
    每次 pop 最小 idx → O(|hits| · log R) where R 是 tainted reg 数.

    实测: heap 版本对长 chain (5000 hits) 上 ~10ms. 对超长 trace 上 N >> hits
    时, heap 版本跳过非 use 的 record 不 decode, 大幅省时.
    """
    if index is None:
        return _forward_taint_slow(trace, start_idx, taint_reg, max_count,
                                    exclude_regs=exclude_regs, data_only=data_only)
    if exclude_regs is None:
        exclude_regs = set(DEFAULT_FRAME_REGS) if data_only else set()
    else:
        exclude_regs = set(exclude_regs)

    import heapq
    tainted_regs = {taint_reg}
    tainted_mem: set[int] = set()
    out = []
    seen_idx = set()

    heap: list = []
    def push_reg(reg, lo_idx):
        if reg in exclude_regs: return
        uses = index.reg_uses.get(reg, [])
        pos = bisect.bisect_right(uses, lo_idx)
        if pos < len(uses):
            heapq.heappush(heap, (uses[pos], reg, pos))
    push_reg(taint_reg, start_idx)

    while heap and len(out) < max_count:
        i, reg, pos = heapq.heappop(heap)
        uses = index.reg_uses.get(reg, [])
        if pos + 1 < len(uses):
            heapq.heappush(heap, (uses[pos+1], reg, pos+1))
        if i in seen_idx: continue
        r = trace.record(i); d = decode(r.pc, r.inst)
        addr_regs = _addressing_regs(d) if data_only else set()
        # In data_only, an insn only counts as "used" if the tainted use is
        # NOT purely an addressing reg.
        used = tainted_regs & set(d.regs_use)
        if data_only:
            used = used - addr_regs
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
        for nr in d.regs_def:
            if nr in exclude_regs: continue
            if nr not in tainted_regs:
                tainted_regs.add(nr)
                push_reg(nr, i)
        for op in d.mem_op:
            if op[4]: tainted_mem.add(_addr_of(r, op))
    return out


def _forward_taint_slow(trace, start_idx, taint_reg, max_count,
                         exclude_regs=None, data_only=False):
    """老的 O(N) 实现, 没 index 时 fallback. 同样支持 exclude_regs/data_only."""
    if exclude_regs is None:
        exclude_regs = set(DEFAULT_FRAME_REGS) if data_only else set()
    else:
        exclude_regs = set(exclude_regs)
    n = len(trace)
    tainted_regs = {taint_reg}
    tainted_mem: set[int] = set()
    out = []
    for i in range(start_idx + 1, n):
        if len(out) >= max_count: break
        r = trace.record(i); d = decode(r.pc, r.inst)
        addr_regs = _addressing_regs(d) if data_only else set()
        used_tainted_reg = tainted_regs & set(d.regs_use)
        if data_only: used_tainted_reg = used_tainted_reg - addr_regs
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
        for reg in d.regs_def:
            if reg in exclude_regs: continue
            tainted_regs.add(reg)
        for op in d.mem_op:
            if op[4]: tainted_mem.add(_addr_of(r, op))
    return out


def backward_taint(trace: Trace, idx: int, taint_reg: str,
                   max_count: int = 5000, depth: int = 0,
                   index=None,
                   exclude_regs: Optional[set] = None,
                   data_only: bool = False):
    """Index-accelerated backward taint.

    用 reg_defs[reg] bisect_left 找最近 def, mem_addr_to_writes 找 mem store.
    O(|chain| · log N) vs 旧 O(N²).

    With exclude_regs / data_only, propagation is filtered to skip
    addressing-only regs (sp/fp/lr) and base/index regs of loads.
    """
    if index is None:
        return _backward_taint_slow(trace, idx, taint_reg, max_count,
                                     exclude_regs=exclude_regs, data_only=data_only)
    if exclude_regs is None:
        exclude_regs = set(DEFAULT_FRAME_REGS) if data_only else set()
    else:
        exclude_regs = set(exclude_regs)

    out = []
    visited = set()
    pending: list[tuple] = []
    r0 = trace.record(idx); d0 = decode(r0.pc, r0.inst)
    addr_regs0 = _addressing_regs(d0) if data_only else set()
    if taint_reg in d0.regs_def and taint_reg not in exclude_regs:
        out.append((idx, taint_reg))
        visited.add((idx, taint_reg))
        for u in _propagation_regs(d0, addr_regs0,
                                    exclude_regs=exclude_regs, data_only=data_only):
            pending.append((idx, u))
        for op in d0.mem_op:
            if op[4]: continue
            a = _addr_of(r0, op)
            pending.append(("MEM", idx, a))
    elif taint_reg not in exclude_regs:
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
            # store 的 source reg = 第一个非 base/index 的 regs_use
            base_w = d.mem_op[0][0] if d.mem_op else None
            idx_w = d.mem_op[0][1] if d.mem_op else None
            src_candidates = [u for u in d.regs_use
                              if u not in (base_w, idx_w) and u not in exclude_regs]
            if src_candidates:
                pending.append((j, src_candidates[0]))
            continue
        cur_idx, want_reg = item
        if want_reg in exclude_regs: continue
        if (cur_idx, want_reg) in visited: continue
        visited.add((cur_idx, want_reg))
        defs = index.reg_defs.get(want_reg, [])
        pos = bisect.bisect_left(defs, cur_idx) - 1
        if pos < 0: continue
        j = defs[pos]
        out.append((j, want_reg))
        r = trace.record(j); d = decode(r.pc, r.inst)
        addr_regs = _addressing_regs(d) if data_only else set()
        for u in _propagation_regs(d, addr_regs,
                                    exclude_regs=exclude_regs, data_only=data_only):
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


def _backward_taint_slow(trace, idx, taint_reg, max_count,
                          exclude_regs=None, data_only=False):
    """老的 O(N²) 实现, 没 index 时 fallback."""
    if exclude_regs is None:
        exclude_regs = set(DEFAULT_FRAME_REGS) if data_only else set()
    else:
        exclude_regs = set(exclude_regs)
    out = []
    visited = set()
    r0 = trace.record(idx); d0 = decode(r0.pc, r0.inst)
    addr_regs0 = _addressing_regs(d0) if data_only else set()
    if taint_reg in d0.regs_def and taint_reg not in exclude_regs:
        out.append((idx, taint_reg)); visited.add((idx, taint_reg))
        pending = [(idx, u) for u in
                   _propagation_regs(d0, addr_regs0,
                                      exclude_regs=exclude_regs, data_only=data_only)]
    elif taint_reg not in exclude_regs:
        pending = [(idx, taint_reg)]
    else:
        pending = []
    while pending and len(out) < max_count:
        cur_idx, want_reg = pending.pop(0)
        if want_reg in exclude_regs: continue
        if (cur_idx, want_reg) in visited: continue
        visited.add((cur_idx, want_reg))
        for j in range(cur_idx - 1, -1, -1):
            r = trace.record(j); d = decode(r.pc, r.inst)
            if want_reg in d.regs_def:
                out.append((j, want_reg))
                addr_regs = _addressing_regs(d) if data_only else set()
                for u in _propagation_regs(d, addr_regs,
                                            exclude_regs=exclude_regs, data_only=data_only):
                    pending.append((j, u))
                break
    seen_idx = set(); dedup = []
    for ix, reg in sorted(out):
        if ix in seen_idx: continue
        seen_idx.add(ix); dedup.append((ix, reg))
    return dedup


# ──────────────────────────── data_chase (Gap-F) ────────────────────────────

@dataclass
class ChaseStep:
    """One step of a data-chase chain."""
    idx: int
    pc: int
    asm: str                  # "mnemonic op_str"
    via: str                  # "reg:x8" / "mem-load" / "mem-store-src"
    reg_or_addr: str          # the source reg name OR hex addr being followed


def data_chase(trace: Trace, start_idx: int, taint_reg: str,
               max_steps: int = 50,
               exclude_regs: Optional[set] = None,
               index=None) -> list[ChaseStep]:
    """Single-path backward data chase across functions.

    The killer workflow LLM agents need: from a register at `start_idx`, walk
    one chain to the real data source — skipping sp/fp/lr noise, handling:
      - `mov dst, src`        → follow src
      - `ldr dst, [base, #N]` → follow mem store at (base+N), then store's src
      - other arithmetic     → follow first non-excluded reg_use

    Stops when:
      - max_steps reached
      - chain hits a constant (e.g. `mov dst, #imm`, no reg deps)
      - chain hits an unobserved mem write (no recorded store to that addr)
      - cycle detected (same (idx, reg) twice)

    Requires `index` (Index built). Without it returns an empty list.
    """
    if index is None: return []
    if exclude_regs is None:
        exclude_regs = set(DEFAULT_FRAME_REGS)
    else:
        exclude_regs = set(exclude_regs)

    cur_idx = start_idx
    cur_reg = taint_reg
    seen = set()
    out: list[ChaseStep] = []

    while len(out) < max_steps:
        key = (cur_idx, cur_reg)
        if key in seen or cur_reg in exclude_regs: break
        seen.add(key)
        defs = index.reg_defs.get(cur_reg, [])
        pos = bisect.bisect_left(defs, cur_idx) - 1
        if pos < 0: break
        j = defs[pos]
        r = trace.record(j); d = decode(r.pc, r.inst)
        # If this is a load (ldr), follow mem store — not the addressing regs.
        is_load = bool(d.mem_op) and not any(op[4] for op in d.mem_op)
        if is_load:
            base, idx_reg, disp, sz, _, _ = d.mem_op[0]
            base_v = r.reg(base) if base in ALL_REGS else 0
            idx_v = r.reg(idx_reg) if (idx_reg and idx_reg in ALL_REGS) else 0
            mem_addr = (base_v + idx_v + disp) & 0xffffffffffffffff
            out.append(ChaseStep(idx=j, pc=r.pc,
                                 asm=f"{d.mnemonic} {d.op_str}",
                                 via="mem-load", reg_or_addr=hex(mem_addr)))
            # Find the latest write to this addr before j
            mem_writes = index.mem_addr_to_writes.get(mem_addr, [])
            mp = bisect.bisect_left(mem_writes, j) - 1
            if mp < 0: break
            w_idx = mem_writes[mp]
            rw = t_rec_decode = trace.record(w_idx); dw = decode(rw.pc, rw.inst)
            # Find the source register of the store (first non-base/idx use)
            base_w = dw.mem_op[0][0] if dw.mem_op else None
            idx_w = dw.mem_op[0][1] if dw.mem_op else None
            src_candidates = [u for u in dw.regs_use
                              if u not in (base_w, idx_w) and u not in exclude_regs]
            src = src_candidates[0] if src_candidates else None
            out.append(ChaseStep(idx=w_idx, pc=rw.pc,
                                 asm=f"{dw.mnemonic} {dw.op_str}",
                                 via="mem-store-src", reg_or_addr=src or "?"))
            if not src: break
            cur_idx = w_idx
            cur_reg = src
            continue
        # Otherwise: arithmetic / mov / etc. Follow first non-excluded reg_use.
        candidates = [u for u in d.regs_use
                      if u not in exclude_regs
                      and u not in _addressing_regs(d)]
        if not candidates:
            # Constant / fully sanitized — terminal
            out.append(ChaseStep(idx=j, pc=r.pc,
                                 asm=f"{d.mnemonic} {d.op_str}",
                                 via="terminal", reg_or_addr="(no data deps)"))
            break
        out.append(ChaseStep(idx=j, pc=r.pc,
                             asm=f"{d.mnemonic} {d.op_str}",
                             via="reg", reg_or_addr=candidates[0]))
        cur_idx = j
        cur_reg = candidates[0]
    return out
