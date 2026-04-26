"""Forward + backward taint propagation on a trace.

Given a starting tainted register at instruction `idx`, walk the trace and
propagate taint through register def/use semantics. We don't track memory
taint precisely (that requires symbolic memory model) — for memory we taint
on a coarse address basis (read at addr A is tainted if any earlier write to
A came from tainted source).

Forward(idx, taint_reg) -> list[(insn_idx, why)]:
    starting at idx, walk forward; at each insn, check if any of its
    `regs_use` is tainted (or it loads from a tainted address). If so:
    - mark insn as tainted
    - taint its `regs_def` (and the destination address if it's a store)

Backward(idx, taint_reg) -> list[(insn_idx, why)]:
    walk backward to find the chain of definitions that produced the value
    of `taint_reg` at instruction `idx`.
"""
from __future__ import annotations
from collections import defaultdict
from .trace import Trace, ALL_REGS
from .disasm import decode


def _addr_of(rec, mem_op_tuple):
    base, idx_reg, disp, sz, is_w = mem_op_tuple
    bv = rec.reg(base) if base in ALL_REGS else 0
    iv = rec.reg(idx_reg) if (idx_reg and idx_reg in ALL_REGS) else 0
    return (bv + iv + disp) & 0xffffffffffffffff


def forward_taint(trace: Trace, start_idx: int, taint_reg: str,
                  max_count: int = 5000, depth: int = 0):
    """Yield instructions affected by `taint_reg` defined just before idx.
    Returns list of (insn_idx, reason)."""
    n = len(trace)
    tainted_regs = {taint_reg}
    tainted_mem: set[int] = set()
    out = []
    for i in range(start_idx + 1, n):
        if len(out) >= max_count: break
        r = trace.record(i)
        d = decode(r.pc, r.inst)
        propagated = False
        why = ""
        # Read from tainted reg or tainted mem?
        used_tainted_reg = tainted_regs & set(d.regs_use)
        load_tainted = False
        for op in d.mem_op:
            if op[4]: continue   # store, not load
            a = _addr_of(r, op)
            if a in tainted_mem:
                load_tainted = True; break
        if used_tainted_reg or load_tainted:
            propagated = True
            why = []
            if used_tainted_reg: why.append("regs:" + ",".join(used_tainted_reg))
            if load_tainted: why.append("mem")
            why = " ".join(why)
        if not propagated: continue
        out.append((i, why))
        # Propagate: define new regs, or write to mem
        for reg in d.regs_def:
            tainted_regs.add(reg)
        for op in d.mem_op:
            if op[4]:  # store
                a = _addr_of(r, op)
                tainted_mem.add(a)
    return out


def backward_taint(trace: Trace, idx: int, taint_reg: str,
                   max_count: int = 5000, depth: int = 0):
    """Walk backward to find the def chain feeding `taint_reg` at `idx`.

    If `idx` itself defines `taint_reg`, this counts as the value's source —
    we then trace its inputs further back.
    """
    out = []
    visited = set()
    # Check if idx itself defines taint_reg → start the chain at idx
    r0 = trace.record(idx); d0 = decode(r0.pc, r0.inst)
    if taint_reg in d0.regs_def:
        out.append((idx, taint_reg))
        visited.add((idx, taint_reg))
        # push its inputs
        pending = [(idx, u) for u in d0.regs_use]
    else:
        pending = [(idx, taint_reg)]
    while pending and len(out) < max_count:
        cur_idx, want_reg = pending.pop(0)
        if (cur_idx, want_reg) in visited: continue
        visited.add((cur_idx, want_reg))
        # Find latest def of want_reg before cur_idx
        for j in range(cur_idx - 1, -1, -1):
            r = trace.record(j)
            d = decode(r.pc, r.inst)
            if want_reg in d.regs_def:
                out.append((j, want_reg))
                # Add its inputs to pending
                for u in d.regs_use:
                    pending.append((j, u))
                # Mem load: trace back the value's memory source
                for op in d.mem_op:
                    if op[4]: continue  # store
                    addr = _addr_of(r, op)
                    # find latest store to addr before j
                    for k in range(j - 1, -1, -1):
                        rk = trace.record(k)
                        dk = decode(rk.pc, rk.inst)
                        for opk in dk.mem_op:
                            if opk[4] and _addr_of(rk, opk) == addr:
                                # the store's source register tainted
                                if dk.regs_use:
                                    pending.append((k, dk.regs_use[0]))
                                break
                        else:
                            continue
                        break
                break
    # 去重（保留每个 idx 第一次出现）
    seen_idx = set()
    dedup = []
    for idx, reg in sorted(out):
        if idx in seen_idx: continue
        seen_idx.add(idx)
        dedup.append((idx, reg))
    return dedup
