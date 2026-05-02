"""traceMiku CLI — subcommands for LLM/scripting access.

Usage:
    python -m viewer <trace_dir_or_file>          # launch TUI (legacy)
    python -m viewer stats <trace>                # JSON trace metadata
    python -m viewer export <trace> --format sqlite -o out.db
    python -m viewer search-pc <trace> <pc>       # idx list where pc hit
    python -m viewer idxs-for-pc <trace> <pc> [--cursor N --limit N]
    python -m viewer search-asm <trace> <regex>   # regex search mnemonic+ops
    python -m viewer taint-fwd <trace> --start N --reg x0 [--max N]
    python -m viewer taint-bwd <trace> --start N --reg x0 [--max N]
    python -m viewer mem-dump <trace> --addr 0x... [--count N]
    python -m viewer field-at <trace> --pc 0x... --reg x0 --offset 0x80 \\
                                       --so /path/to/lib.so

All output is JSON to stdout (LLM-friendly). Errors → stderr + exit 1.
"""
from __future__ import annotations
import sys, argparse, json, pathlib


# ───────────────────────── helpers ─────────────────────────

def _parse_int(s: str) -> int:
    """Accept '0x...' (hex) or decimal."""
    s = str(s).strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def _emit(obj):
    """Print JSON to stdout (LLM-friendly)."""
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def _err(msg):
    print(json.dumps({"error": msg}, indent=2, ensure_ascii=False), file=sys.stderr)
    sys.exit(1)


# ───────────────────────── stats ─────────────────────────

def cmd_stats(args):
    from .trace import load
    t = load(args.trace)
    m = t.meta
    mod = m.module
    all_mods = [{"name": x.name, "base": hex(x.base), "size": x.size,
                 "end": hex(x.end)} for x in m.modules]
    # Gap-C: --top-modules N (default 10) keeps stats output LLM-friendly.
    # Always include the target module first if present.
    target_name = mod.name if mod else None
    sorted_mods = sorted(all_mods, key=lambda x: -x["size"])
    if args.all_modules:
        modules_out = sorted_mods
    else:
        n = max(1, args.top_modules)
        kept = []
        if target_name:
            kept = [x for x in sorted_mods if x["name"] == target_name][:1]
        kept += [x for x in sorted_mods if x["name"] != target_name][:n - len(kept)]
        modules_out = kept
    out = {
        "path": str(args.trace),
        "records": len(t),
        "method": m.method,
        "cmd": m.cmd,
        "fn_addr": hex(m.fn_addr) if m.fn_addr else None,
        "module": {"name": mod.name, "base": hex(mod.base), "size": mod.size,
                   "end": hex(mod.end)} if mod else None,
        "modules": modules_out,
        "modules_total": len(all_mods),
        "modules_truncated": len(modules_out) < len(all_mods),
    }
    t.close()
    _emit(out)


# ───────────────────────── export ─────────────────────────

def cmd_export(args):
    if args.format != "sqlite":
        _err(f"unsupported format: {args.format}")
    from .trace import load, ALL_REGS
    import sqlite3
    t = load(args.trace)
    out_path = args.output or (pathlib.Path(args.trace).resolve().name + ".db")
    con = sqlite3.connect(out_path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=OFF")
    cols = ["idx INTEGER PRIMARY KEY", "pc INTEGER", "inst INTEGER",
            "sp INTEGER", "nzcv INTEGER"]
    for r in ALL_REGS:
        if r in ("pc", "sp", "nzcv"): continue
        cols.append(f'"{r}" INTEGER')
    con.execute(f"CREATE TABLE IF NOT EXISTS records ({', '.join(cols)})")
    con.execute("CREATE INDEX IF NOT EXISTS idx_pc ON records(pc)")
    n = len(t)
    batch = 10000
    for start in range(0, n, batch):
        end = min(start + batch, n)
        rows = []
        for i in range(start, end):
            r = t.record(i)
            row = [i, r.pc, r.inst, r.sp, r.nzcv]
            for reg in ALL_REGS:
                if reg in ("pc", "sp", "nzcv"): continue
                row.append(r.reg(reg))
            rows.append(tuple(row))
        con.executemany(
            f"INSERT INTO records VALUES ({', '.join(['?']*len(cols))})", rows)
        if start % 100000 == 0:
            print(f"  {start}/{n} records...", file=sys.stderr)
    con.commit()
    con.close()
    t.close()
    print(f"exported {n} records to {out_path}", file=sys.stderr)
    _emit({"records": n, "output": out_path, "format": args.format})


# ───────────────────────── search-pc ─────────────────────────

def cmd_search_pc(args):
    """All trace idxs where PC equals the given value. numpy vectorized."""
    import numpy as np
    from .trace import load
    target = _parse_int(args.pc)
    t = load(args.trace)
    arr = t.pc_array()
    idxs = np.nonzero(arr == np.uint64(target))[0]
    out = {"pc": hex(target), "count": int(len(idxs)),
           "idxs": idxs[:args.limit].tolist() if args.limit > 0 else idxs.tolist(),
           "truncated": args.limit > 0 and len(idxs) > args.limit}
    t.close()
    _emit(out)


# ───────────────────────── idxs-for-pc ─────────────────────────

def cmd_idxs_for_pc(args):
    """Cursor-relative neighborhood of PC hits (before/after)."""
    import numpy as np
    from .trace import load
    target = _parse_int(args.pc)
    t = load(args.trace)
    arr = t.pc_array()
    all_idxs = np.nonzero(arr == np.uint64(target))[0]
    cut = int(np.searchsorted(all_idxs, args.cursor, side="left"))
    before = all_idxs[max(0, cut - args.limit):cut][::-1].tolist()
    after = all_idxs[cut:cut + args.limit].tolist()
    out = {
        "pc": hex(target), "cursor": args.cursor,
        "before": before, "after": after,
        "total_before": cut, "total_after": int(len(all_idxs) - cut),
        "before_capped": cut > args.limit,
        "after_capped": (len(all_idxs) - cut) > args.limit,
    }
    t.close()
    _emit(out)


# ───────────────────────── search-asm ─────────────────────────

def cmd_search_asm(args):
    """Regex search across mnemonic + op_str."""
    import re
    from .trace import load
    from .disasm import decode
    from .symbols import build_from_trace
    rx = re.compile(args.pattern, re.I)
    t = load(args.trace)
    sym = build_from_trace(t)
    base = t.meta.module.base if t.meta.module else 0
    rows = []
    for i in range(len(t)):
        r = t.record(i); d = decode(r.pc, r.inst)
        if rx.search(f"{d.mnemonic} {d.op_str}"):
            fname, foff = sym.lookup(r.pc)
            rows.append({
                "idx": i, "pc": hex(r.pc),
                "rel": hex(r.pc - base) if base else None,
                "func": fname if fname != "?" else None,
                "off": hex(foff) if fname != "?" else None,
                "asm": f"{d.mnemonic} {d.op_str}",
            })
            if args.max > 0 and len(rows) >= args.max: break
    t.close()
    _emit({"pattern": args.pattern, "count": len(rows), "hits": rows})


# ───────────────────────── taint-fwd / taint-bwd ─────────────────────────

def _build_index_sync(t):
    """Build trace Index synchronously (CLI runs single-threaded)."""
    from .index import Index
    idx = Index(t)
    idx.build()
    return idx


def _parse_exclude_regs(s):
    if not s: return None
    return {x.strip() for x in s.split(",") if x.strip()}


def _summarize_by_fn(rows: list[dict]) -> list[dict]:
    """Aggregate taint rows by function name. Returns list of
    {func, count, first_idx, last_idx} sorted by count desc."""
    by_fn: dict[str, dict] = {}
    for r in rows:
        fn = r.get("func") or "?"
        e = by_fn.setdefault(fn, {"func": fn, "count": 0,
                                   "first_idx": r["idx"], "last_idx": r["idx"]})
        e["count"] += 1
        if r["idx"] < e["first_idx"]: e["first_idx"] = r["idx"]
        if r["idx"] > e["last_idx"]: e["last_idx"] = r["idx"]
    return sorted(by_fn.values(), key=lambda e: -e["count"])


def cmd_taint_fwd(args):
    from .trace import load
    from .symbols import build_from_trace
    from .disasm import decode
    from .taint import forward_taint
    t = load(args.trace)
    sym = build_from_trace(t)
    idx = _build_index_sync(t)
    base = t.meta.module.base if t.meta.module else 0
    mem = None
    if getattr(args, "through_mem", False):
        from .memshadow import MemShadow
        mem = MemShadow(t); mem.build()
    cfn = getattr(args, "cross_fn_call", False)
    results, stopped_at_max = forward_taint(
        t, args.start, args.reg, max_count=args.max, index=idx,
        exclude_regs=_parse_exclude_regs(args.exclude_regs),
        data_only=args.data_only,
        through_mem=getattr(args, "through_mem", False),
        mem=mem, return_status=True, cross_fn_call=cfn)
    rows = []
    for entry in results:
        if cfn:
            i, why, fdepth = entry
        else:
            i, why = entry; fdepth = None
        r = t.record(i); d = decode(r.pc, r.inst)
        fname, foff = sym.lookup(r.pc)
        row = {
            "idx": i, "pc": hex(r.pc),
            "rel": hex(r.pc - base) if base else None,
            "func": fname if fname != "?" else None,
            "asm": f"{d.mnemonic} {d.op_str}", "why": why,
        }
        if fdepth is not None:
            row["frame_depth"] = fdepth
        rows.append(row)
    t.close()
    out = {"from": args.start, "reg": args.reg, "data_only": args.data_only,
           "count": len(rows), "stopped_at_max": stopped_at_max, "hits": rows}
    if getattr(args, "summary_by_fn", False):
        out["summary_by_fn"] = _summarize_by_fn(rows)
    _emit(out)


def cmd_taint_bwd(args):
    from .trace import load
    from .symbols import build_from_trace
    from .disasm import decode
    from .taint import backward_taint
    t = load(args.trace)
    sym = build_from_trace(t)
    idx = _build_index_sync(t)
    base = t.meta.module.base if t.meta.module else 0
    mem = None
    if getattr(args, "through_mem", False):
        from .memshadow import MemShadow
        mem = MemShadow(t); mem.build()
    cfn = getattr(args, "cross_fn_call", False)
    results, stopped_at_max = backward_taint(
        t, args.start, args.reg, max_count=args.max, index=idx,
        exclude_regs=_parse_exclude_regs(args.exclude_regs),
        data_only=args.data_only,
        through_mem=getattr(args, "through_mem", False),
        mem=mem, return_status=True, cross_fn_call=cfn)
    rows = []
    for entry in results:
        if cfn:
            i, via, fdepth = entry
        else:
            i, via = entry; fdepth = None
        r = t.record(i); d = decode(r.pc, r.inst)
        fname, foff = sym.lookup(r.pc)
        row = {
            "idx": i, "pc": hex(r.pc),
            "rel": hex(r.pc - base) if base else None,
            "func": fname if fname != "?" else None,
            "asm": f"{d.mnemonic} {d.op_str}", "via": via,
        }
        if fdepth is not None:
            row["frame_depth"] = fdepth
        rows.append(row)
    t.close()
    out = {"from": args.start, "reg": args.reg, "data_only": args.data_only,
           "count": len(rows), "stopped_at_max": stopped_at_max, "chain": rows}
    if getattr(args, "summary_by_fn", False):
        out["summary_by_fn"] = _summarize_by_fn(rows)
    _emit(out)


# ───────────────────────── data-chase (Gap-F) ─────────────────────────

def cmd_data_chase(args):
    """Single-path backward data chase across functions, skipping sp/fp/lr noise.

    The killer LLM逆向 workflow: from a register at idx, follow ONE chain
    through mov/ldr/str to the real data source. Use this instead of taint-bwd
    when you want a tight chain not a fanout."""
    from .trace import load
    from .symbols import build_from_trace
    from .taint import data_chase
    t = load(args.trace)
    sym = build_from_trace(t)
    idx_obj = _build_index_sync(t)
    base = t.meta.module.base if t.meta.module else 0
    steps = data_chase(t, args.start, args.reg, max_steps=args.max_steps,
                        exclude_regs=_parse_exclude_regs(args.exclude_regs),
                        index=idx_obj)
    out = []
    for s in steps:
        fn, foff = sym.lookup(s.pc)
        out.append({
            "idx": s.idx, "pc": hex(s.pc),
            "rel": hex(s.pc - base) if base else None,
            "func": fn if fn != "?" else None,
            "asm": s.asm, "via": s.via, "src": s.reg_or_addr,
        })
    t.close()
    _emit({"from": args.start, "reg": args.reg, "count": len(out), "steps": out})


# ───────────────────────── records (Gap-D) ─────────────────────────

def cmd_records(args):
    """Mirror of /api/records: list trace records in [start, start+count).
    Each row carries `module` (the SO that the PC belongs to)."""
    from .trace import load, ALL_REGS
    from .symbols import build_from_trace, ModuleResolver
    from .disasm import decode
    t = load(args.trace)
    sym = build_from_trace(t)
    mres = ModuleResolver(t.meta.modules)
    base = t.meta.module.base if t.meta.module else 0
    n = len(t)
    if args.start < 0 or args.start >= n:
        _emit({"start": args.start, "end": args.start, "count": 0, "records": []}); return
    end = min(args.start + args.count, n)
    regs_filter = None
    if args.regs:
        regs_filter = [r for r in args.regs.split(",") if r in ALL_REGS]
    rows = []
    for i in range(args.start, end):
        r = t.record(i); d = decode(r.pc, r.inst)
        fname, foff = sym.lookup(r.pc)
        m = mres.resolve(r.pc)
        row = {
            "idx": i, "pc": hex(r.pc),
            "rel": hex(r.pc - base) if base else None,
            "module": m.name if m else None,
            "func": fname if fname != "?" else None,
            "off": hex(foff) if fname != "?" else None,
            "asm": f"{d.mnemonic} {d.op_str}",
            "is_branch": d.is_branch, "is_call": d.is_call, "is_ret": d.is_ret,
        }
        if regs_filter:
            row["regs"] = {nm: hex(r.reg(nm)) for nm in regs_filter}
        rows.append(row)
    t.close()
    _emit({"start": args.start, "end": end, "count": end - args.start, "records": rows})


# ───────────────────────── so-stats (Phase 2) ─────────────────────────

def cmd_so_stats(args):
    """Per-SO record counts. numpy vectorized — fast on 7M-record trace.

    Output: list of {name, base, end, records, percent}, sorted by record count desc.
    Records whose PC isn't in any known module → '<unknown>' bucket.
    """
    import numpy as np
    from .trace import load
    from .symbols import ModuleResolver
    t = load(args.trace)
    arr = t.pc_array()
    mres = ModuleResolver(t.meta.modules)
    if not mres.modules:
        _emit({"records": int(len(arr)), "modules": [],
               "note": "no modules in meta — re-run trace with current tracer"})
        t.close(); return
    idx_arr = mres.vectorize(arr)
    n = int(len(arr))
    counts = np.bincount(idx_arr + 1, minlength=len(mres.modules) + 1)
    # idx_arr+1: -1 (unknown) → 0; module 0 → 1; ...
    out = []
    unknown = int(counts[0])
    for i, m in enumerate(mres.modules):
        c = int(counts[i + 1])
        if c == 0 and not args.all: continue
        out.append({
            "name": m.name, "base": hex(m.base), "end": hex(m.end),
            "size": m.size, "records": c,
            "percent": round(c * 100 / n, 2) if n else 0,
        })
    out.sort(key=lambda x: -x["records"])
    if args.top > 0: out = out[:args.top]
    t.close()
    _emit({
        "records": n,
        "modules_total": len(mres.modules),
        "unknown_records": unknown,
        "unknown_percent": round(unknown * 100 / n, 2) if n else 0,
        "modules": out,
    })


# ───────────────────────── last-write-of-addr (Gap-B) ─────────────────────────

def cmd_last_write_of_addr(args):
    """Most recent write to addr before idx. Mirror logic to /api/last-write-of-reg."""
    import bisect
    from .trace import load
    from .symbols import build_from_trace
    from .disasm import decode
    t = load(args.trace)
    sym = build_from_trace(t)
    idx_obj = _build_index_sync(t)
    base = t.meta.module.base if t.meta.module else 0
    addr = _parse_int(args.addr)
    before = args.before_idx if args.before_idx >= 0 else len(t)
    writes = idx_obj.mem_addr_to_writes.get(addr, [])
    pos = bisect.bisect_left(writes, before) - 1
    if pos < 0:
        _emit({"status": "not-found", "addr": args.addr,
               "before_idx": before, "writes_total": len(writes)})
        t.close(); return
    w_idx = writes[pos]
    rw = t.record(w_idx); dw = decode(rw.pc, rw.inst)
    fn, foff = sym.lookup(rw.pc)
    base_w = dw.mem_op[0][0] if dw.mem_op else None
    idx_w = dw.mem_op[0][1] if dw.mem_op else None
    src_candidates = [u for u in dw.regs_use if u not in (base_w, idx_w)]
    src = src_candidates[0] if src_candidates else None
    src_value = hex(rw.reg(src)) if src else None
    t.close()
    _emit({
        "status": "found", "addr": args.addr, "before_idx": before,
        "writer_idx": w_idx, "writer_pc": hex(rw.pc),
        "rel": hex(rw.pc - base) if base else None,
        "func": fn if fn != "?" else None,
        "asm": f"{dw.mnemonic} {dw.op_str}",
        "src_reg": src, "src_value": src_value,
        "writes_before": pos + 1, "writes_after": len(writes) - pos - 1,
    })


# ───────────────────────── find-mem-pattern (Gap-H) ─────────────────────────

def cmd_find_mem_pattern(args):
    """Search MemShadow for a hex byte pattern (e.g. SHA-256 IV '67e6096a').

    --idx-lo/--idx-hi: 仅返回首事件 idx 落在 [lo, hi) 的命中. 用于在长 trace 中
    定位 "在某算法阶段才出现" 的字节序列, 排除前后无关的 hit.
    """
    from .trace import load
    from .memshadow import MemShadow
    t = load(args.trace)
    mem = MemShadow(t); mem.build()
    pat_hex = args.bytes.replace(" ", "").replace("0x", "")
    if len(pat_hex) % 2 != 0:
        _err(f"hex pattern must be even-length: {args.bytes!r}")
    try:
        pat = bytes.fromhex(pat_hex)
    except ValueError as e:
        _err(f"bad hex: {e}")
    if len(pat) == 0: _err("empty pattern")
    if not mem.bytes:
        _emit({"pattern": pat.hex(), "count": 0, "hits": []}); t.close(); return
    # Build a sorted list of all (addr, byte_at_after_writes) and scan
    # Naive: for each addr in mem.bytes, check if pattern matches at addr
    cursor = args.since if args.since >= 0 else (1 << 63)
    idx_lo = getattr(args, "idx_lo", None)
    idx_hi = getattr(args, "idx_hi", None)
    addrs = sorted(mem.bytes.keys())
    hits = []
    for a in addrs:
        match = True
        first_idx = None
        for o, want in enumerate(pat):
            ev_list = mem.bytes.get(a + o)
            if not ev_list:
                match = False; break
            # Latest event with idx <= cursor
            ev_idx, byte_val, kind = None, None, None
            for ev in ev_list:
                if ev[0] > cursor: break
                ev_idx, byte_val, kind = ev
            if byte_val is None or byte_val != want:
                match = False; break
            if first_idx is None or (ev_idx is not None and ev_idx < first_idx):
                first_idx = ev_idx
        if match:
            # idx-range filter (post-match)
            if idx_lo is not None and (first_idx is None or first_idx < idx_lo): continue
            if idx_hi is not None and (first_idx is None or first_idx >= idx_hi): continue
            hits.append({"addr": hex(a), "first_idx": first_idx})
            if args.max > 0 and len(hits) >= args.max: break
    t.close()
    _emit({"pattern": pat.hex(), "since_idx": args.since,
           "idx_range": [idx_lo, idx_hi] if (idx_lo is not None or idx_hi is not None) else None,
           "count": len(hits), "hits": hits})


# ───────────────────────── mem-writes-in-range ─────────────────────────

def cmd_mem_writes_in_range(args):
    """List all memory writes in [idx-lo, idx-hi), optionally filtered.

    Use case: 反向追踪卡在 OLLVM VM 时, 想看"binary 签名生成阶段的所有 byte 写"
    来定位算法步骤. 现 last-write-of-addr 只能单点查; mem-writes-in-range 给整段.

    Filters:
      --src-byte 0xNN   仅写值首字节 == NN 的 (找 binary signature 头字节)
      --addr-lo / --addr-hi  限定目标 addr 范围 (filter heap/stack 等)
      --max  cap 输出条数 (默认 200)
    """
    import numpy as np, bisect
    from .trace import load
    from .memshadow import MemShadow
    from .symbols import build_from_trace
    from .disasm import decode
    t = load(args.trace)
    sym = build_from_trace(t)
    base = t.meta.module.base if t.meta.module else 0
    mem = MemShadow(t); mem.build()

    lo, hi = args.idx_lo, args.idx_hi if args.idx_hi >= 0 else len(t)
    # vectorized idx range filter
    mask = (mem.w_idx >= lo) & (mem.w_idx < hi)
    if args.addr_lo is not None:
        mask &= (mem.w_addr >= _parse_int(args.addr_lo))
    if args.addr_hi is not None:
        mask &= (mem.w_addr < _parse_int(args.addr_hi))
    if args.src_byte is not None:
        sb = _parse_int(args.src_byte) & 0xff
        mask &= ((mem.w_value & 0xff) == sb)
    pos = np.where(mask)[0]
    if args.max > 0 and len(pos) > args.max:
        pos = pos[:args.max]

    rows = []
    for k in pos.tolist():
        i = int(mem.w_idx[k])
        addr = int(mem.w_addr[k]); sz = int(mem.w_size[k])
        val = int(mem.w_value[k])
        r = t.record(i); d = decode(r.pc, r.inst)
        fn, foff = sym.lookup(r.pc)
        # src reg
        base_w = d.mem_op[0][0] if d.mem_op else None
        idx_w  = d.mem_op[0][1] if d.mem_op else None
        src_candidates = [u for u in d.regs_use if u not in (base_w, idx_w)]
        src = src_candidates[0] if src_candidates else None
        rows.append({
            "idx": i, "pc": hex(r.pc),
            "rel": hex(r.pc - base) if base else None,
            "func": fn if fn != "?" else None,
            "asm": f"{d.mnemonic} {d.op_str}",
            "dst_addr": hex(addr), "size": sz,
            "src_reg": src, "src_value": hex(val),
            "byte0": (val & 0xff),
        })
    t.close()
    _emit({"idx_range": [lo, hi], "matched": int(mask.sum()),
           "returned": len(rows), "writes": rows})


# ───────────────────────── mem-flow ─────────────────────────

def cmd_mem_flow(args):
    """Per-byte read/write timeline at addr [+0..count). Shows full event
    history per byte (all reads + writes that touched it, with idx + kind +
    src). Like `mem-dump` but with provenance for every byte, not just latest.

    Use case: 想知道 buffer 被哪些步骤构建. 不是看"现在是什么", 而是"怎么变成
    现在这个状态的".
    """
    from .trace import load
    from .memshadow import MemShadow
    from .symbols import build_from_trace
    from .disasm import decode
    t = load(args.trace)
    sym = build_from_trace(t)
    base = t.meta.module.base if t.meta.module else 0
    mem = MemShadow(t); mem.build()

    addr = _parse_int(args.addr)
    cnt = max(1, args.count)
    cap = max(0, args.events_per_byte)

    kind_filter = None
    if getattr(args, "writers_only", False): kind_filter = {"w", "x"}
    elif getattr(args, "readers_only", False): kind_filter = {"r"}

    out_bytes = []
    for o in range(cnt):
        a = addr + o
        evs_raw = mem.bytes.get(a, [])
        evs = []
        # 应用 idx-range + kind filter (可选)
        for ev_idx, ev_byte, ev_kind in evs_raw:
            if args.idx_lo is not None and ev_idx < args.idx_lo: continue
            if args.idx_hi is not None and ev_idx >= args.idx_hi: continue
            if kind_filter is not None and ev_kind not in kind_filter: continue
            r = t.record(ev_idx); d = decode(r.pc, r.inst)
            fn, foff = sym.lookup(r.pc)
            evs.append({
                "idx": ev_idx, "byte": ev_byte, "kind": ev_kind,
                "pc": hex(r.pc),
                "rel": hex(r.pc - base) if base else None,
                "func": fn if fn != "?" else None,
                "asm": f"{d.mnemonic} {d.op_str}",
            })
        # cap events_per_byte (preserve newest)
        if cap > 0 and len(evs) > cap:
            evs = evs[-cap:]
        out_bytes.append({
            "addr": hex(a), "events": evs, "total": len(evs_raw),
        })
    t.close()
    _emit({"addr": args.addr, "count": cnt, "bytes": out_bytes})


# ───────────────────────── crypto-scan ─────────────────────────

# 标准加密原语的"标志性"常量, 以 **LE 内存中的字节序** 给出 (因为 ARM64 LE 真机
# 的 trace 里, 一个 u32 const 0xVVUUTTSS 写到 mem = 字节 SS TT UU VV).
# 命中 → 算法第一步定位. 来源: 各 RFC + libtomcrypt/mbedtls 静态表 + 国密.
_CRYPTO_PATTERNS = [
    # SHA-1 / MD5 IV
    ("SHA1_H[0]/MD5_A",  "01234567"),  # value 0x67452301
    ("SHA1_H[1]/MD5_B",  "89abcdef"),  # value 0xefcdab89
    ("SHA1_H[2]",        "fedcba98"),  # value 0x98badcfe
    ("SHA1_H[3]/MD5_D",  "76543210"),  # value 0x10325476
    ("SHA1_H[4]",        "f0e1d2c3"),  # value 0xc3d2e1f0  ← MD5 没有
    # SHA-2 IV (SHA-256)
    ("SHA256_H[0]",      "67e6096a"),  # value 0x6a09e667
    ("SHA256_H[1]",      "85ae67bb"),  # value 0xbb67ae85
    ("SHA256_H[2]",      "72f36e3c"),  # value 0x3c6ef372
    # TEA 系
    ("TEA_DELTA",        "b979379e"),  # value 0x9e3779b9
    # AES
    ("AES_SBOX[0..3]",   "637c777b"),
    ("AES_SBOX[4..7]",   "f26b6fc5"),
    ("AES_invSBOX[0..3]","52096ad5"),  # inverse SBOX 起始
    ("AES_Rcon[1..4]",   "01020408"),
    # HMAC
    ("HMAC_ipad_x4",     "36363636"),
    ("HMAC_opad_x4",     "5c5c5c5c"),
    # ChaCha20
    ("CHACHA20_sigma",   "657870616e64203332"),  # "expand 32" prefix
    # SM3 (国密哈希) — IV: 0x7380166F 0x4914B2B9 0x172442D7
    ("SM3_IV[0]",        "6f168073"),  # value 0x7380166F
    ("SM3_IV[1]",        "b9b21449"),  # value 0x4914B2B9
    ("SM3_IV[2]",        "d7422417"),  # value 0x172442D7
    # SM4 (国密分组) — FK[0]: 0xa3b1bac6
    ("SM4_FK[0]",        "c6bab1a3"),  # value 0xa3b1bac6
    # Blake2b/2s IV (常见: SHA-256 IV reused 但很多自定义实现也用)
    ("Blake2b_IV[0]",    "08c9bcf367e6096a"),  # 0x6a09e667f3bcc908 LE
    # CRC32 polynomial table[0..1]
    ("CRC32_table[1]",   "96300777"),  # value 0x77073096
]


def cmd_crypto_scan(args):
    """One-shot scan for ~22 standard crypto primitive constants in MemShadow.

    Each pattern is the LE bytes that the constant would appear as in a memory
    load. 0 命中通常意味着: (a) 编译期常量被拆成多指令计算 (OLLVM 风格 / 优化),
    (b) 算法用自研非标常量, (c) 常量在 untraced 的 SO 里 (libc/libcrypto 等被
    Stalker.exclude).
    """
    from .trace import load
    from .memshadow import MemShadow
    t = load(args.trace)
    mem = MemShadow(t); mem.build()
    if not mem.bytes:
        _emit({"scanned": 0, "primitives": []}); t.close(); return

    addrs_sorted = sorted(mem.bytes.keys())

    def _scan_pattern(pat: bytes):
        hits = []
        for a in addrs_sorted:
            ok = True; first_idx = None
            for o, want in enumerate(pat):
                evs = mem.bytes.get(a + o)
                if not evs: ok = False; break
                last = evs[-1]
                if last[1] != want: ok = False; break
                if first_idx is None or last[0] < first_idx:
                    first_idx = last[0]
            if ok:
                hits.append({"addr": hex(a), "first_idx": first_idx})
                if len(hits) >= 5: break
        return hits

    out = []
    for name, hex_str in _CRYPTO_PATTERNS:
        pat = bytes.fromhex(hex_str)
        hits = _scan_pattern(pat)
        out.append({"name": name, "pattern": hex_str,
                    "hit_count": len(hits), "hits": hits})
    t.close()
    _emit({"scanned": len(_CRYPTO_PATTERNS),
           "primitives": out,
           "any_hit": any(p["hit_count"] for p in out)})


# ───────────────────────── reg-at-idx ─────────────────────────

def cmd_reg_at_idx(args):
    """thin wrapper: 'x14 在 idx N 是多少'. 等价 records --start N --count 1
    --regs ... 但更直接 (无 record 解码 overhead, 直接读 GPR array)."""
    from .trace import load, ALL_REGS
    t = load(args.trace)
    idx = args.idx
    if idx < 0 or idx >= len(t):
        _err(f"idx out of range: {idx} not in [0, {len(t)})")
    r = t.record(idx)
    regs = args.regs.split(",") if args.regs else ["x0","x1","x2","x3","x4","x5","x6","x7","x8","x14","x19","x20","x21","x25","sp","lr"]
    out = {"idx": idx, "pc": hex(t.pc(idx)), "regs": {}}
    for rn in regs:
        rn = rn.strip()
        if rn not in ALL_REGS: continue
        v = r.reg(rn)
        out["regs"][rn] = {"hex": hex(v), "dec": v, "byte0": v & 0xff}
    t.close()
    _emit(out)


# ───────────────────────── call-chain ─────────────────────────

def cmd_call_chain(args):
    """LR-walking caller chain. 在 idx N 时 lr = 当前 frame 的 return PC, fp 链
    指向上一帧 saved lr. 这里用简化: 只看当前帧 lr; 真要走多帧需读 *fp 但 OLLVM
    可能没标准 frame layout, 不强保证."""
    from .trace import load
    from .symbols import build_from_trace
    t = load(args.trace)
    sym = build_from_trace(t)
    base = t.meta.module.base if t.meta.module else 0
    idx = args.idx
    if idx < 0 or idx >= len(t):
        _err(f"idx out of range: {idx} not in [0, {len(t)})")
    chain = []
    cur_idx = idx
    for depth in range(args.depth):
        r = t.record(cur_idx)
        cur_pc = t.pc(cur_idx)
        cur_fn, cur_off = sym.lookup(cur_pc)
        lr = r.reg("lr")
        caller_pc = lr - 4 if lr else 0
        caller_fn, caller_off = sym.lookup(caller_pc) if caller_pc else ("?", 0)
        chain.append({
            "depth": depth, "idx": cur_idx,
            "pc": hex(cur_pc), "rel": hex(cur_pc - base) if base else None,
            "func": cur_fn if cur_fn != "?" else None,
            "off": hex(cur_off) if cur_fn != "?" else None,
            "lr": hex(lr),
            "caller_pc": hex(caller_pc),
            "caller_func": caller_fn if caller_fn != "?" else None,
            "caller_off": hex(caller_pc - caller_off) if caller_fn != "?" else None,
        })
        if not caller_fn or caller_fn == "?": break
        # 找 caller 函数最近一次 entry idx (供下一跳用)
        import numpy as np
        pcs = t.pc_array()
        hits = np.where(pcs == caller_off)[0]
        before = hits[hits < cur_idx]
        if len(before) == 0: break
        cur_idx = int(before[-1])
    t.close()
    _emit({"start_idx": idx, "depth": len(chain), "chain": chain})


# ───────────────────────── hash-input-search ─────────────────────────

def cmd_hash_input_search(args):
    """Brute-force hash input candidates against target bytes in mem.

    给一组候选输入串 + (可选) 候选 key, 算 SHA-1/MD5/SHA-256/HMAC, 比对 prefix
    与 trace 中的目标字节序列. 找到匹配则报告.

    对加密反向: 知道 hash 是 SHA-1, 但不知道输入是 'user_id' 还是
    'user_id\\0app_token' 还是 prefix(key)+user_id — 这个命令一次扫所有组合.
    """
    import hashlib, hmac, itertools, json
    from .trace import load
    from .memshadow import MemShadow
    t = load(args.trace)
    m = MemShadow(t); m.build()

    # parse target bytes
    target_hex = args.target_bytes.replace(" ", "").replace("0x", "")
    if len(target_hex) % 2: _err(f"odd hex: {args.target_bytes!r}")
    target = bytes.fromhex(target_hex)
    prefix_n = max(4, args.prefix_bytes)
    target_prefix = target[:prefix_n]

    # 解析输入 + key 候选
    inputs = [s.strip() for s in args.inputs.split(",")] if args.inputs else []
    keys = [s.strip() for s in args.keys.split(",")] if args.keys else [""]
    if not inputs: _err("no --inputs")

    # 解析算法
    algos = [a.strip() for a in args.algos.split(",")] if args.algos else ["sha1","md5","sha256"]
    valid_algos = {"sha1","md5","sha256","sha384","sha512",
                   "hmac-sha1","hmac-md5","hmac-sha256",
                   "crc32"}
    for a in algos:
        if a not in valid_algos: _err(f"unknown algo: {a!r}, valid: {valid_algos}")

    # 拼装 combos
    combos_str = args.combos.split(",") if args.combos else ["plain","prefix_key","suffix_key","key_prefix_input"]
    def combo_iter(inp, key):
        for c in combos_str:
            c = c.strip()
            if c == "plain": yield ("plain", inp.encode())
            elif c == "prefix_key": yield ("prefix_key", key.encode() + inp.encode())
            elif c == "suffix_key": yield ("suffix_key", inp.encode() + key.encode())
            elif c == "key_prefix_input": yield ("key_prefix_input", key.encode() + b"\0" + inp.encode())
            elif c == "input_pipe_key":   yield ("input_pipe_key",  inp.encode() + b"|" + key.encode())
            elif c == "key_dot_input":    yield ("key_dot_input",   key.encode() + b"." + inp.encode())
            else: _err(f"unknown combo: {c!r}")

    def hash_it(algo, key_bytes, msg):
        import zlib
        if algo == "sha1":   return hashlib.sha1(msg).digest()
        if algo == "md5":    return hashlib.md5(msg).digest()
        if algo == "sha256": return hashlib.sha256(msg).digest()
        if algo == "sha384": return hashlib.sha384(msg).digest()
        if algo == "sha512": return hashlib.sha512(msg).digest()
        if algo == "hmac-sha1":   return hmac.new(key_bytes, msg, hashlib.sha1).digest()
        if algo == "hmac-md5":    return hmac.new(key_bytes, msg, hashlib.md5).digest()
        if algo == "hmac-sha256": return hmac.new(key_bytes, msg, hashlib.sha256).digest()
        if algo == "crc32":
            crc = zlib.crc32(msg) & 0xffffffff
            # 同时尝试 LE 和 BE 两种字节序输出 (调用方对 4 字节 prefix 比较, 分别试)
            return crc.to_bytes(4, "little") + crc.to_bytes(4, "big")  # 8 bytes (LE+BE)

    # MemShadow 内 byte-level prefix 搜
    def find_in_mem(prefix: bytes, max_hits=3):
        hits = []
        for a in m.bytes:
            ok = True
            for o in range(len(prefix)):
                evs = m.bytes.get(a + o)
                if not evs or evs[-1][1] != prefix[o]: ok=False; break
            if ok:
                hits.append((a, evs[-1][0]))
                if len(hits) >= max_hits: break
        return hits

    found = []
    tried = 0
    for inp in inputs:
        for key in keys:
            for combo_name, msg in combo_iter(inp, key):
                for algo in algos:
                    if algo.startswith("hmac-") and not key:
                        continue  # HMAC needs key
                    try:
                        h = hash_it(algo, key.encode(), msg if not algo.startswith("hmac-") else inp.encode())
                    except Exception as _e:
                        continue
                    tried += 1
                    if h.startswith(target_prefix):
                        # check full target
                        full_match = h.startswith(target)
                        found.append({
                            "algo": algo, "input": inp, "key": key,
                            "combo": combo_name,
                            "msg_hex": (msg[:40].hex() + "..." if len(msg) > 40 else msg.hex()),
                            "hash_full": h.hex(),
                            "full_match": full_match,
                            "matches_n_bytes": prefix_n if not full_match else len(target),
                        })
                        continue
                    # also search hash output bytes IN MEM (the hash output may
                    # be stored even if our combo guess doesn't match output position)
                    if args.search_in_mem:
                        mh = find_in_mem(h[:prefix_n], max_hits=1)
                        if mh:
                            found.append({
                                "algo": algo, "input": inp, "key": key,
                                "combo": combo_name,
                                "msg_hex": (msg[:40].hex() + "..."),
                                "hash_full": h.hex(),
                                "found_in_mem": [{"addr": hex(a), "idx": i} for a, i in mh],
                                "match_type": "in_mem",
                            })
    t.close()
    _emit({"target_prefix": target_prefix.hex(), "tried_combos": tried,
           "found": found, "found_count": len(found)})


# ───────────────────────── diff-traces ─────────────────────────

def cmd_diff_traces(args):
    """Multi-trace differential: compare same-input traces to identify
    stable (key/const) vs variable (nonce/timestamp) bytes in outputs.

    给 N 个 trace dir, 提取每个 trace 的 JNI output bytes (x-sign / x-mini-wua /
    x-sgext / x-umt), 跨 trace 做 byte-level diff.

    每个 byte position 分类:
    - STABLE: 跨所有 trace 取值相同 → device-stable key bytes / format constants
    - VARIABLE: 跨 trace 不同 → nonce / timestamp / per-call random
    - PARTIAL: 部分 trace 相同 (少见, 数据噪声)

    用途: 知道哪些字节是 key, 缩小 hash-input-search 的输入空间.
    """
    import json, pathlib, urllib.parse, base64
    from collections import defaultdict
    if len(args.traces) < 2:
        _err("need >= 2 traces for diff")

    # 解析每个 trace 的 JNI output
    def extract_outputs(trace_dir):
        """从 jni_hooks.jsonl 提取 NewStringUTF 调用的 'bytes' 参数. 4 个 header
        在固定时序: x-mini-wua / x-umt / x-sgext / x-sign."""
        td = pathlib.Path(trace_dir)
        # find any jni_hooks.jsonl in this trace dir or its calls/ subdirs
        candidates = list(td.glob("jni_hooks.jsonl")) + list(td.glob("calls/*/jni_hooks.jsonl"))
        if not candidates:
            return None
        events = []
        for jp in candidates:
            for line in jp.read_text().splitlines():
                try: events.append(json.loads(line))
                except Exception: continue
        # NewStringUTF 顺序按 trace_idx
        new_strs = sorted(
            [e for e in events if e.get("id") == "NewStringUTF" and (e.get("args") or {}).get("bytes")],
            key=lambda e: e.get("trace_idx", 0)
        )
        # 关键字段提取: 找 key→value 对. value 跟在 key 后面.
        outputs = {}
        for i, e in enumerate(new_strs):
            v = e["args"]["bytes"]
            if v in ("x-sign", "x-mini-wua", "x-sgext", "x-umt"):
                if i + 1 < len(new_strs):
                    val_e = new_strs[i+1]
                    val_str = val_e["args"]["bytes"]
                    # URL-decode + base64 decode
                    try:
                        url_dec = urllib.parse.unquote(val_str)
                        pad = '=' * ((4 - len(url_dec) % 4) % 4)
                        binary = base64.b64decode(url_dec + pad)
                        outputs[v] = {"raw": val_str, "binary": binary,
                                       "len_b64": len(url_dec), "len_bin": len(binary)}
                    except Exception as ex:
                        outputs[v] = {"raw": val_str, "decode_err": str(ex)}
        return outputs

    all_outputs = []
    for td in args.traces:
        out = extract_outputs(td)
        if out is None:
            _err(f"no jni_hooks.jsonl in {td}")
        all_outputs.append({"trace": td, "outputs": out})

    # 对每个 header, byte-by-byte diff
    headers = ["x-mini-wua", "x-umt", "x-sgext", "x-sign"]
    diff_report = {}
    for hdr in headers:
        # 收集每个 trace 的 binary bytes
        binaries = []
        for ao in all_outputs:
            o = ao["outputs"].get(hdr)
            if not o or "binary" not in o:
                binaries.append(None)
            else:
                binaries.append(o["binary"])
        if any(b is None for b in binaries):
            diff_report[hdr] = {"error": "missing in some trace",
                                 "per_trace_lens": [len(b) if b else None for b in binaries]}
            continue
        lens = [len(b) for b in binaries]
        if len(set(lens)) > 1:
            # 长度不一致 → diff 公共前缀长度. 对于 variable-length payload (像
            # x-sgext) 这给出 "前缀对齐部分" 的差异; 长度本身的变化也是有意义信号.
            n = min(lens)
            length_variable = True
        else:
            n = lens[0]
            length_variable = False
        stable_bytes = []   # idx where all traces agree
        variable_bytes = [] # idx where different
        per_byte = []
        for o in range(n):
            vals = [b[o] for b in binaries]
            if len(set(vals)) == 1:
                stable_bytes.append(o)
                per_byte.append({"off": o, "kind": "STABLE", "value": hex(vals[0])})
            else:
                variable_bytes.append(o)
                per_byte.append({"off": o, "kind": "VARIABLE", "values": [hex(v) for v in vals]})
        # ALIASING groups: 跨 calls 同步变化的 positions = 同源字节
        # 给每个 offset 生成 5-tuple (val_in_call_1, val_in_call_2, ...) 然后聚类:
        # 同一 tuple → 这些 offsets 永远同时变化, 是 byte-level alias / replication.
        # 只看 VARIABLE positions, 因为 STABLE 全相同会形成一个巨大组.
        from collections import defaultdict
        alias_map = defaultdict(list)
        for o in variable_bytes:
            tup = tuple(b[o] for b in binaries)
            alias_map[tup].append(o)
        alias_groups = []
        for tup, positions in alias_map.items():
            if len(positions) > 1:
                alias_groups.append({
                    "positions": positions,
                    "size": len(positions),
                    "values_per_trace": [hex(v) for v in tup],
                })
        alias_groups.sort(key=lambda g: -g["size"])

        # NIBBLE-level: 找 high nibble 固定 / low nibble 固定的 byte
        nibble_findings = []
        for o in variable_bytes:
            vals = [b[o] for b in binaries]
            his = set((v >> 4) & 0xf for v in vals)
            los = set(v & 0xf for v in vals)
            if len(his) == 1:
                nibble_findings.append({"off": o, "kind": "hi_fixed",
                                          "hi": hex(next(iter(his))),
                                          "lo_per_trace": [hex(v & 0xf) for v in vals]})
            elif len(los) == 1:
                nibble_findings.append({"off": o, "kind": "lo_fixed",
                                          "lo": hex(next(iter(los))),
                                          "hi_per_trace": [hex((v >> 4) & 0xf) for v in vals]})

        # summary
        diff_report[hdr] = {
            "len_compared": n,
            "lens_per_trace": lens,
            "length_variable": length_variable,
            "stable_count": len(stable_bytes),
            "variable_count": len(variable_bytes),
            "stable_pct": round(100 * len(stable_bytes) / n, 1) if n else 0,
            "stable_offsets": stable_bytes if args.show_offsets else None,
            "variable_offsets": variable_bytes if args.show_offsets else None,
            "alias_groups": alias_groups,
            "alias_group_count": len(alias_groups),
            "nibble_findings": nibble_findings,
            "per_byte": per_byte if args.show_per_byte else None,
        }

    _emit({
        "traces": [ao["trace"] for ao in all_outputs],
        "n_traces": len(all_outputs),
        "headers": diff_report,
    })


# ───────────────────────── auto-phase-detect ─────────────────────────

def cmd_auto_phase_detect(args):
    """Heuristic 自动找算法阶段, 在 trace 上打 timeline 标签.

    Heuristics:
    - input_read:  每个 GetStringUTFChars JNI hook event
    - byte_stream_write: 同一 PC 在短 idx 范围内多次 strb 写连续地址
    - sha1_init / md5_init: crypto-scan 命中位置
    - base64_encode_start: 第一次写到某 buffer 的 byte 是合法 base64 char
    - jni_output: 每个 NewStringUTF event
    """
    import json, pathlib, numpy as np
    from .trace import load
    from .memshadow import MemShadow
    t = load(args.trace)
    base = t.meta.module.base if t.meta.module else 0

    phases = []

    # JNI events (input + output)
    jni_path = pathlib.Path(t.path).parent / "jni_hooks.jsonl"
    if jni_path.exists():
        for line in jni_path.read_text().splitlines():
            try: e = json.loads(line)
            except Exception: continue
            tid = e.get("trace_idx")
            if tid is None: continue
            op = e.get("id", "")
            if op == "GetStringUTFChars":
                ret_v = e.get("ret")
                if isinstance(ret_v, str) and not ret_v.startswith("0x"):
                    phases.append({"idx": tid, "phase": "jni_input",
                                    "info": f"GetStringUTFChars '{ret_v[:32]}'"})
            elif op == "NewStringUTF":
                v = (e.get("args") or {}).get("bytes")
                if isinstance(v, str):
                    phases.append({"idx": tid, "phase": "jni_output",
                                    "info": f"NewStringUTF '{v[:48]}'"})

    # crypto-scan integration
    m = MemShadow(t); m.build()
    crypto_patterns = [
        ("sha1_init",     bytes.fromhex("01234567")),
        ("sha1_init_h1",  bytes.fromhex("89abcdef")),
        ("sha1_init_h4",  bytes.fromhex("f0e1d2c3")),
        ("sha256_init",   bytes.fromhex("67e6096a")),
    ]
    for label, pat in crypto_patterns:
        # find all addrs where pat matches; report first event idx
        for a in m.bytes:
            ok = True; first_idx = None
            for o in range(len(pat)):
                evs = m.bytes.get(a + o)
                if not evs or evs[-1][1] != pat[o]: ok=False; break
                if first_idx is None or evs[0][0] < first_idx:
                    first_idx = evs[0][0]
            if ok and first_idx is not None:
                phases.append({"idx": first_idx, "phase": label,
                                "info": f"IV pattern at 0x{a:x}"})

    # byte_stream_write: 找连续 strb 同 PC 写连续地址 (超过 4 次)
    if args.detect_byte_streams:
        # 用 numpy 找 size==1 写 + 连续 idx 模式
        size1 = m.w_size == 1
        if size1.any():
            w_idx_b = m.w_idx[size1]
            w_addr_b = m.w_addr[size1]
            # 检测连续: 同一 PC + idx 间隔小 + addr 增量 = 1
            # 简化: 按 idx 排序, 滑动窗口找 4+ 连续 (addr_diff = 1)
            for i in range(len(w_idx_b) - 4):
                if (w_addr_b[i+1] - w_addr_b[i] == 1 and
                    w_addr_b[i+2] - w_addr_b[i+1] == 1 and
                    w_addr_b[i+3] - w_addr_b[i+2] == 1 and
                    w_idx_b[i+3] - w_idx_b[i] < 500):
                    phases.append({"idx": int(w_idx_b[i]),
                                    "phase": "byte_stream_write",
                                    "info": f"4+ contiguous strb starting 0x{int(w_addr_b[i]):x}"})

    phases.sort(key=lambda p: p["idx"])
    # de-dup 同 idx ± 50
    dedup = []
    for p in phases:
        if dedup and abs(p["idx"] - dedup[-1]["idx"]) < 50 and p["phase"] == dedup[-1]["phase"]:
            continue
        dedup.append(p)
    n_records = len(t)
    t.close()
    _emit({"trace_records": n_records, "phases": dedup})


# ───────────────────────── jni-calls (Gap-J) ─────────────────────────

def _load_jni_vtable(custom_path=None):
    """Load JNI vtable offset → name map.

    Source of truth: viewer/jni_offsets.json (regenerated via BN from
    vendor/jni/jni_bn.h — see tools/regen_jni_offsets.py). NEVER hardcoded
    in Python: hardcoded tables drift from upstream + can't be audited.

    Override path: --jni-offsets <PATH>.
    """
    p = pathlib.Path(custom_path) if custom_path else \
        pathlib.Path(__file__).resolve().parent / "jni_offsets.json"
    if not p.exists():
        _err(f"jni offsets file not found: {p}\n"
             f"  hint: run `python tools/regen_jni_offsets.py` to regenerate")
    data = json.loads(p.read_text())
    raw = data.get("offsets", data)
    return {int(k, 16) if isinstance(k, str) else int(k): v for k, v in raw.items()}


def cmd_jni_calls(args):
    """Detect JNI vtable calls in trace.

    Pattern: `ldr xK, [xJ, #imm]` (load fn ptr from JNIEnv vtable) followed
    immediately by `blr xK`. `imm` matched against viewer/jni_offsets.json
    (BN-parsed JNINativeInterface_; not hardcoded — see tools/regen_jni_offsets.py).
    """
    from .trace import load
    from .symbols import build_from_trace
    from .disasm import decode
    jni_vtable = _load_jni_vtable(args.jni_offsets)
    t = load(args.trace)
    sym = build_from_trace(t)
    base = t.meta.module.base if t.meta.module else 0
    n = len(t)
    fn_filter = args.in_fn or None
    hits = []
    prev_d = None
    prev_r = None
    for i in range(n):
        r = t.record(i); d = decode(r.pc, r.inst)
        fname, _ = sym.lookup(r.pc)
        if fn_filter and fname != fn_filter:
            prev_d = d; prev_r = r; continue
        if d.mnemonic == "blr" and d.indirect_branch_reg and prev_d is not None:
            target_reg = d.indirect_branch_reg
            if (prev_d.mnemonic == "ldr" and target_reg in prev_d.regs_def
                    and prev_d.mem_op):
                base_reg, _, disp, _, is_w, _src = prev_d.mem_op[0]
                if not is_w and disp in jni_vtable:
                    fn_name = jni_vtable[disp]
                    hits.append({
                        "idx": i, "pc": hex(r.pc),
                        "rel": hex(r.pc - base) if base else None,
                        "func": fname if fname != "?" else None,
                        "jni_fn": fn_name, "vtable_offset": hex(disp),
                        "args": {a: hex(r.reg(a)) for a in
                                  ("x0", "x1", "x2", "x3", "x4")},
                    })
                    if args.max > 0 and len(hits) >= args.max:
                        prev_d = d; prev_r = r; break
        prev_d = d; prev_r = r
    t.close()
    _emit({"in_fn": fn_filter, "count": len(hits), "hits": hits,
           "vtable_size": len(jni_vtable)})


# ───────────────────────── jobj-history (Gap-K) ─────────────────────────

def _scan_jni_calls(t, sym, jni_vtable):
    """Iterator over all JNI vtable calls in trace.

    Yields (idx, record, decoded, prev_decoded, jni_fn_name, vtable_offset, fname).
    Used by both cmd_jni_calls and the higher-level cmd_jobj_history /
    cmd_jni_strings — they all need the same vtable-call detection logic.
    """
    from .disasm import decode
    n = len(t)
    prev_d = None
    for i in range(n):
        r = t.record(i); d = decode(r.pc, r.inst)
        fname, _ = sym.lookup(r.pc)
        if d.mnemonic == "blr" and d.indirect_branch_reg and prev_d is not None:
            target_reg = d.indirect_branch_reg
            if (prev_d.mnemonic == "ldr" and target_reg in prev_d.regs_def
                    and prev_d.mem_op):
                base_reg, _, disp, _, is_w, _src = prev_d.mem_op[0]
                if not is_w and disp in jni_vtable:
                    yield (i, r, d, prev_d, jni_vtable[disp], disp, fname)
        prev_d = d


def cmd_jobj_history(args):
    """Track a jobject through trace — find all JNI calls where it appears
    as any of x1..x4. Reveals NewObject → SetField → CallMethod lifecycle.
    """
    from .trace import load
    from .symbols import build_from_trace
    jni_vtable = _load_jni_vtable(args.jni_offsets)
    t = load(args.trace)
    sym = build_from_trace(t)
    base = t.meta.module.base if t.meta.module else 0
    target = _parse_int(args.jobject)
    start = max(0, args.start)
    end = args.end if args.end >= 0 else len(t)
    hits = []
    for tup in _scan_jni_calls(t, sym, jni_vtable):
        i, r, d, prev_d, jni_fn, vtbl_off, fname = tup
        if i < start: continue
        if i >= end: break
        # Match jobject in any of x1..x4 (x0 is always JNIEnv*, skip)
        match_arg = None
        for arg in ("x1", "x2", "x3", "x4"):
            if r.reg(arg) == target:
                match_arg = arg; break
        if match_arg is None: continue
        hits.append({
            "idx": i, "pc": hex(r.pc),
            "rel": hex(r.pc - base) if base else None,
            "func": fname if fname != "?" else None,
            "jni_fn": jni_fn,
            "vtable_offset": hex(vtbl_off),
            "match_arg": match_arg,
            "args": {a: hex(r.reg(a)) for a in ("x1", "x2", "x3", "x4")},
        })
        if args.max > 0 and len(hits) >= args.max: break
    t.close()
    _emit({"jobject": hex(target), "start": start, "end": end,
           "count": len(hits), "hits": hits})


# ───────────────────────── jni-strings (Gap-L) ─────────────────────────

# JNI string-related fn names → which arg is the string, and direction
# (in = we have buffer pre-call; out = result is char*/jstring after call)
_JNI_STRING_OPS = {
    # name             arg_idx   direction (after_x0=ret is buffer)
    "NewString":          ("x1", "out_x0"),  # x1=jchar*, ret=jstring
    "NewStringUTF":       ("x1", "out_x0"),  # x1=const char*, ret=jstring
    "GetStringChars":     ("x1", "out_x0"),  # x1=jstring, ret=jchar*
    "GetStringUTFChars":  ("x1", "out_x0"),  # x1=jstring, ret=const char*
    "ReleaseStringChars": ("x2", "in"),      # x2=chars
    "ReleaseStringUTFChars":("x2","in"),
    "GetStringRegion":    ("x4", "out_x4"),  # x4=jchar* dest buffer
    "GetStringUTFRegion": ("x4", "out_x4"),  # x4=char* dest buffer
    "GetStringLength":    ("x1", "in"),
    "GetStringUTFLength": ("x1", "in"),
    "GetStringCritical":  ("x1", "out_x0"),
    "ReleaseStringCritical":("x2", "in"),
}


def _read_str_from_mem(mem, addr, cursor, max_len=128):
    """Read NUL-terminated UTF-8 string from MemShadow. Returns (str_or_None,
    bytes_observed, total_attempted). Returns None if mem doesn't have any
    observed byte at addr (Stalker-excluded ranges produce '?' for entire
    string)."""
    if mem is None or not addr: return None, 0, 0
    out = bytearray()
    seen = 0
    for o in range(max_len):
        b, kind, src = mem.byte_at(addr + o, cursor)
        if b is None:
            if seen == 0: return None, 0, o
            break
        seen += 1
        if b == 0: break
        out.append(b)
    if not out: return None, seen, max_len
    try:
        return out.decode("utf-8", errors="replace"), seen, max_len
    except Exception:
        return None, seen, max_len


def cmd_jni_strings(args):
    """List all JNI string operations + buffer content (when observable in
    MemShadow). Note: libart heap is Stalker-excluded, so many buffers will
    show '(not observed)'. Operations on ART-internal strings won't have
    observable bytes; ones the SO itself reads/writes will."""
    from .trace import load
    from .symbols import build_from_trace
    from .memshadow import MemShadow
    jni_vtable = _load_jni_vtable(args.jni_offsets)
    t = load(args.trace)
    sym = build_from_trace(t)
    base = t.meta.module.base if t.meta.module else 0
    print("Building MemShadow (~5-30s)...", file=sys.stderr)
    mem = MemShadow(t); mem.build()

    hits = []
    for tup in _scan_jni_calls(t, sym, jni_vtable):
        i, r, d, prev_d, jni_fn, vtbl_off, fname = tup
        if jni_fn not in _JNI_STRING_OPS: continue
        arg_name, direction = _JNI_STRING_OPS[jni_fn]
        # Buffer addr depends on direction
        rec = {
            "idx": i, "pc": hex(r.pc),
            "rel": hex(r.pc - base) if base else None,
            "func": fname if fname != "?" else None,
            "jni_fn": jni_fn,
            "arg_name": arg_name,
            "direction": direction,
            "x1": hex(r.reg("x1")),
            "x2": hex(r.reg("x2")),
        }
        # For "out_x0" we need the next record's x0 (post-call result)
        # For "out_x4" the dest buffer was passed in x4 pre-call
        # For "in" the buffer is at the named arg pre-call
        observed = None
        if direction == "out_x0" and i + 1 < len(t):
            nxt = t.record(i + 1)
            buf_addr = nxt.reg("x0")
            rec["buffer_addr"] = hex(buf_addr)
            s, seen, _ = _read_str_from_mem(mem, buf_addr, i + 1, args.max_len)
            observed = (s, seen)
        elif direction == "out_x4":
            buf_addr = r.reg("x4")
            rec["buffer_addr"] = hex(buf_addr)
            s, seen, _ = _read_str_from_mem(mem, buf_addr, i, args.max_len)
            observed = (s, seen)
        elif direction == "in":
            buf_addr = r.reg(arg_name)
            rec["buffer_addr"] = hex(buf_addr)
            s, seen, _ = _read_str_from_mem(mem, buf_addr, i, args.max_len)
            observed = (s, seen)
        if observed is not None:
            s, seen = observed
            rec["observed_bytes"] = seen
            rec["string"] = s if s is not None else None
        hits.append(rec)
        if args.max > 0 and len(hits) >= args.max: break
    t.close()
    # Summarize what we got vs what was Stalker-excluded
    with_str = sum(1 for h in hits if h.get("string"))
    _emit({
        "count": len(hits),
        "with_observed_string": with_str,
        "without_observed_string": len(hits) - with_str,
        "note": ("buffers in libart heap are Stalker-excluded; "
                  "to capture content add agent-side hook on GetStringUTFChars"),
        "hits": hits,
    })


# ───────────────────────── mem-dump ─────────────────────────

def cmd_mem_dump(args):
    """Hex dump from MemShadow. Either --addr or --reg+--idx (reg's value at idx)."""
    from .trace import load, ALL_REGS
    from .memshadow import MemShadow
    t = load(args.trace)
    mem = MemShadow(t); mem.build()
    if args.reg:
        # Gap-I: use reg value at given idx as base addr
        if args.reg not in ALL_REGS:
            _err(f"unknown reg: {args.reg!r}")
        if args.idx < 0 or args.idx >= len(t):
            _err(f"idx out of range: {args.idx} (n={len(t)})")
        start = t.record(args.idx).reg(args.reg)
        addr_str = hex(start)
    elif args.addr:
        start = _parse_int(args.addr)
        addr_str = args.addr
    else:
        _err("mem-dump requires --addr OR (--reg + --idx)")
    out_bytes = []
    cursor = args.cursor if args.cursor >= 0 else (1 << 63)
    for i in range(args.count):
        a = start + i
        b, kind, src_idx = mem.byte_at(a, cursor)
        out_bytes.append({"addr": hex(a), "byte": b, "kind": kind,
                          "src_idx": src_idx})
    t.close()
    out = {"addr": addr_str, "count": args.count, "cursor": args.cursor,
           "bytes": out_bytes}
    if args.reg:
        out["reg"] = args.reg
        out["idx"] = args.idx
    _emit(out)


# ───────────────────────── reg-timeline ─────────────────────────

def cmd_reg_timeline(args):
    """All distinct values of a register across [start, end)."""
    from .trace import load, ALL_REGS
    if args.reg not in ALL_REGS:
        _err(f"unknown reg: {args.reg!r}")
    t = load(args.trace)
    n = len(t)
    end = n if args.end < 0 or args.end > n else args.end
    start = max(0, min(args.start, end))
    out = []
    prev = object()
    truncated = False
    for i in range(start, end):
        v = t.record(i).reg(args.reg)
        if v != prev:
            out.append({"idx": i, "value": hex(v)})
            prev = v
            if len(out) >= args.max_points:
                truncated = True; break
    t.close()
    _emit({"reg": args.reg, "start": start, "end": end,
           "count": len(out), "points": out, "truncated": truncated})


# ───────────────────────── mem-diff ─────────────────────────

def cmd_mem_diff(args):
    """Memory bytes at idx-1 vs idx for [addr, addr+size)."""
    from .trace import load
    from .memshadow import MemShadow
    t = load(args.trace)
    mem = MemShadow(t); mem.build()
    start = _parse_int(args.addr)
    before_t = max(0, args.idx - 1); after_t = args.idx
    out = []; changed = 0
    for o in range(args.size):
        a = start + o
        b_before, _, _ = mem.byte_at(a, before_t)
        b_after, _, _ = mem.byte_at(a, after_t)
        ch = (b_before != b_after)
        if ch: changed += 1
        out.append({"addr": hex(a), "before": b_before,
                    "after": b_after, "changed": ch})
    t.close()
    _emit({"idx": args.idx, "addr": args.addr, "size": args.size,
           "bytes": out, "changed_count": changed})


# ───────────────────────── fn-summary ─────────────────────────

def cmd_fn_summary(args):
    """One-call fn overview: entry, block_count, hot blocks, callees."""
    import numpy as np
    from .trace import load
    from .symbols import build_from_trace
    from .cfg import build_cfg
    t = load(args.trace)
    sym = build_from_trace(t)
    cfg = build_cfg(t, only_module=True)
    base = t.meta.module.base if t.meta.module else 0
    fn_blocks = []; entry_pc = None
    for pc, b in cfg.blocks.items():
        fname, _ = sym.lookup(pc)
        if fname == args.fn:
            fn_blocks.append(b)
            if entry_pc is None or pc < entry_pc: entry_pc = pc
    if not fn_blocks:
        _emit({"status": "not-found", "fn": args.fn}); t.close(); return
    total_exec = sum(b.executions for b in fn_blocks)
    arr = t.pc_array()
    entry_idxs_all = np.nonzero(arr == np.uint64(entry_pc))[0]
    entry_idxs = entry_idxs_all[:50].tolist()
    hot = sorted(fn_blocks, key=lambda b: -b.executions)[:args.top_blocks]
    hot_out = [{"pc": hex(b.start_pc),
                "rel": hex(b.start_pc - base) if base else None,
                "insns": len(b.insns), "executions": b.executions} for b in hot]
    callee_pcs = {}
    fn_starts = {b.start_pc for b in fn_blocks}
    for (s, d), info in cfg.edges.items():
        if s in fn_starts and info["kind"] in ("bl", "blr"):
            callee_pcs[d] = callee_pcs.get(d, 0) + info["count"]
    callees = []
    for cpc, cnt in sorted(callee_pcs.items(), key=lambda x: -x[1])[:20]:
        cfn, _ = sym.lookup(cpc)
        # Gap-E fix: callee's TOTAL executions in trace (sum of executions of
        # all blocks in callee fn). Distinguishes "called from this fn 24×" vs
        # "callee fn ran 168× total (also called by others)".
        callee_blocks = [b for b in cfg.blocks.values()
                         if sym.lookup(b.start_pc)[0] == cfn]
        callee_total = sum(b.executions for b in callee_blocks)
        callees.append({
            "pc": hex(cpc),
            "func": cfn if cfn != "?" else None,
            "count": cnt,                            # edges from this fn
            "callee_block_count": len(callee_blocks),
            "callee_total_executions": callee_total, # all callers combined
        })
    t.close()
    _emit({
        "status": "ready", "fn": args.fn,
        "pc": hex(entry_pc), "rel": hex(entry_pc - base) if base else None,
        "block_count": len(fn_blocks), "total_executions": total_exec,
        "entry_idxs": entry_idxs, "entry_idxs_total": int(len(entry_idxs_all)),
        "hot_blocks": hot_out, "callees": callees,
    })


# ───────────────────────── field-at ─────────────────────────

def cmd_field_at(args):
    """Query BN HLIL struct field semantic at (pc, reg, offset).
    Requires --so <path>; loads BN backend synchronously."""
    if not args.so:
        _err("field-at requires --so <path/to/lib.so>")
    from .trace import load
    from .decompiler import make_backend
    t = load(args.trace)
    base = t.meta.module.base if t.meta.module else 0
    print(f"loading BN backend {args.so} (base={hex(base)})...", file=sys.stderr)
    bk = make_backend(args.backend)
    bk.open(args.so, base=base)
    pc = _parse_int(args.pc)
    offset = _parse_int(args.offset)
    out = {"pc": hex(pc), "reg": args.reg, "offset": offset, "hit": False,
           "struct": None, "field": None, "type_name": None}
    try:
        hint = bk.field_at(pc, args.reg, offset)
    except Exception as e:
        print(f"field_at raised: {e}", file=sys.stderr)
        hint = None
    if hint:
        out["hit"] = True
        out["struct"] = hint.struct or None
        out["field"] = hint.field or None
        out["type_name"] = hint.type_name or None
    t.close()
    _emit(out)


# ───────────────────────── main ─────────────────────────

_KNOWN_SUBCOMMANDS = {
    "stats", "export", "search-pc", "idxs-for-pc", "search-asm",
    "taint-fwd", "taint-bwd", "mem-dump", "field-at",
    "reg-timeline", "mem-diff", "fn-summary",
    # Gap-D / Gap-B / Gap-F / Gap-H / Gap-J:
    "records", "last-write-of-addr", "data-chase", "find-mem-pattern", "jni-calls",
    # Gap-K / Gap-L:
    "jobj-history", "jni-strings",
    # multi-SO trace
    "so-stats",
    # OLLVM 反向追踪 + 加密常量扫描 (post xsign session):
    "mem-writes-in-range", "mem-flow", "crypto-scan",
    # 第二轮 xsign 实战后追加 (P0 + P1):
    "reg-at-idx", "call-chain", "hash-input-search", "auto-phase-detect",
    # 多 trace 差分 (P2 → 现需求做了):
    "diff-traces",
}


def main():
    # Legacy: `python -m viewer <trace_dir_or_file>` → launch TUI directly
    if len(sys.argv) >= 2 and sys.argv[1] not in _KNOWN_SUBCOMMANDS \
            and sys.argv[1] not in ("-h", "--help"):
        from .app import TraceMikuApp
        app = TraceMikuApp(sys.argv[1])
        app.run()
        return

    p = argparse.ArgumentParser(prog="viewer", description="traceMiku CLI")
    sub = p.add_subparsers(dest="subcommand")

    s = sub.add_parser("stats", help="print trace metadata as JSON")
    s.add_argument("trace")
    s.add_argument("--top-modules", type=int, default=10, dest="top_modules",
                    help="show only top-N largest modules (default 10)")
    s.add_argument("--all-modules", action="store_true", dest="all_modules",
                    help="include all modules (don't truncate)")

    s = sub.add_parser("export", help="export trace to SQLite")
    s.add_argument("trace")
    s.add_argument("--format", default="sqlite", choices=["sqlite"])
    s.add_argument("-o", "--output", help="output file path")

    s = sub.add_parser("search-pc", help="all trace idxs where PC equals value")
    s.add_argument("trace")
    s.add_argument("pc", help="hex (0x...) or decimal")
    s.add_argument("--limit", type=int, default=0, help="0=all")

    s = sub.add_parser("idxs-for-pc", help="cursor-relative PC hit neighborhood")
    s.add_argument("trace")
    s.add_argument("pc")
    s.add_argument("--cursor", type=int, default=0)
    s.add_argument("--limit", type=int, default=30)

    s = sub.add_parser("search-asm", help="regex search mnemonic+ops")
    s.add_argument("trace")
    s.add_argument("pattern")
    s.add_argument("--max", type=int, default=200, help="0=unlimited")

    s = sub.add_parser("taint-fwd", help="forward taint from idx on a register")
    s.add_argument("trace")
    s.add_argument("--start", type=int, required=True)
    s.add_argument("--reg", required=True)
    s.add_argument("--max", type=int, default=5000,
                    help="cap chain length (default 5000)")
    s.add_argument("--exclude-regs", default="", dest="exclude_regs",
                    help="comma-sep regs to skip (e.g. 'sp,fp,lr'). Default empty.")
    s.add_argument("--data-only", action="store_true", dest="data_only",
                    help="skip ldr base/idx regs + sp/fp/lr (LLM逆向 mode)")
    s.add_argument("--through-mem", action="store_true", dest="through_mem",
                    help="byte-level mem store→load 穿透 (对称 backward)")
    s.add_argument("--summary-by-fn", action="store_true", dest="summary_by_fn",
                    help="aggregate hits by function (count, first_idx, last_idx)")
    s.add_argument("--cross-fn-call", action="store_true", dest="cross_fn_call",
                    help="annotate each row with frame_depth (bl/ret pair walking)")

    s = sub.add_parser("taint-bwd", help="backward def-chain from idx on a register")
    s.add_argument("trace")
    s.add_argument("--start", type=int, required=True)
    s.add_argument("--reg", required=True)
    s.add_argument("--max", type=int, default=5000,
                    help="cap chain length (default 5000)")
    s.add_argument("--exclude-regs", default="", dest="exclude_regs",
                    help="comma-sep regs to skip (e.g. 'sp,fp,lr')")
    s.add_argument("--data-only", action="store_true", dest="data_only")
    s.add_argument("--through-mem", action="store_true", dest="through_mem",
                    help="byte-level mem overlap (穿透 8B-store + 1B-load 错配; 慢, 需 build MemShadow)")
    s.add_argument("--summary-by-fn", action="store_true", dest="summary_by_fn",
                    help="aggregate chain by function (count, first_idx, last_idx)")
    s.add_argument("--cross-fn-call", action="store_true", dest="cross_fn_call",
                    help="annotate each row with frame_depth (bl/ret pair walking)")

    s = sub.add_parser("data-chase", help="single-path data chase (cross-fn, skips sp/fp noise)")
    s.add_argument("trace")
    s.add_argument("--start", type=int, required=True)
    s.add_argument("--reg", required=True)
    s.add_argument("--max-steps", type=int, default=50, dest="max_steps")
    s.add_argument("--exclude-regs", default="sp,fp,lr", dest="exclude_regs",
                    help="comma-sep regs to skip (default: sp,fp,lr)")

    s = sub.add_parser("records", help="list trace records in [start, start+count)")
    s.add_argument("trace")
    s.add_argument("--start", type=int, default=0)
    s.add_argument("--count", type=int, default=50)
    s.add_argument("--regs", default="", help="comma-sep regs to include in each row")

    s = sub.add_parser("last-write-of-addr",
                       help="find most recent mem write to addr before idx")
    s.add_argument("trace")
    s.add_argument("--addr", required=True, help="hex 0x...")
    s.add_argument("--before-idx", type=int, default=-1, dest="before_idx",
                    help="-1 = end of trace")

    s = sub.add_parser("mem-dump", help="hex dump from MemShadow")
    s.add_argument("trace")
    s.add_argument("--addr", help="hex 0x... (or use --reg+--idx)")
    s.add_argument("--reg", help="reg name; mem-dump uses reg's value at --idx as addr")
    s.add_argument("--idx", type=int, default=0, help="trace idx for --reg lookup")
    s.add_argument("--count", type=int, default=64)
    s.add_argument("--cursor", type=int, default=-1, help="-1=latest")

    s = sub.add_parser("find-mem-pattern", help="search MemShadow for a hex byte pattern")
    s.add_argument("trace")
    s.add_argument("--bytes", required=True, help="hex string e.g. '67e6096a' (SHA-256 IV)")
    s.add_argument("--since", type=int, default=-1, help="trace cursor (latest if -1)")
    s.add_argument("--max", type=int, default=100, help="0=all hits")
    s.add_argument("--idx-lo", type=int, default=None, dest="idx_lo",
                    help="filter: only hits with first_idx >= idx_lo")
    s.add_argument("--idx-hi", type=int, default=None, dest="idx_hi",
                    help="filter: only hits with first_idx < idx_hi")

    s = sub.add_parser("jni-calls", help="detect JNI vtable calls (BN-parsed offset map)")
    s.add_argument("trace")
    s.add_argument("--in-fn", default=None, help="restrict to a function name")
    s.add_argument("--max", type=int, default=200)
    s.add_argument("--jni-offsets", default=None, dest="jni_offsets",
                    help="path to jni_offsets.json (default: viewer/jni_offsets.json)")

    s = sub.add_parser("jobj-history", help="all JNI calls touching a specific jobject")
    s.add_argument("trace")
    s.add_argument("--jobject", required=True, help="jobject value (hex 0x...)")
    s.add_argument("--start", type=int, default=0)
    s.add_argument("--end", type=int, default=-1, help="-1=trace end")
    s.add_argument("--max", type=int, default=200)
    s.add_argument("--jni-offsets", default=None, dest="jni_offsets")

    s = sub.add_parser("jni-strings", help="all JNI string ops + buffer content (when observed)")
    s.add_argument("trace")
    s.add_argument("--max", type=int, default=200, help="0=unlimited")
    s.add_argument("--max-len", type=int, default=128, dest="max_len",
                    help="max bytes to read per string buffer")
    s.add_argument("--jni-offsets", default=None, dest="jni_offsets")

    s = sub.add_parser("so-stats", help="per-SO record counts (multi-SO traces)")
    s.add_argument("trace")
    s.add_argument("--top", type=int, default=20, help="top-N modules (0=all)")
    s.add_argument("--all", action="store_true", help="include zero-count modules")

    s = sub.add_parser("field-at", help="BN HLIL struct field hint at (pc,reg,offset)")
    s.add_argument("trace")
    s.add_argument("--pc", required=True, help="hex 0x...")
    s.add_argument("--reg", required=True)
    s.add_argument("--offset", default="0", help="hex or dec")
    s.add_argument("--so", required=True, help="path to SO file for BN")
    s.add_argument("--backend", default=None, help="binja|ghidra|ida|r2 (auto)")

    s = sub.add_parser("reg-timeline", help="distinct values of a reg across [start,end)")
    s.add_argument("trace")
    s.add_argument("--reg", required=True)
    s.add_argument("--start", type=int, default=0)
    s.add_argument("--end", type=int, default=-1, help="-1=trace end")
    s.add_argument("--max-points", type=int, default=1000, dest="max_points")

    s = sub.add_parser("mem-diff", help="byte-level mem state diff at idx-1 vs idx")
    s.add_argument("trace")
    s.add_argument("--idx", type=int, required=True)
    s.add_argument("--addr", required=True, help="hex 0x...")
    s.add_argument("--size", type=int, default=16)

    s = sub.add_parser("fn-summary", help="overview of a function (block_count, hot, callees)")
    s.add_argument("trace")
    s.add_argument("--fn", required=True, help="function name (e.g. JNI_OnLoad, myFunc)")
    s.add_argument("--top-blocks", type=int, default=5, dest="top_blocks")

    s = sub.add_parser("mem-writes-in-range",
                       help="all mem writes in [idx-lo, idx-hi); filter by src-byte / addr range")
    s.add_argument("trace")
    s.add_argument("--idx-lo", type=int, required=True, dest="idx_lo")
    s.add_argument("--idx-hi", type=int, default=-1, dest="idx_hi", help="-1=trace end")
    s.add_argument("--src-byte", default=None, dest="src_byte",
                   help="hex 0xNN; only show writes whose value low byte == NN")
    s.add_argument("--addr-lo", default=None, dest="addr_lo")
    s.add_argument("--addr-hi", default=None, dest="addr_hi")
    s.add_argument("--max", type=int, default=200, help="0=unlimited")

    s = sub.add_parser("mem-flow",
                       help="per-byte read/write timeline at addr (provenance for every byte)")
    s.add_argument("trace")
    s.add_argument("--addr", required=True, help="hex 0x...")
    s.add_argument("--count", type=int, default=8, help="bytes to dump")
    s.add_argument("--idx-lo", type=int, default=None, dest="idx_lo")
    s.add_argument("--idx-hi", type=int, default=None, dest="idx_hi")
    s.add_argument("--events-per-byte", type=int, default=10, dest="events_per_byte",
                   help="cap events per byte (0=all). Newest kept.")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--writers-only", action="store_true", dest="writers_only",
                   help="only kind='w'/'x' events (skip reads)")
    g.add_argument("--readers-only", action="store_true", dest="readers_only",
                   help="only kind='r' events")

    s = sub.add_parser("crypto-scan",
                       help="scan MemShadow for standard crypto primitive constants (incl. 国密 SM3/SM4)")
    s.add_argument("trace")

    s = sub.add_parser("reg-at-idx",
                       help="reg values at a specific trace idx (thin wrapper)")
    s.add_argument("trace")
    s.add_argument("--idx", type=int, required=True)
    s.add_argument("--regs", default="",
                   help="comma-sep regs (default: x0..x8 + key indices)")

    s = sub.add_parser("call-chain",
                       help="LR-walking caller chain from idx (best-effort, may stop at OLLVM)")
    s.add_argument("trace")
    s.add_argument("--idx", type=int, required=True)
    s.add_argument("--depth", type=int, default=8)

    s = sub.add_parser("hash-input-search",
                       help="brute-force hash input candidates against target bytes")
    s.add_argument("trace")
    s.add_argument("--target-bytes", required=True, dest="target_bytes",
                   help="hex bytes to find as hash output (e.g. SHA-1 prefix)")
    s.add_argument("--inputs", required=True,
                   help="comma-sep candidate input strings")
    s.add_argument("--keys", default="",
                   help="comma-sep candidate key strings (for HMAC variants)")
    s.add_argument("--algos", default="sha1,md5,sha256,hmac-sha1,hmac-md5,hmac-sha256",
                   help="comma-sep algos")
    s.add_argument("--combos", default="plain,prefix_key,suffix_key,key_prefix_input",
                   help="comma-sep msg construction modes")
    s.add_argument("--prefix-bytes", type=int, default=8, dest="prefix_bytes",
                   help="how many bytes of target to require match (4-20)")
    s.add_argument("--search-in-mem", action="store_true", dest="search_in_mem",
                   help="also search if computed hash bytes appear in mem (= used for tag)")

    s = sub.add_parser("auto-phase-detect",
                       help="heuristic timeline of algorithm phases (jni IO + crypto IV + base64)")
    s.add_argument("trace")
    s.add_argument("--no-byte-streams", action="store_false", dest="detect_byte_streams",
                   help="disable byte-stream detection (faster)")

    s = sub.add_parser("diff-traces",
                       help="compare N same-input traces, identify STABLE (key) vs VARIABLE (nonce) bytes")
    s.add_argument("traces", nargs="+", help="trace dirs (>= 2)")
    s.add_argument("--show-offsets", action="store_true", dest="show_offsets",
                   help="include stable_offsets/variable_offsets arrays in output")
    s.add_argument("--show-per-byte", action="store_true", dest="show_per_byte",
                   help="include full per-byte breakdown (verbose)")

    args = p.parse_args()

    handlers = {
        "stats": cmd_stats,
        "export": cmd_export,
        "search-pc": cmd_search_pc,
        "idxs-for-pc": cmd_idxs_for_pc,
        "search-asm": cmd_search_asm,
        "taint-fwd": cmd_taint_fwd,
        "taint-bwd": cmd_taint_bwd,
        "data-chase": cmd_data_chase,
        "records": cmd_records,
        "last-write-of-addr": cmd_last_write_of_addr,
        "mem-dump": cmd_mem_dump,
        "find-mem-pattern": cmd_find_mem_pattern,
        "jni-calls": cmd_jni_calls,
        "jobj-history": cmd_jobj_history,
        "jni-strings": cmd_jni_strings,
        "so-stats": cmd_so_stats,
        "field-at": cmd_field_at,
        "reg-timeline": cmd_reg_timeline,
        "mem-diff": cmd_mem_diff,
        "fn-summary": cmd_fn_summary,
        "mem-writes-in-range": cmd_mem_writes_in_range,
        "mem-flow": cmd_mem_flow,
        "crypto-scan": cmd_crypto_scan,
        "reg-at-idx": cmd_reg_at_idx,
        "call-chain": cmd_call_chain,
        "hash-input-search": cmd_hash_input_search,
        "auto-phase-detect": cmd_auto_phase_detect,
        "diff-traces": cmd_diff_traces,
    }
    h = handlers.get(args.subcommand)
    if h is None:
        p.print_help(); sys.exit(1)
    h(args)


if __name__ == "__main__":
    main()
