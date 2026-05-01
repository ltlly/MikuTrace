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


def cmd_taint_fwd(args):
    from .trace import load
    from .symbols import build_from_trace
    from .disasm import decode
    from .taint import forward_taint
    t = load(args.trace)
    sym = build_from_trace(t)
    idx = _build_index_sync(t)
    base = t.meta.module.base if t.meta.module else 0
    results = forward_taint(t, args.start, args.reg, max_count=args.max, index=idx,
                             exclude_regs=_parse_exclude_regs(args.exclude_regs),
                             data_only=args.data_only)
    rows = []
    for i, why in results:
        r = t.record(i); d = decode(r.pc, r.inst)
        fname, foff = sym.lookup(r.pc)
        rows.append({
            "idx": i, "pc": hex(r.pc),
            "rel": hex(r.pc - base) if base else None,
            "func": fname if fname != "?" else None,
            "asm": f"{d.mnemonic} {d.op_str}", "why": why,
        })
    t.close()
    _emit({"from": args.start, "reg": args.reg, "data_only": args.data_only,
           "count": len(rows), "hits": rows})


def cmd_taint_bwd(args):
    from .trace import load
    from .symbols import build_from_trace
    from .disasm import decode
    from .taint import backward_taint
    t = load(args.trace)
    sym = build_from_trace(t)
    idx = _build_index_sync(t)
    base = t.meta.module.base if t.meta.module else 0
    results = backward_taint(t, args.start, args.reg, max_count=args.max, index=idx,
                              exclude_regs=_parse_exclude_regs(args.exclude_regs),
                              data_only=args.data_only)
    rows = []
    for i, via in results:
        r = t.record(i); d = decode(r.pc, r.inst)
        fname, foff = sym.lookup(r.pc)
        rows.append({
            "idx": i, "pc": hex(r.pc),
            "rel": hex(r.pc - base) if base else None,
            "func": fname if fname != "?" else None,
            "asm": f"{d.mnemonic} {d.op_str}", "via": via,
        })
    t.close()
    _emit({"from": args.start, "reg": args.reg, "data_only": args.data_only,
           "count": len(rows), "chain": rows})


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
    Like search-asm but no filter — for raw inspection of a window."""
    from .trace import load, ALL_REGS
    from .symbols import build_from_trace
    from .disasm import decode
    t = load(args.trace)
    sym = build_from_trace(t)
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
        row = {
            "idx": i, "pc": hex(r.pc),
            "rel": hex(r.pc - base) if base else None,
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
    """Search MemShadow for a hex byte pattern (e.g. SHA-256 IV '67e6096a')."""
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
            hits.append({"addr": hex(a), "first_idx": first_idx})
            if args.max > 0 and len(hits) >= args.max: break
    t.close()
    _emit({"pattern": pat.hex(), "since_idx": args.since,
           "count": len(hits), "hits": hits})


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
                base_reg, _, disp, _, is_w = prev_d.mem_op[0]
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
    s.add_argument("--max", type=int, default=500)
    s.add_argument("--exclude-regs", default="", dest="exclude_regs",
                    help="comma-sep regs to skip (e.g. 'sp,fp,lr'). Default empty.")
    s.add_argument("--data-only", action="store_true", dest="data_only",
                    help="skip ldr base/idx regs + sp/fp/lr (LLM逆向 mode)")

    s = sub.add_parser("taint-bwd", help="backward def-chain from idx on a register")
    s.add_argument("trace")
    s.add_argument("--start", type=int, required=True)
    s.add_argument("--reg", required=True)
    s.add_argument("--max", type=int, default=500)
    s.add_argument("--exclude-regs", default="", dest="exclude_regs",
                    help="comma-sep regs to skip (e.g. 'sp,fp,lr')")
    s.add_argument("--data-only", action="store_true", dest="data_only")

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

    s = sub.add_parser("jni-calls", help="detect JNI vtable calls (BN-parsed offset map)")
    s.add_argument("trace")
    s.add_argument("--in-fn", default=None, help="restrict to a function name")
    s.add_argument("--max", type=int, default=200)
    s.add_argument("--jni-offsets", default=None, dest="jni_offsets",
                    help="path to jni_offsets.json (default: viewer/jni_offsets.json)")

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
    s.add_argument("--fn", required=True, help="function name (e.g. doCommandNative)")
    s.add_argument("--top-blocks", type=int, default=5, dest="top_blocks")

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
        "field-at": cmd_field_at,
        "reg-timeline": cmd_reg_timeline,
        "mem-diff": cmd_mem_diff,
        "fn-summary": cmd_fn_summary,
    }
    h = handlers.get(args.subcommand)
    if h is None:
        p.print_help(); sys.exit(1)
    h(args)


if __name__ == "__main__":
    main()
