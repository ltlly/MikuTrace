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
    out = {
        "path": str(args.trace),
        "records": len(t),
        "method": m.method,
        "cmd": m.cmd,
        "fn_addr": hex(m.fn_addr) if m.fn_addr else None,
        "module": {"name": mod.name, "base": hex(mod.base), "size": mod.size,
                   "end": hex(mod.end)} if mod else None,
        "modules": [{"name": x.name, "base": hex(x.base), "size": x.size,
                     "end": hex(x.end)} for x in m.modules],
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


def cmd_taint_fwd(args):
    from .trace import load
    from .symbols import build_from_trace
    from .disasm import decode
    from .taint import forward_taint
    t = load(args.trace)
    sym = build_from_trace(t)
    idx = _build_index_sync(t)
    base = t.meta.module.base if t.meta.module else 0
    results = forward_taint(t, args.start, args.reg, max_count=args.max, index=idx)
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
    _emit({"from": args.start, "reg": args.reg, "count": len(rows), "hits": rows})


def cmd_taint_bwd(args):
    from .trace import load
    from .symbols import build_from_trace
    from .disasm import decode
    from .taint import backward_taint
    t = load(args.trace)
    sym = build_from_trace(t)
    idx = _build_index_sync(t)
    base = t.meta.module.base if t.meta.module else 0
    results = backward_taint(t, args.start, args.reg, max_count=args.max, index=idx)
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
    _emit({"from": args.start, "reg": args.reg, "count": len(rows), "chain": rows})


# ───────────────────────── mem-dump ─────────────────────────

def cmd_mem_dump(args):
    from .trace import load
    from .memshadow import MemShadow
    t = load(args.trace)
    mem = MemShadow(t); mem.build()
    start = _parse_int(args.addr)
    out_bytes = []
    cursor = args.cursor if args.cursor >= 0 else (1 << 63)
    for i in range(args.count):
        a = start + i
        b, kind, src_idx = mem.byte_at(a, cursor)
        out_bytes.append({"addr": hex(a), "byte": b, "kind": kind,
                          "src_idx": src_idx})
    t.close()
    _emit({"addr": args.addr, "count": args.count, "cursor": args.cursor,
           "bytes": out_bytes})


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
        callees.append({"pc": hex(cpc), "func": cfn if cfn != "?" else None,
                        "count": cnt})
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

    s = sub.add_parser("taint-bwd", help="backward def-chain from idx on a register")
    s.add_argument("trace")
    s.add_argument("--start", type=int, required=True)
    s.add_argument("--reg", required=True)
    s.add_argument("--max", type=int, default=500)

    s = sub.add_parser("mem-dump", help="hex dump from MemShadow")
    s.add_argument("trace")
    s.add_argument("--addr", required=True, help="hex 0x...")
    s.add_argument("--count", type=int, default=64)
    s.add_argument("--cursor", type=int, default=-1, help="-1=latest")

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
        "mem-dump": cmd_mem_dump,
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
