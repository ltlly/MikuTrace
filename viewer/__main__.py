"""traceMiku CLI — subcommands for LLM/scripting access.

Usage:
    python -m viewer <trace_dir_or_file>          # launch TUI (legacy)
    python -m viewer stats <trace_dir_or_file>    # JSON trace metadata
    python -m viewer export <trace_dir_or_file> --format sqlite -o out.db
"""
from __future__ import annotations
import sys, argparse, json, pathlib


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
    print(json.dumps(out, indent=2, ensure_ascii=False))


def cmd_export(args):
    if args.format != "sqlite":
        print(f"unsupported format: {args.format}", file=sys.stderr); sys.exit(1)
    from .trace import load, ALL_REGS
    from .disasm import decode
    import sqlite3
    t = load(args.trace)
    out_path = args.output or (pathlib.Path(args.trace).resolve().name + ".db")
    con = sqlite3.connect(out_path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=OFF")
    # Build table
    cols = ["idx INTEGER PRIMARY KEY", "pc INTEGER", "inst INTEGER",
            "sp INTEGER", "nzcv INTEGER"]
    for r in ALL_REGS:
        if r in ("pc", "sp", "nzcv"): continue
        cols.append(f'"{r}" INTEGER')
    con.execute(f"CREATE TABLE IF NOT EXISTS records ({', '.join(cols)})")
    con.execute("CREATE INDEX IF NOT EXISTS idx_pc ON records(pc)")
    # Insert in batches
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
    print(f"exported {n} records to {out_path}")


_KNOWN_SUBCOMMANDS = {"stats", "export"}


def main():
    # Legacy path: `python -m viewer <trace_dir_or_file>` → launch TUI directly.
    # 必须在 argparse 之前判定, 否则 add_subparsers 会把第一个位置参数当 subcommand
    # 解析失败 (invalid choice).
    if len(sys.argv) >= 2 and sys.argv[1] not in _KNOWN_SUBCOMMANDS \
            and sys.argv[1] not in ("-h", "--help"):
        from .app import TraceMikuApp
        app = TraceMikuApp(sys.argv[1])
        app.run()
        return

    parser = argparse.ArgumentParser(prog="viewer", description="traceMiku CLI")
    sub = parser.add_subparsers(dest="subcommand")

    p_stats = sub.add_parser("stats", help="print trace metadata as JSON")
    p_stats.add_argument("trace", help="trace directory or .bin file")

    p_export = sub.add_parser("export", help="export trace to SQLite")
    p_export.add_argument("trace", help="trace directory or .bin file")
    p_export.add_argument("--format", default="sqlite", choices=["sqlite"])
    p_export.add_argument("-o", "--output", help="output file path")

    args = parser.parse_args()
    if args.subcommand == "stats":
        cmd_stats(args)
    elif args.subcommand == "export":
        cmd_export(args)
    else:
        parser.print_help(); sys.exit(1)


if __name__ == "__main__":
    main()
