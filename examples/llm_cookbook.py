"""traceMiku Rust v2 CLI cookbook for LLM/tooling agents.

The old Python `viewer` SDK was removed during the Rust/Solid v2 cutover.
These examples intentionally use the stable top-level CLI and JSON route
wrappers instead, so they work in the same environment as `make test-v2`.

Usage:
    uv run python examples/llm_cookbook.py <example> [call_dir]
    uv run python examples/llm_cookbook.py all [call_dir]

When `call_dir` is omitted, the script builds and uses the 9-record smoke trace
under `/tmp/tracemiku_smoke`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable


REPO = Path(__file__).resolve().parent.parent
DEFAULT_TRACE = Path("/tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms")


def ensure_default_trace() -> Path:
    if not (DEFAULT_TRACE / "trace.bin").exists():
        subprocess.run(
            [sys.executable, str(REPO / "scripts" / "build_smoke_trace.py")],
            cwd=REPO,
            check=True,
        )
    return DEFAULT_TRACE


def trace_path(raw: str | None) -> Path:
    path = Path(raw).expanduser().resolve() if raw else ensure_default_trace()
    if not (path / "trace.bin").exists():
        raise SystemExit(f"trace call_dir not found or missing trace.bin: {path}")
    return path


def run_json(*args: str) -> Any:
    proc = subprocess.run(
        [str(REPO / "tracemiku"), *args],
        cwd=REPO,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        sys.stderr.write(proc.stdout)
        raise SystemExit(proc.returncode)
    return json.loads(proc.stdout)


def query(path: Path, subcommand: str, *args: str) -> Any:
    return run_json("query", str(path), subcommand, *args)


def print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def info(path: Path) -> None:
    """Trace metadata and completeness."""
    print_json(run_json("info", str(path), "--json"))


def first_records(path: Path) -> None:
    """First 12 decoded records with symbol annotations."""
    resp = query(path, "records", "--range", "0..12", "--regs", "x0,x1,sp")
    rows = [
        {
            "idx": r["idx"],
            "pc": r["pc"],
            "func": r.get("func"),
            "asm": r["asm"],
            "annotation": r.get("annotation"),
        }
        for r in resp.get("records", [])
    ]
    print_json({"returned": resp.get("returned"), "truncated": resp.get("truncated"), "records": rows})


def cfg_summary(path: Path) -> None:
    """CFG size and hottest blocks."""
    cfg = query(path, "cfg")
    blocks = sorted(cfg.get("blocks", []), key=lambda b: -int(b.get("executions", 0)))
    print_json(
        {
            "status": cfg.get("status"),
            "blocks": len(cfg.get("blocks", [])),
            "edges": len(cfg.get("edges", [])),
            "hot_blocks": blocks[:10],
        }
    )


def functions(path: Path) -> None:
    """FunctionIndex summary."""
    resp = query(path, "func-summary")
    print_json(
        {
            "counts": resp.get("counts"),
            "functions": [
                {
                    "id": fn.get("id"),
                    "name": fn.get("name"),
                    "source": fn.get("source"),
                    "entry_idx": fn.get("entry_idx"),
                    "records": fn.get("records"),
                }
                for fn in resp.get("functions", [])[:20]
            ],
        }
    )


def search_calls(path: Path) -> None:
    """Search decoded assembly for call instructions."""
    resp = query(path, "search", "--pattern", r"^bl\b", "--max", "20")
    print_json(
        {
            "returned": resp.get("returned"),
            "total_matches": resp.get("total_matches"),
            "truncated": resp.get("truncated"),
            "hits": resp.get("hits", [])[:20],
        }
    )


def strings(path: Path) -> None:
    """Printable strings found through MemShadow."""
    resp = query(path, "strings", "--min-len", "8")
    print_json(
        {
            "count": resp.get("count"),
            "returned": resp.get("returned"),
            "truncated": resp.get("truncated"),
            "strings": resp.get("strings", [])[:20],
        }
    )


def taint_fwd(path: Path) -> None:
    """Forward taint from x0 at trace idx 0."""
    print_json(query(path, "forward-taint", "--from", "0", "--reg", "x0", "--max", "20"))


def taint_bwd(path: Path) -> None:
    """Backward taint for x0 near the middle of the trace."""
    meta = run_json("info", str(path), "--json")
    start = max(0, int(meta.get("records") or 0) // 2)
    print_json(query(path, "backward-taint", "--from", str(start), "--reg", "x0", "--max", "20"))


def overview(path: Path) -> None:
    """One compact context bundle for an LLM agent."""
    meta = run_json("info", str(path), "--json")
    recs = query(path, "records", "--range", "0..8")
    cfg = query(path, "cfg")
    funcs = query(path, "func-summary")
    print_json(
        {
            "trace": {
                "path": str(path),
                "records": meta.get("records"),
                "complete": meta.get("is_complete"),
                "first_pc": meta.get("first_pc"),
                "last_pc": meta.get("last_pc"),
            },
            "cfg": {
                "status": cfg.get("status"),
                "blocks": len(cfg.get("blocks", [])),
                "edges": len(cfg.get("edges", [])),
            },
            "function_counts": funcs.get("counts"),
            "first_records": recs.get("records", []),
        }
    )


EXAMPLES: dict[str, Callable[[Path], None]] = {
    "info": info,
    "first_records": first_records,
    "cfg_summary": cfg_summary,
    "functions": functions,
    "search_calls": search_calls,
    "strings": strings,
    "taint_fwd": taint_fwd,
    "taint_bwd": taint_bwd,
    "overview": overview,
}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in {"-h", "--help"}:
        print(__doc__)
        print("Examples:")
        for name, fn in EXAMPLES.items():
            print(f"  {name:14s} {fn.__doc__ or ''}")
        return 0

    name = sys.argv[1]
    path = trace_path(sys.argv[2] if len(sys.argv) > 2 else None)
    if name == "all":
        for key, fn in EXAMPLES.items():
            print(f"\n== {key} ==")
            fn(path)
        return 0

    fn = EXAMPLES.get(name)
    if fn is None:
        known = ", ".join(["all", *EXAMPLES.keys()])
        raise SystemExit(f"unknown example {name!r}; expected one of: {known}")
    fn(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
