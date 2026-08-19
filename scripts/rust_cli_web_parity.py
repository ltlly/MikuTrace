"""Compare Rust CLI route wrappers with the live Rust web API on one trace.

Default usage builds the persistent 9-record smoke trace under /tmp and checks
the route families that previously regressed during Rust/Solid hardening:

    uv run python scripts/rust_cli_web_parity.py
    uv run python scripts/rust_cli_web_parity.py traces/run/calls/call_...
"""

from __future__ import annotations

import argparse
import difflib
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rust_web_smoke import (
    REPO_ROOT,
    fetch_json,
    free_port,
    server_cmd,
    stop_proc,
    wait_ready,
)


@dataclass(frozen=True)
class Case:
    name: str
    path: str
    cli_args: tuple[str, ...]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rust CLI vs Rust web API parity gate."
    )
    parser.add_argument(
        "trace",
        nargs="?",
        help="per-call trace directory; default builds /tmp/tracemiku_smoke fixture",
    )
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument(
        "--debug-bin", action="store_true", help="use debug tracemiku-server"
    )
    return parser.parse_args()


def default_trace() -> Path:
    subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "build_smoke_trace.py")],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return Path("/tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms")


def cli_cmd(trace: Path, args: tuple[str, ...]) -> list[str]:
    binary = REPO_ROOT / "rust" / "target" / "debug" / "tracemiku-cli"
    if binary.exists():
        return [str(binary), *args[:1], str(trace), *args[1:]]
    return [
        "cargo",
        "run",
        "--manifest-path",
        "rust/Cargo.toml",
        "-p",
        "tracemiku-cli",
        "--",
        *args[:1],
        str(trace),
        *args[1:],
    ]


def run_cli(trace: Path, args: tuple[str, ...], timeout: float) -> Any:
    out = subprocess.check_output(
        cli_cmd(trace, args), cwd=REPO_ROOT, text=True, timeout=timeout
    )
    return json.loads(out)


def format_json(value: Any) -> list[str]:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).splitlines(
        keepends=True
    )


def assert_equal(case: Case, web: Any, cli: Any) -> None:
    web = normalize_case(case, web)
    cli = normalize_case(case, cli)
    if web == cli:
        return
    diff = "".join(
        difflib.unified_diff(
            format_json(web),
            format_json(cli),
            fromfile=f"web:{case.path}",
            tofile=f"cli:{case.name}",
        )
    )
    raise AssertionError(f"{case.name} parity mismatch\n{diff}")


def sort_dicts(items: Any) -> Any:
    if not isinstance(items, list):
        return items
    return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))


def normalize_case(case: Case, value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    if case.name == "cfg":
        out = dict(value)
        out["blocks"] = sort_dicts(out.get("blocks"))
        out["edges"] = sort_dicts(out.get("edges"))
        return out
    if case.name == "meta":
        # CLI meta adds record_size:272 / format_version:1 (its own contract
        # extensions); the web /api/meta surface does not have them. Compare
        # only the shared contract.
        out = dict(value)
        out.pop("record_size", None)
        out.pop("format_version", None)
        return out
    return value


def cases() -> list[Case]:
    return [
        Case("meta", "/api/meta", ("meta",)),
        Case(
            "records",
            "/api/records?start=0&count=9",
            ("records", "--start", "0", "--count", "9"),
        ),
        Case(
            "api-records",
            "/api/records?start=0&count=2",
            ("api", "/api/records", "-p", "start=0", "-p", "count=2"),
        ),
        Case("cfg", "/api/cfg", ("cfg",)),
        Case(
            "query-records",
            "/api/query?kind=records&q=ret&idx=0&limit=10",
            ("query", "--kind", "records", "--q", "ret", "--idx", "0", "--limit", "10"),
        ),
        Case(
            "search-cursor",
            "/api/search?pattern=ret&max_results=4&cursor=4",
            ("search", "ret", "--max-results", "4", "--cursor", "4"),
        ),
        Case(
            "backtrace",
            "/api/backtrace?idx=4&limit=10",
            ("backtrace", "--idx", "4", "--limit", "10"),
        ),
        Case(
            "block-for-pc",
            "/api/block-for-pc?pc=0x100000",
            ("block-for-pc", "--pc", "0x100000"),
        ),
        Case(
            "idxs-for-block",
            "/api/idxs-for-block?pc=0x100000&max_count=10&near=4",
            ("idxs-for-block", "--pc", "0x100000", "--max-count", "10", "--near", "4"),
        ),
        Case(
            "strings",
            "/api/strings?min_len=4&q=&cursor=-1&limit=20",
            ("strings", "--min-len", "4", "--q", "", "--cursor=-1", "--limit", "20"),
        ),
        Case(
            "string-provenance",
            "/api/string-provenance?addr=0x7000&length=4",
            ("string-provenance", "--addr", "0x7000", "--length", "4"),
        ),
        Case(
            "memory-dump",
            "/api/mem-dump?addr=0x7000&count=8",
            ("mem-dump", "--addr", "0x7000", "--count", "8"),
        ),
        Case(
            "mem-writes-in-range",
            "/api/mem-writes-in-range?idx_lo=0&idx_hi=9&addr_lo=0x7000&addr_hi=0x7008&max=5",
            (
                "mem-writes-in-range",
                "--idx-lo",
                "0",
                "--idx-hi",
                "9",
                "--addr-lo",
                "0x7000",
                "--addr-hi",
                "0x7008",
                "--max",
                "5",
            ),
        ),
        Case(
            "last-write-of-reg",
            "/api/last-write-of-reg?reg=x0&before=4",
            ("last-write-of-reg", "--reg", "x0", "--before", "4"),
        ),
        Case(
            "forward-taint",
            "/api/forward-taint?trace_idx=0&reg=x0&max_count=10&cross_fn_call=true",
            (
                "taint-fwd",
                "--start",
                "0",
                "--reg",
                "x0",
                "--max-count",
                "10",
                "--cross-fn-call",
            ),
        ),
        Case(
            "jni-events",
            "/api/jni-events?limit=10",
            ("jni-events", "--limit", "10"),
        ),
        Case(
            "resolve",
            "/api/resolve?so=libt.so&off=0x100",
            ("resolve", "--so", "libt.so", "--off", "0x100"),
        ),
        Case(
            "coverage",
            "/api/coverage?so=libt.so&off=0x0",
            ("coverage", "--so", "libt.so", "--off", "0x0"),
        ),
        Case("loops", "/api/loops", ("loops",)),
        Case("block", "/api/block?pc=0x100000", ("block", "--pc", "0x100000")),
        Case(
            "reg-timeline",
            "/api/reg-timeline?reg=x0&start=0&end=9",
            ("reg-timeline", "--reg", "x0", "--start", "0", "--end", "9"),
        ),
        Case(
            "mem-flow",
            "/api/mem-flow?addr=0x7000&count=4",
            ("mem-flow", "--addr", "0x7000", "--count", "4"),
        ),
        Case(
            "fn-summary",
            "/api/fn-summary?fn=f_root",
            ("fn-summary", "--fn", "f_root"),
        ),
        Case(
            "idxs-touching-addr",
            "/api/idxs-touching-addr?addr=0x7000",
            ("idxs-touching-addr", "--addr", "0x7000"),
        ),
    ]


def main() -> int:
    args = parse_args()
    trace = Path(args.trace).resolve() if args.trace else default_trace()
    if not trace.is_dir() or not (trace / "trace.bin").exists():
        print(f"FAIL invalid trace call_dir: {trace}", file=sys.stderr)
        return 2
    static_dir = REPO_ROOT / "frontend" / "dist"
    if not (static_dir / "index.html").exists():
        print(
            "FAIL frontend/dist/index.html missing; run npm run build in frontend/",
            file=sys.stderr,
        )
        return 2

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        server_cmd(trace, static_dir, port, args.debug_bin),
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,  # stop_proc 按进程组 kill，等价 preexec_fn=setsid 且线程安全
    )
    try:
        wait_ready(base, proc, args.timeout)
        checked = []
        for case in cases():
            web = fetch_json(base, case.path, args.timeout)
            cli = run_cli(trace, case.cli_args, args.timeout)
            assert_equal(case, web, cli)
            checked.append(case.name)
        print(f"OK rust CLI/web parity trace={trace} cases={','.join(checked)}")
        return 0
    finally:
        stop_proc(proc)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        sys.exit(1)
