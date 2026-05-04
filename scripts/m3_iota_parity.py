"""M3-iota parity gate for real-trace decompiler endpoints.

Boots Python webui + Rust tracemiku-server by default, compares
/api/dec/summary and /api/dec/fn/trace:F0?tier=hot, and exits non-zero on
hard-gate failures.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TRACE = "traces/xsign_run1/calls/call_002_tid30203_7624431r_4655ms"
DEFAULT_PYTHON_PORT = 18080
DEFAULT_RUST_PORT = 18081


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Real-trace parity gate for M3-iota decompiler endpoints."
    )
    parser.add_argument("--trace", default=DEFAULT_TRACE, help="call_dir trace path")
    parser.add_argument("--python-port", type=int, default=DEFAULT_PYTHON_PORT)
    parser.add_argument("--rust-port", type=int, default=DEFAULT_RUST_PORT)
    parser.add_argument(
        "--fn-set-threshold",
        type=float,
        default=0.95,
        help="minimum Jaccard for /api/dec/summary (name, entry_idx) pairs",
    )
    parser.add_argument(
        "--summary-md-threshold",
        type=float,
        default=0.85,
        help="minimum token-set Jaccard for /api/dec/summary summary_md",
    )
    parser.add_argument(
        "--fn-md-threshold",
        type=float,
        default=0.85,
        help="minimum token-set Jaccard for /api/dec/fn/trace:F0 markdown",
    )
    parser.add_argument(
        "--vm-dispatcher-pc-delta",
        type=int,
        default=4,
        help="allowed absolute delta for VM dispatcher_pc when both sides emit candidates",
    )
    parser.add_argument(
        "--vm-confidence-delta",
        type=float,
        default=0.1,
        help="allowed absolute confidence delta when both sides emit VM candidates",
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="do not start services; use the supplied ports as already-running servers",
    )
    return parser.parse_args()


def start_python(trace: Path, port: int) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        ["./tracemiku", "web", str(trace), "--port", str(port), "--no-browser"],
        cwd=REPO_ROOT,
        preexec_fn=os.setsid,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def start_rust(trace: Path, port: int) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            "cargo",
            "run",
            "--release",
            "-p",
            "tracemiku-server",
            "--",
            str(trace),
            "--port",
            str(port),
        ],
        cwd=REPO_ROOT / "rust",
        preexec_fn=os.setsid,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def stop_proc(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5.0)


def fetch(port: int, path: str, timeout: float = 120.0) -> dict[str, Any]:
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def wait_healthy(port: int, label: str, timeout: float = 240.0) -> None:
    deadline = time.time() + timeout
    last_error = ""
    while time.time() < deadline:
        try:
            fetch(port, "/api/meta", timeout=5.0)
            return
        except Exception as exc:  # noqa: BLE001 - report the last health error.
            last_error = str(exc)
            time.sleep(1.0)
    raise TimeoutError(f"{label} server on port {port} not healthy: {last_error}")


def token_set(text: str) -> set[str]:
    return set(re.findall(r"[A-Za-z0-9_:.+-]+", text.lower()))


def jaccard(left: set[Any], right: set[Any]) -> float:
    union = left | right
    return (len(left & right) / len(union)) if union else 1.0


def fn_name_entry_set(summary: dict[str, Any]) -> set[tuple[str, Any]]:
    out = set()
    for fn in summary.get("fns", []) or []:
        name = fn.get("name")
        if name is None:
            continue
        out.add((str(name), fn.get("entry_idx")))
    return out


def metric_line(ok: bool, label: str, value: float, threshold: float) -> str:
    status = "PASS" if ok else "FAIL"
    return f"{status} {label}={value:.3f} threshold={threshold:.3f}"


def compare_threshold(
    failures: list[str],
    lines: list[str],
    label: str,
    value: float,
    threshold: float,
) -> None:
    ok = value >= threshold
    lines.append(metric_line(ok, label, value, threshold))
    if not ok:
        failures.append(f"{label} {value:.3f} < {threshold:.3f}")


def parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def compare_vm_candidates(
    py_summary: dict[str, Any],
    rs_summary: dict[str, Any],
    max_pc_delta: int,
    max_conf_delta: float,
    failures: list[str],
    lines: list[str],
) -> None:
    py_candidates = py_summary.get("vm_candidates", []) or []
    rs_candidates = rs_summary.get("vm_candidates", []) or []
    if not py_candidates or not rs_candidates:
        ok = not py_candidates and not rs_candidates
        status = "PASS" if ok else "FAIL"
        lines.append(f"{status} vm_candidates py={len(py_candidates)} rust={len(rs_candidates)}")
        if not ok:
            failures.append(
                f"vm_candidates presence mismatch py={len(py_candidates)} rust={len(rs_candidates)}"
            )
        return

    py_top = py_candidates[0]
    rs_top = rs_candidates[0]
    py_pc = parse_int(py_top.get("dispatcher_pc"))
    rs_pc = parse_int(rs_top.get("dispatcher_pc"))
    py_conf = float(py_top.get("confidence") or 0.0)
    rs_conf = float(rs_top.get("confidence") or 0.0)

    pc_delta = None if py_pc is None or rs_pc is None else abs(py_pc - rs_pc)
    conf_delta = abs(py_conf - rs_conf)
    ok = pc_delta is not None and pc_delta <= max_pc_delta and conf_delta <= max_conf_delta
    status = "PASS" if ok else "FAIL"
    lines.append(
        f"{status} vm_candidates pc_delta={pc_delta} "
        f"threshold={max_pc_delta} conf_delta={conf_delta:.3f} "
        f"threshold={max_conf_delta:.3f}"
    )
    if not ok:
        failures.append(
            "vm_candidates mismatch "
            f"pc_delta={pc_delta} conf_delta={conf_delta:.3f}"
        )


def main() -> int:
    args = parse_args()
    trace = Path(args.trace)
    if not trace.is_absolute():
        trace = (REPO_ROOT / trace).resolve()
    if not trace.is_dir() or not (trace / "trace.bin").exists():
        print(f"FAIL trace invalid: {trace}", file=sys.stderr)
        return 2

    procs: list[subprocess.Popen[bytes]] = []
    try:
        if not args.no_start:
            procs.append(start_python(trace, args.python_port))
            procs.append(start_rust(trace, args.rust_port))

        wait_healthy(args.python_port, "python")
        wait_healthy(args.rust_port, "rust")

        summary_path = "/api/dec/summary?split_top_k=10&split_min_records=50&with_memshadow=true"
        fn_id = urllib.parse.quote("trace:F0", safe="")
        fn_path = f"/api/dec/fn/{fn_id}?tier=hot"

        py_summary = fetch(args.python_port, summary_path)
        rs_summary = fetch(args.rust_port, summary_path)
        py_fn = fetch(args.python_port, fn_path)
        rs_fn = fetch(args.rust_port, fn_path)

        lines = [f"# M3-iota parity trace={trace.name}"]
        failures: list[str] = []

        fn_score = jaccard(fn_name_entry_set(py_summary), fn_name_entry_set(rs_summary))
        compare_threshold(
            failures, lines, "summary_fns_jaccard", fn_score, args.fn_set_threshold
        )

        summary_score = jaccard(
            token_set(str(py_summary.get("summary_md") or "")),
            token_set(str(rs_summary.get("summary_md") or "")),
        )
        compare_threshold(
            failures,
            lines,
            "summary_md_token_jaccard",
            summary_score,
            args.summary_md_threshold,
        )

        fn_md_score = jaccard(
            token_set(str(py_fn.get("markdown") or "")),
            token_set(str(rs_fn.get("markdown") or "")),
        )
        compare_threshold(
            failures, lines, "fn_trace_F0_md_token_jaccard", fn_md_score, args.fn_md_threshold
        )

        compare_vm_candidates(
            py_summary,
            rs_summary,
            args.vm_dispatcher_pc_delta,
            args.vm_confidence_delta,
            failures,
            lines,
        )

        for line in lines:
            print(line)
        if failures:
            print("FAIL " + "; ".join(failures))
            return 1
        print("PASS all gates")
        return 0
    finally:
        for proc in procs:
            stop_proc(proc)


if __name__ == "__main__":
    sys.exit(main())
