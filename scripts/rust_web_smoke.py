"""Boot a Rust traceMiku web server and run visible-UI API smoke probes.

Usage:
    uv run python scripts/rust_web_smoke.py \
      traces/test_hide_only/calls/_truncated_call_002_tid27340_469639r_1641ms
    uv run python scripts/rust_web_smoke.py <call_dir> --build-release

This is an end-to-end-ish Rust web gate: it starts the real tracemiku-server
binary, serves the current frontend/dist, waits for /api/meta, verifies the SPA
index route is not an API HTML fallback, runs scripts/web_api_perf_probe.py, and
checks taint tree metadata used by the Taint panel. The perf probe also polls a
light health endpoint while each measured request is running, so CPU-heavy
routes cannot silently block the async runtime.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TIMEOUT = 180.0
LARGE_TRACE_PARALLEL_MIN_RECORDS = 1_000_000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Rust web end-to-end smoke gate.")
    parser.add_argument("trace", help="per-call trace directory containing trace.bin")
    parser.add_argument("--port", type=int, default=0, help="listen port; default picks a free port")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--build-release",
        action="store_true",
        help="build rust/target/release/tracemiku-server before starting",
    )
    parser.add_argument(
        "--debug-bin",
        action="store_true",
        help="use rust/target/debug/tracemiku-server instead of release",
    )
    parser.add_argument(
        "--all-surfaces",
        action="store_true",
        help="include hidden/backend-only surfaces in web_api_perf_probe.py",
    )
    parser.add_argument(
        "--wait-mem-ready",
        action="store_true",
        help="wait for background MemShadow to reach ready and print elapsed startup time",
    )
    parser.add_argument(
        "--mem-ready-timeout",
        type=float,
        default=None,
        help="timeout for --wait-mem-ready; defaults to --timeout",
    )
    return parser.parse_args()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def fetch_bytes(base: str, path: str, timeout: float) -> tuple[bytes, int, dict[str, str]]:
    with urllib.request.urlopen(base.rstrip("/") + path, timeout=timeout) as resp:
        body = resp.read()
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return body, int(resp.status), headers


def fetch_json(base: str, path: str, timeout: float) -> Any:
    body, status, headers = fetch_bytes(base, path, timeout)
    content_type = headers.get("content-type", "")
    if status < 200 or status >= 300:
        raise RuntimeError(f"{path} returned HTTP {status}: {body[:160]!r}")
    if "json" not in content_type.lower():
        raise RuntimeError(f"{path} did not return JSON content-type={content_type!r}: {body[:160]!r}")
    return json.loads(body.decode("utf-8"))


def wait_ready(base: str, proc: subprocess.Popen[str], timeout: float) -> None:
    deadline = time.time() + timeout
    last_error = ""
    while time.time() < deadline:
        if proc.poll() is not None:
            logs = read_available_logs(proc)
            raise RuntimeError(f"server exited before ready code={proc.returncode}\n{logs}")
        try:
            fetch_json(base, "/api/meta", 5.0)
            return
        except Exception as exc:  # noqa: BLE001 - report last readiness error.
            last_error = str(exc)
            time.sleep(0.25)
    raise TimeoutError(f"server not ready before timeout: {last_error}")


def read_available_logs(proc: subprocess.Popen[str]) -> str:
    if proc.stdout is None:
        return ""
    try:
        return proc.stdout.read() or ""
    except Exception:  # noqa: BLE001
        return ""


def stop_proc(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
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


def build_release() -> None:
    subprocess.run(
        ["cargo", "build", "--manifest-path", "rust/Cargo.toml", "-p", "tracemiku-server", "--release"],
        cwd=REPO_ROOT,
        check=True,
    )


def server_cmd(trace: Path, static_dir: Path, port: int, debug_bin: bool) -> list[str]:
    profile = "debug" if debug_bin else "release"
    binary = REPO_ROOT / "rust" / "target" / profile / "tracemiku-server"
    if binary.exists():
        return [
            str(binary),
            str(trace),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--static-dir",
            str(static_dir),
        ]
    cargo_profile = [] if debug_bin else ["--release"]
    return [
        "cargo",
        "run",
        "--manifest-path",
        "rust/Cargo.toml",
        *cargo_profile,
        "-p",
        "tracemiku-server",
        "--",
        str(trace),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--static-dir",
        str(static_dir),
    ]


def run_probe(base: str, timeout: float, visible_only: bool) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "web_api_perf_probe.py"),
        base,
        "--json",
        "--timeout",
        str(timeout),
        "--runtime-blocking-check",
        "--health-interval",
        "0.01",
    ]
    if visible_only:
        cmd.append("--visible-ui-only")
    out = subprocess.check_output(cmd, cwd=REPO_ROOT, text=True)
    return json.loads(out)


def verify_frontend(base: str, timeout: float) -> None:
    body, status, headers = fetch_bytes(base, "/", timeout)
    if status != 200:
        raise RuntimeError(f"/ returned HTTP {status}")
    text = body.decode("utf-8", "replace")
    if '<div id="app"></div>' not in text:
        raise RuntimeError("/ did not serve frontend index.html")
    cache_control = headers.get("cache-control", "")
    if "no-cache" not in cache_control and "no-store" not in cache_control:
        raise RuntimeError(f"/ index route missing no-cache header: {cache_control!r}")
    assets = re.findall(r'(?:src|href)="([^"]*?/assets/[^"]+)"', text)
    if not assets:
        raise RuntimeError("frontend index did not reference hashed assets")
    for asset in assets[:4]:
        _, asset_status, _ = fetch_bytes(base, asset, timeout)
        if asset_status != 200:
            raise RuntimeError(f"asset {asset} returned HTTP {asset_status}")


def verify_taint_tree(base: str, timeout: float) -> None:
    meta = fetch_json(base, "/api/meta", timeout)
    records = int(meta.get("records") or 0)
    if records <= 0:
        raise RuntimeError("/api/meta returned no records")
    resp = fetch_json(
        base,
        "/api/forward-taint?trace_idx=0&reg=x0&max_count=200&cross_fn_call=true",
        timeout,
    )
    if resp.get("status") != "ready":
        raise RuntimeError(f"forward taint not ready: {resp}")
    hits = resp.get("hits") or []
    if hits:
        missing_depth = [hit.get("idx") for hit in hits if "taint_depth" not in hit]
        if missing_depth:
            raise RuntimeError(f"taint hits missing taint_depth: {missing_depth[:8]}")
        if not any(hit.get("parent_idxs") for hit in hits):
            raise RuntimeError("taint tree smoke found hits but no parent_idxs edge")


def fetch_bg_status(base: str, timeout: float) -> dict[str, Any]:
    status = fetch_json(base, "/api/bg-status", timeout)
    if not isinstance(status, dict):
        raise RuntimeError(f"/api/bg-status returned non-object: {status!r}")
    parallelism = status.get("parallelism")
    if not isinstance(parallelism, dict):
        raise RuntimeError(f"/api/bg-status missing parallelism object: {status!r}")
    workers = parallelism.get("workers")
    if not isinstance(workers, dict) or not workers:
        raise RuntimeError(f"/api/bg-status parallelism missing workers: {parallelism!r}")
    available = int(parallelism.get("available") or 1)
    records = int(parallelism.get("records") or 0)
    if available > 1 and records >= LARGE_TRACE_PARALLEL_MIN_RECORDS:
        single_worker = {
            str(name): count
            for name, count in workers.items()
            if int(count or 0) < 2
        }
        if single_worker:
            raise RuntimeError(
                "/api/bg-status parallelism planned single-worker large-trace scans "
                f"records={records:,} available={available} workers={single_worker!r}"
            )
    return status


def wait_mem_ready(base: str, timeout: float, server_started: float) -> tuple[dict[str, Any], float]:
    deadline = time.time() + timeout
    last_status = "?"
    while time.time() < deadline:
        status = fetch_bg_status(base, min(5.0, timeout))
        last_status = str((status.get("mem") or {}).get("status", "?"))
        if last_status == "ready":
            return status, (time.perf_counter() - server_started) * 1000.0
        time.sleep(0.25)
    raise TimeoutError(f"MemShadow did not become ready before timeout; last status={last_status}")


def format_parallelism(bg_status: dict[str, Any], mem_ready_ms: float | None = None) -> str:
    parallelism = bg_status.get("parallelism") or {}
    workers = parallelism.get("workers") or {}
    worker_text = " ".join(f"{k}={v}" for k, v in sorted(workers.items()))
    mem = (bg_status.get("mem") or {}).get("status", "?")
    ready = f" mem_ready={mem_ready_ms:.1f}ms" if mem_ready_ms is not None else ""
    return f"available={parallelism.get('available', '?')} mem={mem}{ready} workers: {worker_text}"


def main() -> int:
    args = parse_args()
    trace = Path(args.trace)
    if not trace.is_absolute():
        trace = (REPO_ROOT / trace).resolve()
    if not trace.is_dir() or not (trace / "trace.bin").exists():
        print(f"FAIL invalid trace call_dir: {trace}", file=sys.stderr)
        return 2
    static_dir = REPO_ROOT / "frontend" / "dist"
    if not (static_dir / "index.html").exists():
        print("FAIL frontend/dist/index.html missing; run npm run build in frontend/", file=sys.stderr)
        return 2
    if args.build_release:
        build_release()

    port = args.port or free_port()
    base = f"http://127.0.0.1:{port}"
    cmd = server_cmd(trace, static_dir, port, args.debug_bin)
    server_started = time.perf_counter()
    proc = subprocess.Popen(
        cmd,
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    try:
        wait_ready(base, proc, args.timeout)
        bg_status = fetch_bg_status(base, args.timeout)
        mem_ready_ms: float | None = None
        if args.wait_mem_ready:
            bg_status, mem_ready_ms = wait_mem_ready(
                base,
                args.mem_ready_timeout if args.mem_ready_timeout is not None else args.timeout,
                server_started,
            )
        verify_frontend(base, args.timeout)
        verify_taint_tree(base, args.timeout)
        probe = run_probe(base, args.timeout, visible_only=not args.all_surfaces)
        failures = [m for m in probe["measurements"] if not m["ok"]]
        if failures:
            print(json.dumps({"base_url": base, "failures": failures}, indent=2), file=sys.stderr)
            return 1
        print(
            f"OK rust web smoke base={base} records={probe['records']:,} "
            f"measurements={len(probe['measurements'])}"
        )
        print(f"  parallelism {format_parallelism(bg_status, mem_ready_ms)}")
        slow = sorted(probe["measurements"], key=lambda m: float(m["ms"]), reverse=True)[:5]
        for m in slow:
            print(f"  {m['ms']:8.1f} ms {m['label']}")
        watched = {"cfg svg largest fn", "string provenance first", "reg timeline x0"}
        printed_labels = {m["label"] for m in slow}
        for m in probe["measurements"]:
            if m["label"] in watched and m["label"] not in printed_labels:
                print(f"  watch {float(m['ms']):6.1f} ms {m['label']}")
        health = sorted(
            [m for m in probe["measurements"] if int(m.get("health_polls") or 0) > 0],
            key=lambda m: float(m.get("health_max_ms") or 0.0),
            reverse=True,
        )[:3]
        for m in health:
            print(
                f"  health {float(m.get('health_max_ms') or 0.0):6.1f} ms "
                f"polls={int(m.get('health_polls') or 0)} during {m['label']}"
            )
        return 0
    finally:
        stop_proc(proc)


if __name__ == "__main__":
    sys.exit(main())
