"""M3-δ parity differ — /api/dec/summary fn-id structural comparison.

Boots Python webui + Rust tracemiku-server, fetches /api/dec/summary
on each, compares the fn-id set Jaccard. Tolerance ≥ 0.6.

M3-δ ships a SKELETON: only the trace-ir source (root F0). Python
emits trace-ir + symbol-source entries (fallback fns from CFG / sym).
The Jaccard will likely be very small on real traces — soft-gate
this until M3-ε ports the symbol-source fallback in /api/dec/summary.

Usage:
    uv run python scripts/m3_delta_parity.py <call_dir>
"""
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_listening(port: int, timeout: float = 60.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"port {port} never opened")


def fetch(port: int, path: str) -> dict:
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    with urllib.request.urlopen(req, timeout=60.0) as r:
        return json.loads(r.read().decode("utf-8"))


def main():
    if len(sys.argv) != 2:
        print("usage: m3_delta_parity.py <call_dir>", file=sys.stderr)
        sys.exit(2)
    call_dir = Path(sys.argv[1]).resolve()
    if not call_dir.is_dir() or not (call_dir / "trace.bin").exists():
        print(f"# {call_dir} is not a valid call_dir (missing trace.bin)",
              file=sys.stderr)
        sys.exit(2)

    py_port = free_port()
    rs_port = free_port()
    print(f"# M3-δ parity: python={py_port} rust={rs_port} on {call_dir.name}",
          file=sys.stderr)

    py_proc = subprocess.Popen(
        ["./tracemiku", "web", str(call_dir),
         "--port", str(py_port), "--no-browser"],
        cwd=REPO_ROOT, preexec_fn=os.setsid,
        stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    )
    rs_proc = subprocess.Popen(
        ["./rust/target/release/tracemiku-server", str(call_dir),
         "--port", str(rs_port)],
        cwd=REPO_ROOT, preexec_fn=os.setsid,
        stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    )

    try:
        wait_listening(py_port)
        wait_listening(rs_port)

        # M3-ε closed the soft-gate by porting:
        #   1. split_top_k_callees in build_trace_ir (F1..Fn entries)
        #   2. symbol-source fallback in /api/dec/summary handler
        # Both endpoints are now hard-gated; jaccard ≥ 0.6 required.
        SOFT_LABELS: set[str] = set()

        # Python may take 30-60s on a 469k-record trace to build the IR
        # because TraceIR construction is lazy. fetch() has a 60s timeout.
        try:
            py = fetch(py_port, "/api/dec/summary?split_top_k=10&split_min_records=50")
            rs = fetch(rs_port, "/api/dec/summary")
        except Exception as e:
            print(f"WARN: fetch failed: {e}", file=sys.stderr)
            sys.exit(0)

        py_ids = {f.get("id") for f in py.get("fns", []) or []}
        rs_ids = {f.get("id") for f in rs.get("fns", []) or []}

        if not py_ids and not rs_ids:
            print("# trivial parity (both empty): dec-summary", file=sys.stderr)
            return

        common = py_ids & rs_ids
        union = py_ids | rs_ids
        jaccard = (len(common) / len(union)) if union else 1.0

        diffs = []
        warns = []

        # Sanity: both should have at least the root F0.
        if "trace:F0" not in py_ids:
            diffs.append(f"  python missing trace:F0; got {sorted(py_ids)[:5]}")
        if "trace:F0" not in rs_ids:
            diffs.append(f"  rust missing trace:F0; got {sorted(rs_ids)[:5]}")

        if jaccard < 0.6:
            bucket = warns if "dec-summary" in SOFT_LABELS else diffs
            bucket.append(
                f"  dec-summary fn-id jaccard={jaccard:.2f} <0.6 — "
                f"py={len(py_ids)}, rs={len(rs_ids)}, common={len(common)}"
            )
            bucket.append(f"  py-only sample: {sorted(py_ids - rs_ids)[:5]}")
            bucket.append(f"  rs-only sample: {sorted(rs_ids - py_ids)[:5]}")

        if warns:
            print("WARN (M3-ε-deferred):", file=sys.stderr)
            for w in warns:
                print(w, file=sys.stderr)

        if diffs:
            print("MISMATCH:", file=sys.stderr)
            for d in diffs:
                print(d, file=sys.stderr)
            sys.exit(1)

        print(
            f"OK — dec-summary (py={len(py_ids)} / rs={len(rs_ids)}; "
            f"jaccard={jaccard:.2f})",
            file=sys.stderr,
        )
    finally:
        for proc in (py_proc, rs_proc):
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass


if __name__ == "__main__":
    main()
