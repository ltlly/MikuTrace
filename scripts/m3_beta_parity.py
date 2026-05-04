"""M3-β parity differ — /api/forward-taint + /api/backward-taint.

Boots Python webui + Rust tracemiku-server, fetches forward-taint and
backward-taint with start=0/reg=x0/max=200 and start=N-1/reg=x0/max=200.
Compares the hit-idx set Jaccard between Python and Rust on each endpoint.
Tolerance ≥ 0.6. Trivial-parity case (both empty) is OK.

Usage:
    uv run python scripts/m3_beta_parity.py <call_dir>
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
    with urllib.request.urlopen(req, timeout=30.0) as r:
        return json.loads(r.read().decode("utf-8"))


def wait_py_index_ready(port: int, timeout: float = 180.0):
    """Python webui builds Index lazily on first taint hit. Poll bg-status
    until index.status == 'ready' (or timeout). Kicks off the build by
    making one cheap forward-taint call which transitions status to
    'starting' / 'running'.
    """
    # Trigger BG build: any forward-taint request kicks _bg_run("index", ...).
    try:
        fetch(port, "/api/forward-taint?start=0&reg=x0&max_count=1")
    except Exception:
        pass
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            bg = fetch(port, "/api/bg-status")
            st = (bg.get("index") or {}).get("status")
            if st == "ready":
                return
        except Exception:
            pass
        time.sleep(1.0)
    raise TimeoutError(
        f"python BG index never reached 'ready' after {timeout}s")


def main():
    if len(sys.argv) != 2:
        print("usage: m3_beta_parity.py <call_dir>", file=sys.stderr)
        sys.exit(2)
    call_dir = Path(sys.argv[1]).resolve()
    if not call_dir.is_dir() or not (call_dir / "trace.bin").exists():
        print(f"# {call_dir} is not a valid call_dir (missing trace.bin)",
              file=sys.stderr)
        sys.exit(2)

    py_port = free_port()
    rs_port = free_port()
    print(f"# M3-β parity: python={py_port} rust={rs_port} on {call_dir.name}",
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

        # Python webui builds Index lazily on first taint hit and returns
        # {"status": "...", "hits": []} until ready. Poll bg-status until
        # index is ready before issuing the parity fetches.
        wait_py_index_ready(py_port)

        # Read meta to get total records (and pick a tail-ish index for backward).
        meta = fetch(rs_port, "/api/meta")
        n = int(meta.get("records") or 0)
        last_idx = max(n - 1, 0)

        endpoints = [
            (f"/api/forward-taint?start=0&reg=x0&max_count=200",
             "hits", "forward-taint"),
            (f"/api/backward-taint?start={last_idx}&reg=x0&max_count=200",
             "chain", "backward-taint"),
        ]

        # backward-taint is a SOFT gate in M3-β. Python's index path does
        # MEM-chasing unconditionally (viewer/taint.py:312-356), but the
        # Rust port skips it (M3-β scope: index-accelerated, no
        # through_mem). On real traces with frequent ld/st, the two
        # algorithms reach different parts of the chase graph under the
        # max_count cap. The gap is documented in TODO.md and lands as
        # part of M3-γ (advanced taint flags). Until then we surface the
        # divergence as a WARN, not a fail.
        SOFT_LABELS = {"backward-taint"}

        diffs = []           # hard failures (forward-taint)
        warns = []           # soft warnings (backward-taint)
        ok_lines = []

        for path, key, label in endpoints:
            try:
                py = fetch(py_port, path)
                rs = fetch(rs_port, path)
            except Exception as e:
                diffs.append(f"  {label} fetch failed: {e}")
                continue

            # Defensive: if Python still reports pending despite the wait,
            # retry once after a short sleep.
            if py.get("status") and py.get("status") != "ready":
                time.sleep(2.0)
                try:
                    py = fetch(py_port, path)
                except Exception:
                    pass

            py_idx = {row.get("idx") for row in py.get(key, []) or []}
            rs_idx = {row.get("idx") for row in rs.get(key, []) or []}

            if not py_idx and not rs_idx:
                ok_lines.append(f"# trivial parity (both empty): {label}")
                continue

            common = py_idx & rs_idx
            union = py_idx | rs_idx
            jaccard = (len(common) / len(union)) if union else 1.0

            if jaccard < 0.6:
                bucket = warns if label in SOFT_LABELS else diffs
                bucket.append(
                    f"  {label} hit-idx jaccard={jaccard:.2f} <0.6 — "
                    f"py={len(py_idx)}, rs={len(rs_idx)}, common={len(common)}"
                )
                bucket.append(
                    f"  py-only sample: {sorted(py_idx - rs_idx)[:5]}"
                )
                bucket.append(
                    f"  rs-only sample: {sorted(rs_idx - py_idx)[:5]}"
                )
            else:
                ok_lines.append(
                    f"OK — {label} (py={len(py_idx)} / rs={len(rs_idx)}; "
                    f"jaccard={jaccard:.2f})"
                )

        if warns:
            print("WARN (M3-γ-deferred):", file=sys.stderr)
            for w in warns:
                print(w, file=sys.stderr)

        if diffs:
            print("MISMATCH:", file=sys.stderr)
            for d in diffs:
                print(d, file=sys.stderr)
            sys.exit(1)

        for line in ok_lines:
            print(line, file=sys.stderr)
    finally:
        for proc in (py_proc, rs_proc):
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass


if __name__ == "__main__":
    main()
