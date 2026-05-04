"""M3-α parity differ — /api/call-tree structural comparison.

Boots Python webui + Rust tracemiku-server, fetches /api/call-tree on
each, compares root shape + bl-target name set + total node count.
Tolerance: Jaccard ≥ 0.6 on names, ±10% on total node count. Both
servers walk the same trace.bin so deviation comes only from edge
cases like PC-0 lookups or trailing unclosed frames.

Usage:
    uv run python scripts/m3_alpha_parity.py <call_dir>
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


def collect_names(node: dict) -> set:
    """All non-None fn names anywhere in the tree."""
    out = set()

    def walk(n):
        fn = n.get("fn")
        if fn and fn != "?":
            out.add(fn)
        for c in n.get("children", []) or []:
            walk(c)

    walk(node)
    return out


def count_nodes(node: dict) -> int:
    n = 1
    for c in node.get("children", []) or []:
        n += count_nodes(c)
    return n


def main():
    if len(sys.argv) != 2:
        print("usage: m3_alpha_parity.py <call_dir>", file=sys.stderr)
        sys.exit(2)
    call_dir = Path(sys.argv[1]).resolve()
    if not call_dir.is_dir() or not (call_dir / "trace.bin").exists():
        print(f"# {call_dir} is not a valid call_dir (missing trace.bin)",
              file=sys.stderr)
        sys.exit(2)

    py_port = free_port()
    rs_port = free_port()
    print(f"# M3-α parity: python={py_port} rust={rs_port} on {call_dir.name}",
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

        py_resp = fetch(py_port, "/api/call-tree?max_depth=10")
        rs_resp = fetch(rs_port, "/api/call-tree?max_depth=10")

        py_tree = py_resp.get("tree", {})
        rs_tree = rs_resp.get("tree", {})

        diffs = []

        # 1. Root shape.
        for k, want in (("fn", "?"), ("depth", 0)):
            if py_tree.get(k) != want:
                diffs.append(f"  python tree.{k}={py_tree.get(k)!r}, want {want!r}")
            if rs_tree.get(k) != want:
                diffs.append(f"  rust tree.{k}={rs_tree.get(k)!r}, want {want!r}")

        # 2. Name set Jaccard.
        py_names = collect_names(py_tree)
        rs_names = collect_names(rs_tree)
        common = py_names & rs_names
        union = py_names | rs_names
        jaccard = (len(common) / len(union)) if union else 1.0
        if jaccard < 0.6:
            diffs.append(
                f"  bl-target name jaccard={jaccard:.2f} <0.6 — "
                f"py={len(py_names)}, rs={len(rs_names)}, common={len(common)}"
            )

        # 3. Node-count tolerance ±10%.
        py_n = count_nodes(py_tree)
        rs_n = count_nodes(rs_tree)
        if py_n > 0:
            ratio = abs(rs_n - py_n) / py_n
            if ratio > 0.10:
                diffs.append(
                    f"  node count diff {ratio:.0%} > 10% — py={py_n} rs={rs_n}"
                )

        if diffs:
            print("MISMATCH:", file=sys.stderr)
            for d in diffs:
                print(d, file=sys.stderr)
            sys.exit(1)

        print(
            f"OK — /api/call-tree (py={py_n} nodes / rs={rs_n} nodes; "
            f"name jaccard={jaccard:.2f})",
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
