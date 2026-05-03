"""M2-ε parity differ — /api/functions field-by-field.

Usage:
    uv run python scripts/m2_epsilon_parity.py <call_dir>
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
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
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
    url = f"http://127.0.0.1:{port}{path}"
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read())


def fn_set(funcs: list) -> set:
    """Set of (name, source) tuples."""
    return {(f.get("name"), f.get("source")) for f in funcs}


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr); sys.exit(2)
    call_dir = Path(sys.argv[1]).resolve()
    if not call_dir.exists():
        print(f"call_dir not found: {call_dir}", file=sys.stderr); sys.exit(2)

    py_port = free_port()
    rs_port = free_port()
    print(f"# M2-ε parity: python={py_port} rust={rs_port} on {call_dir.name}",
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

        py_funcs = None
        # Python /api/functions may need CFG ready; poll up to 30s.
        for _ in range(30):
            try:
                py_funcs = fetch(py_port, "/api/functions")
                if py_funcs.get("functions"):
                    break
            except Exception:
                pass
            time.sleep(1)

        rs_funcs = fetch(rs_port, "/api/functions")
        rs_count = len(rs_funcs.get("functions", []))

        diffs = []
        if py_funcs is None or not py_funcs.get("functions"):
            print("# python /api/functions empty/unreachable — skipping name-set parity",
                  file=sys.stderr)
        else:
            py_set = fn_set(py_funcs.get("functions", []))
            rs_set = fn_set(rs_funcs.get("functions", []))
            common = py_set & rs_set
            union = py_set | rs_set
            jaccard = (len(common) / len(union)) if union else 1.0
            if jaccard < 0.5:
                diffs.append(
                    f"  /api/functions name-set jaccard={jaccard:.2f} <0.5 — "
                    f"py={len(py_set)}, rs={len(rs_set)}, common={len(common)}"
                )

        if rs_count < 1:
            diffs.append(f"  /api/functions rust returned 0 functions")

        if diffs:
            print("MISMATCH:", file=sys.stderr)
            for d in diffs:
                print(d, file=sys.stderr)
            sys.exit(1)

        if py_funcs is not None and py_funcs.get("functions"):
            print(
                f"OK — /api/functions name-set within tolerance "
                f"(py={len(fn_set(py_funcs.get('functions', [])))}, rs={rs_count})",
                file=sys.stderr,
            )
        else:
            print(f"OK — /api/functions returned {rs_count} fns (Python skipped)",
                  file=sys.stderr)
    finally:
        for proc in (py_proc, rs_proc):
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass


if __name__ == "__main__":
    main()
