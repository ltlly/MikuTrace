"""M2-β parity differ — Python /api/records vs Rust /api/records.

Boots Python webui (./tracemiku web) + Rust tracemiku-server side-by-side,
hits GET /api/records?start=0&count=20 on each, compares the M2-β-committed
JSON subset (idx, pc, rel, module, asm, is_branch, is_call, is_ret).

Symbol-dependent fields (func, off, annotation, exec_count) are explicitly
NOT compared — they're null on Rust for M2-β; M2-γ populates them.

Usage:
    uv run python scripts/m2_beta_parity.py <call_dir>
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

# Fields we DO compare for M2-β.
M2_BETA_FIELDS = {
    "idx", "pc", "rel", "module", "asm",
    "is_branch", "is_call", "is_ret",
}


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


def wait_listening(port: int, timeout: float = 30.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"port {port} never opened")


def fetch_records(port: int, start: int, count: int) -> dict:
    url = f"http://127.0.0.1:{port}/api/records?start={start}&count={count}"
    with urllib.request.urlopen(url, timeout=15) as r:
        return json.loads(r.read())


def normalize_row(row: dict) -> dict:
    out = {k: row.get(k) for k in M2_BETA_FIELDS}
    # Python capstone emits "mnemonic + ' ' + op_str"; when op_str is empty
    # this produces a trailing space (e.g. "nop " vs Rust's "nop").
    # Normalize both sides by stripping trailing whitespace — the semantic
    # content is identical.
    if isinstance(out.get("asm"), str):
        out["asm"] = out["asm"].rstrip()
    return out


def diff(py: dict, rs: dict) -> list[str]:
    out: list[str] = []
    for top_key in ("start", "end", "count"):
        if py.get(top_key) != rs.get(top_key):
            out.append(f"  top-level {top_key}: python={py.get(top_key)} rust={rs.get(top_key)}")
    py_rows = py.get("records", [])
    rs_rows = rs.get("records", [])
    if len(py_rows) != len(rs_rows):
        out.append(f"  records length: python={len(py_rows)} rust={len(rs_rows)}")
        return out
    for i, (p, r) in enumerate(zip(py_rows, rs_rows)):
        np_ = normalize_row(p)
        nr_ = normalize_row(r)
        if np_ != nr_:
            out.append(f"  row[{i}] differs:")
            for k in M2_BETA_FIELDS:
                if np_.get(k) != nr_.get(k):
                    out.append(f"    {k}: python={np_.get(k)!r} rust={nr_.get(k)!r}")
    return out


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr); sys.exit(2)
    call_dir = Path(sys.argv[1]).resolve()
    if not call_dir.exists():
        print(f"call_dir not found: {call_dir}", file=sys.stderr); sys.exit(2)

    py_port = free_port()
    rs_port = free_port()
    print(f"# M2-β parity: python={py_port} rust={rs_port} on {call_dir.name}",
          file=sys.stderr)

    # Boot Python webui via the project's tracemiku CLI.
    py_proc = subprocess.Popen(
        ["./tracemiku", "web", str(call_dir),
         "--port", str(py_port), "--no-browser"],
        cwd=REPO_ROOT,
        preexec_fn=os.setsid,
        stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    )
    rs_proc = subprocess.Popen(
        ["./rust/target/release/tracemiku-server", str(call_dir),
         "--port", str(rs_port)],
        cwd=REPO_ROOT,
        preexec_fn=os.setsid,
        stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    )

    try:
        wait_listening(py_port)
        wait_listening(rs_port)
        py = fetch_records(py_port, 0, 20)
        rs = fetch_records(rs_port, 0, 20)
        diffs = diff(py, rs)
        if diffs:
            print("MISMATCH:", file=sys.stderr)
            for d in diffs:
                print(d, file=sys.stderr)
            sys.exit(1)
        print(f"OK — {min(len(py.get('records', [])), 20)} records match on "
              f"{', '.join(sorted(M2_BETA_FIELDS))}", file=sys.stderr)
    finally:
        for proc in (py_proc, rs_proc):
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=3)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass


if __name__ == "__main__":
    main()
