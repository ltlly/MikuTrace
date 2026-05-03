"""M2-γ parity differ — adds /api/records.func/off + /api/idxs-for-pc to M2-β.

Boots both webui (Python) and tracemiku-server (Rust) on free ports, hits:
  - /api/records?start=0&count=20
  - /api/idxs-for-pc?pc=<from records[0].pc>&cursor=10&limit=30

Compares the M2-γ-committed subset of /api/records (M2-β fields + func + off)
plus the full /api/idxs-for-pc shape. Symbol fields (func, off) MUST match
when both sides have the same known_offsets in per-call meta.json.

Usage:
    uv run python scripts/m2_gamma_parity.py <call_dir>
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

RECORDS_FIELDS = {
    "idx", "pc", "rel", "module", "asm",
    "is_branch", "is_call", "is_ret",
    "func", "off",
}
IDXS_FIELDS = {
    "status", "pc", "cursor",
    "before", "after",
    "total_before", "total_after",
    "before_capped", "after_capped",
}


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


def normalize_record(row: dict) -> dict:
    out = {k: row.get(k) for k in RECORDS_FIELDS}
    if isinstance(out.get("asm"), str):
        out["asm"] = out["asm"].rstrip()
    return out


def normalize_idxs(d: dict) -> dict:
    return {k: d.get(k) for k in IDXS_FIELDS}


def diff_records(py: dict, rs: dict) -> list[str]:
    out = []
    for tk in ("start", "end", "count"):
        if py.get(tk) != rs.get(tk):
            out.append(f"  records top-level {tk}: py={py.get(tk)} rs={rs.get(tk)}")
    py_rows = py.get("records", [])
    rs_rows = rs.get("records", [])
    if len(py_rows) != len(rs_rows):
        out.append(f"  records length: py={len(py_rows)} rs={len(rs_rows)}")
        return out
    for i, (p, r) in enumerate(zip(py_rows, rs_rows)):
        np_, nr_ = normalize_record(p), normalize_record(r)
        if np_ != nr_:
            out.append(f"  records[{i}]:")
            for k in RECORDS_FIELDS:
                if np_.get(k) != nr_.get(k):
                    out.append(f"    {k}: py={np_.get(k)!r} rs={nr_.get(k)!r}")
    return out


def diff_idxs(py: dict, rs: dict) -> list[str]:
    out = []
    np_, nr_ = normalize_idxs(py), normalize_idxs(rs)
    for k in IDXS_FIELDS:
        if np_.get(k) != nr_.get(k):
            out.append(f"  idxs.{k}: py={np_.get(k)!r} rs={nr_.get(k)!r}")
    return out


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr); sys.exit(2)
    call_dir = Path(sys.argv[1]).resolve()
    if not call_dir.exists():
        print(f"call_dir not found: {call_dir}", file=sys.stderr); sys.exit(2)

    py_port = free_port()
    rs_port = free_port()
    print(f"# M2-γ parity: python={py_port} rust={rs_port} on {call_dir.name}",
          file=sys.stderr)

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

        py_records = fetch(py_port, "/api/records?start=0&count=20")
        rs_records = fetch(rs_port, "/api/records?start=0&count=20")
        records_diffs = diff_records(py_records, rs_records)

        target_pc = py_records["records"][0]["pc"] if py_records["records"] else "0x0"
        py_idxs = fetch(py_port, f"/api/idxs-for-pc?pc={target_pc}&cursor=10&limit=30")
        rs_idxs = fetch(rs_port, f"/api/idxs-for-pc?pc={target_pc}&cursor=10&limit=30")
        idxs_diffs = diff_idxs(py_idxs, rs_idxs)

        all_diffs = []
        if records_diffs:
            all_diffs.append("/api/records mismatches:")
            all_diffs.extend(records_diffs)
        if idxs_diffs:
            all_diffs.append("/api/idxs-for-pc mismatches:")
            all_diffs.extend(idxs_diffs)

        if all_diffs:
            print("MISMATCH:", file=sys.stderr)
            for d in all_diffs:
                print(d, file=sys.stderr)
            sys.exit(1)
        n_rec = min(len(py_records.get("records", [])), 20)
        print(f"OK — {n_rec} records match on {','.join(sorted(RECORDS_FIELDS))}",
              file=sys.stderr)
        print(f"OK — /api/idxs-for-pc?pc={target_pc} matches on full shape",
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
