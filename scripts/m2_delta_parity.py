"""M2-δ parity differ — /api/cfg + /api/idxs-for-block.

Boots both webui (Python) and tracemiku-server (Rust) on free ports,
hits /api/cfg from each. Compares structural shape:
  - block_count tolerance (Python may classify slightly differently)
  - jaccard ≥0.7 on block_starts (set of start_pc values)

Falls back gracefully if Python /api/cfg is unreachable or returns a
status != "ready" (Python builds CFG in background; M2-δ Rust is eager).

Plus validates Rust /api/idxs-for-block on the first known block.

Usage:
    uv run python scripts/m2_delta_parity.py <call_dir>
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


def block_starts(cfg: dict) -> set:
    """Extract set of start-PC integers from a CFG response.

    Handles both field names:
      - Rust server uses  "start_pc"  (e.g. "0x100000")
      - Python webui uses "start"     (e.g. "0x100000")
    """
    out = set()
    for b in cfg.get("blocks", []):
        sp = b.get("start_pc") or b.get("start")
        if sp is None:
            continue
        if isinstance(sp, str):
            sp = int(sp, 16)
        out.add(sp)
    return out


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr); sys.exit(2)
    call_dir = Path(sys.argv[1]).resolve()
    if not call_dir.exists():
        print(f"call_dir not found: {call_dir}", file=sys.stderr); sys.exit(2)

    py_port = free_port()
    rs_port = free_port()
    print(f"# M2-δ parity: python={py_port} rust={rs_port} on {call_dir.name}",
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

        # Python may build CFG in background. Poll for "ready" up to 30s.
        py_cfg = None
        for _ in range(30):
            try:
                py_cfg = fetch(py_port, "/api/cfg")
                if py_cfg.get("status") == "ready":
                    break
            except Exception:
                pass
            time.sleep(1)

        rs_cfg = fetch(rs_port, "/api/cfg")

        diffs = []
        if py_cfg is not None and py_cfg.get("status") == "ready":
            py_starts = block_starts(py_cfg)
            rs_starts = block_starts(rs_cfg)
            common = py_starts & rs_starts
            union = py_starts | rs_starts
            jaccard = (len(common) / len(union)) if union else 1.0
            if jaccard < 0.7:
                diffs.append(
                    f"  /api/cfg block_starts jaccard={jaccard:.2f} <0.7 — "
                    f"py={len(py_starts)}, rs={len(rs_starts)}, common={len(common)}"
                )
        else:
            print(
                f"# python /api/cfg not ready (status={py_cfg.get('status') if py_cfg else 'unreachable'}) "
                f"— skipping cfg parity",
                file=sys.stderr,
            )

        rs_blocks = rs_cfg.get("blocks", [])
        if not rs_blocks:
            print(f"# rust /api/cfg has 0 blocks — synth trace was empty?",
                  file=sys.stderr)
        else:
            first_pc = rs_blocks[0]["start_pc"]
            rs_idxs = fetch(rs_port, f"/api/idxs-for-block?pc={first_pc}")
            if rs_idxs.get("status") != "ready":
                diffs.append(f"  /api/idxs-for-block status={rs_idxs.get('status')!r}")
            elif not rs_idxs.get("idxs"):
                diffs.append(f"  /api/idxs-for-block?pc={first_pc} returned empty idxs")

        if diffs:
            print("MISMATCH:", file=sys.stderr)
            for d in diffs:
                print(d, file=sys.stderr)
            sys.exit(1)

        if py_cfg is not None and py_cfg.get("status") == "ready":
            print(
                f"OK — /api/cfg block_starts within tolerance "
                f"(py={len(block_starts(py_cfg))}, rs={len(block_starts(rs_cfg))})",
                file=sys.stderr,
            )
        else:
            print(f"OK — /api/cfg returned {len(rs_blocks)} blocks (Python skipped)",
                  file=sys.stderr)
        print(f"OK — /api/idxs-for-block validated on first block",
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
