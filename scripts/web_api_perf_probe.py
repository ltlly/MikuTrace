"""Probe traceMiku Rust web API latency on a running server.

Usage:
    uv run python scripts/web_api_perf_probe.py http://127.0.0.1:18900
    uv run python scripts/web_api_perf_probe.py http://127.0.0.1:18900 --visible-ui-only
    uv run python scripts/web_api_perf_probe.py http://127.0.0.1:18900 --json

The probe is intentionally target-agnostic: it derives a middle trace idx,
current SP, and current function from the server responses instead of
hardcoding SO names or offsets. It is meant for large-trace regression checks
after frontend/backend interaction changes.

By default it includes backend surfaces that may be temporarily hidden in the
UI, so regressions do not disappear silently. Use --visible-ui-only when the
goal is to measure the currently exposed frontend interaction path.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from typing import Any


DEFAULT_TIMEOUT = 60.0


@dataclass
class Measurement:
    label: str
    path: str
    status: int | None
    ms: float
    bytes: int
    ok: bool
    note: str = ""


def get_json(base_url: str, path: str, timeout: float = DEFAULT_TIMEOUT) -> tuple[Any, int, int, float]:
    url = base_url.rstrip("/") + path
    t0 = time.perf_counter()
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        body = resp.read()
        elapsed = (time.perf_counter() - t0) * 1000.0
        return json.loads(body.decode("utf-8")), resp.status, len(body), elapsed


def timed_get(
    base_url: str,
    label: str,
    path: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[Measurement, Any | None]:
    url = base_url.rstrip("/") + path
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            body = resp.read()
            elapsed = (time.perf_counter() - t0) * 1000.0
            value = json.loads(body.decode("utf-8")) if body else None
            return (
                Measurement(label, path, resp.status, elapsed, len(body), 200 <= resp.status < 300),
                value,
            )
    except urllib.error.HTTPError as err:
        body = err.read()
        elapsed = (time.perf_counter() - t0) * 1000.0
        return (
            Measurement(label, path, err.code, elapsed, len(body), False, body[:160].decode("utf-8", "replace")),
            None,
        )
    except Exception as err:  # network timeout, refused connection, bad JSON, ...
        elapsed = (time.perf_counter() - t0) * 1000.0
        return (
            Measurement(label, path, None, elapsed, 0, False, str(err)),
            None,
        )


def q(path: str, **params: Any) -> str:
    clean = {k: str(v) for k, v in params.items() if v is not None}
    if not clean:
        return path
    return f"{path}?{urllib.parse.urlencode(clean)}"


def pick_function(functions: Any, fallback: str | None) -> str | None:
    if fallback:
        return fallback
    for fn in (functions or {}).get("functions", []):
        name = fn.get("name")
        fn_id = fn.get("id")
        if isinstance(name, str) and name and name != "?":
            return name
        if isinstance(fn_id, str) and fn_id:
            return fn_id
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base_url", help="running traceMiku web URL, e.g. http://127.0.0.1:18900")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON only")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument(
        "--visible-ui-only",
        action="store_true",
        help="skip endpoints for UI panels that are currently hidden, such as Decompile",
    )
    args = ap.parse_args()

    base = args.base_url.rstrip("/")
    measurements: list[Measurement] = []

    meta, _status, _size, _ms = get_json(base, "/api/meta", args.timeout)
    records = int(meta.get("records") or 0)
    mid = max(0, records // 2)

    rec_mid, _status, _size, _ms = get_json(base, f"/api/record/{mid}", args.timeout)
    sp = (rec_mid.get("regs") or {}).get("sp")
    fn_hint = rec_mid.get("func")

    funcs_measure, funcs = timed_get(base, "functions", "/api/functions", args.timeout)
    measurements.append(funcs_measure)
    fn = pick_function(funcs, fn_hint)

    probes: list[tuple[str, str]] = [
        ("meta", "/api/meta"),
        ("bg status", "/api/bg-status"),
        ("records first 1k", q("/api/records", start=0, count=1000)),
        ("records mid 1k", q("/api/records", start=max(0, mid - 500), count=1000)),
        ("record mid", f"/api/record/{mid}"),
        ("search ret cursor", q("/api/search", pattern="^ret\\b", max_results=5000, cursor=mid)),
        ("idxs current pc", q("/api/idxs-for-pc", pc=rec_mid.get("pc"), cursor=mid, limit=80)),
        ("backtrace mid", q("/api/backtrace", idx=mid, limit=256)),
        ("calltree depth50", q("/api/call-tree", max_depth=50)),
        ("forward taint x0", q("/api/forward-taint", traceIdx=mid, reg="x0", max_count=5000, cross_fn_call="true")),
        ("backward taint x0", q("/api/backward-taint", traceIdx=mid, reg="x0", max_count=5000, cross_fn_call="true")),
        ("strings 5k", q("/api/strings", min_len=4, limit=5000, cursor=-1)),
        ("hash finalize", q("/api/hash-finalize-detect", window=500, min_size=16, limit=500)),
        ("auto phase", q("/api/auto-phase-detect", max_phases=5000, detect_byte_streams="true")),
    ]
    if fn:
        probes.extend(
            [
                ("cfg svg current fn", q("/api/cfg-svg", fn=fn, mode="auto")),
                ("cfg current fn", q("/api/cfg", fn=fn)),
            ]
        )
        if not args.visible_ui_only:
            probes.append(("dec summary", q("/api/dec/summary", split_top_k=40, split_min_records=10)))
    if sp:
        probes.extend(
            [
                ("mem dump sp 128", q("/api/mem-dump", addr=sp, count=128)),
                ("mem diff sp 128", q("/api/mem-diff", idx=mid, addr=sp, size=128)),
                ("touch range sp", q("/api/idxs-touching-range", addr=sp, size=128, cursor=mid, limit=80)),
                ("mem writes sp", q("/api/mem-writes-in-range", addr_lo=sp, addr_hi=sp, idx_lo=0, idx_hi=records, max=200)),
            ]
        )

    for label, path in probes:
        m, _ = timed_get(base, label, path, args.timeout)
        measurements.append(m)

    out = {
        "base_url": base,
        "records": records,
        "mid_idx": mid,
        "mid_pc": rec_mid.get("pc"),
        "mid_func": fn_hint,
        "measurements": [asdict(m) for m in measurements],
    }
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"# {base} records={records:,} mid={mid:,} pc={rec_mid.get('pc')} fn={fn_hint}")
        for m in measurements:
            status = m.status if m.status is not None else "ERR"
            ok = "OK" if m.ok else "FAIL"
            note = f" {m.note}" if m.note else ""
            print(f"{ok:4s} {m.ms:8.1f} ms {m.bytes:9d} B {status!s:>4s} {m.label}{note}")
    return 0 if all(m.ok for m in measurements) else 1


if __name__ == "__main__":
    sys.exit(main())
