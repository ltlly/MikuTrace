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
import concurrent.futures
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
    health_polls: int = 0
    health_max_ms: float = 0.0
    health_failures: int = 0


@dataclass(frozen=True)
class Probe:
    label: str
    path: str
    method: str = "GET"
    json_body: Any | None = None


def get_json(
    base_url: str, path: str, timeout: float = DEFAULT_TIMEOUT
) -> tuple[Any, int, int, float]:
    url = base_url.rstrip("/") + path
    t0 = time.perf_counter()
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        body = resp.read()
        elapsed = (time.perf_counter() - t0) * 1000.0
        return json.loads(body.decode("utf-8")), resp.status, len(body), elapsed


def timed_request(
    base_url: str,
    label: str,
    path: str,
    timeout: float = DEFAULT_TIMEOUT,
    *,
    method: str = "GET",
    json_body: Any | None = None,
) -> tuple[Measurement, Any | None]:
    url = base_url.rstrip("/") + path
    data = None
    headers: dict[str, str] = {}
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["content-type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            elapsed = (time.perf_counter() - t0) * 1000.0
            value = json.loads(body.decode("utf-8")) if body else None
            return (
                Measurement(
                    label,
                    path,
                    resp.status,
                    elapsed,
                    len(body),
                    200 <= resp.status < 300,
                ),
                value,
            )
    except urllib.error.HTTPError as err:
        body = err.read()
        elapsed = (time.perf_counter() - t0) * 1000.0
        return (
            Measurement(
                label,
                path,
                err.code,
                elapsed,
                len(body),
                False,
                body[:160].decode("utf-8", "replace"),
            ),
            None,
        )
    except Exception as err:  # network timeout, refused connection, bad JSON, ...
        elapsed = (time.perf_counter() - t0) * 1000.0
        return (
            Measurement(label, path, None, elapsed, 0, False, str(err)),
            None,
        )


def timed_get(
    base_url: str,
    label: str,
    path: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[Measurement, Any | None]:
    return timed_request(base_url, label, path, timeout)


def timed_get_with_runtime_probe(
    base_url: str,
    label: str,
    path: str,
    timeout: float,
    *,
    enabled: bool,
    health_path: str,
    health_interval: float,
    health_timeout: float,
    max_health_ms: float,
    executor: concurrent.futures.Executor,
    method: str = "GET",
    json_body: Any | None = None,
) -> tuple[Measurement, Any | None]:
    if not enabled:
        return timed_request(
            base_url, label, path, timeout, method=method, json_body=json_body
        )

    future = executor.submit(
        timed_request,
        base_url,
        label,
        path,
        timeout,
        method=method,
        json_body=json_body,
    )
    polls = 0
    max_ms = 0.0
    failures: list[str] = []

    while not future.done():
        time.sleep(max(0.01, health_interval))
        if future.done():
            break
        health, _ = timed_get(base_url, "runtime health", health_path, health_timeout)
        polls += 1
        max_ms = max(max_ms, health.ms)
        if not health.ok or health.ms > max_health_ms:
            detail = f"{health.ms:.1f}ms status={health.status}"
            if health.note:
                detail += f" {health.note[:80]}"
            failures.append(detail)

    measurement, value = future.result()
    measurement.health_polls = polls
    measurement.health_max_ms = max_ms
    measurement.health_failures = len(failures)
    if failures:
        measurement.ok = False
        suffix = f"runtime health blocked: {failures[0]}"
        if len(failures) > 1:
            suffix += f" (+{len(failures) - 1} more)"
        measurement.note = (
            f"{measurement.note}; {suffix}" if measurement.note else suffix
        )
    return measurement, value


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


def pick_function_id(functions: Any) -> str | None:
    fns = (functions or {}).get("functions", [])
    for source in ("trace-ir", "symbol"):
        for fn in fns:
            if fn.get("source") == source and isinstance(fn.get("id"), str):
                return fn["id"]
    for fn in fns:
        fn_id = fn.get("id")
        if isinstance(fn_id, str) and fn_id:
            return fn_id
    return None


def pick_largest_cfg_function(functions: Any, exclude: str | None) -> str | None:
    best: tuple[int, int, str] | None = None
    for fn in (functions or {}).get("functions", []):
        name = fn.get("name")
        if not isinstance(name, str) or not name or name == "?" or name == exclude:
            continue
        blocks = int(fn.get("blocks") or 0)
        records = int(fn.get("records") or 0)
        if blocks <= 0:
            continue
        candidate = (blocks, records, name)
        if best is None or candidate[:2] > best[:2]:
            best = candidate
    return best[2] if best else None


def function_entry_pc(functions: Any, name: str | None) -> str | None:
    if not name:
        return None
    for fn in (functions or {}).get("functions", []):
        if fn.get("name") != name:
            continue
        entry_pc = fn.get("entry_pc")
        if isinstance(entry_pc, int) and entry_pc > 0:
            return f"0x{entry_pc:x}"
    return None


def pick_string_provenance_target(strings_resp: Any) -> tuple[str, int] | None:
    for entry in (strings_resp or {}).get("strings", []):
        addr = entry.get("addr")
        length = int(entry.get("len") or 0)
        if isinstance(addr, str) and addr and length > 0:
            return addr, min(length, 128)
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "base_url", help="running traceMiku web URL, e.g. http://127.0.0.1:18900"
    )
    ap.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON only"
    )
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument(
        "--visible-ui-only",
        action="store_true",
        help="skip endpoints for UI panels that are currently hidden, such as Decompile",
    )
    ap.add_argument(
        "--runtime-blocking-check",
        action="store_true",
        help="while each probe is running, poll /api/bg-status to catch async runtime blockage",
    )
    ap.add_argument("--health-path", default="/api/bg-status")
    ap.add_argument("--health-interval", type=float, default=0.05)
    ap.add_argument("--health-timeout", type=float, default=2.0)
    ap.add_argument("--max-health-ms", type=float, default=1000.0)
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
    fn_id = pick_function_id(funcs)
    largest_cfg_fn = pick_largest_cfg_function(funcs, fn)
    largest_cfg_pc = function_entry_pc(funcs, largest_cfg_fn)
    strings_seed = get_json(
        base, q("/api/strings", min_len=4, limit=1, cursor=-1), args.timeout
    )[0]
    string_provenance_target = pick_string_provenance_target(strings_seed)

    probes: list[Probe] = [
        Probe("meta", "/api/meta"),
        Probe("bg status", "/api/bg-status"),
        Probe("records first 1k", q("/api/records", start=0, count=1000)),
        Probe("records mid 1k", q("/api/records", start=max(0, mid - 500), count=1000)),
        Probe("record mid", f"/api/record/{mid}"),
        Probe(
            "search ret cursor",
            q("/api/search", pattern="^ret\\b", max_results=5000, cursor=mid),
        ),
        Probe(
            "query records ret",
            q("/api/query", kind="records", q="ret", idx=mid, limit=500),
        ),
        Probe(
            "query regs x0", q("/api/query", kind="regs", reg="x0", idx=mid, limit=500)
        ),
        Probe(
            "query jni events", q("/api/query", kind="jni", q="", idx=mid, limit=500)
        ),
        Probe(
            "idxs current pc",
            q("/api/idxs-for-pc", pc=rec_mid.get("pc"), cursor=mid, limit=80),
        ),
        Probe("backtrace mid", q("/api/backtrace", idx=mid, limit=256)),
        Probe("calltree depth50", q("/api/call-tree", max_depth=50)),
        Probe(
            "forward taint x0",
            q(
                "/api/forward-taint",
                traceIdx=mid,
                reg="x0",
                max_count=5000,
                cross_fn_call="true",
            ),
        ),
        Probe(
            "backward taint x0",
            q(
                "/api/backward-taint",
                traceIdx=mid,
                reg="x0",
                max_count=5000,
                cross_fn_call="true",
            ),
        ),
        Probe("strings 5k", q("/api/strings", min_len=4, limit=5000, cursor=-1)),
        Probe(
            "hash finalize",
            q("/api/hash-finalize-detect", window=500, min_size=16, limit=500),
        ),
        Probe(
            "auto phase",
            q("/api/auto-phase-detect", max_phases=5000, detect_byte_streams="true"),
        ),
    ]
    if string_provenance_target:
        string_addr, string_len = string_provenance_target
        probes.append(
            Probe(
                "string provenance first",
                q("/api/string-provenance", addr=string_addr, length=string_len),
            )
        )
    if fn:
        probes.extend(
            [
                Probe("cfg svg current fn", q("/api/cfg-svg", fn=fn, mode="auto")),
                Probe("cfg current fn", q("/api/cfg", fn=fn)),
            ]
        )
    if largest_cfg_fn:
        probes.append(
            Probe(
                "cfg svg largest fn", q("/api/cfg-svg", fn=largest_cfg_fn, mode="auto")
            )
        )
        if largest_cfg_pc:
            probes.append(
                Probe(
                    "cfg svg largest local",
                    q(
                        "/api/cfg-svg",
                        fn=largest_cfg_fn,
                        pc=largest_cfg_pc,
                        local_depth=2,
                        mode="auto",
                    ),
                )
            )
    if not args.visible_ui_only:
        probes.extend(
            [
                Probe(
                    "reg timeline x0",
                    q("/api/reg-timeline", reg="x0", start=0, end=-1, max_points=5000),
                ),
                Probe(
                    "dec summary",
                    q("/api/dec/summary", split_top_k=40, split_min_records=10),
                ),
            ]
        )
        if fn_id:
            probes.append(
                Probe(
                    "dec fn hot",
                    q(
                        f"/api/dec/fn/{urllib.parse.quote(fn_id, safe='')}",
                        tier="hot",
                        split_top_k=40,
                        split_min_records=10,
                    ),
                )
            )
            probes.append(
                Probe(
                    "llil render",
                    "/api/llil/render",
                    method="POST",
                    json_body={
                        "fn_id": fn_id,
                        "max_records": 300,
                        "ssa": True,
                        "constfold": True,
                        "flag_elim": True,
                        "dce": False,
                    },
                )
            )
    if sp:
        probes.extend(
            [
                Probe("mem dump sp 128", q("/api/mem-dump", addr=sp, count=128)),
                Probe(
                    "mem diff sp 128", q("/api/mem-diff", idx=mid, addr=sp, size=128)
                ),
                Probe(
                    "touch range sp",
                    q(
                        "/api/idxs-touching-range",
                        addr=sp,
                        size=128,
                        cursor=mid,
                        limit=80,
                    ),
                ),
                Probe(
                    "mem writes sp",
                    q(
                        "/api/mem-writes-in-range",
                        addr_lo=sp,
                        addr_hi=sp,
                        idx_lo=0,
                        idx_hi=records,
                        max=200,
                    ),
                ),
                Probe(
                    "query mem sp",
                    q("/api/query", kind="mem", addr=sp, len=128, idx=mid, limit=500),
                ),
                Probe(
                    "query writes sp",
                    q("/api/query", kind="writes", q=sp, len=128, idx=mid, limit=500),
                ),
            ]
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        for probe in probes:
            m, _ = timed_get_with_runtime_probe(
                base,
                probe.label,
                probe.path,
                args.timeout,
                enabled=args.runtime_blocking_check,
                health_path=args.health_path,
                health_interval=args.health_interval,
                health_timeout=args.health_timeout,
                max_health_ms=args.max_health_ms,
                executor=executor,
                method=probe.method,
                json_body=probe.json_body,
            )
            measurements.append(m)

    out = {
        "base_url": base,
        "records": records,
        "mid_idx": mid,
        "mid_pc": rec_mid.get("pc"),
        "mid_func": fn_hint,
        "function_id": fn_id,
        "largest_cfg_fn": largest_cfg_fn,
        "largest_cfg_pc": largest_cfg_pc,
        "string_provenance_target": string_provenance_target,
        "runtime_blocking_check": {
            "enabled": args.runtime_blocking_check,
            "health_path": args.health_path,
            "health_interval_ms": args.health_interval * 1000.0,
            "health_timeout_ms": args.health_timeout * 1000.0,
            "max_health_ms": args.max_health_ms,
        },
        "measurements": [asdict(m) for m in measurements],
    }
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(
            f"# {base} records={records:,} mid={mid:,} pc={rec_mid.get('pc')} fn={fn_hint}"
        )
        for m in measurements:
            status = m.status if m.status is not None else "ERR"
            ok = "OK" if m.ok else "FAIL"
            note = f" {m.note}" if m.note else ""
            health = (
                f" health_max={m.health_max_ms:.1f}ms/{m.health_polls}"
                if m.health_polls
                else ""
            )
            print(
                f"{ok:4s} {m.ms:8.1f} ms {m.bytes:9d} B {status!s:>4s} {m.label}{health}{note}"
            )
    return 0 if all(m.ok for m in measurements) else 1


if __name__ == "__main__":
    sys.exit(main())
