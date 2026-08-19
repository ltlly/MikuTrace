"""Static guard for frontend API client fetch discipline.

The API debug logger wraps browser fetch through `fx()`. A previous broad
replace accidentally changed the wrapper's own raw fetch into `fx()`, causing
infinite recursion. This audit pins the intended shape: all API calls go
through `fx`, and `fx` itself is the only place that directly calls `fetch`.
"""

from __future__ import annotations

import re

from _static_audit import REPO, report

CLIENT = REPO / "frontend" / "src" / "api" / "client.ts"


def main() -> int:
    text = CLIENT.read_text()
    failures: list[str] = []

    fetch_lines = [
        (line_no, line.strip())
        for line_no, line in enumerate(text.splitlines(), 1)
        if re.search(r"\bfetch\(", line)
    ]
    if (
        len(fetch_lines) != 1
        or fetch_lines[0][1] != "const r = await fetch(input, init);"
    ):
        failures.append(
            f"expected only fx raw fetch(input, init), found {fetch_lines!r}"
        )

    fx_start = text.find(
        "async function fx(input: string, init?: RequestInit): Promise<Response>"
    )
    fx_end = text.find("async function apiGet<")
    if fx_start < 0 or fx_end < 0 or fx_end <= fx_start:
        failures.append("missing fx wrapper")
    else:
        fx_body = text[fx_start:fx_end]
        if "await fx(" in fx_body or "return fx(" in fx_body:
            failures.append("fx wrapper must not call fx recursively")
        if "await fetch(input, init)" not in fx_body:
            failures.append("fx wrapper must call raw fetch(input, init)")
        for token in (
            "apiDebugEnabled()",
            "console.log",
            "console.warn",
            "console.error",
            "method",
            "status",
            "ms",
        ):
            if token not in fx_body:
                failures.append(f"fx wrapper missing debug field {token!r}")
        if "tracemiku-api-debug" not in text:
            failures.append("API debug localStorage key is not pinned")

    # 所有 fetcher 经 apiGet/apiPost 收敛后，fx 的调用方只剩这两个入口。
    api_calls = re.findall(r"\bawait\s+fx\(", text)
    if len(api_calls) != 2:
        failures.append(
            f"expected exactly 2 fx callers (apiGet/apiPost), got {len(api_calls)}"
        )

    return report(
        "API client", failures, f"OK frontend API client audit fx_calls={len(api_calls)}"
    )


if __name__ == "__main__":
    raise SystemExit(main())
