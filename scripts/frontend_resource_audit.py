"""Static guard for Solid async resources.

Most selection-dependent API calls should use `createGuardedResource` so stale
responses cannot apply to a newer selected trace idx/function. A few resources
are intentionally raw `createResource`: static app metadata, function lists, or
one-record fetches that are wrapped by a current-selection memo before use.

This script keeps that exception list explicit. Add new raw resources only after
deciding they are static/active-only or locally guarded.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "frontend" / "src"

ALLOWED_RAW_RESOURCES = {
    ("App.tsx", "cursorRecord"),
    ("App.tsx", "functions"),
    ("App.tsx", "meta"),
    ("panels/cfg/CfgPanel.tsx", "functions"),
    ("panels/crypto/CryptoPanel.tsx", "resp"),
    ("panels/functions/FunctionsPanel.tsx", "resp"),
    ("panels/memory/MemoryPanel.tsx", "record"),
    ("panels/records/RecordsPanel.tsx", "meta"),
    ("panels/registers/RegistersPanel.tsx", "record"),
    ("panels/settings/SettingsPanel.tsx", "bg"),
    ("panels/settings/SettingsPanel.tsx", "decomp"),
    ("panels/settings/SettingsPanel.tsx", "meta"),
    ("panels/settings/SettingsPanel.tsx", "openapi"),
    ("panels/sofilter/SoFilterPanel.tsx", "stats"),
    ("panels/tracepc/TraceForPcPanel.tsx", "record"),
    ("panels/xref/XrefPanel.tsx", "record"),
}

REQUIRED_RAW_RESOURCE_MARKERS = {
    ("App.tsx", "cursorRecord"): [
        "rowHintCache.has(idx) ? undefined : idx",
        "const r = cursorRecord()",
        "if (r && r.idx === idx)",
        "setCursorHint(hint)",
    ],
    ("panels/memory/MemoryPanel.tsx", "record"): [
        "const currentRecord = createMemo(() =>",
        "return r && r.idx === props.idx ? r : undefined",
    ],
    ("panels/registers/RegistersPanel.tsx", "record"): [
        "const currentRecord = createMemo(() =>",
        "return r && r.idx === props.idx ? r : undefined",
    ],
    ("panels/tracepc/TraceForPcPanel.tsx", "record"): [
        "const currentRecord = createMemo(() =>",
        "return r && r.idx === props.idx ? r : undefined",
        "const [idxs, currentHistory] = createGuardedResource",
    ],
    ("panels/xref/XrefPanel.tsx", "record"): [
        "const currentRecord = createMemo(() =>",
        "return r && r.idx === props.idx ? r : undefined",
        "const [pcRefs, currentPcRefs] = createGuardedResource",
    ],
}

RESOURCE_RE = re.compile(
    r"const\s+\[\s*([A-Za-z_][A-Za-z0-9_]*)[^\]]*\]\s*=\s*createResource\b",
    re.MULTILINE,
)


def main() -> int:
    found: set[tuple[str, str]] = set()
    for path in sorted(SRC.rglob("*.tsx")):
        rel = path.relative_to(SRC).as_posix()
        text = path.read_text()
        for match in RESOURCE_RE.finditer(text):
            found.add((rel, match.group(1)))

    missing = sorted(found - ALLOWED_RAW_RESOURCES)
    stale = sorted(ALLOWED_RAW_RESOURCES - found)
    marker_failures: list[str] = []
    for key, markers in REQUIRED_RAW_RESOURCE_MARKERS.items():
        rel, name = key
        if key not in found:
            continue
        text = (SRC / rel).read_text()
        absent = [marker for marker in markers if marker not in text]
        if absent:
            marker_failures.append(f"{rel}: {name} missing markers {absent!r}")

    if missing or stale or marker_failures:
        if missing:
            print(
                "Raw createResource instances need explicit classification:",
                file=sys.stderr,
            )
            for rel, name in missing:
                print(f"  + {rel}: {name}", file=sys.stderr)
        if stale:
            print("Stale frontend resource allowlist entries:", file=sys.stderr)
            for rel, name in stale:
                print(f"  - {rel}: {name}", file=sys.stderr)
        if marker_failures:
            print("Allowed raw createResource guards regressed:", file=sys.stderr)
            for failure in marker_failures:
                print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"OK frontend resource audit raw_createResource={len(found)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
