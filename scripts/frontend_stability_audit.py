"""Static guard for Solid resource source stability.

Several UI stalls came from source objects changing identity without changing
meaning. Solid resources compare sources by reference, so source memos that
feed guarded resources must reuse the previous object when their fields are
unchanged. This script keeps that rule explicit and pins the RecordsPanel
range-jitter fix that prevents virtual-row refetch oscillation.
"""

from __future__ import annotations

import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "frontend" / "src"

EXPECTED_GUARDED_SOURCES = {
    ("panels/backtrace/BacktracePanel.tsx", "source"),
    ("panels/calltree/CallTreePanel.tsx", "source"),
    ("panels/decompiler/DecompilerPanel.tsx", "fnSource"),
    ("panels/decompiler/DecompilerPanel.tsx", "summarySource"),
    ("panels/hlil/HlilPanel.tsx", "source"),
    ("panels/memory/MemoryPanel.tsx", "diffSource"),
    ("panels/memory/MemoryPanel.tsx", "dumpSource"),
    ("panels/records/RecordsPanel.tsx", "range"),
    ("panels/forks/ForksPanel.tsx", "source"),
    ("panels/strings/StringProvenancePanel.tsx", "source"),
    ("panels/strings/StringsPanel.tsx", "source"),
    ("panels/tracepc/TraceForPcPanel.tsx", "source"),
    ("panels/xref/XrefPanel.tsx", "asmSource"),
    ("panels/xref/XrefPanel.tsx", "pcSource"),
}

STABILITY_TOKENS = {
    ("panels/backtrace/BacktracePanel.tsx", "source"): [
        "createMemo((prev?: { idx: number; limit: number })",
        "prev.idx === next.idx",
        "prev.limit === next.limit",
        "? prev : next",
    ],
    ("panels/calltree/CallTreePanel.tsx", "source"): [
        "createMemo((prev?: { depth: number })",
        "prev.depth === next.depth",
        "? prev : next",
    ],
    ("panels/decompiler/DecompilerPanel.tsx", "summarySource"): [
        "createMemo<SummarySource | undefined>((prev)",
        "sameDecIrSource(prev, next) ? prev : next",
    ],
    ("panels/decompiler/DecompilerPanel.tsx", "fnSource"): [
        "createMemo<FnSource | undefined>((prev)",
        "prev.fnId === next.fnId",
        "prev.tier === next.tier",
        "sameDecIrSource(prev, next)",
        "? prev",
        ": next",
    ],
    ("panels/hlil/HlilPanel.tsx", "source"): [
        "createMemo<HlilSource | undefined>((prev)",
        "prev.pc === next.pc",
        "prev.idx === next.idx",
        "? prev : next",
    ],
    ("panels/memory/MemoryPanel.tsx", "dumpSource"): [
        "createMemo<DumpSource | undefined>((prev)",
        "prev.addr === next.addr",
        "prev.count === next.count",
        "prev.retry === next.retry",
        "? prev",
        ": next",
    ],
    ("panels/memory/MemoryPanel.tsx", "diffSource"): [
        "createMemo<DiffSource | undefined>((prev)",
        "prev.idx === next.idx",
        "prev.addr === next.addr",
        "prev.size === next.size",
        "prev.retry === next.retry",
        "? prev",
        ": next",
    ],
    ("panels/records/RecordsPanel.tsx", "range"): [
        "createMemo<{ start: number; count: number; end: number }>",
        "Math.round((viewHeight() || 480) / ROW_HEIGHT)",
        "prev.start === next.start",
        "prev.count === next.count",
        "prev.end === next.end",
        "return prev;",
    ],
    ("panels/forks/ForksPanel.tsx", "source"): [
        "createMemo((prev?: { status: string; limit: number })",
        "prev.status === next.status",
        "prev.limit === next.limit",
        "? prev : next",
    ],
    ("panels/strings/StringProvenancePanel.tsx", "source"): [
        "createMemo<Source | undefined>((prev)",
        "prev.token === next.token",
        "prev.addr === next.addr",
        "prev.len === next.len",
        "prev.retry === next.retry",
        "? prev",
        ": next",
    ],
    ("panels/strings/StringsPanel.tsx", "source"): [
        "createMemo<StringsSource | undefined>((prev)",
        "prev.minLen === next.minLen",
        "prev.q === next.q",
        "prev.limit === next.limit",
        "prev.cursor === next.cursor",
        "prev.retry === next.retry",
        "? prev",
        ": next",
    ],
    ("panels/tracepc/TraceForPcPanel.tsx", "source"): [
        "createMemo<IpcSource | undefined>((prev)",
        "prev.pc === next.pc",
        "prev.idx === next.idx",
        "prev.limit === next.limit",
        "? prev : next",
    ],
    ("panels/xref/XrefPanel.tsx", "pcSource"): [
        "createMemo<PcRefSource | undefined>((prev)",
        "prev.pc === next.pc",
        "prev.idx === next.idx",
        "prev.limit === next.limit",
        "? prev : next",
    ],
    ("panels/xref/XrefPanel.tsx", "asmSource"): [
        "createMemo<AsmSearchSource | undefined>((prev)",
        "prev.pattern === next.pattern",
        "prev.cursor === next.cursor",
        "prev.limit === next.limit",
        "? prev",
        ": next",
    ],
}


def read(rel: str) -> str:
    return (SRC / rel).read_text()


def skip_generic(text: str, pos: int) -> int:
    if pos >= len(text) or text[pos] != "<":
        return pos
    depth = 0
    while pos < len(text):
        ch = text[pos]
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
            if depth == 0:
                return pos + 1
        pos += 1
    return pos


def guarded_sources(rel: str, text: str) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    needle = "createGuardedResource"
    pos = 0
    while True:
        start = text.find(needle, pos)
        if start < 0:
            return found
        pos = start + len(needle)
        while pos < len(text) and text[pos].isspace():
            pos += 1
        pos = skip_generic(text, pos)
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text) or text[pos] != "(":
            continue
        pos += 1
        while pos < len(text) and text[pos].isspace():
            pos += 1
        name_start = pos
        while pos < len(text) and (text[pos].isalnum() or text[pos] == "_"):
            pos += 1
        if pos > name_start:
            found.add((rel, text[name_start:pos]))


def main() -> int:
    failures: list[str] = []

    found: set[tuple[str, str]] = set()
    for path in sorted((SRC / "panels").rglob("*.tsx")):
        rel = path.relative_to(SRC).as_posix()
        found |= guarded_sources(rel, path.read_text())

    missing = sorted(found - EXPECTED_GUARDED_SOURCES)
    stale = sorted(EXPECTED_GUARDED_SOURCES - found)
    if missing:
        failures.append(f"unclassified guarded resource sources: {missing}")
    if stale:
        failures.append(f"stale guarded resource source allowlist entries: {stale}")

    for key, tokens in sorted(STABILITY_TOKENS.items()):
        rel, source = key
        text = read(rel)
        absent = [token for token in tokens if token not in text]
        if absent:
            failures.append(f"{rel}:{source} missing stability tokens {absent!r}")

    if failures:
        print("Frontend stability static audit failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"OK frontend stability audit guarded_sources={len(found)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
