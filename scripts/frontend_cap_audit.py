"""Static guard for capped/truncated frontend result surfaces.

The Rust web server intentionally caps large responses. A capped response is
safe only if the visible UI tells the user that the result is partial, or the
surface is intentionally hidden/cold and still carries an inline marker. This
script pins the known capped surfaces so future UI edits do not silently remove
those warnings.
"""

from __future__ import annotations

import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "frontend" / "src"


def read(rel: str) -> str:
    return (SRC / rel).read_text()


def require(name: str, ok: bool, failures: list[str]) -> None:
    if not ok:
        failures.append(name)


def has_all(rel: str, *tokens: str) -> bool:
    text = read(rel)
    return all(token in text for token in tokens)


def has_all_in(rels: tuple[str, ...], *tokens: str) -> bool:
    text = "\n".join(read(rel) for rel in rels)
    return all(token in text for token in tokens)


def main() -> int:
    failures: list[str] = []

    require(
        "command search shows partial count",
        has_all("App.tsx", "r.truncated", "partial", "total_matches", "setCmdStatus"),
        failures,
    )
    require(
        "records cap notice is visible",
        has_all("panels/records/RecordsPanel.tsx", "currentResp()?.truncated", "records-cap-notice", "role=\"status\""),
        failures,
    )
    require(
        "strings cap notice has rerun affordance",
        has_all("panels/strings/StringsPanel.tsx", "r().truncated", "cap-notice", "MAX_STRING_LIMIT", "partial result"),
        failures,
    )
    require(
        "taint stopped-at-max explains partial dependency chain",
        has_all("panels/taint/TaintPanel.tsx", "r().stopped", "cap-notice", "full dependency chain may continue", "MAX_TAINT_ROWS"),
        failures,
    )
    require(
        "call tree folded children are surfaced",
        has_all("panels/calltree/CallTreePanel.tsx", "truncatedChildren() > 0", "cap-notice", "deeper child nodes are hidden"),
        failures,
    )
    require(
        "backtrace cap notice has rerun affordance",
        has_all("panels/backtrace/BacktracePanel.tsx", "r().truncated", "cap-notice", "MAX_BACKTRACE_LIMIT", "showing the last"),
        failures,
    )
    require(
        "trace-for-pc caps are visible",
        has_all("panels/tracepc/TraceForPcPanel.tsx", "before_capped", "after_capped", "cap-notice", "MAX_TRACE_PC_LIMIT"),
        failures,
    )
    require(
        "xref same-pc caps are visible",
        has_all("panels/xref/XrefPanel.tsx", "before_capped", "after_capped", "Same-PC refs show", "MAX_PC_REF_LIMIT"),
        failures,
    )
    require(
        "xref asm-search caps are visible",
        has_all("panels/xref/XrefPanel.tsx", "r().truncated", "Instruction text refs stopped", "MAX_ASM_REF_LIMIT", "partial result"),
        failures,
    )
    require(
        "fork events cap notice has rerun affordance",
        has_all("panels/forks/ForksPanel.tsx", "r().truncated", "cap-notice", "MAX_FORK_LIMIT", "partial result"),
        failures,
    )
    require(
        "memory context count cap is explained",
        has_all("panels/memory/MemoryPanel.tsx", "writers_total", "readers_total", "cap-notice", "MEMORY_CONTEXT_LIMIT"),
        failures,
    )
    require(
        "memory write detail cap is explained",
        has_all("panels/memory/MemoryPanel.tsx", "ctx().writes?.truncated", "Write details stopped", "partial result"),
        failures,
    )
    require(
        "hidden decompiler summary still marks partial output",
        has_all("panels/decompiler/DecompilerPanel.tsx", "r().truncated", "cap-notice", "partial result"),
        failures,
    )
    require(
        "hidden LLIL output still marks truncated render",
        has_all("panels/decompiler/DecompilerPanel.tsx", "r.truncated ? \" · partial result\" : \"\"", "llilMaxRecords"),
        failures,
    )
    require(
        "cap notice styling exists",
        has_all_in(
            (
                "styles/foundation.css",
                "styles/records.css",
                "styles/inspectors.css",
                "styles/analysis.css",
                "styles/pseudoc.css",
            ),
            ".cap-notice",
            ".cap-notice button",
        ),
        failures,
    )

    if failures:
        print("Frontend cap static audit failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("OK frontend cap audit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
