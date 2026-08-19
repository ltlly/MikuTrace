"""Shared skeleton for the frontend static audit scripts.

The five audits (frontend_{ui,cap,resource,stability,api_client}_audit.py)
pin frontend source affordances with plain substring/regex checks; only the
assertions differ. This module owns repo-root resolution, source reading, the
`require` accumulator, and the shared pass/fail report so the copies cannot
drift in CLI behavior or output format.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "frontend" / "src"


def read(rel: str) -> str:
    return (SRC / rel).read_text()


def read_many(*rels: str) -> str:
    return "\n".join(read(rel) for rel in rels)


def require(name: str, ok: bool, failures: list[str]) -> None:
    if not ok:
        failures.append(name)


def report(audit: str, failures: list[str], ok_line: str) -> int:
    """Print the shared failure/success report and return the exit code."""
    if failures:
        print(f"Frontend {audit} static audit failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(ok_line)
    return 0
