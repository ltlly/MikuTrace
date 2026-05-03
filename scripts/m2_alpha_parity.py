"""M2-α parity differ — Python `viewer stats` vs Rust `tracemiku-cli stats`.

Usage:
    uv run python scripts/m2_alpha_parity.py <call_dir>
    uv run python scripts/m2_alpha_parity.py /tmp/tracemiku_smoke/run/calls/call_001_*

Runs both implementations, compares the JSON output field-by-field,
prints a diff and exits 1 on any mismatch. Used during M2-α to validate
the Rust port matches Python's reference behavior.

Allowed deviations (auto-normalized before compare):
- `path` may differ in resolution (symlinks, relative-vs-absolute) → both
  passed through Path.resolve() before compare.
- `modules` ordering — both sides sort by size desc, but identical-size
  ties may shuffle. Compared as a sorted list of (name, base, size) tuples.
"""
import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def run_python(call_dir: Path) -> dict:
    out = subprocess.check_output(
        ["uv", "run", "python", "-m", "viewer", "stats", str(call_dir)],
        cwd=REPO_ROOT,
    )
    return json.loads(out)


def run_rust(call_dir: Path) -> dict:
    out = subprocess.check_output(
        ["cargo", "run", "--quiet", "--bin", "tracemiku-cli", "--",
         "stats", str(call_dir)],
        cwd=REPO_ROOT / "rust",
    )
    return json.loads(out)


def normalize(d: dict) -> dict:
    out = dict(d)
    out["path"] = str(Path(out["path"]).resolve())
    if "modules" in out:
        # Compare modules as a sorted list of name+base+size triples (order-insensitive).
        out["modules"] = sorted(
            out["modules"],
            key=lambda m: (m["name"], m["base"], m["size"]),
        )
    return out


def diff(py: dict, rs: dict) -> list[str]:
    """Return a list of human-readable mismatch lines, empty on full match."""
    p, r = normalize(py), normalize(rs)
    diffs: list[str] = []
    keys = set(p.keys()) | set(r.keys())
    for k in sorted(keys):
        if k not in p:
            diffs.append(f"  rust-only field: {k!r} = {r[k]!r}")
            continue
        if k not in r:
            diffs.append(f"  python-only field: {k!r} = {p[k]!r}")
            continue
        if p[k] != r[k]:
            diffs.append(f"  field {k!r} differs:")
            diffs.append(f"    python: {p[k]!r}")
            diffs.append(f"    rust:   {r[k]!r}")
    return diffs


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    call_dir = Path(sys.argv[1]).resolve()
    if not call_dir.exists():
        print(f"call_dir not found: {call_dir}", file=sys.stderr)
        sys.exit(2)

    print(f"# parity check on {call_dir.name}", file=sys.stderr)
    py = run_python(call_dir)
    rs = run_rust(call_dir)
    diffs = diff(py, rs)
    if diffs:
        print("MISMATCH:", file=sys.stderr)
        for line in diffs:
            print(line, file=sys.stderr)
        sys.exit(1)
    print(f"OK — {len(py)} fields match", file=sys.stderr)


if __name__ == "__main__":
    main()
