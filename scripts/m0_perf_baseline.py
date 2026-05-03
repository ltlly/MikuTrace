"""M0 perf baseline — time every major Python analysis stage on a real trace.

Usage:
    uv run python scripts/m0_perf_baseline.py <call_dir>
    uv run python scripts/m0_perf_baseline.py traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms

Output: prints a JSON object to stdout with every measurement. Reused as
the v1-vs-v2 regression baseline; M2 parity tests compare against the
saved snapshot at docs/superpowers/specs/2026-05-03-m0-perf-baseline.md.
"""
import json
import sys
import time
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def stage(label: str, results: dict):
    t0 = time.perf_counter()
    yield
    elapsed = time.perf_counter() - t0
    results[label] = round(elapsed, 3)
    print(f"  {label:30s} {elapsed:8.3f}s", file=sys.stderr)


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    call_dir = Path(sys.argv[1]).resolve()
    if not call_dir.exists():
        print(f"call_dir not found: {call_dir}", file=sys.stderr)
        sys.exit(2)

    results: dict = {"call_dir": str(call_dir)}

    print(f"# M0 baseline on {call_dir.name}", file=sys.stderr)
    print(f"# trace.bin size: {(call_dir / 'trace.bin').stat().st_size:,} bytes",
          file=sys.stderr)

    from viewer import (
        load, build_from_trace, build_cfg, MemShadow,
        forward_taint, decode,
    )
    from viewer.calltree import build_call_tree

    with stage("trace.load (mmap)", results):
        t = load(call_dir)
    results["records"] = len(t)
    print(f"  records: {len(t):,}", file=sys.stderr)

    with stage("symbols.build_from_trace", results):
        sym = build_from_trace(t)

    with stage("cfg.build_cfg only_module=True", results):
        cfg = build_cfg(t, only_module=True)
    results["cfg_blocks"] = len(cfg.blocks)
    results["cfg_edges"] = len(cfg.edges)

    with stage("calltree.build_call_tree", results):
        ct = build_call_tree(t)
    results["calltree_children"] = len(ct.get("children", []))

    with stage("memshadow.MemShadow.build (cold)", results):
        mem = MemShadow(t)
        mem.build()

    # Pick a reasonable taint start: idx 0, reg x0
    with stage("forward_taint x0 from idx 0 (max_count=5000)", results):
        try:
            from viewer.index import Index
            idx = Index(t)
            idx.build()
            results["index_built"] = True
        except Exception as e:
            print(f"  ! Index.build failed: {e}", file=sys.stderr)
            results["index_built"] = False
        if results.get("index_built"):
            try:
                hits = forward_taint(t, start_idx=0, taint_reg="x0",
                                     max_count=5000, index=idx)
                results["taint_fwd_hits"] = len(hits) if isinstance(hits, list) \
                    else len(hits[0])
            except Exception as e:
                print(f"  ! forward_taint failed: {e}", file=sys.stderr)
                results["taint_fwd_hits"] = None

    # Decode every PC in the trace once (capstone cache benchmark)
    with stage("disasm.decode every distinct PC", results):
        seen = set()
        n = 0
        for i in range(min(len(t), 1_000_000)):  # cap at 1M to bound runtime
            r = t.record(i)
            pc = r.pc
            if pc in seen:
                continue
            seen.add(pc)
            decode(pc, r.inst)
            n += 1
        results["disasm_distinct_pcs_in_first_1M"] = n

    print()
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
