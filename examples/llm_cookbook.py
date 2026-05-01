"""traceMiku Python SDK cookbook — ready-to-run examples.

Designed for LLM consumption (plain .py, no Jupyter). Each example is
self-contained and prints results to stdout. Edit the TRACE_PATH at the top
or invoke each function with your own trace.

Run any single example via:
    python examples/llm_cookbook.py <example_name>

Or all:
    python examples/llm_cookbook.py all

Examples:
    1. load_trace                 — Load a trace, print metadata
    2. count_blocks               — Build CFG, count blocks/edges
    3. find_pc                    — All trace idxs where PC == target
    4. taint_x0                   — Forward-taint x0 from idx 0
    5. backward_taint_chain       — Where did the value at idx N in reg X come from?
    6. find_strings_in_mem        — Scan MemShadow for printable ASCII
    7. mem_dump_at_addr           — Hex dump around an address
    8. classify_branch            — Filter trace records by branch type
    9. hot_pcs                    — Top-N most-frequently executed PCs
   10. full_trace_summary         — One-call overview for an LLM agent
"""
import sys, json, pathlib

# Make `viewer` importable when run from anywhere
_PROJ = pathlib.Path(__file__).resolve().parent.parent
if str(_PROJ) not in sys.path:
    sys.path.insert(0, str(_PROJ))

# Edit this if running examples directly:
TRACE_PATH = _PROJ / "traces" / "qunar_drifts_js" \
    / "calls" / "_truncated_call_015_tid0_2970r_?ms"


# ── Example 1 ──────────────────────────────────────────────────────────────
def load_trace(path=TRACE_PATH):
    """Load a trace, print metadata, close."""
    from viewer import load
    t = load(str(path))
    print(f"records: {len(t)}")
    print(f"method:  {t.meta.method!r}")
    print(f"cmd:     {t.meta.cmd}")
    if t.meta.module:
        m = t.meta.module
        print(f"module:  {m.name} @ {hex(m.base)} size={hex(m.size)}")
    print(f"modules: {len(t.meta.modules)} loaded")
    t.close()


# ── Example 2 ──────────────────────────────────────────────────────────────
def count_blocks(path=TRACE_PATH):
    """Build basic-block CFG and report."""
    from viewer import load, build_cfg, loop_sccs
    t = load(str(path))
    cfg = build_cfg(t, only_module=True)
    print(f"blocks: {len(cfg.blocks)}")
    print(f"edges:  {len(cfg.edges)}")
    print(f"loops:  {len(loop_sccs(cfg))}")
    # top-3 hottest blocks
    hot = sorted(cfg.blocks.values(), key=lambda b: -b.executions)[:3]
    print("hottest:")
    for b in hot:
        print(f"  pc={hex(b.start_pc)}  insns={len(b.insns)}  executions={b.executions}")
    t.close()


# ── Example 3 ──────────────────────────────────────────────────────────────
def find_pc(path=TRACE_PATH, target_pc=None):
    """All trace idxs where PC equals `target_pc`. numpy vectorized."""
    import numpy as np
    from viewer import load
    t = load(str(path))
    if target_pc is None:
        target_pc = int(t.pc(0))    # default: first PC of the trace
    arr = t.pc_array()
    idxs = np.nonzero(arr == np.uint64(target_pc))[0]
    print(f"PC {hex(target_pc)} executed {len(idxs)} times")
    print(f"first 5 idxs: {idxs[:5].tolist()}")
    t.close()


# ── Example 4 ──────────────────────────────────────────────────────────────
def taint_x0(path=TRACE_PATH, start_idx=0):
    """Forward-taint x0 starting from idx 0; print first 5 propagations."""
    from viewer import load, Index, forward_taint, decode
    t = load(str(path))
    idx = Index(t); idx.build()
    hits = forward_taint(t, start_idx, "x0", max_count=20, index=idx)
    print(f"x0 forward taint from idx {start_idx}: {len(hits)} hits")
    for i, why in hits[:5]:
        r = t.record(i); d = decode(r.pc, r.inst)
        print(f"  idx={i:5d}  pc={hex(r.pc)}  asm={d.mnemonic} {d.op_str:20s}  why={why}")
    t.close()


# ── Example 5 ──────────────────────────────────────────────────────────────
def backward_taint_chain(path=TRACE_PATH, sink_idx=None, reg="x0"):
    """Where did the value of `reg` at `sink_idx` come from? def-chain walk."""
    from viewer import load, Index, backward_taint, decode
    t = load(str(path))
    if sink_idx is None: sink_idx = len(t) // 2     # default: midpoint
    idx = Index(t); idx.build()
    chain = backward_taint(t, sink_idx, reg, max_count=10, index=idx)
    print(f"backward {reg} from idx {sink_idx}: {len(chain)} steps")
    for i, via in chain:
        r = t.record(i); d = decode(r.pc, r.inst)
        print(f"  idx={i:5d}  pc={hex(r.pc)}  via={via}  asm={d.mnemonic} {d.op_str}")
    t.close()


# ── Example 6 ──────────────────────────────────────────────────────────────
def find_strings_in_mem(path=TRACE_PATH, min_len=8):
    """Scan MemShadow for printable ASCII runs (heuristic)."""
    from viewer import load, MemShadow
    t = load(str(path))
    mem = MemShadow(t); mem.build()
    strings = mem.find_strings(min_len=min_len)
    print(f"found {len(strings)} strings ≥ {min_len} chars")
    for addr, s in strings[:10]:
        print(f"  {hex(addr):>14s}  {s!r}")
    t.close()


# ── Example 7 ──────────────────────────────────────────────────────────────
def mem_dump_at_addr(path=TRACE_PATH, addr=None, count=64):
    """Hex dump from MemShadow at `addr`."""
    from viewer import load, MemShadow
    t = load(str(path))
    mem = MemShadow(t); mem.build()
    if addr is None:
        # default: first observed write address
        if mem.writes:
            addr = mem.writes[0][1]
        else:
            print("no writes in trace"); t.close(); return
    print(f"hex dump at {hex(addr)} ({count} bytes):")
    for line in mem.hex_dump(addr, t=1 << 63, rows=max(1, count // 16))[:8]:
        print("  " + line)
    t.close()


# ── Example 8 ──────────────────────────────────────────────────────────────
def classify_branch(path=TRACE_PATH):
    """Count instruction categories: branch / call / ret / other."""
    from viewer import load, decode
    t = load(str(path))
    counts = {"branch": 0, "call": 0, "ret": 0, "other": 0}
    n = len(t)
    for i in range(min(n, 5000)):    # sample first 5000 for speed
        r = t.record(i); d = decode(r.pc, r.inst)
        if d.is_call:    counts["call"] += 1
        elif d.is_ret:   counts["ret"] += 1
        elif d.is_branch: counts["branch"] += 1
        else:            counts["other"] += 1
    print(f"first {min(n, 5000)} insns:")
    for k, v in counts.items():
        print(f"  {k:8s}  {v:6d}")
    t.close()


# ── Example 9 ──────────────────────────────────────────────────────────────
def hot_pcs(path=TRACE_PATH, top_n=10):
    """Top-N most-frequently executed PCs (numpy bincount on pc_array)."""
    import numpy as np
    from viewer import load, build_from_trace, decode
    t = load(str(path))
    sym = build_from_trace(t)
    arr = t.pc_array()
    unique, counts = np.unique(arr, return_counts=True)
    order = np.argsort(-counts)[:top_n]
    print(f"top {top_n} hot PCs:")
    for idx in order:
        pc = int(unique[idx]); cnt = int(counts[idx])
        fname, foff = sym.lookup(pc)
        # inst at first occurrence
        first = int(np.searchsorted(arr, pc, side="left"))   # NOT correct since unsorted
        # use np.argmax(arr == pc) to find first
        fi = int(np.argmax(arr == np.uint64(pc)))
        d = decode(pc, int(t.inst(fi)))
        print(f"  ×{cnt:5d}  {fname}+{foff:#x}  {d.mnemonic} {d.op_str}")
    t.close()


# ── Example 10 ─────────────────────────────────────────────────────────────
def full_trace_summary(path=TRACE_PATH):
    """One-call overview suitable for LLM agent intro context."""
    from viewer import load, build_from_trace, build_cfg, decode
    t = load(str(path))
    sym = build_from_trace(t)
    cfg = build_cfg(t, only_module=True)
    # entry / exit PC
    entry_pc = int(t.pc(0)); exit_pc = int(t.pc(len(t) - 1))
    fn0, _ = sym.lookup(entry_pc); fn1, _ = sym.lookup(exit_pc)
    summary = {
        "records": len(t),
        "method": t.meta.method,
        "cmd": t.meta.cmd,
        "module": t.meta.module.name if t.meta.module else None,
        "modules_loaded": len(t.meta.modules),
        "cfg_blocks": len(cfg.blocks),
        "cfg_edges": len(cfg.edges),
        "entry": {"pc": hex(entry_pc), "func": fn0 if fn0 != "?" else None},
        "exit":  {"pc": hex(exit_pc),  "func": fn1 if fn1 != "?" else None},
        "unique_funcs_hit": len({sym.lookup(int(t.pc(i)))[0] for i in range(0, len(t), 100)}),
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    t.close()


# ── dispatcher ─────────────────────────────────────────────────────────────
EXAMPLES = {
    "load_trace": load_trace,
    "count_blocks": count_blocks,
    "find_pc": find_pc,
    "taint_x0": taint_x0,
    "backward_taint_chain": backward_taint_chain,
    "find_strings_in_mem": find_strings_in_mem,
    "mem_dump_at_addr": mem_dump_at_addr,
    "classify_branch": classify_branch,
    "hot_pcs": hot_pcs,
    "full_trace_summary": full_trace_summary,
}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nAvailable examples:")
        for name in EXAMPLES: print(f"  - {name}")
        return
    name = sys.argv[1]
    if name == "all":
        for n, fn in EXAMPLES.items():
            print(f"\n══ {n} " + "═" * (60 - len(n)))
            try:
                fn()
            except Exception as e:
                print(f"  FAILED: {e}")
    else:
        fn = EXAMPLES.get(name)
        if fn is None:
            print(f"unknown example: {name}", file=sys.stderr); sys.exit(1)
        fn()


if __name__ == "__main__":
    main()
