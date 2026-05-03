# M0 — Python analysis perf baseline (2026-05-03)

**Trace**: `traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms`
- size: 4,196,117,888 bytes (4.2 GB)
- records: 15,426,904
- 4196117888 ÷ 272 = 15,426,904 (exact, no padding)

**Hardware**: linux-7.0.0-15-generic, single host (this dev box).
**Python**: 3.14.4, `viewer.*` modules at commit `9dc75c4` of branch `refactor/function-index-handoff`.

## Measurements (single-threaded, `uv run python scripts/m0_perf_baseline.py`)

| Stage | Wall time | Notes |
|---|---|---|
| `trace.load` (mmap+meta) | 0.001s | mmap is constant-time; cost is meta.json parse |
| `symbols.build_from_trace` | 6.7s | walk all records, infer fn boundaries |
| `cfg.build_cfg only_module=True` | 6.4s | block-CFG, GIL-bound, currently the subprocess'd path |
| `calltree.build_call_tree` | 18.4s | bl/ret pair-walking |
| `MemShadow.build` (cold, no sidecar) | 13.4s | sparse byte-map, the GIL-bound monster |
| `Index.build` | — | included in forward_taint timing — no separate measurement |
| `forward_taint(x0 from idx 0, max=5000)` | 26.7s | max_count cap hit (taint_fwd_hits=5000); includes Index.build |
| `disasm.decode` distinct PC in first 1M records | 0.8s | 10,825 distinct PCs; capstone cache hit-rate high on repeats |

## v2 perf goals

| Stage | Python wall | Rust target | Why this target |
|---|---|---|---|
| `trace.load` | ~0.0 s | <0.05s | mmap+bytemuck zero-copy → constant time |
| `cfg.build_cfg` | 6.4 s | 1.6 s | rayon over CFG block-discovery loop |
| `MemShadow.build` | 13.4 s | 3.4 s | rayon over write-event scan, sparse storage same |
| `forward_taint` | 26.7 s | 13.4 s | heap walk is inherently sequential; bounded gain |

Targets are 2-4x because the Python implementations are already reasonably-tuned numpy. The real motivation is **eliminating subprocess** (no more `_subprocess_build_cfg_and_pcinst` IPC marshaling), not raw single-thread speed.

## What this validates / invalidates

- ✅ If MemShadow + CFG together take >5s, the subprocess hack is paying real dividends and Rust will eliminate that hack.
- ❌ If everything is <2s, the v2 motivation shifts entirely to "type safety + single binary deploy" (D2 in main spec) and the perf claim should be removed from §1 of the design spec.

**Verdict**: MemShadow (13.4s) + CFG (6.4s) = 19.8s combined. The subprocess hack is justified. calltree (18.4s) and forward_taint (26.7s) are both bottlenecks that will benefit from the Rust port even without parallelism gains.
