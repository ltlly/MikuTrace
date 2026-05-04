# traceMiku Analysis v2 — Rust core + TS frontend (Design Spec)

**Status**: design approved 2026-05-03, awaiting plan + implementation
**Author**: Claude (Opus 4.7) collaborating with @ltlly
**Replaces**: current Python `viewer/` + `webui/server.py` + `webui/app.js` runtime
**Out of scope**: capture chain (`tracer/`, Frida agent, `./tracemiku trace`, adb/device)

---

## 1. Motivation

The Python + vanilla-JS analysis stack has hit two real ceilings during AI-assisted iteration:

1. **GIL forces subprocess for parallelism.** `_subprocess_build_cfg_and_pcinst` in `webui/server.py` exists because CFG/pc_inst build cannot run in-process without freezing `/api/records` and `/api/record/<idx>`. The hack survives but adds forkserver brittleness, IPC marshaling cost, and the test-mode "BG never ready" failure mode that prompted this whole refactor's `_cfg_pack_ready_or_build` sync fallback.
2. **2700-line `app.js` does not scale.** Single global `STATE` object, no types, ad-hoc cache keys (the LLM raw cache key bug we just fixed is one example), tabs reach into each other's DOM. Every change risks a regression a typed module system would catch at build time.

Single-user prototype, no compatibility constraints, AI doing all implementation — the right move is a clean v2, not incremental refactor.

## 2. Scope

### What changes
- **`viewer/` (Python analysis SDK)** → replaced by `rust/crates/tracemiku-core/`
- **`webui/server.py` (FastAPI)** → replaced by `rust/crates/tracemiku-server/` (axum)
- **`webui/app.js` + `index.html` + `styles.css`** → replaced by `frontend/` (Vite + Solid + TS)
- **`viewer/__main__.py` (CLI)** → replaced by `rust/crates/tracemiku-cli/`

### What does NOT change
- `tracer/` (Frida agents, JS) — untouched
- `./tracemiku trace` subcommand — stays Python (only Frida orchestration)
- `tools/hooks/*.json` (JNI specs, suicide patches, type anchors) — format stable
- `examples/<so>/known_offsets.json` — format stable
- **trace.bin 272B record format + per-call dir layout + meta.json schema** — frozen contract; capture writes them, analysis reads them
- Sidecar formats (`.memshadow.v2.npz`) — analysis-side, may need migration; bumped to `.memshadow.v3.bin` (Rust-native binary); old sidecars regenerable, no migration needed in prototype phase

### What is consciously deleted
- `viewer/app.py` (TUI) — already frozen, drop entirely
- Old `webui/` directory after M7 cutover
- Old `tests/test_*.py` after M7 cutover (cargo test + frontend tests cover v2)
- `viewer/__init__.py` SDK Python re-exports (replaced by Rust public API; Python still callable via PyO3 binding if a future need arises)

## 3. Architecture

```
+-------------------------------------------------------------+
|  CAPTURE (unchanged Python + Frida)                         |
|    tracer/agent_cmodule_v5.js  →  trace.bin + meta.json     |
|    ./tracemiku trace            →  per-call dir on disk     |
+-------------------------------------------------------------+
                          |
                          v  reads on-disk trace
+-------------------------------------------------------------+
|  ANALYSIS v2 (Rust)                                         |
|                                                             |
|  rust/crates/tracemiku-core (cdylib + rlib)                 |
|    - trace parser (memmap2 + bytemuck zero-copy)            |
|    - module resolver, symbol map                            |
|    - disasm (capstone-rs)                                   |
|    - CFG, FunctionIndex, calltree                           |
|    - Index (def-use chains, mem ops)                        |
|    - MemShadow (rayon-parallel build, sparse byte map)      |
|    - taint forward / backward                               |
|    - LLIL pipeline (lift → SSA → passes → render)           |
|    - crypto-scan / ollvm-detect / hash-finalize-detect      |
|                                                             |
|  rust/crates/tracemiku-server (binary)                      |
|    - axum HTTP + tokio runtime                              |
|    - utoipa-generated /openapi.json                         |
|    - REST API (~20 endpoints)                               |
|    - WebSocket /ws/jobs (long-job progress)                 |
|    - serves frontend/dist/ as static                        |
|    - spawns + manages Python BN sidecar                     |
|                                                             |
|  rust/crates/tracemiku-cli (binary)                         |
|    - subcommand dispatch (parser/cfg/taint/dec/...)         |
|    - JSON stdout (LLM-friendly)                             |
+-------------------------------------------------------------+
                          |
                          v  spawns on demand
+-------------------------------------------------------------+
|  BN PYTHON SIDECAR  (binja-only Python helper)              |
|    - python -m tracemiku_bn_sidecar (in vendored helper)    |
|    - JSON-RPC over stdin/stdout                             |
|    - methods: open_so / hlil_for / cfg_for / vars_for       |
+-------------------------------------------------------------+
                          ^
                          |  /api/* + ws + static
+-------------------------------------------------------------+
|  FRONTEND (Vite + Solid + TS)                               |
|                                                             |
|  frontend/                                                  |
|    src/                                                     |
|      api/         openapi-typescript-generated client      |
|      stores/      Solid signals, no global STATE           |
|      panels/      one folder per UI panel                  |
|      components/  shared UI primitives                     |
|    public/                                                  |
|    vite.config.ts  →  builds dist/, served by Rust server  |
+-------------------------------------------------------------+
```

### Process model

- **One process** in normal operation (`tracemiku-server`). Rayon ThreadPool for CPU-bound analysis (CFG/MemShadow/taint), Tokio runtime for HTTP + WebSocket.
- **+1 child process** when BN HLIL requested (`python -m tracemiku_bn_sidecar`). Lazy-spawned on first BN request, kept alive for session, killed on server shutdown.

### Data flow on a real request: SPA loads → user clicks Functions row

1. SPA `GET /api/meta` → axum returns `MetaResponse` (cached after first read of `meta.json`)
2. SPA `GET /api/functions` → tracemiku-core builds FunctionIndex (TraceIR top-K + symbol + BN if sidecar ready); returns JSON
3. User clicks row → SPA `GET /api/cfg?fn=<name>` → tracemiku-core returns blocks + edges (rayon-parallel block decode)
4. User double-clicks → SPA opens Decompile panel → `GET /api/dec/fn/{trace:F0}` → tracemiku-core renders FuncIR markdown
5. User clicks "LLM raw" → SPA `POST /api/dec/llm-call` → tracemiku-server `reqwest`-spawn LLM call → returns C-pseudocode

No subprocess for analysis (rayon is in-process). Subprocess only for LLM HTTP and (later) BN sidecar.

## 4. Key data structures (Rust)

```rust
// trace.bin record (272 bytes, fixed-size, zero-copy castable)
#[repr(C, packed)]
#[derive(bytemuck::Pod, bytemuck::Zeroable, Copy, Clone)]
pub struct Record {
    pub pc: u64,           // 8B
    pub regs: [u64; 31],   // 248B  (x0..x30, where x30=lr)
    pub sp: u64,           // 8B
    pub flags: u32,        // 4B    (NZCV etc.)
    pub raw_inst: u32,     // 4B    (4-byte ARM64 encoding)
}
const _: () = assert!(std::mem::size_of::<Record>() == 272);

// trace, mmap-backed
pub struct Trace {
    mmap: memmap2::Mmap,
    pub meta: TraceMeta,
}
impl Trace {
    pub fn records(&self) -> &[Record] {
        bytemuck::cast_slice(&self.mmap[..])
    }
    pub fn len(&self) -> usize { self.records().len() }
}

// FunctionIndex (mirrors current Python viewer/function_index.py)
pub struct FunctionIndex {
    entries: Vec<FunctionEntry>,
}
pub struct FunctionEntry {
    pub id: FnId,                 // typed enum, see below
    pub name: String,
    pub source: FnSource,         // TraceIr | Symbol | Bn
    pub entry_pc: Option<u64>,
    pub blocks: u32,
    pub records: u32,
    pub trace_ir_id: Option<String>,
    pub bn_start: Option<u64>,
    pub can_llil: bool,
    pub can_bn_hlil: bool,
}
pub enum FnId {
    Trace(String),    // "F0" → serializes as "trace:F0"
    Sym(String),      // "f_alpha" → "sym:f_alpha"
    Bn(u64),          // 0x100000 → "bn:0x100000"
}
impl FnId {
    pub fn parse(s: &str) -> Result<Self, FnIdError> { ... }
    pub fn to_wire(&self) -> String { ... }   // public API form
}
```

`FnId::parse` enforces the same legacy aliases as today's `parse_id` in `viewer/function_index.py` (bare `F0` → `Trace`, `cfg:<name>` → `Sym`).

## 5. API surface

Mirror of the current `/api/*` namespace, but typed via utoipa:

| Endpoint | Method | Notes |
|---|---|---|
| `/api/meta` | GET | trace metadata, module list, regs |
| `/api/records?from=&to=` | GET | record window (zero-copy slice → JSON) |
| `/api/record/{idx}` | GET | full record detail with annotations |
| `/api/cfg?fn=` | GET | block-CFG, optional fn filter |
| `/api/cfg-svg?fn=` | GET | rendered SVG (graphviz call via `petgraph` + `graphviz-rust`) |
| `/api/functions` | GET | unified FunctionIndex (this refactor's prize) |
| `/api/dec/summary` | GET | TraceIR markdown |
| `/api/dec/fn/{id}` | GET | per-fn IR markdown |
| `/api/dec/llm-call` | POST | LLM dispatch (HTTP via reqwest) |
| `/api/llil/render` | POST | full LLIL pipeline → C-pseudo |
| `/api/llil/llm` | POST | LLIL skeleton → LLM |
| `/api/hlil-for-pc` | GET | BN sidecar — HLIL for PC |
| `/api/hlil-for-fn` | GET | BN sidecar — HLIL by FunctionIndex id |
| `/api/bn-cfg-svg-for-pc` | GET | BN sidecar — CFG SVG |
| `/api/strings` | GET | MemShadow string scan |
| `/api/forward-taint` | GET | rayon-parallel forward taint |
| `/api/backward-taint` | GET | rayon-parallel backward taint |
| `/api/mem-dump` | GET | memshadow region read |
| `/api/find-mem-pattern` | GET | byte-pattern search |
| `/api/jni-calls` | GET | JNI hook overlay |
| `/api/call-tree` | GET | bl/ret pair-walking nested tree |
| `/api/fork-events` | GET | fork lifecycle |
| `/api/crypto-scan` | GET | known-primitive table scan |
| `/api/ollvm-detect-vm` | GET | VM dispatcher heuristic |
| `/api/openapi.json` | GET | utoipa-generated; consumed by frontend codegen |
| `/ws/jobs` | WS | long-job progress events |

Endpoints not yet in this list (~25 more) get added as panels need them. Each must have a utoipa-typed response struct and a serde test.

## 6. Frontend architecture

### Stack
- **Vite 5** + **Solid 1.x** + **TypeScript strict mode**
- **No UI component library**, hand-written CSS (current `webui/styles.css` is the visual reference)
- **State**: Solid signals, scoped per panel. No global `STATE` god-object.
- **API client**: `openapi-typescript` generates `src/api/types.ts` from `/api/openapi.json` at build time; thin `fetch` wrappers.
- **WebSocket**: native `WebSocket` API, one connection per page, multiplexed by job ID.

### Layout

```
frontend/
  package.json
  vite.config.ts
  tsconfig.json
  index.html
  src/
    main.tsx                  — Solid root + router
    api/
      types.ts                — generated from /api/openapi.json (do not edit)
      client.ts               — typed fetch wrappers
      ws.ts                   — WebSocket multiplexer
    stores/
      trace.ts                — current trace metadata signal
      cursor.ts               — selected record idx, syncs panels
      function_index.ts       — FunctionIndex client cache
    panels/
      records/                — main trace stream virtual list
      cfg/                    — block CFG SVG render
      decompile/              — TraceIR markdown + LLIL render + LLM
      hlil/                   — BN HLIL panel
      strings/                — string scan list
      taint/                  — forward/backward taint visualizer
      memory/                 — mem-dump hex view + diff
      crypto/                 — crypto-scan + hash-finalize-detect
      forks/                  — fork lifecycle table
      calltree/               — nested call tree
      jni/                    — JNI hook overlay
    components/
      VirtualList.tsx         — windowed scroll for big traces
      HexBlock.tsx            — hex dump renderer
      RegisterTable.tsx       — register state table
      FnIdBadge.tsx           — trace:/sym:/bn: badge
    styles/
      base.css                — pwndbg-style monospace dense
      panels.css
```

Each panel folder is self-contained: own component, own store binding, own tests. Panels do not import each other; they read from shared stores (cursor, function_index) and emit events through the cursor store.

## 7. BN Python sidecar

A small Python helper distributed alongside the Rust binary:

```
rust/crates/tracemiku-server/python_sidecar/
  tracemiku_bn_sidecar/
    __main__.py     — JSON-RPC loop on stdin/stdout
    bn_session.py   — BN backend wrapper (reuses viewer/decompiler/backends/binja.py logic)
  pyproject.toml
```

Spawned by Rust server lazily:
```rust
let child = Command::new("python3")
    .args(["-m", "tracemiku_bn_sidecar", "--so", so_path])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .spawn()?;
```

JSON-RPC methods:
- `open_so(path) -> {ok, version, fn_count}`
- `hlil_for(pc) -> {fn: {name,start,end}, lines:[{pc,text}], vars:[...]}`
- `cfg_for(pc) -> {svg, blocks, edges}`
- `vars_for(pc) -> [{name, type, storage}]`

Sidecar dies with parent (process group + SIGTERM on drop). One sidecar per server lifetime; if it crashes the server marks BN endpoints as `ready: false` and tries to respawn on next request (3-retry cap).

## 8. Testing strategy

### Rust side (cargo test)
- **tracemiku-core**: per-module unit tests with synthetic traces
- **tracemiku-server**: per-endpoint smoke (axum::test)
- **One real-trace integration test**: load an existing `traces/debug_minimal/calls/call_001_*` trace (6.8GB), exercise core endpoints, snapshot the JSON outputs as the ground truth. This becomes the regression baseline; any future change must keep these snapshots stable or explicitly update them.

### Frontend side (vitest + Playwright optional)
- Per-panel component tests with mocked API responses
- One e2e test (Playwright when Chrome available, skipped otherwise) running through the same flows as `tests/test_webui_e2e_flow.py`

### Cross-validation during migration (transient)
For each Rust module landed in M2-M5, write a side-by-side comparison script that loads the same trace in Python (current `viewer.*`) and Rust (`cargo run`), compares JSON outputs, and asserts equivalence. Save under `rust/tests/parity/`. These scripts are deleted at M7 cutover; their job is one-shot validation, not permanent test infrastructure.

### What is consciously NOT done
- No 200-300 endpoint snapshot golden corpus (overengineering for prototype phase)
- No differential test harness with normalizers (one ad-hoc parity script per module is enough)
- No 1:1 byte-equal text matching for LLIL render (token-level set comparison)

## 9. Migration milestones

| M | Name | Scope | Primary outputs |
|---|---|---|---|
| **M0** | Reality check + spec freeze | Profile current Python on real trace; freeze data-structure spec; freeze endpoint list; freeze LLIL diff granularity | `docs/superpowers/specs/...m0-perf-baseline.md`, `...llil-diff-spec.md` |
| **M1** | Skeleton + first endpoint | Rust workspace (4 crates); Vite skeleton; `/api/meta` round-trip; CI cargo build green | runnable `tracemiku-server` serving `/api/meta` |
| **M2** | tracemiku-core | Trace parser, module/sym, CFG, Index, MemShadow, taint, FunctionIndex, calltree | `cargo test -p tracemiku-core` green; parity scripts vs Python pass |
| **M3** | tracemiku-server endpoints | All ~25 trace-only endpoints (no BN), WebSocket job system | `tracemiku-server` serves all current /api/* (sans BN); per-route smoke tests via `axum-test` or `tower::ServiceExt` green |
| **M4** | TS frontend core | records / cfg / functions / decompile panels working in browser | `pnpm dev` → click through the 4 main flows |
| **M5** | LLIL pipeline (Rust) | lift → SSA → passes → render — Rust port | parity vs Python LLIL output (token-level) |
| **M6** | BN python sidecar | JSON-RPC sidecar + Rust spawn/lifecycle + HLIL endpoints | BN HLIL panel working in TS frontend |
| **M7** | Cutover + delete legacy | `tracemiku web` defaults to v2; delete `viewer/` (analysis side), `webui/` entirely; rewrite `./tracemiku` dispatcher | single binary `tracemiku-server` + frontend dist |

LLM-side `viewer/decompiler/llm_*.py` (prompt builder, model adapters) gets ported after the M3-ι trace-only decompiler parity gate (M3-ι2d target: async `reqwest` calls + JSON serde). LLIL renderer (M5) is the only piece of `viewer/decompiler/` that's algorithmically complex.

## 10. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| LLIL pipeline parity is harder than estimated (M5) | Medium | Token-level diff (not byte-level); 1 trace at a time; if blocked, keep Python LLIL as sidecar like BN |
| BN sidecar spawn fragility on path/python issues | Medium | Health check on first call; clear error → frontend shows `BN unavailable: <reason>` |
| Rayon thread pool starves Tokio runtime | Low | Use `tokio::task::spawn_blocking` for CPU-bound, separate rayon pool |
| capstone-rs lags upstream capstone version vs Python's | Low | Pin capstone-rs version; if any disasm differs, fix during M2 parity |
| Solid 1.x ecosystem changes drag in M4 | Low | Vite + Solid is mature; vendor-lock with package.json pins |
| User wants a feature that exists in Python but cut from v2 | Medium | Prototype phase, one user — accept the trade and add later if needed |
| Real-trace performance not actually faster than Python | Low | M0 baseline catches this before M2 starts |

## 11. Decisions (locked)

| # | Topic | Choice | Reason |
|---|---|---|---|
| D1 | Frontend framework | Solid + Vite + TS | Fine-grained reactivity matches "cursor change → many panels sync" pattern; React rerenders would lag |
| D2 | UI component library | None, hand-written CSS | Density-heavy reverse-engineering UI doesn't fit form-oriented libs |
| D3 | BN bridge | Python sidecar via JSON-RPC over stdin/stdout | BN has Python API; no Rust API; subprocess-isolated avoids GIL contamination |
| D4 | ARM64 disasm | capstone-rs | One-line dependency, behavior matches Python capstone exactly |
| D5 | Trace parsing | memmap2 + bytemuck zero-copy | 272B fixed record is a perfect fit; mmap'd file becomes `&[Record]` for free |
| D6 | Long-job progress | WebSocket from Rust server | Tokio + axum native; replaces current `/api/bg-status` polling |
| D7 | Test strategy | cargo test + 1 real-trace integration + transient per-module parity scripts | Single-user prototype; full snapshot golden corpus is overkill |
| D8 | Sidecar lifecycle | Lazy spawn, alive for server lifetime, 3-retry on crash | Simple, low overhead; avoids spawn cost on every BN request |
| D9 | Trace format | Frozen — capture writes 272B record + meta.json + per-call dir; analysis only reads | Capture not in scope; format is the contract |
| D10 | Sidecar files (.memshadow.v3.bin) | Bumped, no migration | Prototype, single user — old sidecars regenerable from trace |
| D11 | Old Python webui | Delete at M7, no v1/v2 coexistence | No external users; reference role ends at parity |
| D12 | Old Python viewer SDK | Delete at M7; future Python access via PyO3 binding if ever needed | Prototype phase; YAGNI |
| D13 | Path of frontend dist serving | Rust server serves `frontend/dist/` as static | One binary deploy; `vite build` step in M7 release |
| D14 | Cargo workspace layout | 3 crates: `tracemiku-core` (lib) / `tracemiku-server` (bin) / `tracemiku-cli` (bin); shared test fixtures inside `tracemiku-core/tests/common/` (no separate test-utils crate until two consumers actually need it) | Standard; isolates server from core for parallel work; YAGNI on test-utils |

## 12. Non-goals

- ❌ Cross-platform GUI (no Electron, no Tauri)
- ❌ Distributed analysis (single machine)
- ❌ Real-time collaborative viewing (single user)
- ❌ Replacing capture with Rust (Frida ecosystem is Python/JS)
- ❌ Replacing Frida agent JS with Rust (frida-rs exists but not the goal)
- ❌ Backwards-compatible REST API (breaking changes OK; frontend updated together)
- ❌ Long-running trace daemon mode (each `tracemiku-server` is per-trace)
- ❌ MCP server (CLAUDE.md prohibits)

## 13. Feature parity matrix

Tracks every Python-side feature against v2 status. Status legend:

- 🔜 **要做** — covered by v2 spec, not yet implemented
- ✅ **已完成** — implemented and parity-tested in v2
- 🟡 **部分完成** — partially implemented in current milestone, rest deferred
- ⏸ **延后** — post-cutover (M7+), optional add-on
- ❌ **删除** — consciously dropped, no v2 replacement
- ⛔ **不在范围** — capture-side or external, untouched

Updated as milestones land. Initial state at design freeze: nothing implemented yet.

### 13.1 Capture chain (out of scope, unchanged)

| Component | Status | Note |
|---|---|---|
| `tracer/agent_cmodule_v5.js` | ⛔ | Frida CModule + SPSC ring + on-device gzip |
| `tracer/agent_cmodule_v3.js` | ⛔ | Legacy IPC agent, kept for regression |
| `tracer/agent_generic.js` | ⛔ | JS callout fallback |
| `./tracemiku trace` (subcommand) | ⛔ | Stays Python; only Frida orchestration |
| `./tracemiku finalize` | ⛔ | Per-call dir post-processing, capture side |
| `vendor/frida-patched/` | ⛔ | Patched frida-server |
| `tools/hooks/*.json` | ⛔ | JSON spec format frozen |

### 13.2 viewer/ core modules

| Python module | v2 home | Status | Note |
|---|---|---|---|
| `trace.py` (Trace, Record, mmap parser, REC_SIZE) | `tracemiku-core::trace` | ✅ M2-α | memmap2 + bytemuck zero-copy; 15 unit/integration tests + scripts/m2_alpha_parity.py |
| `disasm.py` (capstone wrapper, decode, def/use) | `tracemiku-core::disasm` | ✅ M2-γ | capstone-rs 0.13 detail=true; thread-local FIFO cache (200k); regs_def/regs_use via two-pass operand walk + cmp-style fix |
| `index.py` (def-use chains, mem ops) | `tracemiku-core::index` | ✅ M2-ζ | sequential build; reg + mem sides both populated in single trace-walk; mem_addr_to_writes holds trace record indices |
| `cfg.py` (build_cfg, CFG, Block, Tarjan SCC) | `tracemiku-core::cfg` | ✅ M2-δ | petgraph 0.6; tarjan_scc; 6 unit/integration tests |
| `cfg.py::write_dot` / `textual_summary` | n/a | ❌ | TUI legacy, dropped |
| `taint.py` (forward/backward, basic) | `tracemiku-core::taint` | ✅ M3-γ | index-accelerated forward + backward (BFS via VecDeque, MEM-chasing). Parity HARD-gated: forward 0.90 / backward 0.81 jaccard on real trace. Sequential — rayon-parallel only if profiling justifies it. |
| `taint.py` (`--through-mem`, `--data-only`) | `tracemiku-core::taint` | ✅ M3-γ | through_mem byte-overlap via MemShadow.latest_write_idx_strict_before. data_only filters addressing-only regs; default exclude={sp,fp,lr} when caller doesn't override. 2 colocated tests pin both flags. |
| `taint.py` (`--cross-fn-call` frame_depth annotation) | `tracemiku-core::taint` | ✅ M3-γ | `build_frame_depth_map` shipped (M3-β); cross_fn_call query param now wired through both endpoints → `frame_depth: Option<u32>` row field with skip_serializing_if. 2 integration tests pin presence/absence. |
| (future) **semantic cross-fn taint propagation** (ABI arg tracking, caller-saved kill, callee→caller return flow) | `tracemiku-core::taint::cross_fn` | ⏸ | Brand-new feature; needs its own design. Python never implemented this; the Python TODO note "全量 propagation 待真机" referred to *this*, not to frame_depth annotation. Do after v2 cutover and after real-trace need is documented. |
| `memshadow.py` (sparse byte map + .npz sidecar) | `tracemiku-core::memshadow` | ✅ M3-λ | core port (BTreeMap byte index, build/byte_at/find_strings/hex_dump) plus Rust-native `trace.bin.memshadow.v3.bin` sidecar. Stale/corrupt sidecars are ignored and regenerated; Python v2 `.npz` is not migrated. |
| `symbols.py` (SymbolMap, ModuleResolver, build_from_trace) | `tracemiku-core::symbols` | 🟡 M2-γ: SymbolMap + ModuleResolver + build_from_trace done; auto_known_offsets M2-δ | sorted-Vec + binary-search via partition_point |
| `symbols.py::load_ida_symbols` | `tracemiku-core::symbols` | ⏸ | IDA JSON import; rare path |
| `symbols.py::auto_known_offsets` | `tracemiku-core::symbols` | ✅ M2-ε | bl-target heuristic + examples/<so>/known_offsets.json overlay; merged into AppState symbols with priority: static > examples > auto |
| `display.py` (pwndbg-style annotations) | frontend rendering | 🔜 M4 | moves to TS frontend; backend just emits structured tokens |
| `function_index.py` (FunctionIndex, FunctionEntry, parse_id) | `tracemiku-core::function_index` | ✅ M2-ε | direct port; legacy F0 / cfg: parser kept; 8 unit tests |
| `calltree.py` (build_call_tree, bl/ret pair-walking) | `tracemiku-core::calltree` | ✅ M3-α | direct port; cap-balance counter for max_depth; 3 unit tests + parity gate |
| `hashfin.py` (hash-finalize-detect) | `tracemiku-core::hashfin` | 🔜 M3 | window-based scan |
| `ollvmdet.py` (ollvm-detect-vm heuristic) | `tracemiku-core::ollvmdet` | ✅ M3-ι2b | 1:1 port; ollvm_detect_vm + OllvmFinding. Heuristic scoring 0.4+0.3+0.2+0.1 (parity with Python). 3 unit tests. |
| `app.py` (TUI) | n/a | ❌ | Frozen long ago, deleted at M7 |
| `__main__.py` (Python CLI, ~31 subcommands) | `tracemiku-cli` (Rust bin) | ✅ M3-μ prep | clap dispatcher now has REST-backed wrappers for shipped trace-only endpoints plus `list`/`info`; destructive legacy replacement remains M7 sign-off |
| `__init__.py` (Python SDK re-exports) | n/a | ❌ | M7 deletes; PyO3 binding only if future need |

### 13.3 viewer/decompiler/ modules

| Python module | v2 home | Status | Note |
|---|---|---|---|
| `backend.py` (FieldHint, Function, Variable dataclasses + Backend Protocol) | `tracemiku-core::decompiler::backend` | 🟡 M3-δ | dataclasses + Backend trait + NoneBackend stub shipped; real BinjaBackend defers to M5+ (PyO3 / sidecar) |
| `backends/binja.py` | BN python sidecar | 🔜 M6 | reused via JSON-RPC |
| `backends/{ghidra,ida,r2}.py` | n/a | ❌ | Stub-only today; never wired up |
| `backends/none.py` | `tracemiku-core::decompiler::backend::NoneBackend` | ✅ M3-δ | trivial null backend; returns None / Default everywhere |
| `ir.py` (TraceIR dataclasses — TopIR / FuncIR / BlockIR / EdgeIR / LoopIR / CallIR / TypeAnchorIR / VmCandidateIR / InductionVarIR) | `tracemiku-core::decompiler::ir` | ✅ M3-δ | direct port; TopIR::fn_by_id helper; serde rename for `ref` / `final` / `static` Rust keywords |
| `builder.py` (build_trace_ir, render_summary_md, render_func_md) | `tracemiku-core::decompiler::builder` | 🟡 M3-ι2c | metadata + root F0 (M3-δ) + top-K callee splits (M3-ε) + BlockIR id/pc/end_pc/insns/exec_count (M3-ζ) + BlockIR asm/samples/tier (M3-η) + BlockIR.exits with kind/taken_count via CFG EdgeMeta (M3-ι) + render_summary_md fidelity (M3-ι) + type_anchors auto-discovery/render (M3-ι2a) + vm_candidates auto-populated with MemShadow hex dump (M3-ι2b) + on-demand symbol FuncIR for `sym:*`/`cfg:*` dec_fn (M3-ι2c). Still partial: root LoopIR/CallIR/induction-var population remains deferred. |
| `llm_client.py` (claude/deepseek/qwen/mimo) | `tracemiku-server::llm` | ✅ M3-ι2d | reqwest + serde JSON adapters; env-only API keys; mock-provider tests cover OpenAI-compatible success path without real API calls |
| `llm_bundle.py` (build_fn_decompile_prompt) | `tracemiku-core::decompiler::prompt` | ✅ M3-ι2d | prompt + VM context injection + hot-block truncation logic |
| `type_anchor.py` (TypeSpec/TypeAnchor + load + find) | `tracemiku-core::decompiler::type_anchor` + `attach_type_anchors` in builder | ✅ M3-ι2a | 1:1 port; auto-discovers tools/hooks/*.json with kind=="type_specs" plus examples/<so>/type_specs.json. Render markdown section parity with Python markdown.py:207-229. |
| `vm_candidate.py` (OLLVM VM detection, DEC3-D) | `tracemiku-core::decompiler::vm_candidate` | ✅ M3-ι2b | 1:1 port; detect_vm_candidates emits VmCandidateIR with hex_dump from MemShadow. Helpers find_self_update_loads + bytecode_range. 3 unit tests. |
| `llil/lift.py` (capstone → LLIL) | `tracemiku-core::llil::lift` | 🔜 M5 | capstone-rs feed |
| `llil/ssa.py` (block-local SSA + cross-block phi) | `tracemiku-core::llil::ssa` | 🔜 M5 | including AAPCS64 caller-saved kill |
| `llil/pass_constfold.py` | `tracemiku-core::llil::pass_constfold` | 🔜 M5 | |
| `llil/pass_dce.py` | `tracemiku-core::llil::pass_dce` | 🔜 M5 | |
| `llil/pass_flag_elim.py` | `tracemiku-core::llil::pass_flag_elim` | 🔜 M5 | |
| `llil/pass_typelat.py` | `tracemiku-core::llil::pass_typelat` | 🔜 M5 | |
| `llil/pass_struct.py` | `tracemiku-core::llil::pass_struct` | 🔜 M5 | |
| `llil/pass_var_unify.py` | `tracemiku-core::llil::pass_var_unify` | 🔜 M5 | |
| `llil/pass_restructure.py` | `tracemiku-core::llil::pass_restructure` | 🔜 M5 | CFG → if/while/for |
| `llil/pass_uidf.py` | `tracemiku-core::llil::pass_uidf` | 🔜 M5 | trace-truth value injection |
| `llil/render.py` (HLIL pseudocode output) | `tracemiku-core::llil::render` | 🔜 M5 | C-pseudo formatter |

### 13.4 CLI subcommands (`python -m viewer <cmd>` → `tracemiku-cli <cmd>`)

| Subcommand | Status | Note |
|---|---|---|
| `stats` | ✅ M2-α | trace metadata JSON |
| `records`, `record` | ✅ M3-μ | REST-backed wrappers for `/api/records` and `/api/record/{idx}` |
| `functions`, `cfg`, `cfg-svg`, `call-tree` | ✅ M3-μ | REST-backed wrappers for shipped server endpoints |
| `strings`, `mem-dump` | ✅ M3-μ | REST-backed wrappers; MemShadow v3 sidecar load-or-build |
| `dec-summary`, `dec-fn` | ✅ M3-μ | REST-backed wrappers for TraceIR markdown routes |
| `idxs-for-pc` | ✅ M3-ξ | REST-backed wrapper for `/api/idxs-for-pc` |
| `search-pc` | ✅ M3-χ | legacy all-hit PC list shape |
| `search`, `search-asm` | ✅ M3-ξ | REST-backed wrappers for `/api/search` |
| `taint-fwd`, `taint-bwd` | ✅ M3-μ | REST-backed wrappers for M3-γ taint endpoints |
| `data-chase` | ✅ M3-τ | single-path backward data chase through reg/load/store |
| `so-stats` | ✅ M3-ξ | REST-backed wrapper for `/api/so-stats` |
| `last-write-of-addr` | ✅ M3-π | REST-backed wrapper for `/api/last-write-of-addr` |
| `find-mem-pattern` | ✅ M3-π | REST-backed wrapper for `/api/find-mem-pattern` |
| `mem-writes-in-range` | ✅ M3-π | covered by `idxs-touching-range` writer partition |
| `mem-flow` | ✅ M3-φ | REST-backed per-byte event timeline |
| `crypto-scan` | 🔜 M3 | 22 standard primitives |
| `reg-value-at`, `reg-at-idx` | ✅ M3-ξ | REST-backed wrappers for `/api/reg-value-at` |
| `call-chain` | ✅ M3-σ | REST-backed LR walking wrapper |
| `hash-input-search` | 🔜 M3 | |
| `diff-traces` | 🔜 M3 | |
| `fork-events` | ✅ M3-ο | reads per-call meta.json fork_events via REST wrapper |
| `ollvm-detect-vm` | ✅ M3-ψ | REST-backed OLLVM VM dispatcher heuristic |
| `hash-finalize-detect` | 🔜 M3 | |
| `auto-phase-detect` | 🔜 M3 | |
| `jni-calls`, `jobj-history`, `jni-strings` | 🔜 M3 | reads jni_hooks.jsonl |
| `mem-dump` | ✅ M3-μ | see `strings`, `mem-dump` row above |
| `reg-timeline` | ✅ M3-υ | REST-backed register change timeline |
| `mem-diff` | ✅ M3-υ | REST-backed MemShadow byte diff around an idx |
| `fn-summary` | ✅ M3-ω | REST-backed function overview |
| `field-at` | 🔜 M3 | |
| `export` (CSV/JSON dump) | ⏸ | Power-user; defer |
| `dec` (LLM-assisted decompile, route B) | 🔜 M5 | uses llm_client |
| `dec-bench` (multi-model benchmark) | ⏸ | Defer until base `dec` parity holds |
| `view` (web subcommand wrapper) | 🔜 M7 | dispatcher to `tracemiku-server` |
| `query` (ad-hoc Python eval) | ❌ | Replaced by `tracemiku-cli` typed subcommands |
| `info` (per-call dir summary) | ✅ M3-μ | filesystem/Core implementation; no Python viewer import |
| `list` (list calls in trace dir) | ✅ M3-μ | filesystem implementation; JSON is parity contract |

### 13.5 REST API endpoints

All listed in §5 plus this exhaustive map of every endpoint currently in `webui/server.py`:

| Endpoint | Status | Note |
|---|---|---|
| `/api/meta` | ✅ M1 | first end-to-end milestone — landed 2026-05-03 |
| `/api/records?start=&count=` | ✅ M2-β | symbol-dependent fields (func/off/annotation/exec_count) emitted null until M2-γ |
| `/api/record/{idx}` | ✅ M2-β | full regs object; prev_regs + regs_annotated deferred to M2-γ |
| `/api/so-stats` | ✅ M3-ν | per-module record counts + unknown PCs |
| `/api/cfg?fn=` | ✅ M2-δ | blocks + edges; ?fn= filter via SymbolMap |
| `/api/cfg-svg` | ✅ M3-κ | Graphviz dot subprocess + cached SVG + Solid Graph panel |
| `/api/block?pc=` | ✅ M3-ρ | block detail with insns and exits |
| `/api/block-for-pc` | ✅ M3-ρ | containing trace-CFG block lookup |
| `/api/loops` | ✅ M3-ρ | SCC loop list from trace CFG |
| `/api/backtrace` | ✅ M3-ρ | dynamic call-stack replay at idx |
| `/api/idxs-for-pc` | ✅ M2-γ | linear pc-scan; ~50ms on 15M records; hashed pc index deferred to M2-δ if profiling demands |
| `/api/idxs-for-block` | ✅ M2-δ | linear pc-scan in [start_pc, end_pc]; M2-ε precomputed map if profiling demands |
| `/api/idxs-touching-addr` | ✅ M3-π | split read/write touches around cursor |
| `/api/idxs-touching-range` | ✅ M3-π | overlapping read/write ranges around cursor |
| `/api/search` | ✅ M3-ν | case-insensitive regex over decoded asm |
| `/api/search-pc` | ✅ M3-χ | legacy all-hit PC list shape |
| `/api/forward-taint` | ✅ M3-γ | through_mem / data_only / cross_fn_call query params + frame_depth row field; parity hard-gate green at 0.90 jaccard |
| `/api/backward-taint` | ✅ M3-γ | through_mem / data_only / cross_fn_call query params + frame_depth row field; backward MEM-chasing + ARM64 writeback handling shipped; parity hard-gate green at 0.81 jaccard |
| `/api/strings` | ✅ M2-ζ | MemShadow-backed; eager build on AppState::load |
| `/api/string-provenance` | 🔜 M3 | |
| `/api/mem-dump` | ✅ M2-ζ | MemShadow-backed; eager build on AppState::load |
| `/api/last-write-of-reg` | ✅ M2-ε | linear backward scan from idx; returns {idx, pc, value} |
| `/api/last-write-of-addr` | ✅ M3-π | latest overlapping write before cursor |
| `/api/reg-value-at`, `/api/reg-at-idx` | ✅ M3-ν | cursor register lookup with x/w/fp/lr aliases |
| `/api/data-chase` | ✅ M3-τ | single-path backward data chase |
| `/api/find-mem-pattern` | ✅ M3-π | MemShadow byte-pattern scan with idx filters |
| `/api/mem-writes-in-range` | ✅ M3-π | covered by `/api/idxs-touching-range` writer partition |
| `/api/mem-flow` | ✅ M3-φ | per-byte read/write event timeline |
| `/api/mem-diff` | ✅ M3-υ | MemShadow byte diff between idx-1 and idx |
| `/api/reg-timeline` | ✅ M3-υ | distinct register value timeline |
| `/api/jni-calls`, `/api/jobj-history`, `/api/jni-strings`, `/api/jni-events` | 🔜 M3 | reads jni_hooks.jsonl |
| `/api/field-at` | 🔜 M3 | |
| `/api/fn-summary` | ✅ M3-ω | function overview with hot blocks and callees |
| `/api/asm-tokens-for-pcs` | 🔜 M3 | BN-asm-tokens (BN sidecar M6) |
| `/api/call-tree` | ✅ M3-α | eager-built at AppState load; max_depth query rebuilds on override |
| `/api/call-chain` | ✅ M3-σ | LR walking caller chain |
| `/api/fork-events` | ✅ M3-ο | per-call fork lifecycle events with status filter |
| `/api/crypto-scan` | 🔜 M3 | |
| `/api/ollvm-detect-vm` | ✅ M3-ψ | OLLVM VM dispatcher heuristic |
| `/api/hash-finalize-detect`, `/api/hash-input-search` | 🔜 M3 | |
| `/api/auto-phase-detect` | 🔜 M3 | |
| `/api/diff-traces` | 🔜 M3 | |
| `/api/functions` | ✅ M2-ε | FunctionIndex prize; trace + symbol + auto sources; source-tagged entries |
| `/api/dec/summary` | ✅ M3-ι2c | trace-ir + symbol-source fallback + VM candidates wire/markdown shipped; m3_iota_parity.py HARD-gate green on real xsign trace (fns 0.978 / summary_md 0.943 / VM exact) |
| `/api/dec/fn/{id}` | ✅ M3-ι2c | trace:* + bare F0 + sym:* + legacy cfg:* supported via render_func_md (hot blocks full + warm stubs; asm/samples/exits). `bn:*` remains gated on Rust BN sidecar/backend (M6). |
| `/api/dec/llm-call` | ✅ M3-ι2d | trace:* / bare F0 / sym:* / cfg:* supported; calls claude/deepseek/qwen/mimo via reqwest; success-only cache; `bn:*` remains M6-gated |
| `/api/dec/models` | ✅ M3-ι2d | lists model aliases and configured server-side env keys |
| `/api/llil/render`, `/api/llil/llm` | 🔜 M5 | LLIL pipeline |
| `/api/hlil-for-pc`, `/api/hlil-for-fn` | 🔜 M6 | BN sidecar |
| `/api/bn-cfg-svg-for-pc`, `/api/bn-cfg-for-pc` | 🔜 M6 | BN sidecar |
| `/api/bg-status` | ❌ | Replaced by `/ws/jobs` WebSocket (D6) |
| `/api/decomp-status` | ❌ | Folded into `/ws/jobs` |
| `/ws/jobs` | 🔜 M3 | new WebSocket endpoint |
| `/openapi.json` | 🔜 M3 | utoipa-generated |

### 13.6 Frontend panels (current `webui/app.js` tabs)

| Panel | Position | Status | Note |
|---|---|---|---|
| Functions | left | ✅ M2-ε | source-tagged list, filter, select-to-cursor; consumes `/api/functions` |
| Backtrace | left | 🔜 M4 | |
| Call Tree | left | ✅ M3-α | Solid panel shipped; also right-bottom duplicate remains deferred |
| Forks | left | 🔜 M4 | |
| Strings | left | ✅ M2-ζ | Solid panel shipped |
| Taint | left | ✅ M3-γ | Solid toggles for through_mem / data_only / cross_fn_call |
| Cross Ref (xref) | left | 🔜 M4 | |
| SO Filter | left | ⏸ | Multi-SO trace filter; rare path |
| Settings | left | 🔜 M4 | |
| Graph (CFG) | right | ✅ M3-κ | SVG render via `/api/cfg-svg` |
| Registers | right | ✅ M4-α | selected-record register table |
| HLIL | right | 🔜 M6 | needs BN sidecar |
| Decompile | right | ✅ M3-ι2d (raw) / M5 (LLIL) | TraceIR summary + fn markdown + LLM-call API; richer frontend UX remains M4 |
| Memory | bottom | ✅ M4-α / 🔜 M4 | MemShadow hex dump + selected-record register shortcuts shipped; diff remains |
| Call Tree (bottom view) | bottom | ⏸ | Duplicate of left-panel Call Tree; consolidate to one |
| Navigation | bottom | ⏸ | Lightweight nav widget; rebuild post-cutover |
| Trace for PC | bottom | ✅ M4-α | PC execution history via `/api/idxs-for-pc` |

> **Note:** M1 added a placeholder `MetaPanel` (frontend/src/panels/meta/MetaPanel.tsx) as scaffolding to validate the end-to-end Vite/Solid/TS toolchain. It is not in the panel table above; it will be replaced by the proper layout in M4.

### 13.7 Tests + sidecars

| Item | Status | Note |
|---|---|---|
| Python `tests/test_*.py` (815 tests) | ⛔ → ❌ | Reference during M2-M6; deleted at M7 |
| `tests/conftest.py` (synth fixtures) | ⛔ → ❌ | Fixtures rewritten as Rust `tests/common/fixtures.rs` |
| `traces/debug_minimal/` real-trace fixture | ⛔ | Filesystem-only; reused as M0 perf baseline + cargo integration test |
| `.memshadow.v2.npz` sidecar | ✅ M3-λ | Replaced by Rust-native `trace.bin.memshadow.v3.bin`; old Python `.npz` sidecars are ignored/regenerable |
| `tools/hooks/*.json` JNI/suicide/type-anchor specs | ⛔ | Format frozen, parsed by both old + new |
| `examples/<so>/known_offsets.json` | ⛔ | Format frozen |
| `examples/llm_cookbook.py` | ❌ | Python SDK demo; deleted at M7 |
| `viewer/__init__.py` SDK Python re-exports | ❌ | M7 deletes; future Python access via PyO3 only on demand |
