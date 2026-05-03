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

LLM-side `viewer/decompiler/llm_*.py` (prompt builder, model adapters) gets ported to Rust in M3 (just async `reqwest` calls + JSON serde). LLIL renderer (M5) is the only piece of `viewer/decompiler/` that's algorithmically complex.

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
| `disasm.py` (capstone wrapper, decode, def/use) | `tracemiku-core::disasm` | 🔜 M2 | capstone-rs |
| `index.py` (def-use chains, mem ops) | `tracemiku-core::index` | 🔜 M2 | rayon-parallel build |
| `cfg.py` (build_cfg, CFG, Block, Tarjan SCC) | `tracemiku-core::cfg` | 🔜 M2 | petgraph |
| `cfg.py::write_dot` / `textual_summary` | n/a | ❌ | TUI legacy, dropped |
| `taint.py` (forward/backward, --through-mem) | `tracemiku-core::taint` | 🔜 M2 | rayon-parallel |
| `taint.py` (`--cross-fn-call` frame_depth annotation) | `tracemiku-core::taint` | 🔜 M2 | ~50 LOC: O(n) walk classifying bl/ret depth + Option<u32> field on each hit. Not the same as semantic cross-fn taint (see below) |
| (future) **semantic cross-fn taint propagation** (ABI arg tracking, caller-saved kill, callee→caller return flow) | `tracemiku-core::taint::cross_fn` | ⏸ | Brand-new feature; needs its own design. Python never implemented this; the Python TODO note "全量 propagation 待真机" referred to *this*, not to frame_depth annotation. Do after v2 cutover and after real-trace need is documented. |
| `memshadow.py` (sparse byte map + .npz sidecar) | `tracemiku-core::memshadow` | 🔜 M2 | bumped to `.memshadow.v3.bin` (D10) |
| `symbols.py` (SymbolMap, ModuleResolver, build_from_trace) | `tracemiku-core::symbols` | 🔜 M2 | |
| `symbols.py::load_ida_symbols` | `tracemiku-core::symbols` | ⏸ | IDA JSON import; rare path |
| `symbols.py::auto_known_offsets` | `tracemiku-core::symbols` | 🔜 M2 | reads per-call meta.json `known_offsets` |
| `display.py` (pwndbg-style annotations) | frontend rendering | 🔜 M4 | moves to TS frontend; backend just emits structured tokens |
| `function_index.py` (FunctionIndex, FunctionEntry, parse_id) | `tracemiku-core::function_index` | 🔜 M2 | direct port; legacy `F0` / `cfg:` parser kept |
| `calltree.py` (build_call_tree, bl/ret pair-walking) | `tracemiku-core::calltree` | 🔜 M2 | |
| `hashfin.py` (hash-finalize-detect) | `tracemiku-core::hashfin` | 🔜 M3 | window-based scan |
| `ollvmdet.py` (ollvm-detect-vm heuristic) | `tracemiku-core::ollvmdet` | 🔜 M3 | confidence-scored, no decode |
| `app.py` (TUI) | n/a | ❌ | Frozen long ago, deleted at M7 |
| `__main__.py` (Python CLI, ~31 subcommands) | `tracemiku-cli` (Rust bin) | 🔜 M3 | clap-based dispatcher |
| `__init__.py` (Python SDK re-exports) | n/a | ❌ | M7 deletes; PyO3 binding only if future need |

### 13.3 viewer/decompiler/ modules

| Python module | v2 home | Status | Note |
|---|---|---|---|
| `backend.py` (FieldHint, Function, Variable dataclasses) | `tracemiku-core::decompiler::backend` | 🔜 M2 | |
| `backends/binja.py` | BN python sidecar | 🔜 M6 | reused via JSON-RPC |
| `backends/{ghidra,ida,r2}.py` | n/a | ❌ | Stub-only today; never wired up |
| `backends/none.py` | `tracemiku-core::decompiler::backend` | 🔜 M2 | trivial null backend |
| `builder.py` (build_trace_ir, render_summary_md, render_func_md) | `tracemiku-core::decompiler::builder` | 🔜 M3 | TraceIR construction |
| `llm_client.py` (claude/deepseek/qwen/mimo) | `tracemiku-server::llm` | 🔜 M3 | reqwest + serde JSON |
| `llm_bundle.py` (build_fn_decompile_prompt) | `tracemiku-core::decompiler::prompt` | 🔜 M3 | prompt + truncation logic |
| `type_anchor.py` (JSON-spec → typed pointer hints) | `tracemiku-core::decompiler::type_anchor` | 🔜 M3 | reads `tools/hooks/*.json` |
| `vm_candidate.py` (OLLVM VM detection) | `tracemiku-core::decompiler::vm_candidate` | 🔜 M3 | |
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
| `stats` | 🔜 M3 | trace metadata JSON |
| `records` | 🔜 M3 | window dump |
| `search-pc`, `idxs-for-pc` | 🔜 M3 | PC search |
| `search-asm` | 🔜 M3 | mnemonic substring search |
| `taint-fwd`, `taint-bwd` | 🔜 M3 | rayon-parallel |
| `data-chase` | 🔜 M3 | follow data flow |
| `so-stats` | 🔜 M3 | per-SO record counts |
| `last-write-of-addr` | 🔜 M3 | |
| `find-mem-pattern` | 🔜 M3 | |
| `mem-writes-in-range`, `mem-flow` | 🔜 M3 | |
| `crypto-scan` | 🔜 M3 | 22 standard primitives |
| `reg-at-idx` | 🔜 M3 | |
| `call-chain` | 🔜 M3 | |
| `hash-input-search` | 🔜 M3 | |
| `diff-traces` | 🔜 M3 | |
| `fork-events` | 🔜 M3 | reads agent fork_events |
| `ollvm-detect-vm` | 🔜 M3 | |
| `hash-finalize-detect` | 🔜 M3 | |
| `auto-phase-detect` | 🔜 M3 | |
| `jni-calls`, `jobj-history`, `jni-strings` | 🔜 M3 | reads jni_hooks.jsonl |
| `mem-dump` | 🔜 M3 | |
| `reg-timeline` | 🔜 M3 | |
| `mem-diff` | 🔜 M3 | |
| `fn-summary` | 🔜 M3 | |
| `field-at` | 🔜 M3 | |
| `export` (CSV/JSON dump) | ⏸ | Power-user; defer |
| `dec` (LLM-assisted decompile, route B) | 🔜 M5 | uses llm_client |
| `dec-bench` (multi-model benchmark) | ⏸ | Defer until base `dec` parity holds |
| `view` (web subcommand wrapper) | 🔜 M7 | dispatcher to `tracemiku-server` |
| `query` (ad-hoc Python eval) | ❌ | Replaced by `tracemiku-cli` typed subcommands |
| `info` (per-call dir summary) | 🔜 M3 | |
| `list` (list calls in trace dir) | 🔜 M3 | |

### 13.5 REST API endpoints

All listed in §5 plus this exhaustive map of every endpoint currently in `webui/server.py`:

| Endpoint | Status | Note |
|---|---|---|
| `/api/meta` | ✅ M1 | first end-to-end milestone — landed 2026-05-03 |
| `/api/records?from=&to=` | 🔜 M3 | |
| `/api/record/{idx}` | 🔜 M3 | |
| `/api/so-stats` | 🔜 M3 | |
| `/api/cfg?fn=` | 🔜 M3 | |
| `/api/cfg-svg` | 🔜 M3 | graphviz-rust |
| `/api/block?pc=` | 🔜 M3 | |
| `/api/block-for-pc` | 🔜 M3 | |
| `/api/loops` | 🔜 M3 | |
| `/api/backtrace` | 🔜 M3 | |
| `/api/idxs-for-pc` | 🔜 M3 | |
| `/api/idxs-for-block` | 🔜 M3 | |
| `/api/idxs-touching-addr` | 🔜 M3 | |
| `/api/idxs-touching-range` | 🔜 M3 | |
| `/api/search` | 🔜 M3 | |
| `/api/forward-taint` | 🔜 M3 | |
| `/api/backward-taint` | 🔜 M3 | |
| `/api/strings` | 🔜 M3 | needs MemShadow ready |
| `/api/string-provenance` | 🔜 M3 | |
| `/api/mem-dump` | 🔜 M3 | |
| `/api/last-write-of-reg`, `/api/last-write-of-addr` | 🔜 M3 | |
| `/api/reg-value-at`, `/api/reg-at-idx` | 🔜 M3 | |
| `/api/data-chase` | 🔜 M3 | |
| `/api/find-mem-pattern` | 🔜 M3 | |
| `/api/mem-writes-in-range`, `/api/mem-flow` | 🔜 M3 | |
| `/api/mem-diff` | 🔜 M3 | |
| `/api/reg-timeline` | 🔜 M3 | |
| `/api/jni-calls`, `/api/jobj-history`, `/api/jni-strings`, `/api/jni-events` | 🔜 M3 | reads jni_hooks.jsonl |
| `/api/field-at` | 🔜 M3 | |
| `/api/fn-summary` | 🔜 M3 | |
| `/api/asm-tokens-for-pcs` | 🔜 M3 | BN-asm-tokens (BN sidecar M6) |
| `/api/call-tree` | 🔜 M3 | |
| `/api/call-chain` | 🔜 M3 | |
| `/api/fork-events` | 🔜 M3 | |
| `/api/crypto-scan` | 🔜 M3 | |
| `/api/ollvm-detect-vm` | 🔜 M3 | |
| `/api/hash-finalize-detect`, `/api/hash-input-search` | 🔜 M3 | |
| `/api/auto-phase-detect` | 🔜 M3 | |
| `/api/diff-traces` | 🔜 M3 | |
| `/api/functions` | 🔜 M3 | the FunctionIndex prize |
| `/api/dec/summary`, `/api/dec/fn/{id}` | 🔜 M3 | TraceIR markdown |
| `/api/dec/llm-call` | 🔜 M3 | |
| `/api/dec/models` | ⏸ | Just lists configured LLM keys; UI nicety |
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
| Functions | left | 🔜 M4 | consumes `/api/functions` |
| Backtrace | left | 🔜 M4 | |
| Call Tree | left | 🔜 M4 | also right-bottom (current dual location collapses to one) |
| Forks | left | 🔜 M4 | |
| Strings | left | 🔜 M4 | |
| Taint | left | 🔜 M4 | |
| Cross Ref (xref) | left | 🔜 M4 | |
| SO Filter | left | ⏸ | Multi-SO trace filter; rare path |
| Settings | left | 🔜 M4 | |
| Graph (CFG) | right | 🔜 M4 | SVG render |
| Registers | right | 🔜 M4 | with smart deref |
| HLIL | right | 🔜 M6 | needs BN sidecar |
| Decompile | right | 🔜 M4 (raw) / M5 (LLIL) | TraceIR + LLM in M4; LLIL pipeline in M5 |
| Memory | bottom | 🔜 M4 | hex dump + diff |
| Call Tree (bottom view) | bottom | ⏸ | Duplicate of left-panel Call Tree; consolidate to one |
| Navigation | bottom | ⏸ | Lightweight nav widget; rebuild post-cutover |
| Trace for PC | bottom | 🔜 M4 | PC execution history |

> **Note:** M1 added a placeholder `MetaPanel` (frontend/src/panels/meta/MetaPanel.tsx) as scaffolding to validate the end-to-end Vite/Solid/TS toolchain. It is not in the panel table above; it will be replaced by the proper layout in M4.

### 13.7 Tests + sidecars

| Item | Status | Note |
|---|---|---|
| Python `tests/test_*.py` (815 tests) | ⛔ → ❌ | Reference during M2-M6; deleted at M7 |
| `tests/conftest.py` (synth fixtures) | ⛔ → ❌ | Fixtures rewritten as Rust `tests/common/fixtures.rs` |
| `traces/debug_minimal/` real-trace fixture | ⛔ | Filesystem-only; reused as M0 perf baseline + cargo integration test |
| `.memshadow.v2.npz` sidecar | ❌ | Bumped to `.memshadow.v3.bin` (Rust-native binary) |
| `tools/hooks/*.json` JNI/suicide/type-anchor specs | ⛔ | Format frozen, parsed by both old + new |
| `examples/<so>/known_offsets.json` | ⛔ | Format frozen |
| `examples/llm_cookbook.py` | ❌ | Python SDK demo; deleted at M7 |
| `viewer/__init__.py` SDK Python re-exports | ❌ | M7 deletes; future Python access via PyO3 only on demand |
