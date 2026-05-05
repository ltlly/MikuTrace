# CLAUDE.md

This file gives Claude Code repository-local guidance for traceMiku. The current
runtime architecture is the Rust/Solid analysis v2 stack; old Python `viewer/`,
old FastAPI `webui/`, and the old pytest parity suite have been removed.

## Project

traceMiku is an Android real-device ARM64 instruction-level trace toolchain.

Current layers:

1. `tracer/`: Frida device agents. `agent_cmodule_v5.js` is the default path
   with CModule, SPSC ring, on-device file output, and gzip pull.
2. `rust/crates/tracemiku-core/`: source of truth for trace parsing, disasm,
   FunctionIndex, CFG, taint, MemShadow, symbols, and LLIL/decompiler analysis.
3. `rust/crates/tracemiku-server/`: axum API server, static Solid frontend
   serving, OpenAPI route list, WebSocket jobs, and BN sidecar bridge.
4. `rust/crates/tracemiku-cli/`: Rust JSON CLI wrappers and filesystem-facing
   commands used by the top-level `./tracemiku` convenience wrapper.
5. `frontend/`: Solid + Vite SPA. This is the only active UI.

`./tracemiku` remains the top-level entry point for trace/list/info/web/view.
`tracemiku web` and `tracemiku view` start the Rust server and serve
`frontend/dist`.

## Hard Rules

- Web is the only active UI. Do not reintroduce or extend the deleted Python
  TUI/FastAPI paths.
- Do not add a traceMiku MCP server or project MCP wrappers. LLM-friendly
  surfaces are Rust CLI JSON output, REST `/openapi.json`, and documented API
  routes.
- End-to-end pipeline changes must be verified across the full link:
  agent, host, `meta.json`, Rust core, Rust server, and display.
- The project goal is the tool, not a single SO target. Do not hardcode Taobao,
  xsign, `libsgmainso`, offsets, or anti-debug specifics into core code. Put
  target-specific data in JSON specs under `tools/hooks/` or
  `examples/<so>/known_offsets.json`.
- Trace formats are stable contracts. `trace.bin` records are 272 bytes;
  per-call directories use `calls/<idx>_tid<T>_<records>r_<ms>ms/`. Format
  changes need a meta version bump and migration path.
- `TODO.md` is the only backlog. Do not create parallel TODO lists in
  subdirectory READMEs.
- Frida agent changes must be memory-bounded. Read `docs/` and
  `tracer/README.md` before editing `tracer/agent_*.js`.

## Performance Rules

- API handlers that do CPU-heavy parsing, CFG, taint, MemShadow, BN, graphviz,
  decompile, or large search work must run off Tokio reactor threads with
  `tokio::task::spawn_blocking` or an equivalent bounded worker path.
- Large API responses must have explicit caps and expose truncation metadata
  when users may confuse partial output with complete analysis.
- Frontend async updates that depend on selected trace/function state must guard
  stale frames by comparing the current selection before applying returned data.
- Solid resources/memos returning object or array sources should preserve stable
  references when semantic values are unchanged. Virtual lists should key by
  trace identity or avoid fetch oscillation through structural snapping.
- Prefer cache warmers only for bounded, interactive paths. Background warmers
  must have a clear disable switch and should not silently build unbounded
  indexes.

## Common Commands

```bash
# Full v2 validation
make test-v2

# Individual validation
cd rust && cargo fmt --check
cd rust && cargo test -p tracemiku-core
cd rust && cargo test -p tracemiku-server
cd rust && cargo test -p tracemiku-cli
cd frontend && npm run build

# Focused server/API guard tests
cargo test --manifest-path rust/Cargo.toml -p tracemiku-server --test api_infra_tests
cargo test --manifest-path rust/Cargo.toml -p tracemiku-server --test test_taint_routes

# Rust web smoke/perf gate on a real call directory
uv run python scripts/rust_web_smoke.py <call_dir> --timeout 180
uv run python scripts/web_api_perf_probe.py http://127.0.0.1:18900 --visible-ui-only

# Run the web UI
./tracemiku web <call_dir> --port 18900
./tracemiku web <call_dir> --so /path/to/libtarget.so --port 18900
```

The local Python environment is managed with `uv`; use `uv run python ...` for
Python helper scripts.

## Code Map

```text
tracemiku                         top-level Python convenience wrapper
tracer/                           device-side Frida agents
frontend/
  src/App.tsx                     Solid app shell and shared selection state
  src/api/client.ts               typed API client and optional debug logging
  src/panels/                     Records, CFG, Registers, Memory, Taint, Xref...
  src/styles/                     global app/panel styling
rust/crates/tracemiku-core/src/
  trace/                          mmap trace parser and metadata
  disasm/                         Capstone wrapper, def/use, mem operand decode
  index.rs                        register and memory indexes
  function_index.rs               stable trace:/sym:/bn: function model
  cfg.rs                          trace CFG rebuild and graph metadata
  taint.rs                        forward/backward taint with dependency metadata
  memshadow.rs                    sparse byte-level memory shadow sidecar
  symbols.rs                      PC to module/function resolution
  decompiler/ and llil/           IR markdown and in-house LLIL routes
rust/crates/tracemiku-server/src/
  main.rs                         axum app, static frontend, cache headers
  state.rs                        shared TraceState and warmers
  routes/                         JSON API route handlers
  bn_sidecar.rs                   BN process bridge
rust/crates/tracemiku-cli/src/    Rust CLI command implementations
scripts/                          parity/smoke/perf helper scripts
docs/                             design notes and migration history
```

## API/Feature Propagation

New analysis should land in `tracemiku-core` first, then a Rust CLI command when
the analysis is useful outside the browser, then a server route with strict JSON
shape, then the Solid UI. Update `/openapi.json` route coverage tests when adding
or renaming endpoints.

When changing shared analysis behavior, run focused Rust unit tests plus any
route tests for the affected surface. For user-visible web behavior, also run
`npm run build` and, when possible, `scripts/rust_web_smoke.py` on a real trace.

## Decompile Routes

Both decompile routes are active but the web decompile/LLM UI can be hidden while
latency work is in progress.

- IR markdown + optional LLM: Rust `tracemiku-core::decompiler` plus server
  `/api/dec/*` routes.
- LLIL: Rust `tracemiku-core::llil` plus `/api/llil/*` routes. This path does
  not depend on an LLM.

Do not merge or delete either route without an explicit project decision.

## Device Notes

The usual development device may already be connected with adb, root, and Frida.
For long interactive sessions, keep the device usable and battery-safe: prevent
auto-lock when you need app interaction, and turn the screen off again when you
are done. Avoid repeated heavy UI operations that keep the app/device hot unless
you are actively tracing or debugging.

## Current Hardening Focus

Recent Rust/Solid work is mainly latency and responsiveness hardening, not new
feature expansion. Before adding broad UI features, check for the recurring
classes already seen in this branch:

- blocking CPU work on async runtime threads;
- unbounded or misleadingly truncated responses;
- stale async frames applying to a newer selected record/function;
- Solid list/resource churn from unstable object identity;
- expensive CFG/decompile/BN work triggered by fast cursor movement;
- UI controls without overflow, resize, scrollbar, or keyboard interaction
  parity.

Prefer turning each class into a test or smoke gate when fixing it.
