# AGENTS.md

Repository instructions for Codex and other coding agents working in traceMiku.

## Project

traceMiku is an Android real-device ARM64 instruction-level trace toolchain.
The current runtime architecture is the Rust/Solid analysis v2 stack.

- `tracer/`: Frida device agents. Default is `agent_cmodule_v5.js` with
  CModule, SPSC ring, on-device file output, and gzip pull.
- `rust/crates/tracemiku-core/`: source of truth for mmap trace parsing,
  Capstone decode, FunctionIndex, CFG, taint, MemShadow, symbols, and LLIL /
  decompiler analysis.
- `rust/crates/tracemiku-server/`: axum API server, static Solid frontend
  serving, OpenAPI route list, WebSocket jobs, and BN sidecar bridge.
- `rust/crates/tracemiku-cli/`: Rust JSON CLI wrappers and filesystem-facing
  commands used by the top-level `./tracemiku` convenience wrapper.
- `frontend/`: Solid + Vite SPA. This is the only active UI.

Old Python `viewer/`, old FastAPI `webui/`, the Python TUI, and old
Python-vs-Rust parity scripts have been removed from the tracked v2 code path.
`tracemiku-view` is only a deprecated shim to `./tracemiku view`.

## Hard Rules

- Web is the only active UI. Do not reintroduce or extend deleted Python
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
  per-call directories use `calls/call_<idx>_tid<T>_<records>r_<ms>ms/`. Format
  changes need a meta version bump and migration path.
- `TODO.md` is the only backlog. Do not create parallel TODO lists in
  subdirectory READMEs.
- Frida agent changes must be memory-bounded. Read `docs/` and
  `tracer/README.md` before editing `tracer/agent_*.js`.

## Workflow Preferences

- Communicate in Chinese by default unless code, APIs, or commit style are
  clearer in English.
- User is a single-person prototype-phase owner; breaking changes are
  acceptable when they serve the current goal.
- Do not pause between completed milestones just to ask whether to continue.
  Stop only for real blockers, destructive actions that need confirmation,
  context pressure, or user interruption.
- `doneMeansMerged` semantics apply: done means PR-ready or a self-contained
  handoff, not merely a first stopping point.
- Long-running milestone work should commit to the current branch unless the
  user asks for a PR. Do not add "Generated with Claude Code",
  "Co-Authored-By: Claude", or similar footers.

## Git Safety

- Do not use `git reset --hard`, force push, branch deletion, or
  `git clean -fd*` unless the user explicitly asks and confirms.
- Do not use `--no-verify` or `--no-gpg-sign` unless the user explicitly asks.
- Prefer `git add` with explicit file paths. Avoid `git add -A` and
  `git add .`.
- If the worktree is dirty, preserve user changes and work around them.

## Common Commands

```bash
make fmt
make test-v2
make test-fast
make smoke-web RUN=traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms
make smoke-web RUN=<trace_dir> SMOKE_ARGS='--all-surfaces --timeout 300'
make smoke-ui BASE=http://127.0.0.1:18900 UI_SMOKE_ARGS='--browser chromium --executable /path/to/chrome'
make webui RUN=<trace_dir> PORT=18900

./tracemiku web <call_dir> --port 18900 --no-browser
./tracemiku web <call_dir> --so /path/to/libtarget.so --port 18900
./tracemiku list traces/run1 --json
./tracemiku info <call_dir> --json
./tracemiku query <call_dir> records --range 0..50 --regs x0,x1,sp
./tracemiku query <call_dir> forward-taint --from 0 --reg x0 --max 500
./tracemiku dec <call_dir> --summary
./tracemiku dec <call_dir> --fn trace:F0 --tier hot
```

The local Python environment is managed with `uv`; use `uv run python ...` for
Python helper scripts. Slow tests may require real traces, Binary Ninja,
browser automation, or a real adb device.

## Current Web Interaction Contracts

- `g` opens the jump command. `#N` / `N` jumps to trace index `N`; `0x...`
  jumps to the first executed record at that PC.
- ArrowUp/ArrowDown, PageUp/PageDown, Home, and End navigate records.
- Clicking a Functions row selects it, switches the right panel to CFG, and
  pauses CFG sync; double-clicking also jumps to the function entry's first
  trace execution when available.
- CFG sync follows the current cursor only when enabled. Manual function
  selection should remain visible while sync is paused.
- CFG `Ctrl+wheel` zoom must be anchored at the mouse cursor. Keep the
  Playwright smoke coverage for this behavior.
- Large trace CFGs may use representative overview SVGs. The UI/API must expose
  total, drawn, and hidden edge counts.
- BN HLIL/CFG may create a BN user function on demand when no static BN function
  contains the trace PC. Prefer trace function start as the creation address,
  with current PC as fallback.

## Code Map

- `tracemiku`: top-level Python convenience wrapper for trace/list/info/query/web/dec.
- `tracer/`: device-side Frida agents.
- `frontend/src/App.tsx`: Solid app shell and shared selected trace/function state.
- `frontend/src/api/client.ts`: typed API client and optional debug logging.
- `frontend/src/panels/`: Records, CFG, Registers, Memory, Taint, Xref, HLIL,
  Settings, and related panels.
- `frontend/src/utils/resourceGuards.ts`: guarded Solid resource helper for
  stale-frame protection.
- `rust/crates/tracemiku-core/src/trace/`: mmap trace parser and record model.
- `rust/crates/tracemiku-core/src/disasm/`: Capstone wrapper, def/use, mem op decode.
- `rust/crates/tracemiku-core/src/index.rs`: register and memory access indexes.
- `rust/crates/tracemiku-core/src/function_index.rs`: stable trace:/sym:/bn: function model.
- `rust/crates/tracemiku-core/src/cfg.rs`: trace CFG rebuild and graph metadata.
- `rust/crates/tracemiku-core/src/taint.rs`: forward/backward taint with dependency metadata.
- `rust/crates/tracemiku-core/src/memshadow.rs`: sparse byte-level memory shadow sidecar.
- `rust/crates/tracemiku-core/src/decompiler/` and `llil/`: IR markdown and in-house LLIL.
- `rust/crates/tracemiku-server/src/routes/`: JSON API route handlers.
- `rust/crates/tracemiku-cli/src/`: Rust CLI command implementations.
- `scripts/rust_web_smoke.py`: real server smoke/perf gate.
- `scripts/frontend_event_smoke.py`: Playwright browser event smoke for row
  clicks, keyboard navigation, context menus, resizing, memory selection, and
  CFG sync.
- `scripts/rust_cli_web_parity.py`: Rust CLI vs live Rust web API parity gate.
- `scripts/web_api_perf_probe.py`: large-trace API latency and runtime-blocking probe.
- `tools/hooks/`: JSON-driven specs.
- `examples/`: sample known offsets and current Rust CLI cookbook.
- `docs/`: design notes and migration history.

## API/Feature Propagation

New analysis should land in `tracemiku-core` first, then a Rust CLI command when
the analysis is useful outside the browser, then a server route with strict JSON
shape, then the Solid UI. Update `/openapi.json` route coverage tests when
adding or renaming endpoints.

For user-visible web behavior, run focused Rust tests plus `frontend` build and,
when possible, `scripts/rust_web_smoke.py` on a real large trace.

## Performance Rules

- API handlers that do CPU-heavy parsing, CFG, taint, MemShadow, BN, graphviz,
  decompile, search, or large memory work must run off Tokio reactor threads
  with `tokio::task::spawn_blocking` or an equivalent bounded worker path.
- Every server route file must be explicitly classified as heavy or light in
  `rust/crates/tracemiku-server/tests/api_infra_tests.rs`.
- Large API responses must have explicit caps and expose truncation metadata
  when users may confuse partial output with complete analysis.
- Frontend async updates that depend on selected trace/function state must guard
  stale frames by comparing current selection before applying returned data.
- Solid resources/memos returning object or array sources should preserve stable
  references when semantic values are unchanged. Virtual lists should key by
  trace identity or avoid fetch oscillation through structural snapping.
- Background warmers must be bounded and should not silently build unbounded
  indexes.

## Decompile Routes

Both decompile routes are active, but web decompile/LLM UI can be hidden while
latency work is in progress.

- IR markdown + optional LLM: Rust `tracemiku-core::decompiler` plus server
  `/api/dec/*` routes.
- LLIL: Rust `tracemiku-core::llil` plus `/api/llil/*` routes. This path does
  not depend on an LLM.

Do not merge or delete either route without an explicit project decision.

## Device Notes

The usual development device may already be connected with adb, root, and
Frida. For long interactive sessions, keep the device usable and battery-safe:
prevent auto-lock when app interaction is needed, and turn the screen off again
when done. Avoid repeated heavy UI operations that keep the app/device hot
unless actively tracing or debugging.
