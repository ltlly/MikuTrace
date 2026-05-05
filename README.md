# traceMiku

traceMiku is an Android real-device ARM64 instruction-level trace toolchain.

The analysis v2 cutover is complete: Python `viewer/`, the old FastAPI `webui/`,
and the old pytest parity suite have been removed. Runtime analysis now lives in
Rust crates plus the Solid frontend.

## Layout

```text
tracer/                         Frida device agents
frontend/                       Solid + Vite SPA
rust/crates/tracemiku-core/     trace parser, disasm, CFG, taint, MemShadow, LLIL
rust/crates/tracemiku-server/   axum API server, static frontend, BN sidecar bridge
rust/crates/tracemiku-cli/      Rust JSON CLI wrappers and filesystem commands
tools/hooks/                    JSON hook/type specs
examples/                       sample target metadata/specs
docs/                           design notes and parity history
```

`./tracemiku` remains the top-level convenience wrapper:

```bash
./tracemiku trace --pkg com.example.app --so libtarget.so --method nativeFn --out traces/run1
./tracemiku list traces/run1 --json
./tracemiku info traces/run1/calls/call_001_tid1_100r_1ms --json
./tracemiku web traces/run1/calls/call_001_tid1_100r_1ms --port 18900
./tracemiku view traces/run1/calls/call_001_tid1_100r_1ms
```

`web` and `view` both start the Rust v2 server and serve `frontend/dist`.
For BN-backed HLIL, pass the target SO:

```bash
./tracemiku web <call_dir> --so /path/to/libtarget.so
```

The wrapper maps `--so` to `TRACEMIKU_BN_SO`. The BN sidecar command defaults to
`tracemiku-bn-sidecar` and can be overridden with `TRACEMIKU_BN_SIDECAR`.

## Current Web UI

The Solid UI is the primary workflow surface:

- Records are virtualized, keyboard-navigable, and keep stable row identity
  during range refetches.
- `g` opens the jump command: `#240` or `240` jumps to a trace index, and
  `0x...` jumps to the first executed record at that PC.
- The CFG panel follows cursor changes when sync is enabled. Manual function
  selection from the Functions tab switches to CFG and pauses sync so the
  selected function is not immediately overwritten by the current cursor.
- Large trace CFGs use a representative overview when Graphviz dot rendering
  would be too expensive. The API reports drawn and hidden edge counts so the
  overview cannot be mistaken for a full graph.
- CFG pan/zoom is interactive; `Ctrl+wheel` zooms around the mouse cursor.
- BN-backed HLIL/Pseudo C follows the current trace PC. If BN has no function
  containing a trace PC, the sidecar can create a user function at the trace
  symbol entry or current PC, then retry HLIL/CFG.

## Rust CLI

The Rust CLI can be run directly during development:

```bash
cd rust
cargo run -p tracemiku-cli -- info <call_dir> --json
cargo run -p tracemiku-cli -- records <call_dir> --start 0 --count 50
cargo run -p tracemiku-cli -- functions <call_dir>
cargo run -p tracemiku-cli -- dec-summary <call_dir>
cargo run -p tracemiku-cli -- dec-fn <call_dir> trace:F0 --tier hot
```

## Development

```bash
make fmt
make test-v2
make smoke-web RUN=traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms SMOKE_ARGS='--all-surfaces'
make smoke-ui BASE=http://127.0.0.1:18900 UI_SMOKE_ARGS='--browser chromium --executable /path/to/chrome'
```

`make test-v2` runs the Python wrapper syntax check, Rust fmt check, Rust
core/server/CLI tests, and the Solid frontend production build.
`make smoke-web` runs the live Rust server API/perf gate. `make smoke-ui` runs
the Playwright browser event smoke against an already running web server.

The Rust server serves API routes under `/api/*`, `/openapi.json`, `/ws/jobs`,
and falls back to the built SPA in `frontend/dist`.

## Documentation

Current source-of-truth docs are:

- `README.md`: user-facing quick start and current UI behavior.
- `AGENTS.md` / `CLAUDE.md`: repository-local agent rules and workflow.
- `TODO.md`: the only active backlog. Completed implementation plans are not
  kept as live TODOs.
- `REFERENCES.md`: external algorithm/tool references and current test gates.
- `docs/PER_CALL_TRACE_DESIGN.md`: current per-call trace layout and record
  contract.
- `docs/trace-decompiler-design.md`: current decompiler/BN/HLIL route design.
- `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`:
  historical Rust/Solid cutover design and parity map.

## Trace Format

`trace.bin` records are 272 bytes. Per-call directories use:

```text
calls/call_<idx>_tid<T>_<records>r_<ms>ms/
```

Format changes require an explicit meta version bump and migration path.
