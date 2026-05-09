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
- Records can show Taint results as a live overlay, either highlighting hits or
  dimming non-hit rows while preserving virtual-scroll layout.
- Records support trace-local row marks from the context menu: color, note,
  strike-through, and dim states persist in browser local storage per trace
  path without changing trace files.
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

The CLI is also the main LLM-friendly surface for trace analysis. It exposes
typed JSON commands for web API routes plus higher-level provenance tools:

```bash
./tracemiku api <call_dir> /api/backtrace -p idx=443 -p limit=64
rust/target/debug/tracemiku-cli output-map <call_dir> --key x-sign --summary --semantic-writer-map
rust/target/debug/tracemiku-cli output-backtrace <call_dir> --key x-sign
rust/target/debug/tracemiku-cli jni-output-strings <call_dir> --key x-umt
rust/target/debug/tracemiku-cli byte-lineage <call_dir> --addr 0x1234 --before-idx 1000 --compact
rust/target/debug/tracemiku-cli byte-lineage <call_dir> --addr 0x1234 --before-idx 1000 --count 32 --compact
rust/target/debug/tracemiku-cli vm-ops <call_dir> --start 1000 --end 1400 --summary
rust/target/debug/tracemiku-cli vm-ops <call_dir> --start 1000 --end 1400 --replay-plan
```

Recent AI-analysis additions include:

- output-driven workflows from JNI strings or known bytes back to memory
  writers, Base64 groups, semantic byte formulas, and VM backchains;
- batched `byte-lineage --count` with compact `frontier_groups`, step stats,
  repeated-value summaries, stable pointer loop hints, call-return boundaries,
  syscall-return boundaries, and bytecode-read frontiers;
- generic VM dynamic-trace helpers (`vm-slice`, `vm-ops`, `vm-backstep`,
  `vm-backchain`, `vm-backtree`) with configurable role registers instead of
  target-specific assumptions;
- replay-plan export and verification through
  `tools/vm_replay_plan_eval.py --emit-python` and
  `--verify-emitted-python`, so an AI agent can turn observed VM effects into
  editable Python scaffolding before replacing trace fallbacks with proven
  parameters;
- memory/JNI helpers such as `find-mem-pattern`, `byte-writer-map`,
  `mem-dump`, `mem-writes-in-range`, `jni-output-strings`, and
  `scan-jni-output-strings`.
- `crypto-scan` covers common crypto/hash magic constants beyond IVs, including
  MD5/SHA round constants, AES/SM3/SM4 tables, CRC32C, FNV, Murmur3, xxHash,
  Poly1305, ChaCha20, and RC4 identity-table markers.

The current `libsgmainso`/`x-sign` reconstruction is tracked as an example, not
as hardcoded tool behavior. The partial simulator in
`examples/libsgmainso/xsign_partial_sim.py` now reproduces the current
call_001 trace model and emits `completion_audit.goal_complete == false` until
the remaining VM bytecode/table frontiers are lifted into portable inputs. The
latest trace evidence also classifies `x-umt` as a companion output over the
same scratch payload stream, rather than as a separate magic secret.
See `docs/ai-cli-xsign-workflow.md` and `docs/xsign-reconstruction-progress.md`
for the detailed workflow and proof log.

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
- `docs/ai-cli-xsign-workflow.md`: target-agnostic AI workflow for using CLI
  provenance, VM, memory, JNI, and output-mapping commands.
- `docs/xsign-reconstruction-progress.md`: target-specific example progress
  report for the current `libsgmainso` trace corpus.
- `docs/android-analysis-frontier-report.md`: Android analysis pain points,
  product/UI direction, and current bug triage.
- `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`:
  historical Rust/Solid cutover design and parity map.

## Trace Format

`trace.bin` records are 272 bytes. Per-call directories use:

```text
calls/call_<idx>_tid<T>_<records>r_<ms>ms/
```

Format changes require an explicit meta version bump and migration path.
