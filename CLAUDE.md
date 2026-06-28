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
  terminal/FastAPI paths.
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

# Device integration test (cross-compile + push + trace + verify)
make test-device

# Lightweight export profiling (no Stalker, no trace.bin)
./tracemiku probe --pkg com.example.app --so libtarget.so --duration 10

# Run the web UI
./tracemiku web <call_dir> --port 18900
./tracemiku web <call_dir> --so /path/to/libtarget.so --port 18900
```

The local Python environment is managed with `uv`; use `uv run python ...` for
Python helper scripts.

## AI Agent Quick Start

When operating as an AI agent, follow this sequence:

1. `cd /Users/ltlly/Code/MikuTrace` (the project root)
2. `./tracemiku --help` — get all subcommands
3. `./tracemiku <subcmd> --help` — get exact parameters for any subcommand
4. **Always prefer dedicated CLI subcommands** over `tracemiku api`. The CLI has
   90+ subcommands covering nearly all analysis; run `./tracemiku --help` and the
   Rust binary `--help` to discover them.
5. Use `./tracemiku doctor --pkg <pkg>` before real-device tracing

### Runtime-truth commands — keyed on the `(SO, offset)` coordinate

These answer what static tools (IDA/BN/Ghidra) structurally cannot, and accept
the same `(SO, static-offset)` coordinate you read in any disassembler (or an
absolute PC). Addresses/offsets are **HEX by default** (`10` = `0x10`); prefix
with `d` to force decimal (`d16` = 16). Strategy:
`docs/competitive/ai-cli-strategy-2026-06-27.md`.

```bash
# (SO,offset) <-> PC, with runtime facts (exec_count, in_module, executed)
./tracemiku query <call_dir> resolve --addr 0x6f4dc74a30
./tracemiku query <call_dir> resolve --so libfoo --off 0x6a30

# where a br/blr actually jumped + hit counts (the obfuscation wall)
./tracemiku query <call_dir> indirect-targets --so libfoo --off 0x7e4c
./tracemiku query <call_dir> indirect-targets          # list every indirect source

# export runtime-DECRYPTED bytes (packers/VMP); --out writes raw for loadfile
./tracemiku query <call_dir> mem-export --so libfoo --off 0x1000 --len 0x200 --out dec.bin

# register value(s) at an offset: per-hit + distinct-value distribution
./tracemiku query <call_dir> reg-at --reg x0 --so libfoo --off 0x7e4c

# executed-path coverage + branch-direction collapse (one_sided = dead branch)
./tracemiku query <call_dir> coverage --fn sub_7f10
./tracemiku query <call_dir> coverage --so libfoo --off 0x7e4c

# lineage seeded by (SO,offset): --so/--off/--occurrence on these too
./tracemiku query <call_dir> backward-taint --so libfoo --off 0x7f1c --reg x16
# (Rust binary also: bfs-slice / forward-dep-tree accept --so/--off/--occurrence)
```

### CLI vs `tracemiku api` — When to Use Which

**Always prefer dedicated CLI subcommands.** They are faster, more ergonomic,
and many are multi-step orchestration commands that would require dozens of
sequential `api` calls to replicate:

- `./tracemiku query <call_dir> <sub> ...` — common query patterns (records,
  search, forward-taint, backward-taint, etc.)
- `./tracemiku list`, `info`, `stats` — filesystem operations, no router needed
- `./tracemiku dec <call_dir> --summary` — decompile overview
- Rust CLI subcommands like `output-backtrace`, `output-map`, `vm-ops`,
  `byte-lineage`, `vm-backchain` — multi-API orchestration with summary output

**Only use `tracemiku api` as a last resort** when no dedicated CLI subcommand
exists for the route you need. Currently only 3 callable routes lack a CLI
wrapper: `/api/analysis-index`, `/api/dec/llm-call`, `/api/llil/llm`.

```bash
# GOOD — use dedicated subcommands:
./tracemiku query <call_dir> records --range 0..50 --regs x0,x1,sp
./tracemiku query <call_dir> forward-taint --from 0 --reg x0 --max 500
./tracemiku list traces/run1 --json
./tracemiku info <call_dir> --json
./tracemiku dec <call_dir> --summary

# Rust CLI subcommands (run the binary directly via the wrapper):
./tracemiku query <call_dir> backtrace --idx 100
./tracemiku query <call_dir> mem-dump --addr 0x... --size 256
./tracemiku query <call_dir> functions
./tracemiku query <call_dir> cfg --fn trace:F0
./tracemiku query <call_dir> strings

# BAD — do NOT use api when a CLI subcommand exists:
./tracemiku api <call_dir> /api/backtrace -p idx=100      # use query backtrace
./tracemiku api <call_dir> /api/functions                  # use query functions
./tracemiku api <call_dir> /api/forward-taint -p from=0 -p reg=x0  # use query forward-taint

# OK — api is acceptable when no CLI subcommand exists:
./tracemiku api <call_dir> /api/analysis-index
```

### Key Rules for AI Agents

- **Never start `tracemiku web` just to curl it** — use CLI subcommands
  directly. The web server is for human interactive use only.
- **`./tracemiku` is the canonical entry** — do not invoke `tracemiku-cli` Rust
  binary directly; the Python wrapper handles binary resolution.
- **All CLI output is JSON** — pipe-safe for most commands without `--json`.
- **MemShadow is partial** — only bytes actually accessed during the traced
  execution are tracked. `None` bytes mean "never observed during this trace",
  not "memory is zero". Check the `completeness` field in mem-dump responses;
  if <0.7, the data may be insufficient for emulation. Each byte carries a
  provenance `kind`: `w` (traced store), `r` (traced load), `x` (external/
  syscall/boundary-diff write), `i` (initial memory snapshot, see below), `??`
  (never observed). Trust `w`/`x`/`i` as ground truth; `??` is a real frontier.
- **Initial memory snapshot (`--snapshot-mem`)** — captures real device memory
  at trace start (t=0) into `memory_snapshot.bin`, used by MemShadow as the `i`
  fallback layer. This recovers data initialized BEFORE the trace window opened
  (decrypted VM bytecode tables, `.rodata` constants, embedded keys) that pure
  instruction tracing cannot see. Use it when a trace shows
  `observed_read_without_matching_traced_write` frontiers on pre-trace data.
  See `docs/memory-completeness-design.md` for the layered-oracle design.
- **Real-device trace pre-checks** — run `./tracemiku doctor --pkg <pkg>` before
  tracing to verify frida/SELinux/device state in one pass.
- **Do not set `--max-records`** unless you specifically want a truncated trace.
  The default captures the full function execution.
- **For batch record queries**, use `--indices 0,5,10,100` instead of looping
  individual subprocess calls.

### Common Pitfalls

- `tracemiku web` may compile Rust on first run — compilation output goes to
  stderr but don't pipe its stdout to JSON parsers during startup.
- `query search` accepts both `--pattern "bl"` and positional `"bl"` — both work.
- If `tracemiku api` fails with "No such file", check you're passing a per-call
  directory (e.g. `traces/run1/calls/call_0_tid123_500r_10ms/`), not the run root.

## Current Web Interaction Contracts

- Global jump command: `g` opens the command bar. `#N` / `N` jumps to trace
  index `N`; `0x...` resolves the first executed record at that PC.
- Records keyboard navigation: ArrowUp/ArrowDown, PageUp/PageDown, Home, End.
- Functions tab: click selects a function, switches the right pane to CFG, and
  pauses CFG sync; double-click also jumps to the function entry's first trace
  execution when present.
- CFG: sync follows the current cursor when enabled; manual function selection
  should not be overwritten while sync is paused. `Ctrl+wheel` zooms around the
  mouse cursor, not around the SVG origin.
- Large CFGs: `/api/cfg-svg` may return `status=large` with a lightweight
  representative overview. Surface `edge_count`, `drawn_edge_count`, and
  `hidden_edge_count` anywhere the overview is shown.
- BN HLIL/CFG sidecar: when no BN function contains a trace PC, pass the trace
  function start when available and allow the sidecar to create a BN user
  function before retrying. Surface `created_function` in the UI for clarity.

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
  memshadow.rs                    sparse byte-level memory shadow sidecar (w/r/x/i layered oracle)
  symbols.rs                      PC to module/function resolution
  decompiler/                     TraceIR (LLM-friendly skeleton IR), il_pipeline (full three-layer), pass framework (14 passes)
  llil/                           in-house Low-Level IL (ARM64 lifter, cross-block SSA, Phi placement, flag elim)
  mlil/                           in-house Medium-Level IL (variable-based, flag-free, struct aware, type system)
  hlil/                           in-house High-Level IL (structured control flow, For/Switch/Break/Continue, CToken rendering, branch bias, C-like output)
rust/crates/tracemiku-server/src/
  main.rs                         axum app, static frontend, cache headers
  state.rs                        shared TraceState and warmers
  routes/                         JSON API route handlers
    resolve.rs                    (SO,offset)<->PC interop (runtime-truth foundation)
    indirect_targets.rs           br/blr runtime jump-target distribution
    mem_export.rs                 runtime-decrypted byte export by (SO,offset,len)
    reg_at.rs                     register value distribution at (SO,offset)/PC
    coverage.rs                   executed-path + branch-direction collapse
  bn_sidecar.rs                   BN process bridge
rust/crates/tracemiku-cli/src/    Rust CLI command implementations
scripts/                          parity/smoke/perf helper scripts
docs/                             design notes, audit reports, migration history
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

- TraceIR (LLM-friendly): Rust `tracemiku-core::decompiler` plus server
  `/api/dec/*` routes.
- In-house three-layer IL pipeline: Rust `tracemiku-core::llil`,
  `tracemiku-core::mlil`, `tracemiku-core::hlil`. LLIL→MLIL→HLIL lowering
  with C-like rendering. This path does not depend on an LLM or BN.
- Trace-enhanced decompiler: `tracemiku-core::decompiler::il_pipeline` lifts
  ARM64 through all three layers enriched with runtime trace values.
- Eval tool: `cargo run --example decompile_trace --release -- <call_dir>`
  measures coverage, timing, and layer statistics on real traces.

Do not merge or delete any of these routes without an explicit project
decision. The MLIL and HLIL layers are separate from the LLM-dependent
TraceIR route; they provide a fully local three-layer decompiler path.

## Device Notes

The usual development device may already be connected with adb, root, and Frida.
Run `./tracemiku doctor` to verify all prerequisites before tracing. The `trace`
command also runs a lightweight pre-flight check and warns if issues are detected.

For long interactive sessions, keep the device usable and battery-safe: prevent
auto-lock when you need app interaction, and turn the screen off again when you
are done. Avoid repeated heavy UI operations that keep the app/device hot unless
you are actively tracing or debugging.

## Current Hardening Focus

2026-06-02: All 26 decompiler audit tasks (Ghidra benchmark gap analysis from
`docs/decompiler-audit-2026-06-01.md`) have been implemented across 2 parallel
workflow waves. The decompiler pipeline now has:

- Cross-block SSA with Phi placement (Bilardi-Pingali + CHK dominator)
- 15+ TypeKind with signedness, float, struct/array/union, TypeOp rules
- 10 simplify rules, BitField pass, multi-precision arithmetic
- HLIL For/Switch/Break/Continue, path specialization, 5-hop convergence
- MemShadow→decompiler integration with scaled index + negative offset
- Parameter identification, call signature inference, value stability
- Token-based C rendering (CToken/CTokenKind), branch bias annotations
- Jump table recovery, indirect br CFG, CALLOTHER/syscall/JNI extension
- Union resolution, type database, TraceIR loop bodies, LLM fewshot
- Semantic test framework, eval tool --semantic metric
- Frontend keyboard navigation parity (line cursor, persistent rename/type)

One deferred item: Variable merging (Varnode→HighVariable→VariableGroup) —
depends on Phi node wire-up through MLIL/HLIL lowering.

Focus has shifted from feature expansion to iterative refinement and performance.

## Interaction Design (对标 IDA / Ghidra / Binary Ninja)

WebUI interaction MUST align with IDA Pro, Ghidra, and Binary Ninja conventions:

- **Single-click variable**: highlight all occurrences of the same variable
  (IDA/Ghidra behaviour). Do NOT select/highlight on single-click — use it
  for cross-reference highlighting.
- **Double-click variable**: rename variable (inline edit, IDA shortcut `N`).
  Validate against empty names, numeric-only names (e.g. `123`), keyword
  collisions, and duplicate names within the same function.
- **Right-click variable**: set variable type. Show an input dialog (not a
  fixed menu) that accepts C type expressions including pointers (`int*`,
  `char**`), structs (`struct MyStruct`), and typedefs. Parse with an
  embedded C type parser (consider tree-sitter-c or similar). Future:
  support user-defined struct types.
- **Hover variable/register/address**: show runtime value from trace records.
  Must work for registers (`x0`–`x30`, `fp`, `lr`, `sp`), memory addresses
  (`0xHEX`), and named variables (`var_*`).
- **Hover in assembly window**: registers and memory addresses must also
  show runtime values on hover (not just in decompile).
- **Goto labels**: IL must emit labels for jump targets (Goto/Label).
  Double-click on label name → jump to corresponding label definition.
- **Assembly scroll on click**: clicking a record should keep the viewport
  centred on the clicked row. Do NOT snap the viewport so the clicked row
  ends up at the top — keep surrounding context visible (centre or
  near-centre).

## Decompile Pipeline Quality

- LLIL → MLIL → HLIL must show meaningful structural differences. MLIL
  should eliminate register indirection; HLIL must show structured control
  flow (if/else, while, do-while, for, switch) and eliminate goto where
  possible. If the three layers look identical, the lowering passes are
  not running correctly.
- Run the Ghidra-style pass framework (6-phase pipeline) on every
  decompile request. The passes include: stack variable recovery, struct
  access detection, control flow structuring, dead code elimination,
  constant folding, and type propagation.
- When a feature exists in Ghidra, prefer to read Ghidra's Java source,
  understand the algorithm, and re-implement in Rust with equivalent
  semantics. Do not invent novel decompiler algorithms when established
  ones exist.

## Workflow Rules

- When starting a task, FIRST read and update `TODO.md` to reflect current
  status. `TODO.md` is the single source of truth for the backlog.
- Break large tasks into independent sub-tasks. Use AgentTeam or parallel
  sub-agents to accelerate work when subtasks are independent.
- After completing a task set, run agent-based or sub-agent audits to verify
  correctness, edge cases, and code quality before committing.
- Every feature must include tests. If a Ghidra feature is ported, include
  equivalent test cases from Ghidra's test suite.
- Feature implementation order: `tracemiku-core` (analysis) → `tracemiku-cli`
  (CLI surface) → `tracemiku-server` (API route) → `frontend` (WebUI).
  CLI output should be JSON-structured for AI consumption; WebUI should be
  human-friendly with reference to IDA/Ghidra/BN UX patterns.
- Destructive updates are acceptable as long as code quality and tool
  effectiveness improve. Do not preserve backwards compatibility at the
  expense of correctness or UX.
