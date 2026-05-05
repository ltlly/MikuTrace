# traceMiku Backlog / TODO

This is the only active backlog. Completed implementation plans and handoffs are
deleted instead of kept as parallel TODO lists.

## Current Focus

Rust/Solid analysis v2 is the active stack. Python `viewer/`, old FastAPI
`webui/`, the TUI, and old Python-vs-Rust parity scripts are gone from the
tracked runtime path.

The current branch focus is interaction latency and parity hardening:

- keep CPU-heavy route work off Tokio reactor threads;
- cap large responses and surface truncation/partial-result metadata;
- guard stale frontend async frames against current cursor/function changes;
- keep Solid list/resource sources reference-stable when semantics are
  unchanged;
- convert every user-visible regression into a focused Rust test, static audit,
  or Playwright smoke check.

## Active Backlog

### P0 - Keep The Web UI Responsive

- Add any new heavy API route to
  `rust/crates/tracemiku-server/tests/api_infra_tests.rs` with the correct
  heavy/light classification.
- For large-route fixes, extend `scripts/rust_web_smoke.py` or
  `scripts/web_api_perf_probe.py` rather than relying on manual timing.
- For frontend interaction regressions, extend
  `scripts/frontend_event_smoke.py` or the static frontend audit scripts.

### P1 - CFG Usability

- Replace the large CFG overview with a better navigation model. The current
  fallback intentionally draws only representative edges and reports hidden
  edge count; it is not a full graph layout.
- Add local-neighborhood controls for large CFGs: selected block, incoming and
  outgoing neighbors, hot blocks, and loop/SCC grouping.
- Keep Graphviz force-render bounded. Do not allow large dot renders to block
  cursor movement or records scrolling.

### P1 - BN Sidecar And HLIL

- Persist or cache BN user functions created on demand when no BN function
  contains a trace PC, so repeated HLIL/CFG requests do not pay avoidable
  analysis cost.
- Add focused tests around BN request parameters (`pc`, trace function start,
  mode, timeout) and returned `created_function` metadata.
- Improve HLIL/Pseudo C rendering only through tokenized structured lines; keep
  LLM controls hidden unless their latency/cancellation behavior is proven.

### P1 - Taint And Data Provenance

- Continue validating backward taint semantics on real traces where the user can
  name the expected data source. Tree view is the default surface; timeline/table
  are secondary.
- Memory provenance must keep range selection, writers/readers separation, and
  partial-result notices.

### P2 - Decompiler

- Keep both decompile routes:
  - TraceIR / route B markdown plus optional model call routes.
  - In-house LLIL/pseudocode route that does not depend on an LLM.
- Before exposing hidden or cold decompiler UI by default, prove cancellation,
  stale-frame protection, and health-poll latency on a large trace.

### P2 - Documentation

- Keep `README.md`, `AGENTS.md`, `CLAUDE.md`, `rust/README.md`, and this file in
  sync with current Rust/Solid behavior.
- Historical design specs may stay under `docs/superpowers/specs/`, but
  completed implementation plans should not be treated as live instructions.

## Validation Gates

```bash
make test-v2
make test-fast
make smoke-web RUN=<call_dir> SMOKE_ARGS='--all-surfaces'
make smoke-ui BASE=http://127.0.0.1:18900 UI_SMOKE_ARGS='--browser chromium --executable /path/to/chrome'
```

Use `uv run python ...` for Python helper scripts.
