# Analysis v2 — M3-μ Implementation Plan (Cutover Prep, No Legacy Delete)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development if available. In Codex sessions where the `superpowers:*` skills are not installed, execute with native tools and keep DONE/BLOCKED reporting.

**Goal:** Prepare the Rust v2 stack for eventual Python viewer/webui cutover without deleting legacy code.

1. `tracemiku-cli` gains typed JSON wrappers for the trace-only Rust server endpoints already shipped in M3.
2. `tracemiku-cli list` and `tracemiku-cli info` cover the current Python top-level helper workflow for run/call inspection.
3. The old Python `webui/` and `viewer/` are not removed in M3-μ. Removal stays gated on explicit manual sign-off in M7.

**Out of scope:**

- Deleting `webui/`, `viewer/`, or Python tests.
- Making `./tracemiku web` default to v2.
- BN/HLIL endpoints and `bn:*` decompile support.
- LLM POST CLI wrapper. `/api/dec/llm-call` remains server/API-first.

**Architecture:**

- Add a small in-process REST bridge in `tracemiku-cli`: build `tracemiku_server::build_router(call_dir)` and issue a `tower::ServiceExt::oneshot` request to the exact route path. This avoids duplicating route wire logic in the CLI.
- Keep `stats` direct-core because it already has Python parity and does not need full AppState.
- Implement `list`/`info` directly in CLI using filesystem metadata and `tracemiku-core::Trace`/`decode`.

**Branch:** `refactor/function-index-handoff`. Stream commits.

---

## File Structure

| File | Role |
|---|---|
| `rust/Cargo.toml` | Add workspace dependency entry for `tracemiku-server` if needed. |
| `rust/crates/tracemiku-cli/Cargo.toml` | Add server/router test deps (`tracemiku-server`, axum/tower/body/tokio). |
| `rust/crates/tracemiku-cli/src/main.rs` | Add CLI commands and route bridge. |
| `rust/crates/tracemiku-cli/tests/cli_smoke.rs` | Smoke typed CLI commands on a synthetic per-call trace. |
| `TODO.md` + spec | Mark M3-μ cutover prep done; leave destructive delete as M7 sign-off. |

---

## Task 1: REST-backed CLI wrappers

- [ ] Add commands:
  - `records`, `record`, `functions`, `cfg`, `cfg-svg`, `call-tree`
  - `strings`, `mem-dump`
  - `taint-fwd`, `taint-bwd`
  - `dec-summary`, `dec-fn`
- [ ] Each command prints endpoint JSON exactly as returned by the route.
- [ ] Non-2xx route response exits with an error.

**Verify:** `cargo run -p tracemiku-cli -- functions <call_dir>`

**Commit:** `feat(cli): add rest-backed analysis commands`

---

## Task 2: list/info helpers

- [ ] `list [path] --json` lists runs or calls, mirroring the Python helper shape.
- [ ] `info <path> --json` supports per-call and per-run directories.
- [ ] Text output is useful but JSON is the parity contract.

**Verify:** CLI smoke tests.

**Commit:** Fold into Task 1 if compact.

---

## Task 3: Tests and docs

- [ ] Add `tracemiku-cli` smoke tests for `info`, `records`, and `functions`.
- [ ] Mark M3-μ prep done in TODO/spec; explicitly note legacy deletion remains deferred to M7 sign-off.
- [ ] Run:

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo build -p tracemiku-cli
cargo test -p tracemiku-cli
cargo clippy -p tracemiku-cli --tests
```

**Commit:** `docs(v2): mark M3-μ prep complete`

---

## Self-Review

- [ ] No legacy Python/webui files deleted.
- [ ] CLI wrappers call the same Rust routes as the frontend.
- [ ] JSON output remains machine-readable by default for typed wrappers.
- [ ] `list`/`info` do not require Frida, FastAPI, or Python viewer imports.
