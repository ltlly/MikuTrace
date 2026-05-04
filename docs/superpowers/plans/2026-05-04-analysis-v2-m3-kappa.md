# Analysis v2 — M3-κ Implementation Plan (CFG SVG + Graph Panel)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development if available. In Codex sessions where the `superpowers:*` skills are not installed, execute with native tools and keep DONE/BLOCKED reporting.

**Goal:** Restore the primary CFG graph surface in the Rust/Solid v2 stack:

1. `GET /api/cfg-svg?fn=&timeout=` returns Python-compatible Graphviz SVG response shapes.
2. Server builds trace CFG DOT from `tracemiku-core::cfg::CFG`, `Trace`, `SymbolMap`, and `ModuleResolver` without Python viewer dependencies.
3. SVG output is cached per function filter.
4. Solid frontend adds a Graph panel that lists functions, requests SVG, displays status/error/cache metadata, and renders the returned SVG.

**Out of scope:**

- Binary Ninja CFG endpoints (`/api/bn-cfg-svg-for-pc`, `/api/bn-cfg-for-pc`), deferred to M6 sidecar work.
- Replacing Graphviz with a pure Rust layout engine.
- Interactive instruction-selection sync with RecordsPanel. M3-κ renders clickable SVG anchors but does not wire global cursor state.
- Old `webui/` changes. Web v2 lives under `rust/` + `frontend/`.

**Architecture:**

- **Route contract:** Mirror Python `/api/cfg-svg` response variants:
  - `ready`: `svg`, `fn`, `block_count`, `total_block_count`, `cached`
  - `empty`: `fn`, `svg: null`
  - `error`: `err`
- **DOT generation:** Keep rendering helpers local to `routes/cfg_svg.rs`; use stable HTML escaping, Graphviz HTML labels, mnemonic coloring, edge-kind colors, and external in/out stub nodes.
- **Cache:** Add `cfg_svg_cache: Mutex<HashMap<String, CfgSvgCached>>` to `AppState`.
- **Graphviz call:** Invoke `dot -Tsvg` via `std::process::Command`. Keep `TRACEMIKU_DOT` as a test/dev override; default to `dot`.
- **Frontend:** Add `CfgPanel` with a function selector fed by `/api/functions`, timeout input, reload button, and `innerHTML` SVG render.

**Branch:** `refactor/function-index-handoff`. Stream commits.

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-server/src/state.rs` | Add typed SVG cache. |
| `rust/crates/tracemiku-server/src/routes/cfg_svg.rs` | New DOT builder + `/api/cfg-svg` handler. |
| `rust/crates/tracemiku-server/src/routes/mod.rs` | Register route. |
| `rust/crates/tracemiku-server/tests/cfg_endpoint_tests.rs` | Add route tests for ready/cache/empty/error. |
| `frontend/src/api/types.ts` | Add `CfgSvgResponse` union. |
| `frontend/src/api/client.ts` | Add `fetchCfgSvg`. |
| `frontend/src/panels/cfg/CfgPanel.tsx` | New Graph panel. |
| `frontend/src/App.tsx` | Mount Graph panel. |
| `frontend/src/styles/base.css` | Graph panel layout and SVG viewport styles. |
| `TODO.md` + spec | Mark M3-κ done and move next pointer. |

---

## Task 1: Rust CFG SVG route

- [ ] Add typed cache to `AppState`.
- [ ] Implement `cfg_svg_handler` and DOT/SVG helpers.
- [ ] Register `GET /api/cfg-svg`.
- [ ] Preserve JSON shape for ready/empty/error.

**Verify:** `cargo test -p tracemiku-server --test cfg_endpoint_tests`

**Commit:** `feat(server): add cfg svg endpoint`

---

## Task 2: Route tests and error coverage

- [ ] Test ready SVG response on synthetic trace when `dot` is available.
- [ ] Test second request returns `cached: true`.
- [ ] Test unknown function returns `status: empty`.
- [ ] Test Graphviz executable failure via `TRACEMIKU_DOT`.

**Verify:** `cargo test -p tracemiku-server --test cfg_endpoint_tests`

**Commit:** Fold into Task 1 unless the patch grows too large.

---

## Task 3: Solid Graph panel

- [ ] Add API types/client call.
- [ ] Add `CfgPanel` with function selector, timeout, reload, metadata, and SVG viewport.
- [ ] Mount panel in `App.tsx`.
- [ ] Add CSS for controls, SVG viewport, and graph status states.

**Verify:**

```bash
cd /home/ltlly/Code/traceMiku/frontend
npm run typecheck
npm run build
```

**Commit:** `feat(frontend): add graph cfg panel`

---

## Task 4: Docs and final verification

- [ ] Mark M3-κ complete in TODO/spec and move next pointer to M3-λ.
- [ ] Run:

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo build -p tracemiku-server
cargo test -p tracemiku-server --test cfg_endpoint_tests
cargo test -p tracemiku-server
cargo clippy -p tracemiku-server --tests

cd /home/ltlly/Code/traceMiku/frontend
npm run typecheck
npm run build
```

**Commit:** `docs(v2): mark M3-κ complete`

---

## Self-Review

- [ ] No Python viewer imports or old `webui/` edits.
- [ ] `dot` failures return JSON `status: error`, not server 500.
- [ ] Cache only stores successful SVG output.
- [ ] Large traces remain bounded by per-function filtering and route timeout.
- [ ] Frontend renders the actual SVG and does not require a generated `dist/` edit.
