# Analysis v2 — M3-ι2c Implementation Plan (sym:* dec_fn + real-trace parity gate)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development if available. In Codex sessions where the `superpowers:*` skills are not installed, execute this plan with the native subagent/worker tools and keep the same DONE/BLOCKED reporting discipline. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the practical M3-ι series parity gate without waiting on the Rust BN backend:

1. `/api/dec/fn/{id}` supports `sym:<name>` and legacy `cfg:<name>` by building an on-demand `FuncIR` from CFG blocks grouped by symbol name. `trace:*` and bare `F0` behavior stays unchanged.
2. Add `scripts/m3_iota_parity.py`, a real-trace Python-vs-Rust gate for `/api/dec/summary` and `/api/dec/fn/trace:F0?tier=hot`, including type-anchor / VM-candidate coverage when present.
3. Sync `TODO.md` and the Analysis v2 spec: mark M3-ι2c done, explicitly defer `/api/dec/llm-call` and `bn:*` to a later milestone.

**Out of scope (deferred):**

- `/api/dec/fn/{id}` `bn:*` source support. No Rust BN backend / sidecar is available yet; this remains gated on the BN backend milestone.
- `/api/dec/llm-call`. LLM client port needs async `reqwest` clients and backend-specific JSON; it is a separate M3-ι2d-sized task.
- Frontend TS/Solid work. The Rust server still exposes JSON only in this milestone.
- Any trace format, capture agent, or per-call directory changes.

**Architecture:**

- **Core helper:** Add `build_symbol_func_ir(trace, sym, cfg, name) -> Option<FuncIR>` in `tracemiku-core::decompiler::builder`. It mirrors Python `webui/server.py::_func_ir_from_cfg_name`:
  - collect CFG blocks whose `sym.lookup(block.start_pc).0 == name`;
  - assign local block ids `B0..Bn` ordered by ascending block PC;
  - reuse decoded asm, samples, exec_count, and CFG outgoing edge metadata;
  - map exits to local block ids when the destination is inside the same symbol function, else `ext:<hex>`;
  - compute entry/exit idx from first/last trace hits for those block PCs;
  - set `FuncIR.id` to `sym:<name>`.
- **Server route:** `dec_fn_handler` keeps `trace:*` resolution through `top_ir.fn_by_id`. For `sym:*`, call the helper and render it with `render_func_md`. For `bn:*`, return 404 with a clear deferred message.
- **Parity script:** Start or reuse Python webui and Rust server on configurable ports. Compare JSON responses with stable tolerant metrics:
  - `/api/dec/summary` `fns`: Jaccard on `(name, entry_idx)` >= 0.95;
  - `/api/dec/summary` `summary_md`: token-set Jaccard >= 0.85;
  - `/api/dec/fn/trace:F0?tier=hot` markdown: token-set Jaccard >= 0.85;
  - if both sides emit `vm_candidates`, compare dispatcher PCs and confidence within +/- 0.1.
- **Docs sync:** TODO and spec milestone table should show M3-ι2c as complete and move `bn:*` + LLM call to M3-ι2d or BN-gated future work.

**Tech Stack:** Rust 1.95, Python 3. No new Rust workspace dependencies. Python script uses standard library plus `requests` if already present; otherwise `urllib.request`.

**Branch:** `refactor/function-index-handoff`. Stream commits to current branch.

**Spec inputs:**

- `webui/server.py:_func_ir_from_cfg_name` — Python on-demand symbol FuncIR reference.
- `viewer/function_index.py::parse_id` and Rust `tracemiku_core::function_index::parse_id` — accepted public ids and legacy aliases.
- `rust/crates/tracemiku-core/src/decompiler/builder.rs::make_block_ir` — shared Rust block IR construction pattern.
- `rust/crates/tracemiku-server/src/routes/dec_fn.rs` — current trace-only route.
- `scripts/m2_zeta_parity.py`, `scripts/m3_beta_parity.py`, `scripts/m3_delta_parity.py` — parity script conventions.

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-core/src/decompiler/builder.rs` | Add public `build_symbol_func_ir` helper and unit tests. |
| `rust/crates/tracemiku-core/src/prelude.rs` | Re-export `build_symbol_func_ir`. |
| `rust/crates/tracemiku-server/src/routes/dec_fn.rs` | Support `sym:*` / `cfg:*`; keep `bn:*` deferred. |
| `rust/crates/tracemiku-server/tests/test_dec_fn_route.rs` | Change sym test from 404 to 200 and assert symbol markdown contents. |
| `scripts/m3_iota_parity.py` | Real-trace summary/fn markdown parity gate. |
| `TODO.md` | Mark M3-ι2c done and move deferred items forward. |
| `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` | Sync milestone status / deferred scope. |

---

## Task 1: Core on-demand symbol FuncIR

**Files:**
- Modify: `rust/crates/tracemiku-core/src/decompiler/builder.rs`
- Modify: `rust/crates/tracemiku-core/src/prelude.rs`

- [ ] Step 1: Factor reusable first-hit helpers only if needed; keep scope tight and avoid redesigning existing `make_block_ir`.
- [ ] Step 2: Add `pub fn build_symbol_func_ir(trace, sym, cfg, name) -> Option<FuncIR>`.
- [ ] Step 3: Build local block ids ordered by symbol-owned CFG blocks, not global ids, to match Python on-demand rendering.
- [ ] Step 4: Populate `entry_idx`, `exit_idx`, `exec_count`, `pc_start`, `pc_end`, `blocks`, and `id = make_sym_id(name)`.
- [ ] Step 5: Add unit tests for a known symbol and unknown symbol.

**Verify:**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo test -p tracemiku-core --lib decompiler::builder
```

**Commit:** `feat(core): build on-demand symbol FuncIR`

---

## Task 2: Wire /api/dec/fn sym:* support

**Files:**
- Modify: `rust/crates/tracemiku-server/src/routes/dec_fn.rs`
- Modify: `rust/crates/tracemiku-server/tests/test_dec_fn_route.rs`

- [ ] Step 1: Resolve `trace:*` as today.
- [ ] Step 2: Resolve `sym:*` and legacy `cfg:*` through `build_symbol_func_ir`.
- [ ] Step 3: Keep `bn:*` as an explicit 404 with a deferred Rust BN backend message.
- [ ] Step 4: Update integration tests so `/api/dec/fn/sym:f_root` returns markdown and bad symbols still return 404.

**Verify:**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo test -p tracemiku-server --test test_dec_fn_route
```

**Commit:** `feat(server): support sym dec_fn route`

---

## Task 3: Real-trace M3-ι parity script

**Files:**
- Add: `scripts/m3_iota_parity.py`

- [ ] Step 1: Implement configurable CLI flags for trace path, Python port, Rust port, thresholds, and `--no-start` mode.
- [ ] Step 2: Start Python webui with `./tracemiku web <trace> --port <port> --no-browser` when needed.
- [ ] Step 3: Start Rust server with `cargo run --release -p tracemiku-server -- <trace> --port <port>` when needed.
- [ ] Step 4: Compare endpoints and print a compact PASS/FAIL report with metric values.
- [ ] Step 5: Exit non-zero on any hard-gate failure.

**Verify:**

```bash
python scripts/m3_iota_parity.py --trace traces/xsign_run1/calls/call_002_tid30203_7624431r_4655ms
```

**Commit:** `test(parity): add M3 iota real-trace gate`

---

## Task 4: Docs sync and final verification

**Files:**
- Modify: `TODO.md`
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`

- [ ] Step 1: Mark M3-ι2c done.
- [ ] Step 2: Add or adjust the next pointer for `/api/dec/llm-call` and `bn:*`.
- [ ] Step 3: Run standard verification:

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo build -p tracemiku-core
cargo build -p tracemiku-server
cargo test -p tracemiku-core --lib decompiler
cargo test -p tracemiku-server
cargo clippy -p tracemiku-core -p tracemiku-server --tests
```

**Commit:** `docs(v2): mark M3-ι2c complete`

---

## Self-Review

- [ ] `sym:*` and `cfg:*` both resolve; `trace:*` behavior unchanged.
- [ ] `bn:*` returns a deliberate deferred response, not a confusing parse failure.
- [ ] Symbol on-demand FuncIR has blocks, asm, samples, exits, and stable markdown.
- [ ] Parity script has hard thresholds and non-zero failure exit.
- [ ] No trace data, capture agents, or frozen `viewer/app.py` touched.
- [ ] Worktree commits use explicit paths and no generated footers.
