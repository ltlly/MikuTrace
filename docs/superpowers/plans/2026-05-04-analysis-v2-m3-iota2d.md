# Analysis v2 — M3-ι2d Implementation Plan (/api/dec/llm-call)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development if available. In Codex sessions where the `superpowers:*` skills are not installed, execute with native tools and keep DONE/BLOCKED reporting.

**Goal:** Port the Python decompiler LLM call path to Rust:

1. `tracemiku-core::decompiler::prompt` exposes `Bundle`, `build_fn_decompile_prompt`, and prompt constants ported from `viewer/decompiler/llm_bundle.py`.
2. `tracemiku-server::llm` exposes async reqwest adapters for claude / deepseek / qwen / mimo, returning a Python-compatible `LlmResult` shape.
3. `POST /api/dec/llm-call` resolves `trace:*`, bare `F0`, `sym:*`, and legacy `cfg:*`, builds the prompt, calls the selected model, and returns the Python wire shape.
4. `GET /api/dec/models` returns available model aliases and API-key status.

**Out of scope:**

- `bn:*` decompile support. It remains gated on the Rust BN sidecar/backend.
- `opencode` subprocess adapter. M3-ι2d is reqwest JSON adapters only.
- Real provider integration tests. Tests must use mock HTTP servers or missing-key paths.
- Frontend wiring.

**Architecture:**

- **Prompt builder in core:** Keep prompt formatting close to Python `llm_bundle.py`, but accept a resolved `&FuncIR` so `sym:*` on-demand functions do not need mutating cached `TopIR`.
- **Reqwest client in server:** One `call_model(model_name, prompt, system, max_tokens)` function dispatches:
  - Anthropic `/v1/messages` with `x-api-key` and `anthropic-version`.
  - OpenAI-compatible `/chat/completions` for DeepSeek/Qwen/MiMo.
- **Env-only secrets:** Server reads API keys from env. Request body never accepts API keys.
- **Cache:** Add an in-memory per-process successful-output cache keyed by fn_id/model/lang/tier/max_tokens. Error results are not cached.
- **Tests:** Route tests use a local OpenAI-compatible mock server by setting `MIMO_BASE_URL` and `MIMO_API_KEY`; missing-key and unknown-fn paths are covered without external network.

**Tech Stack:** Rust 1.95. Add `reqwest = { version = "0.12", features = ["json", "rustls-tls"] }` to workspace dependencies.

**Branch:** `refactor/function-index-handoff`. Stream commits.

---

## File Structure

| File | Role |
|---|---|
| `rust/Cargo.toml` | Add workspace `reqwest`. |
| `rust/crates/tracemiku-server/Cargo.toml` | Add `reqwest.workspace = true`. |
| `rust/crates/tracemiku-core/src/decompiler/prompt.rs` | New prompt bundle port. |
| `rust/crates/tracemiku-core/src/decompiler/mod.rs` | `pub mod prompt;`. |
| `rust/crates/tracemiku-core/src/prelude.rs` | Re-export prompt helpers. |
| `rust/crates/tracemiku-server/src/llm.rs` | New model registry + reqwest adapters. |
| `rust/crates/tracemiku-server/src/lib.rs` | Export `llm`. |
| `rust/crates/tracemiku-server/src/state.rs` | Add LLM output cache. |
| `rust/crates/tracemiku-server/src/routes/dec_llm_call.rs` | New POST route. |
| `rust/crates/tracemiku-server/src/routes/dec_models.rs` | New GET route. |
| `rust/crates/tracemiku-server/src/routes/mod.rs` | Register routes. |
| `rust/crates/tracemiku-server/tests/test_dec_llm_call_route.rs` | Missing-key, mock success, sym resolution, bad fn tests. |
| `TODO.md` + spec | Mark M3-ι2d done and move next pointer. |

---

## Task 1: Core prompt bundle

**Files:** core prompt module + exports.

- [ ] Port `Bundle`, system prompts, token estimate, `build_summary_prompt`, `build_fn_decompile_prompt`.
- [ ] Include trace-level VM Candidates section when present.
- [ ] Truncate large functions by hottest blocks before render.
- [ ] Unit tests for EN/ZH prompt, VM context, truncation.

**Verify:** `cargo test -p tracemiku-core --lib decompiler::prompt`

**Commit:** `feat(core): port decompile prompt bundle`

---

## Task 2: Server LLM adapters

**Files:** server LLM module + Cargo deps.

- [ ] Add reqwest dependency.
- [ ] Implement registry aliases and `list_llm_models`.
- [ ] Implement missing-key errors without network.
- [ ] Implement Anthropic and OpenAI-compatible request/response parsing.
- [ ] Unit tests using a local mock OpenAI-compatible server.

**Verify:** `cargo test -p tracemiku-server --lib llm`

**Commit:** `feat(server): add reqwest LLM adapters`

---

## Task 3: /api/dec/llm-call route

**Files:** route, state cache, integration tests.

- [ ] Add request/response structs matching Python wire shape.
- [ ] Resolve `trace:*`, bare `F0`, `sym:*`, `cfg:*`; keep `bn:*` 404.
- [ ] Build prompt and call selected model.
- [ ] Cache successful outputs.
- [ ] Add `/api/dec/models`.
- [ ] Integration tests with mock MiMo endpoint.

**Verify:** `cargo test -p tracemiku-server --test test_dec_llm_call_route`

**Commit:** `feat(server): add dec llm-call endpoint`

---

## Task 4: Docs and final verification

- [ ] Mark M3-ι2d complete in TODO/spec.
- [ ] Run:

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo build -p tracemiku-core
cargo build -p tracemiku-server
cargo test -p tracemiku-core --lib decompiler
cargo test -p tracemiku-server
cargo clippy -p tracemiku-core -p tracemiku-server --tests
```

**Commit:** `docs(v2): mark M3-ι2d complete`

---

## Self-Review

- [ ] No API keys accepted from client payload.
- [ ] Tests do not call real LLM providers.
- [ ] Error results are not cached.
- [ ] `bn:*` remains a clear deferred 404.
- [ ] No frontend or BN sidecar scope creep.
