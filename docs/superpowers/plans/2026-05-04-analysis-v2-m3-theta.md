# Analysis v2 — M3-θ Implementation Plan (/api/dec/fn/{id} skeleton + render_func_md)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `GET /api/dec/fn/{fn_id}` matching the Python wire shape (`{fn_id, name, tier, markdown}`). Add a Rust `render_func_md(fn, tier) -> String` skeleton that produces a useful (if minimal) markdown bundle: header line, metadata table, per-block sections with asm/samples. Mirrors `viewer/decompiler/render/func.py` (Python's render_func_md) at the structural level — full Python fidelity (LLM-friendly summary tokens, type-anchor inlining, sub-fn cross-refs) defers to later milestones.

**Architecture:** New `tracemiku-core::decompiler::render` module with `render_func_md(fn: &FuncIR, tier: &str) -> String`. New route handler `routes::dec_fn::dec_fn_handler` accepts path param `fn_id`, optional query `tier=hot`. Resolves the fn via existing `TopIR::fn_by_id` + handle the `trace:F0` and bare `F0` legacy aliases via `function_index::parse_id`. Returns the markdown wrapped in JSON.

**Tech Stack:** Rust 1.95. No new workspace deps.

**Branch:** `refactor/function-index-handoff`. Stream commits.

**Spec inputs:**
- `webui/server.py:2775-2790` — Python `/api/dec/fn/{id}` reference. Wire shape: `{fn_id, name, tier, markdown}`.
- `viewer/decompiler/render/func.py` (or wherever `render_func_md` lives) — markdown formatter reference. Skeleton scope: header + metadata + per-block; defer LLM-summary tokens, type-anchor inlining, sub-fn cross-refs.
- `tracemiku-core::decompiler::ir::{TopIR, FuncIR, BlockIR}` (M3-δ..η shipped) — IR populated with id/name/blocks/exec_count/asm/samples/tier.
- `tracemiku-core::function_index::parse_id` (M2-ε shipped) — handles `trace:F0` / `F0` / `cfg:<name>` legacy.

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-core/src/decompiler/render.rs` (new) | `pub fn render_func_md(fn: &FuncIR, tier: &str) -> String`. Skeleton: header + metadata table + per-block sections. |
| `rust/crates/tracemiku-core/src/decompiler/mod.rs` (modify) | `pub mod render;` |
| `rust/crates/tracemiku-core/src/prelude.rs` (modify) | Re-export `render_func_md`. |
| `rust/crates/tracemiku-server/src/routes/dec_fn.rs` (new) | `GET /api/dec/fn/{fn_id}?tier=hot` handler. Resolves via `parse_id` + `top_ir.fn_by_id`. |
| `rust/crates/tracemiku-server/src/routes/mod.rs` (modify) | Add `pub mod dec_fn;` + route registration. |
| `rust/crates/tracemiku-server/tests/test_dec_fn_route.rs` (new) | 1 test: GET `/api/dec/fn/trace:F0` returns 200 + non-empty markdown; GET `/api/dec/fn/nonexistent` returns 404. |
| `TODO.md` + spec | Mark `/api/dec/fn/{id}` 🟡 M3-θ; refine M3-ι pointer. |

---

## Task 1: `render_func_md` + `/api/dec/fn/{id}`

**Files:**
- Create: `rust/crates/tracemiku-core/src/decompiler/render.rs`
- Modify: `rust/crates/tracemiku-core/src/decompiler/mod.rs`
- Modify: `rust/crates/tracemiku-core/src/prelude.rs`
- Create: `rust/crates/tracemiku-server/src/routes/dec_fn.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/mod.rs`
- Create: `rust/crates/tracemiku-server/tests/test_dec_fn_route.rs`

- [ ] **Step 1: Add `render_func_md`**

```rust
//! Markdown renderer for FuncIR.
//!
//! M3-θ skeleton: emits header + metadata table + per-block sections
//! (B-id, exec_count, tier, asm, samples). Full Python fidelity (LLM
//! summary tokens, type-anchor inlining, sub-fn cross-refs, induction
//! var summaries) defers to later milestones.

use crate::decompiler::ir::FuncIR;

/// Render a FuncIR as a markdown bundle. `tier_filter` is one of
/// `"hot"` / `"warm"` / `"cold"` / `"all"` — only blocks matching the
/// requested tier are rendered (matches Python webui's `tier` param).
pub fn render_func_md(fn_: &FuncIR, tier_filter: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("# {} — {}\n\n", fn_.id, fn_.name));
    out.push_str(&format!(
        "- **records**: idx [{}..{}]\n",
        fn_.entry_idx, fn_.exit_idx
    ));
    out.push_str(&format!("- **exec_count**: {}\n", fn_.exec_count));
    out.push_str(&format!("- **blocks**: {}\n", fn_.blocks.len()));
    out.push_str(&format!("- **loops**: {}\n", fn_.loops.len()));
    out.push_str(&format!("- **calls**: {}\n", fn_.calls.len()));
    out.push_str(&format!("- **type_anchors**: {}\n", fn_.type_anchors.len()));
    if fn_.truncated {
        out.push_str("- **truncated**: yes\n");
    }
    out.push('\n');

    // Per-block sections.
    let want_all = tier_filter == "all";
    for block in &fn_.blocks {
        if !want_all && block.tier != tier_filter {
            continue;
        }
        out.push_str(&format!("## {} (pc {:#x}, exec {})\n\n", block.id, block.pc, block.exec_count));
        out.push_str(&format!("- **tier**: {}\n", block.tier));
        out.push_str(&format!("- **insns**: {}\n", block.insns));
        if !block.samples.is_empty() {
            out.push_str("- **samples**:\n");
            // Sort keys for stable output.
            let mut keys: Vec<&String> = block.samples.keys().collect();
            keys.sort();
            for k in keys {
                let v = block.samples[k];
                // Render as hex when value is non-trivial (>= 16) and not
                // negative; small integers (e.g. counters) render as decimal.
                let v_str = if v.abs() >= 16 {
                    format!("{:#x}", v as u64)
                } else {
                    v.to_string()
                };
                out.push_str(&format!("  - {} = {}\n", k, v_str));
            }
        }
        if !block.asm.is_empty() {
            out.push_str("\n```asm\n");
            out.push_str(&block.asm);
            if !block.asm.ends_with('\n') {
                out.push('\n');
            }
            out.push_str("```\n");
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ir::{BlockIR, FuncIR};
    use std::collections::HashMap;

    #[test]
    fn render_func_md_emits_header_metadata_blocks() {
        let mut samples = HashMap::new();
        samples.insert("x0".to_string(), 0xdead_i64);
        samples.insert("sp".to_string(), 0x7000_i64);
        let f = FuncIR {
            id: "F0".to_string(),
            name: "doCommandNative".to_string(),
            entry_idx: 0,
            exit_idx: 100,
            exec_count: 1,
            blocks: vec![BlockIR {
                id: "B0".to_string(),
                pc: 0x1000,
                end_pc: 0x100c,
                insns: 4,
                exec_count: 5,
                samples,
                asm: "  0x1000: nop\n  0x1004: ret".to_string(),
                tier: "hot".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let md = render_func_md(&f, "hot");
        assert!(md.contains("# F0 — doCommandNative"), "missing header in {md}");
        assert!(md.contains("**records**: idx [0..100]"), "missing records line: {md}");
        assert!(md.contains("**blocks**: 1"), "missing blocks count: {md}");
        assert!(md.contains("## B0"), "missing block heading: {md}");
        assert!(md.contains("**tier**: hot"), "missing tier line: {md}");
        assert!(md.contains("```asm"), "missing asm code fence: {md}");
        assert!(md.contains("0x1000: nop"), "missing asm content: {md}");
        assert!(md.contains("x0 = 0xdead"), "missing samples x0: {md}");
        assert!(md.contains("sp = 0x7000"), "missing samples sp: {md}");
    }

    #[test]
    fn render_func_md_filters_by_tier() {
        let f = FuncIR {
            id: "F0".to_string(),
            name: "f".to_string(),
            blocks: vec![
                BlockIR {
                    id: "B0".to_string(),
                    pc: 0x1000,
                    tier: "hot".to_string(),
                    ..Default::default()
                },
                BlockIR {
                    id: "B1".to_string(),
                    pc: 0x2000,
                    tier: "warm".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let md_hot = render_func_md(&f, "hot");
        assert!(md_hot.contains("## B0"), "B0 (hot) should appear: {md_hot}");
        assert!(!md_hot.contains("## B1"), "B1 (warm) should be filtered: {md_hot}");
        let md_all = render_func_md(&f, "all");
        assert!(md_all.contains("## B0"));
        assert!(md_all.contains("## B1"), "all should include warm: {md_all}");
    }
}
```

- [ ] **Step 2: Module + prelude wiring**

`decompiler/mod.rs`: add `pub mod render;` after `pub mod ir;`.

`prelude.rs`: append after the existing `pub use crate::decompiler::ir::{...}`:

```rust
pub use crate::decompiler::render::render_func_md;
```

- [ ] **Step 3: `routes/dec_fn.rs`**

```rust
//! GET /api/dec/fn/{fn_id} — per-fn TraceIR markdown.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::function_index::parse_id;
use tracemiku_core::prelude::render_func_md;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct DecFnQuery {
    #[serde(default = "default_tier")]
    pub tier: String,
}

fn default_tier() -> String {
    "hot".to_string()
}

#[derive(Debug, Serialize)]
pub struct DecFnResponse {
    pub fn_id: String,
    pub name: String,
    pub tier: String,
    pub markdown: String,
}

pub async fn dec_fn_handler(
    State(state): State<AppState>,
    Path(fn_id): Path<String>,
    Query(q): Query<DecFnQuery>,
) -> Result<Json<DecFnResponse>, (StatusCode, String)> {
    let inner = &state.inner;

    // Resolve fn_id to a FuncIR. Accept trace:F0, bare F0, sym:<name>,
    // bn:<addr>, cfg:<name> via parse_id legacy-alias path. M3-θ
    // supports trace:* only — sym/bn fall back to 404 (M3-ι could
    // wire those by looking up in FunctionIndex / building on demand).
    let (src, payload) = parse_id(&fn_id)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid fn_id: {e}")))?;
    if src != "trace" {
        return Err((
            StatusCode::NOT_FOUND,
            format!("fn_id {fn_id} (source={src}) not yet supported by /api/dec/fn — only trace:* in M3-θ"),
        ));
    }
    let fn_ = inner
        .top_ir
        .fn_by_id(&payload)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no such fn {fn_id}")))?;

    let markdown = render_func_md(fn_, &q.tier);

    Ok(Json(DecFnResponse {
        fn_id: fn_id.clone(),
        name: fn_.name.clone(),
        tier: q.tier,
        markdown,
    }))
}
```

- [ ] **Step 4: Register route**

`routes/mod.rs`: add `pub mod dec_fn;` (alphabetically before `dec_summary`). Add route registration:

```rust
        .route("/api/dec/fn/:fn_id", get(dec_fn::dec_fn_handler))
```

(Place near `/api/dec/summary`.)

- [ ] **Step 5: Integration test**

`tests/test_dec_fn_route.rs`. Use the existing 3-rec fixture pattern from `test_dec_summary_route.rs`:

```rust
//! /api/dec/fn/{fn_id} integration test.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::fs;
use tower::ServiceExt;

fn synth_root_only() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_3r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 3];
    for i in 0..3usize {
        let off = i * 272;
        let pc = 0x100000u64 + (i as u64) * 4;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":3,"known_offsets":{"0x0":"f_root"}}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":4096},"method":"f","cmd":42,"fn_addr":"0x100000"}"#,
    )
    .unwrap();
    dir
}

fn call_dir(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path()
        .join("run")
        .join("calls")
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
}

#[tokio::test]
async fn dec_fn_returns_markdown_for_trace_f0() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/fn/trace:F0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["fn_id"], "trace:F0");
    assert_eq!(v["tier"], "hot");
    let md = v["markdown"].as_str().unwrap();
    assert!(md.contains("# F0"), "markdown should have header: {md}");
    assert!(!md.is_empty());
}

#[tokio::test]
async fn dec_fn_accepts_bare_f0_legacy_id() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/fn/F0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["fn_id"], "F0");  // route handler echoes the input fn_id
    let md = v["markdown"].as_str().unwrap();
    assert!(md.contains("# F0"), "bare F0 should resolve via parse_id legacy");
}

#[tokio::test]
async fn dec_fn_returns_404_for_unknown() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/fn/trace:F99")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dec_fn_returns_404_for_unsupported_source() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/fn/sym:f_root")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // sym:* not yet wired — return 404 with explanatory message.
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
```

- [ ] **Step 6: Verify**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo build -p tracemiku-server 2>&1 | tail -5
cargo test -p tracemiku-core --lib decompiler 2>&1 | tail -15
cargo test -p tracemiku-server --test test_dec_fn_route 2>&1 | tail -10
cargo test -p tracemiku-server 2>&1 | grep "test result:" | tail -5
cargo clippy -p tracemiku-core -p tracemiku-server --tests 2>&1 | tail -5
```

Expected:
- 15 decompiler tests pass (13 prior + 2 new render tests).
- 4 dec_fn route tests pass.
- All other server tests still green. Clippy clean.

- [ ] **Step 7: Commit**

```bash
git add rust/crates/tracemiku-core/src/decompiler/render.rs \
        rust/crates/tracemiku-core/src/decompiler/mod.rs \
        rust/crates/tracemiku-core/src/prelude.rs \
        rust/crates/tracemiku-server/src/routes/dec_fn.rs \
        rust/crates/tracemiku-server/src/routes/mod.rs \
        rust/crates/tracemiku-server/tests/test_dec_fn_route.rs
git commit -m "$(cat <<'EOF'
feat(core,server): /api/dec/fn/{fn_id} — render_func_md + per-fn route

render_func_md(fn, tier) emits a markdown bundle:
  - Header: # F0 — doCommandNative
  - Metadata: records range, exec_count, blocks/loops/calls/type_anchors counts
  - Per-block sections: ## B<id>, tier, insns count, samples (sorted keys),
    asm code fence

tier filter ∈ {"hot", "warm", "cold", "all"}.

Route handler resolves fn_id via function_index::parse_id (accepts
trace:F0, bare F0). sym:* / bn:* return 404 with message — M3-ι
will wire those.

Full Python fidelity (render/func.py) — LLM-summary tokens,
type-anchor inlining, sub-fn cross-refs, induction-var summaries —
defers to later milestones.

Tests:
  - render_func_md_emits_header_metadata_blocks (core)
  - render_func_md_filters_by_tier (core)
  - dec_fn_returns_markdown_for_trace_f0
  - dec_fn_accepts_bare_f0_legacy_id
  - dec_fn_returns_404_for_unknown
  - dec_fn_returns_404_for_unsupported_source

M3-θ Task 1.
EOF
)"
```

## Caveats

- DON'T add `/api/dec/llm-call` (that wraps render_func_md → LLM bundle, separate scope).
- DON'T port `viewer/decompiler/render/summary.py` (`render_summary_md` fidelity for `/api/dec/summary` — defer to later, current Rust handler emits a one-line text fallback that's good enough).
- DON'T extend BlockIR.exits (M3-ι scope).
- The `axum::Path<String>` for the `fn_id` route param needs colon-form path: `/api/dec/fn/:fn_id` (axum 0.7 syntax). Double-check by looking at sibling route registrations in `routes/mod.rs`.

## Report

Status: DONE | DONE_WITH_CONCERNS | BLOCKED | NEEDS_CONTEXT
- Commit SHA
- Files changed
- `cargo test -p tracemiku-core --lib decompiler` output (last 12 lines)
- `cargo test -p tracemiku-server --test test_dec_fn_route` output (last 10 lines)
- Clippy output (last 5 lines)
- Self-review
- Any deviations

---

## Task 2: Spec/TODO sync

**Files:**
- Modify: `TODO.md`
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`

- [ ] **Step 1: Update spec rows**

Find `/api/dec/fn/{id}` row (currently `🔜 M3-ζ`). Update to `🟡 M3-θ` with note:

```markdown
| `/api/dec/fn/{id}` | 🟡 M3-θ | trace:* + bare F0 legacy id supported via render_func_md (skeleton — header/metadata/per-block asm/samples). sym:* / bn:* + render_summary_md fidelity + LLM bundle defer to later milestones |
```

- [ ] **Step 2: Update TODO.md**

Append:

```markdown
- M3-θ /api/dec/fn/{id} + render_func_md skeleton (header + metadata + per-block asm/samples; trace:* + bare F0): ✅ 2026-05-04
```

Refine M3-ι pointer:

```markdown
- M3-ι (next): BlockIR.exits with kind/taken_count (extends Rust CFG to track edge metadata), /api/dec/fn/{id} sym:* / bn:* source support, render_summary_md fidelity, type_anchor.py port (json-spec driven), vm_candidate.py port
```

- [ ] **Step 3: Commit**

```bash
git add TODO.md docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md
git commit -m "docs(v2): mark M3-θ complete (/api/dec/fn/{id} skeleton)"
```

---

## Self-Review

**Spec coverage:**
| Item | Task |
|---|---|
| `render_func_md` skeleton | Task 1 |
| `/api/dec/fn/{id}` route | Task 1 |
| Legacy `F0` / `trace:F0` resolution | Task 1 (parse_id) |
| Tier filter | Task 1 |
| Docs sync | Task 2 |

**Out of scope (deferred to M3-ι):**
- BlockIR.exits with kind/taken_count (needs CFG edge-metadata extension)
- /api/dec/fn/{id} sym:* / bn:* source support
- render_summary_md fidelity
- type_anchor.py + vm_candidate.py ports
- /api/dec/llm-call

**Risk:** axum 0.7 path-param syntax is `:fn_id` (not `{fn_id}` like FastAPI). Verify by looking at existing routes; if axum 0.7 in this workspace uses `{fn_id}`, switch. (Both forms exist in the wild depending on version.)

---

**Plan complete and saved.** Per `CLAUDE.md` user-pref §"Skip the 'Two execution options' handoff" — execution proceeds via `superpowers:subagent-driven-development`.
