# Analysis v2 — M3-ε Implementation Plan (dec-summary parity closure: callee splits + symbol-source fallback)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the M3-δ `/api/dec/summary` parity soft-gate (currently 0.01 jaccard). Two minimum-viable additions: (1) port a metadata-only `split_top_k_callees` to `decompiler::builder` (groups calltree by fn_pc, ranks by total records, promotes ≥`min_records` callees to `F1..Fn` FuncIR entries — without per-block BlockIR construction yet, that's M3-ζ). (2) Add the symbol-source fallback to the `/api/dec/summary` handler so it merges in `sym:<name>` entries from `FunctionIndex` not already in the trace-ir set. Re-tighten the parity gate to hard-fail.

**Architecture:** Reuse `tracemiku-core::calltree::build_call_tree` (M3-α) to produce the nested tree. Flatten depth-first into `Frame { fn_pc, fn_name, enter_idx, exit_idx }`. Filter calltree noise (instances ≥3 records, ≤30% trace length — Python parity at `viewer/decompiler/builder.py:86-90`). Group by `fn_pc`, score by total records, take top-K above `min_records`, emit one `FuncIR` per. **No BlockIR / asm / samples / exits in the FuncIR yet** — `blocks: vec![]`, `calls: vec![]`, etc. Just the structural metadata (id, name, pc_start, pc_end, entry_idx, exit_idx, exec_count). M3-ζ adds the per-block content. The symbol-source fallback in the route handler is purely additive: read `inner.function_index.entries`, skip names already in trace-ir's set, append as `DecFnEntry { source: "symbol", entry_idx: None, exit_idx: None, blocks: 0, ... }`.

**Tech Stack:** Rust 1.95. No new workspace deps.

**Branch:** `refactor/function-index-handoff`. Stream commits.

**Spec inputs:**
- `viewer/decompiler/builder.py:34-203` — `_flatten_calltree` + `split_top_k_callees`. Port the structural side; defer the BlockIR construction subroutines (lines 105-178).
- `webui/server.py:2745-2755` — symbol-source fallback in `/api/dec/summary`. The Rust analog uses `FunctionIndex::entries`.
- `tracemiku-core::function_index` (M2-ε shipped) — `FunctionEntry { id: "sym:<name>", name, source: "symbol", entry_pc, blocks, ... }`. Already aggregated from SymbolMap + CFG.
- M3-δ plan + commits — locks the IR + skeleton infrastructure that M3-ε extends.

**Lessons from M3-β/γ/δ applied:**
- Don't expand task scope mid-flight — BlockIR construction (the heaviest piece of `split_top_k_callees`) is explicitly deferred to M3-ζ here.
- Subagents get full code blocks; the algorithm is well-understood from Python source.

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-core/src/decompiler/builder.rs` (modify) | Add `flatten_calltree(node) -> Vec<Frame>` helper. Add `split_top_k_callees(top: &mut TopIR, trace, sym, top_k, min_records)` that ranks bl-targets by total records and emits F1..Fn FuncIR entries (metadata only). Update `build_trace_ir` signature: `build_trace_ir(trace, meta, sym, top_k: usize, min_records: usize) -> TopIR`. Default values for backward compat: `build_trace_ir_default(trace, meta, sym)` → calls with `top_k=10, min_records=50` (matches Python webui defaults). |
| `rust/crates/tracemiku-server/src/state.rs` (modify) | `AppState::load` calls `build_trace_ir(&trace, &meta, &symbols, 10, 50)`. |
| `rust/crates/tracemiku-server/src/routes/dec_summary.rs` (modify) | After collecting trace-ir entries, iterate `inner.function_index.entries` filtering `source == "symbol"`, skip names already in trace-ir set, append as `DecFnEntry { source: "symbol", entry_idx: None, exit_idx: None, ... }`. |
| `rust/crates/tracemiku-server/tests/test_dec_summary_route.rs` (modify) | Update existing test to also accept N≥1 fns when symbol-source fallback fires; add 1 new test pinning that a symbol entry shows up in fns when SymbolMap has names beyond root. |
| `scripts/m3_delta_parity.py` (modify) | Remove `SOFT_LABELS` (set to empty); update comment to note M3-ε closure. |
| `TODO.md` (modify) | Append M3-ε rows; refine M3-ζ pointer (BlockIR construction + /api/dec/fn/{id} + render_summary_md fidelity). |
| `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` (modify) | Mark `decompiler/builder.py` row + `/api/dec/summary` row as ✅ M3-ε (full surface modulo BlockIR — that's M3-ζ). |

---

## Task 1: `split_top_k_callees` metadata-only port

**Files:**
- Modify: `rust/crates/tracemiku-core/src/decompiler/builder.rs`

Direct port of `viewer/decompiler/builder.py:34-203` with two scope cuts:
- BlockIR construction omitted (`own_blocks` collection, asm rendering, samples extraction). Each new FuncIR has `blocks: vec![]`, `calls: vec![]`, `loops: vec![]`. M3-ζ fills these.
- numpy-vectorized PC mask omitted — Python uses `np.zeros + mask scanning` for performance on 7M-record traces; M3-ε's metadata-only port only needs per-frame `(enter_idx, exit_idx)` ranges, no PC-array scanning.

- [ ] **Step 1: Add the `Frame` struct + `flatten_calltree` helper**

In `decompiler/builder.rs`, just below the imports:

```rust
use crate::calltree::{build_call_tree, CallNode};
use crate::decompiler::ir::{FuncIR, TopIR};

/// One flattened calltree frame. Mirrors the shape Python uses at
/// viewer/decompiler/builder.py:42-48.
#[derive(Debug, Clone)]
struct Frame {
    fn_pc: u64,
    fn_name: String,
    enter_idx: usize,
    exit_idx: usize,
}

/// Depth-first flatten of a calltree (root excluded).
/// Mirrors viewer/decompiler/builder.py:34-51.
fn flatten_calltree(root: &CallNode) -> Vec<Frame> {
    let mut out = Vec::new();
    fn walk(node: &CallNode, out: &mut Vec<Frame>) {
        for c in &node.children {
            out.push(Frame {
                fn_pc: c.fn_pc,
                fn_name: c.fn_name.clone().unwrap_or_default(),
                enter_idx: c.enter_idx,
                exit_idx: c.exit_idx,
            });
            walk(c, out);
        }
    }
    walk(root, &mut out);
    out
}
```

- [ ] **Step 2: Add `split_top_k_callees`**

```rust
/// In-place: promote top-K bl-targets (ranked by total records hit)
/// to standalone FuncIR entries `F1..Fn`. Skips entries with fewer
/// than `min_records` records.
///
/// Mirrors viewer/decompiler/builder.py:54-203, with two scope cuts
/// for M3-ε: no BlockIR construction (blocks: vec![]), no asm/samples.
/// M3-ζ fills the per-block content.
pub fn split_top_k_callees(
    top: &mut TopIR,
    trace: &Trace,
    sym: &SymbolMap,
    top_k: usize,
    min_records: usize,
) {
    use std::collections::HashMap;

    if top.fns.is_empty() {
        return;
    }
    let n = trace.len();
    if n == 0 {
        return;
    }

    // Build calltree, flatten.
    let tree = build_call_tree(trace, sym, 50);
    let frames_all = flatten_calltree(&tree);
    if frames_all.is_empty() {
        return;
    }

    // Filter calltree noise (Python:86-90):
    //   instance length 3..=30% of trace.
    let max_inst_len = std::cmp::max((n as f64 * 0.30) as usize, 1);
    let frames: Vec<Frame> = frames_all
        .into_iter()
        .filter(|f| {
            let len = f.exit_idx.saturating_sub(f.enter_idx) + 1;
            f.fn_pc != 0 && (3..=max_inst_len).contains(&len)
        })
        .collect();
    if frames.is_empty() {
        return;
    }

    // Group by fn_pc.
    let mut by_pc: HashMap<u64, Vec<Frame>> = HashMap::new();
    for f in frames {
        by_pc.entry(f.fn_pc).or_default().push(f);
    }

    // Score: total records covered.
    let score = |fs: &[Frame]| -> usize {
        fs.iter()
            .map(|f| f.exit_idx.saturating_sub(f.enter_idx) + 1)
            .sum()
    };

    // Rank descending.
    let mut ranked: Vec<(u64, Vec<Frame>)> = by_pc.into_iter().collect();
    ranked.sort_by_key(|(_, fs)| std::cmp::Reverse(score(fs)));

    // Promote top-K above min_records.
    let module_base = top.module_base;
    let mut new_fns: Vec<FuncIR> = Vec::new();
    for (fn_pc, instances) in ranked.into_iter().take(top_k) {
        let records = score(&instances);
        if records < min_records {
            continue;
        }

        // Resolve name: SymbolMap > sub_<offset>.
        let (sym_name, _) = sym.lookup(fn_pc);
        let name = if sym_name.is_empty() || sym_name == "?" {
            format!("sub_{:x}", fn_pc.wrapping_sub(module_base))
        } else {
            sym_name
        };

        let first_idx = instances.iter().map(|f| f.enter_idx).min().unwrap_or(0);
        let last_idx = instances.iter().map(|f| f.exit_idx).max().unwrap_or(0);

        // M3-ζ fills blocks/calls/loops; M3-ε emits structural metadata only.
        new_fns.push(FuncIR {
            id: format!("F{}", top.fns.len() + new_fns.len()),
            name,
            pc_start: fn_pc,
            pc_end: fn_pc, // M3-ζ: max(b.end_pc) when blocks land
            entry_idx: first_idx,
            exit_idx: last_idx,
            exec_count: instances.len() as u64,
            ..Default::default()
        });
    }
    top.fns.extend(new_fns);
}
```

- [ ] **Step 3: Update `build_trace_ir` signature**

Change the existing `pub fn build_trace_ir(trace, meta, sym) -> TopIR` to accept `top_k` and `min_records`:

```rust
/// Build a TopIR from a loaded Trace.
///
/// `top_k`: max number of bl-target callees to promote to standalone
///   FuncIR entries (F1..Fn). 0 = root only (skeleton).
/// `min_records`: minimum total records a callee must cover to be
///   promoted. Filters out trivial callees.
///
/// Defaults match Python webui: top_k=10, min_records=50
/// (`webui/server.py:2734-2735`).
pub fn build_trace_ir(
    trace: &Trace,
    meta: &TraceMeta,
    sym: &SymbolMap,
    top_k: usize,
    min_records: usize,
) -> TopIR {
    let mut top = build_root_only(trace, meta, sym);
    if top_k > 0 {
        split_top_k_callees(&mut top, trace, sym, top_k, min_records);
    }
    top
}

/// Internal: emit just the root F0 FuncIR + metadata. Extracted from
/// the M3-δ skeleton body to make split_top_k_callees orthogonal.
fn build_root_only(trace: &Trace, meta: &TraceMeta, sym: &SymbolMap) -> TopIR {
    // ... existing body of build_trace_ir from M3-δ Task 3 — no changes
}
```

(Refactor: the existing body of `build_trace_ir` becomes `build_root_only`. The new `build_trace_ir` is a thin wrapper that calls `build_root_only` then `split_top_k_callees`.)

- [ ] **Step 4: Add 2 colocated tests**

Append to the existing `#[cfg(test)] mod tests` block in `builder.rs`:

```rust
    #[test]
    fn build_trace_ir_with_callee_splits_emits_f1_when_threshold_met() {
        // Reuse the synth_two_callees fixture from calltree.rs / taint.rs.
        // f_root → bl f_alpha (2 records) → ret; bl f_beta (3 records) → ret ret ret.
        // f_alpha range=2 records; below min_records=3 → not promoted.
        // f_beta range=3 records; meets min_records=3 → promoted as F1.
        let dir = synth_two_callees();
        let t = load_two_callees(&dir);
        let meta = load_meta_two_callees(&dir);
        let sym = build_sym_two_callees();

        // top_k=10, min_records=3 → only f_beta promoted.
        let top = build_trace_ir(&t, &meta, &sym, 10, 3);
        assert!(top.fns.len() >= 2, "expected F0 + at least F1, got {top:?}");
        let names: Vec<&str> = top.fns.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.contains(&"f_beta"),
            "f_beta should promote to F1; got {names:?}"
        );
        let f1 = top.fns.iter().find(|f| f.name == "f_beta").unwrap();
        assert_eq!(f1.id, "F1");
        assert!(f1.exec_count >= 1);
    }

    #[test]
    fn build_trace_ir_top_k_zero_skips_callee_splits() {
        let dir = synth_two_callees();
        let t = load_two_callees(&dir);
        let meta = load_meta_two_callees(&dir);
        let sym = build_sym_two_callees();
        let top = build_trace_ir(&t, &meta, &sym, 0, 3);
        assert_eq!(top.fns.len(), 1, "top_k=0 → root only; got {top:?}");
        assert_eq!(top.fns[0].id, "F0");
    }
```

You'll need to add `synth_two_callees`, `load_two_callees`, `load_meta_two_callees`, `build_sym_two_callees` helpers if not already in the test module. The 9-record root+2-callees fixture from `calltree.rs::tests::synth_trace_dir` is the precedent — copy it into `builder.rs::tests` (intentional duplication; same justification as Task 1 of M3-α). The fixture meta.json should include `known_offsets: {"0x100": "f_alpha", "0x200": "f_beta"}` so `sym.lookup(0x100100)` returns `"f_alpha"`.

If the existing M3-δ tests `build_trace_ir_emits_root_funcir`, `build_trace_ir_unknown_root_uses_sub_hex_name`, `build_trace_ir_empty_trace_returns_metadata_only` break because of the signature change, update their `build_trace_ir(...)` call sites to pass `0, 0` (top_k=0 disables splits — same as M3-δ behavior).

- [ ] **Step 5: Verify**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo test -p tracemiku-core --lib decompiler 2>&1 | tail -15
cargo test -p tracemiku-core 2>&1 | grep "test result:" | tail -5
cargo clippy -p tracemiku-core --tests 2>&1 | tail -5
```

Expected: 5 builder tests + 2 backend tests + 3 ir tests = 10 decompiler tests pass. No regressions elsewhere. Clippy clean.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-core/src/decompiler/builder.rs
git commit -m "feat(core): decompiler::builder — split_top_k_callees (metadata only)"
```

---

## Task 2: Symbol-source fallback in `/api/dec/summary` + tighten parity

**Files:**
- Modify: `rust/crates/tracemiku-server/src/state.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/dec_summary.rs`
- Modify: `rust/crates/tracemiku-server/tests/test_dec_summary_route.rs`
- Modify: `scripts/m3_delta_parity.py`

- [ ] **Step 1: Update AppState to pass top_k=10, min_records=50**

In `rust/crates/tracemiku-server/src/state.rs`, change the `build_trace_ir(&trace, &meta, &symbols)` call to:

```rust
        let top_ir = build_trace_ir(&trace, &meta, &symbols, 10, 50);
```

(Matches Python webui defaults at `webui/server.py:2734-2735`.)

- [ ] **Step 2: Add symbol-source fallback in handler**

In `rust/crates/tracemiku-server/src/routes/dec_summary.rs`, after collecting the trace-ir `fns: Vec<DecFnEntry>`:

```rust
    // Symbol-source fallback (Python parity at webui/server.py:2745-2755):
    // for each FunctionIndex entry with source=="symbol" whose name isn't
    // already in the trace-ir set, append as a sym-source DecFnEntry.
    let trace_names: std::collections::HashSet<String> =
        fns.iter().map(|f| f.name.clone()).collect();
    let mut fns = fns;
    for entry in &inner.function_index.entries {
        if entry.source != "symbol" {
            continue;
        }
        if trace_names.contains(&entry.name) {
            continue;
        }
        fns.push(DecFnEntry {
            id: entry.id.clone(),    // already "sym:<name>" form
            name: entry.name.clone(),
            blocks: entry.blocks as usize,
            loops: 0,
            calls: 0,
            type_anchors: 0,
            entry_idx: None,
            exit_idx: None,
            source: "symbol",
            trace_ir_id: None,
        });
    }
```

(`entry.id` is already in `sym:<name>` form — `tracemiku-core::function_index::make_sym_id` was used at index-build time.)

- [ ] **Step 3: Update existing test + add new test**

The existing test `dec_summary_emits_root_funcir_with_trace_ir_source` asserts `fns.len() == 1`. Update to `fns.len() >= 1` since the symbol-source fallback may add entries.

Add a new test:

```rust
#[tokio::test]
async fn dec_summary_includes_symbol_source_fallback() {
    // Use a fixture with 2+ named symbols beyond the root, so the
    // FunctionIndex sym-source has something to add to /api/dec/summary.
    //
    // Reuse the 9-record root+2-callees fixture (or build a fresh one).
    // known_offsets: { "0x0": "f_root", "0x100": "f_alpha", "0x200": "f_beta" }
    // → SymbolMap has 3 names; FunctionIndex emits 3 sym entries; trace-ir
    //   adds F0=f_root (top-K=0 in skeleton, so no F1/F2). Symbol fallback
    //   adds f_alpha + f_beta as sym:* entries.
    //
    // Expected fns: [trace:F0=f_root, sym:f_alpha, sym:f_beta] (or 4 if
    //   top_k>=1 promotes f_beta). Pin: at least one sym-source entry
    //   shows up.
    let dir = synth_two_callees_fixture();   // implement using same 9-rec layout
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/summary")
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
    let fns = v["fns"].as_array().unwrap();
    let sources: Vec<&str> = fns
        .iter()
        .map(|f| f["source"].as_str().unwrap())
        .collect();
    assert!(
        sources.contains(&"symbol"),
        "expected at least one symbol-source entry in fns; got sources={sources:?}"
    );
    let sym_names: Vec<&str> = fns
        .iter()
        .filter(|f| f["source"] == "symbol")
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert!(
        sym_names.iter().any(|n| *n == "f_alpha" || *n == "f_beta"),
        "expected f_alpha or f_beta in sym-source fns; got {sym_names:?}"
    );
}

fn synth_two_callees_fixture() -> tempfile::TempDir {
    use std::fs;
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_9r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let pcs: [u64; 9] = [
        0x100000, 0x100004, 0x100100, 0x100104, 0x100008, 0x100200, 0x100204, 0x100208,
        0x10000c,
    ];
    let insts: [u32; 9] = [
        0xd503201f, 0x9400003f, 0xd503201f, 0xd65f03c0, 0x9400007e, 0xd503201f, 0xd503201f,
        0xd65f03c0, 0xd65f03c0,
    ];
    let mut buf = vec![0u8; 272 * 9];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":9,"known_offsets":{"0x0":"f_root","0x100":"f_alpha","0x200":"f_beta"}}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536},"method":"f","cmd":42}"#,
    )
    .unwrap();
    dir
}
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p tracemiku-server --test test_dec_summary_route 2>&1 | tail -10
cargo test -p tracemiku-server 2>&1 | grep "test result:" | tail -5
cargo clippy -p tracemiku-server --tests 2>&1 | tail -5
cargo build --release -p tracemiku-server 2>&1 | tail -3
```

Expected: 2 dec_summary tests pass. All other server tests still pass.

- [ ] **Step 5: Tighten parity gate**

Edit `scripts/m3_delta_parity.py`. Replace:

```python
        # M3-δ skeleton emits only the trace-ir root F0; Python
        # emits trace-ir top-K + symbol-source fallback. Soft-gate
        # the parity until M3-ε ports the symbol-source path.
        SOFT_LABELS = {"dec-summary"}
```

With:

```python
        # M3-ε closed the soft-gate by porting:
        #   1. split_top_k_callees in build_trace_ir (F1..Fn entries)
        #   2. symbol-source fallback in /api/dec/summary handler
        # Both endpoints are now hard-gated; jaccard ≥ 0.6 required.
        SOFT_LABELS: set[str] = set()
```

- [ ] **Step 6: Run parity**

```bash
cd /home/ltlly/Code/traceMiku
uv run python scripts/m3_delta_parity.py traces/test_hide_only/calls/_truncated_call_002_tid27340_469639r_1641ms 2>&1 | tail -8
```

Expected: `OK — dec-summary (py=N / rs=N; jaccard=0.X)` with jaccard ≥ 0.6.

If jaccard is still low, investigate: does Python emit `cfg:<name>` legacy IDs that Rust's `sym:<name>` doesn't match? Check by sampling `py-only` and `rs-only` from the dump. The `tracemiku-core::function_index::parse_id` legacy alias path (M2-ε) should handle `cfg:<name>` → `sym:<name>` already, but the wire emission might differ.

If a real third divergence shows up that's not just `cfg:` vs `sym:` aliasing, **STOP and report BLOCKED** — don't lower tolerance.

- [ ] **Step 7: Commit**

```bash
git add rust/crates/tracemiku-server/src/state.rs \
        rust/crates/tracemiku-server/src/routes/dec_summary.rs \
        rust/crates/tracemiku-server/tests/test_dec_summary_route.rs \
        scripts/m3_delta_parity.py
git commit -m "$(cat <<'EOF'
feat(server): /api/dec/summary — symbol-source fallback + parity tighten

Closes the M3-δ soft-gated dec-summary parity. Two changes:

  1. AppState calls build_trace_ir(trace, meta, sym, 10, 50) — same
     defaults as Python webui (split_top_k=10, split_min_records=50).
     Top-K bl-target callees promote to F1..Fn FuncIR entries.

  2. dec_summary_handler merges in inner.function_index entries with
     source=="symbol" whose names aren't already in the trace-ir set.
     Mirrors webui/server.py:2745-2755 line-for-line.

Re-tightens scripts/m3_delta_parity.py: SOFT_LABELS now empty.

New test: dec_summary_includes_symbol_source_fallback pins that
f_alpha and f_beta surface as sym:* entries on the 9-rec fixture.

Live parity result on traces/test_hide_only:
  py=82 / rs=N (≥ 49 to clear 0.6 jaccard threshold).

M3-ε Task 2.
EOF
)"
```

---

## Task 3: Spec/TODO sync

**Files:**
- Modify: `TODO.md`
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`

- [ ] **Step 1: Update spec rows**

`docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`:
- `builder.py` row: 🟡 M3-δ → 🟡 M3-ε (callee splits + symbol fallback shipped; BlockIR construction + render_summary_md fidelity defer to M3-ζ).
- `/api/dec/summary` row: 🟡 M3-δ → ✅ M3-ε (parity hard-gated).

- [ ] **Step 2: Update TODO.md**

Append:

```markdown
- M3-ε split_top_k_callees in build_trace_ir (metadata only, no BlockIR yet): ✅ 2026-05-04
- M3-ε /api/dec/summary symbol-source fallback + parity hard-gate: ✅ 2026-05-04
```

Refine M3-ζ pointer to absorb the deferred items:

```markdown
- M3-ζ (next): BlockIR construction (asm/samples/exits/tier classification),
  /api/dec/fn/{id} per-fn markdown, render_summary_md fidelity,
  type_anchor.py port (json-spec driven), vm_candidate.py port
- M3-η: Graph panel SVG (cfg-svg via petgraph or graphviz-rust)
- M3-θ: memshadow v3 binary sidecar (.memshadow.v3.bin)
- M3-ι: Python viewer cutover prep (CLI parity + remove webui after manual sign-off)
```

- [ ] **Step 3: Final commit**

```bash
git add TODO.md docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md
git commit -m "docs(v2): mark M3-ε complete (dec-summary parity closed)"
```

---

## Self-Review

**Spec coverage:**
| Item | Task |
|---|---|
| split_top_k_callees metadata-only | Task 1 |
| Symbol-source fallback in /api/dec/summary | Task 2 |
| Parity hard-gate restored | Task 2 Step 5 |
| Docs sync | Task 3 |

**Out of scope (deferred to M3-ζ):**
- BlockIR construction (asm/samples/exits/exec_count/tier classification per block)
- /api/dec/fn/{id} per-fn markdown bundle
- /api/dec/llm-call LLM bundle
- render_summary_md fidelity (Python's pretty markdown — current Rust output is one-line text)
- type_anchor.py port (TypeAnchorIR population from JSON specs)
- vm_candidate.py port (VmCandidateIR detection)
- Loop detection (LoopIR + InductionVarIR)

**Type consistency:**
- `build_trace_ir` signature gains `top_k: usize, min_records: usize` parameters at the end. AppState updated to match.
- `Frame` is a private internal type in builder.rs.
- `flatten_calltree` and `split_top_k_callees` return / mutate types from `decompiler::ir`.

**Risk:** The Python algorithm at `viewer/decompiler/builder.py:54-203` does TWO things M3-ε explicitly skips:
1. Per-block PC mask + asm/samples extraction (lines 105-178). M3-ε emits FuncIR with `blocks: vec![]` instead.
2. numpy-vectorized PC array operations. The M3-ε metadata-only path doesn't need them.

The parity comparison is on the `fns[].id` set (not on `fns[].blocks` count), so the two skipped pieces don't affect M3-ε parity. They DO affect future M3-ζ /api/dec/fn/{id} fidelity — which is exactly why they're scoped there.

---

**Plan complete and saved.** Per `CLAUDE.md` user-pref §"Skip the 'Two execution options' handoff" — execution proceeds via `superpowers:subagent-driven-development`.
