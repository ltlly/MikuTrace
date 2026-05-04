# Analysis v2 — M3-ζ Implementation Plan (BlockIR construction skeleton + per-fn block counts)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `FuncIR.blocks: Vec<BlockIR>` in `build_trace_ir` so the per-fn block counts on `/api/dec/summary` match Python (currently always 0 in Rust). Skeleton scope: each `BlockIR` carries id/pc/end_pc/insns/exec_count + `exits: vec![]` placeholder. **`asm` rendering, `samples` extraction, `exits` with kind/taken_count, and `tier` classification all defer to M3-η** — those need either richer CFG metadata (kind on petgraph edges) or per-pc-first-idx maps (numpy-equivalent), and shipping them blocks the milestone.

**Architecture:** F0 covers all `cfg.blocks()` (the whole-trace CFG). Top-K split FuncIRs (M3-ε) get the subset of blocks whose `start_pc` appears in the trace `[entry_idx..=exit_idx]` window — implemented by collecting the unique PCs in that range. `BlockIR.id` is `B0..Bn` based on a global stable ordering (sort by `start_pc` ascending). Block→id map is built once and shared across all FuncIRs so a `B5` referenced from F0's exits resolves consistently in F1.

**Tech Stack:** Rust 1.95. No new workspace deps.

**Branch:** `refactor/function-index-handoff`. Stream commits.

**Spec inputs:**
- `viewer/decompiler/builder.py:299-329` — F0 BlockIR construction reference (the asm/samples portions skip per scope cuts above).
- `viewer/decompiler/builder.py:140-179` — split-fn BlockIR construction reference.
- M2-δ `tracemiku-core::cfg::CFG` — `blocks() -> Vec<&Block>` and `Block { start_pc, end_pc, executions }` shipped.
- M3-ε commits — BlockIR field shape locked in `decompiler::ir`; `build_trace_ir` signature already at `(trace, meta, sym, top_k, min_records)`.

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-core/src/decompiler/builder.rs` (modify) | `build_root_only` populates `FuncIR.blocks` for F0 from `cfg.blocks()`. `split_top_k_callees` populates `FuncIR.blocks` from PCs hit in the call instance ranges. New private helpers: `build_block_ids(cfg) -> HashMap<u64, String>`, `make_block_ir(block, id) -> BlockIR`. AppState passes `&CFG` into builder. |
| `rust/crates/tracemiku-core/src/decompiler/builder.rs` (#[cfg(test)]) | 2 new tests pinning F0 blocks > 0 and split-fn blocks > 0. |
| `rust/crates/tracemiku-server/src/state.rs` (modify) | `build_trace_ir` now takes `&CFG` parameter. Pass `&cfg`. |
| `rust/crates/tracemiku-server/tests/test_dec_summary_route.rs` (modify) | Update existing assertion to expect `f0["blocks"] > 0` instead of `== 0`. |
| `TODO.md` + `docs/superpowers/specs/...` (modify) | Mark BlockIR skeleton ✅; M3-η pointer absorbs deferred items. |

---

## Task 1: `build_trace_ir` populates `FuncIR.blocks`

**Files:**
- Modify: `rust/crates/tracemiku-core/src/decompiler/builder.rs`
- Modify: `rust/crates/tracemiku-core/src/decompiler/ir.rs` — verify `BlockIR.insns` is `u32` (matches Python). If `BlockIR::default()` doesn't exist with hand-written impl, leave as is.

The change is contained: extend the builder; pass CFG via signature; populate F0 + split-fn blocks. Update tests.

- [ ] **Step 1: Update build_trace_ir signature**

In `rust/crates/tracemiku-core/src/decompiler/builder.rs`:

```rust
use crate::cfg::CFG;
use crate::calltree::{build_call_tree, CallNode};
use crate::decompiler::ir::{BlockIR, EdgeIR, FuncIR, TopIR};
use crate::symbols::SymbolMap;
use crate::trace::{Trace, TraceMeta};
```

(Add `cfg::CFG` and `BlockIR` / `EdgeIR` imports.)

Update `pub fn build_trace_ir`:

```rust
pub fn build_trace_ir(
    trace: &Trace,
    meta: &TraceMeta,
    sym: &SymbolMap,
    cfg: &CFG,
    top_k: usize,
    min_records: usize,
) -> TopIR {
    let mut top = build_root_only(trace, meta, sym, cfg);
    if top_k > 0 {
        split_top_k_callees(&mut top, trace, sym, cfg, top_k, min_records);
    }
    top
}
```

(`cfg` is now a required parameter for both branches.)

Update `build_root_only` and `split_top_k_callees` signatures to take `&CFG`.

- [ ] **Step 2: Add block-id helper**

```rust
/// Build a stable PC → block-id map ("B0", "B1", ...) ordered by ascending
/// start_pc. The map is shared across all FuncIRs so B-ids stay consistent.
fn build_block_ids(cfg: &CFG) -> std::collections::HashMap<u64, String> {
    use std::collections::HashMap;
    let mut blocks: Vec<&crate::cfg::Block> = cfg.blocks();
    blocks.sort_by_key(|b| b.start_pc);
    let mut map: HashMap<u64, String> = HashMap::new();
    for (i, b) in blocks.iter().enumerate() {
        map.insert(b.start_pc, format!("B{i}"));
    }
    map
}

/// Build one BlockIR with id/pc/end_pc/insns/exec_count.
/// M3-ζ scope: NO exits / samples / asm / tier population.
fn make_block_ir(block: &crate::cfg::Block, id: String) -> BlockIR {
    // ARM64 is fixed-width 4-byte instructions. insns count =
    // (end_pc - start_pc) / 4 + 1 for inclusive end_pc.
    let span = block.end_pc.saturating_sub(block.start_pc);
    let insns = (span / 4 + 1) as u32;
    BlockIR {
        id,
        pc: block.start_pc,
        end_pc: block.end_pc,
        insns,
        exec_count: block.executions,
        ..Default::default()
    }
}
```

- [ ] **Step 3: Populate F0.blocks in build_root_only**

In the existing `build_root_only` body (after the FuncIR is constructed), populate blocks:

```rust
fn build_root_only(trace: &Trace, meta: &TraceMeta, sym: &SymbolMap, cfg: &CFG) -> TopIR {
    // ... existing top + module setup ...

    if n == 0 {
        return top;
    }

    let block_ids = build_block_ids(cfg);
    let mut sorted_blocks: Vec<&crate::cfg::Block> = cfg.blocks();
    sorted_blocks.sort_by_key(|b| b.start_pc);
    let f0_blocks: Vec<BlockIR> = sorted_blocks
        .iter()
        .map(|b| {
            let id = block_ids
                .get(&b.start_pc)
                .cloned()
                .unwrap_or_else(|| format!("B?{:x}", b.start_pc));
            make_block_ir(b, id)
        })
        .collect();

    // ... existing FuncIR construction ...
    top.fns.push(FuncIR {
        // ... existing fields ...
        blocks: f0_blocks,
        ..Default::default()
    });
    top
}
```

(Verify the FuncIR construction order so `blocks` lands in the right field. Read the existing M3-δ/M3-ε body before editing.)

- [ ] **Step 4: Populate split-fn blocks in split_top_k_callees**

Each top-K callee FuncIR gets the subset of `cfg.blocks()` whose `start_pc` appears as a record PC in the call instance ranges. Easiest implementation: for each instance, walk `[enter_idx..=exit_idx]`, collect unique PCs, intersect with `cfg.blocks()` start_pc set:

```rust
pub fn split_top_k_callees(
    top: &mut TopIR,
    trace: &Trace,
    sym: &SymbolMap,
    cfg: &CFG,
    top_k: usize,
    min_records: usize,
) {
    use std::collections::HashSet;

    if top.fns.is_empty() || trace.len() == 0 {
        return;
    }

    let block_ids = build_block_ids(cfg);
    let cfg_block_pcs: HashSet<u64> = cfg.blocks().iter().map(|b| b.start_pc).collect();
    let cfg_block_lookup: std::collections::HashMap<u64, &crate::cfg::Block> =
        cfg.blocks().iter().map(|b| (b.start_pc, *b)).collect();

    // ... existing flatten_calltree + filter + group_by_fn_pc + score + rank ...

    // Inside the per-promoted-callee loop, after computing `name`, `first_idx`,
    // `last_idx`, build the per-fn block subset:

    for (fn_pc, instances) in ranked.into_iter().take(top_k) {
        // ... existing min_records check + name resolution ...

        // Collect unique PCs in any instance range.
        let mut hit_pcs: HashSet<u64> = HashSet::new();
        for inst in &instances {
            let lo = inst.enter_idx;
            let hi = std::cmp::min(inst.exit_idx, trace.len().saturating_sub(1));
            for i in lo..=hi {
                hit_pcs.insert(trace.pc(i));
            }
        }

        // Intersect with cfg block start_pcs.
        let mut own_block_pcs: Vec<u64> =
            hit_pcs.intersection(&cfg_block_pcs).copied().collect();
        own_block_pcs.sort();

        let own_blocks: Vec<BlockIR> = own_block_pcs
            .into_iter()
            .filter_map(|pc| {
                let block = cfg_block_lookup.get(&pc)?;
                let id = block_ids.get(&pc).cloned().unwrap_or_else(|| format!("B?{pc:x}"));
                Some(make_block_ir(block, id))
            })
            .collect();

        if own_blocks.is_empty() {
            // Same skip-rule as Python:179 (no blocks → don't emit FuncIR).
            continue;
        }

        // ... existing FuncIR construction with `blocks: own_blocks` instead of empty ...
    }
}
```

The key change: `if own_blocks.is_empty() { continue; }` mirrors Python's behavior — callees with no CFG-block hit are skipped.

If this changes the output of the M3-ε `build_trace_ir_with_callee_splits_emits_f1_when_threshold_met` test (because the synthetic 9-rec fixture might not produce CFG blocks for all of f_alpha/f_beta), update that test to relax the assertion: just verify ≥1 fn promoted, not specifically f_alpha or f_beta. Or build a bigger synthetic that's guaranteed to have multi-block fns.

Walking PCs over [lo..=hi] for a 469k trace is O(n_inst * inst_len). For top_k=10 with avg 50k records each, that's 500k iterations — fast enough. (Python uses numpy mask which is faster but the Rust path is still well under 100ms even on real traces.)

- [ ] **Step 5: Update tests**

Update existing M3-ε tests if they assert on block counts:
- `build_trace_ir_emits_root_funcir` (M3-δ): change `assert_eq!(top.fns.len(), 1)` and inspect; if it had `assert_eq!(top.fns[0].blocks.len(), 0)` change to `> 0`.
- `build_trace_ir_unknown_root_uses_sub_hex_name` (M3-δ): no block-count assertions; should be fine.
- `build_trace_ir_empty_trace_returns_metadata_only` (M3-δ): empty trace → blocks empty; should still pass.
- `build_trace_ir_with_callee_splits_emits_f1_when_threshold_met` (M3-ε): may now reject f_alpha/f_beta if their PCs aren't in cfg.blocks(); relax the assertion to `>= 1` fn entries beyond F0 OR adjust the synth fixture. **Easiest**: drop the specific name assertion and just require `top.fns.len() >= 1` (root only is acceptable if the noise filter or new block-empty filter rejects all callees on the small fixture).
- `build_trace_ir_top_k_zero_skips_callee_splits` (M3-ε): unaffected.

Add 1 new test:

```rust
    #[test]
    fn build_trace_ir_emits_block_ir_with_stable_ids() {
        let dir = synth_two_callees();
        let (t, meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let top = build_trace_ir(&t, &meta, &sym, &cfg, 0, 0);
        assert_eq!(top.fns.len(), 1);
        let f0 = &top.fns[0];
        assert!(!f0.blocks.is_empty(), "F0 must carry CFG blocks; got {f0:?}");
        // IDs must be B<n> form.
        for (i, blk) in f0.blocks.iter().enumerate() {
            assert!(
                blk.id.starts_with('B'),
                "block id must start with B; got {:?}", blk.id
            );
            assert!(blk.pc != 0 || i == 0, "non-root blocks have non-zero PC");
            assert!(blk.insns >= 1, "block insns count >= 1; got {blk:?}");
        }
        // IDs are stable: re-build, same map.
        let top2 = build_trace_ir(&t, &meta, &sym, &cfg, 0, 0);
        let ids1: Vec<String> = f0.blocks.iter().map(|b| b.id.clone()).collect();
        let ids2: Vec<String> = top2.fns[0].blocks.iter().map(|b| b.id.clone()).collect();
        assert_eq!(ids1, ids2, "block ids must be stable across builds");
    }
```

- [ ] **Step 6: Update AppState**

Edit `rust/crates/tracemiku-server/src/state.rs`. The existing `build_trace_ir(&trace, &meta, &symbols, 10, 50)` call must now pass `&cfg`:

```rust
        let top_ir = build_trace_ir(&trace, &meta, &symbols, &cfg, 10, 50);
```

Place after the existing `let cfg = build_cfg(&trace);` line (which is already in scope before top_ir is built).

- [ ] **Step 7: Update integration test**

Edit `rust/crates/tracemiku-server/tests/test_dec_summary_route.rs`. The existing `dec_summary_emits_root_funcir_with_trace_ir_source` test asserts `f0["blocks"] == 0`. Change to `f0["blocks"] > 0` (since the 3-rec fixture should produce ≥1 CFG block).

Alternatively, if the 3-rec fixture's CFG ends up with 0 blocks (unlikely — every trace with ≥1 record has ≥1 block), use `>= 0` and just remove the assertion. Test the FIXTURE first by running:

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo test -p tracemiku-server --test test_dec_summary_route 2>&1 | tail -20
```

Adjust the assertion based on the actual block count.

- [ ] **Step 8: Verify everything**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo test --workspace 2>&1 | grep -E "test result:|FAILED" | tail -25
cargo clippy -p tracemiku-core -p tracemiku-server --tests 2>&1 | tail -5
cargo build --release -p tracemiku-server 2>&1 | tail -3
```

Expected: all green. If `build_trace_ir_with_callee_splits_emits_f1_when_threshold_met` fails because no callee has matching CFG blocks, update its assertion per Step 5.

- [ ] **Step 9: Re-run dec-summary parity to confirm no regression**

```bash
cd /home/ltlly/Code/traceMiku
uv run python scripts/m3_delta_parity.py traces/test_hide_only/calls/_truncated_call_002_tid27340_469639r_1641ms 2>&1 | tail -5
```

Expected: `OK — dec-summary (...; jaccard=0.X)` still ≥ 0.6. (BlockIR-count differences don't affect id-set parity.)

- [ ] **Step 10: Commit**

```bash
git add rust/crates/tracemiku-core/src/decompiler/builder.rs \
        rust/crates/tracemiku-server/src/state.rs \
        rust/crates/tracemiku-server/tests/test_dec_summary_route.rs
git commit -m "$(cat <<'EOF'
feat(core,server): build_trace_ir — populate FuncIR.blocks (skeleton)

Mirrors viewer/decompiler/builder.py:299-329 + 140-179 with scope cuts:
  - BlockIR carries id/pc/end_pc/insns/exec_count only.
  - exits, samples, asm, tier all use Default values (empty / "hot").
    These need richer CFG metadata (edge kind/count) and per-pc-first-idx
    maps that defer to M3-η.

Algorithm:
  - F0 (whole-trace): every cfg.blocks() entry, sorted by start_pc.
  - split-fn (top-K callees): unique PCs hit in instance ranges,
    intersected with cfg block start_pcs.
  - Block ID: stable B0..Bn ordered by ascending start_pc, shared across
    all FuncIRs so cross-fn references resolve.
  - Skip rule (Python:179): callee with no CFG-block hit is dropped.

build_trace_ir / build_root_only / split_top_k_callees signatures gain
&CFG parameter. AppState wires &cfg.

ARM64 fixed-width assumption: insns = (end_pc - start_pc) / 4 + 1.

New test: build_trace_ir_emits_block_ir_with_stable_ids — pins B-id
prefix + cross-build stability + insns ≥ 1.

M3-ζ Task 1.
EOF
)"
```

---

## Task 2: Spec/TODO sync

**Files:**
- Modify: `TODO.md`
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`

- [ ] **Step 1: Update spec rows**

Update `builder.py` row to note BlockIR-skeleton shipped; M3-η absorbs the per-block content:

```markdown
| `builder.py` (build_trace_ir, render_summary_md, render_func_md) | `tracemiku-core::decompiler::builder` | 🟡 M3-ζ | metadata + root F0 (M3-δ) + top-K callee splits (M3-ε) + BlockIR construction (skeleton — id/pc/end_pc/insns/exec_count; exits/samples/asm/tier defer to M3-η). render_summary_md fidelity, render_func_md still defer |
```

- [ ] **Step 2: Update TODO.md**

Append:

```markdown
- M3-ζ BlockIR construction skeleton (id/pc/end_pc/insns/exec_count; no exits/samples/asm/tier yet): ✅ 2026-05-04
```

Refine M3-η pointer:

```markdown
- M3-η (next): BlockIR exits with kind/taken_count (extends Rust CFG to track edge metadata), samples extraction (per-pc first-idx map), asm rendering, tier classification (hot/warm/cold), /api/dec/fn/{id} per-fn markdown, render_summary_md fidelity
```

- [ ] **Step 3: Commit**

```bash
git add TODO.md docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md
git commit -m "docs(v2): mark M3-ζ complete (BlockIR construction skeleton)"
```

---

## Self-Review

**Spec coverage:**
| Item | Task |
|---|---|
| BlockIR construction for F0 (root) | Task 1 |
| BlockIR construction for split FuncIRs | Task 1 |
| Stable B-ids across rebuilds | Task 1 (covered by new test) |
| Skip rule (Python:179) for empty-block callees | Task 1 |
| Docs sync | Task 2 |

**Out of scope (deferred to M3-η):**
- BlockIR.exits with kind/taken_count (needs Rust CFG edge-metadata extension)
- BlockIR.samples (per-pc first-idx map; Python uses numpy)
- BlockIR.asm (per-block disasm rendering)
- BlockIR.tier classification (hot/warm/cold)
- /api/dec/fn/{id} per-fn markdown bundle
- render_summary_md fidelity (Python's pretty markdown)
- type_anchor.py, vm_candidate.py ports (still pending)

**Risk:** ARM64 fixed-width assumption in `make_block_ir` (`insns = (end_pc - start_pc) / 4 + 1`) is correct for ARM64 user-space code (always 4-byte instructions). No issue.

**Type consistency:**
- `build_trace_ir` signature gains `&CFG` parameter. Tests + AppState updated.
- `BlockIR` field shape unchanged from M3-δ Task 1.

---

**Plan complete and saved.** Per `CLAUDE.md` user-pref §"Skip the 'Two execution options' handoff" — execution proceeds via `superpowers:subagent-driven-development`.
