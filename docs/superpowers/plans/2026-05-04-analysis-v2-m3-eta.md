# Analysis v2 — M3-η Implementation Plan (BlockIR.asm + samples + tier)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `BlockIR.asm` (per-block disasm rendering), `BlockIR.samples` (first-execution snapshot of x0..x3 + sp), and `BlockIR.tier` (`"hot"` for top-K by exec_count, `"warm"` for the rest with exec_count>0, `"cold"` for unexecuted — though the Rust CFG only contains executed blocks, so cold is currently never produced). The asm + samples both hinge on a per-PC first-idx map computed once per `build_trace_ir` call. Defer `BlockIR.exits` (still empty Vec) — it requires extending the Rust `CFG` to track edge metadata, a separate refactor.

**Architecture:** One pass over the trace builds `HashMap<u64, usize>` mapping each unique PC to its first-occurrence record idx. For each `BlockIR`, fill `samples` from the record at the start_pc's first idx (read `x0..x3` + `sp`); fill `asm` by stepping `block.start_pc..=block.end_pc` in 4-byte strides and decoding each via `disasm::decode`. After all blocks are built, run `classify_blocks_by_tier`: sort blocks by exec_count desc, mark top-K (default 150) as `"hot"`, others with exec_count > 0 as `"warm"`. The hot-K cap matches `viewer/decompiler/builder.py:206-242`.

**Tech Stack:** Rust 1.95. No new workspace deps.

**Branch:** `refactor/function-index-handoff`. Stream commits.

**Spec inputs:**
- `viewer/decompiler/builder.py:289-329` — F0 BlockIR samples + asm reference.
- `viewer/decompiler/builder.py:140-178` — split-fn BlockIR samples + asm reference.
- `viewer/decompiler/builder.py:206-242` — tier classification.
- `tracemiku-core::trace::Record` (M2-α shipped) — `reg(name)` returns `Option<u64>`, `sp: u64` field.
- `tracemiku-core::disasm::decode(pc, inst) -> DecodedInsn` (M2-β shipped) — `mnemonic`, `op_str` fields.

---

## Task 1: per-PC first-idx map + BlockIR.asm + BlockIR.samples

**Files:**
- Modify: `rust/crates/tracemiku-core/src/decompiler/builder.rs`

The change is contained: add the first-idx map build, thread through `make_block_ir`. Existing M3-ζ tests should still pass with strengthened assertions. Add 1 new test for asm/samples shape.

- [ ] **Step 1: Add first-idx-map helper**

In `decompiler/builder.rs`, near the other helpers:

```rust
use std::collections::HashMap;
use crate::disasm::decode;

/// Build a PC → first-occurrence-record-idx map. One trace pass.
fn build_first_idx_map(trace: &Trace) -> HashMap<u64, usize> {
    let n = trace.len();
    let mut map: HashMap<u64, usize> = HashMap::with_capacity(n.min(1 << 20));
    for i in 0..n {
        let pc = trace.pc(i);
        map.entry(pc).or_insert(i);
    }
    map
}
```

- [ ] **Step 2: Extend `make_block_ir` signature to take the trace + first-idx map**

```rust
fn make_block_ir(
    block: &crate::cfg::Block,
    id: String,
    trace: &Trace,
    first_idx: &HashMap<u64, usize>,
) -> BlockIR {
    let span = block.end_pc.saturating_sub(block.start_pc);
    let insns_count = (span / 4 + 1) as u32;

    // samples: x0..x3 + sp at the first record where this block's start_pc fires.
    // Mirrors viewer/decompiler/builder.py:309-315.
    let mut samples: HashMap<String, i64> = HashMap::new();
    if let Some(&idx) = first_idx.get(&block.start_pc) {
        let rec = trace.record(idx);
        for reg in &["x0", "x1", "x2", "x3"] {
            if let Some(v) = rec.reg(reg) {
                samples.insert((*reg).to_string(), v as i64);
            }
        }
        samples.insert("sp".to_string(), rec.sp as i64);
    }

    // asm: walk block_pc..=end_pc by 4 (ARM64 fixed-width). For each insn-pc,
    // look up first_idx → fetch record's inst word → decode → format.
    // Mirrors viewer/decompiler/builder.py:317-324.
    let mut asm_lines: Vec<String> = Vec::new();
    let mut pc = block.start_pc;
    while pc <= block.end_pc {
        if let Some(&idx) = first_idx.get(&pc) {
            let inst = trace.inst(idx);
            let d = decode(pc, inst);
            asm_lines.push(format!("  {pc:#x}: {} {}", d.mnemonic, d.op_str).trim_end().to_string());
        }
        pc = pc.checked_add(4).unwrap_or(u64::MAX);
        if pc == u64::MAX {
            break;
        }
    }
    let asm = asm_lines.join("\n");

    BlockIR {
        id,
        pc: block.start_pc,
        end_pc: block.end_pc,
        insns: insns_count,
        exec_count: block.executions,
        samples,
        asm,
        ..Default::default()
    }
}
```

- [ ] **Step 3: Wire the first_idx map through callers**

Update `build_root_only` to build the first-idx map once, pass into each `make_block_ir`:

```rust
fn build_root_only(trace: &Trace, meta: &TraceMeta, sym: &SymbolMap, cfg: &CFG) -> TopIR {
    // ... existing top + module setup ...

    if n == 0 {
        return top;
    }

    // ... existing pc0 / pc_last / resolved_name ...

    let block_ids = build_block_ids(cfg);
    let first_idx = build_first_idx_map(trace);
    let mut sorted_blocks: Vec<&crate::cfg::Block> = cfg.blocks();
    sorted_blocks.sort_by_key(|b| b.start_pc);
    let f0_blocks: Vec<BlockIR> = sorted_blocks
        .iter()
        .map(|b| {
            let id = block_ids
                .get(&b.start_pc)
                .cloned()
                .unwrap_or_else(|| format!("B?{:x}", b.start_pc));
            make_block_ir(b, id, trace, &first_idx)
        })
        .collect();

    top.fns.push(FuncIR {
        // ... unchanged fields ...
        blocks: f0_blocks,
        ..Default::default()
    });
    top
}
```

Update `split_top_k_callees` similarly: call `build_first_idx_map` once before the loop, pass into `make_block_ir`:

```rust
pub fn split_top_k_callees(
    top: &mut TopIR,
    trace: &Trace,
    sym: &SymbolMap,
    cfg: &CFG,
    top_k: usize,
    min_records: usize,
) {
    use std::collections::{HashMap, HashSet};
    // ... existing early-returns ...

    let block_ids = build_block_ids(cfg);
    let first_idx = build_first_idx_map(trace);
    let cfg_block_pcs: HashSet<u64> = cfg.blocks().iter().map(|b| b.start_pc).collect();
    let cfg_block_lookup: HashMap<u64, &crate::cfg::Block> =
        cfg.blocks().iter().map(|b| (b.start_pc, *b)).collect();

    // ... existing flatten + filter + group + rank ...

    for (fn_pc, instances) in ranked.into_iter().take(top_k) {
        // ... existing min_records check + hit_pcs collection ...

        let own_blocks: Vec<BlockIR> = own_block_pcs
            .into_iter()
            .filter_map(|pc| {
                let block = cfg_block_lookup.get(&pc)?;
                let id = block_ids.get(&pc).cloned().unwrap_or_else(|| format!("B?{pc:x}"));
                Some(make_block_ir(block, id, trace, &first_idx))
            })
            .collect();

        // ... rest unchanged ...
    }
}
```

- [ ] **Step 4: Add 1 new colocated test**

```rust
    #[test]
    fn build_trace_ir_block_ir_carries_asm_and_samples() {
        let dir = synth_two_callees();
        let (t, meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let top = build_trace_ir(&t, &meta, &sym, &cfg, 0, 0);
        let f0 = &top.fns[0];
        assert!(!f0.blocks.is_empty(), "F0 must have blocks");
        let any_with_asm = f0.blocks.iter().any(|b| !b.asm.is_empty());
        assert!(any_with_asm, "at least one block should have asm; got {f0:?}");
        let any_with_samples = f0.blocks.iter().any(|b| !b.samples.is_empty());
        assert!(any_with_samples, "at least one block should have samples; got {f0:?}");
        // samples should contain sp + x0..x3 keys when populated.
        for blk in &f0.blocks {
            if blk.samples.is_empty() {
                continue;
            }
            assert!(blk.samples.contains_key("sp"), "block {} samples missing sp: {:?}", blk.id, blk.samples);
        }
    }
```

If existing tests previously asserted `f0.blocks[i].samples.is_empty()` or `f0.blocks[i].asm.is_empty()`, update them to `>= 0` (or remove the assertion). Read the existing tests first to know what to relax.

- [ ] **Step 5: Verify**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo test -p tracemiku-core --lib decompiler 2>&1 | tail -15
cargo clippy -p tracemiku-core --tests 2>&1 | tail -5
cargo test -p tracemiku-server 2>&1 | grep "test result:" | tail -5
```

Expected: 12 decompiler tests pass (11 prior + 1 new). Server tests still pass. Clippy clean.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-core/src/decompiler/builder.rs
git commit -m "feat(core): BlockIR — populate asm + samples (per-PC first-idx map)"
```

---

## Task 2: BlockIR.tier classification

**Files:**
- Modify: `rust/crates/tracemiku-core/src/decompiler/builder.rs`

`viewer/decompiler/builder.py:206-242` runs after build is done. Sort all blocks across all FuncIRs by exec_count desc; mark top-K (default 150) as `"hot"`; others with exec_count > 0 as `"warm"`. Cold (exec_count==0) never appears in current Rust CFG (only executed blocks are recorded), so the tier check is `if exec_count > top_k_threshold { "warm" } else { "hot" }`.

- [ ] **Step 1: Add `classify_blocks_by_tier` helper**

```rust
/// In-place tier classification.
///
/// Sorts ALL blocks across ALL FuncIRs by exec_count desc; top-K marked
/// `"hot"`, others marked `"warm"`. exec_count == 0 → `"cold"` (never
/// produced by current Rust CFG since it only records executed blocks).
///
/// Mirrors viewer/decompiler/builder.py:206-242.
pub fn classify_blocks_by_tier(top: &mut TopIR, hot_top_k: usize) {
    // Collect (exec_count, fn_idx, block_idx) triples.
    let mut triples: Vec<(u64, usize, usize)> = Vec::new();
    for (fi, f) in top.fns.iter().enumerate() {
        for (bi, b) in f.blocks.iter().enumerate() {
            triples.push((b.exec_count, fi, bi));
        }
    }
    triples.sort_by(|a, b| b.0.cmp(&a.0));

    // Mark top-K as "hot"; rest with exec_count > 0 as "warm";
    // exec_count == 0 as "cold" (matches Python tier semantics).
    for (rank, (exec_count, fi, bi)) in triples.iter().enumerate() {
        let tier = if *exec_count == 0 {
            "cold"
        } else if rank < hot_top_k {
            "hot"
        } else {
            "warm"
        };
        top.fns[*fi].blocks[*bi].tier = tier.to_string();
    }
}
```

- [ ] **Step 2: Wire into `build_trace_ir`**

After the optional `split_top_k_callees` call:

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
    classify_blocks_by_tier(&mut top, 150);  // Python webui default
    top
}
```

- [ ] **Step 3: Add 1 new colocated test**

```rust
    #[test]
    fn build_trace_ir_classifies_block_tiers() {
        let dir = synth_two_callees();
        let (t, meta, sym) = load_two_callees(&dir);
        let cfg = crate::cfg::build_cfg(&t);
        let top = build_trace_ir(&t, &meta, &sym, &cfg, 0, 0);
        // All blocks should be classified (no default "hot" leak).
        for blk in &top.fns[0].blocks {
            assert!(
                ["hot", "warm", "cold"].contains(&blk.tier.as_str()),
                "block {} tier {:?} not in {{hot,warm,cold}}", blk.id, blk.tier
            );
        }
        // For a 9-record trace with few blocks, all blocks fit in top-150
        // so they're all "hot".
        let all_hot = top.fns[0].blocks.iter().all(|b| b.tier == "hot");
        assert!(all_hot, "small trace blocks all under top-150 → all hot");
    }
```

- [ ] **Step 4: Verify + commit**

```bash
cargo test -p tracemiku-core --lib decompiler 2>&1 | tail -15
cargo clippy -p tracemiku-core --tests 2>&1 | tail -5

git add rust/crates/tracemiku-core/src/decompiler/builder.rs
git commit -m "feat(core): BlockIR — tier classification (hot/warm/cold)"
```

---

## Task 3: Spec/TODO sync

**Files:**
- Modify: `TODO.md`
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`

Mark `builder.py` row 🟡 M3-η; refine M3-θ pointer.

- [ ] **Step 1: Update spec row**

```markdown
| `builder.py` (build_trace_ir, render_summary_md, render_func_md) | `tracemiku-core::decompiler::builder` | 🟡 M3-η | metadata + root F0 (M3-δ) + top-K callee splits (M3-ε) + BlockIR id/pc/end_pc/insns/exec_count (M3-ζ) + asm/samples/tier (M3-η). BlockIR.exits (with kind/taken_count) + render_summary_md fidelity + render_func_md still defer to M3-θ |
```

- [ ] **Step 2: Update TODO.md**

Append:

```markdown
- M3-η BlockIR asm rendering + samples extraction (per-PC first-idx map): ✅ 2026-05-04
- M3-η BlockIR tier classification (hot top-150, warm, cold): ✅ 2026-05-04
```

Refine M3-θ pointer:

```markdown
- M3-θ (next): BlockIR.exits with kind/taken_count (extends Rust CFG to track edge metadata), /api/dec/fn/{id} per-fn markdown, render_summary_md fidelity, type_anchor.py port (json-spec driven), vm_candidate.py port
```

- [ ] **Step 3: Commit**

```bash
git add TODO.md docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md
git commit -m "docs(v2): mark M3-η complete (BlockIR asm + samples + tier)"
```

---

## Self-Review

**Spec coverage:**
| Item | Task |
|---|---|
| Per-PC first-idx map | Task 1 |
| BlockIR.asm rendering | Task 1 |
| BlockIR.samples (x0..x3 + sp) | Task 1 |
| BlockIR.tier classification | Task 2 |
| Docs sync | Task 3 |

**Out of scope (deferred to M3-θ):**
- BlockIR.exits (needs Rust CFG edge-metadata extension)
- /api/dec/fn/{id} per-fn markdown bundle
- render_summary_md fidelity
- type_anchor.py + vm_candidate.py ports

**Risk:** Memory cost of `build_first_idx_map` on a 7M-record trace: ~7M × (8B PC + 8B usize) = ~112 MB peak. Acceptable for one-shot build at AppState load. Python's numpy version uses ~56 MB (32-bit usize); the Rust version is 2× because we use 64-bit. Optimizable later if profiling shows it matters.

**Type consistency:**
- `make_block_ir` signature gains `(trace, first_idx)`. Both callers (`build_root_only` + `split_top_k_callees`) updated.
- `classify_blocks_by_tier` is a separate post-process, not threaded through internal helpers.

---

**Plan complete and saved.** Per `CLAUDE.md` user-pref §"Skip the 'Two execution options' handoff" — execution proceeds via `superpowers:subagent-driven-development`.
