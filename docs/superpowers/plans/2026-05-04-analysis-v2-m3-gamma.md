# Analysis v2 — M3-γ Implementation Plan (advanced taint: MEM-chasing + through_mem + data_only + cross_fn_call)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the M3-β gaps. Add backward MEM-chasing to Rust `tracemiku-core::taint` (closes the parity-script soft-warn at jaccard=0.31). Wire `through_mem` (byte-overlap via MemShadow), `data_only` (addressing-reg filter), and `cross_fn_call` (frame_depth annotation per row) flags through both core taint paths AND both endpoints. Surface 3 toggles + a frame_depth column in TaintPanel. Re-tighten the parity gate so backward jaccard ≥ 0.6 hard-fails.

**Architecture:** Replace `backward_taint`'s single-variant pending queue with `VecDeque<BwdItem>` where `BwdItem` is `Reg(idx, reg)` or `Mem(before_idx, addr, size)`. MEM-chasing uses `index.mem_addr_to_writes` for the exact-addr fast path (mirroring `viewer/taint.py:277-281`: returns ONLY the latest writer strictly before `before_idx`, not all writers). `through_mem=true` swaps to a byte-overlap scan over the MemShadow byte map (`viewer/taint.py:282-299`). `data_only` adds `DEFAULT_FRAME_REGS = {sp, fp, lr}` to the exclude set when no caller override + filters addressing-only regs from propagation in both forward and backward. `cross_fn_call` consumes the existing `state.frame_depths` (M3-β shipped) and threads `frame_depth: Option<u32>` onto each wire row. Frontend gets 3 checkbox toggles (default off) + a conditional column.

**Tech Stack:** Rust 1.95 (`VecDeque`, no rayon yet — sequential is fine on real workloads), axum 0.7, capstone-rs, Solid+TS+Vite. No new workspace deps.

**Branch:** `refactor/function-index-handoff`. Stream commits (no PR until user requests).

**Spec inputs:**
- `viewer/taint.py:235-411` — full backward_taint reference (the slice we deferred from M3-β).
- `viewer/taint.py:92-196` — forward_taint with `through_mem` / `data_only` reference.
- `viewer/taint.py:269-299` — `_mem_writers_overlapping` exact-addr vs byte-overlap branch.
- `viewer/taint.py:65-89` — `_propagation_regs` and `_addressing_regs` helpers.
- `viewer/taint.py:37` — `DEFAULT_FRAME_REGS = frozenset({"sp", "fp", "lr"})`.
- `webui/server.py:910-981` — Python endpoint reference for `through_mem` / `data_only` / `cross_fn_call` query params + `frame_depth` row field.
- `viewer/memshadow.py` — for the byte-overlap walk in through_mem mode (already ported as `tracemiku-core::memshadow::MemShadow` in M2-ζ).
- `scripts/m3_beta_parity.py` — soft-gates backward; M3-γ Task 1 re-tightens to hard.
- M3-β plan + commits — locks the basic infrastructure that M3-γ extends.

**Lesson from M3-β** (now a saved memory): when parity catches drift outside the declared sub-milestone scope, document and defer rather than expand mid-flight. M3-γ is the closure where deferred items land.

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-core/src/taint.rs` (modify, big) | Add `BwdItem` enum, replace `backward_taint` body with MEM-chasing + initial-seed branch. Add `through_mem`/`data_only` parameters to BOTH forward and backward (default `false`). Add `addressing_regs` helper. Add `propagation_regs` filter. Update file-level + per-fn doc-comments. |
| `rust/crates/tracemiku-core/src/taint.rs` (#[cfg(test)] tail) | Add 3 new colocated tests: `backward_taint_chases_mem_writer` (str/nop/ldr/nop fixture), `forward_taint_data_only_filters_sp` (synth chain through sp), `backward_taint_through_mem_byte_overlap` (8-byte str + 1-byte ldrb). Keep all 5 existing tests green. |
| `rust/crates/tracemiku-core/src/prelude.rs` (modify) | (No change — surface stays the same.) |
| `rust/crates/tracemiku-server/src/routes/forward_taint.rs` (modify) | Accept `through_mem`, `data_only`, `cross_fn_call` query params. Pass through to core. Add `frame_depth: Option<u32>` to `TaintRow`. Populate frame_depth from `state.frame_depths` when `cross_fn_call=true`. |
| `rust/crates/tracemiku-server/src/routes/backward_taint.rs` (modify) | Mirror of forward — same flag wiring, `TaintChainRow.frame_depth: Option<u32>`. |
| `rust/crates/tracemiku-server/tests/test_taint_routes.rs` (modify) | Add 2 tests: `forward_taint_cross_fn_call_emits_frame_depth`, `backward_taint_through_mem_query_param_smoke`. Keep existing 2 green. |
| `frontend/src/api/types.ts` (modify) | Add `frame_depth?: number` to `TaintRow`. |
| `frontend/src/api/client.ts` (modify) | `fetchForwardTaint` / `fetchBackwardTaint` accept new optional flags. |
| `frontend/src/panels/taint/TaintPanel.tsx` (modify) | 3 checkboxes (through_mem, data_only, cross_fn_call) above the Run button. Conditional `frame_depth` column when `cross_fn_call`. |
| `frontend/src/styles/base.css` (modify, minor) | (Likely no new rules — checkboxes inherit `.taint-controls`.) |
| `scripts/m3_beta_parity.py` (modify) | Remove `SOFT_LABELS` set — backward becomes hard-gated again. Comment notes the re-tightening rationale + commit reference. |
| `TODO.md` (modify) | Mark M3-γ deliverables ✅; refine M3-δ pointer (decompiler::backend stub). |
| `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` (modify) | Mark `taint.py` row + endpoint rows as ✅ M3-γ (full surface). |

---

## Task 1: Backward MEM-chasing + initial-seed branch (closes M3-β backward parity)

**Files:**
- Modify: `rust/crates/tracemiku-core/src/taint.rs`

The Python algorithm at `viewer/taint.py:301-356` is the authoritative reference. The rejected M3-β-extension work outline (which was correct in shape but expanded scope mid-milestone) is rolled into this M3-γ task as planned.

Key Python invariant (line 277-281, `through_mem=False` path):
```python
writes = index.mem_addr_to_writes.get(addr, [])
pos = bisect.bisect_left(writes, before_idx) - 1
if pos < 0: return []
return [writes[pos]]   # ← ONLY the latest writer, not all writers
```

So the exact-addr backward MEM-chase returns at most ONE writer per MEM item. Implementations that return all writers diverge from Python.

- [ ] **Step 1: Add helper `addressing_regs` to taint.rs**

Insert near the top (after the BwdItem enum, before `forward_taint`):

```rust
use crate::disasm::{addr_of, decode, MemOp};

/// Set of registers used purely as base/index of memory ops in this insn.
/// Mirrors `viewer/taint.py:83` `_addressing_regs(d)`.
fn addressing_regs(mem_ops: &[MemOp]) -> HashSet<String> {
    let mut s = HashSet::new();
    for op in mem_ops {
        if !op.base.is_empty() {
            s.insert(op.base.clone());
        }
        if !op.index.is_empty() {
            s.insert(op.index.clone());
        }
    }
    s
}
```

`addr_of` and `MemOp` already re-exported from `crate::disasm`. Verify with `grep`.

- [ ] **Step 2: Add the BwdItem enum**

```rust
/// Pending-queue item for backward taint BFS.
/// Mirrors Python `pending: list[tuple]` which holds either
/// `(cur_idx, want_reg)` reg-chases or `("MEM", before_idx, addr, sz)`
/// mem-chases. The Rust port uses a tagged enum.
#[derive(Debug)]
enum BwdItem {
    Reg(usize, String),                  // (cur_idx, want_reg)
    Mem(usize, u64, u32),                // (before_idx, addr, size)
}
```

- [ ] **Step 3: Replace `backward_taint` body**

```rust
pub fn backward_taint(
    trace: &Trace,
    index: &Index,
    idx: usize,
    taint_reg: &str,
    max_count: usize,
    exclude_regs: &HashSet<String>,
) -> (Vec<TaintHit>, bool) {
    let mut pending: VecDeque<BwdItem> = VecDeque::new();
    let mut visited: HashSet<(usize, String)> = HashSet::new();
    let mut raw_out: Vec<(usize, String)> = Vec::new();
    let cap = if max_count == 0 { usize::MAX } else { max_count };
    let mut stopped = false;

    // Initial seed branch (viewer/taint.py:306-318).
    let r0 = trace.record(idx);
    let d0 = decode(r0.pc, r0.inst);
    let starts_with_def = d0.regs_def.iter().any(|r| r == taint_reg);

    if starts_with_def && !exclude_regs.contains(taint_reg) {
        raw_out.push((idx, taint_reg.to_string()));
        visited.insert((idx, taint_reg.to_string()));
        for u in &d0.regs_use {
            if exclude_regs.contains(u) {
                continue;
            }
            pending.push_back(BwdItem::Reg(idx, u.clone()));
        }
        for op in &d0.mem_op {
            if op.is_write {
                continue;
            }
            let addr = addr_of(&r0, op);
            pending.push_back(BwdItem::Mem(idx, addr, op.size));
        }
    } else if !exclude_regs.contains(taint_reg) {
        pending.push_back(BwdItem::Reg(idx, taint_reg.to_string()));
    }

    while let Some(item) = pending.pop_front() {
        if raw_out.len() >= cap {
            stopped = true;
            break;
        }
        match item {
            BwdItem::Mem(before_idx, addr, _size) => {
                // Exact-addr mode (M3-γ Task 2 adds byte-overlap):
                // ONLY return the LATEST writer strictly before before_idx.
                // Python: `return [writes[pos]]` after `bisect_left - 1`.
                let Some(writer_idxs) = index.mem_addr_to_writes.get(&addr) else {
                    continue;
                };
                let pos = writer_idxs.partition_point(|&w| w < before_idx);
                if pos == 0 {
                    continue;
                }
                let j = writer_idxs[pos - 1];
                let r = trace.record(j);
                let d = decode(r.pc, r.inst);
                let (base_w, idx_w) = if let Some(op) = d.mem_op.first() {
                    (op.base.clone(), op.index.clone())
                } else {
                    (String::new(), String::new())
                };
                // First non-addressing reg in regs_use (Python: src_candidates[0]).
                if let Some(src) = d.regs_use.iter().find(|u| {
                    !exclude_regs.contains(*u) && **u != base_w && **u != idx_w
                }) {
                    pending.push_back(BwdItem::Reg(j, src.clone()));
                }
            }
            BwdItem::Reg(cur_idx, want_reg) => {
                if exclude_regs.contains(&want_reg) {
                    continue;
                }
                if visited.contains(&(cur_idx, want_reg.clone())) {
                    continue;
                }
                visited.insert((cur_idx, want_reg.clone()));

                let Some(defs) = index.reg_defs.get(&want_reg) else {
                    continue;
                };
                let pos = defs.partition_point(|&d| d < cur_idx);
                if pos == 0 {
                    continue;
                }
                let j = defs[pos - 1];
                raw_out.push((j, want_reg.clone()));

                let r = trace.record(j);
                let d = decode(r.pc, r.inst);
                for u in &d.regs_use {
                    if exclude_regs.contains(u) {
                        continue;
                    }
                    pending.push_back(BwdItem::Reg(j, u.clone()));
                }
                for op in &d.mem_op {
                    if op.is_write {
                        continue;
                    }
                    let addr = addr_of(&r, op);
                    pending.push_back(BwdItem::Mem(j, addr, op.size));
                }
            }
        }
    }

    // Dedup by sorted idx (Python lines 358-361).
    raw_out.sort_by(|(ai, ar), (bi, br)| ai.cmp(bi).then_with(|| ar.cmp(br)));
    let mut seen_idx: HashSet<usize> = HashSet::new();
    let mut out: Vec<TaintHit> = Vec::new();
    for (i, reg) in raw_out {
        if seen_idx.contains(&i) {
            continue;
        }
        seen_idx.insert(i);
        out.push(TaintHit { idx: i, why: reg });
    }
    (out, stopped)
}
```

- [ ] **Step 4: Add the colocated test `backward_taint_chases_mem_writer`**

```rust
    #[test]
    fn backward_taint_chases_mem_writer() {
        // 4-record trace:
        //   idx 0: str x0, [sp]    (0xf90003e0)  — write to sp
        //   idx 1: nop             (0xd503201f)
        //   idx 2: ldr x1, [sp]    (0xf94003e1)  — read from sp; defs x1
        //   idx 3: nop             (0xd503201f)
        //
        // Backward from idx=2, taint=x1.
        //   d0 (idx=2) defines x1 → starts_with_def branch:
        //     pre-emit (2, "x1"); push regs_use of d0 (sp); push MEM(2, 0x7000, 8).
        //   pop MEM(2, 0x7000, 8): writers of 0x7000 < 2 → {0}.
        //     j=0; first non-addressing reg in d.regs_use → x0; push Reg(0, "x0").
        //   pop Reg(0, "x0"): no def of x0 before idx 0 → empty defs.
        //   pop Reg(2, "sp"): partition_point on reg_defs["sp"] before 2.
        //     If sp is "defined" by str, picks latest; otherwise no def → skip.
        //
        // Expected: hits idxs include 0 AND 2 (str→ldr crosses memory).
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_4r_1ms");
        std::fs::create_dir_all(&cd).unwrap();
        let mut buf = vec![0u8; REC_SIZE * 4];
        let pcs: [u64; 4] = [0x100000, 0x100004, 0x100008, 0x10000c];
        let insts: [u32; 4] = [0xf90003e0, 0xd503201f, 0xf94003e1, 0xd503201f];
        for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
            // x0 = 0xdead at all idxs (so str x0 has a defined source value).
            buf[off + 8..off + 16].copy_from_slice(&0xdeadu64.to_le_bytes());
            // sp = 0x7000.
            buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":4}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x100000","size":4096}}"#,
        )
        .unwrap();
        let cd_path = dir
            .path()
            .join("run")
            .join("calls")
            .read_dir()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let t = Trace::load(&cd_path).unwrap();
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, _stopped) = backward_taint(&t, &idx, 2, "x1", 100, &exclude);
        let idxs: Vec<usize> = hits.iter().map(|h| h.idx).collect();
        assert!(
            idxs.contains(&0),
            "MEM-chasing should reach idx 0 via str→ldr at sp=0x7000; got {idxs:?}"
        );
        assert!(
            idxs.contains(&2),
            "should pre-emit (idx=2, want_reg=x1) when start defines x1; got {idxs:?}"
        );
    }
```

- [ ] **Step 5: Verify all colocated tests pass**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo test -p tracemiku-core --lib taint -- --nocapture 2>&1 | tail -15
cargo clippy -p tracemiku-core --tests 2>&1 | tail -5
```

Expected: 6 tests passing (5 existing + 1 new). Clippy clean.

If `0xf94003e1` (`ldr x1, [sp]`) doesn't decode to `regs_def=[x1]` + a non-write mem_op at sp+0, dump `decode(...)` once and adjust the opcode. Same for `0xf90003e0` (`str x0, [sp]`) — it should decode with x0 in regs_use AND a write mem_op at sp+0.

- [ ] **Step 6: Re-tighten the parity gate**

Edit `/home/ltlly/Code/traceMiku/scripts/m3_beta_parity.py`:

Replace:
```python
        # backward-taint is a SOFT gate in M3-β. Python's index path does
        # MEM-chasing unconditionally (viewer/taint.py:312-356), but the
        # Rust port skips it (M3-β scope: index-accelerated, no
        # through_mem). On real traces with frequent ld/st, the two
        # algorithms reach different parts of the chase graph under the
        # max_count cap. The gap is documented in TODO.md and lands as
        # part of M3-γ (advanced taint flags). Until then we surface the
        # divergence as a WARN, not a fail.
        SOFT_LABELS = {"backward-taint"}
```

With:
```python
        # M3-γ Task 1 closed the M3-β backward gap by porting MEM-chasing.
        # Both endpoints are now hard-gated; jaccard ≥ 0.6 required.
        SOFT_LABELS: set[str] = set()
```

- [ ] **Step 7: Re-run parity**

```bash
cd /home/ltlly/Code/traceMiku
cargo build --release -p tracemiku-server --manifest-path rust/Cargo.toml 2>&1 | tail -3
uv run python scripts/m3_beta_parity.py traces/test_hide_only/calls/_truncated_call_002_tid27340_469639r_1641ms 2>&1 | tail -5
```

Expected: TWO `OK ...` lines. If backward jaccard is now < 0.6, STOP and report BLOCKED — there's a third divergence point we missed (likely `_propagation_regs` data_only filter behavior; check Python lines 65-80 vs Rust). The parity script's symmetric-diff dump pinpoints the offending idxs.

If backward jaccard is e.g. 0.55-0.59 (close but missing tolerance), check whether Python's `data_only=False` default still applies the addressing-reg filter (see line 264-267 — when `exclude_regs is None and data_only=False`, the exclude set is empty, so no filter). The Rust port also passes empty exclude — should match. If jaccard is in this range, dump the symmetric difference and study before deciding.

- [ ] **Step 8: Commit**

```bash
git add rust/crates/tracemiku-core/src/taint.rs scripts/m3_beta_parity.py
git commit -m "$(cat <<'EOF'
feat(core): backward_taint — MEM-chasing + d0.regs_def initial seed

Closes the M3-β soft-gated backward parity (was 0.31 jaccard).

Python (viewer/taint.py:301-356) does MEM-chasing in backward_taint
unconditionally, NOT gated by through_mem. The flag only swaps the
writer-resolution mode (exact-addr vs byte-overlap). M3-β had the
infrastructure but skipped MEM items in pending entirely.

  pending: VecDeque<BwdItem> where BwdItem = Reg | Mem
  Mem(before_idx, addr, sz) → look up index.mem_addr_to_writes,
    take only the LATEST writer < before_idx (Python: writes[pos]).
    First non-addressing reg in writer's regs_use becomes a new chase.

Initial seed now branches on whether d0 defines taint_reg
(Python:306-318). When yes: pre-emit (idx, taint_reg), seed pending
with regs_use of d0 + MEM items from d0's loads.

  New test: backward_taint_chases_mem_writer (4-rec str/nop/ldr/nop)
  pins MEM-chase reaches idx 0 from a backward query at idx 2 on x1.

Re-tightens scripts/m3_beta_parity.py — SOFT_LABELS now empty;
both endpoints hard-gated. Real-trace verification: forward 0.90,
backward jaccard now ≥ 0.6 (run and update commit if exact value
desired).

M3-γ Task 1.
EOF
)"
```

---

## Task 2: `through_mem` flag (forward + backward byte-overlap)

**Files:**
- Modify: `rust/crates/tracemiku-core/src/taint.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/forward_taint.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/backward_taint.rs`

When `through_mem=true`:
- **Forward**: stores tag bytes; loads check overlap. Python uses a `set[int]` (`tainted_mem`) of byte addresses; on store: add `[addr, addr+size)`; on load: check any byte in `[addr, addr+size)` is in `tainted_mem`. (See `viewer/taint.py:131, 158-187`.)
- **Backward**: replace exact-addr `mem_addr_to_writes` lookup with byte-overlap scan over `MemShadow` byte map. Python: `viewer/taint.py:282-299` — for each byte in `[addr, addr+size)`, find the latest writer <= before_idx using bisect on `mem.bytes[byte_addr]`; collect unique writer idxs.

Rust core needs `MemShadow` access. Currently the `forward_taint` / `backward_taint` signatures take `&Index`. Add `mem: Option<&MemShadow>` parameter (`None` when through_mem=false). Update both signatures + callers.

- [ ] **Step 1: Add `through_mem` parameter and `MemShadow` plumbing**

Update both functions' signatures:

```rust
pub fn forward_taint(
    trace: &Trace,
    index: &Index,
    start_idx: usize,
    taint_reg: &str,
    max_count: usize,
    exclude_regs: &HashSet<String>,
    through_mem: bool,
    mem: Option<&MemShadow>,
) -> (Vec<TaintHit>, bool)
```

(And same for backward.) Add `use crate::memshadow::MemShadow;` to the imports.

When `through_mem=true && mem.is_some()`, use byte-overlap; else use the existing exact-addr fast path.

- [ ] **Step 2: Forward `tainted_mem` byte set**

In `forward_taint`, add `let mut tainted_mem: HashSet<u64> = HashSet::new();`.

On every visited record, before `if used.is_empty()`:

```rust
        // Check loads against tainted_mem.
        let mut load_tainted = false;
        for op in &d.mem_op {
            if op.is_write {
                continue;
            }
            let base = addr_of(&r, op);
            for o in 0..op.size as u64 {
                if tainted_mem.contains(&(base + o)) {
                    load_tainted = true;
                    break;
                }
            }
            if load_tainted { break; }
        }
```

Combine with `used` test: `if !used.is_empty() || load_tainted`. Append `if load_tainted { why parts include "mem" }`.

After emission, populate tainted_mem from stores:

```rust
        for op in &d.mem_op {
            if !op.is_write {
                continue;
            }
            let base = addr_of(&r, op);
            if through_mem {
                for o in 0..op.size as u64 {
                    tainted_mem.insert(base + o);
                }
            } else {
                tainted_mem.insert(base);
            }
        }
```

(Python's behavior: even with `through_mem=False`, stores tag the BASE byte. So a 1-byte tagged addr only matches a load that exactly hits that byte's first overlap. This preserves the partial mem-flow gate.)

- [ ] **Step 3: Backward byte-overlap MEM resolution**

Replace the `BwdItem::Mem(before_idx, addr, size)` handler:

```rust
            BwdItem::Mem(before_idx, addr, size) => {
                let writers = mem_writers_overlapping(
                    index, mem, addr, size, before_idx, through_mem
                );
                for j in writers {
                    let r = trace.record(j);
                    let d = decode(r.pc, r.inst);
                    let (base_w, idx_w) = if let Some(op) = d.mem_op.first() {
                        (op.base.clone(), op.index.clone())
                    } else {
                        (String::new(), String::new())
                    };
                    if let Some(src) = d.regs_use.iter().find(|u| {
                        !exclude_regs.contains(*u) && **u != base_w && **u != idx_w
                    }) {
                        pending.push_back(BwdItem::Reg(j, src.clone()));
                    }
                }
            }
```

And add the helper:

```rust
/// Return writer record indices that overlap `[addr, addr+size)` strictly
/// before `before_idx`. Mirrors `viewer/taint.py:274-299`.
fn mem_writers_overlapping(
    index: &Index,
    mem: Option<&MemShadow>,
    addr: u64,
    size: u32,
    before_idx: usize,
    through_mem: bool,
) -> Vec<usize> {
    if !through_mem || mem.is_none() {
        // Exact-addr fast path: ONLY the latest writer < before_idx.
        let Some(writers) = index.mem_addr_to_writes.get(&addr) else {
            return Vec::new();
        };
        let pos = writers.partition_point(|&w| w < before_idx);
        if pos == 0 {
            return Vec::new();
        }
        return vec![writers[pos - 1]];
    }
    // Byte-overlap mode: scan bytes, collect unique writers.
    let mem = mem.unwrap();
    let mut seen: HashSet<usize> = HashSet::new();
    for o in 0..size as u64 {
        let byte_addr = addr + o;
        // MemShadow API: bytes[byte_addr] -> Vec<ByteEvent>?
        // Adapt to whichever lookup the Rust MemShadow exposes for
        // "latest write event <= before_idx" queries. Read M2-ζ's
        // memshadow.rs to find the right helper.
        if let Some(latest_writer) = mem.latest_write_idx_before(byte_addr, before_idx) {
            seen.insert(latest_writer);
        }
    }
    let mut out: Vec<usize> = seen.into_iter().collect();
    out.sort_unstable();
    out.reverse(); // descending (Python: `sorted(seen, reverse=True)`)
    out
}
```

If `MemShadow` doesn't have `latest_write_idx_before`, add it:

```rust
// In rust/crates/tracemiku-core/src/memshadow.rs:
impl MemShadow {
    /// Find the latest write event idx for `byte_addr` strictly before `before_idx`.
    /// Returns None if no such write exists.
    pub fn latest_write_idx_before(&self, byte_addr: u64, before_idx: usize) -> Option<usize> {
        let evs = self.bytes.get(&byte_addr)?;
        // events sorted by idx; find latest with idx < before_idx and kind in {w, x}
        let pos = evs.partition_point(|ev| ev.idx < before_idx);
        for j in (0..pos).rev() {
            let ev = &evs[j];
            // ByteEvent::kind is "w"|"r"|"x" or similar; match the kind enum/tag
            // used in the Rust MemShadow port.
            if matches!(ev.kind, EventKind::Write | EventKind::External) {
                return Some(ev.idx);
            }
        }
        None
    }
}
```

(Adjust to actual MemShadow API; `kind` may be a `&str` per M2-ζ. Read `rust/crates/tracemiku-core/src/memshadow.rs` to confirm.)

- [ ] **Step 4: Update endpoint signatures**

Both `routes/forward_taint.rs` and `routes/backward_taint.rs` need:

```rust
#[derive(Debug, Deserialize)]
pub struct ForwardTaintQuery {
    pub start: usize,
    pub reg: String,
    pub max_count: Option<usize>,
    #[serde(default)]
    pub through_mem: bool,
    #[serde(default)]
    pub data_only: bool,
    #[serde(default)]
    pub cross_fn_call: bool,
}
```

Pass `q.through_mem` + `Some(&inner.memshadow)` (or `None` when through_mem=false) into `forward_taint`. Symmetric for backward.

- [ ] **Step 5: Add 1 colocated test**

```rust
    #[test]
    fn forward_taint_through_mem_byte_overlap() {
        // 3-record trace:
        //   idx 0: str x0, [sp]    (0xf90003e0) — 8-byte write
        //   idx 1: ldrb w1, [sp]   (0x39400061) — 1-byte load at sp+0
        //   idx 2: nop             (0xd503201f)
        //
        // Forward from idx=0, taint=x0, through_mem=true.
        // - idx 0 writes x0 to [sp..sp+8].
        // - idx 1 loads byte at sp+0 — overlaps with the tagged store.
        // Expected: hits include idx 1 with why containing "mem".
        //
        // Without through_mem, the same idx 1 load would only match
        // because the tagged store also writes the BASE byte even in
        // exact-addr mode (Python:185-187). So this test specifically
        // exercises through_mem when load is at a DIFFERENT byte.
        // Use ldrb w1, [sp, #1] (0x39400461) for sp+1 to force byte-overlap.
        // ... (adjust opcode and assertion accordingly)
    }
```

(Honest about the test's complexity: writing a synthetic ARM64 trace where through_mem-vs-exact-addr makes a difference takes care. If the precise opcode for `ldrb w1, [sp, #1]` is unclear, use `cargo test -- --nocapture` with a `decode(...)` debug print to find the right encoding.)

- [ ] **Step 6: Verify**

```bash
cargo test -p tracemiku-core --lib taint 2>&1 | tail -10
cargo test -p tracemiku-server 2>&1 | grep -E "test result:" | tail -5
cargo clippy -p tracemiku-core -p tracemiku-server --tests 2>&1 | tail -5
```

All green.

- [ ] **Step 7: Commit**

```bash
git add rust/crates/tracemiku-core/src/taint.rs \
        rust/crates/tracemiku-core/src/memshadow.rs \
        rust/crates/tracemiku-server/src/routes/forward_taint.rs \
        rust/crates/tracemiku-server/src/routes/backward_taint.rs
git commit -m "feat(core,server): taint --through-mem byte-overlap (forward + backward)"
```

---

## Task 3: `data_only` flag

**Files:**
- Modify: `rust/crates/tracemiku-core/src/taint.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/forward_taint.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/backward_taint.rs`

When `data_only=true`:
1. If caller didn't pass an exclude_regs override, default to `DEFAULT_FRAME_REGS = {sp, fp, lr}`.
2. In propagation, exclude regs that are USED purely as base/index of mem ops in the current insn (Python `_propagation_regs`). Forward: filter `regs_use ∩ tainted_regs - addressing_regs`; backward: filter `regs_use - addressing_regs - exclude_regs` when constructing the next push.

In Rust, the cleanest design: the route handler builds the effective exclude set (default frame regs union user override) before calling core. Core takes `data_only: bool` as a parameter; when true, applies the addressing-reg filter inline at each visited insn.

- [ ] **Step 1: Add `data_only` parameter to forward + backward signatures**

(Drop in alongside `through_mem` from Task 2.)

- [ ] **Step 2: Default frame regs constant**

```rust
/// Default frame regs almost always skipped during data-only taint
/// (matches viewer/taint.py:37 DEFAULT_FRAME_REGS).
pub const DEFAULT_FRAME_REGS: [&str; 3] = ["sp", "fp", "lr"];

pub fn default_frame_reg_set() -> HashSet<String> {
    DEFAULT_FRAME_REGS.iter().map(|s| s.to_string()).collect()
}
```

Re-export from prelude.

- [ ] **Step 3: Filter inline in forward + backward**

In `forward_taint`, where `used` is collected:

```rust
        let addr_regs = if data_only {
            addressing_regs(&d.mem_op)
        } else {
            HashSet::new()
        };
        let mut used: Vec<String> = Vec::new();
        for u in &d.regs_use {
            if data_only && addr_regs.contains(u) {
                continue;
            }
            if tainted_regs.contains(u) {
                used.push(u.clone());
            }
        }
```

In `backward_taint::BwdItem::Reg` arm, where regs_use of the def-instruction are pushed back:

```rust
                let addr_regs = if data_only {
                    addressing_regs(&d.mem_op)
                } else {
                    HashSet::new()
                };
                for u in &d.regs_use {
                    if exclude_regs.contains(u) {
                        continue;
                    }
                    if data_only && addr_regs.contains(u) {
                        continue;
                    }
                    pending.push_back(BwdItem::Reg(j, u.clone()));
                }
```

- [ ] **Step 4: Endpoint handlers — build effective exclude when `data_only`**

```rust
    let exclude: HashSet<String> = if q.data_only {
        tracemiku_core::prelude::default_frame_reg_set()
    } else {
        HashSet::new()
    };
    let (hits, stopped) = forward_taint(
        &inner.trace, &inner.index, q.start, &q.reg, eff,
        &exclude, q.through_mem, mem_arg, q.data_only,
    );
```

(Where `mem_arg = if q.through_mem { Some(&inner.memshadow) } else { None }`.)

- [ ] **Step 5: 1 colocated test**

```rust
    #[test]
    fn forward_taint_data_only_filters_sp_addressing() {
        // 3-record:
        //   idx 0: add x0, x0, #1
        //   idx 1: str x0, [sp]      — sp is addressing reg, x0 is value
        //   idx 2: add x0, x0, #1
        //
        // Forward from idx=0, taint=sp.
        //   data_only=false: x0 chain may pull in sp through the str's
        //                    regs_use (including sp).
        //   data_only=true: sp is filtered out from `used` because it's
        //                   in addr_regs of idx 1.
        // (Exact assertion shape depends on the synth setup; the goal
        // is to confirm data_only EXCLUDES at least one hit that the
        // !data_only run includes.)
    }
```

- [ ] **Step 6: Verify + commit**

```bash
cargo test -p tracemiku-core --lib taint 2>&1 | tail -10
cargo test -p tracemiku-server 2>&1 | grep "test result:" | tail -5

git add rust/crates/tracemiku-core/src/taint.rs \
        rust/crates/tracemiku-core/src/prelude.rs \
        rust/crates/tracemiku-server/src/routes/forward_taint.rs \
        rust/crates/tracemiku-server/src/routes/backward_taint.rs
git commit -m "feat(core,server): taint --data-only (filter addressing regs + DEFAULT_FRAME_REGS)"
```

---

## Task 4: `cross_fn_call` wire-through (frame_depth annotation per row)

**Files:**
- Modify: `rust/crates/tracemiku-server/src/routes/forward_taint.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/backward_taint.rs`
- Modify: `rust/crates/tracemiku-server/tests/test_taint_routes.rs`

The Rust core's `forward_taint` / `backward_taint` already emit `TaintHit { idx, why }`. The `cross_fn_call` flag is purely a wire-decoration: at the route handler, if `q.cross_fn_call`, annotate each row with `frame_depth: Option<u32>` from `state.frame_depths[idx]`.

- [ ] **Step 1: Add `frame_depth` field to `TaintRow` and `TaintChainRow`**

```rust
#[derive(Debug, Serialize)]
pub struct TaintRow {
    // ... existing fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_depth: Option<u32>,
}
```

(Same for `TaintChainRow`.)

- [ ] **Step 2: Populate frame_depth in handler**

```rust
            frame_depth: if q.cross_fn_call {
                inner.frame_depths.get(h.idx).copied()
            } else {
                None
            },
```

- [ ] **Step 3: Add 1 integration test in `tests/test_taint_routes.rs`**

```rust
#[tokio::test]
async fn forward_taint_cross_fn_call_emits_frame_depth() {
    // Use the existing 5-record `add x0, x0, #1` chain.
    // GET /api/forward-taint?start=0&reg=x0&max_count=10&cross_fn_call=true
    // Each row's `frame_depth` should be present + numeric (likely 0).
    //
    // GET /api/forward-taint?start=0&reg=x0&max_count=10
    // (no cross_fn_call) — `frame_depth` should be omitted (skip_serializing_if).
}
```

- [ ] **Step 4: Verify + commit**

```bash
cargo test -p tracemiku-server 2>&1 | tail -10

git add rust/crates/tracemiku-server/src/routes/forward_taint.rs \
        rust/crates/tracemiku-server/src/routes/backward_taint.rs \
        rust/crates/tracemiku-server/tests/test_taint_routes.rs
git commit -m "feat(server): taint endpoints — cross_fn_call → frame_depth row field"
```

---

## Task 5: Frontend toggles + frame_depth column

**Files:**
- Modify: `frontend/src/api/types.ts`
- Modify: `frontend/src/api/client.ts`
- Modify: `frontend/src/panels/taint/TaintPanel.tsx`

- [ ] **Step 1: Update types.ts**

```typescript
export interface TaintRow {
  // ... existing
  frame_depth?: number;   // present iff cross_fn_call=true was passed
}
```

- [ ] **Step 2: Update client.ts**

```typescript
export interface TaintFlags {
  through_mem?: boolean;
  data_only?: boolean;
  cross_fn_call?: boolean;
}

export async function fetchForwardTaint(
  start: number, reg: string, maxCount = 200, flags: TaintFlags = {}
): Promise<ForwardTaintResponse> {
  const params = new URLSearchParams({
    start: String(start), reg, max_count: String(maxCount),
  });
  if (flags.through_mem) params.set("through_mem", "true");
  if (flags.data_only) params.set("data_only", "true");
  if (flags.cross_fn_call) params.set("cross_fn_call", "true");
  // ... rest unchanged
}
```

(Same for backward.)

- [ ] **Step 3: Update TaintPanel.tsx**

Add 3 boolean signals. Add 3 `<label><input type="checkbox" />` rows next to existing controls. Pass flags to fetch helpers. When `cross_fn_call` is on, render an extra `<th>depth</th>` column + `<td>{row.frame_depth}</td>`.

- [ ] **Step 4: Build + commit**

```bash
cd frontend && npm run build 2>&1 | tail -5

git add frontend/src/api/types.ts frontend/src/api/client.ts \
        frontend/src/panels/taint/TaintPanel.tsx
git commit -m "feat(frontend): TaintPanel — through_mem/data_only/cross_fn_call toggles + depth column"
```

---

## Task 6: Spec/TODO sync

**Files:**
- Modify: `TODO.md`
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`

- [ ] **Step 1: Run final verification sweep**

```bash
cd rust && cargo test --workspace 2>&1 | grep "test result:" | tail -10
cd .. && cargo build --release -p tracemiku-server --manifest-path rust/Cargo.toml 2>&1 | tail -3
uv run python scripts/m3_beta_parity.py traces/test_hide_only/calls/_truncated_call_002_tid27340_469639r_1641ms 2>&1 | tail -5
cd frontend && npm run build 2>&1 | tail -3
```

Expected: all green; parity prints two `OK ...` lines (forward + backward).

- [ ] **Step 2: Update spec rows**

In `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`:
- `taint.py (forward/backward, basic)` row → ✅ M3-γ (full surface; no longer 🟡)
- `taint.py (--through-mem, --data-only)` row → ✅ M3-γ
- `taint.py (--cross-fn-call frame_depth)` row → ✅ M3-γ
- `/api/forward-taint` → ✅ M3-γ
- `/api/backward-taint` → ✅ M3-γ (no longer 🟡)

- [ ] **Step 3: Update TODO.md**

Append M3-γ completion rows. Update the M3 sub-milestone roadmap:

```markdown
- M3-γ: backward MEM-chasing + through_mem + data_only + cross_fn_call wire + frontend toggles ✅ 2026-05-04
- M3-δ (next): decompiler::backend stub + TraceIR builder skeleton
- M3-ε: Graph panel SVG (cfg-svg via petgraph or graphviz-rust)
- M3-ζ: memshadow v3 binary sidecar
- M3-η: Python viewer cutover prep
```

Remove the M3-γ scope-precise block (it's now history).

- [ ] **Step 4: Commit**

```bash
git add TODO.md docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md
git commit -m "docs(v2): mark M3-γ complete — taint full surface; M3-δ next"
```

---

## Self-Review

**Spec coverage:**
| Item | Task |
|---|---|
| Backward MEM-chasing + initial-seed branch | Task 1 |
| Re-tighten parity gate (backward hard) | Task 1 Step 6 |
| `through_mem` byte-overlap (forward + backward) | Task 2 |
| `data_only` filter + DEFAULT_FRAME_REGS | Task 3 |
| `cross_fn_call` row annotation | Task 4 |
| Frontend toggles + depth column | Task 5 |
| Docs sync | Task 6 |

**Out of scope (intentional):**
- Rayon parallelism (sequential is fast enough on real workloads; revisit only if profiling shows need)
- Slow-path fallback (`_forward_taint_slow` etc.) — Rust always has Index
- Cross-fn semantic taint (ABI arg tracking, callee→caller return flow) — own spec, see existing v2 design §13.5 entry "(future) **semantic cross-fn taint propagation**"

**Risk:** Task 2's MemShadow byte-overlap walk depends on a `MemShadow::latest_write_idx_before(byte_addr, before_idx)` API that may not exist in the M2-ζ Rust port — Step 3 adds it if missing. Pre-flight: read `rust/crates/tracemiku-core/src/memshadow.rs` before dispatching Task 2 to determine whether the helper is already there or needs adding.

**Type consistency:**
- `forward_taint` and `backward_taint` signatures gain `through_mem: bool, mem: Option<&MemShadow>, data_only: bool` parameters in same order in both.
- `TaintHit` (core) stays unchanged. `TaintRow` and `TaintChainRow` (server) add `frame_depth: Option<u32>` (omitted from wire when None).
- Frontend `TaintRow` mirrors the wire — `frame_depth?: number`.
- All 3 query params (`through_mem`, `data_only`, `cross_fn_call`) are `bool` with `#[serde(default)]` so absent = false.

---

**Plan complete and saved.** Per `CLAUDE.md` user-pref §"Skip the 'Two execution options' handoff" — execution proceeds via `superpowers:subagent-driven-development`.
