# Analysis v2 — M3-β Implementation Plan (taint forward/backward + frame_depth + /api/forward-taint + /api/backward-taint + TaintPanel + parity)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the **basic, index-accelerated** forward/backward taint paths from `viewer/taint.py` to `tracemiku-core::taint`, plus the `build_frame_depth_map` helper. Expose them as `GET /api/forward-taint` / `GET /api/backward-taint`. Add a Solid `TaintPanel` (start_idx + reg input → results table). Lock structural parity with the Python webui via `scripts/m3_beta_parity.py`. Advanced flags (`through_mem`, `data_only`, `cross_fn_call`) intentionally land in M3-γ — this milestone delivers the minimum-viable taint that unblocks the UI workflow.

**Architecture:** Reuse existing `tracemiku-core::index::Index` (M2-γ, already populates `reg_defs[r] -> Vec<usize>` and `reg_uses[r] -> Vec<usize>` sorted). Forward taint = `BinaryHeap` of `(next_use_idx, reg, cursor)`, pop minimum, propagate `regs_def` of the visited record, push back the next use of each newly-tainted reg. Backward taint = `BinaryHeap`-via-`Reverse(...)` over `reg_defs[r]` `partition_point`. Both run sequentially over O(|hits| · log N) records — far below the 7M-record fatigue threshold. `build_frame_depth_map` walks the trace once, increments on `is_call`, decrements on `is_ret`, returns `Vec<u32>` of length `trace.len()`. Eager-build at `AppState::load`. Endpoint handlers re-decode each hit to enrich the wire row with `pc`/`rel`/`func`/`asm`. Frontend takes `(start, reg)`, calls the endpoint, renders the rows in a table that's structurally identical to RecordsPanel.

**Tech Stack:** Rust 1.95 (stdlib `BinaryHeap` + `Reverse`), axum 0.7, capstone-rs (already wired through `decode`), Solid+TS+Vite (frontend). No new workspace deps.

**Branch:** `refactor/function-index-handoff`. M3-β streams commits to this branch like M3-α did.

**Spec inputs:**
- `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` §13.5 endpoints (`/api/forward-taint`, `/api/backward-taint` rows).
- `viewer/taint.py:40-232` — `build_frame_depth_map`, `forward_taint`, `_forward_taint_slow`. Reference algorithm, including `exclude_regs` semantics (`{sp, fp, lr}` default frame regs).
- `viewer/taint.py:235-415` — `backward_taint`, `_backward_taint_slow`.
- `webui/server.py:910-981` — Python endpoint reference for wire shape.
- `webui/schemas.py:339-405` — `ForwardTaintReadyResponse`, `BackwardTaintReadyResponse`. Wire fields: `count`, `from`, `reg`, `hits|chain`, `stopped_at_max`, `max_count_used`. Each row: `idx`, `pc`, `rel`, `func`, `asm`, `why|via`, optional `frame_depth`.
- M3-α plan (`2026-05-04-analysis-v2-m3-alpha.md`) for the established M3-* patterns: eager-build, route registration alphabetical, parity script idiom.

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-core/src/taint.rs` (new) | `build_frame_depth_map(&Trace) -> Vec<u32>`, `forward_taint(&Trace, &Index, start, reg, max_count) -> (Vec<TaintHit>, bool)`, `backward_taint(...)` mirror. Pure-Rust, no axum coupling. |
| `rust/crates/tracemiku-core/src/lib.rs` (modify) | `pub mod taint;` after `pub mod symbols;`. |
| `rust/crates/tracemiku-core/src/prelude.rs` (modify) | Re-export `build_frame_depth_map`, `forward_taint`, `backward_taint`, `TaintHit`. |
| `rust/crates/tracemiku-core/src/taint.rs` (#[cfg(test)] tail) | 4 colocated tests: empty trace, simple reg-use chain forward, simple def-chain backward, frame-depth map shape. |
| `rust/crates/tracemiku-server/src/state.rs` (modify) | Eager-build `frame_depths: Vec<u32>` at `AppState::load` (cheap; same complexity as Index walk). Taint itself is on-demand per request. |
| `rust/crates/tracemiku-server/src/routes/forward_taint.rs` (new) | `GET /api/forward-taint?start=N&reg=x0&max_count=M` — returns ready or pending shape. Use the Index that AppState already holds. |
| `rust/crates/tracemiku-server/src/routes/backward_taint.rs` (new) | Mirror of forward. |
| `rust/crates/tracemiku-server/src/routes/mod.rs` (modify) | Add `pub mod forward_taint; pub mod backward_taint;` alphabetically + 2 routes. |
| `rust/crates/tracemiku-server/tests/test_taint_routes.rs` (new) | 2 integration tests (forward/backward) on the synth fixture from Task 1's calltree pattern, verify hit list shape. |
| `frontend/src/api/types.ts` (modify) | `TaintRow`, `ForwardTaintResponse`, `BackwardTaintResponse` interfaces. |
| `frontend/src/api/client.ts` (modify) | `fetchForwardTaint(start, reg, maxCount)`, `fetchBackwardTaint(...)`. |
| `frontend/src/panels/taint/TaintPanel.tsx` (new) | Two inputs (`start_idx`, `reg`) + direction toggle + "Run" button → table of hits/chain. Pattern matches RecordsPanel (paginated table). |
| `frontend/src/App.tsx` (modify) | Mount `<TaintPanel />` between `<CallTreePanel />` and `<StringsPanel />`. |
| `frontend/src/styles/base.css` (modify) | Append `.taint-*` CSS rules. |
| `scripts/m3_beta_parity.py` (new) | Boot Python+Rust, fetch `/api/forward-taint?start=0&reg=x0&max_count=200` from each (use root pc-0 reg-x0 as a deterministic test surface), structural compare: same `count`, hit-idx set Jaccard ≥ 0.6. |
| `TODO.md` (modify) | Append M3-β rows; refine M3 sub-milestone roadmap. |
| `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` (modify) | Mark `taint.py` row + `/api/forward-taint`, `/api/backward-taint` rows as ✅ M3-β. Mark `cross-fn frame_depth` row as ✅ M3-β if present. |

---

## Task 1: `tracemiku-core::taint` port (TDD)

**Files:**
- Create: `rust/crates/tracemiku-core/src/taint.rs`
- Modify: `rust/crates/tracemiku-core/src/lib.rs`
- Modify: `rust/crates/tracemiku-core/src/prelude.rs`

Direct port of `viewer/taint.py` for the MVP scope. **Out of scope for this task** (deferred to M3-γ): `through_mem` flag, `data_only` flag, `cross_fn_call` flag, the slow O(N) fallback (`_forward_taint_slow` / `_backward_taint_slow`). Rust always has Index — no fallback needed.

The `exclude_regs` parameter IS in scope: a default-empty set is acceptable for MVP, but the helper signature must accept it so M3-γ can wire `data_only`'s `{sp, fp, lr}` default without breaking-change.

- [ ] **Step 1: Write the type + frame_depth_map skeleton (failing tests)**

Create `rust/crates/tracemiku-core/src/taint.rs`:

```rust
//! Forward + backward taint propagation on a trace.
//!
//! Direct port of `viewer/taint.py` minus the slow-path fallback,
//! `through_mem`, `data_only`, and `cross_fn_call` flags (those land in
//! M3-γ). MVP scope: index-accelerated forward + backward with optional
//! exclude-reg set.
//!
//! Algorithm (forward):
//!   - min-heap of (next_use_idx, reg, cursor)
//!   - pop minimum; if seen, advance cursor + re-push and continue
//!   - decode the visited record; if any tainted reg appears in regs_use,
//!     emit a hit with `why = "regs:<sorted set>"`
//!   - push each newly-defined reg (regs_def) onto the heap with its first
//!     use position via partition_point on `index.reg_uses[reg]`
//!
//! Algorithm (backward): symmetric over `reg_defs`, walking by Reverse(idx)
//! to pop highest-index first.

use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};

use crate::disasm::decode;
use crate::index::Index;
use crate::trace::Trace;

/// One taint hit row. The HTTP layer enriches this with pc/asm/func by
/// re-decoding the record at `idx` — keeping the core dependency-free.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TaintHit {
    pub idx: usize,
    /// "regs:x0,x1" for forward; "regs:..." or "via:..." for backward.
    /// Caller decides field name on the wire.
    pub why: String,
}

/// Walk trace once; return a Vec of length `trace.len()` where `out[i]`
/// is the call-frame depth at record `i` (root frame = 0). Used by the
/// `cross_fn_call` flag in M3-γ; eagerly built so M3-γ can opt in cheaply.
pub fn build_frame_depth_map(trace: &Trace) -> Vec<u32> {
    let n = trace.len();
    let mut out = vec![0u32; n];
    let mut depth: u32 = 0;
    for i in 0..n {
        out[i] = depth;
        let r = trace.record(i);
        let d = decode(r.pc, r.inst);
        if d.is_call {
            depth = depth.saturating_add(1);
        } else if d.is_ret && depth > 0 {
            depth -= 1;
        }
    }
    out
}

/// Forward taint propagation. Returns `(hits, stopped_at_max)`.
///
/// `start_idx`: the record index where the source register is considered
/// tainted. Propagation begins at `start_idx + 1`'s first use.
/// `taint_reg`: e.g. "x0".
/// `max_count`: hard cap on hits. `0` means no cap (matches Python when
/// `max_count <= 0`, which the slow-path treats as no cap; the
/// index-accelerated path simply iterates until heap empty).
/// `exclude_regs`: regs whose defs are NOT propagated through. Empty is fine.
pub fn forward_taint(
    trace: &Trace,
    index: &Index,
    start_idx: usize,
    taint_reg: &str,
    max_count: usize,
    exclude_regs: &HashSet<String>,
) -> (Vec<TaintHit>, bool) {
    let mut tainted_regs: HashSet<String> = HashSet::new();
    tainted_regs.insert(taint_reg.to_string());
    let mut heap: BinaryHeap<Reverse<(usize, String, usize)>> = BinaryHeap::new();

    let push_reg = |heap: &mut BinaryHeap<_>, reg: &str, lo: usize| {
        if exclude_regs.contains(reg) {
            return;
        }
        let Some(uses) = index.reg_uses.get(reg) else {
            return;
        };
        let pos = uses.partition_point(|&u| u <= lo);
        if pos < uses.len() {
            heap.push(Reverse((uses[pos], reg.to_string(), pos)));
        }
    };
    push_reg(&mut heap, taint_reg, start_idx);

    let mut out: Vec<TaintHit> = Vec::new();
    let mut seen: HashSet<usize> = HashSet::new();

    let cap = if max_count == 0 { usize::MAX } else { max_count };
    let mut stopped = false;

    while let Some(Reverse((i, reg, pos))) = heap.pop() {
        if out.len() >= cap {
            stopped = true;
            break;
        }
        if let Some(uses) = index.reg_uses.get(&reg) {
            if pos + 1 < uses.len() {
                heap.push(Reverse((uses[pos + 1], reg.clone(), pos + 1)));
            }
        }
        if seen.contains(&i) {
            continue;
        }
        let r = trace.record(i);
        let d = decode(r.pc, r.inst);
        let used: HashSet<&String> = tainted_regs.intersection(&d.regs_use.iter().cloned().collect::<HashSet<_>>()).collect();
        if used.is_empty() {
            continue;
        }
        let mut sorted: Vec<&str> = used.iter().map(|s| s.as_str()).collect();
        sorted.sort();
        let why = format!("regs:{}", sorted.join(","));
        out.push(TaintHit { idx: i, why });
        seen.insert(i);
        for nr in &d.regs_def {
            if exclude_regs.contains(nr) {
                continue;
            }
            if !tainted_regs.contains(nr) {
                tainted_regs.insert(nr.clone());
                push_reg(&mut heap, nr, i);
            }
        }
    }

    (out, stopped)
}

/// Backward taint — symmetric of forward. Walks `reg_defs[r]` for
/// "what wrote `r` before idx?" and propagates the reading regs of that
/// def-instruction backward.
pub fn backward_taint(
    trace: &Trace,
    index: &Index,
    idx: usize,
    taint_reg: &str,
    max_count: usize,
    exclude_regs: &HashSet<String>,
) -> (Vec<TaintHit>, bool) {
    // pending: max-heap on (idx, reg) — we want the *latest* def before
    // the cursor, so we pop the largest idx first.
    let mut pending: BinaryHeap<(usize, String)> = BinaryHeap::new();
    let mut tainted_regs: HashSet<String> = HashSet::new();
    tainted_regs.insert(taint_reg.to_string());

    let push_def = |heap: &mut BinaryHeap<(usize, String)>, reg: &str, hi: usize| {
        if exclude_regs.contains(reg) {
            return;
        }
        let Some(defs) = index.reg_defs.get(reg) else {
            return;
        };
        // largest def index strictly less than `hi`
        let pos = defs.partition_point(|&d| d < hi);
        if pos > 0 {
            heap.push((defs[pos - 1], reg.to_string()));
        }
    };
    push_def(&mut pending, taint_reg, idx);

    let mut out: Vec<TaintHit> = Vec::new();
    let mut seen: HashSet<usize> = HashSet::new();
    let cap = if max_count == 0 { usize::MAX } else { max_count };
    let mut stopped = false;

    while let Some((i, _reg)) = pending.pop() {
        if out.len() >= cap {
            stopped = true;
            break;
        }
        if seen.contains(&i) {
            continue;
        }
        seen.insert(i);
        let r = trace.record(i);
        let d = decode(r.pc, r.inst);
        let mut producers: Vec<&str> = d.regs_use.iter().map(|s| s.as_str()).collect();
        producers.sort();
        let via = if producers.is_empty() {
            "via:?".to_string()
        } else {
            format!("via:{}", producers.join(","))
        };
        out.push(TaintHit { idx: i, why: via });
        for ur in &d.regs_use {
            if exclude_regs.contains(ur) {
                continue;
            }
            if !tainted_regs.contains(ur) {
                tainted_regs.insert(ur.clone());
                push_def(&mut pending, ur, i);
            }
        }
    }

    (out, stopped)
}
```

(Note: the `forward_taint` body has one collect-into-set spot using `.cloned()` that the Rust borrow checker may quibble with. If so, rewrite the intersection as a `for u in &d.regs_use { if tainted_regs.contains(u) { ... } }` loop. The implementer should choose the clearest form.)

Add `pub mod taint;` to `rust/crates/tracemiku-core/src/lib.rs` after `pub mod symbols;`.

Add to prelude (`rust/crates/tracemiku-core/src/prelude.rs`) after the `crate::symbols::...` line:

```rust
pub use crate::taint::{
    backward_taint, build_frame_depth_map, forward_taint, TaintHit,
};
```

- [ ] **Step 2: Compile + colocated test scaffold**

Run: `cargo build -p tracemiku-core --tests 2>&1 | tail -15`. Expect clean. Fix borrow-checker issues encountered above by replacing the `.intersection` pattern with an explicit loop.

- [ ] **Step 3: Add 4 colocated tests at end of `taint.rs` (under `#[cfg(test)] mod tests`)**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::REC_SIZE;

    /// Same 9-record fixture as calltree tests:
    /// idx 0..8: f_root → bl alpha → ret; bl beta → ret ret ret.
    /// We reuse the synth approach to keep test coverage consistent.
    fn synth() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_9r_1ms");
        std::fs::create_dir_all(&cd).unwrap();
        let pcs: [u64; 9] = [
            0x100000, 0x100004, 0x100100, 0x100104, 0x100008, 0x100200, 0x100204, 0x100208,
            0x10000c,
        ];
        let insts: [u32; 9] = [
            0xd503201f, 0x9400003f, 0xd503201f, 0xd65f03c0, 0x9400007e, 0xd503201f, 0xd503201f,
            0xd65f03c0, 0xd65f03c0,
        ];
        let mut buf = vec![0u8; REC_SIZE * 9];
        for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
            buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(
            cd.join("meta.json"),
            r#"{"records":9,"known_offsets":{"0x0":"f_root","0x100":"f_alpha","0x200":"f_beta"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
        )
        .unwrap();
        dir
    }

    fn load_trace(dir: &tempfile::TempDir) -> Trace {
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .read_dir()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        Trace::load(&cd).unwrap()
    }

    #[test]
    fn frame_depth_map_root_only_then_one_call() {
        let dir = synth();
        let t = load_trace(&dir);
        let depths = build_frame_depth_map(&t);
        assert_eq!(depths.len(), 9);
        // idx 0 (nop @ f_root): depth 0
        // idx 1 (bl): depth 0 (the bl itself is *at* depth 0; next idx = 1)
        // idx 2 (nop @ f_alpha): depth 1
        // idx 3 (ret @ f_alpha): depth 1 (the ret itself)
        // idx 4 (bl @ f_root): depth 0
        // idx 5..7 (f_beta): depth 1
        // idx 8 (ret @ f_root): depth 0
        assert_eq!(depths[0], 0);
        assert_eq!(depths[1], 0);
        assert_eq!(depths[2], 1);
        assert_eq!(depths[3], 1);
        assert_eq!(depths[4], 0);
        assert_eq!(depths[5], 1);
        assert_eq!(depths[8], 0);
    }

    #[test]
    fn forward_taint_empty_when_reg_unused() {
        let dir = synth();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        // The synth trace is all nop / bl / ret — no real reg uses of x0.
        let (hits, stopped) = forward_taint(&t, &idx, 0, "x0", 100, &exclude);
        assert!(hits.is_empty(), "no x0 use in synth trace");
        assert!(!stopped);
    }

    #[test]
    fn backward_taint_empty_when_reg_undefined() {
        let dir = synth();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, stopped) = backward_taint(&t, &idx, 8, "x0", 100, &exclude);
        assert!(hits.is_empty(), "no x0 def in synth trace");
        assert!(!stopped);
    }

    #[test]
    fn forward_taint_max_count_caps() {
        // Construct a tiny synthetic Index by hand: reg "x0" used at idxs
        // 1, 2, 3, 4, 5. forward_taint with max_count=3 should stop at 3
        // hits with stopped=true.
        // Easier: synth a Trace where every record uses x0 trivially.
        // For MVP: use a 5-record `add x0, x0, #1` chain.
        // Opcode for `add x0, x0, #1` = 0x91000400.
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_5r_1ms");
        std::fs::create_dir_all(&cd).unwrap();
        let mut buf = vec![0u8; REC_SIZE * 5];
        for i in 0..5 {
            let off = i * REC_SIZE;
            let pc = 0x100000u64 + (i as u64) * 4;
            buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
            buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&0x91000400u32.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":5}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x100000","size":4096}}"#,
        )
        .unwrap();
        let t = load_trace(&dir);
        let idx = Index::build(&t);
        let exclude = HashSet::new();
        let (hits, stopped) = forward_taint(&t, &idx, 0, "x0", 3, &exclude);
        assert_eq!(hits.len(), 3, "should stop after 3 hits");
        assert!(stopped, "max_count truncation should set stopped=true");
        for h in &hits {
            assert!(h.why.contains("x0"), "hit row references x0: {h:?}");
        }
    }
}
```

If `add x0, x0, #1` opcode `0x91000400` doesn't decode to `regs_use=[x0]`, swap for any opcode that does — e.g. `add x0, x0, x1` (`0x8b010000`) and ensure x0 is in regs_use. Verify by adding a one-line `eprintln!("{d:?}")` after `decode` in a fresh test, then remove it.

- [ ] **Step 4: Run colocated tests — must PASS**

Run: `cargo test -p tracemiku-core --lib taint -- --nocapture 2>&1 | tail -25`
Expected: 4 tests passed.

If the `forward_taint_max_count_caps` test fails because the chosen opcode doesn't read x0 (e.g. `add x0, x1, x2` doesn't read x0), check the actual `regs_use` via the eprintln approach above and pick the right opcode.

- [ ] **Step 5: Clippy clean**

Run: `cargo clippy -p tracemiku-core --tests 2>&1 | tail -10`
Expected: no warnings beyond pre-existing. If `items_after_test_module` fires, the `#[cfg(test)] mod tests` block is at file end as required.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-core/src/taint.rs \
        rust/crates/tracemiku-core/src/lib.rs \
        rust/crates/tracemiku-core/src/prelude.rs
git commit -m "$(cat <<'EOF'
feat(core): tracemiku-core::taint — index-accelerated forward + backward + frame_depth

MVP scope: heap-driven taint over Index::reg_uses / reg_defs, optional
exclude_regs set. Out of scope: through_mem, data_only, cross_fn_call,
slow-path fallback (M3-γ).

  forward:  BinaryHeap<Reverse<(next_use_idx, reg, cursor)>>  — pop min
  backward: BinaryHeap<(latest_def_idx, reg)>                  — pop max

build_frame_depth_map walks once (depth+=1 on bl/blr, depth-=1 on ret),
returns Vec<u32>. Wired through prelude for M3-γ cross_fn_call.

Tests: frame-depth shape, forward/backward empty, forward max_count cap.

M3-β Task 1.
EOF
)"
```

---

## Task 2: `GET /api/forward-taint` + `GET /api/backward-taint` + AppState wiring

**Files:**
- Modify: `rust/crates/tracemiku-server/src/state.rs`
- Create: `rust/crates/tracemiku-server/src/routes/forward_taint.rs`
- Create: `rust/crates/tracemiku-server/src/routes/backward_taint.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/mod.rs`
- Create: `rust/crates/tracemiku-server/tests/test_taint_routes.rs`

Wire shape (forward; backward swaps `hits`→`chain` and `why`→`via`, plus path):

```json
{
  "count": 3,
  "from": 0,
  "reg": "x0",
  "hits": [
    { "idx": 1, "pc": "0x100004", "rel": "0x4", "func": "f_root",
      "asm": "add x0, x0, #0x1", "why": "regs:x0" },
    ...
  ],
  "stopped_at_max": false,
  "max_count_used": 5000
}
```

Hard ceiling on `max_count`: 50_000 (matches Python `TAINT_MAX_COUNT_CEILING`). Anything larger is silently clamped.

- [ ] **Step 1: Extend AppState with frame_depths**

Edit `rust/crates/tracemiku-server/src/state.rs`. Add to imports:

```rust
use tracemiku_core::prelude::{
    build_call_tree, build_frame_depth_map, build_from_trace, build_function_index,
    CallNode, FunctionIndex, Index, MemShadow, ModuleResolver, SymbolMap,
    Trace, TraceMeta, CFG,
};
```

Add field:

```rust
pub struct AppStateInner {
    // ... existing fields
    pub frame_depths: Vec<u32>,
}
```

In `AppState::load`, after `let call_tree = build_call_tree(...);`:

```rust
        let frame_depths = build_frame_depth_map(&trace);
```

Add to constructor.

- [ ] **Step 2: Create the route handler shared utility**

The two route files share a "decorate hit row with pc/rel/func/asm" step. Inline the logic in each handler (it's ~10 lines and fragmenting it across files for one shared helper isn't worth it for two consumers).

Create `rust/crates/tracemiku-server/src/routes/forward_taint.rs`:

```rust
//! GET /api/forward-taint — index-accelerated forward taint.

use std::collections::HashSet;

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::disasm::decode;
use tracemiku_core::prelude::forward_taint;

use crate::state::AppState;

const MAX_COUNT_CEILING: usize = 50_000;
const DEFAULT_MAX_COUNT: usize = 5_000;

#[derive(Debug, Deserialize)]
pub struct ForwardTaintQuery {
    pub start: usize,
    pub reg: String,
    pub max_count: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct TaintRow {
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub func: Option<String>,
    pub asm: String,
    pub why: String,
}

#[derive(Debug, Serialize)]
pub struct ForwardTaintResponse {
    pub count: usize,
    pub from: usize,
    pub reg: String,
    pub hits: Vec<TaintRow>,
    pub stopped_at_max: bool,
    pub max_count_used: usize,
}

pub async fn forward_taint_handler(
    State(state): State<AppState>,
    Query(q): Query<ForwardTaintQuery>,
) -> Json<ForwardTaintResponse> {
    let inner = &state.inner;
    let raw = q.max_count.unwrap_or(DEFAULT_MAX_COUNT);
    let eff = raw.min(MAX_COUNT_CEILING);
    let exclude: HashSet<String> = HashSet::new();
    let (hits, stopped) =
        forward_taint(&inner.trace, &inner.index, q.start, &q.reg, eff, &exclude);

    let base = inner
        .meta
        .module
        .as_ref()
        .map(|m| u64::from_str_radix(m.base.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0);

    let rows: Vec<TaintRow> = hits
        .into_iter()
        .map(|h| {
            let r = inner.trace.record(h.idx);
            let d = decode(r.pc, r.inst);
            let (fname, _) = inner.symbols.lookup(r.pc);
            TaintRow {
                idx: h.idx,
                pc: format!("{:#x}", r.pc),
                rel: if base != 0 {
                    Some(format!("{:#x}", r.pc - base))
                } else {
                    None
                },
                func: if fname == "?" { None } else { Some(fname) },
                asm: format!("{} {}", d.mnemonic, d.op_str),
                why: h.why,
            }
        })
        .collect();

    Json(ForwardTaintResponse {
        count: rows.len(),
        from: q.start,
        reg: q.reg,
        hits: rows,
        stopped_at_max: stopped,
        max_count_used: eff,
    })
}
```

Create `rust/crates/tracemiku-server/src/routes/backward_taint.rs` — identical structure with these textual swaps:
- field name `hits` → `chain`
- field name `why` → `via`
- struct `ForwardTaintResponse` → `BackwardTaintResponse`
- struct `ForwardTaintQuery` → `BackwardTaintQuery`
- struct `TaintRow` → reuse via `pub use forward_taint::TaintRow as ForwardTaintRow;` is **not** worth it; just declare a parallel `TaintChainRow` struct with `via` instead of `why`. Code duplication is intentional (avoids a third file just to share types).

Actually — since the only difference between TaintRow and TaintChainRow is the field name, simpler approach: parameterize the wire-shape with `serde(rename = "...")`. But that adds magic for one-time savings. **Decision: ship two parallel structs.** Each handler file remains ~80 lines and self-contained.

- [ ] **Step 3: Register routes in `routes/mod.rs`**

Add module decls alphabetically:

```rust
pub mod backward_taint;
pub mod call_tree;
pub mod cfg;
pub mod forward_taint;
pub mod functions;
// ... rest unchanged
```

Add route registrations grouped:

```rust
        .route("/api/forward-taint", get(forward_taint::forward_taint_handler))
        .route("/api/backward-taint", get(backward_taint::backward_taint_handler))
```

Place these next to `/api/last-write-of-reg` (the closest analog — register-side query).

- [ ] **Step 4: Integration tests**

Create `rust/crates/tracemiku-server/tests/test_taint_routes.rs`. Use the same 5-record `add x0, x0, #1` chain from Task 1 Step 3 (the Task 1 fixture). Hit `/api/forward-taint?start=0&reg=x0&max_count=10` and assert:
- HTTP 200
- `count >= 1` (at least one hit on x0)
- `from == 0`, `reg == "x0"`
- `stopped_at_max == false`
- Each row has non-empty `pc`, `asm`, and `why` containing "x0"

Mirror for backward: hit `/api/backward-taint?start=4&reg=x0&max_count=10`, assert non-empty `chain` with `via` containing "x0".

If the synth fixture fails to load (e.g. records=5 disagrees with file size), check the per-call `meta.json` records-count matches the file byte count / 272.

- [ ] **Step 5: Run all server tests**

```bash
cargo test -p tracemiku-server 2>&1 | tail -10
```

Expected: previous 13 tests + 2 new = 15 tests passing.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-server/src/state.rs \
        rust/crates/tracemiku-server/src/routes/forward_taint.rs \
        rust/crates/tracemiku-server/src/routes/backward_taint.rs \
        rust/crates/tracemiku-server/src/routes/mod.rs \
        rust/crates/tracemiku-server/tests/test_taint_routes.rs
git commit -m "$(cat <<'EOF'
feat(server): GET /api/forward-taint + /api/backward-taint

Wire shape mirrors Python webui ForwardTaintReadyResponse /
BackwardTaintReadyResponse. Hard ceiling 50_000 (matches Python).
AppState pre-builds frame_depths (M3-γ cross_fn_call hookpoint).

Each row decorates with pc/rel/func/asm via per-hit decode + symbols
lookup — keeps the core taint module dependency-free.

M3-β Task 2.
EOF
)"
```

---

## Task 3: Frontend `TaintPanel`

**Files:**
- Modify: `frontend/src/api/types.ts`
- Modify: `frontend/src/api/client.ts`
- Create: `frontend/src/panels/taint/TaintPanel.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/styles/base.css`

A simple two-input panel: `start_idx` (number), `reg` (text, default `x0`), direction toggle (forward / backward), max count (number, default 200). Run button triggers fetch. Results table with columns: idx · pc · func · asm · why/via.

- [ ] **Step 1: Add types**

Append to `frontend/src/api/types.ts`:

```typescript
// ── /api/forward-taint, /api/backward-taint ───────────────────────────────

export interface TaintRow {
  idx: number;
  pc: string;
  rel: string | null;
  func: string | null;
  asm: string;
  why?: string;     // forward
  via?: string;     // backward
}

export interface ForwardTaintResponse {
  count: number;
  from: number;
  reg: string;
  hits: TaintRow[];
  stopped_at_max: boolean;
  max_count_used: number;
}

export interface BackwardTaintResponse {
  count: number;
  from: number;
  reg: string;
  chain: TaintRow[];
  stopped_at_max: boolean;
  max_count_used: number;
}
```

- [ ] **Step 2: Add client helpers**

Append to `frontend/src/api/client.ts` (and add the 2 new types to the import block at top):

```typescript
export async function fetchForwardTaint(
  start: number,
  reg: string,
  maxCount = 200,
): Promise<ForwardTaintResponse> {
  const params = new URLSearchParams({
    start: String(start),
    reg,
    max_count: String(maxCount),
  });
  const r = await fetch(`/api/forward-taint?${params}`);
  if (!r.ok) throw new Error(`/api/forward-taint ${r.status}: ${await r.text()}`);
  return (await r.json()) as ForwardTaintResponse;
}

export async function fetchBackwardTaint(
  start: number,
  reg: string,
  maxCount = 200,
): Promise<BackwardTaintResponse> {
  const params = new URLSearchParams({
    start: String(start),
    reg,
    max_count: String(maxCount),
  });
  const r = await fetch(`/api/backward-taint?${params}`);
  if (!r.ok) throw new Error(`/api/backward-taint ${r.status}: ${await r.text()}`);
  return (await r.json()) as BackwardTaintResponse;
}
```

- [ ] **Step 3: Create the panel**

Create `frontend/src/panels/taint/TaintPanel.tsx`:

```tsx
import { Component, createSignal, For, Show } from "solid-js";

import { fetchBackwardTaint, fetchForwardTaint } from "~/api/client";
import type { TaintRow } from "~/api/types";

type Direction = "forward" | "backward";

interface RunResult {
  rows: TaintRow[];
  count: number;
  stopped: boolean;
  direction: Direction;
}

export default function TaintPanel() {
  const [start, setStart] = createSignal(0);
  const [reg, setReg] = createSignal("x0");
  const [direction, setDirection] = createSignal<Direction>("forward");
  const [maxCount, setMaxCount] = createSignal(200);
  const [running, setRunning] = createSignal(false);
  const [result, setResult] = createSignal<RunResult | null>(null);
  const [error, setError] = createSignal<string | null>(null);

  async function run() {
    setRunning(true);
    setError(null);
    try {
      const dir = direction();
      if (dir === "forward") {
        const resp = await fetchForwardTaint(start(), reg(), maxCount());
        setResult({
          rows: resp.hits,
          count: resp.count,
          stopped: resp.stopped_at_max,
          direction: "forward",
        });
      } else {
        const resp = await fetchBackwardTaint(start(), reg(), maxCount());
        setResult({
          rows: resp.chain,
          count: resp.count,
          stopped: resp.stopped_at_max,
          direction: "backward",
        });
      }
    } catch (e: unknown) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setRunning(false);
    }
  }

  const labelFor = (row: TaintRow): string =>
    row.why ?? row.via ?? "";

  return (
    <section class="panel">
      <h2>Taint</h2>
      <div class="taint-controls">
        <label>
          start
          <input
            type="number"
            min="0"
            value={start()}
            onInput={(e) => setStart(Number(e.currentTarget.value) || 0)}
          />
        </label>
        <label>
          reg
          <input
            type="text"
            value={reg()}
            onInput={(e) => setReg(e.currentTarget.value)}
          />
        </label>
        <label>
          direction
          <select
            value={direction()}
            onChange={(e) =>
              setDirection(e.currentTarget.value as Direction)
            }
          >
            <option value="forward">forward</option>
            <option value="backward">backward</option>
          </select>
        </label>
        <label>
          max
          <input
            type="number"
            min="1"
            max="50000"
            value={maxCount()}
            onInput={(e) =>
              setMaxCount(Number(e.currentTarget.value) || 200)
            }
          />
        </label>
        <button type="button" disabled={running()} onClick={run}>
          {running() ? "running…" : "Run"}
        </button>
      </div>
      <Show when={error()}>
        <p class="err">{error()}</p>
      </Show>
      <Show when={result()}>
        {(r) => (
          <>
            <p class="dim small">
              {r().direction} · {r().count} row{r().count === 1 ? "" : "s"}
              <Show when={r().stopped}>
                {" "}· stopped at max
              </Show>
            </p>
            <table class="taint-table">
              <thead>
                <tr>
                  <th>idx</th>
                  <th>pc</th>
                  <th>func</th>
                  <th>asm</th>
                  <th>{r().direction === "forward" ? "why" : "via"}</th>
                </tr>
              </thead>
              <tbody>
                <For each={r().rows}>
                  {(row) => (
                    <tr>
                      <td>{row.idx}</td>
                      <td class="dim small">{row.pc}</td>
                      <td>{row.func ?? "?"}</td>
                      <td>{row.asm}</td>
                      <td>{labelFor(row)}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </>
        )}
      </Show>
    </section>
  );
}
```

- [ ] **Step 4: Mount in App + add styles**

Edit `frontend/src/App.tsx`:

```tsx
import TaintPanel from "./panels/taint/TaintPanel";
// ...

      <FunctionsPanel />
      <CallTreePanel />
      <TaintPanel />
      <StringsPanel />
      <RecordsPanel />
```

Append to `frontend/src/styles/base.css`:

```css
.taint-controls { display: flex; gap: 1em; align-items: center; margin: 0.5em 0; flex-wrap: wrap; }
.taint-controls input[type="number"] { width: 5em; }
.taint-controls input[type="text"] { width: 5em; }
.taint-controls select { padding: 2px 4px; }
.taint-table { width: 100%; border-collapse: collapse; font-family: monospace; font-size: 12px; }
.taint-table th, .taint-table td { padding: 2px 6px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.06); }
.taint-table th { color: var(--dim, #888); font-weight: normal; }
```

- [ ] **Step 5: Build**

```bash
cd frontend && npm run build 2>&1 | tail -8
```
Expected: tsc + vite build clean.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/api/types.ts frontend/src/api/client.ts \
        frontend/src/panels/taint/TaintPanel.tsx frontend/src/App.tsx \
        frontend/src/styles/base.css
git commit -m "$(cat <<'EOF'
feat(frontend): TaintPanel — start/reg/direction/max + results table

Two endpoints (forward + backward) behind a direction toggle. Results
table with idx/pc/func/asm/why-or-via columns. Inputs default to
start=0, reg=x0, max=200 — minimal cost on accidental click.

M3-β Task 3.
EOF
)"
```

---

## Task 4: `scripts/m3_beta_parity.py` — structural parity gate

**Files:**
- Create: `scripts/m3_beta_parity.py`

Pattern matches `scripts/m3_alpha_parity.py`. Differences:
- Two endpoints to compare: `/api/forward-taint?start=0&reg=x0&max_count=200`, `/api/backward-taint?start=N-1&reg=x0&max_count=200` where N=meta.records.
- For each endpoint, compare on the **set of hit indices** (i.e. `{row.idx for row in resp.hits|chain}`). Tolerance: Jaccard ≥ 0.6.
- Wire shape sanity: `count`, `from`, `reg` exist on both responses.

If the chosen `start`/`reg` returns 0 hits on Python (likely on a synthetic trace where x0 is never used), **the script should not error** — just print `# trivial parity (both empty)`. This avoids a flaky gate on small fixtures.

- [ ] **Step 1: Write the script**

Mostly copy `scripts/m3_alpha_parity.py` and adapt:

```python
"""M3-β parity differ — /api/forward-taint + /api/backward-taint.

Boots Python webui + Rust tracemiku-server, fetches forward-taint and
backward-taint with start=0/reg=x0/max=200 and start=N-1/reg=x0/max=200.
Compares the hit-idx set Jaccard between Python and Rust on each endpoint.
Tolerance ≥ 0.6. Trivial-parity case (both empty) is OK.

Usage:
    uv run python scripts/m3_beta_parity.py <call_dir>
"""
# (boilerplate — free_port, wait_listening, fetch — copy from m3_alpha_parity.py)

# In main():
#   meta = fetch(rs_port, "/api/meta")
#   n = meta["records"]
#
#   for path, key, label in [
#       ("/api/forward-taint?start=0&reg=x0&max_count=200", "hits", "forward-taint"),
#       (f"/api/backward-taint?start={max(n - 1, 0)}&reg=x0&max_count=200", "chain", "backward-taint"),
#   ]:
#       py = fetch(py_port, path)
#       rs = fetch(rs_port, path)
#       py_idx = {row["idx"] for row in py.get(key, [])}
#       rs_idx = {row["idx"] for row in rs.get(key, [])}
#       if not py_idx and not rs_idx:
#           print(f"# trivial parity (both empty): {label}", file=sys.stderr)
#           continue
#       common = py_idx & rs_idx
#       union  = py_idx | rs_idx
#       jaccard = len(common) / len(union) if union else 1.0
#       if jaccard < 0.6:
#           diffs.append(f"  {label} hit-idx jaccard={jaccard:.2f}")
#           diffs.append(f"  py-only sample: {sorted(py_idx - rs_idx)[:5]}")
#           diffs.append(f"  rs-only sample: {sorted(rs_idx - py_idx)[:5]}")
#
#   if diffs: ... else: print("OK ...")
```

(Implementer should expand the boilerplate copy from m3_alpha_parity.py — keep `free_port`, `wait_listening`, `fetch`, the Popen pair + `os.killpg` cleanup. Replace the body of `main()` with the loop above.)

- [ ] **Step 2: Build the Rust release binary (if not already from M3-α)**

```bash
cd rust && cargo build --release -p tracemiku-server 2>&1 | tail -3
```

- [ ] **Step 3: Run on the standard small trace**

```bash
cd /home/ltlly/Code/traceMiku
chmod +x scripts/m3_beta_parity.py
uv run python scripts/m3_beta_parity.py traces/test_hide_only/calls/_truncated_call_002_tid27340_469639r_1641ms
```

Expected: `OK — /api/forward-taint + /api/backward-taint (jaccard fwd=X bwd=Y)` (or trivial-parity messages if x0 isn't used).

If MISMATCH on jaccard, dump both index sets symmetric diff (the script does this automatically per the boilerplate above) and decide: real semantic drift → BLOCK, or expected (e.g. Python `data_only` default differs because the Rust port has no `data_only` flag yet → in scope for M3-γ).

- [ ] **Step 4: Commit**

```bash
chmod +x scripts/m3_beta_parity.py
git add scripts/m3_beta_parity.py
git commit -m "test(parity): scripts/m3_beta_parity.py — fwd/bwd taint hit-idx jaccard"
```

---

## Task 5: Spec/TODO sync + final M3-β verification

**Files:**
- Modify: `TODO.md`
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`

- [ ] **Step 1: Run full sweep**

```bash
cd rust && cargo test --workspace 2>&1 | grep -E "test result:|FAILED" | tail -25
cd ../frontend && npm run build 2>&1 | tail -5
cd .. && uv run python scripts/m3_beta_parity.py traces/test_hide_only/calls/_truncated_call_002_tid27340_469639r_1641ms 2>&1 | tail -3
```
Expected: all green.

- [ ] **Step 2: Update spec §13.5**

Find rows for `taint.py`, `/api/forward-taint`, `/api/backward-taint`. Change `🔜 M3` → `✅ M3-β`. Note in the right-side cell whether `through_mem` / `data_only` / `cross_fn_call` are deferred (yes — to M3-γ).

- [ ] **Step 3: Update TODO.md**

Append:

```markdown
- M3-β `tracemiku-core::taint` (forward/backward index-accelerated, frame_depth_map): ✅ 2026-05-04
- M3-β /api/forward-taint + /api/backward-taint + TaintPanel: ✅ 2026-05-04
- M3-β scripts/m3_beta_parity.py: ✅ 2026-05-04
```

Update the M3 sub-milestone roadmap to mark β as complete:

```markdown
- M3-β (this): basic taint forward/backward + frame_depth + 2 endpoints + TaintPanel + parity ✅ 2026-05-04
- M3-γ (next): taint advanced flags (through_mem, data_only, cross_fn_call) + decompiler::backend stub + TraceIR builder skeleton
```

- [ ] **Step 4: Commit**

```bash
git add TODO.md docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md
git commit -m "$(cat <<'EOF'
docs(v2): mark M3-β complete + roadmap update

Shipped:
  - tracemiku-core::taint (basic forward/backward + frame_depth_map) → ✅ M3-β
  - /api/forward-taint + /api/backward-taint → ✅ M3-β
  - frontend TaintPanel → ✅ M3-β
  - scripts/m3_beta_parity.py → ✅ M3-β

Deferred to M3-γ (advanced taint): through_mem, data_only, cross_fn_call.
Index already populates the byte-level mem-write side, so M3-γ
through_mem mostly piggybacks on existing infrastructure.
EOF
)"
```

---

## Self-Review

**Spec coverage:**

| Spec line | Task |
|---|---|
| `tracemiku-core::taint` (forward/backward MVP) | Task 1 |
| `build_frame_depth_map` | Task 1 |
| `/api/forward-taint` endpoint | Task 2 |
| `/api/backward-taint` endpoint | Task 2 |
| Frontend TaintPanel | Task 3 |
| Parity gate vs Python | Task 4 |
| TODO/spec sync | Task 5 |

**Out of scope (deferred to M3-γ, intentionally):**
- `through_mem` flag (byte-level mem overlap via MemShadow)
- `data_only` flag (filter addressing-reg propagation)
- `cross_fn_call` flag (annotate row with frame_depth — `frame_depths` field already pre-built so M3-γ wiring is cheap)
- Slow-path fallback (Rust always has Index)

**Placeholder scan:** No `TODO`, no `add error handling`. Each step has code or an exact command. The boilerplate copy in Task 4 Step 1 is annotated with explicit "copy from m3_alpha_parity.py" — that's a directed reference, not a placeholder.

**Type consistency:**
- `TaintHit` (Rust core) → `TaintRow` (Rust server with pc/asm enrichment) → `TaintRow` (TS) all carry `idx: usize/number`, optional `why|via: String`. Confirmed.
- `ForwardTaintResponse.hits` ↔ `BackwardTaintResponse.chain` field-name asymmetry matches Python wire shape exactly.
- `max_count_used` is `usize` in Rust → `number` in TS — same as `max_count` everywhere else.

**Algorithmic risk:** the `BinaryHeap<Reverse<...>>` for forward and `BinaryHeap<...>` for backward differ in min/max-heap orientation. Verify by hand:
- Forward: pop the smallest `next_use_idx` first → `Reverse((idx, ...))` makes BinaryHeap (max-heap by default) act as min-heap. Correct.
- Backward: pop the largest `def_idx` first → BinaryHeap default max-heap. Correct.

Both `seen` sets prevent infinite loops on revisited indices.

---

**Plan complete and saved to `docs/superpowers/plans/2026-05-04-analysis-v2-m3-beta.md`.**

Per `CLAUDE.md` user-pref §"Skip the 'Two execution options... Which approach?' handoff at end of plans" — execution choice has already been answered (subagent-driven). Plan executor proceeds via `superpowers:subagent-driven-development`.
