# Analysis v2 — M3-α Implementation Plan (calltree + /api/call-tree + CallTreePanel + parity)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port `viewer/calltree.py` (bl/ret-pair-walked nested call tree) to `tracemiku-core::calltree`, expose it as `GET /api/call-tree?max_depth=N` in `tracemiku-server`, render it in a Solid `CallTreePanel`, and lock parity with the Python webui via a structural comparison script. Wire up the M3 milestone scaffold so M3-β (taint) onwards can pick up the same patterns.

**Architecture:** `tracemiku-core::calltree::build_call_tree(&Trace, &SymbolMap, max_depth) -> CallNode` walks the trace once, matching `bl`/`blr` (push) with `ret` (pop), reading callee names from `SymbolMap::lookup` at the post-call PC (`trace.pc(i+1)`). Eager build at `AppState::load` (small payload, deterministic — same model as `MemShadow`/`FunctionIndex`). Frontend renders an indented tree with collapse/expand and a depth slider. Parity script `scripts/m3_alpha_parity.py` boots Python webui + Rust server side-by-side, fetches `/api/call-tree`, and asserts structural shape (root depth=0, child counts within tolerance, identical bl-target name set).

**Tech Stack:** Rust 1.95, axum 0.7, capstone-rs (already in workspace), Solid+TS+Vite (frontend), Python (parity harness only — `requests` + `subprocess`).

**Branch:** `refactor/function-index-handoff` (current). M3-α streams commits to this branch per `CLAUDE.md` user-pref §"Long-running milestone work should stream commits."

**Spec inputs:**
- `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` §9 milestones M3 row + §13.5 endpoint table (`/api/call-tree` row).
- `viewer/calltree.py` — algorithm reference (75 lines, single function).
- `webui/server.py:1995-2000` — Python `/api/call-tree` reference handler.
- `webui/schemas.py:903-915` — `CallTreeNode` / `CallTreeResponse` wire shape.
- M2-ζ plan `docs/superpowers/plans/2026-05-04-analysis-v2-m2-zeta.md` §"Next (M3, separate plan)" — confirms M3 sub-milestone breakdown.

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-core/src/calltree.rs` (new) | `CallNode`, `build_call_tree(&Trace, &SymbolMap, max_depth) -> CallNode`. Pure function, no axum/serde framework deps beyond `serde::Serialize`. |
| `rust/crates/tracemiku-core/src/lib.rs` (modify) | `pub mod calltree;` after `pub mod cfg;`. |
| `rust/crates/tracemiku-core/src/prelude.rs` (modify) | Re-export `CallNode`, `build_call_tree`. |
| `rust/crates/tracemiku-core/tests/test_calltree.rs` (new) | Synthetic-trace integration tests (root + nested + max_depth cap). |
| `rust/crates/tracemiku-server/src/state.rs` (modify) | `AppState::load` builds call tree eagerly; expose `pub call_tree: CallNode`. |
| `rust/crates/tracemiku-server/src/routes/call_tree.rs` (new) | `call_tree_handler` returns `{tree: CallNode}` with optional `max_depth` query param (rebuilds when overridden). |
| `rust/crates/tracemiku-server/src/routes/mod.rs` (modify) | Add `pub mod call_tree;` + `.route("/api/call-tree", get(call_tree::call_tree_handler))`. |
| `frontend/src/api/types.ts` (modify) | Add `CallNode`, `CallTreeResponse`. |
| `frontend/src/panels/calltree/CallTreePanel.tsx` (new) | Solid component: depth slider, indented expand/collapse tree, fn-name + idx range. |
| `frontend/src/App.tsx` (modify) | Mount `<CallTreePanel />` after `<FunctionsPanel />`. |
| `scripts/m3_alpha_parity.py` (new) | Boot both servers, fetch `/api/call-tree?max_depth=10`, structural-compare. |
| `tools/synth_targets/build_calltree_smoke_trace.py` (new — only if existing fixtures inadequate) | Build a fixed synthetic trace (root → bl alpha → bl beta) for parity script. |
| `TODO.md` (modify) | Append `M3-α` row to "进度概览"; refine "M3 (next)" pointer. |
| `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` (modify) | Mark `/api/call-tree` and `tracemiku-core::calltree` cells as `✅ M3-α`. |

**Synthetic trace fixture** — Rust integration tests use a hand-rolled `Trace` builder (existing pattern: see `rust/crates/tracemiku-core/tests/test_index.rs` if present, else build via `tempfile` + writing 272-byte records). Frontend tests intentionally out of scope for M3-α (Solid component test infra not yet set up — separate M3-η plan).

---

## Task 1: `tracemiku-core::calltree` port (TDD)

**Files:**
- Create: `rust/crates/tracemiku-core/src/calltree.rs`
- Modify: `rust/crates/tracemiku-core/src/lib.rs`
- Modify: `rust/crates/tracemiku-core/src/prelude.rs`
- Create: `rust/crates/tracemiku-core/tests/test_calltree.rs`

Rust direct port of `viewer/calltree.py:22-75`. Algorithm verbatim; only Rust-flavor difference: `CallNode` is a struct with serde derives instead of a Python dict, and `Vec<CallNode>` for children.

- [ ] **Step 1: Inspect existing core test pattern**

```bash
ls rust/crates/tracemiku-core/tests/ 2>/dev/null || echo "(no tests/ dir yet)"
find rust/crates/tracemiku-core -name 'test_*.rs' -o -name '*_test.rs' 2>/dev/null
```

If there are no integration tests yet (likely on this branch), use `rust/crates/tracemiku-core/src/cfg.rs` `#[cfg(test)] mod tests` style as the precedent — colocate tests in the source file. Otherwise mirror whatever test layout exists.

For this plan we colocate tests in `calltree.rs` (`#[cfg(test)] mod tests`) **and** add a single integration test under `tests/test_calltree.rs` for the end-to-end build path. Both styles coexist in workspace conventions.

- [ ] **Step 2: Write the failing colocated unit test for the empty trace**

Create `rust/crates/tracemiku-core/src/calltree.rs` with this body (test only, no implementation yet):

```rust
//! Build nested call tree from trace by walking bl/ret pairs.
//!
//! Direct port of `viewer/calltree.py`. See that file's module docstring
//! for the algorithm + caveats (indirect br x14 tail-calls, b-only tail-calls,
//! Frinet FP-chain not done here).

use serde::Serialize;

use crate::disasm::decode;
use crate::symbols::SymbolMap;
use crate::trace::Trace;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CallNode {
    /// Function name. Root node uses "?" (matches Python).
    /// Children with unknown symbol use None (Python: `cf if cf != "?" else None`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fn_name: Option<String>,
    /// Static entry PC of callee (0 for root). Renamed from Python's `fn_pc`
    /// to avoid Rust keyword shadow; serialized as `fn_pc` for wire parity.
    #[serde(rename = "fn_pc")]
    pub fn_pc: u64,
    pub enter_idx: usize,
    pub exit_idx: usize,
    pub depth: usize,
    pub children: Vec<CallNode>,
    /// Count of children that hit max_depth and were flattened away.
    /// `None` (omitted from JSON) when zero, matching Python which only
    /// sets the key when truncation occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_children: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trace_returns_root_only() {
        // We need a Trace; the simplest construction is via Trace::load
        // on a synth dir. Test driver helper builds it (Step 3 below).
        // For this first failing test, just assert the type signature:
        let f = build_call_tree;
        let _ = f; // referenced — compile-only check
    }
}

/// Build nested call tree.
///
/// `max_depth` caps nesting; deeper calls are flattened into the deepest
/// permitted frame's `truncated_children` count rather than nested further.
/// Prevents runaway HTML for OLLVM auto-recursive jumpouts (Python parity).
pub fn build_call_tree(_trace: &Trace, _sym: &SymbolMap, _max_depth: usize) -> CallNode {
    todo!("M3-α Task 1 Step 4")
}
```

(The `fn_name` field is named `fn_name` in Rust — `fn` is a keyword. JSON key stays `fn` via `#[serde(rename = "fn")]`. Update the field def accordingly:)

```rust
    #[serde(rename = "fn", skip_serializing_if = "Option::is_none")]
    pub fn_name: Option<String>,
```

Add the module hook in `rust/crates/tracemiku-core/src/lib.rs`. Insert after `pub mod cfg;` (line 12 or wherever `cfg` sits):

```rust
pub mod calltree;
```

Add re-export in `rust/crates/tracemiku-core/src/prelude.rs`. After the `pub use crate::cfg::{Block, CFG};` line, add:

```rust
pub use crate::calltree::{build_call_tree, CallNode};
```

- [ ] **Step 3: Compile (failing test) to confirm scaffold compiles**

Run: `cargo build -p tracemiku-core --tests 2>&1 | tail -20`
Expected: build OK with one `unreachable_code`/`todo!` warning. The colocated test compiles trivially since it only references `build_call_tree` symbol.

- [ ] **Step 4: Implement `build_call_tree` (port of Python algorithm)**

Replace the `todo!` stub with the full implementation:

```rust
pub fn build_call_tree(trace: &Trace, sym: &SymbolMap, max_depth: usize) -> CallNode {
    let n = trace.len();
    let last_idx = n.saturating_sub(1);

    // Stack of indices into a single flat `nodes` Vec would be more
    // ergonomic, but Python uses a parent-pointer stack with direct
    // child-list mutation. We mirror the exact behavior using a
    // recursive-friendly Box-on-the-heap pattern: own each frame, build
    // children Vec inline, and unwind on `ret`.
    //
    // Approach: maintain a parallel `stack: Vec<CallNode>` where the last
    // element is the current frame. On `bl/blr`: push new child. On
    // `ret`: pop top, push it onto the second-from-top's `children`.

    let root = CallNode {
        fn_name: Some("?".to_string()),
        fn_pc: 0,
        enter_idx: 0,
        exit_idx: last_idx,
        depth: 0,
        children: Vec::new(),
        truncated_children: None,
    };
    let mut stack: Vec<CallNode> = vec![root];

    for i in 0..n {
        let r = trace.record(i);
        let d = decode(r.pc, r.inst);
        let m = d.mnemonic.as_str();
        let is_call = m == "bl" || m == "blr";
        let is_ret = m == "ret";

        if is_call {
            // Resolve callee name from PC of the *next* trace record (the
            // first instruction the call lands on).
            let target_pc = if i + 1 < n { trace.pc(i + 1) } else { 0 };
            let (cf, _off) = if target_pc != 0 {
                sym.lookup(target_pc)
            } else {
                ("?".to_string(), 0u64)
            };
            let top_depth = stack.last().expect("stack non-empty").depth;
            let new_depth = top_depth + 1;
            if new_depth > max_depth {
                // Cap reached. Mark top as having flattened children.
                let top = stack.last_mut().expect("stack non-empty");
                top.truncated_children = Some(top.truncated_children.unwrap_or(0) + 1);
                // Push a duplicate so the next `ret` balances. Python
                // does `stack.append(top)` — we clone instead. Cheap
                // because this is the cap path only.
                let dup = stack.last().expect("stack non-empty").clone();
                stack.push(dup);
                continue;
            }
            let child = CallNode {
                fn_name: if cf == "?" { None } else { Some(cf) },
                fn_pc: target_pc,
                enter_idx: i,
                exit_idx: i,
                depth: new_depth,
                children: Vec::new(),
                truncated_children: None,
            };
            stack.push(child);
        } else if is_ret {
            if stack.len() > 1 {
                let mut top = stack.pop().expect("stack > 1");
                top.exit_idx = i;
                // Was this frame a duplicate from the cap branch above?
                // Then the popped frame == the new top (same depth).
                // Don't double-attach; just skip (Python: pops cleanly
                // because the pushed dup is the same dict, not a new one).
                let parent_depth = stack.last().expect("stack non-empty").depth;
                if top.depth > parent_depth {
                    let parent = stack.last_mut().expect("stack non-empty");
                    parent.children.push(top);
                }
                // else: dup-balance, parent already counted via
                // truncated_children; popped frame is discarded.
            }
        }
    }

    // Close any remaining open frames at last_idx.
    while stack.len() > 1 {
        let mut top = stack.pop().expect("stack > 1");
        top.exit_idx = last_idx;
        let parent_depth = stack.last().expect("stack non-empty").depth;
        if top.depth > parent_depth {
            let parent = stack.last_mut().expect("stack non-empty");
            parent.children.push(top);
        }
    }
    let mut root = stack.pop().expect("root left");
    root.exit_idx = last_idx;
    root
}
```

**Subtle point — Python `stack.append(top)` semantics.** In Python the cap-path `stack.append(top)` pushes the **same dict** as the current top, not a copy. So the next `ret` pops it, reads its `depth` (== top's depth), and the `if top.depth > parent_depth` check then **fails** (depths equal) → discarded. We replicate that with `let dup = ...clone()` + the depth comparison guarding the `parent.children.push(top)` line. Without the guard the cap-path would double-attach the parent into itself.

- [ ] **Step 5: Add real unit tests in `mod tests`**

Replace the stub colocated test with three real tests. They need a working `Trace`; we use a small in-memory builder that mirrors what existing tests do.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::REC_SIZE;
    use std::io::Write;

    /// Build a synthetic call_dir with a 9-record trace:
    /// idx | pc        | mnem | comment
    ///   0 | 0x100000  | nop  | f_root entry
    ///   1 | 0x100004  | bl   | call f_alpha @ 0x100100
    ///   2 | 0x100100  | nop  | f_alpha entry
    ///   3 | 0x100104  | ret  | f_alpha return
    ///   4 | 0x100008  | bl   | call f_beta  @ 0x100200
    ///   5 | 0x100200  | nop  | f_beta entry
    ///   6 | 0x100204  | nop
    ///   7 | 0x100208  | ret  | f_beta return
    ///   8 | 0x10000c  | ret  | f_root return
    fn synth_trace_dir() -> tempfile::TempDir {
        use capstone::prelude::*;
        let cs = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .unwrap();
        let _ = cs; // not strictly needed; we hand-write opcodes below.

        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("calls").join("call_001_tid1_9r_1ms");
        std::fs::create_dir_all(&cd).unwrap();

        // ARM64 little-endian opcodes:
        //   nop                      = 0xd503201f
        //   ret                      = 0xd65f03c0
        //   bl #+0xfc  (rel +252)    = 0x9400003f
        //   bl #+0x1f8 (rel +504)    = 0x9400007e
        let pcs_and_inst: [(u64, u32); 9] = [
            (0x100000, 0xd503201f),
            (0x100004, 0x9400003f),
            (0x100100, 0xd503201f),
            (0x100104, 0xd65f03c0),
            (0x100008, 0x9400007e),
            (0x100200, 0xd503201f),
            (0x100204, 0xd503201f),
            (0x100208, 0xd65f03c0),
            (0x10000c, 0xd65f03c0),
        ];
        let mut buf = Vec::with_capacity(9 * REC_SIZE);
        for (pc, inst) in pcs_and_inst {
            buf.extend_from_slice(&pc.to_le_bytes());
            for _ in 0..31 {
                buf.extend_from_slice(&0u64.to_le_bytes());
            }
            buf.extend_from_slice(&0x7000u64.to_le_bytes()); // sp
            buf.extend_from_slice(&0u32.to_le_bytes()); // pad
            buf.extend_from_slice(&inst.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(
            cd.join("meta.json"),
            r#"{"callIdx":1,"tid":1,"records":9,"ms":1,"retval":"0x0","truncated":false,"last_insn_is_ret":true}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("meta.json"),
            r#"{"pkg":"t","so":"libt","method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000","known_offsets":{"0x0":"f_root","0x100":"f_alpha","0x200":"f_beta"}}"#,
        )
        .unwrap();
        // Smuggle the call_dir path back via TempDir; caller looks up calls/<single>.
        dir
    }

    fn load_trace_and_sym(dir: &tempfile::TempDir) -> (Trace, SymbolMap) {
        let cd = dir
            .path()
            .join("calls")
            .read_dir()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let trace = Trace::load(&cd).expect("trace loads");
        let mut sym = SymbolMap::new();
        sym.add(0x100000, "f_root".to_string());
        sym.add(0x100100, "f_alpha".to_string());
        sym.add(0x100200, "f_beta".to_string());
        sym.freeze();
        (trace, sym)
    }

    #[test]
    fn empty_trace_returns_root_only() {
        // Construct a 0-record trace by writing a 0-length trace.bin.
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("calls").join("call_001_tid1_0r_0ms");
        std::fs::create_dir_all(&cd).unwrap();
        std::fs::File::create(cd.join("trace.bin")).unwrap();
        std::fs::write(
            cd.join("meta.json"),
            r#"{"callIdx":1,"tid":1,"records":0,"ms":0,"retval":"0x0","truncated":false,"last_insn_is_ret":false}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("meta.json"),
            r#"{"pkg":"t","so":"l","method":"f","cmd":1,"module":{"name":"l.so","base":"0x0","size":0},"fn_addr":"0x0","known_offsets":{}}"#,
        )
        .unwrap();
        let trace = Trace::load(&cd).unwrap();
        let sym = SymbolMap::new();
        let root = build_call_tree(&trace, &sym, 50);
        assert_eq!(root.fn_name.as_deref(), Some("?"));
        assert_eq!(root.depth, 0);
        assert_eq!(root.enter_idx, 0);
        assert_eq!(root.exit_idx, 0);
        assert!(root.children.is_empty());
        assert!(root.truncated_children.is_none());
    }

    #[test]
    fn root_has_two_callees_with_correct_idx_ranges() {
        let dir = synth_trace_dir();
        let (trace, sym) = load_trace_and_sym(&dir);
        let root = build_call_tree(&trace, &sym, 50);
        assert_eq!(root.children.len(), 2, "expected 2 callees of root");
        let alpha = &root.children[0];
        let beta = &root.children[1];
        assert_eq!(alpha.fn_name.as_deref(), Some("f_alpha"));
        assert_eq!(alpha.enter_idx, 1);
        assert_eq!(alpha.exit_idx, 3);
        assert_eq!(alpha.depth, 1);
        assert!(alpha.children.is_empty());
        assert_eq!(beta.fn_name.as_deref(), Some("f_beta"));
        assert_eq!(beta.enter_idx, 4);
        assert_eq!(beta.exit_idx, 7);
    }

    #[test]
    fn max_depth_cap_flattens_into_truncated_children() {
        let dir = synth_trace_dir();
        let (trace, sym) = load_trace_and_sym(&dir);
        // Cap at depth 0 — every child is flattened into root.truncated_children.
        let root = build_call_tree(&trace, &sym, 0);
        assert!(root.children.is_empty(), "depth=0 cap means no nested children");
        assert_eq!(
            root.truncated_children,
            Some(2),
            "two bl-targets flattened into root"
        );
    }
}
```

You also need `tempfile` as a dev-dependency for `tracemiku-core` (already present per `rust/crates/tracemiku-core/Cargo.toml`). If absent, add:

```toml
[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 6: Run colocated tests — must PASS**

Run: `cargo test -p tracemiku-core --lib calltree -- --nocapture 2>&1 | tail -30`
Expected: 3 tests passed.

If `root_has_two_callees_with_correct_idx_ranges` fails, dump the produced tree:
```rust
eprintln!("{}", serde_json::to_string_pretty(&root).unwrap());
```
and reconcile against the trace-walk table in the doc-comment.

- [ ] **Step 7: Verify lib still builds & re-export reachable**

Run: `cargo build -p tracemiku-core 2>&1 | tail -5`
Expected: clean build, no warnings besides any pre-existing ones.

Run: `cargo run -p tracemiku-core --example _exists 2>/dev/null; echo "(no examples — fine)"`
Run: `cargo doc -p tracemiku-core --no-deps 2>&1 | grep -E 'error|warning' | head -5`
Expected: no errors. Warnings on doc references are tolerable.

- [ ] **Step 8: Commit**

```bash
git add rust/crates/tracemiku-core/src/calltree.rs \
        rust/crates/tracemiku-core/src/lib.rs \
        rust/crates/tracemiku-core/src/prelude.rs
git commit -m "$(cat <<'EOF'
feat(core): tracemiku-core::calltree — bl/ret pair-walking call tree

Direct port of viewer/calltree.py. Produces nested CallNode tree with
fn_name, fn_pc, enter_idx, exit_idx, depth, children, truncated_children.
max_depth cap flattens deeper bl-targets into the deepest permitted
frame's truncated_children count (matches Python semantics including
the dup-balance trick on the stack).

Tests:
- empty trace → root-only with fn="?"
- root + two callees → idx ranges match trace-walk table
- max_depth=0 → all children flattened, truncated_children=2

M3-α Task 1.
EOF
)"
```

---

## Task 2: `GET /api/call-tree` endpoint + AppState wiring

**Files:**
- Modify: `rust/crates/tracemiku-server/src/state.rs`
- Create: `rust/crates/tracemiku-server/src/routes/call_tree.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/mod.rs`

The Python webui rebuilds the call tree on every request. For the Rust server we eager-build at `AppState::load` (one-time, deterministic) and rebuild only when the caller passes a non-default `max_depth`. This matches MemShadow's pattern.

- [ ] **Step 1: Extend `AppState`**

Edit `rust/crates/tracemiku-server/src/state.rs`. Update imports:

```rust
use tracemiku_core::prelude::{
    build_call_tree, build_from_trace, build_function_index, CallNode, FunctionIndex, Index,
    MemShadow, ModuleResolver, SymbolMap, Trace, TraceMeta, CFG,
};
```

Add field to `AppStateInner`:

```rust
pub struct AppStateInner {
    pub trace_dir: PathBuf,
    pub meta: TraceMeta,
    pub trace: Trace,
    pub index: Index,
    pub symbols: SymbolMap,
    pub modules: ModuleResolver,
    pub cfg: CFG,
    pub function_index: FunctionIndex,
    pub memshadow: MemShadow,
    pub call_tree: CallNode,
}
```

In `AppState::load`, after `let memshadow = MemShadow::build_from_trace(&trace);`, insert:

```rust
        let call_tree = build_call_tree(&trace, &symbols, 50);
```

Add to the constructed `AppStateInner`:

```rust
            call_tree,
```

- [ ] **Step 2: Confirm server builds**

Run: `cargo build -p tracemiku-server 2>&1 | tail -10`
Expected: clean build.

- [ ] **Step 3: Write the failing route test**

Create `rust/crates/tracemiku-server/tests/test_call_tree_route.rs` (mirror existing route test pattern; if no `tests/` exists yet, the integration tests can live colocated in `routes/call_tree.rs` under `#[cfg(test)] mod tests`).

```rust
//! /api/call-tree integration test.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

fn synth_trace_dir() -> tempfile::TempDir {
    // Same builder as in tracemiku-core::calltree::tests::synth_trace_dir.
    // Duplicate intentionally — keeping core tests core-only and server
    // tests server-only avoids public-export bloat.
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let cd = dir.path().join("calls").join("call_001_tid1_9r_1ms");
    std::fs::create_dir_all(&cd).unwrap();
    let pcs_and_inst: [(u64, u32); 9] = [
        (0x100000, 0xd503201f),
        (0x100004, 0x9400003f),
        (0x100100, 0xd503201f),
        (0x100104, 0xd65f03c0),
        (0x100008, 0x9400007e),
        (0x100200, 0xd503201f),
        (0x100204, 0xd503201f),
        (0x100208, 0xd65f03c0),
        (0x10000c, 0xd65f03c0),
    ];
    let mut buf = Vec::with_capacity(9 * 272);
    for (pc, inst) in pcs_and_inst {
        buf.extend_from_slice(&pc.to_le_bytes());
        for _ in 0..31 {
            buf.extend_from_slice(&0u64.to_le_bytes());
        }
        buf.extend_from_slice(&0x7000u64.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&inst.to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), &buf).unwrap();
    std::fs::write(
        cd.join("meta.json"),
        r#"{"callIdx":1,"tid":1,"records":9,"ms":1,"retval":"0x0","truncated":false,"last_insn_is_ret":true}"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("meta.json"),
        r#"{"pkg":"t","so":"libt","method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000","known_offsets":{"0x0":"f_root","0x100":"f_alpha","0x200":"f_beta"}}"#,
    )
    .unwrap();
    dir.path().join("calls").read_dir().unwrap();
    dir
}

#[tokio::test]
async fn call_tree_default_max_depth() {
    let dir = synth_trace_dir();
    let cd = dir
        .path()
        .join("calls")
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/call-tree")
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
    let tree = &v["tree"];
    assert_eq!(tree["fn"], "?");
    assert_eq!(tree["depth"], 0);
    let children = tree["children"].as_array().unwrap();
    assert_eq!(children.len(), 2);
    assert_eq!(children[0]["fn"], "f_alpha");
    assert_eq!(children[1]["fn"], "f_beta");
}

#[tokio::test]
async fn call_tree_max_depth_zero_flattens_children() {
    let dir = synth_trace_dir();
    let cd = dir
        .path()
        .join("calls")
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/call-tree?max_depth=0")
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
    let tree = &v["tree"];
    assert!(tree["children"].as_array().unwrap().is_empty());
    assert_eq!(tree["truncated_children"], 2);
}
```

You'll also need `tower` + `axum` + `tempfile` + `tokio` dev-dependencies in `rust/crates/tracemiku-server/Cargo.toml` (most already present). Verify:

```bash
grep -A 5 dev-dependencies rust/crates/tracemiku-server/Cargo.toml
```

If `tempfile` or `tower` is missing, add:

```toml
[dev-dependencies]
tempfile = "3"
tower = { workspace = true }
tokio = { workspace = true, features = ["macros", "rt"] }
```

- [ ] **Step 4: Run failing test**

Run: `cargo test -p tracemiku-server --test test_call_tree_route 2>&1 | tail -10`
Expected: FAIL — "404 Not Found" because the route isn't registered yet.

- [ ] **Step 5: Implement the route**

Create `rust/crates/tracemiku-server/src/routes/call_tree.rs`:

```rust
//! GET /api/call-tree — nested call tree (bl/ret pair-walked).

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::{build_call_tree, CallNode};

use crate::state::AppState;

const DEFAULT_MAX_DEPTH: usize = 50;

#[derive(Debug, Deserialize)]
pub struct CallTreeQuery {
    pub max_depth: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct CallTreeResponse {
    pub tree: CallNode,
}

pub async fn call_tree_handler(
    State(state): State<AppState>,
    Query(q): Query<CallTreeQuery>,
) -> Json<CallTreeResponse> {
    let inner = &state.inner;
    let depth = q.max_depth.unwrap_or(DEFAULT_MAX_DEPTH);
    let tree = if depth == DEFAULT_MAX_DEPTH {
        // Reuse the eagerly-built tree from AppState.
        inner.call_tree.clone()
    } else {
        build_call_tree(&inner.trace, &inner.symbols, depth)
    };
    Json(CallTreeResponse { tree })
}
```

Edit `rust/crates/tracemiku-server/src/routes/mod.rs`. Add module declaration alphabetically:

```rust
pub mod call_tree;
pub mod cfg;
pub mod functions;
pub mod idxs_for_block;
pub mod idxs_for_pc;
pub mod last_write_of_reg;
pub mod mem_dump;
pub mod meta;
pub mod record;
pub mod records;
pub mod strings;
```

Add the route registration:

```rust
        .route("/api/call-tree", get(call_tree::call_tree_handler))
```

Place it next to `/api/cfg` for grouping with other tree-style endpoints.

- [ ] **Step 6: Run integration test — must PASS**

Run: `cargo test -p tracemiku-server --test test_call_tree_route 2>&1 | tail -20`
Expected: 2 tests passed.

If the depth-0 test fails with 1 child instead of 0, the eager-built tree (at depth 50) is being returned despite `max_depth=0` — verify the `if depth == DEFAULT_MAX_DEPTH` branch.

- [ ] **Step 7: Run full server test suite to confirm no regression**

Run: `cargo test -p tracemiku-server 2>&1 | tail -10`
Expected: all green.

- [ ] **Step 8: Commit**

```bash
git add rust/crates/tracemiku-server/src/state.rs \
        rust/crates/tracemiku-server/src/routes/call_tree.rs \
        rust/crates/tracemiku-server/src/routes/mod.rs \
        rust/crates/tracemiku-server/tests/test_call_tree_route.rs
# also add Cargo.toml if dev-deps changed:
git add rust/crates/tracemiku-server/Cargo.toml 2>/dev/null
git commit -m "$(cat <<'EOF'
feat(server): GET /api/call-tree — eager build + max_depth override

AppState eagerly builds CallNode at depth 50 (matches Python default).
Endpoint reuses cached tree when default depth is requested; rebuilds
on any other depth. Wire shape:

  { "tree": { "fn":"?", "fn_pc":0, "enter_idx":0, "exit_idx":N-1,
              "depth":0, "children":[...], "truncated_children":<int|absent> } }

Children with unknown symbol omit the "fn" key (None → skip_serializing).

Tests: default + max_depth=0 (cap-flatten) on synth root+2-callees trace.

M3-α Task 2.
EOF
)"
```

---

## Task 3: Frontend `CallTreePanel` (Solid + TS)

**Files:**
- Modify: `frontend/src/api/types.ts`
- Create: `frontend/src/panels/calltree/CallTreePanel.tsx`
- Modify: `frontend/src/App.tsx`

Match the existing panel pattern (see `StringsPanel.tsx`). Single fetch, no global store, depth slider, expandable rows. Optimize for the existing Solid+vanilla-CSS aesthetic; no new dep additions.

- [ ] **Step 1: Read the StringsPanel for reference**

```bash
cat frontend/src/panels/strings/StringsPanel.tsx | head -120
```

Match its file size and patterns: `createSignal`, `createResource`, controls row, table, error banner.

- [ ] **Step 2: Add types**

Append to `frontend/src/api/types.ts`:

```typescript
// ── /api/call-tree ────────────────────────────────────────────────────────

export interface CallNode {
  fn?: string | null;     // omitted from wire when null/unknown
  fn_pc: number;
  enter_idx: number;
  exit_idx: number;
  depth: number;
  children: CallNode[];
  truncated_children?: number;
}

export interface CallTreeResponse {
  tree: CallNode;
}
```

Note: JSON numbers in TS are `number`. `fn_pc` may exceed Number.MAX_SAFE_INTEGER (2^53) for some module bases — for ARM64 user-space PCs (under 2^48 typically) this is safe. If it ever isn't, switch to `string` hex on the wire and update the Rust serializer too. Out of scope for M3-α.

- [ ] **Step 3: Write the panel**

Create `frontend/src/panels/calltree/CallTreePanel.tsx`:

```tsx
/** /api/call-tree panel. Indented expand/collapse tree with depth slider. */
import { Component, createResource, createSignal, For, Show } from "solid-js";

import type { CallNode, CallTreeResponse } from "../../api/types";

const DEFAULT_DEPTH = 10;
const MIN_DEPTH = 1;
const MAX_DEPTH = 50;

async function fetchCallTree(maxDepth: number): Promise<CallTreeResponse> {
  const r = await fetch(`/api/call-tree?max_depth=${maxDepth}`);
  if (!r.ok) throw new Error(`/api/call-tree HTTP ${r.status}`);
  return r.json();
}

const CallTreeRow: Component<{ node: CallNode; defaultOpen: boolean }> = (
  props,
) => {
  const [open, setOpen] = createSignal(props.defaultOpen);
  const hasChildren = () =>
    (props.node.children?.length ?? 0) > 0 ||
    (props.node.truncated_children ?? 0) > 0;
  const label = () => props.node.fn ?? "?";
  const idxRange = () => `[${props.node.enter_idx}..${props.node.exit_idx}]`;
  const indent = () => `${props.node.depth * 16}px`;

  return (
    <div class="ct-row">
      <div
        class="ct-line"
        style={{ "padding-left": indent() }}
        onClick={() => setOpen((o) => !o)}
      >
        <span class="ct-toggle">
          {hasChildren() ? (open() ? "▼" : "▶") : " "}
        </span>
        <span class="ct-fn">{label()}</span>
        <span class="ct-meta">{idxRange()}</span>
        <Show when={(props.node.truncated_children ?? 0) > 0}>
          <span class="ct-trunc">
            +{props.node.truncated_children} truncated
          </span>
        </Show>
      </div>
      <Show when={open()}>
        <For each={props.node.children}>
          {(child) => <CallTreeRow node={child} defaultOpen={false} />}
        </For>
      </Show>
    </div>
  );
};

export default function CallTreePanel() {
  const [depth, setDepth] = createSignal(DEFAULT_DEPTH);
  const [tree] = createResource(depth, fetchCallTree);

  return (
    <section class="panel">
      <header class="panel-head">
        <h2>Call tree</h2>
        <div class="controls">
          <label>
            max depth:&nbsp;
            <input
              type="range"
              min={MIN_DEPTH}
              max={MAX_DEPTH}
              value={depth()}
              onInput={(e) => setDepth(parseInt(e.currentTarget.value, 10))}
            />
            &nbsp;
            <span class="dim small">{depth()}</span>
          </label>
        </div>
      </header>
      <Show when={tree.error}>
        <div class="error">error: {String((tree.error as Error)?.message)}</div>
      </Show>
      <Show
        when={!tree.loading && tree()}
        fallback={<div class="dim">loading…</div>}
      >
        <div class="ct-wrap">
          <CallTreeRow node={tree()!.tree} defaultOpen={true} />
        </div>
      </Show>
    </section>
  );
}
```

- [ ] **Step 4: Add styles (inline-friendly)**

Match existing pattern: most panels use class-based styles in `frontend/src/styles/*.css`. If `frontend/src/styles/global.css` (or similar) is the convention, append:

```css
.ct-wrap { font-family: monospace; font-size: 12px; line-height: 1.5; }
.ct-row { white-space: nowrap; }
.ct-line { display: flex; gap: 0.6em; cursor: pointer; }
.ct-line:hover { background: rgba(255,255,255,0.04); }
.ct-toggle { width: 1em; color: var(--dim, #888); user-select: none; }
.ct-fn { color: var(--accent, #6cf); }
.ct-meta { color: var(--dim, #888); }
.ct-trunc { color: var(--warn, #fc6); margin-left: 0.4em; }
```

If the project has a different style-loading convention (e.g. CSS Modules), follow it instead. Find by:

```bash
grep -rn 'class="' frontend/src/panels/strings/StringsPanel.tsx | head -5
ls frontend/src/styles/
```

- [ ] **Step 5: Mount in App**

Edit `frontend/src/App.tsx`:

```tsx
import CallTreePanel from "./panels/calltree/CallTreePanel";
// ... existing imports

      <FunctionsPanel />
      <CallTreePanel />
      <StringsPanel />
      <RecordsPanel />
```

- [ ] **Step 6: Build the frontend**

Run: `cd frontend && npm run build 2>&1 | tail -15`
Expected: tsc + Vite build succeeds. Fix any TS errors (most likely missing `Show`/`For` imports, or `tree()!` non-null when types differ).

- [ ] **Step 7: Live smoke**

In one terminal:
```bash
cd rust && cargo run --release -p tracemiku-server -- traces/xsign_run1/calls/call_002_tid30203_7624431r_4655ms --port 18900
```
(Or the synthetic call_dir under the cargo-test temp path — easier to reproduce: any small trace works.)

In another:
```bash
cd frontend && npm run dev -- --host 0.0.0.0 --port 5174
# Open http://127.0.0.1:5174/ — verify "Call tree" panel renders.
```

If the dev proxy isn't configured for port 18900, set the proxy in `frontend/vite.config.ts` (look for the existing `/api` proxy line) or override via env. The existing proxy should already point to a Rust port — read it before changing.

If a real trace isn't on the dev host, document the smoke as "skipped, no trace mounted" in the commit message rather than silently passing.

- [ ] **Step 8: Commit**

```bash
git add frontend/src/api/types.ts \
        frontend/src/panels/calltree/CallTreePanel.tsx \
        frontend/src/App.tsx \
        frontend/src/styles/  # whichever file got the new CSS
git commit -m "$(cat <<'EOF'
feat(frontend): CallTreePanel — indented expand/collapse + depth slider

Solid component over /api/call-tree?max_depth=N. Default depth 10, slider
1-50. Truncated-children badge surfaces the cap-flatten count from the
Rust core. Click row to expand/collapse; root opens by default.

M3-α Task 3.
EOF
)"
```

---

## Task 4: `scripts/m3_alpha_parity.py` — structural parity gate

**Files:**
- Create: `scripts/m3_alpha_parity.py`

Boots Python webui + Rust server on the same trace, fetches `/api/call-tree?max_depth=10` from each, asserts:
1. Both return `tree.fn == "?"`, `tree.depth == 0`.
2. The bl-target name set (collected over the whole tree) matches with Jaccard ≥ 0.6 (loose tolerance — Python and Rust can differ on rare `bl` targets that hit unmapped PCs).
3. Total node count is within 10% (matches Python's nesting decisions when `max_depth` is generous).

Pattern matches `scripts/m2_zeta_parity.py` exactly.

- [ ] **Step 1: Write the script**

```python
"""M3-α parity differ — /api/call-tree structural comparison.

Boots Python webui + Rust tracemiku-server, fetches /api/call-tree on
each, compares root shape + bl-target name set + total node count.
Tolerance: Jaccard ≥ 0.6 on names, ±10% on total node count. Both
servers walk the same trace.bin so deviation comes only from edge
cases like PC-0 lookups or trailing unclosed frames.

Usage:
    uv run python scripts/m3_alpha_parity.py <call_dir>
"""
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_listening(port: int, timeout: float = 60.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"port {port} never opened")


def fetch(port: int, path: str) -> dict:
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    with urllib.request.urlopen(req, timeout=30.0) as r:
        return json.loads(r.read().decode("utf-8"))


def collect_names(node: dict) -> set:
    """All non-None fn names anywhere in the tree."""
    out = set()

    def walk(n):
        fn = n.get("fn")
        if fn and fn != "?":
            out.add(fn)
        for c in n.get("children", []) or []:
            walk(c)

    walk(node)
    return out


def count_nodes(node: dict) -> int:
    n = 1
    for c in node.get("children", []) or []:
        n += count_nodes(c)
    return n


def main():
    if len(sys.argv) != 2:
        print("usage: m3_alpha_parity.py <call_dir>", file=sys.stderr)
        sys.exit(2)
    call_dir = Path(sys.argv[1]).resolve()
    if not call_dir.is_dir() or not (call_dir / "trace.bin").exists():
        print(f"# {call_dir} is not a valid call_dir (missing trace.bin)",
              file=sys.stderr)
        sys.exit(2)

    py_port = free_port()
    rs_port = free_port()
    print(f"# M3-α parity: python={py_port} rust={rs_port} on {call_dir.name}",
          file=sys.stderr)

    py_proc = subprocess.Popen(
        ["./tracemiku", "web", str(call_dir),
         "--port", str(py_port), "--no-browser"],
        cwd=REPO_ROOT, preexec_fn=os.setsid,
        stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    )
    rs_proc = subprocess.Popen(
        ["./rust/target/release/tracemiku-server", str(call_dir),
         "--port", str(rs_port)],
        cwd=REPO_ROOT, preexec_fn=os.setsid,
        stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    )

    try:
        wait_listening(py_port)
        wait_listening(rs_port)

        py_resp = fetch(py_port, "/api/call-tree?max_depth=10")
        rs_resp = fetch(rs_port, "/api/call-tree?max_depth=10")

        py_tree = py_resp.get("tree", {})
        rs_tree = rs_resp.get("tree", {})

        diffs = []

        # 1. Root shape.
        for k, want in (("fn", "?"), ("depth", 0)):
            if py_tree.get(k) != want:
                diffs.append(f"  python tree.{k}={py_tree.get(k)!r}, want {want!r}")
            if rs_tree.get(k) != want:
                diffs.append(f"  rust tree.{k}={rs_tree.get(k)!r}, want {want!r}")

        # 2. Name set Jaccard.
        py_names = collect_names(py_tree)
        rs_names = collect_names(rs_tree)
        common = py_names & rs_names
        union = py_names | rs_names
        jaccard = (len(common) / len(union)) if union else 1.0
        if jaccard < 0.6:
            diffs.append(
                f"  bl-target name jaccard={jaccard:.2f} <0.6 — "
                f"py={len(py_names)}, rs={len(rs_names)}, common={len(common)}"
            )

        # 3. Node-count tolerance ±10%.
        py_n = count_nodes(py_tree)
        rs_n = count_nodes(rs_tree)
        if py_n > 0:
            ratio = abs(rs_n - py_n) / py_n
            if ratio > 0.10:
                diffs.append(
                    f"  node count diff {ratio:.0%} > 10% — py={py_n} rs={rs_n}"
                )

        if diffs:
            print("MISMATCH:", file=sys.stderr)
            for d in diffs:
                print(d, file=sys.stderr)
            sys.exit(1)

        print(
            f"OK — /api/call-tree (py={py_n} nodes / rs={rs_n} nodes; "
            f"name jaccard={jaccard:.2f})",
            file=sys.stderr,
        )
    finally:
        for proc in (py_proc, rs_proc):
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Build the Rust release binary the script depends on**

Run: `cargo build --release -p tracemiku-server 2>&1 | tail -3`
Expected: clean build.

- [ ] **Step 3: Pick a small real-trace fixture and run the parity script**

Find a small trace:
```bash
find traces -name 'call_*' -type d | xargs -I{} sh -c 'echo "$(stat -c %s {}/trace.bin 2>/dev/null) {}"' | sort -n | head -5
```

Run:
```bash
uv run python scripts/m3_alpha_parity.py <smallest call_dir>
```
Expected: `OK — /api/call-tree (py=N nodes / rs=N nodes; name jaccard=...)`.

If MISMATCH is on root shape (`fn != "?"`), inspect both responses with:
```bash
curl -s http://127.0.0.1:<py_port>/api/call-tree?max_depth=10 | jq '.tree | {fn, depth, n: (.children | length)}'
curl -s http://127.0.0.1:<rs_port>/api/call-tree?max_depth=10 | jq '.tree | {fn, depth, n: (.children | length)}'
```
(Re-run interactively without the parity harness if needed.)

If MISMATCH is on name jaccard, dump both name sets with:
```python
print("py-only:", py_names - rs_names)
print("rs-only:", rs_names - py_names)
```
inserted into the script. Likely cause: SymbolMap differing on `auto_known_offsets` heuristic — Rust's port might miss a corner case.

- [ ] **Step 4: Make the script executable + commit**

```bash
chmod +x scripts/m3_alpha_parity.py
git add scripts/m3_alpha_parity.py
git commit -m "test(parity): scripts/m3_alpha_parity.py — /api/call-tree shape+name+count"
```

---

## Task 5: Spec/TODO sync + final M3-α verification

**Files:**
- Modify: `TODO.md`
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`

- [ ] **Step 1: Run the full Rust test suite + parity once more**

```bash
cargo test --workspace 2>&1 | tail -5
uv run python scripts/m3_alpha_parity.py <call_dir>
```

Expected: all green. Document the chosen `<call_dir>` in the upcoming TODO row.

- [ ] **Step 2: Update §13.5 / §9 in the v2 spec**

Edit `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`. Find:

- The `viewer/calltree.py` row in the feature parity matrix § (look for `calltree` keyword) → change the right-side cell from `🔜 M3` to `✅ M3-α`.
- The `/api/call-tree` row → change `🔜 M3` to `✅ M3-α`.
- The `call-tree` CLI row (if present) → leave as `🔜 M3` (Task 5 does not port the CLI; that's M3-η).

Use `grep -n 'calltree\|call-tree' docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` to find exact line numbers.

- [ ] **Step 3: Update TODO.md**

Append under "🚧 进行中 (2026-05-03 — Analysis v2 — Rust core + TS frontend)":

```markdown
- M3-α `tracemiku-core::calltree` port + `/api/call-tree` + CallTreePanel + parity script: ✅ 2026-05-04
```

Update the M3 pointer:

```markdown
- M3-α (this): calltree + /api/call-tree + CallTreePanel + parity ✅ 2026-05-04
- M3-β (next): taint forward/backward (rayon) + cross-fn frame_depth + /api/forward-taint + /api/backward-taint + parity
- M3-γ: decompiler::backend stub + TraceIR builder skeleton
- M3-δ: Graph panel SVG (cfg-svg via petgraph or graphviz-rust)
- M3-ε: memshadow v3 binary sidecar (.memshadow.v3.bin)
- M3-ζ: Python viewer cutover prep (CLI parity + remove webui after manual sign-off)
```

- [ ] **Step 4: Final commit**

```bash
git add TODO.md docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md
git commit -m "$(cat <<'EOF'
docs(v2): mark M3-α complete + M3 sub-milestone roadmap

Shipped:
  - tracemiku-core::calltree → ✅ M3-α
  - /api/call-tree → ✅ M3-α
  - frontend CallTreePanel → ✅ M3-α
  - scripts/m3_alpha_parity.py → ✅ M3-α

Next (M3-β, separate plan): taint forward/backward (rayon) + cross-fn
frame_depth + /api/forward-taint + /api/backward-taint + parity.
EOF
)"
```

- [ ] **Step 5: Smoke the manual web UI one last time (only if user asks)**

```bash
cargo run --release -p tracemiku-server -- <call_dir> --port 18900 &
cd frontend && npm run preview -- --port 5175
```

Expected: Call tree panel renders, depth slider responsive, expand/collapse works on a real trace. Capture nothing — manual sanity check.

If a user-side smoke produces UI bugs (font cutoff, off-by-one indent, etc.), fix in a separate follow-up commit on this branch — do not block the milestone close.

---

## Self-Review

**Spec coverage** (M2-ζ "Next" line + v2 design §9 M3 cell + §13.5 endpoints):

| Spec line | Task |
|---|---|
| `tracemiku-core::calltree` port | Task 1 |
| `/api/call-tree` endpoint | Task 2 |
| Frontend CallTreePanel | Task 3 |
| Parity gate vs Python | Task 4 |
| TODO/spec sync + M3 roadmap | Task 5 |

Out of scope (deferred to later M3 sub-milestones):
- `tracemiku-cli call-tree` subcommand → M3-η
- WebSocket job system → M3-ζ or later
- BN-source enumeration in calltree (e.g. tail-call recovery via BN HLIL) → not planned for M3

**Placeholder scan:** No `TODO`, no `add appropriate error handling`, no `similar to Task N`. Each step has either code or an exact command. Task 3 Step 4 has a one-line "match the convention by reading existing files" — this is a directed reconnaissance, not a placeholder; the panel CSS is already-written above it.

**Type consistency:**
- `CallNode` fields are identical across `tracemiku-core::calltree` (Task 1), `tracemiku-server::routes::call_tree::CallTreeResponse` (Task 2), `frontend/src/api/types.ts` (Task 3), and the Python CallTreeNode in `webui/schemas.py:903-915` (parity reference).
- Field names: Rust `fn_name` with `#[serde(rename = "fn")]` ↔ JSON `fn` ↔ TS `fn` ↔ Python `fn`. Confirmed.
- `truncated_children` is `Option<u32>` in Rust, `number | undefined` in TS, `Optional[int] = None` in Python. All omit when zero.

**Algorithmic-parity risk:** the `dup-balance` trick in Task 1 Step 4 is the one place semantic drift can hide. The Python implementation pushes the **same dict** as the current top, so popping it later doesn't add a new node. Rust uses `clone()` (no shared mutability) and recovers the equivalent behavior via a depth-equality check before attaching to parent. The colocated test `max_depth_cap_flattens_into_truncated_children` covers this exact path.

**Frontend test coverage:** Solid component test infrastructure isn't in place for this branch. M3-α intentionally ships without component tests; the parity script's structural assertions provide end-to-end coverage. Setting up Vitest + @solidjs/testing-library is a separate task (deferred to M3-η or whenever a UI bug forces it).

---

**Plan complete and saved to `docs/superpowers/plans/2026-05-04-analysis-v2-m3-alpha.md`.**

Per `CLAUDE.md` user-pref §"Skip the 'Two execution options... Which approach?' handoff at end of plans" — execution choice has already been answered (subagent-driven). Plan executor proceeds via `superpowers:subagent-driven-development`.
