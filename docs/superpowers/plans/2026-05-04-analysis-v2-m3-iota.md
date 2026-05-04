# Analysis v2 — M3-ι Implementation Plan (BlockIR.exits + render_summary_md fidelity)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the two CFG-edge / markdown-fidelity gaps left by M3-θ:

1. **BlockIR.exits population** — extend Rust `cfg::CFG` to carry edge
   metadata (`kind`, `count`) the same way Python's
   `viewer/cfg.py::CFG.edges: dict[(src,dst), {kind,count}]` does, then wire
   it into `decompiler::builder` so every BlockIR's `exits: Vec<EdgeIR>` is
   populated when emitted by both `build_root_only` and
   `split_top_k_callees`. `render_func_md` (M3-θ skeleton) gains an
   `## Exits` section per block.
2. **`render_summary_md` fidelity** — replace the one-line
   `summary_md` text fallback in `routes/dec_summary.rs` with a real
   `render_summary_md(top: &TopIR) -> String` port of
   `viewer/decompiler/render/markdown.py:18-83`. Header line, metadata
   bullet list, VM-candidates section (header only when present, since
   `vm_candidates` stays empty until M3-ι' / vm_candidate.py port), and
   the Functions table.

**Out of scope (deferred):**
- `type_anchor.py` port (json-spec driven). New milestone (M3-ι').
- `vm_candidate.py` port (OLLVM detector). New milestone (M3-ι'/M3-ι'').
- `/api/dec/fn/{id}` `sym:*` / `bn:*` source support — depends on
  `function_index` carrying CFG-derived block lists per symbol entry,
  and Rust BN backend (no Rust BN backend exists yet). Defer until BN
  backend lands.
- `/api/dec/llm-call` — separate RFC.

**Architecture:**

- **CFG edge metadata:** Replace `petgraph::DiGraph<Block, ()>` with
  `DiGraph<Block, EdgeMeta>` where `EdgeMeta { kind: String, count: u64 }`.
  Existing call sites that only read node weights stay untouched. Anywhere
  we currently `add_edge(fn_, tn, ())`, we now classify the kind from
  the branch instruction (`b`, `bl`, `blr`, `br`, `ret`, `b.cond`,
  `cbz`, `cbnz`, `tbz`, `tbnz`, `fall`, `call-return`) and increment a
  count. Match Python: per-(src,dst) the LAST kind seen wins on tie, but
  count is sum of all observations.
- **Builder wiring:** `make_block_ir` receives the `&CFG` so it can walk
  outgoing edges of `block.start_pc` and emit `Vec<EdgeIR>` with `dst`
  resolved through the shared `block_ids: HashMap<u64, String>` (already
  computed). External edges (dst not in block_ids) render as
  `ext:<hex>` in the EdgeIR.dst, mirroring Python's `f"ext:{dst_pc:#x}"`
  fallback (builder.py:167).
- **Per-block exits markdown:** `render_func_md` emits a new
  `### Exits` subheader (or inline list) before the asm fence:

  ```markdown
  - **exits**:
    - `b.eq` → **B5** (×42)
    - `fall` → **B6** (×17)
  ```

  Order: by `dst` asc for stability.
- **`render_summary_md`:** new fn in `decompiler::render`. Format:

  ```markdown
  # Trace Summary

  - records: **{n}**
  - module: `{name}` @ {base:#x} (size {size:#x})
  - cmd: **{cmd}**            (omit if None)
  - method: `{method}`        (omit if empty)
  - truncated: {bool}
  - last_insn_is_ret: {bool}
  - generated: {ts} (tracemiku {version})

  ## VM Candidates ({n})           (omit section if empty)
  …per-candidate detail (skeleton — full hex dump body defers)

  ## Functions ({n})

  | id | name | blocks | loops | calls | idx range |
  |---|---|---|---|---|---|
  | [F0](fns/F0.md) | `name` | … | … | … | a..b |
  ```

  `routes/dec_summary.rs` switches `summary_md` field to
  `render_summary_md(&inner.top_ir)`.

**Tech Stack:** Rust 1.95. No new workspace deps.

**Branch:** `refactor/function-index-handoff`. Stream commits.

**Spec inputs:**
- `viewer/cfg.py:25-50, 110-247` — Python CFG / edge / kind reference.
  `cfg.edges: dict[(src,dst), {kind,count}]`. `_add_call_return` sets
  `kind="call-return"`; main loop sets `kind=d.mnemonic` for branches
  and `kind="fall"` for fall-through-into-block-start.
- `viewer/decompiler/builder.py:162-178, 325-343` — how Python populates
  per-block `exits`.
- `viewer/decompiler/render/markdown.py:18-136` — `render_summary_md`
  + per-block `_fmt_edge` reference.
- `tracemiku-core::decompiler::ir::EdgeIR` — already has `dst`, `kind`,
  `taken_count`, `not_taken_count` fields (M3-δ shipped). We populate
  `dst`/`kind`/`taken_count`. `not_taken_count` stays 0 in this
  milestone (Python doesn't compute it either; reserved for future).
- `tracemiku-core::cfg::CFG` (M2-δ shipped) — current edge weight is
  `()`. We extend to `EdgeMeta`.

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-core/src/cfg.rs` (modify) | Add `EdgeMeta { kind, count }`. Change `DiGraph<Block, ()>` → `DiGraph<Block, EdgeMeta>`. Classify kind per branch insn during build. Add `CFG::edges_from(start_pc) -> Vec<(u64, &EdgeMeta)>` helper. |
| `rust/crates/tracemiku-core/src/decompiler/builder.rs` (modify) | `make_block_ir` takes `&CFG` + `&HashMap<u64, String>` block_ids; emits `Vec<EdgeIR>` from outgoing edges, resolving dst pc → block-id (or `ext:<hex>`). Both `build_root_only` and `split_top_k_callees` callers pass cfg + block_ids through. |
| `rust/crates/tracemiku-core/src/decompiler/render.rs` (modify) | Add `pub fn render_summary_md(top: &TopIR) -> String`. Extend `render_func_md` per-block section to emit exits list when `block.exits` is non-empty. |
| `rust/crates/tracemiku-core/src/prelude.rs` (modify) | Re-export `render_summary_md`. |
| `rust/crates/tracemiku-server/src/routes/dec_summary.rs` (modify) | Replace ad-hoc one-liner `summary_md` with `render_summary_md(&inner.top_ir)`. |
| `rust/crates/tracemiku-server/tests/test_dec_summary_route.rs` (modify) | Add assertion: `summary_md` starts with `# Trace Summary` and contains the Functions table header. |
| `rust/crates/tracemiku-server/tests/test_dec_fn_route.rs` (modify) | Add assertion: rendered markdown contains `**exits**` section when fixture trace has at least one branch. |
| `TODO.md` + spec | Mark `BlockIR.exits` and `render_summary_md` complete; refine M3-ι' (renumbered to ι' or new κ-prefix) pointer. |

---

## Task 1: CFG edge metadata

**Files:**
- Modify: `rust/crates/tracemiku-core/src/cfg.rs`

- [ ] **Step 1: Define `EdgeMeta`**

After `Block` (around line 35):

```rust
/// CFG edge metadata. Mirrors Python `viewer/cfg.py::CFG.edges` value
/// dict: `{kind: str, count: int}`.
///
/// `kind` strings (parity with Python):
/// - `"fall"` — sequential fall-through into a block start.
/// - `"call-return"` — bl/blr → ret pair (caller block → post-call PC).
/// - `"b"`, `"bl"`, `"blr"`, `"br"`, `"ret"` — direct branch mnemonic.
/// - `"b.cond"` (or `"b.eq"`, `"b.ne"`, ...) — conditional branch
///   (Python uses the full `d.mnemonic` here, e.g. `"b.eq"`).
/// - `"cbz"`, `"cbnz"`, `"tbz"`, `"tbnz"` — compare-and-branch.
#[derive(Debug, Clone, Default, Serialize)]
pub struct EdgeMeta {
    pub kind: String,
    pub count: u64,
}
```

- [ ] **Step 2: Switch graph type**

`pub graph: DiGraph<Block, ()>` → `pub graph: DiGraph<Block, EdgeMeta>`.

`build_cfg` body changes:
1. Replace the single `edges: Vec<(u64, u64)>` with
   `edges: Vec<(u64, u64, EdgeMeta)>`. When pushing a branch edge,
   classify the kind from the decoded mnemonic
   (`d.mnemonic.to_string()`).
2. Add fall-through edge detection: when leaving a block due to
   the next record being a known block-start AND the previous insn
   was NOT a branch AND `prev_pc + 4 == next_pc`, push
   `(prev_block_start, next_pc, EdgeMeta { kind: "fall", count: 1 })`.
3. Add call-return edge: when seeing a `bl`/`blr` at idx i, remember
   `(caller_block, idx_of_bl)` on a stack. When seeing a `ret` at
   idx j, pop the stack and push
   `(popped_caller_block, pc(j+1), EdgeMeta { kind: "call-return", count: 1 })`.
   This is best-effort and matches Python's `_add_call_return` only
   approximately — Python tracks module-boundary re-entry; for parity
   in this milestone, restrict to in-trace bl/ret pairs (no module
   boundary handling). Document divergence in a `// NOTE:` comment.
4. When inserting the edge, deduplicate by `(src, dst)`: if an edge
   already exists, increment its `count` and update its `kind` to
   the latest mnemonic. (Python uses `setdefault({"kind":k,"count":0})["count"] += 1`,
   so `kind` first-write-wins; match that — only set `kind` when
   the edge is new, increment count always.)

```rust
// Sketch (replace existing add-edges block):
let mut edge_index: HashMap<(u64, u64), petgraph::graph::EdgeIndex> = HashMap::new();
for (from, to, kind_str) in edges {
    let (Some(&fn_), Some(&tn)) = (cfg.by_pc.get(&from), cfg.by_pc.get(&to)) else { continue };
    if let Some(&eidx) = edge_index.get(&(from, to)) {
        if let Some(meta) = cfg.graph.edge_weight_mut(eidx) {
            meta.count += 1;
        }
    } else {
        let eidx = cfg.graph.add_edge(fn_, tn, EdgeMeta { kind: kind_str, count: 1 });
        edge_index.insert((from, to), eidx);
    }
}
```

- [ ] **Step 3: Add `CFG::edges_from` helper**

```rust
impl CFG {
    /// Iterate outgoing edges of `start_pc`. Returns `(dst_start_pc, &EdgeMeta)`.
    pub fn edges_from(&self, start_pc: u64) -> Vec<(u64, EdgeMeta)> {
        let Some(&n) = self.by_pc.get(&start_pc) else { return Vec::new(); };
        let mut out: Vec<(u64, EdgeMeta)> = self.graph
            .edges_directed(n, petgraph::Direction::Outgoing)
            .filter_map(|e| {
                let dst_pc = self.graph.node_weight(e.target())?.start_pc;
                Some((dst_pc, e.weight().clone()))
            })
            .collect();
        out.sort_by_key(|(pc, _)| *pc);
        out
    }
}
```

(Need `use petgraph::visit::EdgeRef;` at the top.)

- [ ] **Step 4: Test — CFG edge metadata smoke**

Add to existing `cfg.rs` `#[cfg(test)] mod tests { ... }`:

```rust
#[test]
fn build_cfg_classifies_branch_kinds() {
    // Trace: 3 records, ARM64 nop sequence with one bl + one ret.
    // We can't easily synthesize without a real trace fixture; just
    // check that the EdgeMeta has a non-empty kind once edges exist.
    use crate::trace::{Trace, REC_SIZE};
    let dir = tempfile::tempdir().unwrap();
    let cd = dir.path().join("run").join("calls").join("c");
    std::fs::create_dir_all(&cd).unwrap();
    // Sequence: nop @ 0x1000, bl @ 0x1004 → 0x2000, nop @ 0x2000.
    // 0x94000400 = bl +0x1000.
    let pcs = [0x1000u64, 0x1004, 0x2000];
    let insts = [0xd503201fu32, 0x94000400, 0xd503201f];
    let mut buf = vec![0u8; REC_SIZE * 3];
    for (i, (&pc, &inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * REC_SIZE;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), &buf).unwrap();
    std::fs::write(cd.join("meta.json"), r#"{"records":3}"#).unwrap();
    std::fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x1000","size":0x10000}}"#,
    ).unwrap();
    let trace = Trace::load(&cd).unwrap();
    let cfg = build_cfg(&trace);
    // Should have at least one classified edge.
    let any_kind_set = cfg.graph.edge_weights().any(|m| !m.kind.is_empty());
    assert!(any_kind_set, "at least one edge should have a non-empty kind");
}
```

If this test is fragile because the fall-through / call-return logic
depends on the exact instruction stream, gate it behind a more
permissive assertion: `assert!(cfg.edge_count() >= 1)`. Adjust to
your synth fixture.

- [ ] **Step 5: Verify**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo build -p tracemiku-core 2>&1 | tail -5
cargo test -p tracemiku-core --lib cfg 2>&1 | tail -10
cargo test -p tracemiku-core 2>&1 | grep "test result:" | tail -5
```

Existing CFG tests must still pass — `Block`, `block_count`,
`successors` are unchanged in shape; only edge weight type
flipped from `()` to `EdgeMeta`.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-core/src/cfg.rs
git commit -m "$(cat <<'EOF'
feat(core): cfg edge metadata — kind/count per (src,dst)

petgraph DiGraph<Block, ()> → DiGraph<Block, EdgeMeta { kind, count }>.

kind classification (parity with viewer/cfg.py):
  - "fall" for sequential fall-through into a block start
  - "call-return" for bl/blr → ret pair (caller → post-call PC)
  - branch mnemonic ("b", "b.cond", "cbz", ...) for direct edges
count: incremented on each observation; kind first-write-wins (Python parity).

CFG::edges_from(start_pc) helper added for builder use in M3-ι Task 2.

M3-ι Task 1.
EOF
)"
```

---

## Task 2: Builder wires BlockIR.exits

**Files:**
- Modify: `rust/crates/tracemiku-core/src/decompiler/builder.rs`
- Modify: `rust/crates/tracemiku-core/src/decompiler/render.rs`

- [ ] **Step 1: Make `make_block_ir` populate `exits`**

Pass `cfg: &CFG` + `block_ids: &HashMap<u64, String>` into
`make_block_ir`. New body computes exits:

```rust
let exits: Vec<EdgeIR> = cfg
    .edges_from(block.start_pc)
    .into_iter()
    .map(|(dst_pc, meta)| {
        let dst_id = block_ids
            .get(&dst_pc)
            .cloned()
            .unwrap_or_else(|| format!("ext:{dst_pc:#x}"));
        EdgeIR {
            dst: dst_id,
            kind: meta.kind,
            taken_count: meta.count,
            not_taken_count: 0,
        }
    })
    .collect();

BlockIR {
    id,
    pc: block.start_pc,
    end_pc: block.end_pc,
    insns: insns_count,
    exec_count: block.executions,
    exits,
    samples,
    asm,
    ..Default::default()
}
```

- [ ] **Step 2: Update both callers**

`build_root_only` already passes `cfg` (it's in the function
parameter list); just thread `&block_ids` through:

```rust
let f0_blocks: Vec<BlockIR> = sorted_blocks
    .iter()
    .map(|b| {
        let id = block_ids
            .get(&b.start_pc)
            .cloned()
            .unwrap_or_else(|| format!("B?{:x}", b.start_pc));
        make_block_ir(b, id, trace, &first_idx, cfg, &block_ids)
    })
    .collect();
```

`split_top_k_callees` already has both `cfg` and `block_ids` in
scope — pass them through.

- [ ] **Step 3: Render exits in `render_func_md`**

In the per-block loop of `render_func_md`, before the asm fence
emission, add:

```rust
if !block.exits.is_empty() {
    out.push_str("- **exits**:\n");
    let mut exits_sorted: Vec<&crate::decompiler::ir::EdgeIR> = block.exits.iter().collect();
    exits_sorted.sort_by(|a, b| a.dst.cmp(&b.dst));
    for e in exits_sorted {
        let cnt = if e.taken_count > 0 {
            format!(" (×{})", e.taken_count)
        } else {
            String::new()
        };
        out.push_str(&format!("  - `{}` → **{}**{}\n", e.kind, e.dst, cnt));
    }
}
```

- [ ] **Step 4: Tests**

In `decompiler/builder.rs` tests:

```rust
#[test]
fn build_trace_ir_block_ir_carries_exits_when_branches_present() {
    let dir = synth_two_callees();
    let (t, meta, sym) = load_two_callees(&dir);
    let cfg = crate::cfg::build_cfg(&t);
    let top = build_trace_ir(&t, &meta, &sym, &cfg, 0, 0);
    let f0 = &top.fns[0];
    let any_with_exits = f0.blocks.iter().any(|b| !b.exits.is_empty());
    assert!(any_with_exits, "at least one block should have exits; got {f0:?}");
    for blk in &f0.blocks {
        for e in &blk.exits {
            assert!(!e.kind.is_empty(), "exit kind must be non-empty: {e:?}");
            assert!(!e.dst.is_empty(), "exit dst must be non-empty: {e:?}");
        }
    }
}
```

In `decompiler/render.rs` tests, add a per-block exits assertion:

```rust
#[test]
fn render_func_md_emits_exits_section_when_present() {
    use crate::decompiler::ir::EdgeIR;
    let f = FuncIR {
        id: "F0".to_string(),
        name: "f".to_string(),
        blocks: vec![BlockIR {
            id: "B0".to_string(),
            pc: 0x1000,
            tier: "hot".to_string(),
            exits: vec![EdgeIR {
                dst: "B1".to_string(),
                kind: "b.eq".to_string(),
                taken_count: 5,
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let md = render_func_md(&f, "hot");
    assert!(md.contains("**exits**"), "missing exits section: {md}");
    assert!(md.contains("`b.eq`"), "missing kind: {md}");
    assert!(md.contains("**B1**"), "missing dst: {md}");
    assert!(md.contains("(×5)"), "missing count: {md}");
}
```

- [ ] **Step 5: Update existing dec_fn route test**

Append to `rust/crates/tracemiku-server/tests/test_dec_fn_route.rs`
a new test that checks the markdown for an `**exits**` section when
the synth trace has multiple blocks. The existing `synth_root_only`
fixture is 3 nops with no branches, so all blocks fall in the root
block — there are no edges. Use a slightly extended fixture that
emits at least one branch:

```rust
fn synth_with_branch() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_3r_1ms");
    fs::create_dir_all(&cd).unwrap();
    // 3 records: nop, bl @ 0x100004 → 0x100200, nop @ 0x100200.
    let pcs = [0x100000u64, 0x100004, 0x100200];
    let insts = [0xd503201fu32, 0x9400007e, 0xd503201f];
    let mut buf = vec![0u8; 272 * 3];
    for (i, (&pc, &inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":3}"#).unwrap();
    fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":0x10000},"method":"f","cmd":42,"fn_addr":"0x100000"}"#,
    )
    .unwrap();
    dir
}

#[tokio::test]
async fn dec_fn_markdown_contains_exits_section_when_branches_present() {
    let dir = synth_with_branch();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/fn/trace:F0?tier=all")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let md = v["markdown"].as_str().unwrap();
    // At least one block should carry an exits bullet.
    assert!(
        md.contains("**exits**"),
        "F0 markdown should contain an exits section: {md}"
    );
}
```

- [ ] **Step 6: Verify**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo test -p tracemiku-core --lib decompiler 2>&1 | tail -15
cargo test -p tracemiku-server --test test_dec_fn_route 2>&1 | tail -10
cargo test -p tracemiku-server 2>&1 | grep "test result:" | tail -10
cargo clippy -p tracemiku-core -p tracemiku-server --tests 2>&1 | tail -5
```

- [ ] **Step 7: Commit**

```bash
git add rust/crates/tracemiku-core/src/decompiler/builder.rs \
        rust/crates/tracemiku-core/src/decompiler/render.rs \
        rust/crates/tracemiku-server/tests/test_dec_fn_route.rs
git commit -m "$(cat <<'EOF'
feat(core): builder populates BlockIR.exits + render_func_md exits section

make_block_ir now reads outgoing edges from CFG (M3-ι Task 1
EdgeMeta) and emits Vec<EdgeIR>. Block ids resolved via the shared
block_ids map; external dsts render as ext:<hex>.

render_func_md gains a per-block "**exits**" bullet list:
  - `kind` → **dst_id** (×count)

Tests:
  - build_trace_ir_block_ir_carries_exits_when_branches_present (core)
  - render_func_md_emits_exits_section_when_present (core)
  - dec_fn_markdown_contains_exits_section_when_branches_present (server)

M3-ι Task 2.
EOF
)"
```

---

## Task 3: `render_summary_md` + `/api/dec/summary` wiring

**Files:**
- Modify: `rust/crates/tracemiku-core/src/decompiler/render.rs`
- Modify: `rust/crates/tracemiku-core/src/prelude.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/dec_summary.rs`
- Modify: `rust/crates/tracemiku-server/tests/test_dec_summary_route.rs`

- [ ] **Step 1: Add `render_summary_md`**

Append to `decompiler/render.rs`:

```rust
use crate::decompiler::ir::TopIR;

/// Render TopIR → summary.md text. Mirrors
/// `viewer/decompiler/render/markdown.py::render_summary_md`.
///
/// Skeleton: header, metadata bullet list, optional VM-candidates
/// section (header only — full hex-dump rendering defers until
/// vm_candidate.py is ported), Functions table.
pub fn render_summary_md(top: &TopIR) -> String {
    let mut out = String::new();
    out.push_str("# Trace Summary\n\n");
    out.push_str(&format!("- records: **{}**\n", top.records));
    out.push_str(&format!(
        "- module: `{}` @ {:#x} (size {:#x})\n",
        top.module_name, top.module_base, top.module_size
    ));
    if let Some(cmd) = top.cmd {
        out.push_str(&format!("- cmd: **{cmd}**\n"));
    }
    if !top.method.is_empty() {
        out.push_str(&format!("- method: `{}`\n", top.method));
    }
    out.push_str(&format!("- truncated: {}\n", top.truncated));
    out.push_str(&format!("- last_insn_is_ret: {}\n", top.last_insn_is_ret));
    if !top.tracemiku_version.is_empty() {
        out.push_str(&format!(
            "- generated: {} (tracemiku {})\n",
            top.generated_at, top.tracemiku_version
        ));
    }
    out.push('\n');

    if !top.vm_candidates.is_empty() {
        out.push_str(&format!("## VM Candidates ({})\n\n", top.vm_candidates.len()));
        out.push_str("> evidence only — bytecode not decoded.\n\n");
        for (i, vc) in top.vm_candidates.iter().enumerate() {
            out.push_str(&format!("### Candidate #{i}\n\n"));
            out.push_str(&format!("- dispatcher_pc: `{:#x}`\n", vc.dispatcher_pc));
            out.push_str(&format!("- confidence: **{:.2}**\n", vc.confidence));
            if !vc.reasons.is_empty() {
                out.push_str("- reasons:\n");
                for r in &vc.reasons {
                    out.push_str(&format!("  - {r}\n"));
                }
            }
            out.push('\n');
        }
    }

    out.push_str(&format!("## Functions ({})\n\n", top.fns.len()));
    out.push_str("| id | name | blocks | loops | calls | idx range |\n");
    out.push_str("|---|---|---|---|---|---|\n");
    for f in &top.fns {
        out.push_str(&format!(
            "| [{0}](fns/{0}.md) | `{1}` | {2} | {3} | {4} | {5}..{6} |\n",
            f.id,
            f.name,
            f.blocks.len(),
            f.loops.len(),
            f.calls.len(),
            f.entry_idx,
            f.exit_idx
        ));
    }
    out
}
```

- [ ] **Step 2: Re-export in prelude**

`prelude.rs`:

```rust
pub use crate::decompiler::render::{render_func_md, render_summary_md};
```

- [ ] **Step 3: Wire in `routes/dec_summary.rs`**

Replace the ad-hoc `summary_md` block:

```rust
use tracemiku_core::prelude::{make_trace_id, render_summary_md};
// ...
let summary_md = render_summary_md(top);
```

Drop the manual `let mut summary_md = format!(...)` + per-fn loop.

- [ ] **Step 4: Tests**

In `decompiler/render.rs`:

```rust
#[test]
fn render_summary_md_emits_header_and_functions_table() {
    let mut top = TopIR::default();
    top.records = 100;
    top.module_name = "libt.so".to_string();
    top.module_base = 0x1000;
    top.module_size = 0x10000;
    top.method = "f".to_string();
    top.cmd = Some(42);
    top.fns.push(FuncIR {
        id: "F0".to_string(),
        name: "doCommandNative".to_string(),
        entry_idx: 0,
        exit_idx: 99,
        blocks: vec![BlockIR::default(), BlockIR::default()],
        ..Default::default()
    });
    let md = render_summary_md(&top);
    assert!(md.starts_with("# Trace Summary"), "header missing: {md}");
    assert!(md.contains("- records: **100**"));
    assert!(md.contains("`libt.so`"));
    assert!(md.contains("- cmd: **42**"));
    assert!(md.contains("- method: `f`"));
    assert!(md.contains("## Functions (1)"));
    assert!(md.contains("| [F0](fns/F0.md) |"));
    assert!(md.contains("| `doCommandNative` |"));
    assert!(md.contains(" 2 |"), "blocks count missing: {md}"); // 2 blocks
    assert!(md.contains(" 0..99 |"));
}

#[test]
fn render_summary_md_omits_optional_fields_when_absent() {
    let top = TopIR { records: 0, ..Default::default() };
    let md = render_summary_md(&top);
    assert!(md.contains("- records: **0**"));
    assert!(!md.contains("- cmd:"), "cmd should be omitted when None: {md}");
    assert!(!md.contains("- method:"), "method should be omitted when empty: {md}");
    assert!(!md.contains("## VM Candidates"));
    assert!(md.contains("## Functions (0)"));
}
```

In `tests/test_dec_summary_route.rs`, append:

```rust
#[tokio::test]
async fn dec_summary_summary_md_uses_render_summary_md() {
    let dir = synth_root_only();
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
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let md = v["summary_md"].as_str().unwrap();
    assert!(
        md.starts_with("# Trace Summary"),
        "summary_md should start with markdown header: {md}"
    );
    assert!(md.contains("## Functions"), "Functions section missing: {md}");
    assert!(md.contains("| id | name |"), "Functions table header missing: {md}");
}
```

- [ ] **Step 5: Verify**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo build -p tracemiku-server 2>&1 | tail -5
cargo test -p tracemiku-core --lib decompiler 2>&1 | tail -15
cargo test -p tracemiku-server --test test_dec_summary_route 2>&1 | tail -10
cargo test -p tracemiku-server --test test_dec_fn_route 2>&1 | tail -10
cargo test -p tracemiku-server 2>&1 | grep "test result:" | tail -10
cargo clippy -p tracemiku-core -p tracemiku-server --tests 2>&1 | tail -5
```

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-core/src/decompiler/render.rs \
        rust/crates/tracemiku-core/src/prelude.rs \
        rust/crates/tracemiku-server/src/routes/dec_summary.rs \
        rust/crates/tracemiku-server/tests/test_dec_summary_route.rs
git commit -m "$(cat <<'EOF'
feat(core,server): render_summary_md + /api/dec/summary fidelity

render_summary_md(&TopIR) -> String emits markdown:
  # Trace Summary
  - records / module / cmd / method / truncated / last_insn_is_ret / generated
  ## VM Candidates (n)        (omitted when empty)
  ## Functions (n)            with per-fn id/name/blocks/loops/calls/idx-range table

Mirrors viewer/decompiler/render/markdown.py::render_summary_md
(VM-candidate hex-dump rendering deferred until vm_candidate.py port).

routes::dec_summary now uses render_summary_md instead of the
M3-δ one-line text fallback.

Tests:
  - render_summary_md_emits_header_and_functions_table (core)
  - render_summary_md_omits_optional_fields_when_absent (core)
  - dec_summary_summary_md_uses_render_summary_md (server)

M3-ι Task 3.
EOF
)"
```

---

## Task 4: Spec/TODO sync

**Files:**
- Modify: `TODO.md`
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`

- [ ] **Step 1: Update spec rows**

Find the `builder.py` row (currently `🟡 M3-η`). Update to `🟡 M3-ι` with note:

```markdown
| `builder.py` (build_trace_ir, render_summary_md, render_func_md) | `tracemiku-core::decompiler::builder` | 🟡 M3-ι | metadata + root F0 (M3-δ) + top-K callee splits (M3-ε) + BlockIR id/pc/end_pc/insns/exec_count (M3-ζ) + BlockIR asm/samples/tier (M3-η) + BlockIR.exits with kind/taken_count via CFG EdgeMeta (M3-ι) + render_summary_md fidelity (M3-ι). type_anchor + vm_candidate ports defer to next milestone. |
```

Find `/api/dec/fn/{id}` row (currently `🟡 M3-θ`). Update note:

```markdown
| `/api/dec/fn/{id}` | 🟡 M3-ι | trace:* + bare F0 legacy id supported via render_func_md (header + metadata + per-block asm/samples + exits + tier filter). sym:* / bn:* sources defer to BN-backend milestone. |
```

If there's a `/api/dec/summary` row, update its note to mention render_summary_md fidelity.

- [ ] **Step 2: Update TODO.md**

In the progress section (around line 73), append:

```markdown
- M3-ι BlockIR.exits + cfg EdgeMeta (kind/count) + render_summary_md fidelity: ✅ 2026-05-04
```

Refine M3-ι' / next-milestone pointer (replace line 74):

```markdown
- M3-ι (next): type_anchor.py port (json-spec driven), vm_candidate.py port (OLLVM detector), /api/dec/fn/{id} sym:* / bn:* source support (gated on Rust BN backend), /api/dec/llm-call
```

(Keep numbering — naming the next pass "M3-ι'" gets confusing. Use the
currently-unused `M3-ι` slot once the M3-ι work above is marked done by
overwriting the line.)

Better: since both items shipped under M3-ι, leave the new pointer name
as-is and call the next slot **`M3-ι2`** or just merge into existing
M3-κ / M3-λ slots. Recommend appending to the spec/TODO:

```markdown
- M3-ι2 (next-after-ι): type_anchor.py + vm_candidate.py + sym:*/bn:* dec_fn + /api/dec/llm-call
```

- [ ] **Step 3: Commit**

```bash
git add TODO.md docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md
git commit -m "docs(v2): mark M3-ι complete (BlockIR.exits + render_summary_md)"
```

---

## Self-Review

**Spec coverage:**

| Item | Task |
|---|---|
| `EdgeMeta { kind, count }` on CFG | Task 1 |
| Fall-through / call-return edge classification | Task 1 |
| `make_block_ir` populates `Vec<EdgeIR>` | Task 2 |
| `render_func_md` emits per-block exits section | Task 2 |
| `render_summary_md` matches Python skeleton | Task 3 |
| `/api/dec/summary.summary_md` uses render_summary_md | Task 3 |
| Integration test on real synth fixture | Tasks 2–3 |
| Docs sync | Task 4 |

**Out of scope (deferred to a later milestone — call it M3-ι2 or roll into M3-κ planning):**

- `type_anchor.py` port — JSON-spec loading + per-bl idx anchor matching.
- `vm_candidate.py` port — depends on `ollvmdet.py` port (OLLVM
  detector heuristic).
- `/api/dec/fn/{id}` `sym:*` / `bn:*` source support — needs BN-backed
  FuncIR construction (no Rust BN backend yet).
- `/api/dec/llm-call` — separate RFC; needs LLM client port.

**Risks:**

1. **Breaking `cfg.rs` consumers.** Anyone currently iterating
   `cfg.graph.edge_weights()` will see `EdgeMeta` instead of `()`. The
   only existing consumer (`Tarjan SCC`) doesn't read edge weights —
   safe. `successors` / `block_count` / `edge_count` API unchanged.
2. **Fall-through and call-return classification divergence.** Python's
   logic in `cfg.py:_add_call_return` handles module-boundary re-entry
   (pops call stack on cross-module return). For the M3-ι skeleton, do
   the simpler in-trace bl/ret pairing — note the simplification in
   a `// NOTE:` comment. Real-trace parity gate is not run in this
   milestone (deferred to a later real-trace check; the
   functions-side tests catch the basic cases).
3. **Test fragility on synth fixtures.** The 3-record `synth_with_branch`
   may not produce a useful CFG depending on how the bl is classified —
   if `is_branch_arr` for `0x9400007e` (bl) isn't terminating the block
   (it should), the assertion should still pass because the bl edge
   into 0x100200 will be on the resulting CFG. Validate by running
   the test and adjust the fixture if it produces 0 edges.

---

**Plan complete and saved.** Per `CLAUDE.md` user-pref §"Skip the 'Two execution options' handoff" — execution proceeds via `superpowers:subagent-driven-development`.
