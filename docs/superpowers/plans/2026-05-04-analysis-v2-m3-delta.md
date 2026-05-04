# Analysis v2 — M3-δ Implementation Plan (decompiler::backend stub + TraceIR builder skeleton + /api/dec/summary)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Open the `tracemiku-core::decompiler` namespace with three stub modules — `ir` (data carriers ported from `viewer/decompiler/ir.py`), `backend` (Function/FieldHint/VarType + `Backend` trait + `NoneBackend` impl, ported from `viewer/decompiler/backend.py`), and `builder` (a minimal `build_trace_ir(...) -> TopIR` skeleton that produces just the root `F0` FuncIR — no callee splits, no per-block BlockIR, no type anchors, no VM candidates). Expose this as `GET /api/dec/summary` matching the Python webui wire shape (trace-ir source only). Lock parity with `scripts/m3_delta_parity.py`. Advanced features (top-K callee splits, BlockIR with asm/samples, type anchors, VM detection, sym/cfg-source fallback, /api/dec/fn/{id}, render_summary_md fidelity) land in M3-ε.

**Architecture:** `decompiler::ir` is dataclasses-only (no behavior beyond a `TopIR::fn(id)` lookup helper). `decompiler::backend` defines the static-analysis sidecar Protocol — Rust trait. `NoneBackend` returns `None` / `Default` for everything (placeholder for tests + the no-BN-installed code path). `decompiler::builder::build_trace_ir` is the "trace → IR" entry point; the M3-δ skeleton produces `TopIR { records, module_*, fns: vec![FuncIR{id:"F0", name:<root_fn_name>, entry_idx:0, exit_idx:n-1, ...}] }`. The endpoint handler runs this on `AppState::trace + symbols + cfg` and returns the documented wire shape.

**Tech Stack:** Rust 1.95, axum 0.7. No new workspace deps.

**Branch:** `refactor/function-index-handoff`. Stream commits.

**Spec inputs:**
- `viewer/decompiler/ir.py` (185 lines) — full IR dataclass reference. Port verbatim modulo Rust idioms.
- `viewer/decompiler/backend.py` (158 lines) — `Backend` trait + dataclass reference. Port the Protocol → Rust trait.
- `viewer/decompiler/builder.py:244-498` — `build_trace_ir` reference. M3-δ ports only the top-level skeleton (lines 271-287). Block construction (lines 304-462) deferred to M3-ε.
- `webui/server.py:2723-2773` — `/api/dec/summary` endpoint reference. Wire shape locked.
- `viewer/decompiler/__init__.py` — `from .ir import ...`, `from .builder import build_trace_ir`. Mirror in Rust prelude.

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-core/src/decompiler/mod.rs` (new) | Module declaration: `pub mod ir; pub mod backend; pub mod builder;` |
| `rust/crates/tracemiku-core/src/decompiler/ir.rs` (new) | Port of `viewer/decompiler/ir.py`: BlockIR, EdgeIR, LoopIR, CallIR, TypeAnchorIR, FuncIR, TopIR, VmCandidateIR, InductionVarIR. All Serialize. `TopIR::fn(id)` helper. |
| `rust/crates/tracemiku-core/src/decompiler/backend.rs` (new) | Port of `viewer/decompiler/backend.py`: Function, Token, HlilLine, CfgBlock, CfgEdge, FieldHint, VarType structs. `Backend` trait with stub methods. `NoneBackend` impl returning Default/None. |
| `rust/crates/tracemiku-core/src/decompiler/builder.rs` (new) | `pub fn build_trace_ir(trace, sym, ...) -> TopIR` skeleton — root F0 only. |
| `rust/crates/tracemiku-core/src/lib.rs` (modify) | `pub mod decompiler;` |
| `rust/crates/tracemiku-core/src/prelude.rs` (modify) | Re-export `build_trace_ir`, `TopIR`, `FuncIR`, `BlockIR`, `Backend`, `NoneBackend`. |
| `rust/crates/tracemiku-server/src/state.rs` (modify) | Eager-build `top_ir: TopIR` at AppState::load (cheap; same complexity as Index walk). |
| `rust/crates/tracemiku-server/src/routes/dec_summary.rs` (new) | `GET /api/dec/summary` handler. Wire shape mirrors Python `webui/server.py:2756-2773`. |
| `rust/crates/tracemiku-server/src/routes/mod.rs` (modify) | Add `pub mod dec_summary;` + route registration. |
| `rust/crates/tracemiku-server/tests/test_dec_summary_route.rs` (new) | 1 integration test: GET `/api/dec/summary`, expect 1 entry in `fns` with `source=="trace-ir"`, `id=="trace:F0"`. |
| `frontend/src/api/types.ts` (modify) | Add `DecFnEntry`, `DecSummaryResponse` interfaces. |
| `frontend/src/api/client.ts` (modify) | Add `fetchDecSummary()`. |
| `frontend/src/panels/decompiler/DecompilerPanel.tsx` (new) | Minimal panel: list fns (id, name, blocks, calls, idx range). No body view yet. |
| `frontend/src/App.tsx` (modify) | Mount `<DecompilerPanel />` after `<TaintPanel />`. |
| `frontend/src/styles/base.css` (modify) | Append `.dec-*` CSS rules. |
| `scripts/m3_delta_parity.py` (new) | Parity gate: hit-set Jaccard ≥ 0.6 on `/api/dec/summary` fn-id set (or trivial-empty OK). |
| `TODO.md` (modify) | Append M3-δ rows; refine M3-ε pointer. |
| `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` (modify) | Mark `decompiler/ir.py`, `decompiler/backend.py`, `decompiler/builder.py`, `/api/dec/summary` rows as 🟡 M3-δ (skeleton). |

**M3-δ skeleton means**: F0 only. Other fields (loops, calls, type_anchors, vm_candidates, blocks) ship as empty `Vec`s. `summary_md` is a one-line text fallback. `render_summary_md` Python fidelity, BlockIR construction, callee splits, type anchors, VM detection, /api/dec/fn/{id}, /api/dec/llm-call all defer to M3-ε.

---

## Task 1: `tracemiku-core::decompiler::ir` port (TDD)

**Files:**
- Create: `rust/crates/tracemiku-core/src/decompiler/mod.rs`
- Create: `rust/crates/tracemiku-core/src/decompiler/ir.rs`
- Modify: `rust/crates/tracemiku-core/src/lib.rs`

Direct port of `viewer/decompiler/ir.py` (185 lines). Pure dataclasses + one `TopIR::fn` lookup. Order, field names, defaults — mirror Python verbatim modulo Rust idiom.

- [ ] **Step 1: Create the module file**

`rust/crates/tracemiku-core/src/decompiler/mod.rs`:

```rust
//! Decompiler — TraceIR + Backend abstraction.
//!
//! M3-δ ships skeleton only: IR dataclasses, Backend trait + NoneBackend,
//! and a build_trace_ir that emits a single root FuncIR. M3-ε fills
//! BlockIR, callee splits, type anchors, VM candidates, /api/dec/fn/{id}.
//!
//! See `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`
//! §13.3 for the migration table.

pub mod backend;
pub mod builder;
pub mod ir;
```

- [ ] **Step 2: Create `ir.rs`**

Port `viewer/decompiler/ir.py` line-by-line into Rust. Each dataclass becomes a `#[derive(Debug, Clone, Serialize, Default)] pub struct ...`. Field types:
- Python `int` → `i64` for trace indices (Python uses signed) and `u64` for PCs/addresses (Rust convention). Match the wire shape: in JSON, both serialize as numbers; the only stable contract is the JSON output.
- Python `str` → `String`.
- Python `Optional[X]` → `Option<X>` with `#[serde(skip_serializing_if = "Option::is_none")]`.
- Python `list[X]` → `Vec<X>`.
- Python `dict[str, int]` → `HashMap<String, i64>`.

Specifically:
- `BlockIR { id: String, pc: u64, end_pc: u64, insns: u32, exec_count: u64, exits: Vec<EdgeIR>, samples: HashMap<String, i64>, asm: String, ref_id: Option<String> (renamed from `ref` since `ref` is a Rust keyword; serialize as `"ref"`), tier: String (default "hot") }`
- `EdgeIR { dst: String, kind: String, taken_count: u64, not_taken_count: u64 }`
- `InductionVarIR { reg: String, init: i64, final_value: i64 (`final` is reserved-ish; rename + serde("final")), step: f64, n_iters: u32, classification: String, linearity_score: f64, samples: Vec<i64> }`
- `LoopIR { id: String, header: String, body: Vec<String>, iters: u64, induction_var: Option<serde_json::Value> (legacy dict, just opaque), induction_vars: Vec<InductionVarIR> }`
- `CallIR { idx: usize, src_block: String, callee_pc: u64, callee_fn: Option<String>, callee_name: String, ret_idx: Option<usize>, ret_val_x0: Option<u64> }`
- `TypeAnchorIR { idx: usize, callee_pc: u64, callee_name: String, params: Vec<(String, String)>, ret_reg: String (default "x0"), ret_type: String, provenance: String }`
- `FuncIR { id: String, name: String, pc_start: u64, pc_end: u64, entry_idx: usize, exit_idx: usize, truncated: bool, last_insn_is_ret: bool, blocks: Vec<BlockIR>, loops: Vec<LoopIR>, calls: Vec<CallIR>, static_info: Option<serde_json::Value> (renamed from `static`; serialize as `"static"`), exec_count: u64 (default 1), type_anchors: Vec<TypeAnchorIR> }`
- `VmCandidateIR { dispatcher_pc: u64, confidence: f64, reasons: Vec<String>, reader_pc: u64, reader_inst: String, reader_hits: u32, reader_base_reg: String, bytecode_addr: u64, bytecode_len: u64, hex_dump: Vec<String> }`
- `TopIR { records: usize, truncated: bool, last_insn_is_ret: bool, module_name: String, module_base: u64, module_size: u64, cmd: Option<i64>, method: String, fns: Vec<FuncIR>, vm_candidates: Vec<VmCandidateIR>, tracemiku_version: String, generated_at: String }`

`TopIR` impl block:

```rust
impl TopIR {
    pub fn fn_by_id(&self, fn_id: &str) -> Option<&FuncIR> {
        self.fns.iter().find(|f| f.id == fn_id)
    }
}
```

(Python's method is named `fn` but `fn` is reserved in Rust; pick `fn_by_id` — same surface, different name.)

For each renamed field, use `#[serde(rename = "<python-name>")]`:

```rust
#[derive(Debug, Clone, Serialize, Default)]
pub struct BlockIR {
    // ...
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub ref_id: Option<String>,
}
```

- [ ] **Step 3: Wire module + build**

Edit `rust/crates/tracemiku-core/src/lib.rs`:

```rust
pub mod decompiler;
```

(Place alphabetically — between `cfg` and `disasm`, OR wherever the existing alphabetical order falls.)

```bash
cargo build -p tracemiku-core 2>&1 | tail -5
```

Expected: clean. Fix any "unused" warnings by adding `#[allow(dead_code)]` on the most exotic fields (e.g. `induction_var` legacy field) until M3-ε consumes them — OR add a one-line `#[cfg(test)] use ...;` reference.

- [ ] **Step 4: Add 1 colocated test**

In `decompiler/ir.rs`, append:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topir_fn_by_id_finds_the_funcir() {
        let mut top = TopIR::default();
        top.fns.push(FuncIR {
            id: "F0".to_string(),
            name: "root".to_string(),
            ..Default::default()
        });
        top.fns.push(FuncIR {
            id: "F1".to_string(),
            name: "alpha".to_string(),
            ..Default::default()
        });
        let f = top.fn_by_id("F1").unwrap();
        assert_eq!(f.name, "alpha");
        assert!(top.fn_by_id("F2").is_none());
    }

    #[test]
    fn block_ir_ref_field_serializes_as_ref_when_set() {
        let blk = BlockIR {
            id: "B0".to_string(),
            ref_id: Some("B5".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&blk).unwrap();
        assert!(json.contains(r#""ref":"B5""#), "got {json}");
    }

    #[test]
    fn block_ir_ref_field_omitted_when_none() {
        let blk = BlockIR {
            id: "B0".to_string(),
            ref_id: None,
            ..Default::default()
        };
        let json = serde_json::to_string(&blk).unwrap();
        assert!(!json.contains(r#""ref""#), "ref must be omitted when None: {json}");
    }
}
```

Run:
```bash
cargo test -p tracemiku-core --lib decompiler::ir 2>&1 | tail -10
cargo clippy -p tracemiku-core --tests 2>&1 | tail -5
```

Expected: 3 tests pass, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/tracemiku-core/src/decompiler/mod.rs \
        rust/crates/tracemiku-core/src/decompiler/ir.rs \
        rust/crates/tracemiku-core/src/lib.rs
git commit -m "feat(core): decompiler::ir — TraceIR dataclasses (M3-δ skeleton)"
```

---

## Task 2: `decompiler::backend` stub trait + NoneBackend

**Files:**
- Create: `rust/crates/tracemiku-core/src/decompiler/backend.rs`
- Modify: `rust/crates/tracemiku-core/src/prelude.rs`

Port `viewer/decompiler/backend.py:69-159`. The MVP: dataclasses + the `Backend` trait + `NoneBackend` returning placeholders. Real `BinjaBackend` lands in M5+ (blocked on PyO3 / capnproto sidecar; out of scope here).

- [ ] **Step 1: Port dataclasses**

```rust
//! Decompiler backend abstraction. Port of viewer/decompiler/backend.py.
//!
//! M3-δ ships the trait + NoneBackend stub. Real backends (binja, ghidra)
//! land in later milestones — they need PyO3 / sidecar plumbing that is
//! out of scope for the v2 trace-side rewrite.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct Function {
    pub start: u64,
    pub end: u64,
    pub name: String,
    pub backend: String,
    // raw: object — Python carries a backend-specific handle. Rust uses
    // a separate trait method to fetch the handle when needed.
}

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct Token {
    pub text: String,
    pub cls: String,
    pub addr: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct HlilLine {
    pub text: String,
    pub pc_lo: u64,
    pub pc_hi: u64,
    pub indent: u32,
    pub tokens: Vec<Token>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CfgBlock {
    pub start: u64,
    pub end: u64,
    pub lines: Vec<HlilLine>,
    pub exec_count: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CfgEdge {
    pub src: u64,
    pub dst: u64,
    pub kind: String,
    pub seen_in_trace: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct FieldHint {
    pub struct_name: String,    // renamed from `struct` (Rust keyword)
    pub field: String,
    pub offset: i64,
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct VarType {
    pub name: String,
    pub type_name: String,
    pub storage: String,
}
```

(`struct_name` is renamed from Python's `struct` because `struct` is a Rust keyword. Add `#[serde(rename = "struct")]` if wire compat matters; M3-δ keeps it as `struct_name` — Python/Rust callers use the Rust API for now, no FieldHint endpoint exists.)

- [ ] **Step 2: Define the `Backend` trait**

```rust
/// Decompiler backend protocol.
///
/// Hot-path queries should be < 50ms after open. NoneBackend (the M3-δ
/// stub impl) returns trivial defaults — placeholder until M5+ wires
/// real BN/Ghidra backends.
pub trait Backend: Send + Sync {
    fn name(&self) -> &str;
    fn is_available(&self) -> bool;
    fn open(&mut self, so_path: &str, base: u64) -> anyhow::Result<()>;
    fn close(&mut self);
    fn loaded_base(&self) -> u64;
    fn function_at(&self, pc: u64) -> Option<Function>;
    fn hlil_for(&self, fn_: &Function) -> Vec<HlilLine>;
    fn vars_for(&self, fn_: &Function) -> Vec<VarType>;
    fn field_at(&self, pc: u64, reg: &str, offset: i64) -> Option<FieldHint>;
    fn xrefs_to(&self, addr: u64) -> Vec<u64>;
    fn cfg_for(&self, fn_: &Function, mode: &str) -> (Vec<CfgBlock>, Vec<CfgEdge>);
    fn asm_tokens_at(&self, pc: u64) -> Option<Vec<Token>>;
}
```

- [ ] **Step 3: Implement `NoneBackend`**

```rust
/// Stub backend — placeholder when no real decompiler is available.
/// All queries return None / Default. Useful for tests and the
/// no-binja-installed code path.
#[derive(Debug, Default)]
pub struct NoneBackend;

impl NoneBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Backend for NoneBackend {
    fn name(&self) -> &str {
        "none"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn open(&mut self, _so_path: &str, _base: u64) -> anyhow::Result<()> {
        Ok(())
    }
    fn close(&mut self) {}
    fn loaded_base(&self) -> u64 {
        0
    }
    fn function_at(&self, _pc: u64) -> Option<Function> {
        None
    }
    fn hlil_for(&self, _fn_: &Function) -> Vec<HlilLine> {
        Vec::new()
    }
    fn vars_for(&self, _fn_: &Function) -> Vec<VarType> {
        Vec::new()
    }
    fn field_at(&self, _pc: u64, _reg: &str, _offset: i64) -> Option<FieldHint> {
        None
    }
    fn xrefs_to(&self, _addr: u64) -> Vec<u64> {
        Vec::new()
    }
    fn cfg_for(&self, _fn_: &Function, _mode: &str) -> (Vec<CfgBlock>, Vec<CfgEdge>) {
        (Vec::new(), Vec::new())
    }
    fn asm_tokens_at(&self, _pc: u64) -> Option<Vec<Token>> {
        None
    }
}
```

- [ ] **Step 4: Re-export from prelude**

Edit `rust/crates/tracemiku-core/src/prelude.rs`. Add:

```rust
pub use crate::decompiler::backend::{
    Backend, CfgBlock as DecCfgBlock, CfgEdge as DecCfgEdge, FieldHint, Function as DecFunction,
    HlilLine, NoneBackend, Token as DecToken, VarType,
};
pub use crate::decompiler::ir::{
    BlockIR, CallIR, EdgeIR, FuncIR, InductionVarIR, LoopIR, TopIR, TypeAnchorIR, VmCandidateIR,
};
```

(Aliases `DecCfgBlock`, `DecCfgEdge`, `DecFunction`, `DecToken` avoid clashes with the cfg module's `Block`, edge types, etc.)

- [ ] **Step 5: Add 2 colocated tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_backend_returns_placeholders() {
        let bn = NoneBackend::new();
        assert_eq!(bn.name(), "none");
        assert!(bn.is_available());
        assert_eq!(bn.loaded_base(), 0);
        assert!(bn.function_at(0x1000).is_none());
        let f = Function::default();
        assert!(bn.hlil_for(&f).is_empty());
        assert!(bn.vars_for(&f).is_empty());
        assert!(bn.field_at(0, "x0", 0).is_none());
        assert!(bn.xrefs_to(0).is_empty());
        let (blocks, edges) = bn.cfg_for(&f, "asm");
        assert!(blocks.is_empty() && edges.is_empty());
        assert!(bn.asm_tokens_at(0).is_none());
    }

    #[test]
    fn none_backend_open_close_roundtrip() {
        let mut bn = NoneBackend::new();
        bn.open("/nonexistent.so", 0x10000).unwrap();
        bn.close();
    }
}
```

- [ ] **Step 6: Build + test + commit**

```bash
cargo test -p tracemiku-core --lib decompiler::backend 2>&1 | tail -10
cargo clippy -p tracemiku-core --tests 2>&1 | tail -5

git add rust/crates/tracemiku-core/src/decompiler/backend.rs \
        rust/crates/tracemiku-core/src/prelude.rs
git commit -m "feat(core): decompiler::backend — Backend trait + NoneBackend stub"
```

---

## Task 3: `decompiler::builder::build_trace_ir` skeleton

**Files:**
- Create: `rust/crates/tracemiku-core/src/decompiler/builder.rs`
- Modify: `rust/crates/tracemiku-core/src/prelude.rs` (add `build_trace_ir`)

Port `viewer/decompiler/builder.py:244-287` only — the metadata + empty-trace-early-return path. Block/loop/call construction (lines 304-462) defers to M3-ε.

- [ ] **Step 1: Write the skeleton**

```rust
//! TraceIR builder — M3-δ skeleton.
//!
//! Produces a TopIR with metadata + a single root FuncIR `F0` covering
//! the entire trace. Block/loop/call/type_anchor/vm-candidate
//! construction defer to M3-ε.
//!
//! Mirrors viewer/decompiler/builder.py:244-287.

use crate::decompiler::ir::{FuncIR, TopIR};
use crate::symbols::SymbolMap;
use crate::trace::Trace;

/// Build a minimal TopIR from a loaded Trace. Skeleton scope:
///   - top-level metadata (records, module_*, cmd, method, truncated)
///   - one root FuncIR `F0` covering [0, n-1]
///
/// Args mirror Python `viewer/decompiler/builder.py:244-251` (only the
/// MVP-relevant ones — split_top_k, type_spec_paths, detect_vm, memshadow
/// stay as ignored params for forward-compat with the Python signature).
pub fn build_trace_ir(trace: &Trace, sym: &SymbolMap) -> TopIR {
    let n = trace.len();
    let mut top = TopIR {
        records: n,
        truncated: trace.meta.raw_truncated(),
        last_insn_is_ret: trace.meta.raw_last_insn_is_ret(),
        cmd: trace.meta.cmd,
        method: trace.meta.method.clone(),
        tracemiku_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at: String::new(), // M3-ε: chrono::Utc::now() ISO
        ..Default::default()
    };
    if let Some(m) = &trace.meta.module {
        top.module_name = m.name.clone();
        top.module_base = u64::from_str_radix(m.base.trim_start_matches("0x"), 16).unwrap_or(0);
        top.module_size = m.size;
    }

    if n == 0 {
        return top;
    }

    // Root FuncIR. M3-δ: no blocks, loops, calls, type_anchors yet.
    // pc_start: pc at idx 0; pc_end: pc at last idx.
    let pc0 = trace.pc(0);
    let pc_last = trace.pc(n - 1);
    let (root_name, _) = sym.lookup(pc0);
    top.fns.push(FuncIR {
        id: "F0".to_string(),
        name: if root_name == "?" {
            format!("sub_{:x}", pc0.wrapping_sub(top.module_base))
        } else {
            root_name
        },
        pc_start: pc0,
        pc_end: pc_last,
        entry_idx: 0,
        exit_idx: n - 1,
        truncated: top.truncated,
        last_insn_is_ret: top.last_insn_is_ret,
        exec_count: 1,
        ..Default::default()
    });
    top
}
```

`trace.meta.raw_truncated()` and `raw_last_insn_is_ret()` — the per-call meta.json reader exposes these. If the Rust `TraceMeta` doesn't have them yet, add minimal accessors:

```rust
// In rust/crates/tracemiku-core/src/trace/meta.rs (or wherever TraceMeta lives):
impl TraceMeta {
    pub fn raw_truncated(&self) -> bool {
        // Read the per-call meta.json's "truncated" field. If TraceMeta already
        // parses this, return the field directly. Otherwise return false.
        false  // <-- M3-δ skeleton; M3-ε wires real value
    }
    pub fn raw_last_insn_is_ret(&self) -> bool {
        false
    }
}
```

(Read `rust/crates/tracemiku-core/src/trace/meta.rs` first; the per-call meta JSON has `"records"`, `"truncated"`, `"last_insn_is_ret"`. If `TraceMeta` doesn't currently parse the latter two, add them as `pub truncated: bool, pub last_insn_is_ret: bool` fields with `#[serde(default)]` — that's a minor extension worth doing now.)

- [ ] **Step 2: Re-export from prelude**

Add to `prelude.rs`:

```rust
pub use crate::decompiler::builder::build_trace_ir;
```

- [ ] **Step 3: 1 colocated test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::REC_SIZE;

    /// Reuse the existing 9-record root+2-callees synth fixture from
    /// calltree.rs / taint.rs tests. (Or just inline a similar tiny one.)
    fn synth() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_3r_1ms");
        std::fs::create_dir_all(&cd).unwrap();
        let mut buf = vec![0u8; REC_SIZE * 3];
        for i in 0..3usize {
            let off = i * REC_SIZE;
            buf[off..off + 8].copy_from_slice(&(0x100000u64 + (i as u64) * 4).to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
        }
        std::fs::write(cd.join("trace.bin"), &buf).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":3}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x100000","size":4096},"method":"f","cmd":42,"known_offsets":{"0x0":"f_root"}}"#,
        )
        .unwrap();
        dir
    }

    fn load(dir: &tempfile::TempDir) -> Trace {
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
    fn build_trace_ir_emits_root_funcir() {
        let dir = synth();
        let t = load(&dir);
        let mut sym = SymbolMap::new();
        sym.add(0x100000, "f_root".to_string());
        sym.freeze();
        let top = build_trace_ir(&t, &sym);

        assert_eq!(top.records, 3);
        assert_eq!(top.module_name, "libt.so");
        assert_eq!(top.module_base, 0x100000);
        assert_eq!(top.method, "f");
        assert_eq!(top.cmd, Some(42));
        assert_eq!(top.fns.len(), 1, "skeleton emits exactly 1 root FuncIR");
        let f0 = &top.fns[0];
        assert_eq!(f0.id, "F0");
        assert_eq!(f0.name, "f_root");
        assert_eq!(f0.entry_idx, 0);
        assert_eq!(f0.exit_idx, 2);
    }

    #[test]
    fn build_trace_ir_empty_trace_returns_metadata_only() {
        let dir = tempfile::tempdir().unwrap();
        let cd = dir
            .path()
            .join("run")
            .join("calls")
            .join("call_001_tid1_0r_0ms");
        std::fs::create_dir_all(&cd).unwrap();
        std::fs::File::create(cd.join("trace.bin")).unwrap();
        std::fs::write(cd.join("meta.json"), r#"{"records":0}"#).unwrap();
        std::fs::write(
            dir.path().join("run").join("meta.json"),
            r#"{"module":{"name":"libt.so","base":"0x0","size":0}}"#,
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
        let sym = SymbolMap::new();
        let top = build_trace_ir(&t, &sym);
        assert_eq!(top.records, 0);
        assert!(top.fns.is_empty(), "empty trace → no fns");
    }
}
```

- [ ] **Step 4: Verify + commit**

```bash
cargo test -p tracemiku-core --lib decompiler::builder 2>&1 | tail -10
cargo clippy -p tracemiku-core --tests 2>&1 | tail -5

git add rust/crates/tracemiku-core/src/decompiler/builder.rs \
        rust/crates/tracemiku-core/src/prelude.rs \
        rust/crates/tracemiku-core/src/trace/meta.rs   # if accessors added
git commit -m "feat(core): decompiler::builder — build_trace_ir skeleton (root F0 only)"
```

---

## Task 4: `GET /api/dec/summary` endpoint + AppState wiring

**Files:**
- Modify: `rust/crates/tracemiku-server/src/state.rs`
- Create: `rust/crates/tracemiku-server/src/routes/dec_summary.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/mod.rs`
- Create: `rust/crates/tracemiku-server/tests/test_dec_summary_route.rs`

Wire shape (from `webui/server.py:2756-2773`):

```json
{
  "records": 469639,
  "module_name": "libfoo.so",
  "module_base": 0x100000,
  "module_size": 0x80000,
  "truncated": false,
  "fns": [
    {
      "id": "trace:F0",
      "name": "doCommandNative",
      "blocks": 0,
      "loops": 0,
      "calls": 0,
      "type_anchors": 0,
      "entry_idx": 0,
      "exit_idx": 469638,
      "source": "trace-ir",
      "trace_ir_id": "F0"
    }
  ],
  "vm_candidates": [],
  "summary_md": "trace: 469639 records, module=libfoo.so\n  F0 doCommandNative ..."
}
```

- [ ] **Step 1: AppState pre-builds top_ir**

In `rust/crates/tracemiku-server/src/state.rs`:

Add to imports:
```rust
use tracemiku_core::prelude::{
    build_call_tree, build_frame_depth_map, build_from_trace, build_function_index,
    build_trace_ir, CallNode, FunctionIndex, Index, MemShadow, ModuleResolver,
    SymbolMap, TopIR, Trace, TraceMeta, CFG,
};
```

Add field:
```rust
pub struct AppStateInner {
    // ... existing fields
    pub top_ir: TopIR,
}
```

In `AppState::load`, after `let frame_depths = build_frame_depth_map(&trace);`:
```rust
        let top_ir = build_trace_ir(&trace, &symbols);
```

Append to constructor.

- [ ] **Step 2: Route handler**

Create `rust/crates/tracemiku-server/src/routes/dec_summary.rs`:

```rust
//! GET /api/dec/summary — TraceIR top-level summary.

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use tracemiku_core::prelude::make_trace_id;

use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct DecFnEntry {
    pub id: String,
    pub name: String,
    pub blocks: usize,
    pub loops: usize,
    pub calls: usize,
    pub type_anchors: usize,
    pub entry_idx: Option<usize>,
    pub exit_idx: Option<usize>,
    pub source: &'static str,
    pub trace_ir_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DecSummaryResponse {
    pub records: usize,
    pub module_name: String,
    pub module_base: u64,
    pub module_size: u64,
    pub truncated: bool,
    pub fns: Vec<DecFnEntry>,
    pub vm_candidates: Vec<serde_json::Value>,
    pub summary_md: String,
}

pub async fn dec_summary_handler(State(state): State<AppState>) -> Json<DecSummaryResponse> {
    let inner = &state.inner;
    let top = &inner.top_ir;

    let fns: Vec<DecFnEntry> = top
        .fns
        .iter()
        .map(|f| DecFnEntry {
            id: make_trace_id(&f.id),
            name: f.name.clone(),
            blocks: f.blocks.len(),
            loops: f.loops.len(),
            calls: f.calls.len(),
            type_anchors: f.type_anchors.len(),
            entry_idx: Some(f.entry_idx),
            exit_idx: Some(f.exit_idx),
            source: "trace-ir",
            trace_ir_id: Some(f.id.clone()),
        })
        .collect();

    // Minimal summary_md — Python's render_summary_md produces a much
    // richer markdown; M3-ε ports the full renderer.
    let mut summary_md = format!(
        "trace: {} records, module={}\n",
        top.records, top.module_name
    );
    for f in &top.fns {
        summary_md.push_str(&format!(
            "  {} {:24} blocks={:<4} loops={:<3} calls={:<3} idx=[{},{}]\n",
            f.id,
            f.name,
            f.blocks.len(),
            f.loops.len(),
            f.calls.len(),
            f.entry_idx,
            f.exit_idx
        ));
    }

    Json(DecSummaryResponse {
        records: top.records,
        module_name: top.module_name.clone(),
        module_base: top.module_base,
        module_size: top.module_size,
        truncated: top.truncated,
        fns,
        vm_candidates: Vec::new(),
        summary_md,
    })
}
```

- [ ] **Step 3: Register route**

In `routes/mod.rs`:

```rust
pub mod dec_summary;
// ... rest
```

```rust
        .route("/api/dec/summary", get(dec_summary::dec_summary_handler))
```

Place near `/api/functions` (the closest analog).

- [ ] **Step 4: Integration test**

Create `rust/crates/tracemiku-server/tests/test_dec_summary_route.rs`. Reuse the synth-fixture pattern from `test_call_tree_route.rs` (3-record minimal trace). Assert:
- HTTP 200
- `records >= 1`
- `module_name == "libt.so"`
- `fns.len() == 1`
- `fns[0].id == "trace:F0"`
- `fns[0].source == "trace-ir"`
- `fns[0].trace_ir_id == "F0"`
- `fns[0].entry_idx == 0`
- `fns[0].exit_idx == records - 1`
- `vm_candidates` is an empty array
- `summary_md` is non-empty

- [ ] **Step 5: Verify + commit**

```bash
cargo test -p tracemiku-server --test test_dec_summary_route 2>&1 | tail -10
cargo test -p tracemiku-server 2>&1 | grep "test result:" | tail -5
cargo clippy -p tracemiku-server --tests 2>&1 | tail -5

git add rust/crates/tracemiku-server/src/state.rs \
        rust/crates/tracemiku-server/src/routes/dec_summary.rs \
        rust/crates/tracemiku-server/src/routes/mod.rs \
        rust/crates/tracemiku-server/tests/test_dec_summary_route.rs
git commit -m "feat(server): GET /api/dec/summary — TraceIR top-level (skeleton)"
```

---

## Task 5: Frontend `DecompilerPanel` (minimal fn list)

**Files:**
- Modify: `frontend/src/api/types.ts`
- Modify: `frontend/src/api/client.ts`
- Create: `frontend/src/panels/decompiler/DecompilerPanel.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/styles/base.css`

A list of FuncIR entries: id, name, blocks count, calls count, idx range. No body view yet — that's M3-ε with `/api/dec/fn/{id}`.

- [ ] **Step 1: Add types**

```typescript
// ── /api/dec/summary ──────────────────────────────────────────────────────

export interface DecFnEntry {
  id: string;
  name: string;
  blocks: number;
  loops: number;
  calls: number;
  type_anchors: number;
  entry_idx: number | null;
  exit_idx: number | null;
  source: string;          // "trace-ir" | "symbol" (M3-ε) | "bn" (M5+)
  trace_ir_id: string | null;
}

export interface DecSummaryResponse {
  records: number;
  module_name: string;
  module_base: number;
  module_size: number;
  truncated: boolean;
  fns: DecFnEntry[];
  vm_candidates: unknown[];
  summary_md: string;
}
```

- [ ] **Step 2: Client helper**

```typescript
export async function fetchDecSummary(): Promise<DecSummaryResponse> {
  const r = await fetch("/api/dec/summary");
  if (!r.ok) throw new Error(`/api/dec/summary ${r.status}: ${await r.text()}`);
  return (await r.json()) as DecSummaryResponse;
}
```

- [ ] **Step 3: Panel component**

```tsx
import { createResource, For, Show } from "solid-js";

import { fetchDecSummary } from "~/api/client";

export default function DecompilerPanel() {
  const [resp] = createResource(fetchDecSummary);
  return (
    <section class="panel">
      <h2>Decompiler (skeleton)</h2>
      <Show when={resp.error}>
        <p class="err">load failed: {String(resp.error)}</p>
      </Show>
      <Show when={resp.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={resp()}>
        {(r) => (
          <>
            <p class="dim small">
              {r().records} records · module {r().module_name} · {r().fns.length} fn{r().fns.length === 1 ? "" : "s"}
            </p>
            <table class="dec-table">
              <thead>
                <tr>
                  <th>id</th>
                  <th>name</th>
                  <th>blocks</th>
                  <th>calls</th>
                  <th>idx range</th>
                  <th>source</th>
                </tr>
              </thead>
              <tbody>
                <For each={r().fns}>
                  {(f) => (
                    <tr>
                      <td class="dim small">{f.id}</td>
                      <td>{f.name}</td>
                      <td>{f.blocks}</td>
                      <td>{f.calls}</td>
                      <td class="dim small">
                        {f.entry_idx ?? "?"}..{f.exit_idx ?? "?"}
                      </td>
                      <td class="dim small">{f.source}</td>
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

- [ ] **Step 4: Mount + style**

App.tsx — slot after `<TaintPanel />`. CSS:

```css
.dec-table { width: 100%; border-collapse: collapse; font-family: monospace; font-size: 12px; }
.dec-table th, .dec-table td { padding: 2px 6px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.06); }
.dec-table th { color: var(--dim, #888); font-weight: normal; }
```

- [ ] **Step 5: Build + commit**

```bash
cd frontend && npm run build 2>&1 | tail -5

git add frontend/src/api/types.ts frontend/src/api/client.ts \
        frontend/src/panels/decompiler/DecompilerPanel.tsx \
        frontend/src/App.tsx frontend/src/styles/base.css
git commit -m "feat(frontend): DecompilerPanel — minimal fn list (M3-δ skeleton)"
```

---

## Task 6: `scripts/m3_delta_parity.py` + spec/TODO sync

**Files:**
- Create: `scripts/m3_delta_parity.py`
- Modify: `TODO.md`
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`

Parity gate: compare `/api/dec/summary` `fns[].id` set Jaccard between Python and Rust. Tolerance ≥ 0.6 (loose because M3-δ skeleton emits only F0 while Python may emit F0 + symbol-source entries).

If Python emits more fns than Rust (likely on real traces — Python has the symbol-source fallback), the Jaccard will be small. **Soft-gate this for M3-δ** — backward parity convention from M3-β: print a `WARN (M3-ε-deferred)` line, don't fail. Hard-gate restored when M3-ε ports symbol-source entries.

Pattern matches `scripts/m3_alpha_parity.py` and `scripts/m3_beta_parity.py`. Copy the boilerplate.

- [ ] **Step 1: Write the script**

(Mostly copy `m3_beta_parity.py`. Replace endpoint + key + label. Soft-label `dec-summary`.)

- [ ] **Step 2: Run on real trace**

```bash
chmod +x scripts/m3_delta_parity.py
uv run python scripts/m3_delta_parity.py traces/test_hide_only/calls/_truncated_call_002_tid27340_469639r_1641ms 2>&1 | tail -5
```

Expected: `WARN (M3-ε-deferred): dec-summary jaccard=...` OR `OK — dec-summary (...)` if Jaccard ≥ 0.6 anyway.

- [ ] **Step 3: Update spec rows**

In `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`:
- `decompiler/ir.py` row → 🟡 M3-δ (skeleton; full BlockIR/calls/loops/anchors deferred to M3-ε)
- `decompiler/backend.py` row → 🟡 M3-δ (Backend trait + NoneBackend; real backends deferred to M5+)
- `decompiler/builder.py` row → 🟡 M3-δ (skeleton — root F0 only)
- `/api/dec/summary` row → 🟡 M3-δ (trace-ir source only; symbol/bn sources + render_summary_md fidelity in M3-ε)

- [ ] **Step 4: Update TODO.md**

Append M3-δ rows. Refine M3-ε pointer:

```markdown
- M3-ε (next): full TraceIR — BlockIR construction (asm/samples/exits), top-K callee splits (split_top_k), type anchors (json-spec driven), VM candidate detection, /api/dec/fn/{id}, /api/dec/llm-call, render_summary_md fidelity, symbol/bn source fallback in /api/dec/summary, parity gate hardening
```

- [ ] **Step 5: Final commit**

```bash
git add scripts/m3_delta_parity.py TODO.md \
        docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md
git commit -m "$(cat <<'EOF'
docs(v2): mark M3-δ skeleton complete + M3-ε pointer

Shipped:
  - tracemiku-core::decompiler::{ir, backend, builder}        🟡 M3-δ
  - /api/dec/summary (trace-ir source only)                    🟡 M3-δ
  - frontend DecompilerPanel (minimal fn list)                ✅ M3-δ
  - scripts/m3_delta_parity.py (soft-gated)                    ✅ M3-δ

Skeleton scope: root F0 FuncIR only. BlockIR construction, callee
splits, type anchors, VM detection, /api/dec/fn/{id}, render_summary_md
fidelity, symbol/bn source fallback all defer to M3-ε.

Backend trait + NoneBackend stub: Real BinjaBackend / GhidraBackend
defer to M5+ (PyO3 / sidecar plumbing).

M3-ε scope precisely captured in TODO.md.
EOF
)"
```

---

## Self-Review

**Spec coverage:**
| Spec line | Task |
|---|---|
| `decompiler/ir.py` port | Task 1 |
| `decompiler/backend.py` (Protocol + dataclasses) | Task 2 |
| `decompiler/builder.py` skeleton (build_trace_ir) | Task 3 |
| `/api/dec/summary` endpoint | Task 4 |
| Frontend DecompilerPanel | Task 5 |
| Parity script + docs sync | Task 6 |

**Out of scope (deferred to M3-ε, intentional):**
- BlockIR construction (asm/samples/exits/exec_count tier classification)
- Top-K callee splits (`split_top_k` / `split_min_records`)
- Type anchors (JSON-spec driven; consumed via M5 `type_anchor.py` port)
- VM candidate detection (`vm_candidate.py` port)
- Loop detection (Tarjan SCC over function-scope CFG → LoopIR + InductionVar)
- `/api/dec/fn/{id}` per-fn markdown
- `/api/dec/llm-call` LLM bundle
- `render_summary_md` fidelity (Python's pretty markdown, currently a 1-line text fallback in Rust)
- Symbol-source fallback in `/api/dec/summary` (the `_cfg_funcs()` Python branch)
- Real BinjaBackend / GhidraBackend impls (PyO3 / sidecar — M5+)

**Type consistency:**
- `TopIR.fn_by_id(id)` (Rust) ↔ `TopIR.fn(id)` (Python) — same surface, renamed because `fn` is a Rust keyword.
- `BlockIR.ref_id` (Rust) ↔ `BlockIR.ref` (Python) — same wire (`#[serde(rename = "ref")]`).
- `FuncIR.static_info` (Rust) ↔ `FuncIR.static` (Python) — same wire (`#[serde(rename = "static")]`).
- `FieldHint.struct_name` (Rust) ↔ `FieldHint.struct` (Python) — Rust field naming pragmatic; wire compat deferred until /api/field-at lands (M5+).

**Risk:** Task 3's `trace.meta.raw_truncated()` / `raw_last_insn_is_ret()` accessors may not exist in current Rust `TraceMeta`. If absent, add them as a small extension to `meta.rs` (parse from per-call meta.json into `pub truncated: bool, pub last_insn_is_ret: bool` fields). Step 1 has the inline guidance.

**Lessons applied from M3-β/γ:**
- Don't expand task scope mid-flight to chase gaps surfaced by parity; soft-gate + defer (Task 6 explicitly soft-gates dec-summary parity for M3-ε to close).
- Subagents get full code blocks where the algorithm is non-trivial (Tasks 1-4); structural / cosmetic tasks (Task 5/6) get pointers + patterns.

---

**Plan complete and saved.** Per `CLAUDE.md` user-pref §"Skip the 'Two execution options' handoff" — execution proceeds via `superpowers:subagent-driven-development`.
