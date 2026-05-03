# Analysis v2 — M2-γ Implementation Plan (Index + Symbols + populated `/api/records`)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Light up the symbol-resolution path so the v2 trace stack actually attributes records to functions. Port `viewer/disasm.py::def_use` (capstone `regs_access`) + reg-name normalization + `viewer/index.py::Index` (reg-def/use chains) + `viewer/symbols.py::{SymbolMap, ModuleResolver, auto_known_offsets}` to Rust. Wire them into the server via a new `/api/idxs-for-pc` endpoint and populate the previously-null `func` / `off` fields on `/api/records`. Atomic deliverable: `scripts/m2_gamma_parity.py` prints `OK` confirming Rust `/api/idxs-for-pc` and `/api/records.func/off` match Python field-by-field on the synth trace, AND on the 4.2 GB real trace `traces/debug_minimal/...` for at least the first 100 records (real-trace parity is the milestone gate that proves the symbol pipeline works on live data).

**Architecture:** `tracemiku-core::disasm::decoder` flips `detail(true)` so capstone exposes `regs_access`. New `disasm::regs` ports `viewer/regs.py::normalize_disasm_reg` (w0→x0, x29→fp, x30→lr, etc.). `tracemiku-core::index::Index` is a sequential builder over `Trace` that fills `reg_defs: HashMap<String, Vec<usize>>` + `reg_uses: HashMap<String, Vec<usize>>` (mem_writes/mem_reads deferred to M2-δ when MemShadow lands). `tracemiku-core::symbols::{SymbolMap, ModuleResolver}` are PC→fn+off and PC→module lookups respectively, both sorted-Vec + binary-search. `auto_known_offsets` heuristic ports verbatim. `AppState` now owns `Arc<Index>` + `Arc<SymbolMap>` + `Arc<ModuleResolver>` (eager-loaded; Index build on a 15M-record real trace is ~1-2s in M0 baseline so eager is fine). `/api/records` handler enriches each row with `func` / `off` via SymbolMap and `module` via ModuleResolver — lifting the previously-`null` fields. New `/api/idxs-for-pc?pc=&cursor=&limit=` matches Python wire shape exactly.

**Tech Stack:** Same Rust workspace. No new deps — capstone 0.13's `detail(true)` exposes `regs_access` natively; `Index` and `SymbolMap` are pure-std data structures.

**Spec:** `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` §13.2 (`disasm.py def/use`, `index.py`, `symbols.py` rows); §13.5 (`/api/idxs-for-pc` row); wire contract for `/api/idxs-for-pc` and `RecordRow` in `webui/schemas.py:37-50` + `webui/server.py:838-861`. Symbol-dependent fields on `/api/records` (the `func`, `off`, `module` columns) become non-null in M2-γ — that's the user-visible deliverable.

**M2 milestone status:** plan **3 of 4** within M2:
- ✅ M2-α: Trace + Record + CLI stats parity
- ✅ M2-β: capstone disasm + records endpoints + frontend records panel
- 🚧 M2-γ (this plan): Index (reg def/use) + SymbolMap + ModuleResolver + def_use + `/api/idxs-for-pc` + populated `/api/records`
- 🔜 M2-δ: CFG (petgraph) + MemShadow + Index mem ops + taint + calltree + FunctionIndex + decompiler::backend stub + Graph panel + Functions panel + final M2 parity

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-core/src/disasm/regs.rs` (new) | `normalize_disasm_reg(name) -> String` mirror of `viewer/regs.py:35-46`. Pure fn. |
| `rust/crates/tracemiku-core/src/disasm/decoder.rs` (modify) | Flip `detail(false)` → `detail(true)`. Extend `DecodedInsn` with `regs_def: Vec<String>` + `regs_use: Vec<String>`. Build them from capstone's `regs_access()` API. |
| `rust/crates/tracemiku-core/src/disasm/mod.rs` (modify) | `pub mod regs;` + re-export `normalize_disasm_reg`. |
| `rust/crates/tracemiku-core/src/index.rs` (new) | `Index` struct: `reg_defs: HashMap<String, Vec<usize>>`, `reg_uses: HashMap<String, Vec<usize>>`. `Index::build(trace) -> Self`. mem_writes/mem_reads stub (empty Vec for M2-γ; M2-δ fills). |
| `rust/crates/tracemiku-core/src/symbols.rs` (new) | `SymbolMap` (sorted-Vec + binary-search PC→(name, offset)). `ModuleResolver` (sorted-Vec PC→Option<ModuleInfo>). `auto_known_offsets(trace) -> HashMap<u64, String>` ports `viewer/symbols.py:96-156`. `build_from_trace(trace, base, known_offsets) -> SymbolMap`. |
| `rust/crates/tracemiku-core/src/lib.rs` (modify) | `pub mod index; pub mod symbols;`. |
| `rust/crates/tracemiku-core/src/prelude.rs` (modify) | Re-export `Index`, `SymbolMap`, `ModuleResolver`. |
| `rust/crates/tracemiku-core/tests/index_tests.rs` (new) | TDD: build Index from synth trace (reg_defs[x0] from a `mov x0, ...` instruction). |
| `rust/crates/tracemiku-core/tests/symbols_tests.rs` (new) | TDD: SymbolMap.lookup binary-search semantics; ModuleResolver.resolve PC→module; auto_known_offsets discovers fn boundaries. |
| `rust/crates/tracemiku-server/src/state.rs` (modify) | `AppState` gains `index: Arc<Index>`, `symbols: Arc<SymbolMap>`, `modules: Arc<ModuleResolver>`. Eager-loaded at `AppState::load`. |
| `rust/crates/tracemiku-server/src/routes/idxs_for_pc.rs` (new) | `GET /api/idxs-for-pc?pc=&cursor=&limit=` linear pc-scan over Trace returning `{status, pc, cursor, before, after, total_before, total_after, before_capped, after_capped}`. |
| `rust/crates/tracemiku-server/src/routes/records.rs` (modify) | Replace the `func: None, off: None` placeholders with real values from `state.symbols.lookup(pc)` and `state.modules.resolve(pc)`. |
| `rust/crates/tracemiku-server/src/routes/record.rs` (modify) | Same enrichment for `/api/record/{idx}` detail. |
| `rust/crates/tracemiku-server/src/routes/mod.rs` (modify) | Wire `/api/idxs-for-pc`. |
| `rust/crates/tracemiku-server/tests/idxs_for_pc_tests.rs` (new) | Integration tests: synth trace pc-scan, cursor/limit pagination, capped flags. |
| `rust/crates/tracemiku-server/tests/records_endpoint.rs` (modify) | Add tests asserting `func` is non-null on synth trace (after symbols populated). |
| `scripts/m2_gamma_parity.py` (new) | Boot Python webui + Rust server, hit `/api/records?count=20` and `/api/idxs-for-pc?pc=...`, diff M2-γ-committed subset including newly-populated `func`/`off`/`module`. |
| `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` (modify) | §13.2 mark `disasm.py def/use` ✅, `index.py` 🟡 (reg side done; mem side M2-δ), `symbols.py` ✅. §13.5 mark `/api/idxs-for-pc` ✅. |
| `TODO.md` (modify) | Append M2-γ completion bullets. |

---

## Task 1: reg-name normalization (regs.rs)

**Files:**
- Create: `rust/crates/tracemiku-core/src/disasm/regs.rs`
- Modify: `rust/crates/tracemiku-core/src/disasm/mod.rs`

Direct port of `viewer/regs.py::normalize_disasm_reg`. Pure functions over `&str`, returning `String`. M2-γ only needs the disasm-side normalize; the canonical_reg helper for endpoint input validation can wait until an endpoint actually consumes user-supplied reg names (the M2-γ endpoints don't).

- [ ] **Step 1: Write failing tests**

Create `rust/crates/tracemiku-core/src/disasm/regs.rs`:

```rust
//! ARM64 register name normalization. Direct port of viewer/regs.py.
//!
//! Capstone returns reg names like "w0", "X29", "WZR", "wsp". Our internal
//! canonical form is what the trace stores: x0..x28, fp, lr, sp, pc, xzr.

/// Map capstone's reg name to the canonical name used in record reg slots.
///
/// - `w0..w30` → `x0..x30` (32-bit alias of the 64-bit register)
/// - `x29` → `fp` (frame pointer alias used by trace storage)
/// - `x30` → `lr` (link register alias)
/// - `wsp` → `sp` (stack pointer 32-bit alias)
/// - `xzr` / `wzr` → `xzr` (zero register)
/// - empty input → empty output
pub fn normalize_disasm_reg(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    let n = name.to_ascii_lowercase();

    // w0..w30 → x0..x30
    if let Some(rest) = n.strip_prefix('w') {
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
            return format!("x{rest}");
        }
    }

    // Zero registers
    if n == "xzr" || n == "wzr" {
        return "xzr".to_string();
    }

    // Aliases
    match n.as_str() {
        "x29" => "fp".to_string(),
        "x30" => "lr".to_string(),
        "wsp" => "sp".to_string(),
        _ => n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_w_to_x() {
        assert_eq!(normalize_disasm_reg("w0"), "x0");
        assert_eq!(normalize_disasm_reg("w28"), "x28");
        assert_eq!(normalize_disasm_reg("W30"), "x30");
    }

    #[test]
    fn normalize_aliases() {
        assert_eq!(normalize_disasm_reg("x29"), "fp");
        assert_eq!(normalize_disasm_reg("x30"), "lr");
        assert_eq!(normalize_disasm_reg("wsp"), "sp");
    }

    #[test]
    fn normalize_zero_regs() {
        assert_eq!(normalize_disasm_reg("xzr"), "xzr");
        assert_eq!(normalize_disasm_reg("wzr"), "xzr");
        assert_eq!(normalize_disasm_reg("WZR"), "xzr");
    }

    #[test]
    fn normalize_canonical_passthrough() {
        assert_eq!(normalize_disasm_reg("x0"), "x0");
        assert_eq!(normalize_disasm_reg("fp"), "fp");
        assert_eq!(normalize_disasm_reg("lr"), "lr");
        assert_eq!(normalize_disasm_reg("sp"), "sp");
        assert_eq!(normalize_disasm_reg("pc"), "pc");
    }

    #[test]
    fn normalize_empty_and_garbage() {
        assert_eq!(normalize_disasm_reg(""), "");
        // "wfoo" — w-prefix but not all digits → not a w-reg, returns as lowercased
        assert_eq!(normalize_disasm_reg("wfoo"), "wfoo");
        assert_eq!(normalize_disasm_reg("garbage"), "garbage");
    }
}
```

- [ ] **Step 2: Wire into mod.rs**

Open `rust/crates/tracemiku-core/src/disasm/mod.rs`. Current:

```rust
//! ARM64 instruction decoding (capstone-rs wrapper).
//!
//! Public entry: [`decode`] — cached per-thread via the FIFO buffer in
//! [`cache`]. Cold path: [`raw_decode`] — uncached.

pub mod cache;
pub mod classify;
pub mod decoder;

pub use cache::decode;
pub use decoder::{raw_decode, DecodedInsn};
```

Replace with:

```rust
//! ARM64 instruction decoding (capstone-rs wrapper).
//!
//! Public entry: [`decode`] — cached per-thread via the FIFO buffer in
//! [`cache`]. Cold path: [`raw_decode`] — uncached.

pub mod cache;
pub mod classify;
pub mod decoder;
pub mod regs;

pub use cache::decode;
pub use decoder::{raw_decode, DecodedInsn};
pub use regs::normalize_disasm_reg;
```

- [ ] **Step 3: Run tests**

```bash
cd rust && cargo test -p tracemiku-core --lib disasm::regs 2>&1 | tail -10 ; cd ..
```

Expected: `test result: ok. 5 passed; 0 failed`.

- [ ] **Step 4: cargo fmt + clippy**

```bash
cd rust && cargo fmt --all && cargo clippy -p tracemiku-core --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 5: Commit**

```bash
git add rust/crates/tracemiku-core/src/disasm/
git commit -m "$(cat <<'EOF'
feat(core): normalize_disasm_reg — direct port of viewer/regs.py

w0..w30 → x0..x30 (32-bit alias collapse).
x29 → fp, x30 → lr, wsp → sp (canonical name).
xzr/wzr → "xzr" (zero register sentinel).

5 unit tests cover w-prefix, aliases, zero regs, canonical passthrough,
empty/garbage. Used by Task 2 to normalize capstone regs_access output.
EOF
)"
```

---

## Task 2: Extend DecodedInsn with regs_def/regs_use (capstone detail=true)

**Files:**
- Modify: `rust/crates/tracemiku-core/src/disasm/decoder.rs`
- Modify: `rust/crates/tracemiku-core/tests/disasm_decode.rs`

Flip `detail(false)` to `detail(true)` so capstone populates operand info. Use `Insn.regs_access()` to get the read/write reg lists, normalize each via `normalize_disasm_reg`, attach to `DecodedInsn`. The `cmp/tst/cmn/...` write-classification fix (Python `viewer/disasm.py:84-98`) is a known capstone quirk we replicate verbatim.

- [ ] **Step 1: Append failing tests**

Append to `rust/crates/tracemiku-core/tests/disasm_decode.rs`:

```rust
// ── regs_access (def/use) — Task 2 ─────────────────────────────────────────

#[test]
fn decode_extracts_regs_def_use_for_mov() {
    // mov x0, x1 → 0xaa0103e0
    let d = raw_decode(0x100000, 0xaa0103e0);
    assert!(d.regs_def.contains(&"x0".to_string()),
            "mov x0, x1 must def x0; got defs={:?}", d.regs_def);
    assert!(d.regs_use.contains(&"x1".to_string()),
            "mov x0, x1 must use x1; got uses={:?}", d.regs_use);
}

#[test]
fn decode_cmp_writes_only_nzcv() {
    // cmp x0, x1 → 0xeb01001f (subs xzr, x0, x1)
    // Python convention: cmp DEFS only nzcv, USES x0+x1. capstone may falsely
    // claim x0 is defined; the wrapper must reclassify.
    let d = raw_decode(0x100000, 0xeb01001f);
    assert!(d.regs_def == vec!["nzcv".to_string()] || d.regs_def.is_empty(),
            "cmp must NOT def operand register; got defs={:?}", d.regs_def);
    let uses_set: std::collections::HashSet<&String> = d.regs_use.iter().collect();
    assert!(uses_set.contains(&"x0".to_string()),
            "cmp must use x0; got uses={:?}", d.regs_use);
    assert!(uses_set.contains(&"x1".to_string()),
            "cmp must use x1; got uses={:?}", d.regs_use);
}

#[test]
fn decode_w_alias_normalized_to_x() {
    // mov w0, w1 → 0x2a0103e0 (32-bit reg variant; capstone reports w0/w1)
    let d = raw_decode(0x100000, 0x2a0103e0);
    // After normalization, regs_def/regs_use should contain x0/x1, NOT w0/w1.
    assert!(d.regs_def.contains(&"x0".to_string()),
            "w0 alias must normalize to x0; got defs={:?}", d.regs_def);
    assert!(d.regs_use.contains(&"x1".to_string()),
            "w1 alias must normalize to x1; got uses={:?}", d.regs_use);
    assert!(!d.regs_def.contains(&"w0".to_string()),
            "raw w0 must not appear in defs (post-normalize)");
}

#[test]
fn decode_nop_has_empty_regs() {
    let d = raw_decode(0x100000, 0xd503201f);
    assert!(d.regs_def.is_empty(), "nop has no def, got {:?}", d.regs_def);
    assert!(d.regs_use.is_empty(), "nop has no use, got {:?}", d.regs_use);
}
```

- [ ] **Step 2: Run — failing red**

```bash
cd rust && cargo test -p tracemiku-core --test disasm_decode 2>&1 | tail -10 ; cd ..
```

Expected: 4 new tests fail (compile error: `regs_def` / `regs_use` fields don't exist on `DecodedInsn`).

- [ ] **Step 3: Modify decoder.rs**

Open `rust/crates/tracemiku-core/src/disasm/decoder.rs`. Replace contents with:

```rust
//! capstone-rs wrapper. Provides decode() returning DecodedInsn with mnemonic,
//! op_str, branch/call/ret classification, and (M2-γ) register def/use lists.

use std::cell::RefCell;

use capstone::arch::{arm64, BuildsCapstone, BuildsCapstoneSyntax, DetailsArchInsn};
use capstone::Capstone;
use serde::Serialize;

use crate::disasm::classify::{is_branch_mnem, is_call_mnem, is_ret_mnem};
use crate::disasm::regs::normalize_disasm_reg;

#[derive(Debug, Clone, Serialize)]
pub struct DecodedInsn {
    pub pc: u64,
    pub inst: u32,
    pub mnemonic: String,
    pub op_str: String,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_ret: bool,
    /// Registers written by this instruction, normalized to canonical names.
    pub regs_def: Vec<String>,
    /// Registers read by this instruction, normalized to canonical names.
    pub regs_use: Vec<String>,
}

impl DecodedInsn {
    pub fn bad(pc: u64, inst: u32) -> Self {
        Self {
            pc,
            inst,
            mnemonic: "<bad>".to_string(),
            op_str: format!("{inst:08x}"),
            is_branch: false,
            is_call: false,
            is_ret: false,
            regs_def: Vec::new(),
            regs_use: Vec::new(),
        }
    }
}

thread_local! {
    static CS: RefCell<Capstone> = RefCell::new(
        Capstone::new()
            .arm64()
            .mode(arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .expect("capstone arm64 init failed — bundled build broken?"),
    );
}

/// Subset of mnemonics where capstone falsely claims the operand register is
/// written (it's only read; only nzcv is actually written). Mirrors
/// `viewer/disasm.py:84-98`.
fn is_compare_style(mnem: &str) -> bool {
    let base = mnem.split('.').next().unwrap_or(mnem);
    matches!(base, "cmp" | "tst" | "cmn" | "ccmn" | "ccmp" | "fcmp" | "fccmp" | "fccmpe")
}

pub fn raw_decode(pc: u64, inst: u32) -> DecodedInsn {
    let bytes = inst.to_le_bytes();
    CS.with(|cs| {
        let cs = cs.borrow();
        let insns = match cs.disasm_all(&bytes, pc) {
            Ok(i) => i,
            Err(_) => return DecodedInsn::bad(pc, inst),
        };
        let Some(ins) = insns.iter().next() else {
            return DecodedInsn::bad(pc, inst);
        };
        let mnem = ins.mnemonic().unwrap_or("<bad>").to_string();
        let op_str = ins.op_str().unwrap_or("").to_string();

        // Extract register access via capstone detail. Returns Result<(read, write)>.
        let (mut regs_use, mut regs_def): (Vec<String>, Vec<String>) =
            match cs.regs_access(ins) {
                Ok((r, w)) => (
                    r.iter()
                        .filter_map(|reg| cs.reg_name(*reg))
                        .map(|name| normalize_disasm_reg(&name))
                        .filter(|s| !s.is_empty())
                        .collect(),
                    w.iter()
                        .filter_map(|reg| cs.reg_name(*reg))
                        .map(|name| normalize_disasm_reg(&name))
                        .filter(|s| !s.is_empty())
                        .collect(),
                ),
                Err(_) => (Vec::new(), Vec::new()),
            };

        // cmp-style fix: capstone falsely claims the operand reg is written.
        // Reclassify all non-nzcv "defs" as uses, keep only nzcv.
        if is_compare_style(&mnem) {
            let nzcv_def = regs_def.iter().any(|r| r == "nzcv");
            let falsely_def: Vec<String> =
                regs_def.iter().filter(|r| *r != "nzcv").cloned().collect();
            regs_def = if nzcv_def {
                vec!["nzcv".to_string()]
            } else {
                Vec::new()
            };
            for r in falsely_def {
                if !regs_use.contains(&r) {
                    regs_use.push(r);
                }
            }
        }

        DecodedInsn {
            pc,
            inst,
            is_branch: is_branch_mnem(&mnem),
            is_call: is_call_mnem(&mnem),
            is_ret: is_ret_mnem(&mnem),
            mnemonic: mnem,
            op_str,
            regs_def,
            regs_use,
        }
    })
}
```

The `BuildsCapstoneSyntax` and `DetailsArchInsn` traits may not be required — the imports above are conservative. If clippy reports unused imports, drop them. The key API is `cs.regs_access(insn) -> CsResult<(Vec<RegId>, Vec<RegId>)>` for (read, write).

If the capstone-rs API differs (e.g., `regs_access` requires `detail=true` to be set AND a specific feature flag), check `cargo doc --open --package capstone` and adapt. Common issue: `regs_access` returns `Result<(insn_regs_read, insn_regs_write), CsErr>` — match on it accordingly.

- [ ] **Step 4: Run tests — should PASS**

```bash
cd rust && cargo test -p tracemiku-core --test disasm_decode 2>&1 | tail -15 ; cd ..
```

Expected: `15 passed` (11 from M2-β + 4 new). If `decode_cmp_writes_only_nzcv` fails because capstone v0.13's regs_access doesn't classify cmp as "writes operand", then the cmp-style fix is unnecessary and the test should pass anyway (defs would just be `["nzcv"]`).

If `decode_w_alias_normalized_to_x` fails because capstone doesn't return `w0`/`w1` for the 32-bit mov variant: dump the actual reg names with:

```bash
cd rust && cargo test -p tracemiku-core --test disasm_decode decode_w_alias_normalized_to_x -- --nocapture 2>&1 | tail -20 ; cd ..
```

If capstone is already returning `x0`/`x1` directly (no w-alias), the test still passes via the canonical-passthrough path of `normalize_disasm_reg`.

- [ ] **Step 5: Re-run cache + record + record-detail tests** — they consume DecodedInsn through the prelude and may fail to compile if the struct shape change is incomplete:

```bash
cd rust && cargo test -p tracemiku-core 2>&1 | tail -10 ; cd ..
cd rust && cargo test -p tracemiku-server 2>&1 | tail -10 ; cd ..
```

Expected: all green (~50 tests across both crates).

- [ ] **Step 6: cargo fmt + clippy clean**

```bash
cd rust && cargo fmt --all && cargo clippy --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 7: Commit**

```bash
git add rust/crates/tracemiku-core/src/disasm/decoder.rs rust/crates/tracemiku-core/tests/disasm_decode.rs
git commit -m "$(cat <<'EOF'
feat(core): DecodedInsn.regs_def/regs_use — capstone detail mode + def/use

Flips capstone detail(false)→detail(true). regs_access() yields read/write
RegIds; we resolve via reg_name() and normalize through normalize_disasm_reg
(w0→x0, x29→fp, etc.).

cmp/tst/cmn/ccmn/ccmp/fcmp/fccmp/fccmpe fix mirrors viewer/disasm.py:84-98:
capstone falsely claims the operand reg is written; we keep only nzcv on
defs and move the rest to uses.

4 new TDD tests cover mov def/use, cmp-style nzcv-only def, w-alias
normalization, nop empty regs.
EOF
)"
```

---

## Task 3: Index struct + build (reg_defs / reg_uses)

**Files:**
- Create: `rust/crates/tracemiku-core/src/index.rs`
- Modify: `rust/crates/tracemiku-core/src/lib.rs`
- Modify: `rust/crates/tracemiku-core/src/prelude.rs`
- Create: `rust/crates/tracemiku-core/tests/index_tests.rs`

`Index` mirrors `viewer/index.py` for the reg side only. mem_writes/mem_reads are deferred to M2-δ when MemShadow lands and taint actually consumes them — exposing empty stubs now would be dead code (CLAUDE.md: don't add features beyond what the task requires).

The build is a single-pass `for i in 0..trace.len()` walking `decode(pc, inst)` per record, appending `i` to the relevant `Vec` in two HashMaps. On 15M records this takes ~2-3s sequentially (capstone-bounded, not HashMap-bounded). Parallel via rayon is M2-δ when CFG also wants the same iteration pattern.

- [ ] **Step 1: Write failing tests**

Create `rust/crates/tracemiku-core/tests/index_tests.rs`:

```rust
//! TDD for tracemiku-core::index.

mod common {
    include!("common/mod.rs");
}

use tracemiku_core::prelude::*;

#[test]
fn index_records_reg_def_for_mov_record() {
    use std::fs;
    use std::io::Write;

    // Build a tiny custom trace: 1 record at PC=0x100000 with inst=mov x0, x1.
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp.path().join("run").join("calls").join("call_001_tid100_1r_2ms");
    fs::create_dir_all(&cd).unwrap();

    let mut buf = vec![0u8; 272];
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[256..264].copy_from_slice(&0x7000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xaa0103e0u32.to_le_bytes());  // mov x0, x1
    let mut f = fs::File::create(cd.join("trace.bin")).unwrap();
    f.write_all(&buf).unwrap();

    fs::write(cd.join("meta.json"),
              r#"{"records":1,"tid":100,"ms":2,"truncated":false}"#).unwrap();
    fs::write(tmp.path().join("run").join("meta.json"),
              r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#).unwrap();

    let t = Trace::load(&cd).unwrap();
    let idx = Index::build(&t);

    // x0 is defined at record 0 (mov dst is x0).
    let x0_defs = idx.reg_defs.get("x0").expect("x0 must have defs");
    assert_eq!(x0_defs, &vec![0usize]);

    // x1 is used at record 0 (mov src is x1).
    let x1_uses = idx.reg_uses.get("x1").expect("x1 must have uses");
    assert_eq!(x1_uses, &vec![0usize]);

    // x0 should NOT be in uses (not read by mov x0, x1).
    assert!(idx.reg_uses.get("x0").map(|v| v.is_empty()).unwrap_or(true));
}

#[test]
fn index_empty_trace_yields_empty_index() {
    let fix = common::synth_trace_dir(0);
    let t = Trace::load(&fix.call_dir).unwrap();
    let idx = Index::build(&t);
    assert!(idx.reg_defs.is_empty());
    assert!(idx.reg_uses.is_empty());
}

#[test]
fn index_synth_trace_has_consistent_counts() {
    // Synth trace from common::synth_trace_dir writes nop instructions
    // (inst=0xd503201f). nop has no def/use, so the Index should be empty.
    let fix = common::synth_trace_dir(5);
    let t = Trace::load(&fix.call_dir).unwrap();
    let idx = Index::build(&t);
    // All synth records are nop → no def/use entries.
    let total_def_entries: usize = idx.reg_defs.values().map(|v| v.len()).sum();
    let total_use_entries: usize = idx.reg_uses.values().map(|v| v.len()).sum();
    assert_eq!(total_def_entries, 0,
               "nop-only synth trace should have no defs, got: {:?}", idx.reg_defs);
    assert_eq!(total_use_entries, 0);
}
```

The `mod common { include!("common/mod.rs"); }` workaround imports the existing `synth_trace_dir` fixture without re-defining it. If cargo complains about duplicate `mod common` between integration test files, change to `#[path = "common/mod.rs"] mod common;`.

- [ ] **Step 2: Run — failing red**

```bash
cd rust && cargo test -p tracemiku-core --test index_tests 2>&1 | tail -10 ; cd ..
```

Expected: compile error — `Index` not in prelude.

- [ ] **Step 3: Implement Index**

Create `rust/crates/tracemiku-core/src/index.rs`:

```rust
//! Per-register def-use indices over a Trace. Used by taint and the
//! `last-write-of-reg` family of endpoints.
//!
//! M2-γ: reg_defs / reg_uses only. mem_writes / mem_reads come in M2-δ
//! when MemShadow lands and taint actually consumes them. Defining empty
//! stubs now would be dead code (CLAUDE.md: don't add features beyond
//! what the task requires).

use std::collections::HashMap;

use crate::disasm::decode;
use crate::trace::Trace;

/// Inverted index: register name → sorted list of record indices.
#[derive(Debug, Default, Clone)]
pub struct Index {
    /// `reg_defs[r]` = sorted record indices that WRITE to `r`.
    pub reg_defs: HashMap<String, Vec<usize>>,
    /// `reg_uses[r]` = sorted record indices that READ from `r`.
    pub reg_uses: HashMap<String, Vec<usize>>,
}

impl Index {
    /// Walk every record in `trace`, decode the instruction, and accumulate
    /// def/use entries by register name. Sequential — one Capstone call per
    /// record (cached by the disasm FIFO, so re-decoding the same PC is free).
    pub fn build(trace: &Trace) -> Self {
        let mut idx = Index::default();
        for i in 0..trace.len() {
            let pc = trace.pc(i);
            let inst = trace.inst(i);
            let d = decode(pc, inst);
            for r in &d.regs_def {
                idx.reg_defs.entry(r.clone()).or_default().push(i);
            }
            for r in &d.regs_use {
                idx.reg_uses.entry(r.clone()).or_default().push(i);
            }
        }
        idx
    }

    /// Last def index for `reg` strictly before `cursor`. Binary search.
    /// Returns None if `reg` has no defs before cursor.
    pub fn last_def_before(&self, reg: &str, cursor: usize) -> Option<usize> {
        let defs = self.reg_defs.get(reg)?;
        match defs.binary_search(&cursor) {
            Ok(i) => {
                if i == 0 { None } else { Some(defs[i - 1]) }
            }
            Err(i) => {
                if i == 0 { None } else { Some(defs[i - 1]) }
            }
        }
    }
}
```

- [ ] **Step 4: Update lib.rs and prelude**

Open `rust/crates/tracemiku-core/src/lib.rs`. Add `pub mod index;` (alphabetical):

```rust
//! traceMiku v2 — analysis core.
//!
//! See `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`
//! for the architecture. This crate contains all trace-side analysis;
//! the HTTP server lives in `tracemiku-server`, the CLI in `tracemiku-cli`.
//!
//! Public surface is re-exported from [`prelude`].

#![deny(unused_must_use)]
#![warn(clippy::all)]

pub mod disasm;
pub mod index;
pub mod prelude;
pub mod trace;
```

Open `rust/crates/tracemiku-core/src/prelude.rs`. Replace with:

```rust
//! Re-exports the public API surface for downstream consumers.
//!
//! Use `use tracemiku_core::prelude::*;` rather than reaching into
//! submodules directly.

pub use crate::disasm::{decode, normalize_disasm_reg, DecodedInsn};
pub use crate::index::Index;
pub use crate::trace::{
    CallInfo, MetaError, ModuleInfo, Record, Trace, TraceMeta,
    REC_NUM_REGS, REC_SIZE,
};
```

- [ ] **Step 5: Run tests — should PASS**

```bash
cd rust && cargo test -p tracemiku-core --test index_tests 2>&1 | tail -10 ; cd ..
```

Expected: `test result: ok. 3 passed; 0 failed`.

If the `include!` macro for common fails because the path resolution differs between integration test binaries, fall back to creating `tests/common_index.rs` that has its own copy of synth_trace_dir. But typical Rust convention is `#[path = "common/mod.rs"] mod common;` — use that if the include! version errors.

- [ ] **Step 6: cargo fmt + clippy**

```bash
cd rust && cargo fmt --all && cargo clippy -p tracemiku-core --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 7: Commit**

```bash
git add rust/crates/tracemiku-core/src/index.rs rust/crates/tracemiku-core/src/lib.rs rust/crates/tracemiku-core/src/prelude.rs rust/crates/tracemiku-core/tests/index_tests.rs
git commit -m "$(cat <<'EOF'
feat(core): Index — reg_defs / reg_uses inverted index over Trace

Direct port of viewer/index.py (reg side only). HashMap<String, Vec<usize>>
keyed on canonical reg name, values sorted by record idx. Sequential build
via decode(pc, inst); cache makes repeat decodes free.

mem_writes / mem_reads deferred to M2-δ (need mem_op extraction + MemShadow).

last_def_before(reg, cursor) helper for taint / last-write-of-reg endpoint.
3 TDD tests: mov def/use round-trip, empty trace, nop-only trace (no defs).
EOF
)"
```

---

## Task 4: SymbolMap (PC → fn+off via binary search)

**Files:**
- Create: `rust/crates/tracemiku-core/src/symbols.rs`
- Modify: `rust/crates/tracemiku-core/src/lib.rs`
- Modify: `rust/crates/tracemiku-core/src/prelude.rs`
- Create: `rust/crates/tracemiku-core/tests/symbols_tests.rs`

Direct port of `viewer/symbols.py::SymbolMap`. Sorted-Vec + binary-search lookup. The Python lazily sorts; Rust will sort eagerly at construction time since it's cheap and avoids interior mutability.

- [ ] **Step 1: Write failing tests**

Create `rust/crates/tracemiku-core/tests/symbols_tests.rs`:

```rust
//! TDD for SymbolMap.

use tracemiku_core::prelude::*;

#[test]
fn symbol_map_lookup_returns_unknown_for_empty() {
    let m = SymbolMap::new();
    let (name, off) = m.lookup(0x100000);
    assert_eq!(name, "?");
    assert_eq!(off, 0);
}

#[test]
fn symbol_map_lookup_finds_function() {
    let mut m = SymbolMap::new();
    m.add(0x100000, "f_root".to_string());
    m.add(0x100100, "f_alpha".to_string());
    m.add(0x100200, "f_beta".to_string());

    // Exactly at f_root start
    let (n, o) = m.lookup(0x100000);
    assert_eq!(n, "f_root");
    assert_eq!(o, 0);

    // Inside f_root
    let (n, o) = m.lookup(0x100050);
    assert_eq!(n, "f_root");
    assert_eq!(o, 0x50);

    // Boundary: 0x100100 is start of f_alpha (NOT end of f_root)
    let (n, o) = m.lookup(0x100100);
    assert_eq!(n, "f_alpha");
    assert_eq!(o, 0);

    // Inside f_alpha
    let (n, o) = m.lookup(0x100105);
    assert_eq!(n, "f_alpha");
    assert_eq!(o, 0x5);
}

#[test]
fn symbol_map_lookup_before_first_returns_unknown() {
    let mut m = SymbolMap::new();
    m.add(0x100000, "f".to_string());
    let (n, o) = m.lookup(0x0fffff);
    assert_eq!(n, "?");
    assert_eq!(o, 0);
}

#[test]
fn symbol_map_unsorted_input_handled() {
    // Add functions in non-sorted order; lookup must still work.
    let mut m = SymbolMap::new();
    m.add(0x100200, "f_beta".to_string());
    m.add(0x100000, "f_root".to_string());
    m.add(0x100100, "f_alpha".to_string());
    let (n, _) = m.lookup(0x100050);
    assert_eq!(n, "f_root");
    let (n, _) = m.lookup(0x100150);
    assert_eq!(n, "f_alpha");
    let (n, _) = m.lookup(0x100250);
    assert_eq!(n, "f_beta");
}
```

- [ ] **Step 2: Run — failing red**

```bash
cd rust && cargo test -p tracemiku-core --test symbols_tests 2>&1 | tail -5 ; cd ..
```

Expected: compile error — `SymbolMap` not found.

- [ ] **Step 3: Implement SymbolMap + ModuleResolver**

Create `rust/crates/tracemiku-core/src/symbols.rs`:

```rust
//! Symbol resolution: PC → function name + offset, PC → module.
//!
//! Direct port of `viewer/symbols.py::{SymbolMap, ModuleResolver}`.
//! Both use sorted-Vec + binary-search; sort happens lazily on first lookup
//! to amortize many `add` calls during construction.

use std::collections::HashMap;

use crate::trace::{ModuleInfo, Trace};

/// Lookup PC → (function-name, offset-within).
#[derive(Debug, Default, Clone)]
pub struct SymbolMap {
    /// (start_pc, name), sorted by start_pc (lazy).
    functions: Vec<(u64, String)>,
    sorted: bool,
}

impl SymbolMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function entry. Multiple entries with the same start_pc are
    /// allowed (last-added wins on ties due to binary-search bias).
    pub fn add(&mut self, pc: u64, name: String) {
        self.functions.push((pc, name));
        self.sorted = false;
    }

    fn ensure_sorted(&mut self) {
        if !self.sorted {
            self.functions.sort_by_key(|(pc, _)| *pc);
            self.sorted = true;
        }
    }

    /// `(name, offset_in_func)`. Returns `("?", 0)` if `pc` is before any
    /// known function or no functions exist.
    pub fn lookup(&self, pc: u64) -> (String, u64) {
        if self.functions.is_empty() {
            return ("?".to_string(), 0);
        }
        // We can't sort here because &self. But the user MUST call lookup
        // after all adds; we sort once on first lookup via interior mutability.
        // Simpler: clone the data and binary-search on the clone if not sorted.
        // Cleaner: take &mut self for sorting on the lookup path. But that's
        // awkward for callers.
        //
        // Pragmatic choice: panic if not sorted. Users call seal() once before
        // first lookup, OR add() and lookup are interleaved naturally because
        // the dataset is small and sort cost is negligible — call sort_unstable
        // every time on a Vec we own via Cell. Simplest and correct: clone +
        // sort + binary-search per lookup is O(n log n) per lookup; not OK for
        // millions of lookups.
        //
        // Real solution: take &mut self for lookup, OR seal() before lookups.
        // We expose seal() AND auto-sort on lookup via interior mutability
        // (RefCell<Vec>) — but that complicates the public API.
        //
        // Compromise: `lookup` requires `&self`, and users SHOULD call
        // `into_sorted` (consuming) or `sort` (&mut self) after building.
        // Since this is internal API used by AppState (which controls the
        // build lifecycle), expose a `freeze` method and document.

        let funcs = &self.functions;
        // Binary search for the largest start_pc <= pc.
        // Standard "find rightmost less-than-or-equal" via partition_point.
        let i = funcs.partition_point(|(start, _)| *start <= pc);
        if i == 0 {
            return ("?".to_string(), 0);
        }
        let (start, ref name) = funcs[i - 1];
        (name.clone(), pc.wrapping_sub(start))
    }

    /// Sort the function list. MUST be called before `lookup` if any `add`
    /// was made out of order. Cheap (O(n log n) — typically a few hundred
    /// entries).
    pub fn freeze(&mut self) {
        self.ensure_sorted();
    }

    /// Number of registered functions.
    pub fn len(&self) -> usize {
        self.functions.len()
    }
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}

/// Build a SymbolMap from per-call `meta.json::known_offsets` and run-meta
/// `module` info. `base` is the primary-module base PC; offsets in the
/// known_offsets dict are RELATIVE to that base (per the per-call meta.json
/// contract).
pub fn build_from_trace(
    trace: &Trace,
    base: u64,
    known_offsets: &HashMap<u64, String>,
) -> SymbolMap {
    let _ = trace; // M2-γ doesn't use the trace bytes directly; reserved for
                   // M2-δ when auto_known_offsets walks call instructions.
    let mut m = SymbolMap::new();
    for (off, name) in known_offsets {
        m.add(base.wrapping_add(*off), name.clone());
    }
    m.freeze();
    m
}

/// Resolve PC → primary module (or any module) by base+size range.
#[derive(Debug, Default, Clone)]
pub struct ModuleResolver {
    modules: Vec<ModuleResolverEntry>,
}

#[derive(Debug, Clone)]
struct ModuleResolverEntry {
    base: u64,
    end: u64,
    name: String,
    size: u64,
    base_str: String,
    end_str: String,
}

impl ModuleResolver {
    pub fn from_modules(modules: &[ModuleInfo]) -> Self {
        let mut entries: Vec<ModuleResolverEntry> = modules
            .iter()
            .map(|m| {
                let base = u64::from_str_radix(m.base.trim_start_matches("0x"), 16).unwrap_or(0);
                ModuleResolverEntry {
                    base,
                    end: base.wrapping_add(m.size),
                    name: m.name.clone(),
                    size: m.size,
                    base_str: m.base.clone(),
                    end_str: m.end.clone(),
                }
            })
            .collect();
        entries.sort_by_key(|e| e.base);
        Self { modules: entries }
    }

    /// PC → ModuleInfo (first module whose [base, end) contains pc).
    pub fn resolve(&self, pc: u64) -> Option<ModuleInfo> {
        // Linear scan is fine for <100 modules. Vectorized version comes in
        // M2-δ if profiling demands it.
        self.modules
            .iter()
            .find(|m| m.base <= pc && pc < m.end)
            .map(|m| ModuleInfo {
                name: m.name.clone(),
                base: m.base_str.clone(),
                size: m.size,
                end: m.end_str.clone(),
            })
    }

    /// PC → module name (or None).
    pub fn resolve_name(&self, pc: u64) -> Option<String> {
        self.resolve(pc).map(|m| m.name)
    }
}
```

The "compromise" comment block in `lookup` documents the design tradeoff. The actual implementation uses `partition_point` (available on `Vec<T>`) which gives the desired behavior without needing interior mutability — assumes the caller has called `freeze()`. We could add a `debug_assert!(self.sorted)` at the top of lookup but that breaks the hot path; instead document the contract.

- [ ] **Step 4: Update lib.rs + prelude**

Open `rust/crates/tracemiku-core/src/lib.rs`. Add `pub mod symbols;` (alphabetical, between `prelude` and `trace`):

```rust
pub mod disasm;
pub mod index;
pub mod prelude;
pub mod symbols;
pub mod trace;
```

Open `rust/crates/tracemiku-core/src/prelude.rs`. Add SymbolMap + ModuleResolver:

```rust
pub use crate::disasm::{decode, normalize_disasm_reg, DecodedInsn};
pub use crate::index::Index;
pub use crate::symbols::{build_from_trace, ModuleResolver, SymbolMap};
pub use crate::trace::{
    CallInfo, MetaError, ModuleInfo, Record, Trace, TraceMeta,
    REC_NUM_REGS, REC_SIZE,
};
```

- [ ] **Step 5: Run tests — should PASS**

```bash
cd rust && cargo test -p tracemiku-core --test symbols_tests 2>&1 | tail -10 ; cd ..
```

Expected: `4 passed`. The `symbol_map_unsorted_input_handled` test verifies that `freeze()` (called via `lookup` indirectly through `add` → `sorted=false` → … wait, the impl above doesn't sort on lookup).

Actually the `lookup` path uses `partition_point` directly on `self.functions` without checking `self.sorted`. The `symbol_map_unsorted_input_handled` test would fail unless the test calls `m.freeze()` after the adds, OR `lookup` is changed to take `&mut self`, OR `lookup` does sort lazily via interior mutability.

**Pick one**:
- (a) Make all tests call `m.freeze()` before lookup. Simplest. Document in `lookup` rustdoc that callers must freeze.
- (b) Use `RefCell<Vec>` and sort on first lookup. Hides the contract from callers.
- (c) `lookup` takes `&mut self`. Awkward for AppState (lookup is concurrent-read by axum handlers).

**Choose (a) for clean ownership.** Update the test:

```rust
#[test]
fn symbol_map_unsorted_input_handled() {
    let mut m = SymbolMap::new();
    m.add(0x100200, "f_beta".to_string());
    m.add(0x100000, "f_root".to_string());
    m.add(0x100100, "f_alpha".to_string());
    m.freeze();    // <-- add this line
    let (n, _) = m.lookup(0x100050);
    assert_eq!(n, "f_root");
    let (n, _) = m.lookup(0x100150);
    assert_eq!(n, "f_alpha");
    let (n, _) = m.lookup(0x100250);
    assert_eq!(n, "f_beta");
}
```

The other tests (which add in sorted order or have a single entry) work without freeze() because the natural single-element / append-order Vec is already sorted, but ADD freeze() to all of them anyway for consistency:

```rust
#[test]
fn symbol_map_lookup_finds_function() {
    let mut m = SymbolMap::new();
    m.add(0x100000, "f_root".to_string());
    m.add(0x100100, "f_alpha".to_string());
    m.add(0x100200, "f_beta".to_string());
    m.freeze();   // <-- add
    // ... rest unchanged
}

#[test]
fn symbol_map_lookup_before_first_returns_unknown() {
    let mut m = SymbolMap::new();
    m.add(0x100000, "f".to_string());
    m.freeze();   // <-- add
    let (n, o) = m.lookup(0x0fffff);
    // ...
}
```

`symbol_map_lookup_returns_unknown_for_empty` doesn't add anything, so no freeze needed (no-op). Re-run:

```bash
cd rust && cargo test -p tracemiku-core --test symbols_tests 2>&1 | tail -10 ; cd ..
```

Expected: `4 passed`.

- [ ] **Step 6: cargo fmt + clippy**

```bash
cd rust && cargo fmt --all && cargo clippy -p tracemiku-core --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 7: Commit**

```bash
git add rust/crates/tracemiku-core/src/symbols.rs rust/crates/tracemiku-core/src/lib.rs rust/crates/tracemiku-core/src/prelude.rs rust/crates/tracemiku-core/tests/symbols_tests.rs
git commit -m "$(cat <<'EOF'
feat(core): SymbolMap + ModuleResolver — PC→fn+off, PC→module

SymbolMap: sorted Vec<(u64, String)> + binary-search lookup via
partition_point. Caller must call freeze() after all add() calls; lookup
documented as no-mut-required hot path.

ModuleResolver: linear PC→ModuleInfo scan over <100 modules; vectorize
later if profiling demands.

build_from_trace(trace, base, known_offsets): assemble SymbolMap from
per-call meta.json known_offsets dict (offsets relative to module base).

4 TDD tests cover lookup boundaries, before-first-fn fallback, unsorted
input + freeze.
EOF
)"
```

---

## Task 5: AppState extension (Index + SymbolMap + ModuleResolver eager)

**Files:**
- Modify: `rust/crates/tracemiku-server/src/state.rs`
- Modify: `rust/crates/tracemiku-server/tests/meta_endpoint.rs` (extend existing test)

`AppState` gets three new `Arc`-wrapped fields. All three are eager-loaded at `AppState::load`. For the 4.2GB real trace, M0 baseline showed `build_from_trace` ~6.7s and `Index.build` ~26s (Python). Rust should be 5-10× faster, putting startup at ~3-5s — acceptable for a single-trace server (no need for lazy-load + Mutex complexity).

- [ ] **Step 1: Modify state.rs**

Open `rust/crates/tracemiku-server/src/state.rs`. Current content (post-M2-α):

```rust
use std::path::PathBuf;
use std::sync::Arc;

use tracemiku_core::prelude::{Trace, TraceMeta};

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppStateInner>,
}

pub struct AppStateInner {
    pub trace_dir: PathBuf,
    pub meta: TraceMeta,
    pub trace: Trace,
}

impl AppState {
    pub fn load(trace_dir: PathBuf) -> anyhow::Result<Self> {
        let meta = TraceMeta::load(&trace_dir)?;
        let trace = Trace::load(&trace_dir)?;
        Ok(Self {
            inner: Arc::new(AppStateInner { trace_dir, meta, trace }),
        })
    }
}
```

Replace with:

```rust
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tracemiku_core::prelude::{
    build_from_trace, Index, ModuleResolver, SymbolMap, Trace, TraceMeta,
};

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppStateInner>,
}

pub struct AppStateInner {
    pub trace_dir: PathBuf,
    pub meta: TraceMeta,
    pub trace: Trace,
    pub index: Index,
    pub symbols: SymbolMap,
    pub modules: ModuleResolver,
}

impl AppState {
    pub fn load(trace_dir: PathBuf) -> anyhow::Result<Self> {
        let meta = TraceMeta::load(&trace_dir)?;
        let trace = Trace::load(&trace_dir)?;

        let index = Index::build(&trace);
        let modules = ModuleResolver::from_modules(&meta.modules);

        // Build SymbolMap from per-call meta.json known_offsets if present,
        // otherwise empty. Format from the per-call meta.json:
        //   { "known_offsets": { "0x0": "f_root", "0x100": "f_alpha", ... } }
        // Offsets are RELATIVE to the primary module base.
        let primary_base: u64 = meta.module.as_ref().map(|m| {
            u64::from_str_radix(m.base.trim_start_matches("0x"), 16).unwrap_or(0)
        }).unwrap_or(0);
        let known_offsets = parse_known_offsets(&trace_dir).unwrap_or_default();
        let symbols = build_from_trace(&trace, primary_base, &known_offsets);

        Ok(Self {
            inner: Arc::new(AppStateInner {
                trace_dir, meta, trace, index, symbols, modules,
            }),
        })
    }
}

/// Read `<call_dir>/meta.json::known_offsets` and parse into hex-keyed map.
/// Returns None on any parse failure (caller treats as empty).
fn parse_known_offsets(call_dir: &std::path::Path) -> Option<HashMap<u64, String>> {
    let path = call_dir.join("meta.json");
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let ko = v.get("known_offsets")?.as_object()?;
    let mut out = HashMap::new();
    for (k, val) in ko.iter() {
        let off = u64::from_str_radix(k.trim_start_matches("0x"), 16).ok()?;
        let name = val.as_str()?;
        out.insert(off, name.to_string());
    }
    Some(out)
}
```

- [ ] **Step 2: Update meta_endpoint test fixture**

The existing M2-α `synth_call_dir()` in `rust/crates/tracemiku-server/tests/meta_endpoint.rs` writes empty trace.bin. It also doesn't write `known_offsets` to meta.json. For Task 5 testing, the existing test should still pass because the synth has no records (Index empty) and no known_offsets (SymbolMap empty), and the module resolver gets a single libt.so module.

Run the existing tests to confirm:

```bash
cd rust && cargo test -p tracemiku-server --test meta_endpoint 2>&1 | tail -5 ; cd ..
```

Expected: 2 passed (the M2-α tests). If `app_state_loads_trace_eagerly` fails because the new fields panic during init, fix the panic — all three constructors (Index::build, build_from_trace, ModuleResolver::from_modules) handle empty inputs gracefully so this should work without modification.

- [ ] **Step 3: Add a state-level test for the new fields**

Append to `rust/crates/tracemiku-server/tests/meta_endpoint.rs`:

```rust
#[test]
fn app_state_eagerly_loads_index_symbols_modules() {
    let (_tmp, call_dir) = synth_call_dir();
    let state = tracemiku_server::AppState::load(call_dir).expect("load AppState");
    // Index built — empty regs maps for an empty trace are OK.
    let _ = &state.inner.index.reg_defs;
    let _ = &state.inner.index.reg_uses;
    // SymbolMap built — empty for synth (no known_offsets in fixture).
    assert_eq!(state.inner.symbols.len(), 0);
    // ModuleResolver has libt.so.
    let m = state.inner.modules.resolve(0x100000);
    assert!(m.is_some(), "0x100000 should resolve to libt.so");
    assert_eq!(m.unwrap().name, "libt.so");
}
```

- [ ] **Step 4: Run server tests**

```bash
cd rust && cargo test -p tracemiku-server 2>&1 | tail -10 ; cd ..
```

Expected: meta_endpoint = 3 passed (2 existing + 1 new); records_endpoint = 6 passed.

- [ ] **Step 5: cargo fmt + clippy**

```bash
cd rust && cargo fmt --all && cargo clippy --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-server/src/state.rs rust/crates/tracemiku-server/tests/meta_endpoint.rs
git commit -m "$(cat <<'EOF'
feat(server): AppState now eager-loads Index + SymbolMap + ModuleResolver

All three are built at AppState::load (mmap is constant-time + Index/CFG
builds are 5-10× faster in Rust than Python so eager is fine for a single-
trace server).

SymbolMap built from per-call meta.json::known_offsets (offsets relative
to primary module base). Empty if absent.

1 new test: app_state_eagerly_loads_index_symbols_modules verifies all
three fields populate; ModuleResolver.resolve(libt.so PC) succeeds.
EOF
)"
```

---

## Task 6: GET /api/idxs-for-pc endpoint (TDD)

**Files:**
- Create: `rust/crates/tracemiku-server/src/routes/idxs_for_pc.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/mod.rs`
- Create: `rust/crates/tracemiku-server/tests/idxs_for_pc_tests.rs`

Wire shape (from Python `webui/server.py:838-861`):

```typescript
interface IdxsForPcResponse {
  status: "ready";        // M2-γ always ready (no BG building);
                          // Python uses status="building" when CFG isn't ready
                          // — that field is preserved for forward-compat.
  pc: string;             // echo of the input "0x..."
  cursor: number;
  before: number[];       // record idxs < cursor with pc==target, descending
                          // (closest-to-cursor first), capped at limit
  after: number[];        // record idxs >= cursor with pc==target, ascending,
                          // capped at limit
  total_before: number;   // total count of pc-matches < cursor
  total_after: number;    // total count of pc-matches >= cursor
  before_capped: boolean; // total_before > limit
  after_capped: boolean;  // total_after > limit
}
```

Algorithm: linear scan over `Trace::pc(i)` for `i in 0..n`, partition by `i < cursor` vs `i >= cursor`. For 15M-record real trace, this is ~50ms (memory bandwidth bound). Future optimization: add a pc → Vec<usize> hash index built lazily; not needed for M2-γ.

- [ ] **Step 1: Write failing tests**

Create `rust/crates/tracemiku-server/tests/idxs_for_pc_tests.rs`:

```rust
//! Black-box tests for GET /api/idxs-for-pc.

use std::fs;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn synth_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp.path().join("run").join("calls").join("call_001_tid100_9r_2ms");
    fs::create_dir_all(&cd).unwrap();

    // 9 records, PCs as in the existing records_endpoint fixture but with
    // intentional duplicates: pc 0x100000 appears at idx 0 and idx 5 (so we
    // can test the before/after split on a known-duplicate PC).
    let pcs = [
        0x100000u64, 0x100004, 0x100100, 0x100104,
        0x100008, 0x100000,    // <-- duplicate of idx 0
        0x100204, 0x100208, 0x10000c,
    ];
    let insts: [u32; 9] = [
        0xd503201f, 0x94000040, 0xd503201f, 0xd65f03c0,
        0x94000080, 0xd503201f, 0xd503201f, 0xd65f03c0, 0xd65f03c0,
    ];
    let mut buf = vec![0u8; 272 * 9];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"),
              r#"{"records":9,"tid":100,"ms":2,"truncated":false}"#).unwrap();
    fs::write(tmp.path().join("run").join("meta.json"),
              r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#).unwrap();
    (tmp, cd)
}

#[tokio::test]
async fn idxs_for_pc_finds_duplicates() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    // Cursor 3 splits: idx 0 (pc=0x100000) is BEFORE; idx 5 (pc=0x100000) is AFTER.
    let resp = app
        .oneshot(Request::builder()
            .uri("/api/idxs-for-pc?pc=0x100000&cursor=3&limit=10")
            .body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ready");
    assert_eq!(v["pc"], "0x100000");
    assert_eq!(v["cursor"], 3);
    // before: idx 0 (closest to cursor 3, descending)
    assert_eq!(v["before"], serde_json::json!([0]));
    // after: idx 5
    assert_eq!(v["after"], serde_json::json!([5]));
    assert_eq!(v["total_before"], 1);
    assert_eq!(v["total_after"], 1);
    assert_eq!(v["before_capped"], false);
    assert_eq!(v["after_capped"], false);
}

#[tokio::test]
async fn idxs_for_pc_no_match_empty() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder()
            .uri("/api/idxs-for-pc?pc=0xdeadbeef&cursor=0&limit=10")
            .body(Body::empty()).unwrap())
        .await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["before"], serde_json::json!([]));
    assert_eq!(v["after"], serde_json::json!([]));
    assert_eq!(v["total_before"], 0);
    assert_eq!(v["total_after"], 0);
}

#[tokio::test]
async fn idxs_for_pc_limit_caps_results() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    // pc=0xd503201f-encoded NOP appears at idx 0, 2, 5, 6 — wait no, those
    // are the inst values not pcs. Re-pick: pc 0x100000 at idx 0 and idx 5.
    // limit=0 should yield empty arrays but report total counts honestly.
    let resp = app
        .oneshot(Request::builder()
            .uri("/api/idxs-for-pc?pc=0x100000&cursor=10&limit=0")
            .body(Body::empty()).unwrap())
        .await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["before"], serde_json::json!([]));
    assert_eq!(v["after"], serde_json::json!([]));
    assert_eq!(v["total_before"], 2);   // both 0x100000s are before cursor=10
    assert_eq!(v["total_after"], 0);
    assert_eq!(v["before_capped"], true);
    assert_eq!(v["after_capped"], false);
}

#[tokio::test]
async fn idxs_for_pc_default_cursor_zero() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    // No cursor provided → defaults to 0, so all matches go to "after".
    let resp = app
        .oneshot(Request::builder()
            .uri("/api/idxs-for-pc?pc=0x100000")
            .body(Body::empty()).unwrap())
        .await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["after"], serde_json::json!([0, 5]));
    assert_eq!(v["total_after"], 2);
    assert_eq!(v["total_before"], 0);
}
```

- [ ] **Step 2: Run — failing red**

```bash
cd rust && cargo test -p tracemiku-server --test idxs_for_pc_tests 2>&1 | tail -10 ; cd ..
```

Expected: 4 tests fail with 404 (route not registered).

- [ ] **Step 3: Implement idxs_for_pc.rs**

Create `rust/crates/tracemiku-server/src/routes/idxs_for_pc.rs`:

```rust
//! GET /api/idxs-for-pc?pc=&cursor=&limit=
//!
//! Returns the set of record indices whose PC equals the target, partitioned
//! around `cursor` into `before` (descending, closest-to-cursor first) and
//! `after` (ascending). Each partition is capped at `limit`; the unbounded
//! totals are returned alongside as `total_before` / `total_after` plus
//! `*_capped` booleans.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct IdxsForPcQuery {
    pub pc: String,
    #[serde(default = "default_cursor")]
    pub cursor: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_cursor() -> usize { 0 }
fn default_limit() -> usize { 30 }

#[derive(Debug, Serialize)]
pub struct IdxsForPcResponse {
    pub status: &'static str,
    pub pc: String,
    pub cursor: usize,
    pub before: Vec<usize>,
    pub after: Vec<usize>,
    pub total_before: usize,
    pub total_after: usize,
    pub before_capped: bool,
    pub after_capped: bool,
}

pub async fn idxs_for_pc_handler(
    State(state): State<AppState>,
    Query(q): Query<IdxsForPcQuery>,
) -> Json<IdxsForPcResponse> {
    // Parse target PC from "0x..." or bare hex. On parse failure, return
    // the canonical empty response — match Python behavior (which would
    // raise but our wire shape doesn't define a 400 for this).
    let target = u64::from_str_radix(q.pc.trim_start_matches("0x"), 16).unwrap_or(0);

    let trace = &state.inner.trace;
    let n = trace.len();
    let cursor = q.cursor.min(n);

    // Linear scan: collect every i in 0..n where trace.pc(i) == target.
    // Partition by `i < cursor` vs `i >= cursor`. For 15M records this is
    // ~50ms; M2-δ adds a hashed pc index if profiling demands.
    let mut before_all: Vec<usize> = Vec::new();
    let mut after_all: Vec<usize> = Vec::new();
    for i in 0..n {
        if trace.pc(i) != target {
            continue;
        }
        if i < cursor {
            before_all.push(i);
        } else {
            after_all.push(i);
        }
    }

    let total_before = before_all.len();
    let total_after = after_all.len();
    let before_capped = total_before > q.limit;
    let after_capped = total_after > q.limit;

    // before: closest-to-cursor first (descending), capped at limit.
    before_all.reverse();
    before_all.truncate(q.limit);

    // after: ascending, capped.
    after_all.truncate(q.limit);

    Json(IdxsForPcResponse {
        status: "ready",
        pc: q.pc,
        cursor: q.cursor,
        before: before_all,
        after: after_all,
        total_before,
        total_after,
        before_capped,
        after_capped,
    })
}
```

- [ ] **Step 4: Wire into routes/mod.rs**

Open `rust/crates/tracemiku-server/src/routes/mod.rs`. Current:

```rust
pub mod meta;
pub mod record;
pub mod records;

use axum::routing::get;
use axum::Router;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/meta", get(meta::meta_handler))
        .route("/api/records", get(records::records_handler))
        .route("/api/record/:idx", get(record::record_handler))
        .with_state(state)
}
```

Replace with:

```rust
pub mod idxs_for_pc;
pub mod meta;
pub mod record;
pub mod records;

use axum::routing::get;
use axum::Router;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/meta", get(meta::meta_handler))
        .route("/api/records", get(records::records_handler))
        .route("/api/record/:idx", get(record::record_handler))
        .route("/api/idxs-for-pc", get(idxs_for_pc::idxs_for_pc_handler))
        .with_state(state)
}
```

- [ ] **Step 5: Run — should PASS**

```bash
cd rust && cargo test -p tracemiku-server --test idxs_for_pc_tests 2>&1 | tail -10 ; cd ..
```

Expected: `4 passed`.

- [ ] **Step 6: cargo fmt + clippy**

```bash
cd rust && cargo fmt --all && cargo clippy --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 7: Commit**

```bash
git add rust/crates/tracemiku-server/src/routes/ rust/crates/tracemiku-server/tests/idxs_for_pc_tests.rs
git commit -m "$(cat <<'EOF'
feat(server): GET /api/idxs-for-pc — record indices for a target PC

Wire shape exactly mirrors Python webui/server.py:838-861. Linear pc-scan
over Trace; ~50ms on 15M records (memory bandwidth bound). Hashed pc
index deferred to M2-δ if profiling demands.

before/after partition around cursor; before is descending (closest-to-
cursor first), both capped at limit, totals reported alongside with
*_capped booleans.

4 integration tests: duplicate split, no-match, limit-zero edge case,
default-cursor-zero (no cursor param).
EOF
)"
```

---

## Task 7: Populate /api/records.func / off / module via SymbolMap + ModuleResolver

**Files:**
- Modify: `rust/crates/tracemiku-server/src/routes/records.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/record.rs`
- Modify: `rust/crates/tracemiku-server/tests/records_endpoint.rs`

The M2-β handler emitted `func: None, off: None, module: <from meta>`. M2-γ replaces the symbol-dependent fields with real values: `func` from `state.symbols.lookup(pc)`, `off` from the same lookup's offset, `module` from `state.modules.resolve(pc)`. `annotation` and `exec_count` remain `None` until M2-δ (they need CFG).

The existing handler already reads `state.inner.meta.module` for `module`; we override that with `state.inner.modules.resolve(pc).map(|m| m.name)` so per-record cross-SO traces get correct names.

- [ ] **Step 1: Modify records.rs handler**

Open `rust/crates/tracemiku-server/src/routes/records.rs`. Find the `for i in q.start..end {` loop. Current body:

```rust
    let module_name: Option<&str> = inner.meta.module.as_ref().map(|m| m.name.as_str());

    let mut rows = Vec::with_capacity(end - q.start);
    for i in q.start..end {
        let r = inner.trace.record(i);
        let d = decode(r.pc, r.inst);
        let rel = base.map(|b| format!("{:#x}", r.pc.wrapping_sub(b)));
        let regs = regs_filter.as_ref().map(|fs| {
            let mut m = std::collections::BTreeMap::new();
            for nm in fs {
                if let Some(v) = r.reg(nm) {
                    m.insert(nm.clone(), format!("{v:#x}"));
                }
            }
            m
        });
        rows.push(RecordRow {
            idx: i,
            pc: format!("{:#x}", r.pc),
            rel,
            module: module_name.map(|s| s.to_string()),
            func: None,
            off: None,
            asm: format!("{} {}", d.mnemonic, d.op_str).trim().to_string(),
            annotation: None,
            exec_count: None,
            is_branch: d.is_branch,
            is_call: d.is_call,
            is_ret: d.is_ret,
            regs,
        });
    }
```

Replace the `module_name` line + the for-loop body with:

```rust
    let mut rows = Vec::with_capacity(end - q.start);
    for i in q.start..end {
        let r = inner.trace.record(i);
        let d = decode(r.pc, r.inst);
        let rel = base.map(|b| format!("{:#x}", r.pc.wrapping_sub(b)));
        let regs = regs_filter.as_ref().map(|fs| {
            let mut m = std::collections::BTreeMap::new();
            for nm in fs {
                if let Some(v) = r.reg(nm) {
                    m.insert(nm.clone(), format!("{v:#x}"));
                }
            }
            m
        });

        // Symbol resolution (M2-γ): per-record func + off + module.
        let module = inner.modules.resolve_name(r.pc);
        let (func_name, func_off) = inner.symbols.lookup(r.pc);
        let (func, off) = if func_name == "?" {
            (None, None)
        } else {
            (Some(func_name), Some(format!("{func_off:#x}")))
        };

        rows.push(RecordRow {
            idx: i,
            pc: format!("{:#x}", r.pc),
            rel,
            module,
            func,
            off,
            asm: format!("{} {}", d.mnemonic, d.op_str).trim().to_string(),
            annotation: None,
            exec_count: None,
            is_branch: d.is_branch,
            is_call: d.is_call,
            is_ret: d.is_ret,
            regs,
        });
    }
```

- [ ] **Step 2: Same enrichment for /api/record/{idx}**

Open `rust/crates/tracemiku-server/src/routes/record.rs`. Find the `Ok(Json(RecordDetail { ... }))` block. Replace the `func: None, off: None,` lines with the resolved values:

```rust
    // Symbol resolution (M2-γ).
    let (func_name, func_off) = inner.symbols.lookup(r.pc);
    let (func, off) = if func_name == "?" {
        (None, None)
    } else {
        (Some(func_name), Some(format!("{func_off:#x}")))
    };

    Ok(Json(RecordDetail {
        idx,
        pc: format!("{:#x}", r.pc),
        rel,
        func,
        off,
        asm: format!("{} {}", d.mnemonic, d.op_str).trim().to_string(),
        regs,
    }))
```

The exact placement: the `let (func_name, func_off)` and `let (func, off)` lines go ABOVE the `Ok(Json(RecordDetail {` block, then use the `func` / `off` variables in the struct literal.

- [ ] **Step 3: Add a test that verifies func/off populate**

The existing synth fixture in `rust/crates/tracemiku-server/tests/records_endpoint.rs` doesn't write `known_offsets` to per-call meta.json, so SymbolMap stays empty for that test. To verify func/off, we need a fixture WITH known_offsets. Append to that test file:

```rust
fn synth_call_dir_with_symbols() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp.path().join("run").join("calls").join("call_001_tid100_9r_2ms");
    fs::create_dir_all(&cd).unwrap();

    let pcs = [
        0x100000u64, 0x100004, 0x100100, 0x100104,
        0x100008, 0x100200, 0x100204, 0x100208, 0x10000c,
    ];
    let insts: [u32; 9] = [
        0xd503201f, 0x94000040, 0xd503201f, 0xd65f03c0,
        0x94000080, 0xd503201f, 0xd503201f, 0xd65f03c0, 0xd65f03c0,
    ];
    let mut buf = vec![0u8; 272 * 9];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    // Per-call meta.json with known_offsets keyed by hex offset within module.
    fs::write(cd.join("meta.json"),
              r#"{"records":9,"tid":100,"ms":2,"truncated":false,"known_offsets":{"0x0":"f_root","0x100":"f_alpha","0x200":"f_beta"}}"#).unwrap();
    fs::write(tmp.path().join("run").join("meta.json"),
              r#"{"pkg":"tst","so":"libt","method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#).unwrap();
    (tmp, cd)
}

#[tokio::test]
async fn records_with_symbols_populates_func_off() {
    let (_tmp, call_dir) = synth_call_dir_with_symbols();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder().uri("/api/records?count=9").body(Body::empty()).unwrap())
        .await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // idx 0 (pc=0x100000) → f_root + 0x0
    assert_eq!(v["records"][0]["func"], "f_root");
    assert_eq!(v["records"][0]["off"], "0x0");
    assert_eq!(v["records"][0]["module"], "libt.so");

    // idx 1 (pc=0x100004) → f_root + 0x4
    assert_eq!(v["records"][1]["func"], "f_root");
    assert_eq!(v["records"][1]["off"], "0x4");

    // idx 2 (pc=0x100100) → f_alpha + 0x0
    assert_eq!(v["records"][2]["func"], "f_alpha");
    assert_eq!(v["records"][2]["off"], "0x0");

    // idx 5 (pc=0x100200) → f_beta + 0x0
    assert_eq!(v["records"][5]["func"], "f_beta");
    assert_eq!(v["records"][5]["off"], "0x0");
}

#[tokio::test]
async fn record_detail_with_symbols_populates_func_off() {
    let (_tmp, call_dir) = synth_call_dir_with_symbols();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder().uri("/api/record/2").body(Body::empty()).unwrap())
        .await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["func"], "f_alpha");
    assert_eq!(v["off"], "0x0");
}
```

- [ ] **Step 4: Run tests**

```bash
cd rust && cargo test -p tracemiku-server 2>&1 | tail -15 ; cd ..
```

Expected: meta_endpoint = 3 + records_endpoint = 8 (6 from M2-β + 2 new) + idxs_for_pc = 4 = 15 server tests passing.

The existing `records_default_window` test asserts `r0["func"].is_null()`. With Task 7's enrichment, the synth fixture (no known_offsets) still resolves to `"?"` → null, so that test still passes. The NEW `records_with_symbols_populates_func_off` test uses a fixture WITH known_offsets, proving the enrichment works.

If `records_default_window` fails because module now resolves to "libt.so" (it already did via the M2-β code that read `state.inner.meta.module`), then nothing changed — the new code path resolves via ModuleResolver but produces the same name. Confirm with `--nocapture`.

- [ ] **Step 5: cargo fmt + clippy**

```bash
cd rust && cargo fmt --all && cargo clippy --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-server/src/routes/records.rs rust/crates/tracemiku-server/src/routes/record.rs rust/crates/tracemiku-server/tests/records_endpoint.rs
git commit -m "$(cat <<'EOF'
feat(server): /api/records + /api/record/{idx} populate func/off/module

Replaces M2-β placeholder nulls with real values:
- func / off via state.symbols.lookup(pc) → ('?', 0) → null mapping preserved
- module via state.modules.resolve(pc) → first module containing pc

annotation + exec_count remain null until M2-δ (need CFG.block.executions).

2 new integration tests use a fixture with per-call meta.json known_offsets;
verify f_root/f_alpha/f_beta resolve at the expected PCs.
EOF
)"
```

---

## Task 8: Smoke + parity script for M2-γ

**Files:**
- Create: `scripts/m2_gamma_parity.py`

Boots Python webui + Rust server, hits `/api/records?count=20` AND `/api/idxs-for-pc?pc=...&cursor=0` from each. Diffs the M2-γ-committed subset:

- `/api/records`: M2-β subset (idx, pc, rel, module, asm, is_branch/call/ret) + NEW `func`, `off`
- `/api/idxs-for-pc`: status, pc, cursor, before, after, total_before, total_after, before_capped, after_capped

- [ ] **Step 1: Write the script**

Create `scripts/m2_gamma_parity.py`:

```python
"""M2-γ parity differ — adds /api/records.func/off + /api/idxs-for-pc to M2-β.

Boots both webui (Python) and tracemiku-server (Rust) on free ports, hits:
  - /api/records?start=0&count=20
  - /api/idxs-for-pc?pc=<from records[0].pc>&cursor=10&limit=30

Compares the M2-γ-committed subset of /api/records (M2-β fields + func + off)
plus the full /api/idxs-for-pc shape. Symbol fields (func, off) MUST match
when both sides have the same known_offsets in per-call meta.json.

Usage:
    uv run python scripts/m2_gamma_parity.py <call_dir>
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

# /api/records fields M2-γ commits to.
RECORDS_FIELDS = {
    "idx", "pc", "rel", "module", "asm",
    "is_branch", "is_call", "is_ret",
    "func", "off",
}
# /api/idxs-for-pc full shape (all fields M2-γ commits to).
IDXS_FIELDS = {
    "status", "pc", "cursor",
    "before", "after",
    "total_before", "total_after",
    "before_capped", "after_capped",
}


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
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
    url = f"http://127.0.0.1:{port}{path}"
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read())


def normalize_record(row: dict) -> dict:
    out = {k: row.get(k) for k in RECORDS_FIELDS}
    # asm: trailing-space normalize (Python's f"{m} {op}" with empty op produces "nop ").
    if isinstance(out.get("asm"), str):
        out["asm"] = out["asm"].rstrip()
    return out


def normalize_idxs(d: dict) -> dict:
    return {k: d.get(k) for k in IDXS_FIELDS}


def diff_records(py: dict, rs: dict) -> list[str]:
    out = []
    for tk in ("start", "end", "count"):
        if py.get(tk) != rs.get(tk):
            out.append(f"  records top-level {tk}: py={py.get(tk)} rs={rs.get(tk)}")
    py_rows = py.get("records", [])
    rs_rows = rs.get("records", [])
    if len(py_rows) != len(rs_rows):
        out.append(f"  records length: py={len(py_rows)} rs={len(rs_rows)}")
        return out
    for i, (p, r) in enumerate(zip(py_rows, rs_rows)):
        np_, nr_ = normalize_record(p), normalize_record(r)
        if np_ != nr_:
            out.append(f"  records[{i}]:")
            for k in RECORDS_FIELDS:
                if np_.get(k) != nr_.get(k):
                    out.append(f"    {k}: py={np_.get(k)!r} rs={nr_.get(k)!r}")
    return out


def diff_idxs(py: dict, rs: dict) -> list[str]:
    out = []
    np_, nr_ = normalize_idxs(py), normalize_idxs(rs)
    for k in IDXS_FIELDS:
        if np_.get(k) != nr_.get(k):
            out.append(f"  idxs.{k}: py={np_.get(k)!r} rs={nr_.get(k)!r}")
    return out


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr); sys.exit(2)
    call_dir = Path(sys.argv[1]).resolve()
    if not call_dir.exists():
        print(f"call_dir not found: {call_dir}", file=sys.stderr); sys.exit(2)

    py_port = free_port()
    rs_port = free_port()
    print(f"# M2-γ parity: python={py_port} rust={rs_port} on {call_dir.name}",
          file=sys.stderr)

    py_proc = subprocess.Popen(
        ["./tracemiku", "web", str(call_dir),
         "--port", str(py_port), "--no-browser"],
        cwd=REPO_ROOT,
        preexec_fn=os.setsid,
        stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    )
    rs_proc = subprocess.Popen(
        ["./rust/target/release/tracemiku-server", str(call_dir),
         "--port", str(rs_port)],
        cwd=REPO_ROOT,
        preexec_fn=os.setsid,
        stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    )

    try:
        wait_listening(py_port)
        wait_listening(rs_port)

        py_records = fetch(py_port, "/api/records?start=0&count=20")
        rs_records = fetch(rs_port, "/api/records?start=0&count=20")
        records_diffs = diff_records(py_records, rs_records)

        # /api/idxs-for-pc: pick the first record's PC; cursor=10, limit=30.
        target_pc = py_records["records"][0]["pc"] if py_records["records"] else "0x0"
        py_idxs = fetch(py_port, f"/api/idxs-for-pc?pc={target_pc}&cursor=10&limit=30")
        rs_idxs = fetch(rs_port, f"/api/idxs-for-pc?pc={target_pc}&cursor=10&limit=30")
        idxs_diffs = diff_idxs(py_idxs, rs_idxs)

        all_diffs = []
        if records_diffs:
            all_diffs.append("/api/records mismatches:")
            all_diffs.extend(records_diffs)
        if idxs_diffs:
            all_diffs.append("/api/idxs-for-pc mismatches:")
            all_diffs.extend(idxs_diffs)

        if all_diffs:
            print("MISMATCH:", file=sys.stderr)
            for d in all_diffs:
                print(d, file=sys.stderr)
            sys.exit(1)
        n_rec = min(len(py_records.get("records", [])), 20)
        print(f"OK — {n_rec} records match on {','.join(sorted(RECORDS_FIELDS))}",
              file=sys.stderr)
        print(f"OK — /api/idxs-for-pc?pc={target_pc} matches on full shape",
              file=sys.stderr)
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

- [ ] **Step 2: Make executable + ensure release binary current + run on synth**

```bash
chmod +x scripts/m2_gamma_parity.py
cd rust && cargo build --release --bin tracemiku-server 2>&1 | tail -3 ; cd ..

uv run python scripts/m2_gamma_parity.py /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms 2>&1 | tail -5
```

Expected:
```
OK — 9 records match on asm,func,idx,is_branch,is_call,is_ret,module,off,pc,rel
OK — /api/idxs-for-pc?pc=0x100000 matches on full shape
```

If MISMATCH on `func` / `off`: most likely Python's SymbolMap has additional auto-discovered functions (via `auto_known_offsets` walking call instructions) that Rust doesn't have yet. The synth `build_smoke_trace.py` fixture writes `{"0x0":"f_root","0x100":"f_alpha","0x200":"f_beta"}` to per-call meta.json — both Python and Rust should pick these up identically. If Python adds extras, that's the auto_known_offsets divergence (deferred to M2-δ when we port that heuristic). Solution: relax the parity script's `RECORDS_FIELDS` to exclude `func`/`off` from the synth-trace assertion; or **better**: confirm the scope mismatch and add a known-offsets-only flag to `auto_known_offsets`.

Pragmatic for M2-γ: accept that synth has only 3 known fns and Python's auto_known_offsets adds a few more. **DO NOT relax the parity assertion** without first reading what Python's auto_known_offsets did differently. If unfixable, report BLOCKED with the exact diff and we decide whether to (a) port auto_known_offsets in this plan, (b) defer it to M2-δ and accept a temporary parity gap.

- [ ] **Step 3: Run on real trace**

```bash
uv run python scripts/m2_gamma_parity.py traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms 2>&1 | tail -5
```

Wall-clock: ~15-20s (includes Python's 7s build_from_trace + Rust's faster equivalent). Expected: `OK` on both.

If real-trace MISMATCH on `func` reveals Python's auto_known_offsets coverage is significantly larger than Rust's static-only known_offsets: this is M2-δ work. Document the gap in the commit message.

- [ ] **Step 4: Commit (only if OK on synth at minimum)**

```bash
git add scripts/m2_gamma_parity.py
git commit -m "$(cat <<'EOF'
test(m2): M2-γ parity differ — /api/records.func/off + /api/idxs-for-pc

Boots both Python webui and Rust tracemiku-server, fetches:
  - /api/records?start=0&count=20
  - /api/idxs-for-pc?pc=<records[0].pc>&cursor=10&limit=30

Compares M2-γ-committed subset of /api/records (M2-β fields + func + off)
plus full /api/idxs-for-pc shape (status, before/after partition, totals,
capped flags).

asm trailing-whitespace normalized (Python emits "nop " from
f"{m} {op}" with empty op_str).
EOF
)"
```

If MISMATCH on synth and you want to ship M2-γ anyway with a known parity gap, mark in the commit body which fields are deferred to M2-δ.

---

## Task 9: Update parity matrix + TODO.md

**Files:**
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`
- Modify: `TODO.md`

- [ ] **Step 1: Update §13.2 rows in spec**

Find these lines:

```
| `disasm.py` (capstone wrapper, decode, def/use) | `tracemiku-core::disasm` | 🟡 M2-β: decode + classify done; def/use M2-γ | capstone-rs 0.13; thread-local FIFO cache (200k); 11 unit tests + scripts/m2_beta_parity.py |
| `index.py` (def-use chains, mem ops) | `tracemiku-core::index` | 🔜 M2 | rayon-parallel build |
```

Replace with:

```
| `disasm.py` (capstone wrapper, decode, def/use) | `tracemiku-core::disasm` | ✅ M2-γ | capstone-rs 0.13 detail=true; thread-local FIFO cache (200k); regs_def/regs_use + cmp-style fix |
| `index.py` (def-use chains, mem ops) | `tracemiku-core::index` | 🟡 M2-γ: reg side done; mem ops M2-δ | sequential build; reg_defs/reg_uses HashMap<String, Vec<usize>>; rayon parallel deferred to M2-δ |
```

Find:

```
| `symbols.py` (SymbolMap, ModuleResolver, build_from_trace) | `tracemiku-core::symbols` | 🔜 M2 | |
```

Replace with:

```
| `symbols.py` (SymbolMap, ModuleResolver, build_from_trace) | `tracemiku-core::symbols` | 🟡 M2-γ: SymbolMap + ModuleResolver + build_from_trace done; auto_known_offsets M2-δ | sorted-Vec + binary-search |
```

Find:

```
| `symbols.py::auto_known_offsets` | `tracemiku-core::symbols` | 🔜 M2 | reads per-call meta.json `known_offsets` |
```

Leave it `🔜 M2-δ` (the row already says reads per-call meta — that's the static path, which IS done in M2-γ via build_from_trace; the "auto" heuristic that walks call instructions is the deferred piece. Update the status to reflect that):

```
| `symbols.py::auto_known_offsets` | `tracemiku-core::symbols` | 🔜 M2-δ | per-call meta.json known_offsets dict already consumed by build_from_trace (M2-γ); auto-discovery via bl-target heuristic deferred |
```

- [ ] **Step 2: Update §13.5 /api/idxs-for-pc row**

Find:

```
| `/api/idxs-for-pc` | 🔜 M3 | |
```

Replace with:

```
| `/api/idxs-for-pc` | ✅ M2-γ | linear pc-scan; ~50ms on 15M records; hashed pc index deferred to M2-δ if profiling demands |
```

- [ ] **Step 3: Update TODO.md M2 progress**

Find this line (added in M2-α/β):

```markdown
- M2-γ: MemShadow + taint + symbols + calltree
```

Replace with:

```markdown
- M2-γ `tracemiku-core::disasm.regs_def/regs_use` (capstone detail + cmp fix): ✅ 2026-05-04
- M2-γ `tracemiku-core::index::Index` (reg_defs/reg_uses sequential build): ✅ 2026-05-04
- M2-γ `tracemiku-core::symbols::{SymbolMap, ModuleResolver, build_from_trace}`: ✅ 2026-05-04
- M2-γ `/api/idxs-for-pc` + populated `/api/records.func/off/module`: ✅ 2026-05-04
- M2-δ (next): CFG (petgraph) + MemShadow + Index mem ops + taint + calltree + FunctionIndex + decompiler::backend stub + Functions/Graph panels
```

Note: this REPLACES the previous M2-γ placeholder with concrete bullets, AND replaces the M2-δ pre-statement with one that lists concrete remaining items.

- [ ] **Step 4: Final verification**

```bash
cd rust && cargo test --workspace 2>&1 | grep "test result:" | head -10 ; cd ..
cd frontend && npm run typecheck && npm run build 2>&1 | tail -5 ; cd ..
uv run python scripts/m2_alpha_parity.py /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms 2>&1 | tail -2
uv run python scripts/m2_beta_parity.py /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms 2>&1 | tail -2
uv run python scripts/m2_gamma_parity.py /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms 2>&1 | tail -3
```

Expected:
- cargo test: all pass (estimated ~55 tests)
- frontend builds clean
- m2_alpha parity: OK
- m2_beta parity: OK
- m2_gamma parity: OK

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md TODO.md
git commit -m "$(cat <<'EOF'
docs(v2): mark M2-γ complete in parity matrix + TODO.md

§13.2:
  - disasm.py def/use → ✅ M2-γ (was 🟡 M2-β)
  - index.py → 🟡 M2-γ (reg side done; mem ops M2-δ)
  - symbols.py → 🟡 M2-γ (SymbolMap + ModuleResolver + build_from_trace
    done; auto_known_offsets heuristic M2-δ)
§13.5:
  - /api/idxs-for-pc → ✅ M2-γ

TODO.md: M2-γ bullets concrete (4 items); M2-δ pointer updated to
include CFG, MemShadow, taint, calltree, FunctionIndex, decompiler stub,
plus Functions/Graph panels.

Three parity scripts (alpha/beta/gamma) all pass on synth trace; M2-γ
parity also exercised on real 4.2GB trace.

Next: M2-δ — final M2 milestone before M3 endpoints batch.
EOF
)"
```

---

## Task 10: Done — verify branch is shippable, hand off to next plan writer

**Files:** none new — pure verification gate.

This task is the M2-γ "done check": confirm everything tests cleanly, three parity scripts all pass, and the spec/TODO docs accurately reflect what's on disk. Don't add new code.

- [ ] **Step 1: Full test sweep**

```bash
cd rust && cargo test --workspace 2>&1 | tail -20 ; cd ..
cd rust && cargo test --workspace -- --ignored 2>&1 | tail -10 ; cd ..
cd frontend && npm run typecheck && npm run build 2>&1 | tail -5 ; cd ..
```

Expected: every cargo test green; ignored real-trace tests still passing; npm build clean.

- [ ] **Step 2: All three parity scripts on synth + real**

```bash
for s in m2_alpha m2_beta m2_gamma; do
    echo "=== $s synth ==="
    uv run python "scripts/${s}_parity.py" /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms 2>&1 | tail -3
done
echo "=== m2_alpha real ==="
uv run python scripts/m2_alpha_parity.py traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms 2>&1 | tail -2
echo "=== m2_beta real ==="
uv run python scripts/m2_beta_parity.py traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms 2>&1 | tail -2
echo "=== m2_gamma real ==="
uv run python scripts/m2_gamma_parity.py traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms 2>&1 | tail -2
```

Expected: every line ends with `OK`. Real-trace m2_gamma may take 30-60s due to Python webui boot + 7s build_from_trace.

If a parity script reports MISMATCH on real trace but OK on synth, document the gap in commit message and decide:
- accept gap as known M2-δ work (auto_known_offsets, CFG-derived enrichments)
- block M2-γ done until fixed

For known gaps, update the spec parity matrix row to reflect "🟡 with known gap on real trace" instead of "✅".

- [ ] **Step 3: Push the branch (do NOT push to main)**

If the user wants to share the work, push to the existing branch:

```bash
git push origin refactor/function-index-handoff
```

If the branch is not tracking origin, suggest: `git push -u origin refactor/function-index-handoff` — but ONLY ask the user before doing this; never auto-push.

- [ ] **Step 4: Mark M2-γ done, no commit needed**

This step has no code change — it's the handoff gate. The next plan (M2-δ) should be written by the controller in a fresh session if context is full, or inline if context is healthy.

---

## Self-Review

**1. Spec coverage:**

| Spec section | Covered by |
|---|---|
| §3 Architecture (capstone detail + def/use + AppState extension) | Tasks 1-2, 5 |
| §4 Data structures (Index, SymbolMap, ModuleResolver) | Tasks 3, 4 |
| §5 API surface (/api/idxs-for-pc, /api/records.func/off populated) | Tasks 6, 7 |
| §11 Decisions D-relevant (D5 capstone-rs detail mode; D8 sorted-Vec for symbols) | Tasks 1, 2, 4 |
| §13.2 disasm.py def/use, index.py, symbols.py | Task 9 |
| §13.5 /api/idxs-for-pc | Task 9 |
| §8 Testing (cargo + parity script) | Tasks 1-8, 10 |

Out-of-scope (deferred to M2-δ):
- Index mem_writes / mem_reads (need MemShadow + mem_op extraction)
- auto_known_offsets bl-target heuristic
- /api/last-write-of-reg / /api/last-write-of-addr endpoints (need Index.reg_defs binary search; trivial wrapper but added in M2-δ alongside the mem variants)
- /api/cfg / /api/cfg-svg (need CFG)
- Functions / Graph frontend panels (need /api/functions + /api/cfg)

**2. Placeholder scan:** No `TBD`, `TODO`, `implement later`, `similar to Task N`, `fill in details`. All code blocks complete. All test code present in full.

**3. Type consistency:**
- `DecodedInsn` adds `regs_def: Vec<String>` + `regs_use: Vec<String>` in Task 2; consumed by Task 3's Index::build (`for r in &d.regs_def`), no name drift.
- `Index` field names: `reg_defs`, `reg_uses` — consistent with Python's `viewer/index.py:22-23`.
- `SymbolMap::lookup(pc) -> (String, u64)` — `("?", 0)` sentinel matches Python.
- `ModuleResolver::resolve(pc) -> Option<ModuleInfo>` consistent across Tasks 4, 5, 7.
- `AppState.inner.{index, symbols, modules}` field names consistent across Tasks 5, 6, 7.
- `IdxsForPcResponse` shape exactly mirrors Python `webui/server.py:856-861` and `webui/schemas.py` IdxsForPcResponse.

**4. Atomic deliverable check:** Task 8's `m2_gamma_parity.py` printing OK on synth + real trace is the gate. Task 7 (populated `/api/records`) is the user-visible deliverable; without it, `func`/`off` stay null and the parity script trivially passes (both sides null) — so the test in Task 7 (`records_with_symbols_populates_func_off`) is the actual functional gate.

**5. Risk flag — capstone API uncertainty:** Task 2's `cs.regs_access(insn) -> Result<(Vec<RegId>, Vec<RegId>)>` API may differ in capstone-rs 0.13. The Step 3 implementation is conservative; if capstone exposes `insn.regs_access()` as a method on `Insn` instead of `cs.regs_access(insn)`, adapt. Worst case: drop to operand-walking via `arch_detail::ArchDetail::operands()` and reg-name lookup per operand. The is_compare_style fix is independent of this and can stay.

---

**Plan complete.** Per `CLAUDE.md` user preferences (default subagent + don't pause between milestones), execution proceeds immediately via subagent-driven-development.
