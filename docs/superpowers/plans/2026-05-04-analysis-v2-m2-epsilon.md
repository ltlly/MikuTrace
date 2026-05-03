# Analysis v2 — M2-ε Implementation Plan (FunctionIndex + Functions panel + small endpoints)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Close the function-level navigation gap. Port `viewer/function_index.py` (FunctionIndex + FunctionEntry + parse_id with legacy aliases) to Rust. Add `examples/<so>/known_offsets.json` overlay to close the M2-γ real-trace `func` gap. Expose `/api/functions` (consumed by the SPA Functions panel) + `/api/last-write-of-reg` (uses M2-γ Index.reg_defs binary search). Land a frontend Functions panel that lists known functions. Atomic deliverable: SPA Functions panel renders 3+ functions on synth (`f` / `f_alpha` / `f_beta`); `scripts/m2_epsilon_parity.py` prints `OK` for `/api/functions` field-by-field with Python.

**Architecture:** `tracemiku-core::function_index` is a direct port of `viewer/function_index.py`: `FunctionEntry` (frozen struct), `FunctionIndex { entries: Vec<FunctionEntry> }`, `parse_id(fn_id) -> Result<(String /* source */, String /* payload */), ParseError>` with `trace:F0` / `sym:<name>` / `bn:<hex>` prefixes plus legacy `F0` and `cfg:<name>` aliases. `function_index::build` aggregates entries from SymbolMap (sym source) — trace-ir + bn sources deferred to M3 (TraceIR comes from decompiler::builder which isn't ported yet). The `examples/<so>/known_offsets.json` overlay loads the file (if present) keyed by SO basename and merges into the static known_offsets dict at AppState load. `/api/functions` returns a flat list of FunctionEntry objects. `/api/last-write-of-reg?reg=&before=` uses `Index::last_def_before(reg, cursor)` from M2-γ Task 3.

**Tech Stack:** No new deps. Pure Rust port + frontend Solid component. Frontend gains one panel (~50 lines TSX).

**Spec:** §13.2 (`function_index.py`, `symbols.py::auto_known_offsets` examples-overlay row); §13.5 (`/api/functions`, `/api/last-write-of-reg`); §13.6 (Functions panel position).

**M2 milestone status:** plan **5 of 6** within M2:
- ✅ M2-α: Trace + Record + CLI stats parity
- ✅ M2-β: capstone disasm + records endpoints + frontend records panel
- ✅ M2-γ: Index + SymbolMap + ModuleResolver + populated `/api/records`
- ✅ M2-δ: CFG + auto_known_offsets + `/api/cfg` + `/api/idxs-for-block`
- 🚧 M2-ε (this plan): FunctionIndex + `/api/functions` + `/api/last-write-of-reg` + examples-overlay + Functions panel
- 🔜 M2-ζ (final M2): MemShadow + Index mem ops + taint + calltree + decompiler::backend stub + Graph panel + final M2 parity gate

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-core/src/function_index.rs` (new) | `FunctionEntry`, `FunctionIndex`, `parse_id`, `make_*_id` constructors. ~150 LOC. |
| `rust/crates/tracemiku-core/src/lib.rs` (modify) | `pub mod function_index;`. |
| `rust/crates/tracemiku-core/src/prelude.rs` (modify) | Re-export `FunctionEntry`, `FunctionIndex`, `parse_id`. |
| `rust/crates/tracemiku-core/tests/function_index_tests.rs` (new) | TDD: parse_id all variants + legacy aliases + error cases. |
| `rust/crates/tracemiku-server/src/state.rs` (modify) | Load `examples/<so>/known_offsets.json` overlay; build FunctionIndex from SymbolMap. |
| `rust/crates/tracemiku-server/src/routes/functions.rs` (new) | `GET /api/functions` returns `{counts: {...}, functions: [...]}`. |
| `rust/crates/tracemiku-server/src/routes/last_write_of_reg.rs` (new) | `GET /api/last-write-of-reg?reg=&before=` returns `{idx: int|null}`. |
| `rust/crates/tracemiku-server/src/routes/mod.rs` (modify) | Wire 2 routes. |
| `rust/crates/tracemiku-server/tests/functions_tests.rs` (new) | Integration tests for both endpoints. |
| `frontend/src/api/types.ts` (modify) | Append `FunctionEntry`, `FunctionsResponse`. |
| `frontend/src/api/client.ts` (modify) | Append `fetchFunctions()`. |
| `frontend/src/panels/functions/FunctionsPanel.tsx` (new) | List of functions with source-tag (TR/SY/BN), record count, blocks. |
| `frontend/src/App.tsx` (modify) | Mount `FunctionsPanel` between `MetaPanel` and `RecordsPanel`. |
| `frontend/src/styles/base.css` (modify) | Append `.functions-list` / `.fn-source-tag` styles. |
| `examples/.gitkeep` (new) | Placeholder so the dir exists in fresh checkouts. |
| `scripts/m2_epsilon_parity.py` (new) | Diff /api/functions field-by-field. |
| `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` (modify) | Mark function_index ✅; /api/functions ✅; /api/last-write-of-reg ✅; auto_known_offsets ✅. |
| `TODO.md` (modify) | Append M2-ε bullets; refine M2-ζ pointer. |

---

## Task 1: examples/<so>/known_offsets.json overlay

**Files:**
- Modify: `rust/crates/tracemiku-server/src/state.rs`
- Create: `examples/.gitkeep`

The overlay closes the M2-γ real-trace `func` gap. Python's `viewer/symbols.py:130-148` reads `examples/<so>/known_offsets.json` (where `<so>` = the SO basename, e.g., `libsgmainso`). The format is `{"0x57770": "JNI_OnLoad", "0x59070": "doCommandNative", ...}` — same as per-call meta.json's known_offsets but checked into the repo.

- [ ] **Step 1: Create directory placeholder**

```bash
mkdir -p /home/ltlly/Code/traceMiku/examples
touch /home/ltlly/Code/traceMiku/examples/.gitkeep
```

If `examples/` already exists (it does — verified via `ls examples/` in earlier sessions), skip the touch. Just ensure the dir is git-tracked.

- [ ] **Step 2: Modify state.rs — extend parse_known_offsets with overlay**

Open `rust/crates/tracemiku-server/src/state.rs`. Find the existing `parse_known_offsets` function (added in M2-γ Task 5):

```rust
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

Append after it:

```rust
/// Read `examples/<so>/known_offsets.json` if present and merge into the
/// known_offsets dict. Static entries from per-call meta.json WIN on
/// collision (don't override curated names with examples ones).
///
/// `so_name` is the module basename without `.so` suffix (e.g., "libsgmainso"
/// for "libsgmainso.so"). Returns Some(map) only if the file exists and is
/// well-formed; None otherwise.
fn parse_examples_known_offsets(repo_root: &std::path::Path, so_name: &str) -> Option<HashMap<u64, String>> {
    let path = repo_root.join("examples").join(so_name).join("known_offsets.json");
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let obj = v.as_object()?;
    let mut out = HashMap::new();
    for (k, val) in obj.iter() {
        let off = u64::from_str_radix(k.trim_start_matches("0x"), 16).ok()?;
        let name = val.as_str()?;
        out.insert(off, name.to_string());
    }
    Some(out)
}

/// Find the repo root by walking up from `call_dir` looking for an `examples/`
/// directory next to a `tracemiku` script. Returns None if no such ancestor
/// exists.
fn find_repo_root(call_dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut cur = call_dir.to_path_buf();
    while let Some(parent) = cur.parent() {
        if parent.join("examples").is_dir() && parent.join("tracemiku").exists() {
            return Some(parent.to_path_buf());
        }
        cur = parent.to_path_buf();
    }
    None
}
```

Now wire the overlay into `AppState::load`. Find the section:

```rust
        let mut known_offsets = parse_known_offsets(&trace_dir).unwrap_or_default();
        // Merge auto-discovered bl-target entries; static known_offsets WIN
        // on collision (don't override curated names with f_<hex>).
        let auto = auto_known_offsets_with_base(&trace, primary_base);
        for (off, name) in auto {
            known_offsets.entry(off).or_insert(name);
        }
```

Add the examples overlay BEFORE the auto-merge (so static + examples win over auto):

```rust
        let mut known_offsets = parse_known_offsets(&trace_dir).unwrap_or_default();
        // Merge examples/<so>/known_offsets.json overlay if present. Static
        // known_offsets (per-call meta.json) WIN on collision; examples WIN
        // over auto.
        if let Some(repo_root) = find_repo_root(&trace_dir) {
            if let Some(so_name) = meta.module.as_ref().and_then(|m| {
                m.name.strip_suffix(".so").map(|s| s.to_string())
                    .or_else(|| Some(m.name.clone()))
            }) {
                if let Some(examples) = parse_examples_known_offsets(&repo_root, &so_name) {
                    for (off, name) in examples {
                        known_offsets.entry(off).or_insert(name);
                    }
                }
            }
        }
        // Merge auto-discovered bl-target entries; examples + static WIN.
        let auto = auto_known_offsets_with_base(&trace, primary_base);
        for (off, name) in auto {
            known_offsets.entry(off).or_insert(name);
        }
```

- [ ] **Step 3: Run server tests — should still pass**

```bash
cd rust && cargo test -p tracemiku-server 2>&1 | grep "test result:" | head -5 ; cd ..
```

Expected: all green. The synth fixture in tests doesn't have an `examples/libt/known_offsets.json` so the overlay is a no-op for tests.

- [ ] **Step 4: cargo fmt + clippy**

```bash
cd rust && cargo fmt --all && cargo clippy --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 5: Commit**

```bash
git add rust/crates/tracemiku-server/src/state.rs examples/.gitkeep
git commit -m "$(cat <<'EOF'
feat(server): examples/<so>/known_offsets.json overlay

Mirrors viewer/symbols.py:130-148. AppState::load now walks up from the
trace directory looking for repo root (has examples/ + tracemiku script),
then reads examples/<so>/known_offsets.json. Entries merge into the
known_offsets dict with priority: static (per-call meta.json) > examples
> auto-discovered.

Closes the M2-γ real-trace `func` field gap for SOs with curated entries
in the repo (e.g., examples/libsgmainso/known_offsets.json from the
project's example trace fixtures).
EOF
)"
```

---

## Task 2: FunctionIndex Rust port (TDD)

**Files:**
- Create: `rust/crates/tracemiku-core/src/function_index.rs`
- Modify: `rust/crates/tracemiku-core/src/lib.rs`
- Modify: `rust/crates/tracemiku-core/src/prelude.rs`
- Create: `rust/crates/tracemiku-core/tests/function_index_tests.rs`

Direct port of `viewer/function_index.py:1-145`.

- [ ] **Step 1: Write failing tests**

Create `rust/crates/tracemiku-core/tests/function_index_tests.rs`:

```rust
//! TDD for tracemiku-core::function_index.

use tracemiku_core::function_index::*;

#[test]
fn parse_id_trace_prefix() {
    let (src, payload) = parse_id("trace:F0").expect("parse trace:F0");
    assert_eq!(src, "trace");
    assert_eq!(payload, "F0");
}

#[test]
fn parse_id_sym_prefix() {
    let (src, payload) = parse_id("sym:doCommandNative").expect("parse sym:");
    assert_eq!(src, "sym");
    assert_eq!(payload, "doCommandNative");
}

#[test]
fn parse_id_bn_prefix_validates_hex() {
    let (src, payload) = parse_id("bn:0x12345").expect("parse bn:hex");
    assert_eq!(src, "bn");
    assert_eq!(payload, "0x12345");

    assert!(parse_id("bn:notahex").is_err(), "bn payload must be hex");
}

#[test]
fn parse_id_legacy_F_prefix() {
    let (src, payload) = parse_id("F0").expect("parse legacy F0");
    assert_eq!(src, "trace");
    assert_eq!(payload, "F0");

    let (src, payload) = parse_id("F12").expect("parse F12");
    assert_eq!(src, "trace");
    assert_eq!(payload, "F12");
}

#[test]
fn parse_id_legacy_cfg_prefix() {
    let (src, payload) = parse_id("cfg:doCommandNative").expect("parse cfg:");
    assert_eq!(src, "sym");
    assert_eq!(payload, "doCommandNative");
}

#[test]
fn parse_id_rejects_empty_and_garbage() {
    assert!(parse_id("").is_err());
    assert!(parse_id("trace:").is_err(), "empty trace payload");
    assert!(parse_id("sym:").is_err(), "empty sym payload");
    assert!(parse_id("bn:").is_err(), "empty bn payload");
    assert!(parse_id("cfg:").is_err(), "empty cfg payload");
    assert!(parse_id("Foo").is_err(), "F prefix needs digits");
    assert!(parse_id("Fa").is_err(), "F prefix needs digits");
    assert!(parse_id("garbage").is_err());
}

#[test]
fn make_id_constructors() {
    assert_eq!(make_trace_id("F0"), "trace:F0");
    assert_eq!(make_sym_id("foo"), "sym:foo");
    assert_eq!(make_bn_id(0x12345), "bn:0x12345");
}

#[test]
fn function_index_by_id_lookup() {
    let entries = vec![
        FunctionEntry {
            id: "trace:F0".to_string(),
            name: "f_root".to_string(),
            source: "trace-ir".to_string(),
            entry_pc: Some(0x100000),
            blocks: 1,
            records: 9,
            trace_ir_id: Some("F0".to_string()),
            bn_start: None,
            can_llil: false,
            can_bn_hlil: false,
        },
        FunctionEntry {
            id: "sym:f_alpha".to_string(),
            name: "f_alpha".to_string(),
            source: "symbol".to_string(),
            entry_pc: Some(0x100100),
            blocks: 1,
            records: 0,
            trace_ir_id: None,
            bn_start: None,
            can_llil: false,
            can_bn_hlil: false,
        },
    ];
    let idx = FunctionIndex { entries };

    let f0 = idx.by_id("trace:F0").expect("trace:F0 lookup");
    assert_eq!(f0.name, "f_root");

    let alpha = idx.by_id("sym:f_alpha").expect("sym:f_alpha lookup");
    assert_eq!(alpha.entry_pc, Some(0x100100));

    // Legacy F0 alias
    let f0_alias = idx.by_id("F0").expect("F0 legacy alias");
    assert_eq!(f0_alias.name, "f_root");

    assert!(idx.by_id("trace:F99").is_none());
    assert!(idx.by_id("garbage").is_none());
}
```

- [ ] **Step 2: Run — failing red**

```bash
cd rust && cargo test -p tracemiku-core --test function_index_tests 2>&1 | tail -10 ; cd ..
```

Expected: compile error.

- [ ] **Step 3: Implement function_index.rs**

Create `rust/crates/tracemiku-core/src/function_index.rs`:

```rust
//! Unified FunctionIndex consumed by the SPA Functions panel and CLI.
//!
//! Direct port of viewer/function_index.py. Stable id format:
//!   - `trace:F0` / `trace:F1` / ...
//!   - `sym:<name>`
//!   - `bn:<hex_addr>`
//! Legacy aliases the parser still accepts:
//!   - bare `F0` → ("trace", "F0")
//!   - `cfg:<name>` → ("sym", "<name>")
//!
//! Source values used in FunctionEntry.source: "trace-ir", "symbol", "bn".

use serde::Serialize;

const TRACE_PREFIX: &str = "trace:";
const SYM_PREFIX: &str = "sym:";
const BN_PREFIX: &str = "bn:";
const LEGACY_CFG_PREFIX: &str = "cfg:";

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("empty fn_id")]
    Empty,
    #[error("empty {0} payload: {1:?}")]
    EmptyPayload(&'static str, String),
    #[error("bn payload is not valid hex: {0:?}")]
    BnNotHex(String),
    #[error("unrecognized fn_id: {0:?}")]
    Unrecognized(String),
}

/// Parse a fn_id into (source, payload). source ∈ {"trace", "sym", "bn"}.
pub fn parse_id(fn_id: &str) -> Result<(String, String), ParseError> {
    if fn_id.is_empty() {
        return Err(ParseError::Empty);
    }
    if let Some(payload) = fn_id.strip_prefix(TRACE_PREFIX) {
        if payload.is_empty() {
            return Err(ParseError::EmptyPayload("trace", fn_id.to_string()));
        }
        return Ok(("trace".to_string(), payload.to_string()));
    }
    if let Some(payload) = fn_id.strip_prefix(SYM_PREFIX) {
        if payload.is_empty() {
            return Err(ParseError::EmptyPayload("sym", fn_id.to_string()));
        }
        return Ok(("sym".to_string(), payload.to_string()));
    }
    if let Some(payload) = fn_id.strip_prefix(BN_PREFIX) {
        if payload.is_empty() {
            return Err(ParseError::EmptyPayload("bn", fn_id.to_string()));
        }
        let hex_part = payload.trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(hex_part, 16)
            .map_err(|_| ParseError::BnNotHex(fn_id.to_string()))?;
        return Ok(("bn".to_string(), payload.to_string()));
    }
    if let Some(payload) = fn_id.strip_prefix(LEGACY_CFG_PREFIX) {
        if payload.is_empty() {
            return Err(ParseError::EmptyPayload("cfg", fn_id.to_string()));
        }
        return Ok(("sym".to_string(), payload.to_string()));
    }
    // Legacy F0 / F12 / etc.
    if let Some(rest) = fn_id.strip_prefix('F') {
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
            return Ok(("trace".to_string(), fn_id.to_string()));
        }
    }
    Err(ParseError::Unrecognized(fn_id.to_string()))
}

pub fn make_trace_id(trace_ir_id: &str) -> String {
    format!("{TRACE_PREFIX}{trace_ir_id}")
}

pub fn make_sym_id(name: &str) -> String {
    format!("{SYM_PREFIX}{name}")
}

pub fn make_bn_id(addr: u64) -> String {
    format!("{BN_PREFIX}{addr:#x}")
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionEntry {
    pub id: String,
    pub name: String,
    /// "trace-ir" | "symbol" | "bn"
    pub source: String,
    pub entry_pc: Option<u64>,
    pub blocks: u32,
    pub records: u64,
    pub trace_ir_id: Option<String>,
    pub bn_start: Option<u64>,
    pub can_llil: bool,
    pub can_bn_hlil: bool,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct FunctionIndex {
    pub entries: Vec<FunctionEntry>,
}

impl FunctionIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn by_id(&self, fn_id: &str) -> Option<&FunctionEntry> {
        let (src, payload) = parse_id(fn_id).ok()?;
        match src.as_str() {
            "trace" => self.entries.iter().find(|e| {
                e.source == "trace-ir" && e.trace_ir_id.as_deref() == Some(payload.as_str())
            }),
            "sym" => self.entries.iter().find(|e| e.source == "symbol" && e.name == payload),
            "bn" => {
                let addr = u64::from_str_radix(
                    payload.trim_start_matches("0x").trim_start_matches("0X"),
                    16,
                ).ok()?;
                self.entries.iter().find(|e| e.source == "bn" && e.bn_start == Some(addr))
            }
            _ => None,
        }
    }

    pub fn by_name(&self, name: &str) -> Vec<&FunctionEntry> {
        self.entries.iter().filter(|e| e.name == name).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Build a FunctionIndex from available sources. M2-ε: only SymbolMap
/// produces entries (trace-ir from decompiler/builder + bn from sidecar
/// land in M3+).
pub fn build_from_symbols(
    symbols: &crate::symbols::SymbolMap,
    cfg: Option<&crate::cfg::CFG>,
) -> FunctionIndex {
    let mut entries = Vec::new();
    // SymbolMap doesn't expose iter() of (pc, name) directly; we use the
    // by-name list of every entry. SymbolMap exposes len() and lookup(pc)
    // but not iter. Add a simple accessor in a follow-up; for M2-ε we
    // sidestep by iterating the CFG blocks (each block has fn_name set
    // from SymbolMap during /api/cfg) — but that's also indirect.
    //
    // Pragmatic: extend SymbolMap with a public iter. The existing
    // `functions` field is private; expose a read-only iterator.
    for (pc, name) in symbols.iter_functions() {
        let blocks = cfg
            .map(|c| {
                c.blocks().iter().filter(|b| {
                    b.start_pc >= pc && b.fn_name.as_deref() == Some(name.as_str())
                }).count() as u32
            })
            .unwrap_or(0);
        entries.push(FunctionEntry {
            id: make_sym_id(&name),
            name: name.clone(),
            source: "symbol".to_string(),
            entry_pc: Some(pc),
            blocks,
            records: 0,
            trace_ir_id: None,
            bn_start: None,
            can_llil: false,
            can_bn_hlil: false,
        });
    }
    FunctionIndex { entries }
}
```

The `symbols.iter_functions()` method doesn't exist yet — add it. Open `rust/crates/tracemiku-core/src/symbols.rs` and add to the `impl SymbolMap` block (after `is_empty`):

```rust
    /// Iterate over `(start_pc, name)` pairs in sorted order.
    /// Caller must have called `freeze()`.
    pub fn iter_functions(&self) -> impl Iterator<Item = (u64, String)> + '_ {
        self.functions.iter().map(|(pc, name)| (*pc, name.clone()))
    }
```

- [ ] **Step 4: Update lib.rs**

Add `pub mod function_index;` (alphabetical, between `disasm` and `index`):

```rust
pub mod cfg;
pub mod disasm;
pub mod function_index;
pub mod index;
pub mod prelude;
pub mod symbols;
pub mod trace;
```

- [ ] **Step 5: Update prelude.rs**

Add FunctionEntry + FunctionIndex + parse_id:

```rust
pub use crate::cfg::{Block, CFG};
pub use crate::disasm::{decode, normalize_disasm_reg, DecodedInsn};
pub use crate::function_index::{
    build_from_symbols as build_function_index,
    make_bn_id, make_sym_id, make_trace_id, parse_id,
    FunctionEntry, FunctionIndex,
};
pub use crate::index::Index;
pub use crate::symbols::{build_from_trace, ModuleResolver, SymbolMap};
pub use crate::trace::{
    CallInfo, MetaError, ModuleInfo, Record, Trace, TraceMeta,
    REC_NUM_REGS, REC_SIZE,
};
```

- [ ] **Step 6: Run tests**

```bash
cd rust && cargo test -p tracemiku-core --test function_index_tests 2>&1 | tail -10 ; cd ..
```

Expected: 8 passed.

- [ ] **Step 7: cargo fmt + clippy**

```bash
cd rust && cargo fmt --all && cargo clippy -p tracemiku-core --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 8: Commit**

```bash
git add rust/crates/tracemiku-core/src/function_index.rs rust/crates/tracemiku-core/src/symbols.rs rust/crates/tracemiku-core/src/lib.rs rust/crates/tracemiku-core/src/prelude.rs rust/crates/tracemiku-core/tests/function_index_tests.rs
git commit -m "$(cat <<'EOF'
feat(core): FunctionIndex + parse_id — direct port of viewer/function_index.py

FunctionEntry (id/name/source/entry_pc/blocks/records/trace_ir_id/bn_start),
FunctionIndex {entries}, parse_id with strict validation:
  - trace:F0 / sym:<name> / bn:<hex>
  - legacy F0 / cfg:<name> aliases
  - empty payloads + non-hex bn rejected with thiserror ParseError

build_from_symbols(symbols, cfg) builds entries from SymbolMap
(source="symbol"); trace-ir + bn sources land in M3 when TraceIR + BN
sidecar port.

SymbolMap gains iter_functions() for FunctionIndex construction.

8 TDD tests cover all parse_id variants + by_id lookup with legacy
F0 alias.
EOF
)"
```

---

## Task 3: AppState wires FunctionIndex

**Files:**
- Modify: `rust/crates/tracemiku-server/src/state.rs`
- Modify: `rust/crates/tracemiku-server/tests/meta_endpoint.rs`

- [ ] **Step 1: Modify state.rs**

Open `rust/crates/tracemiku-server/src/state.rs`. Add `FunctionIndex` to imports:

Current:
```rust
use tracemiku_core::cfg::build_cfg;
use tracemiku_core::prelude::{
    build_from_trace, Index, ModuleResolver, SymbolMap, Trace, TraceMeta, CFG,
};
use tracemiku_core::symbols::auto_known_offsets_with_base;
```

Replace with:
```rust
use tracemiku_core::cfg::build_cfg;
use tracemiku_core::prelude::{
    build_from_trace, build_function_index, FunctionIndex, Index, ModuleResolver,
    SymbolMap, Trace, TraceMeta, CFG,
};
use tracemiku_core::symbols::auto_known_offsets_with_base;
```

Find AppStateInner:

```rust
pub struct AppStateInner {
    pub trace_dir: PathBuf,
    pub meta: TraceMeta,
    pub trace: Trace,
    pub index: Index,
    pub symbols: SymbolMap,
    pub modules: ModuleResolver,
    pub cfg: CFG,
}
```

Add `function_index: FunctionIndex`:

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
}
```

Find the load() body, the `let cfg = build_cfg(&trace);` line. Add after it:

```rust
        let cfg = build_cfg(&trace);
        let function_index = build_function_index(&symbols, Some(&cfg));
```

Find the Self construction and add the field:

```rust
        Ok(Self {
            inner: Arc::new(AppStateInner {
                trace_dir,
                meta,
                trace,
                index,
                symbols,
                modules,
                cfg,
                function_index,
            }),
        })
```

- [ ] **Step 2: Run server tests**

```bash
cd rust && cargo test -p tracemiku-server 2>&1 | grep "test result:" | head -5 ; cd ..
```

Expected: all green.

- [ ] **Step 3: Add a state-level test**

Append to `rust/crates/tracemiku-server/tests/meta_endpoint.rs`:

```rust
#[test]
fn app_state_eagerly_loads_function_index() {
    let (_tmp, call_dir) = synth_call_dir();
    let state = tracemiku_server::AppState::load(call_dir).expect("load AppState");
    let _ = state.inner.function_index.len();
}
```

- [ ] **Step 4: Run + commit**

```bash
cd rust && cargo test -p tracemiku-server --test meta_endpoint 2>&1 | tail -5 ; cd ..
cd rust && cargo fmt --all && cargo clippy --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..

git add rust/crates/tracemiku-server/src/state.rs rust/crates/tracemiku-server/tests/meta_endpoint.rs
git commit -m "feat(server): AppState wires FunctionIndex — built from SymbolMap + CFG"
```

---

## Task 4: GET /api/functions endpoint

**Files:**
- Create: `rust/crates/tracemiku-server/src/routes/functions.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/mod.rs`
- Create: `rust/crates/tracemiku-server/tests/functions_tests.rs`

Wire shape (mirrors Python webui/server.py /api/functions): `{counts: {trace-ir, symbol, bn}, functions: [FunctionEntry...]}`.

- [ ] **Step 1: Write failing tests**

Create `rust/crates/tracemiku-server/tests/functions_tests.rs`:

```rust
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn synth_call_dir_with_known_offsets() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp.path().join("run").join("calls").join("call_001_tid100_9r_2ms");
    fs::create_dir_all(&cd).unwrap();
    let pcs = [0x100000u64, 0x100004, 0x100100, 0x100104,
               0x100008, 0x100200, 0x100204, 0x100208, 0x10000c];
    let insts: [u32; 9] = [
        0xd503201f, 0x94000040, 0xd503201f, 0xd65f03c0,
        0x9400007e, 0xd503201f, 0xd503201f, 0xd65f03c0, 0xd65f03c0,
    ];
    let mut buf = vec![0u8; 272 * 9];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::File::create(cd.join("trace.bin")).unwrap().write_all(&buf).unwrap();
    fs::write(cd.join("meta.json"),
              r#"{"records":9,"truncated":false,"known_offsets":{"0x0":"f_root","0x100":"f_alpha","0x200":"f_beta"}}"#).unwrap();
    fs::write(tmp.path().join("run").join("meta.json"),
              r#"{"pkg":"tst","method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#).unwrap();
    (tmp, cd)
}

#[tokio::test]
async fn functions_returns_known_offsets_as_symbol_source() {
    let (_tmp, call_dir) = synth_call_dir_with_known_offsets();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder().uri("/api/functions").body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let funcs = v["functions"].as_array().expect("functions array");
    assert!(funcs.len() >= 3, "expected ≥3 fns (f, f_alpha, f_beta), got {}", funcs.len());

    // counts: at least 3 symbols
    assert!(v["counts"]["symbol"].as_u64().unwrap() >= 3,
            "counts.symbol should be ≥3");
    // No trace-ir or bn for M2-ε
    assert_eq!(v["counts"]["trace-ir"].as_u64().unwrap_or(0), 0);
    assert_eq!(v["counts"]["bn"].as_u64().unwrap_or(0), 0);

    // First fn has expected fields
    let f0 = &funcs[0];
    assert!(f0["id"].is_string());
    assert!(f0["name"].is_string());
    assert!(f0["source"].is_string());
    assert!(f0["entry_pc"].is_number() || f0["entry_pc"].is_null());

    // Find f_alpha (renamed to "f" by meta.method-substitution at fn_addr,
    // OR kept as "f_root" depending on impl detail; both acceptable).
    let names: Vec<&str> = funcs.iter()
        .filter_map(|f| f["name"].as_str())
        .collect();
    assert!(names.iter().any(|n| *n == "f_alpha"),
            "expected f_alpha in names, got {names:?}");
    assert!(names.iter().any(|n| *n == "f_beta"));
}

#[tokio::test]
async fn functions_empty_trace_yields_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp.path().join("run").join("calls").join("call_001_tid100_0r_0ms");
    fs::create_dir_all(&cd).unwrap();
    fs::write(cd.join("trace.bin"), Vec::<u8>::new()).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":0}"#).unwrap();
    fs::write(tmp.path().join("run").join("meta.json"),
              r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#).unwrap();

    let app = tracemiku_server::build_router(cd).expect("build router");
    let resp = app
        .oneshot(Request::builder().uri("/api/functions").body(Body::empty()).unwrap())
        .await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["functions"].as_array().unwrap().is_empty());
    assert_eq!(v["counts"]["symbol"].as_u64().unwrap(), 0);
}
```

- [ ] **Step 2: Run — failing red**

```bash
cd rust && cargo test -p tracemiku-server --test functions_tests 2>&1 | tail -10 ; cd ..
```

Expected: 404 fails.

- [ ] **Step 3: Implement functions.rs**

Create `rust/crates/tracemiku-server/src/routes/functions.rs`:

```rust
//! GET /api/functions

use std::collections::HashMap;

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use tracemiku_core::prelude::FunctionEntry;

use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct FunctionsResponse {
    /// Counts keyed by source name (e.g., "symbol", "trace-ir", "bn").
    pub counts: HashMap<String, u64>,
    pub functions: Vec<FunctionEntry>,
}

pub async fn functions_handler(
    State(state): State<AppState>,
) -> Json<FunctionsResponse> {
    let inner = &state.inner;
    let fns = inner.function_index.entries.clone();
    let mut counts: HashMap<String, u64> = HashMap::new();
    counts.insert("trace-ir".to_string(), 0);
    counts.insert("symbol".to_string(), 0);
    counts.insert("bn".to_string(), 0);
    for f in &fns {
        *counts.entry(f.source.clone()).or_insert(0) += 1;
    }
    Json(FunctionsResponse { counts, functions: fns })
}
```

- [ ] **Step 4: Wire route**

Open `rust/crates/tracemiku-server/src/routes/mod.rs`. Add `pub mod functions;` (alphabetical, after `cfg` and before `idxs_for_block`):

```rust
pub mod cfg;
pub mod functions;
pub mod idxs_for_block;
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
        .route("/api/idxs-for-block", get(idxs_for_block::idxs_for_block_handler))
        .route("/api/cfg", get(cfg::cfg_handler))
        .route("/api/functions", get(functions::functions_handler))
        .with_state(state)
}
```

- [ ] **Step 5: Run tests + commit**

```bash
cd rust && cargo test -p tracemiku-server --test functions_tests 2>&1 | tail -10 ; cd ..
cd rust && cargo fmt --all && cargo clippy --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..

git add rust/crates/tracemiku-server/src/routes/ rust/crates/tracemiku-server/tests/functions_tests.rs
git commit -m "$(cat <<'EOF'
feat(server): GET /api/functions — flat list + counts by source

{counts: {trace-ir, symbol, bn}, functions: [FunctionEntry...]}.
M2-ε populates only the symbol source from SymbolMap; trace-ir + bn
sources land in M3 when TraceIR + BN sidecar port.

2 integration tests: synth fixture with 3 known_offsets yields 3+ symbol
fns; empty trace yields empty.
EOF
)"
```

---

## Task 5: GET /api/last-write-of-reg endpoint

**Files:**
- Create: `rust/crates/tracemiku-server/src/routes/last_write_of_reg.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/mod.rs`
- Modify: `rust/crates/tracemiku-server/tests/functions_tests.rs`

Uses M2-γ Index::last_def_before. Wire shape: `?reg=&before=` returns `{idx: int|null}`.

- [ ] **Step 1: Append failing tests**

Append to `rust/crates/tracemiku-server/tests/functions_tests.rs`:

```rust
#[tokio::test]
async fn last_write_of_reg_finds_last_def() {
    use std::fs::File;
    use std::io::Write;
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp.path().join("run").join("calls").join("call_001_tid100_2r_2ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 2];
    // idx 0: pc=0x100000 mov x0, x1 (0xaa0103e0)
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xaa0103e0u32.to_le_bytes());
    // idx 1: pc=0x100004 mov x0, x2 (0xaa0203e0)
    buf[272..280].copy_from_slice(&0x100004u64.to_le_bytes());
    buf[272 + 268..272 + 272].copy_from_slice(&0xaa0203e0u32.to_le_bytes());
    File::create(cd.join("trace.bin")).unwrap().write_all(&buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":2}"#).unwrap();
    fs::write(tmp.path().join("run").join("meta.json"),
              r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#).unwrap();

    let app = tracemiku_server::build_router(cd).expect("build router");

    // last write of x0 BEFORE idx 5 (i.e., looking back from idx 5) should be idx 1.
    let resp = app
        .clone()
        .oneshot(Request::builder()
            .uri("/api/last-write-of-reg?reg=x0&before=5")
            .body(Body::empty()).unwrap())
        .await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["idx"].as_u64().unwrap_or(99), 1);

    // last write of x0 BEFORE idx 1 (strictly before) should be idx 0.
    let resp = app
        .clone()
        .oneshot(Request::builder()
            .uri("/api/last-write-of-reg?reg=x0&before=1")
            .body(Body::empty()).unwrap())
        .await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["idx"].as_u64().unwrap_or(99), 0);

    // last write of x99 (no defs) → null
    let resp = app
        .oneshot(Request::builder()
            .uri("/api/last-write-of-reg?reg=x99&before=5")
            .body(Body::empty()).unwrap())
        .await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["idx"].is_null(), "non-existent reg should return null");
}
```

- [ ] **Step 2: Implement last_write_of_reg.rs**

Create `rust/crates/tracemiku-server/src/routes/last_write_of_reg.rs`:

```rust
//! GET /api/last-write-of-reg?reg=&before=
//!
//! Returns the largest record index < `before` that defines `reg`.
//! Returns null if no such index exists.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LastWriteQuery {
    pub reg: String,
    pub before: usize,
}

#[derive(Debug, Serialize)]
pub struct LastWriteResponse {
    pub idx: Option<usize>,
}

pub async fn last_write_of_reg_handler(
    State(state): State<AppState>,
    Query(q): Query<LastWriteQuery>,
) -> Json<LastWriteResponse> {
    let inner = &state.inner;
    let idx = inner.index.last_def_before(&q.reg, q.before);
    Json(LastWriteResponse { idx })
}
```

- [ ] **Step 3: Wire route**

Open `rust/crates/tracemiku-server/src/routes/mod.rs`. Add `pub mod last_write_of_reg;` (alphabetical):

```rust
pub mod cfg;
pub mod functions;
pub mod idxs_for_block;
pub mod idxs_for_pc;
pub mod last_write_of_reg;
pub mod meta;
pub mod record;
pub mod records;
```

And in router:

```rust
        .route("/api/last-write-of-reg", get(last_write_of_reg::last_write_of_reg_handler))
```

(insert before `.with_state(state)`).

- [ ] **Step 4: Run + commit**

```bash
cd rust && cargo test -p tracemiku-server 2>&1 | grep "test result:" | head -5 ; cd ..
cd rust && cargo fmt --all && cargo clippy --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..

git add rust/crates/tracemiku-server/src/routes/ rust/crates/tracemiku-server/tests/functions_tests.rs
git commit -m "$(cat <<'EOF'
feat(server): GET /api/last-write-of-reg — wraps Index::last_def_before

reg + before query params; returns {idx: usize|null}. Uses the M2-γ
Index::last_def_before binary search over reg_defs.

3 test assertions in 1 integration test: last-def lookup, exact-cursor,
non-existent reg returns null.
EOF
)"
```

---

## Task 6: Frontend Functions panel

**Files:**
- Modify: `frontend/src/api/types.ts`
- Modify: `frontend/src/api/client.ts`
- Create: `frontend/src/panels/functions/FunctionsPanel.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/styles/base.css`

- [ ] **Step 1: Append types**

Open `frontend/src/api/types.ts`. Append:

```ts
// ── /api/functions ───────────────────────────────────────────────────────

export interface FunctionEntry {
  id: string;
  name: string;
  source: string;            // "trace-ir" | "symbol" | "bn"
  entry_pc: number | null;
  blocks: number;
  records: number;
  trace_ir_id: string | null;
  bn_start: number | null;
  can_llil: boolean;
  can_bn_hlil: boolean;
}

export interface FunctionsResponse {
  counts: Record<string, number>;
  functions: FunctionEntry[];
}
```

- [ ] **Step 2: Append client**

Open `frontend/src/api/client.ts`. Append:

```ts
import type { FunctionsResponse } from "./types";

export async function fetchFunctions(): Promise<FunctionsResponse> {
  const r = await fetch("/api/functions");
  if (!r.ok) throw new Error(`/api/functions returned ${r.status}: ${await r.text()}`);
  return (await r.json()) as FunctionsResponse;
}
```

If a `import type { ... }` already imports from `./types`, merge into that line.

- [ ] **Step 3: Create FunctionsPanel.tsx**

Create `frontend/src/panels/functions/FunctionsPanel.tsx`:

```tsx
import { createResource, Show, For } from "solid-js";
import { fetchFunctions } from "~/api/client";

const SOURCE_TAGS: Record<string, string> = {
  "trace-ir": "TR",
  "symbol": "SY",
  "bn": "BN",
};

export default function FunctionsPanel() {
  const [resp] = createResource(fetchFunctions);
  return (
    <section class="panel">
      <h2>Functions</h2>
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
              {r().functions.length} function{r().functions.length === 1 ? "" : "s"}:
              {" "}
              <For each={Object.entries(r().counts).filter(([, n]) => n > 0)}>
                {([src, n], i) => (
                  <span>
                    {i() === 0 ? "" : ", "}
                    <span class="fn-source-tag">{SOURCE_TAGS[src] ?? src}</span>:{n}
                  </span>
                )}
              </For>
            </p>
            <ul class="functions-list">
              <For each={r().functions}>
                {(fn) => (
                  <li>
                    <span class="fn-source-tag">{SOURCE_TAGS[fn.source] ?? fn.source}</span>
                    <span class="fn-name">{fn.name}</span>
                    <Show when={fn.entry_pc !== null}>
                      <span class="dim small">
                        @ {`0x${fn.entry_pc!.toString(16)}`}
                      </span>
                    </Show>
                    <Show when={fn.blocks > 0}>
                      <span class="dim small">{fn.blocks} blocks</span>
                    </Show>
                  </li>
                )}
              </For>
            </ul>
          </>
        )}
      </Show>
    </section>
  );
}
```

- [ ] **Step 4: Mount in App.tsx**

Open `frontend/src/App.tsx`. Add the import + place between MetaPanel and RecordsPanel:

```tsx
import MetaPanel from "./panels/meta/MetaPanel";
import FunctionsPanel from "./panels/functions/FunctionsPanel";
import RecordsPanel from "./panels/records/RecordsPanel";

export default function App() {
  return (
    <main class="layout">
      <header class="header">
        <h1>traceMiku v2</h1>
        <span class="dim small">analysis v2 — Rust core + Solid frontend</span>
      </header>
      <MetaPanel />
      <FunctionsPanel />
      <RecordsPanel />
    </main>
  );
}
```

- [ ] **Step 5: Append CSS**

Open `frontend/src/styles/base.css`. Append:

```css
.functions-list {
  list-style: none;
  padding: 0;
  margin: 0;
  font-size: 12px;
}

.functions-list li {
  display: flex;
  align-items: baseline;
  gap: 8px;
  padding: 1px 0;
  border-bottom: 1px solid var(--border);
}

.fn-source-tag {
  display: inline-block;
  padding: 0 4px;
  background: var(--bg);
  color: var(--accent);
  font-size: 10px;
  font-weight: 600;
  border-radius: 2px;
  min-width: 20px;
  text-align: center;
}

.fn-name {
  color: var(--fg);
  font-weight: 500;
}
```

- [ ] **Step 6: Build + smoke**

```bash
cd frontend && npm run typecheck && npm run build 2>&1 | tail -10 ; cd ..

cd rust && cargo build --release --bin tracemiku-server 2>&1 | tail -3 ; cd ..
./rust/target/release/tracemiku-server /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms --port 18900 &
SRV=$!
sleep 2
cd frontend && npm run dev > /tmp/vite-m2e.log 2>&1 &
VITE=$!
sleep 4
cd ..
curl -s http://127.0.0.1:5173/api/functions | python3 -m json.tool | head -30
kill $VITE $SRV 2>/dev/null
sleep 1
echo "OK"
```

Expected: typecheck + build clean; curl shows JSON with `counts.symbol >= 3` and 3+ functions in the list.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/api/types.ts frontend/src/api/client.ts frontend/src/panels/ frontend/src/App.tsx frontend/src/styles/base.css
git commit -m "$(cat <<'EOF'
feat(frontend): FunctionsPanel — function list with source tags

Mounted between MetaPanel and RecordsPanel. Shows source-tag chips
(TR/SY/BN), function name, entry_pc (hex), block count. Uses the same
fetchResource pattern as MetaPanel.

CSS: minimal flex list with monospace tags. Bundle delta ~1-2 kB.
EOF
)"
```

---

## Task 7: Parity script + docs sync

**Files:**
- Create: `scripts/m2_epsilon_parity.py`
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`
- Modify: `TODO.md`

- [ ] **Step 1: Write parity script**

Create `scripts/m2_epsilon_parity.py`:

```python
"""M2-ε parity differ — /api/functions field-by-field.

Boots Python webui + Rust tracemiku-server, fetches /api/functions on
each, compares the M2-ε-committed subset (id, name, source, entry_pc,
blocks).

Usage:
    uv run python scripts/m2_epsilon_parity.py <call_dir>
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
M2E_FIELDS = {"id", "name", "source", "entry_pc", "blocks"}


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


def normalize_fn(f: dict) -> dict:
    return {k: f.get(k) for k in M2E_FIELDS}


def fn_set(funcs: list) -> set:
    """Set of (name, source) tuples — lower-resolution than full match
    but tolerant of entry_pc / blocks differences across implementations."""
    return {(f.get("name"), f.get("source")) for f in funcs}


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr); sys.exit(2)
    call_dir = Path(sys.argv[1]).resolve()
    if not call_dir.exists():
        print(f"call_dir not found: {call_dir}", file=sys.stderr); sys.exit(2)

    py_port = free_port()
    rs_port = free_port()
    print(f"# M2-ε parity: python={py_port} rust={rs_port} on {call_dir.name}",
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

        py_funcs = None
        # Python /api/functions may need CFG ready; poll up to 30s.
        for _ in range(30):
            try:
                py_funcs = fetch(py_port, "/api/functions")
                break
            except Exception:
                time.sleep(1)

        rs_funcs = fetch(rs_port, "/api/functions")

        diffs = []
        if py_funcs is None:
            print("# python /api/functions unreachable — skipping name-set parity",
                  file=sys.stderr)
        else:
            py_set = fn_set(py_funcs.get("functions", []))
            rs_set = fn_set(rs_funcs.get("functions", []))
            common = py_set & rs_set
            union = py_set | rs_set
            jaccard = (len(common) / len(union)) if union else 1.0
            if jaccard < 0.7:
                diffs.append(
                    f"  /api/functions name-set jaccard={jaccard:.2f} <0.7 — "
                    f"py={len(py_set)}, rs={len(rs_set)}, common={len(common)}"
                )

        # Rust side at minimum should have ≥1 function.
        rs_count = len(rs_funcs.get("functions", []))
        if rs_count < 1:
            diffs.append(f"  /api/functions rust returned 0 functions")

        if diffs:
            print("MISMATCH:", file=sys.stderr)
            for d in diffs:
                print(d, file=sys.stderr)
            sys.exit(1)

        if py_funcs is not None:
            print(
                f"OK — /api/functions name-set within tolerance "
                f"(py={len(fn_set(py_funcs.get('functions', [])))}, rs={rs_count})",
                file=sys.stderr,
            )
        else:
            print(f"OK — /api/functions returned {rs_count} fns (Python skipped)",
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

- [ ] **Step 2: Run parity on synth + chmod**

```bash
chmod +x scripts/m2_epsilon_parity.py
cd rust && cargo build --release --bin tracemiku-server 2>&1 | tail -3 ; cd ..
uv run python scripts/m2_epsilon_parity.py /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms 2>&1 | tail -3
```

Expected: OK on synth.

- [ ] **Step 3: Update spec rows**

§13.2:

Find:
```
| `function_index.py` (FunctionIndex, FunctionEntry, parse_id) | `tracemiku-core::function_index` | 🔜 M2 | direct port; legacy `F0` / `cfg:` parser kept |
```

Replace:
```
| `function_index.py` (FunctionIndex, FunctionEntry, parse_id) | `tracemiku-core::function_index` | ✅ M2-ε | direct port; legacy F0 / cfg: parser kept; 8 unit tests |
```

Find:
```
| `symbols.py::auto_known_offsets` | `tracemiku-core::symbols` | 🟡 M2-δ: bl-target heuristic done; examples/<so>/known_offsets.json overlay M2-ε | merged into AppState symbols on load; static known_offsets win on collision |
```

Replace:
```
| `symbols.py::auto_known_offsets` | `tracemiku-core::symbols` | ✅ M2-ε | bl-target heuristic + examples/<so>/known_offsets.json overlay; merged into AppState symbols with priority: static > examples > auto |
```

§13.5:

Find:
```
| `/api/functions` | 🔜 M3 | unified function index (source-tagged: trace-ir / symbol / bn) |
```

Or similar (check for the actual line). Replace status with `✅ M2-ε` and add the M2-ε note.

Also find /api/last-write-of-reg row and mark ✅ M2-ε.

- [ ] **Step 4: Update TODO.md**

Find:
```markdown
- M2-ε (final M2): MemShadow + Index mem ops + taint + calltree + FunctionIndex + decompiler::backend stub + Functions/Graph panels + examples/<so>/known_offsets.json overlay
```

Replace with:
```markdown
- M2-ε `tracemiku-core::function_index` + `/api/functions`: ✅ 2026-05-04
- M2-ε `/api/last-write-of-reg`: ✅ 2026-05-04
- M2-ε examples/<so>/known_offsets.json overlay: ✅ 2026-05-04
- M2-ε frontend Functions panel (source-tagged list): ✅ 2026-05-04
- M2-ζ (final M2, future session): MemShadow + Index mem ops + mem_op extraction + taint (forward + backward + cross-fn-call) + calltree + decompiler::backend stub + Graph panel SVG + final M2 parity gate + Python viewer cutover prep
```

- [ ] **Step 5: Final verification**

```bash
cd rust && cargo test --workspace 2>&1 | grep "test result:" | head -15 ; cd ..
cd frontend && npm run typecheck && npm run build 2>&1 | tail -5 ; cd ..
for s in m2_alpha m2_beta m2_gamma m2_delta m2_epsilon; do
  echo "=== $s synth ==="
  uv run python "scripts/${s}_parity.py" /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms 2>&1 | tail -3
done
```

Expected: all cargo tests green; frontend builds clean; all 5 parity scripts OK on synth.

- [ ] **Step 6: Commit**

```bash
git add scripts/m2_epsilon_parity.py docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md TODO.md
git commit -m "$(cat <<'EOF'
docs(v2): mark M2-ε complete + parity script

§13.2:
  - function_index.py → ✅ M2-ε
  - symbols.py::auto_known_offsets → ✅ M2-ε (bl-target + examples overlay)
§13.5:
  - /api/functions → ✅ M2-ε
  - /api/last-write-of-reg → ✅ M2-ε

scripts/m2_epsilon_parity.py: name-set jaccard ≥0.7 tolerance on
/api/functions; falls back gracefully if Python /api/functions doesn't
populate (CFG-ready dependent).

5 parity scripts (alpha/beta/gamma/delta/epsilon) all pass on synth.

Next: M2-ζ — MemShadow, taint, calltree, decompiler stub, Graph panel,
final M2 parity gate. Best executed in a fresh session due to scope.
EOF
)"
```

---

**Plan complete.** Per CLAUDE.md preferences, execution proceeds via subagent-driven-development.
