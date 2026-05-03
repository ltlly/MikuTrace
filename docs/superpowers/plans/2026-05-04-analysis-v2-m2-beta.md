# Analysis v2 — M2-β Implementation Plan (Disasm + /api/records + frontend)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lift the Trace mmap from M2-α to a decoded record stream — port `viewer/disasm.py` to Rust (capstone-rs + thread-local FIFO cache), add the first trace-content endpoints (`/api/records`, `/api/record/{idx}`), and ship a Solid frontend `RecordsPanel` that scrolls through the decoded trace. Atomic deliverable: open the SPA, see Records panel render the synth trace's 9 instructions with `nop / bl 0x100100 / nop / ret / ...` mnemonics — **and** `scripts/m2_beta_parity.py` prints `OK` confirming Rust `/api/records` JSON matches Python `/api/records` field-by-field on subset (idx, pc, asm, is_branch, is_call, is_ret, rel, module).

**Architecture:** New `tracemiku-core::disasm` module wraps `capstone` 0.13 with a thread-local LRU-ish cache (200k entries via `LinkedHashMap`-style FIFO eviction; matches Python's `lru_cache(maxsize=200000)`). `DecodedInsn { pc, inst, mnemonic, op_str, is_branch, is_call, is_ret }` is the public surface for M2-β — register def/use, branch_target, mem_op all deferred to M2-γ. Server adds `/api/records?start=&count=&regs=` mirroring Python's wire shape with symbol-dependent fields (`func`, `off`, `annotation`, `exec_count`) emitted as `null` for now (populated when M2-γ lands SymbolMap + CFG). Frontend `RecordsPanel` shows `idx | pc | asm` columns with prev/next pagination buttons.

**Tech Stack:** capstone 0.13 (capstone-rs), no other new Rust deps (`HashMap` from std for the FIFO cache; plain `parking_lot`-free thread-local). Frontend stays Vite/Solid/TS — no new npm deps.

**Spec:** `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` §13.2 (disasm.py row), §13.5 (/api/records, /api/record/{idx} rows), §13.6 (Records-tab equivalent — "Trace for PC" panel will subsume this in M4). Wire contract for `RecordRow` matches Python `webui/schemas.py:37-50` (`RecordRow`) and Python `webui/server.py:265-308` (`/api/records` handler). Symbol-dependent fields are defined as `null` here; their non-null behavior is locked in M2-γ.

**M2 milestone status:** M2-β is plan **2 of 4** within M2:
- ✅ M2-α: Trace + Record + CLI stats parity (commits e6bd9fc..b47c114)
- 🚧 M2-β (this plan): capstone disasm + records endpoints + frontend records panel
- 🔜 M2-γ: Index (def-use) + CFG (petgraph) + SymbolMap + /api/cfg + /api/idxs-for-pc + Graph panel
- 🔜 M2-δ: MemShadow + taint + calltree + FunctionIndex + decompiler::backend stub + final M2 parity

---

## File Structure

| File | Role |
|---|---|
| `rust/Cargo.toml` (modify) | Add `capstone = "0.13"` to `[workspace.dependencies]`. |
| `rust/crates/tracemiku-core/Cargo.toml` (modify) | Add `capstone.workspace = true` to `[dependencies]`. |
| `rust/crates/tracemiku-core/src/lib.rs` (modify) | Add `pub mod disasm;` (currently has `pub mod prelude; pub mod trace;`). |
| `rust/crates/tracemiku-core/src/disasm/mod.rs` (new) | Module root: declares `decoder`, `cache`, `classify`; re-exports `DecodedInsn` + `decode`. |
| `rust/crates/tracemiku-core/src/disasm/decoder.rs` (new) | `DecodedInsn` struct, thread-local `Capstone` handle, `raw_decode(pc, inst) -> DecodedInsn` (no caching). |
| `rust/crates/tracemiku-core/src/disasm/cache.rs` (new) | Thread-local FIFO cache (200k entries) wrapping `raw_decode`. Public `decode(pc, inst) -> DecodedInsn` is the cached entry point. |
| `rust/crates/tracemiku-core/src/disasm/classify.rs` (new) | `is_branch`, `is_call`, `is_ret` mnemonic classifiers (pure functions). |
| `rust/crates/tracemiku-core/src/prelude.rs` (modify) | Add `pub use crate::disasm::{DecodedInsn, decode};` to existing re-exports. |
| `rust/crates/tracemiku-core/tests/disasm_decode.rs` (new) | TDD tests: NOP / B / BL / RET / CMP-style / unknown-bytes happy paths. |
| `rust/crates/tracemiku-core/tests/disasm_real.rs` (new) | `#[ignore]` real-trace test: decode every distinct PC in first 1M records, time it, assert cache hit-rate >50%. |
| `rust/crates/tracemiku-server/src/routes/records.rs` (new) | `GET /api/records?start=&count=&regs=` handler. |
| `rust/crates/tracemiku-server/src/routes/record.rs` (new) | `GET /api/record/{idx}` handler. |
| `rust/crates/tracemiku-server/src/routes/mod.rs` (modify) | Wire `/api/records` and `/api/record/:idx` into the router. |
| `rust/crates/tracemiku-server/tests/records_endpoint.rs` (new) | Integration tests: empty start, full window, regs filter, single-record detail. |
| `frontend/src/api/types.ts` (modify) | Append `RecordRow`, `RecordsResponse`, `RecordDetail` interfaces. |
| `frontend/src/api/client.ts` (modify) | Append `fetchRecords({start, count, regs})` and `fetchRecord(idx)`. |
| `frontend/src/panels/records/RecordsPanel.tsx` (new) | Solid component: table of (idx, pc, asm), prev/next pagination over 50-record windows. |
| `frontend/src/App.tsx` (modify) | Mount `RecordsPanel` below `MetaPanel`. |
| `frontend/src/styles/base.css` (modify) | Append `.records-table`, `.records-pagination` styles. |
| `scripts/m2_beta_parity.py` (new) | Boot Python webui server (port A) + Rust server (port B), curl `/api/records?start=0&count=20` from each, diff JSON subset (idx, pc, asm, is_branch, is_call, is_ret, rel, module). |
| `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` (modify) | §13.2 `disasm.py` row → ✅ M2-β. §13.5 `/api/records` and `/api/record/{idx}` rows → ✅ M2-β. |
| `TODO.md` (modify) | Append M2-β completion bullets to existing `🚧 进行中` section. |

---

## Task 1: Add capstone dep + DecodedInsn skeleton

**Files:**
- Modify: `rust/Cargo.toml` (workspace `[workspace.dependencies]` block)
- Modify: `rust/crates/tracemiku-core/Cargo.toml`
- Create: `rust/crates/tracemiku-core/src/disasm/mod.rs`
- Create: `rust/crates/tracemiku-core/src/disasm/decoder.rs`
- Modify: `rust/crates/tracemiku-core/src/lib.rs`

The capstone crate (`capstone` 0.13 on crates.io as of 2026-05) wraps the C library. We'll declare it at workspace level for future crates (cli's `disasm` subcommand in M3 will share it).

- [ ] **Step 1: Add capstone to the workspace deps**

Open `rust/Cargo.toml`. Find the `[workspace.dependencies]` block. After the `bytemuck = ...` line, append:

```toml
capstone = "0.13"
```

Final block tail should look like:

```toml
memmap2 = "0.9"
bytemuck = { version = "1", features = ["derive"] }
capstone = "0.13"
# Internal
tracemiku-core = { path = "crates/tracemiku-core" }
```

- [ ] **Step 2: Pull capstone into tracemiku-core**

Open `rust/crates/tracemiku-core/Cargo.toml`. Append to `[dependencies]`:

```toml
capstone.workspace = true
```

Final `[dependencies]` block:

```toml
[dependencies]
anyhow.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tracing.workspace = true
memmap2.workspace = true
bytemuck.workspace = true
capstone.workspace = true
```

- [ ] **Step 3: Create disasm module skeleton**

Create `rust/crates/tracemiku-core/src/disasm/decoder.rs`:

```rust
//! capstone-rs wrapper. M2-β provides decode() returning DecodedInsn with
//! mnemonic + op_str + branch/call/ret classification. Register def/use,
//! branch_target, mem_op come in M2-γ when Index needs them.

use serde::Serialize;

/// Decoded ARM64 instruction. Wire-compatible with Python `viewer.disasm.Decoded`
/// for the fields M2-β consumes; remaining fields filled in M2-γ.
#[derive(Debug, Clone, Serialize)]
pub struct DecodedInsn {
    pub pc: u64,
    pub inst: u32,
    pub mnemonic: String,
    pub op_str: String,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_ret: bool,
}

impl DecodedInsn {
    /// Construct a decode-failure placeholder. Mirrors Python's
    /// `Decoded(pc, inst, "<bad>", f"{inst:08x}")`.
    pub fn bad(pc: u64, inst: u32) -> Self {
        Self {
            pc,
            inst,
            mnemonic: "<bad>".to_string(),
            op_str: format!("{inst:08x}"),
            is_branch: false,
            is_call: false,
            is_ret: false,
        }
    }
}
```

Create `rust/crates/tracemiku-core/src/disasm/mod.rs`:

```rust
//! ARM64 instruction decoding (capstone-rs wrapper).
//!
//! Public entry: [`decode`] — cached per-thread via the FIFO buffer in
//! [`cache`]. Cold path: [`decoder::raw_decode`] — uncached, allocates
//! a Capstone handle on first call per thread.

pub mod decoder;

pub use decoder::DecodedInsn;
```

Modify `rust/crates/tracemiku-core/src/lib.rs`. Current content:

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

pub mod prelude;
pub mod trace;
```

Add `pub mod disasm;`:

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
pub mod prelude;
pub mod trace;
```

- [ ] **Step 4: Verify build still passes**

```bash
cd rust && cargo build -p tracemiku-core 2>&1 | tail -5 ; cd ..
```

Expected: `Finished \`dev\`...`. First compile pulls capstone-sys → builds the C library; can take 30-90s on first run. Subsequent compiles are cached.

If the capstone C build fails with "missing CMake" or similar, the `capstone-sys` build script needs the system-level `cmake` and a C compiler. Most dev systems have these; if not, install via the system package manager and re-run. Don't paper over with `--features bundled` — capstone defaults to bundled build of the C library and that's what we want.

If `cargo build` complains that capstone 0.13 is yanked or doesn't exist, fall back to `capstone = "0.12"` in both `rust/Cargo.toml` and re-run. The 0.12 → 0.13 API surface used in this plan (Capstone builder, disasm_all, Insn::mnemonic/op_str) is stable.

- [ ] **Step 5: Commit**

```bash
git add rust/Cargo.toml rust/crates/tracemiku-core/Cargo.toml rust/crates/tracemiku-core/src/lib.rs rust/crates/tracemiku-core/src/disasm/
git commit -m "$(cat <<'EOF'
build(core): add capstone dep + DecodedInsn skeleton

capstone 0.13 (workspace pin). DecodedInsn fields M2-β consumes:
mnemonic, op_str, is_branch, is_call, is_ret. Register def/use,
branch_target, mem_op deferred to M2-γ when Index needs them.

DecodedInsn::bad() mirrors Python's `<bad> {inst:08x}` placeholder.
EOF
)"
```

---

## Task 2: raw_decode(pc, inst) — single-decode via capstone (TDD)

**Files:**
- Modify: `rust/crates/tracemiku-core/src/disasm/decoder.rs`
- Create: `rust/crates/tracemiku-core/tests/disasm_decode.rs`

The cold-path decoder. Each thread keeps its own `Capstone` handle (capstone-rs handles are not `Send`-safe; thread-local is the recommended pattern).

- [ ] **Step 1: Write failing tests**

Create `rust/crates/tracemiku-core/tests/disasm_decode.rs`:

```rust
//! TDD for tracemiku-core::disasm::raw_decode.
//!
//! Reference instruction encodings (ARM64 little-endian u32):
//!   nop:                0xd503201f
//!   ret:                0xd65f03c0
//!   bl <pc + 0x100>:    encoded from base PC = 0x100000 → "bl 0x100100"
//!     (keystone-asm output: 0x94000040)
//!   cmp x0, x1:         0xeb01001f (subs xzr, x0, x1; "cmp" alias)
//!   bad bytes:          0x00000000 (decodes as <udf> on capstone OR <bad>)

use tracemiku_core::disasm::{decoder::raw_decode, DecodedInsn};

#[test]
fn decodes_nop() {
    let d: DecodedInsn = raw_decode(0x100000, 0xd503201f);
    assert_eq!(d.pc, 0x100000);
    assert_eq!(d.inst, 0xd503201f);
    assert_eq!(d.mnemonic, "nop");
    assert!(!d.is_branch);
    assert!(!d.is_call);
    assert!(!d.is_ret);
}

#[test]
fn decodes_ret() {
    let d = raw_decode(0x100008, 0xd65f03c0);
    assert_eq!(d.mnemonic, "ret");
    assert!(d.is_branch);   // ret is a branch
    assert!(!d.is_call);
    assert!(d.is_ret);
}

#[test]
fn decodes_bl_as_call_and_branch() {
    // bl 0x100100 from PC 0x100000 = offset +0x100 / 4 = 0x40 → 0x94000040
    let d = raw_decode(0x100000, 0x94000040);
    assert_eq!(d.mnemonic, "bl");
    assert!(d.is_branch);
    assert!(d.is_call);
    assert!(!d.is_ret);
    // op_str should mention the target address
    assert!(d.op_str.contains("0x100100") || d.op_str.contains("100100"),
            "op_str should resolve target, got: {:?}", d.op_str);
}

#[test]
fn decodes_b_unconditional_as_branch_not_call() {
    // b 0x100008 from PC 0x100000 = offset +8 / 4 = 2 → 0x14000002
    let d = raw_decode(0x100000, 0x14000002);
    assert_eq!(d.mnemonic, "b");
    assert!(d.is_branch);
    assert!(!d.is_call);
    assert!(!d.is_ret);
}

#[test]
fn decodes_b_dot_eq_as_branch() {
    // b.eq +0 from PC 0x100000 → 0x54000000
    let d = raw_decode(0x100000, 0x54000000);
    // Capstone reports "b.eq" mnemonic (with dot).
    assert!(d.mnemonic.starts_with("b."), "expected b.cond, got {:?}", d.mnemonic);
    assert!(d.is_branch, "b.eq must be classified as a branch");
    assert!(!d.is_call);
}

#[test]
fn decodes_unknown_bytes_yields_bad() {
    // 0x00000000 is "udf" or invalid depending on capstone version.
    let d = raw_decode(0x100000, 0x00000000);
    // Either capstone returns "udf" or we fall back to <bad>. Both acceptable
    // — what's not acceptable is a panic.
    assert!(d.mnemonic == "udf" || d.mnemonic == "<bad>",
            "unexpected mnemonic for invalid inst: {:?}", d.mnemonic);
}
```

- [ ] **Step 2: Run — failing red**

```bash
cd rust && cargo test -p tracemiku-core --test disasm_decode 2>&1 | tail -10 ; cd ..
```

Expected: compile error: `raw_decode` not found.

- [ ] **Step 3: Implement raw_decode + thread-local handle**

Replace contents of `rust/crates/tracemiku-core/src/disasm/decoder.rs` with:

```rust
//! capstone-rs wrapper. M2-β provides decode() returning DecodedInsn with
//! mnemonic + op_str + branch/call/ret classification. Register def/use,
//! branch_target, mem_op come in M2-γ when Index needs them.

use std::cell::RefCell;

use capstone::arch::{arm64, BuildsCapstone};
use capstone::Capstone;
use serde::Serialize;

use crate::disasm::classify::{is_branch_mnem, is_call_mnem, is_ret_mnem};

/// Decoded ARM64 instruction. Wire-compatible with Python `viewer.disasm.Decoded`
/// for the fields M2-β consumes; remaining fields filled in M2-γ.
#[derive(Debug, Clone, Serialize)]
pub struct DecodedInsn {
    pub pc: u64,
    pub inst: u32,
    pub mnemonic: String,
    pub op_str: String,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_ret: bool,
}

impl DecodedInsn {
    /// Construct a decode-failure placeholder. Mirrors Python's
    /// `Decoded(pc, inst, "<bad>", f"{inst:08x}")`.
    pub fn bad(pc: u64, inst: u32) -> Self {
        Self {
            pc,
            inst,
            mnemonic: "<bad>".to_string(),
            op_str: format!("{inst:08x}"),
            is_branch: false,
            is_call: false,
            is_ret: false,
        }
    }
}

thread_local! {
    /// Each thread keeps its own Capstone handle. Capstone instances are
    /// `!Send` (per capstone-rs docs), so thread-local is mandatory.
    static CS: RefCell<Capstone> = RefCell::new(
        Capstone::new()
            .arm64()
            .mode(arm64::ArchMode::Arm)
            .detail(false)  // M2-β: no operand details needed; M2-γ flips this on for def_use
            .build()
            .expect("capstone arm64 init failed — bundled build broken?"),
    );
}

/// Decode a single 4-byte ARM64 instruction at the given PC.
/// On decode failure (e.g. invalid bytes), returns [`DecodedInsn::bad`].
///
/// Cold path — no caching. For repeat decodes prefer [`crate::disasm::decode`].
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
        DecodedInsn {
            pc,
            inst,
            is_branch: is_branch_mnem(&mnem),
            is_call: is_call_mnem(&mnem),
            is_ret: is_ret_mnem(&mnem),
            mnemonic: mnem,
            op_str,
        }
    })
}
```

This file references `crate::disasm::classify` which Task 3 creates — but Task 3 has the test discipline upside-down (need classifiers before tests can pass). To avoid a circular failure, **also create a stub `classify.rs` here** with sentinel implementations:

Create `rust/crates/tracemiku-core/src/disasm/classify.rs`:

```rust
//! Mnemonic-based branch/call/ret classification. Pure functions over &str.
//!
//! Mirrors the Python logic in `viewer/disasm.py:65-71`:
//!   is_branch = mnem in {"b","bl","br","blr","ret","cbz","cbnz","tbz","tbnz"}
//!               OR mnem.startswith("b.")
//!   is_call   = mnem in {"bl","blr"}
//!   is_ret    = mnem == "ret"
//!
//! Task 3 adds tests; this module ships its real implementation directly
//! (no behavior bait-and-switch).

/// `true` if mnemonic is any branch (conditional, indirect, compare-and-branch,
/// test-and-branch, ret).
pub fn is_branch_mnem(mnem: &str) -> bool {
    matches!(
        mnem,
        "b" | "bl" | "br" | "blr" | "ret"
        | "cbz" | "cbnz" | "tbz" | "tbnz"
    ) || mnem.starts_with("b.")
}

/// `true` if mnemonic is a function call (direct or indirect).
pub fn is_call_mnem(mnem: &str) -> bool {
    matches!(mnem, "bl" | "blr")
}

/// `true` if mnemonic is the function-return instruction.
pub fn is_ret_mnem(mnem: &str) -> bool {
    mnem == "ret"
}
```

Update `rust/crates/tracemiku-core/src/disasm/mod.rs`:

```rust
//! ARM64 instruction decoding (capstone-rs wrapper).
//!
//! Public entry: [`decode`] — cached per-thread via the FIFO buffer in
//! [`cache`] (added in Task 4). Cold path: [`decoder::raw_decode`] —
//! uncached, allocates a Capstone handle on first call per thread.

pub mod classify;
pub mod decoder;

pub use decoder::DecodedInsn;
pub use decoder::raw_decode;
```

- [ ] **Step 4: Run tests — should PASS**

```bash
cd rust && cargo test -p tracemiku-core --test disasm_decode 2>&1 | tail -10 ; cd ..
```

Expected: `test result: ok. 6 passed; 0 failed`.

If `decodes_bl_as_call_and_branch` fails because op_str shows `0x100100` differently (e.g. `#0x100100` or no `0x` prefix), relax the assertion — capstone 0.13 vs 0.12 may format differently. The test's `contains("100100")` fallback already handles this.

If `decodes_b_dot_eq_as_branch` fails because capstone returns mnemonic without the dot (e.g. `beq` instead of `b.eq`), update the classifier `is_branch_mnem` to also recognize `beq`/`bne`/etc — but FIRST verify by running with a print:

```bash
cd rust && cargo test -p tracemiku-core --test disasm_decode decodes_b_dot_eq_as_branch -- --nocapture 2>&1 | tail -20 ; cd ..
```

Either fix the assertion (if mnemonic is unexpected) or fix the classifier.

- [ ] **Step 5: cargo fmt + clippy clean**

```bash
cd rust && cargo fmt --all && cargo clippy -p tracemiku-core --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-core/src/disasm/ rust/crates/tracemiku-core/tests/disasm_decode.rs
git commit -m "$(cat <<'EOF'
feat(core): raw_decode + classify — capstone-rs ARM64 wrapper

Thread-local Capstone handle (capstone-rs is !Send). raw_decode(pc, inst)
returns DecodedInsn with mnemonic + op_str + is_branch/is_call/is_ret.
Failures (invalid bytes, capstone error) yield DecodedInsn::bad(pc, inst)
matching Python's "<bad> {inst:08x}" sentinel.

is_branch / is_call / is_ret classifiers in classify.rs are pure-fn
mirrors of viewer/disasm.py:65-71. b.cond and conditional-branch family
covered.

6 TDD tests cover nop / ret / bl / b / b.eq / invalid-bytes.
EOF
)"
```

---

## Task 3: Classify edge cases — full test sweep

**Files:**
- Modify: `rust/crates/tracemiku-core/tests/disasm_decode.rs` (append edge-case tests)

The classify functions in Task 2 were already implemented (couldn't avoid it — `decoder.rs` references them). This task locks in their behavior with a comprehensive test sweep so M2-γ doesn't regress them.

- [ ] **Step 1: Append exhaustive classifier tests**

Append to `rust/crates/tracemiku-core/tests/disasm_decode.rs`:

```rust
// ── Classifier sweep ───────────────────────────────────────────────────────

use tracemiku_core::disasm::classify::{is_branch_mnem, is_call_mnem, is_ret_mnem};

#[test]
fn classifier_branch_set() {
    for m in [
        "b", "bl", "br", "blr", "ret",
        "cbz", "cbnz", "tbz", "tbnz",
        "b.eq", "b.ne", "b.gt", "b.lt", "b.al",
    ] {
        assert!(is_branch_mnem(m), "{m} should be a branch");
    }
}

#[test]
fn classifier_call_set() {
    for m in ["bl", "blr"] {
        assert!(is_call_mnem(m), "{m} should be a call");
    }
    for m in ["b", "br", "ret", "cbz", "b.eq"] {
        assert!(!is_call_mnem(m), "{m} should NOT be a call");
    }
}

#[test]
fn classifier_ret_set() {
    assert!(is_ret_mnem("ret"));
    for m in ["b", "bl", "br", "blr", "cbz", "b.eq"] {
        assert!(!is_ret_mnem(m), "{m} should NOT be a ret");
    }
}

#[test]
fn classifier_negatives() {
    for m in ["nop", "mov", "add", "sub", "ldr", "str", "cmp", "beep"] {
        // "beep" must NOT match starts_with("b.") — verify the "." matters
        let expected_branch = m.starts_with("b.") || matches!(
            m,
            "b" | "bl" | "br" | "blr" | "ret"
            | "cbz" | "cbnz" | "tbz" | "tbnz"
        );
        assert_eq!(is_branch_mnem(m), expected_branch, "branch classify of {m:?}");
    }
}

#[test]
fn classifier_beep_not_a_branch() {
    // Regression: ensure starts_with("b.") doesn't accidentally match "beep" or "br"
    // (br is in the explicit set; "beep" must be false).
    assert!(!is_branch_mnem("beep"));
    assert!(!is_branch_mnem("blob"));
    assert!(!is_branch_mnem("bx"));   // not present in ARM64 (it's ARM32)
    assert!(is_branch_mnem("br"));    // explicit set
}
```

- [ ] **Step 2: Run — should PASS without changes**

```bash
cd rust && cargo test -p tracemiku-core --test disasm_decode 2>&1 | tail -10 ; cd ..
```

Expected: `test result: ok. 11 passed; 0 failed`.

- [ ] **Step 3: cargo fmt + clippy**

```bash
cd rust && cargo fmt --all && cargo clippy -p tracemiku-core --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 4: Commit**

```bash
git add rust/crates/tracemiku-core/tests/disasm_decode.rs
git commit -m "test(disasm): exhaustive classifier sweep — pin is_branch/call/ret behavior"
```

---

## Task 4: Thread-local FIFO cache (lru_cache parity)

**Files:**
- Create: `rust/crates/tracemiku-core/src/disasm/cache.rs`
- Modify: `rust/crates/tracemiku-core/src/disasm/mod.rs`
- Modify: `rust/crates/tracemiku-core/src/prelude.rs`
- Create: `rust/crates/tracemiku-core/tests/disasm_cache.rs`

Python's `@lru_cache(maxsize=200000)` on `decode(pc, inst)` is the hot path optimization. For Rust we use a FIFO eviction policy (capacity 200_000), which is simpler than true LRU and behaviorally equivalent on the workload (every distinct PC decoded ~once per scan).

We use a `VecDeque<u64> + HashMap<u64, DecodedInsn>` pair, keying on `(pc << 32) | inst as u64` (pc is < 2^48 in real traces; this gives unique 64-bit keys without collisions for any practical inst).

- [ ] **Step 1: Write failing tests**

Create `rust/crates/tracemiku-core/tests/disasm_cache.rs`:

```rust
//! Tests the public `decode(pc, inst)` cached entrypoint.

use tracemiku_core::disasm::decode;

#[test]
fn decode_returns_same_result_repeated() {
    let a = decode(0x100000, 0xd503201f);
    let b = decode(0x100000, 0xd503201f);
    // Cached value should be byte-equal (we don't expose hit/miss, just verify
    // semantics: same input -> same output).
    assert_eq!(a.mnemonic, b.mnemonic);
    assert_eq!(a.op_str, b.op_str);
    assert_eq!(a.pc, b.pc);
    assert_eq!(a.inst, b.inst);
}

#[test]
fn decode_distinct_keys_distinct_results() {
    let a = decode(0x100000, 0xd503201f);  // nop
    let b = decode(0x100008, 0xd65f03c0);  // ret
    assert_eq!(a.mnemonic, "nop");
    assert_eq!(b.mnemonic, "ret");
}

#[test]
fn decode_works_on_many_distinct_pcs() {
    // Exceed a small cache; should still produce correct results.
    for i in 0..1024u64 {
        let d = decode(0x100000 + i * 4, 0xd503201f);
        assert_eq!(d.mnemonic, "nop", "iteration {i}");
        assert_eq!(d.pc, 0x100000 + i * 4);
    }
}
```

- [ ] **Step 2: Run — failing red**

```bash
cd rust && cargo test -p tracemiku-core --test disasm_cache 2>&1 | tail -5 ; cd ..
```

Expected: compile error: `decode` not found.

- [ ] **Step 3: Implement cache.rs**

Create `rust/crates/tracemiku-core/src/disasm/cache.rs`:

```rust
//! Thread-local FIFO cache over [`raw_decode`]. Capacity matches Python's
//! `@lru_cache(maxsize=200000)`. FIFO instead of true LRU — simpler and
//! behaviorally equivalent on trace-walk workloads where every distinct PC
//! is decoded once per scan.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

use crate::disasm::decoder::{raw_decode, DecodedInsn};

const CAP: usize = 200_000;

struct Cache {
    map: HashMap<u64, DecodedInsn>,
    /// FIFO queue of keys in insertion order; oldest at front.
    order: VecDeque<u64>,
}

impl Cache {
    fn new() -> Self {
        Self {
            map: HashMap::with_capacity(CAP),
            order: VecDeque::with_capacity(CAP),
        }
    }

    fn get_or_insert(&mut self, pc: u64, inst: u32) -> DecodedInsn {
        let key = (pc << 32) | (inst as u64);
        if let Some(v) = self.map.get(&key) {
            return v.clone();
        }
        let d = raw_decode(pc, inst);
        if self.map.len() >= CAP {
            // FIFO evict oldest.
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
        self.map.insert(key, d.clone());
        self.order.push_back(key);
        d
    }
}

thread_local! {
    static CACHE: RefCell<Cache> = RefCell::new(Cache::new());
}

/// Cached decode — looks up `(pc, inst)` in the per-thread FIFO buffer
/// (200k entries) and falls through to [`raw_decode`] on miss.
pub fn decode(pc: u64, inst: u32) -> DecodedInsn {
    CACHE.with(|c| c.borrow_mut().get_or_insert(pc, inst))
}
```

Update `rust/crates/tracemiku-core/src/disasm/mod.rs`:

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

Update `rust/crates/tracemiku-core/src/prelude.rs`. Current:

```rust
//! Re-exports the public API surface for downstream consumers.
//!
//! Use `use tracemiku_core::prelude::*;` rather than reaching into
//! submodules directly.

pub use crate::trace::{
    CallInfo, MetaError, ModuleInfo, Record, Trace, TraceMeta,
    REC_NUM_REGS, REC_SIZE,
};
```

Replace with:

```rust
//! Re-exports the public API surface for downstream consumers.
//!
//! Use `use tracemiku_core::prelude::*;` rather than reaching into
//! submodules directly.

pub use crate::disasm::{decode, DecodedInsn};
pub use crate::trace::{
    CallInfo, MetaError, ModuleInfo, Record, Trace, TraceMeta,
    REC_NUM_REGS, REC_SIZE,
};
```

- [ ] **Step 4: Run tests — should PASS**

```bash
cd rust && cargo test -p tracemiku-core --test disasm_cache 2>&1 | tail -10 ; cd ..
```

Expected: `test result: ok. 3 passed; 0 failed`.

- [ ] **Step 5: cargo fmt + clippy clean**

```bash
cd rust && cargo fmt --all && cargo clippy -p tracemiku-core --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-core/src/disasm/cache.rs rust/crates/tracemiku-core/src/disasm/mod.rs rust/crates/tracemiku-core/src/prelude.rs rust/crates/tracemiku-core/tests/disasm_cache.rs
git commit -m "$(cat <<'EOF'
feat(core): thread-local FIFO cache for decode (200k entries)

Mirrors Python `@lru_cache(maxsize=200000)`. FIFO eviction (HashMap +
VecDeque) is simpler than true LRU and behaviorally equivalent on the
workload (each distinct PC decoded once per scan).

Public `tracemiku_core::prelude::decode(pc, inst) -> DecodedInsn` is now
the recommended entry; raw_decode stays public for tests and benchmarks.
EOF
)"
```

---

## Task 5: Real-trace decode integration test (#[ignore])

**Files:**
- Create: `rust/crates/tracemiku-core/tests/disasm_real.rs`

Validates capstone + cache against the 4.2 GB real-trace fixture. M0 baseline: Python decoded 10,825 distinct PCs in first 1M records in 0.838s. Rust target: same set of distinct PCs in <500ms.

- [ ] **Step 1: Create the test**

Create `rust/crates/tracemiku-core/tests/disasm_real.rs`:

```rust
//! Real-trace decode integration. #[ignore] — opt in via cargo test --ignored.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Instant;

use tracemiku_core::prelude::*;

const REAL_TRACE_REL: &str =
    "../../../traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms";
const SCAN_LIMIT: usize = 1_000_000;

fn real_trace_path() -> Option<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let p = PathBuf::from(manifest).join(REAL_TRACE_REL);
    let p = p.canonicalize().ok()?;
    if !p.join("trace.bin").exists() {
        return None;
    }
    Some(p)
}

#[test]
#[ignore]
fn decodes_first_1m_distinct_pcs() {
    let Some(p) = real_trace_path() else {
        eprintln!("skip: real trace fixture not found");
        return;
    };
    let t = Trace::load(&p).expect("load real trace");
    let limit = SCAN_LIMIT.min(t.len());

    // First pass: scan the first SCAN_LIMIT records, decode each distinct PC once.
    let scan_t = Instant::now();
    let mut seen = HashSet::with_capacity(20_000);
    let mut decoded_count = 0usize;
    for i in 0..limit {
        let pc = t.pc(i);
        if !seen.insert(pc) {
            continue;
        }
        let _d = decode(pc, t.inst(i));
        decoded_count += 1;
    }
    let scan_ms = scan_t.elapsed().as_millis();
    eprintln!("decoded {decoded_count} distinct PCs in {scan_ms}ms (target <500ms; Python baseline 838ms)");
    assert!(decoded_count > 0, "must decode at least one PC");
    // Python baseline: 10,825 distinct PCs in first 1M records. Allow 50% tolerance for
    // test-data drift but flag if WAY off.
    assert!(decoded_count > 100, "implausibly few distinct PCs: {decoded_count}");

    // Second pass: re-decode the same PCs, should be 100% cache hits — much faster.
    let cache_t = Instant::now();
    for i in 0..limit {
        let pc = t.pc(i);
        if seen.contains(&pc) {
            let _d = decode(pc, t.inst(i));
        }
    }
    let cache_ms = cache_t.elapsed().as_millis();
    eprintln!("re-scan with cache hits: {cache_ms}ms");
    // We don't assert cache_ms < scan_ms strictly — second pass also walks 1M records.
    // The capstone work is what's elided; pc(i) + HashSet contains() is the floor.
}
```

- [ ] **Step 2: Compile check**

```bash
cd rust && cargo test -p tracemiku-core --test disasm_real 2>&1 | tail -5 ; cd ..
```

Expected: `1 ignored`. Compile must succeed.

- [ ] **Step 3: Opt-in run**

```bash
cd rust && cargo test -p tracemiku-core --test disasm_real -- --ignored --nocapture 2>&1 | tail -10 ; cd ..
```

Expected: passes; printlns show `decoded ~10000 distinct PCs in <500ms` and second-pass `cache ms` is significantly lower (or comparable — depends on scan overhead). Records: 15.4M total, scan caps at 1M.

- [ ] **Step 4: Commit**

```bash
git add rust/crates/tracemiku-core/tests/disasm_real.rs
git commit -m "$(cat <<'EOF'
test(disasm): real-trace decode — first 1M records, distinct PCs only

#[ignore] by default. Decodes every distinct PC in the first 1M records
of the 4.2GB fixture; targets <500ms (Python baseline: 838ms). Second
pass re-decodes the same set to confirm cache hits dominate runtime.
EOF
)"
```

---

## Task 6: GET /api/records endpoint (TDD)

**Files:**
- Create: `rust/crates/tracemiku-server/src/routes/records.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/mod.rs`
- Create: `rust/crates/tracemiku-server/tests/records_endpoint.rs`

The wire shape mirrors Python's `webui/schemas.py:37-57`:

```typescript
interface RecordRow {
  idx: number;
  pc: string;             // hex, "0x..."
  rel: string | null;     // hex offset within primary module
  module: string | null;
  func: null;             // M2-β: always null; populated in M2-γ
  off: null;              // ditto
  asm: string;            // "<mnemonic> <op_str>"
  annotation: null;       // ditto
  exec_count: null;       // ditto
  is_branch: boolean;
  is_call: boolean;
  is_ret: boolean;
  regs?: Record<string, string>;  // present only when ?regs=x0,x1,...
}
interface RecordsResponse {
  start: number;
  end: number;
  count: number;
  records: RecordRow[];
}
```

- [ ] **Step 1: Write failing integration tests**

Create `rust/crates/tracemiku-server/tests/records_endpoint.rs`:

```rust
//! Black-box tests for GET /api/records and GET /api/record/{idx}.

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

    // Write 9 records with known PCs + insts (matches scripts/build_smoke_trace.py).
    // Layout: PC = 0x100000 + 4*i; insts cycle through nop/bl/nop/ret patterns.
    let mut buf = vec![0u8; 272 * 9];
    let pcs = [
        0x100000u64, 0x100004, 0x100100, 0x100104,
        0x100008, 0x100200, 0x100204, 0x100208, 0x10000c,
    ];
    let insts: [u32; 9] = [
        0xd503201f, // nop
        0x94000040, // bl 0x100100   (offset 0x40*4 = 0x100 from PC 0x100000)
        0xd503201f, // nop
        0xd65f03c0, // ret
        0x94000080, // bl 0x100200   (offset 0x80*4 = 0x200 from PC 0x100008 → 0x100208... wait)
        0xd503201f, // nop
        0xd503201f, // nop
        0xd65f03c0, // ret
        0xd65f03c0, // ret
    ];
    // NOTE: bl encoding = 0x94000000 | ((target - pc) >> 2 & 0x3FFFFFF). For
    // synth purposes the exact target is not asserted; just that bl decodes
    // and is classified as a call. So we use generic encodings:
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        // sp at 256..264
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        // inst at 268..272
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"),
              r#"{"callIdx":1,"tid":100,"records":9,"ms":2,"retval":"0x0","truncated":false,"last_insn_is_ret":true}"#).unwrap();
    fs::write(tmp.path().join("run").join("meta.json"),
              r#"{"pkg":"tst","so":"libt","method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#).unwrap();
    let cd_owned = cd.clone();
    (tmp, cd_owned)
}

#[tokio::test]
async fn records_default_window() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder().uri("/api/records").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(v["start"], 0);
    assert_eq!(v["end"], 9);
    assert_eq!(v["count"], 9);
    assert_eq!(v["records"].as_array().unwrap().len(), 9);

    let r0 = &v["records"][0];
    assert_eq!(r0["idx"], 0);
    assert_eq!(r0["pc"], "0x100000");
    assert_eq!(r0["rel"], "0x0");
    assert_eq!(r0["module"], "libt.so");
    assert!(r0["asm"].as_str().unwrap().starts_with("nop"));
    assert_eq!(r0["is_branch"], false);
    assert_eq!(r0["is_call"], false);
    assert_eq!(r0["is_ret"], false);
    // Symbol-dependent fields are null in M2-β.
    assert!(r0["func"].is_null());
    assert!(r0["off"].is_null());
    assert!(r0["annotation"].is_null());
    assert!(r0["exec_count"].is_null());
    // regs not requested → field absent or null.
    assert!(r0.get("regs").map_or(true, |v| v.is_null()));

    // Spot-check the bl record (index 1) is classified as a call+branch.
    let r1 = &v["records"][1];
    assert_eq!(r1["pc"], "0x100004");
    assert_eq!(r1["is_branch"], true);
    assert_eq!(r1["is_call"], true);
    assert_eq!(r1["is_ret"], false);

    // Spot-check the ret record (index 3) is classified ret + branch.
    let r3 = &v["records"][3];
    assert_eq!(r3["is_ret"], true);
    assert_eq!(r3["is_branch"], true);
    assert_eq!(r3["is_call"], false);
}

#[tokio::test]
async fn records_start_count_window() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder()
            .uri("/api/records?start=2&count=3")
            .body(Body::empty()).unwrap())
        .await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["start"], 2);
    assert_eq!(v["end"], 5);
    assert_eq!(v["count"], 3);
    assert_eq!(v["records"].as_array().unwrap().len(), 3);
    assert_eq!(v["records"][0]["idx"], 2);
    assert_eq!(v["records"][2]["idx"], 4);
}

#[tokio::test]
async fn records_start_out_of_range_empty() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder()
            .uri("/api/records?start=999&count=10")
            .body(Body::empty()).unwrap())
        .await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["start"], 999);
    assert_eq!(v["end"], 999);
    assert_eq!(v["count"], 0);
    assert_eq!(v["records"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn records_with_regs_filter() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder()
            .uri("/api/records?start=0&count=1&regs=sp,pc")
            .body(Body::empty()).unwrap())
        .await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let r0 = &v["records"][0];
    let regs = r0["regs"].as_object().expect("regs object present when filter set");
    assert_eq!(regs["pc"], "0x100000");
    assert_eq!(regs["sp"], "0x7000");
    assert!(!regs.contains_key("x0"), "x0 must be absent when not filtered");
}
```

- [ ] **Step 2: Run — failing red**

```bash
cd rust && cargo test -p tracemiku-server --test records_endpoint 2>&1 | tail -10 ; cd ..
```

Expected: 404 from `/api/records` (route not registered) → tests fail on `assert_eq!(resp.status(), OK)`.

- [ ] **Step 3: Implement records.rs**

Create `rust/crates/tracemiku-server/src/routes/records.rs`:

```rust
//! GET /api/records?start=&count=&regs=
//!
//! Returns a window of decoded trace records. Wire-compatible subset of
//! Python `webui/server.py` /api/records — symbol-dependent fields
//! (func/off/annotation/exec_count) are emitted as `null` for M2-β;
//! M2-γ populates them after SymbolMap + CFG land.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::*;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RecordsQuery {
    #[serde(default = "default_start")]
    pub start: usize,
    #[serde(default = "default_count")]
    pub count: usize,
    /// Comma-separated reg names. Empty / absent → no `regs` field on rows.
    #[serde(default)]
    pub regs: String,
}

fn default_start() -> usize { 0 }
fn default_count() -> usize { 100 }

#[derive(Debug, Serialize)]
pub struct RecordRow {
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub module: Option<String>,
    /// M2-β: always None. M2-γ: function name from SymbolMap.
    pub func: Option<String>,
    /// M2-β: always None. M2-γ: hex offset from func base.
    pub off: Option<String>,
    pub asm: String,
    /// M2-β: always None. M2-γ: derived from CFG + SymbolMap.
    pub annotation: Option<String>,
    /// M2-β: always None. M2-γ: from CFG block.executions.
    pub exec_count: Option<u64>,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_ret: bool,
    /// Only emitted when ?regs=... is set. Otherwise omitted via skip_if.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regs: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Serialize)]
pub struct RecordsResponse {
    pub start: usize,
    pub end: usize,
    pub count: usize,
    pub records: Vec<RecordRow>,
}

pub async fn records_handler(
    State(state): State<AppState>,
    Query(q): Query<RecordsQuery>,
) -> Json<RecordsResponse> {
    let inner = &state.inner;
    let n = inner.trace.len();
    if q.start >= n {
        return Json(RecordsResponse {
            start: q.start, end: q.start, count: 0, records: vec![],
        });
    }
    let end = (q.start + q.count).min(n);

    // Parse regs filter. Empty string → no filter.
    let regs_filter: Option<Vec<String>> = if q.regs.is_empty() {
        None
    } else {
        // Validate against ALL_REGS = x0..x28, fp, lr, sp, pc, nzcv. We accept
        // any name that Record::reg() returns Some for.
        let names: Vec<String> = q.regs
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        Some(names)
    };

    // Primary module base for `rel` field.
    let base: Option<u64> = inner.meta.module.as_ref().map(|m| {
        u64::from_str_radix(m.base.trim_start_matches("0x"), 16).unwrap_or(0)
    });
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

    Json(RecordsResponse {
        start: q.start,
        end,
        count: end - q.start,
        records: rows,
    })
}
```

Update `rust/crates/tracemiku-server/src/routes/mod.rs`. Current:

```rust
pub mod meta;

use axum::Router;
use axum::routing::get;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/meta", get(meta::meta_handler))
        .with_state(state)
}
```

Replace with:

```rust
pub mod meta;
pub mod records;

use axum::routing::get;
use axum::Router;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/meta", get(meta::meta_handler))
        .route("/api/records", get(records::records_handler))
        .with_state(state)
}
```

- [ ] **Step 4: Run tests — should PASS**

```bash
cd rust && cargo test -p tracemiku-server --test records_endpoint 2>&1 | tail -15 ; cd ..
```

Expected: 4 passed (records_default_window, records_start_count_window, records_start_out_of_range_empty, records_with_regs_filter).

If any test fails, read the assertion message carefully — the most likely culprits are:
- `r0["pc"]` mismatch: Rust formats as `format!("{:#x}", ...)` which produces lowercase `0x100000`. If Python produced `0x100000` (lowercase), they match. If anywhere asserts uppercase, lower it.
- `r0["asm"].starts_with("nop")`: capstone may emit `"nop"` or `"nop "` or `nop\t` — the `.trim().to_string()` in the handler strips trailing whitespace from `"nop "` (when op_str is empty). If still failing, change the test to `assert!(r0["asm"].as_str().unwrap().contains("nop"))`.

- [ ] **Step 5: cargo fmt + clippy clean**

```bash
cd rust && cargo fmt --all && cargo clippy --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-server/src/routes/ rust/crates/tracemiku-server/tests/records_endpoint.rs
git commit -m "$(cat <<'EOF'
feat(server): GET /api/records — decoded trace window

start/count query params; optional regs=x0,x1 filter. Wire-compatible
subset of Python /api/records — symbol-dependent fields (func/off/
annotation/exec_count) emitted null for M2-β, populated when M2-γ
lands SymbolMap + CFG.

4 integration tests: default window (start=0, count=100), explicit
start+count slice, out-of-range start (empty), regs filter.
EOF
)"
```

---

## Task 7: GET /api/record/{idx} — single-record detail

**Files:**
- Create: `rust/crates/tracemiku-server/src/routes/record.rs`
- Modify: `rust/crates/tracemiku-server/src/routes/mod.rs`
- Modify: `rust/crates/tracemiku-server/tests/records_endpoint.rs`

`/api/record/{idx}` returns one decoded record with **all 33 registers** (matches Python's `RecordDetail` schema where `regs: dict[str, str]` is required, not optional). M2-β skips `prev_regs` and `regs_annotated` (which need the previous record + classifier from M2-γ display.py).

- [ ] **Step 1: Append failing test**

Append to `rust/crates/tracemiku-server/tests/records_endpoint.rs`:

```rust
#[tokio::test]
async fn record_single_returns_full_regs() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder().uri("/api/record/0").body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["idx"], 0);
    assert_eq!(v["pc"], "0x100000");
    assert!(v["asm"].as_str().unwrap().contains("nop"));

    let regs = v["regs"].as_object().expect("regs always required");
    // 31 GPR (x0..x28, fp, lr) + sp + pc + nzcv = 34 entries.
    assert!(regs.len() >= 33, "expected ≥33 reg entries, got {}", regs.len());
    assert_eq!(regs["pc"], "0x100000");
    assert_eq!(regs["sp"], "0x7000");
    assert_eq!(regs["x0"], "0x0");
}

#[tokio::test]
async fn record_out_of_range_404() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder().uri("/api/record/999").body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
```

- [ ] **Step 2: Run — failing red**

```bash
cd rust && cargo test -p tracemiku-server --test records_endpoint 2>&1 | tail -10 ; cd ..
```

Expected: the new tests fail (404 from a route that doesn't exist).

- [ ] **Step 3: Implement record.rs**

Create `rust/crates/tracemiku-server/src/routes/record.rs`:

```rust
//! GET /api/record/{idx} — single-record detail.
//!
//! Always emits all 33 registers (x0..x28, fp, lr, sp, pc, nzcv). For M2-β,
//! `prev_regs` and `regs_annotated` from the Python schema are omitted —
//! M2-γ adds them once display.py / pwndbg-style classifier lands.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use std::collections::BTreeMap;

use tracemiku_core::prelude::*;

use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct RecordDetail {
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub func: Option<String>,
    pub off: Option<String>,
    pub asm: String,
    pub regs: BTreeMap<String, String>,
}

pub async fn record_handler(
    State(state): State<AppState>,
    Path(idx): Path<usize>,
) -> Result<Json<RecordDetail>, StatusCode> {
    let inner = &state.inner;
    if idx >= inner.trace.len() {
        return Err(StatusCode::NOT_FOUND);
    }
    let r = inner.trace.record(idx);
    let d = decode(r.pc, r.inst);

    let base: Option<u64> = inner.meta.module.as_ref().map(|m| {
        u64::from_str_radix(m.base.trim_start_matches("0x"), 16).unwrap_or(0)
    });
    let rel = base.map(|b| format!("{:#x}", r.pc.wrapping_sub(b)));

    // All 33 regs. Use the same canonical name list as REG_NAMES (without nzcv,
    // we add nzcv separately so the response includes it.
    let mut regs = BTreeMap::new();
    let names = [
        "x0","x1","x2","x3","x4","x5","x6","x7","x8","x9",
        "x10","x11","x12","x13","x14","x15","x16","x17","x18","x19",
        "x20","x21","x22","x23","x24","x25","x26","x27","x28",
        "fp","lr","sp","pc","nzcv",
    ];
    for nm in names {
        if let Some(v) = r.reg(nm) {
            regs.insert(nm.to_string(), format!("{v:#x}"));
        }
    }

    Ok(Json(RecordDetail {
        idx,
        pc: format!("{:#x}", r.pc),
        rel,
        func: None,
        off: None,
        asm: format!("{} {}", d.mnemonic, d.op_str).trim().to_string(),
        regs,
    }))
}
```

Update `rust/crates/tracemiku-server/src/routes/mod.rs`:

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

- [ ] **Step 4: Run tests — should PASS**

```bash
cd rust && cargo test -p tracemiku-server --test records_endpoint 2>&1 | tail -10 ; cd ..
```

Expected: 6 passed.

- [ ] **Step 5: cargo fmt + clippy clean**

```bash
cd rust && cargo fmt --all && cargo clippy --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-server/src/routes/ rust/crates/tracemiku-server/tests/records_endpoint.rs
git commit -m "$(cat <<'EOF'
feat(server): GET /api/record/{idx} — single-record detail

Returns idx, pc, rel, asm, all 33 regs (x0..x28, fp, lr, sp, pc, nzcv).
404 on out-of-range idx. M2-β skips prev_regs + regs_annotated; those
land in M2-γ once display.py classifier ports.

2 integration tests: happy path (full regs object), out-of-range 404.
EOF
)"
```

---

## Task 8: Frontend types + client (RecordsResponse / RecordDetail / fetchRecords)

**Files:**
- Modify: `frontend/src/api/types.ts`
- Modify: `frontend/src/api/client.ts`

- [ ] **Step 1: Append types**

Open `frontend/src/api/types.ts`. Current content has `MetaResponse` + `ModuleInfo` interfaces. Append at the bottom:

```ts
// ── /api/records, /api/record/{idx} ───────────────────────────────────────

export interface RecordRow {
  idx: number;
  pc: string;
  rel: string | null;
  module: string | null;
  func: string | null;
  off: string | null;
  asm: string;
  annotation: string | null;
  exec_count: number | null;
  is_branch: boolean;
  is_call: boolean;
  is_ret: boolean;
  regs?: Record<string, string>;
}

export interface RecordsResponse {
  start: number;
  end: number;
  count: number;
  records: RecordRow[];
}

export interface RecordDetail {
  idx: number;
  pc: string;
  rel: string | null;
  func: string | null;
  off: string | null;
  asm: string;
  regs: Record<string, string>;
}
```

- [ ] **Step 2: Append client functions**

Open `frontend/src/api/client.ts`. Current file has `fetchMeta()`. Append:

```ts
import type { RecordsResponse, RecordDetail } from "./types";

export interface FetchRecordsOpts {
  start?: number;
  count?: number;
  regs?: string;
}

export async function fetchRecords(opts: FetchRecordsOpts = {}): Promise<RecordsResponse> {
  const params = new URLSearchParams();
  if (opts.start !== undefined) params.set("start", String(opts.start));
  if (opts.count !== undefined) params.set("count", String(opts.count));
  if (opts.regs) params.set("regs", opts.regs);
  const qs = params.toString();
  const r = await fetch(`/api/records${qs ? "?" + qs : ""}`);
  if (!r.ok) throw new Error(`/api/records returned ${r.status}: ${await r.text()}`);
  return (await r.json()) as RecordsResponse;
}

export async function fetchRecord(idx: number): Promise<RecordDetail> {
  const r = await fetch(`/api/record/${idx}`);
  if (!r.ok) throw new Error(`/api/record/${idx} returned ${r.status}: ${await r.text()}`);
  return (await r.json()) as RecordDetail;
}
```

- [ ] **Step 3: Verify typecheck still passes**

```bash
cd frontend && npm run typecheck 2>&1 | tail -5 ; cd ..
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/api/types.ts frontend/src/api/client.ts
git commit -m "$(cat <<'EOF'
feat(frontend): RecordRow / RecordsResponse / RecordDetail types + client

fetchRecords({start, count, regs}) -> RecordsResponse.
fetchRecord(idx) -> RecordDetail (always includes all regs).

Wire shape matches webui/schemas.py:37-71 (Python reference). Symbol-
dependent fields typed `string | null` since M2-β emits null; populated
in M2-γ.
EOF
)"
```

---

## Task 9: Frontend RecordsPanel — paginated trace window

**Files:**
- Create: `frontend/src/panels/records/RecordsPanel.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/styles/base.css`

The panel shows a 50-record window with prev/next pagination. M4 will replace it with the proper "Trace for PC" view; M2-β just proves the data is reachable.

- [ ] **Step 1: Create RecordsPanel.tsx**

Create `frontend/src/panels/records/RecordsPanel.tsx`:

```tsx
import { createResource, createSignal, Show, For } from "solid-js";
import { fetchRecords } from "~/api/client";

const PAGE = 50;

export default function RecordsPanel() {
  const [start, setStart] = createSignal(0);
  const [resp] = createResource(
    () => start(),
    (s) => fetchRecords({ start: s, count: PAGE }),
  );

  return (
    <section class="panel">
      <h2>Records</h2>
      <Show when={resp.error}>
        <p class="err">load failed: {String(resp.error)}</p>
      </Show>
      <Show when={resp.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={resp()}>
        {(r) => (
          <>
            <div class="records-pagination">
              <button
                disabled={start() === 0}
                onClick={() => setStart(Math.max(0, start() - PAGE))}
              >prev</button>
              <span class="dim">
                showing {r().start}–{r().end} of trace
              </span>
              <button
                disabled={r().count < PAGE}
                onClick={() => setStart(r().end)}
              >next</button>
            </div>
            <table class="records-table">
              <thead>
                <tr>
                  <th>idx</th>
                  <th>pc</th>
                  <th>rel</th>
                  <th>asm</th>
                  <th>flags</th>
                </tr>
              </thead>
              <tbody>
                <For each={r().records}>
                  {(row) => (
                    <tr>
                      <td>{row.idx}</td>
                      <td><code>{row.pc}</code></td>
                      <td><code>{row.rel ?? "—"}</code></td>
                      <td><code>{row.asm}</code></td>
                      <td>
                        {row.is_call ? "📞" : ""}
                        {row.is_ret ? "↩" : ""}
                        {row.is_branch && !row.is_call && !row.is_ret ? "↳" : ""}
                      </td>
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

- [ ] **Step 2: Mount in App.tsx**

Open `frontend/src/App.tsx`. Current:

```tsx
import MetaPanel from "./panels/meta/MetaPanel";

export default function App() {
  return (
    <main class="layout">
      <header class="header">
        <h1>traceMiku v2</h1>
        <span class="dim small">analysis v2 — Rust core + Solid frontend</span>
      </header>
      <MetaPanel />
    </main>
  );
}
```

Replace with:

```tsx
import MetaPanel from "./panels/meta/MetaPanel";
import RecordsPanel from "./panels/records/RecordsPanel";

export default function App() {
  return (
    <main class="layout">
      <header class="header">
        <h1>traceMiku v2</h1>
        <span class="dim small">analysis v2 — Rust core + Solid frontend</span>
      </header>
      <MetaPanel />
      <RecordsPanel />
    </main>
  );
}
```

- [ ] **Step 3: Append CSS**

Open `frontend/src/styles/base.css`. Append (do not replace):

```css
.records-pagination {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
}

.records-pagination button {
  background: var(--bg);
  color: var(--fg);
  border: 1px solid var(--border);
  padding: 2px 8px;
  font-family: var(--font-mono);
  font-size: 12px;
  cursor: pointer;
}

.records-pagination button:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.records-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}

.records-table th,
.records-table td {
  text-align: left;
  padding: 2px 8px;
  border-bottom: 1px solid var(--border);
}

.records-table th {
  color: var(--dim);
  font-weight: normal;
}

.records-table td code {
  background: transparent;
  padding: 0;
}
```

- [ ] **Step 4: Build + typecheck**

```bash
cd frontend && npm run typecheck && npm run build 2>&1 | tail -10 ; cd ..
```

Expected: clean build; new bundle size shows the RecordsPanel chunk added (~1-2 kB delta).

- [ ] **Step 5: Smoke in dev mode**

```bash
cd rust && cargo build --release --bin tracemiku-server 2>&1 | tail -3 ; cd ..
./rust/target/release/tracemiku-server /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms --port 18900 &
SERVER_PID=$!
sleep 2

cd frontend && npm run dev > /tmp/vite-m2b.log 2>&1 &
VITE_PID=$!
sleep 4
cd ..

# Hit the proxied endpoint to confirm it works
curl -s http://127.0.0.1:5173/api/records?start=0\&count=5 | python3 -m json.tool | head -20

kill $VITE_PID $SERVER_PID 2>/dev/null
sleep 1
echo "OK"
```

Expected: curl shows JSON with `start: 0, end: 5, count: 5, records: [...]`. The 9 synth records have NOPs / bl / ret — at least one row's `is_call` should be `true`, one's `is_ret` should be `true`.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/panels/ frontend/src/App.tsx frontend/src/styles/base.css
git commit -m "$(cat <<'EOF'
feat(frontend): RecordsPanel — paginated trace window

50-record windows; prev/next buttons. Shows idx, pc, rel offset, asm,
and emoji flags (📞 call, ↩ ret, ↳ other branch). Mounted below MetaPanel.

CSS: minimal mono table with dim header + per-row border. Matches
pwndbg-style aesthetic established by base.css.
EOF
)"
```

---

## Task 10: Parity script — Rust /api/records vs Python /api/records

**Files:**
- Create: `scripts/m2_beta_parity.py`

Boots Python webui server (port 8765) + Rust server (port 18901), curls `/api/records?start=0&count=20` from each, compares the JSON subset that M2-β commits to: `idx`, `pc`, `rel`, `module`, `asm`, `is_branch`, `is_call`, `is_ret`. Symbol-dependent fields (`func`, `off`, `annotation`, `exec_count`) are explicitly ignored — they're null on Rust for M2-β; that's expected.

- [ ] **Step 1: Write the script**

Create `scripts/m2_beta_parity.py`:

```python
"""M2-β parity differ — Python /api/records vs Rust /api/records.

Boots Python webui (uvicorn) + Rust tracemiku-server side-by-side, hits
GET /api/records?start=0&count=20 on each, compares the M2-β-committed
JSON subset (idx, pc, rel, module, asm, is_branch, is_call, is_ret).

Symbol-dependent fields (func, off, annotation, exec_count) are explicitly
NOT compared — they're null on Rust for M2-β; M2-γ populates them.

Usage:
    uv run python scripts/m2_beta_parity.py <call_dir>
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

# Fields we DO compare for M2-β.
M2_BETA_FIELDS = {
    "idx", "pc", "rel", "module", "asm",
    "is_branch", "is_call", "is_ret",
}


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


def wait_listening(port: int, timeout: float = 15.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"port {port} never opened")


def fetch_records(port: int, start: int, count: int) -> dict:
    url = f"http://127.0.0.1:{port}/api/records?start={start}&count={count}"
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read())


def normalize_row(row: dict) -> dict:
    return {k: row.get(k) for k in M2_BETA_FIELDS}


def diff(py: dict, rs: dict) -> list[str]:
    out: list[str] = []
    for top_key in ("start", "end", "count"):
        if py.get(top_key) != rs.get(top_key):
            out.append(f"  top-level {top_key}: python={py.get(top_key)} rust={rs.get(top_key)}")
    py_rows = py.get("records", [])
    rs_rows = rs.get("records", [])
    if len(py_rows) != len(rs_rows):
        out.append(f"  records length: python={len(py_rows)} rust={len(rs_rows)}")
        return out
    for i, (p, r) in enumerate(zip(py_rows, rs_rows)):
        np_ = normalize_row(p)
        nr_ = normalize_row(r)
        if np_ != nr_:
            out.append(f"  row[{i}] differs:")
            for k in M2_BETA_FIELDS:
                if np_.get(k) != nr_.get(k):
                    out.append(f"    {k}: python={np_.get(k)!r} rust={nr_.get(k)!r}")
    return out


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr); sys.exit(2)
    call_dir = Path(sys.argv[1]).resolve()
    if not call_dir.exists():
        print(f"call_dir not found: {call_dir}", file=sys.stderr); sys.exit(2)

    py_port = free_port()
    rs_port = free_port()
    print(f"# M2-β parity: python={py_port} rust={rs_port} on {call_dir.name}",
          file=sys.stderr)

    # Boot Python webui.
    py_proc = subprocess.Popen(
        ["uv", "run", "python", "-m", "uvicorn",
         "webui.server:make_app", "--factory",
         "--host", "127.0.0.1", "--port", str(py_port),
         "--no-access-log"],
        cwd=REPO_ROOT,
        env={**os.environ, "TRACEMIKU_TRACE_DIR": str(call_dir)},
        preexec_fn=os.setsid,
        stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    )
    # NOTE: webui/server.py:make_app() reads the trace_dir from constructor
    # arg, not env. We rely on the wrapper script that's used by `tracemiku
    # web`. Simpler approach: invoke `tracemiku web` directly:
    py_proc.terminate(); py_proc.wait(timeout=5)
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
        py = fetch_records(py_port, 0, 20)
        rs = fetch_records(rs_port, 0, 20)
        diffs = diff(py, rs)
        if diffs:
            print("MISMATCH:", file=sys.stderr)
            for d in diffs:
                print(d, file=sys.stderr)
            sys.exit(1)
        print(f"OK — {min(len(py.get('records', [])), 20)} records match on "
              f"{', '.join(sorted(M2_BETA_FIELDS))}", file=sys.stderr)
    finally:
        for proc in (py_proc, rs_proc):
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=3)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Make executable + smoke**

```bash
chmod +x scripts/m2_beta_parity.py
# First need the rust release binary built.
cd rust && cargo build --release --bin tracemiku-server 2>&1 | tail -3 ; cd ..

uv run python scripts/m2_beta_parity.py /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms
```

Expected: `OK — 9 records match on asm, idx, is_branch, is_call, is_ret, module, pc, rel`.

If MISMATCH appears, the most likely sources:
- **`asm` differs**: Python uses capstone via Python; Rust uses capstone-rs via C library (different version). Check the actual rendered strings — minor whitespace differences. If the mnemonic itself differs (e.g., `nop` vs `hint`), bump `capstone` version in rust to match Python's. If only formatting differs, normalize both via `.split()` join.
- **`pc` differs**: hex case — Python uses lowercase, Rust formats via `{:#x}` which is also lowercase. Should match.
- **`rel` differs**: Python uses `hex()` which gives `"0x0"`, Rust uses `{:#x}` which gives `"0x0"`. Should match.
- **`module` differs**: Python's ModuleResolver may classify differently for synth trace. If only Python has `null`, the synth meta.json's module info isn't being parsed by ModuleResolver — accept this as M2-β limitation; document in commit.

If you hit unfixable differences, do NOT commit a passing parity. Report BLOCKED to the controller with the diff output; we'll either fix Rust or relax the comparison set.

- [ ] **Step 3: Commit**

```bash
git add scripts/m2_beta_parity.py
git commit -m "$(cat <<'EOF'
test(m2): parity differ for /api/records — Python vs Rust JSON subset

Boots both webui (Python) and tracemiku-server (Rust) on free ports,
hits /api/records?start=0&count=20 on each, compares the M2-β-committed
JSON fields (idx, pc, rel, module, asm, is_branch/call/ret).

Symbol-dependent fields (func, off, annotation, exec_count) are
explicitly excluded — they're null on Rust for M2-β; populated in M2-γ.
EOF
)"
```

---

## Task 11: Update parity matrix + TODO.md

**Files:**
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`
- Modify: `TODO.md`

- [ ] **Step 1: Update §13.2 disasm.py row in spec**

Find the line (around line 393):

```
| `disasm.py` (capstone wrapper, decode, def/use) | `tracemiku-core::disasm` | 🔜 M2 | capstone-rs |
```

Replace with:

```
| `disasm.py` (capstone wrapper, decode, def/use) | `tracemiku-core::disasm` | 🟡 M2-β: decode + classify done; def/use M2-γ | capstone-rs 0.13; thread-local FIFO cache (200k); 11 unit tests + scripts/m2_beta_parity.py |
```

- [ ] **Step 2: Update §13.5 /api/records and /api/record/{idx} rows**

Find the lines (around lines 481-482):

```
| `/api/records?from=&to=` | 🔜 M3 | |
| `/api/record/{idx}` | 🔜 M3 | |
```

Replace with:

```
| `/api/records?start=&count=` | ✅ M2-β | symbol-dependent fields (func/off/annotation/exec_count) emitted null until M2-γ |
| `/api/record/{idx}` | ✅ M2-β | full regs object; prev_regs + regs_annotated deferred to M2-γ |
```

(Note the query-string fix: `?from=&to=` was wrong in the original spec — Python uses `?start=&count=`.)

- [ ] **Step 3: Update TODO.md M2 progress**

Find the M2-β line in `TODO.md` (added during M2-α Task 10):

```markdown
- M2-β (next): capstone-rs disasm + Index + CFG + /api/records + /api/cfg + RecordsPanel
```

Replace with three concrete-status bullets:

```markdown
- M2-β `tracemiku-core::disasm` (capstone wrapper + thread-local FIFO cache 200k): ✅ 2026-05-04
- M2-β `/api/records` + `/api/record/{idx}` (subset wire shape; symbol-fields null): ✅ 2026-05-04
- M2-β frontend `RecordsPanel` (paginated 50-record windows): ✅ 2026-05-04
```

- [ ] **Step 4: Final verification**

```bash
cd rust && cargo test --workspace 2>&1 | tail -5 ; cd ..
cd frontend && npm run typecheck && npm run build 2>&1 | tail -5 ; cd ..
uv run python scripts/m2_alpha_parity.py /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms 2>&1 | tail -2
uv run python scripts/m2_beta_parity.py /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms 2>&1 | tail -2
```

Expected:
- cargo test: all pass (likely ~25 tests across crates)
- npm build: clean
- m2_alpha parity: `OK`
- m2_beta parity: `OK`

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md TODO.md
git commit -m "$(cat <<'EOF'
docs(v2): mark M2-β complete in parity matrix + TODO.md

§13.2 disasm.py → 🟡 M2-β (decode+classify done; def/use deferred to M2-γ).
§13.5 /api/records + /api/record/{idx} → ✅ M2-β. Spec query-string
corrected from ?from=&to= to ?start=&count= (matches Python webui).

TODO.md: M2-β bullets concrete (disasm cache, two endpoints, RecordsPanel).
Both M2-α and M2-β parity scripts pass on synth trace.

Next: M2-γ — Index (def-use) + CFG + SymbolMap + /api/cfg + Graph panel.
EOF
)"
```

---

## Self-Review

**1. Spec coverage:**

| Spec section | Covered by |
|---|---|
| §3 Architecture (capstone + thread-local cache) | Tasks 1, 2, 4 |
| §4 Data structures (DecodedInsn) | Task 1 (skeleton), Task 2 (full) |
| §5 API surface (`/api/records`, `/api/record/{idx}`) | Tasks 6, 7 |
| §6 Frontend architecture (per-panel folders) | Task 9 |
| §11 Decisions D-relevant (D5 capstone-rs over python disasm; D11 thread-local handle) | Tasks 1, 2 |
| §13.2 disasm.py row | Task 11 |
| §13.5 /api/records + /api/record/{idx} rows | Task 11 |
| §8 Testing (cargo test green + parity script) | Tasks 2, 3, 4, 5, 6, 7, 10 |

Out-of-scope (deferred to M2-γ+):
- def_use extraction (mem_op, regs_def/regs_use, branch_target)
- SymbolMap → populating `func`, `off`, `annotation`
- CFG → populating `exec_count`
- prev_regs + regs_annotated for /api/record/{idx} detail

**2. Placeholder scan:** No `TBD`, `TODO`, `implement later`, `similar to Task N`. All code blocks complete; all test code present in full.

**3. Type consistency:**
- `DecodedInsn` field set: `pc, inst, mnemonic, op_str, is_branch, is_call, is_ret` — referenced consistently across Tasks 1 (skeleton), 2 (full), 4 (cache), 5 (real-trace), 6 (records handler), 7 (record handler).
- `RecordRow` (Rust struct in Task 6) ↔ `RecordRow` (TS interface in Task 8) — same field names, same nullability semantics. `regs` is `Option<BTreeMap>` in Rust serializing to `Record<string, string>` in TS, with `skip_serializing_if Option::is_none` on Rust → TS sees field absent (matching `regs?:` in TS).
- `RecordsResponse` (Rust struct Task 6) ↔ `RecordsResponse` (TS interface Task 8) — both have `start, end, count, records`.
- `RecordDetail` (Rust struct Task 7, BTreeMap regs always present) ↔ `RecordDetail` (TS interface Task 8, `regs: Record<string, string>` required not optional). Match.
- `is_branch_mnem`, `is_call_mnem`, `is_ret_mnem` — names consistent between Tasks 2 (definition) and 3 (test sweep) and 6 (used via `decode().is_branch` etc.).

**4. Atomic deliverable check:** Task 10's `scripts/m2_beta_parity.py` printing `OK` is the M2-β completion gate. Task 9's frontend smoke (Step 5: curl through Vite proxy) is the user-visible deliverable. Both must pass for M2-β to be considered complete.

**5. Risk flag:** Task 6's `synth_call_dir()` rewrites the existing M1 fixture (which wrote empty trace.bin). The current `tests/meta_endpoint.rs::synth_call_dir()` (added in M1 Task 8) writes empty trace.bin; Task 6 introduces a SEPARATE fixture in `tests/records_endpoint.rs` that writes 9 records. The two fixtures don't share code — that's fine for test isolation. If a refactor consolidates them later, M2-γ can do it. Don't preemptively unify.

---

**Plan complete and saved to `docs/superpowers/plans/2026-05-04-analysis-v2-m2-beta.md`.**

Two execution options:

**1. Subagent-Driven (recommended)** — fresh subagent per task with two-stage review between. Same workflow as M0+M1 and M2-α.

**2. Inline Execution** — execute in this session with checkpoints.

**Which approach?**
