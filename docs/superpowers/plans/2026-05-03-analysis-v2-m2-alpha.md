# Analysis v2 — M2-α Implementation Plan (Trace foundation)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the foundational `Record` + `Trace` types in `tracemiku-core` that mmap a real `trace.bin`, expose zero-copy iteration over fixed-272-byte records, and prove parity with Python's `viewer.trace` on the 4.2 GB / 15.4M-record real-trace fixture. Atomic deliverable: `cargo run --bin tracemiku-cli -- stats traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms` outputs JSON whose `records` field equals `15426904` (counted from mmap, not just read from meta.json) AND matches `python -m viewer stats <same path>` field-by-field via the `scripts/m2_alpha_parity.py` differ.

**Architecture:** Add `memmap2` + `bytemuck` deps to `tracemiku-core`. Define `Record` as a `#[repr(C)] Pod` struct exactly 272 bytes (compile-time size assertion). `Trace` opens a per-call dir, mmaps `trace.bin`, validates that `len % 272 == 0`, exposes `len()`, `record(idx)`, `pc(idx)` fast-path, and an iterator. Wire it into `tracemiku-cli stats` (replacing the M1 stub's TraceMeta-only output) so the CLI binary becomes the parity-test surface for Python's `viewer stats`. No changes to the server or frontend in this milestone — that comes in M2-β when disasm lands and `/api/records` can return decoded rows.

**Tech Stack:** Rust 1.95, memmap2 0.9, bytemuck 1.x with `derive` feature for the `Pod` trait, anyhow for CLI errors. No new server / frontend deps.

**Spec:** `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` (read §4 "Data structures" and §13.2 trace.py row before starting). Wire contract for `RawRecord` JSON shape (this plan's deliverable) is defined inline in Task 8 — there is no separate /api/* endpoint contract for this milestone.

**M2 split:** This is **plan 2 of an expected 4** covering M2:
- **M2-α (this plan)**: Trace + Record foundation, CLI stats parity. ~10 tasks.
- **M2-β** (next): capstone-rs disasm + Index (def-use) + CFG (petgraph) + `/api/records` and `/api/cfg` endpoints + frontend RecordsPanel.
- **M2-γ**: MemShadow + taint (forward + backward + cross-fn-call frame_depth) + symbols + calltree.
- **M2-δ**: FunctionIndex port + decompiler::backend stub + final M2 parity validation.

Splitting keeps each plan to roughly the same density as M0+M1 (10-12 tasks, ~1500-2000 plan LOC). Each split produces working, testable software on its own.

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-core/Cargo.toml` (modify) | Add `memmap2.workspace = true` and `bytemuck.workspace = true` to `[dependencies]`. The workspace already pins both. |
| `rust/crates/tracemiku-core/src/trace/mod.rs` (modify) | Extend module declarations: add `pub mod record; pub mod trace;` plus re-export `Record, Trace, REC_SIZE`. |
| `rust/crates/tracemiku-core/src/trace/record.rs` (new) | `Record` POD struct (272 bytes, 33 u64 + 2 u32), `REC_SIZE` const, `REC_NUM_REGS` const, register-name accessors. |
| `rust/crates/tracemiku-core/src/trace/trace.rs` (new) | `Trace` struct: opens per-call dir, mmaps `trace.bin`, validates layout, exposes `len()`, `record(idx)`, `pc(idx)`, `inst(idx)`, `iter()`. |
| `rust/crates/tracemiku-core/src/prelude.rs` (modify) | Add `pub use crate::trace::{Trace, Record, REC_SIZE};`. |
| `rust/crates/tracemiku-core/tests/common/mod.rs` (modify) | Add `synth_trace_dir()` builder: writes 9 hand-crafted records to a tempdir (matches `scripts/build_smoke_trace.py` shape but vendored as Rust). |
| `rust/crates/tracemiku-core/tests/trace_parser.rs` (new) | Integration tests for `Trace::load` + `Record` accessors using the synth fixture. |
| `rust/crates/tracemiku-core/tests/real_trace.rs` (new) | `#[ignore]` integration test that loads `traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms` and asserts `trace.len() == 15_426_904`. Run via `cargo test --ignored`. |
| `rust/crates/tracemiku-cli/Cargo.toml` (modify) | No deps change needed (anyhow + serde_json + tracemiku-core already there). Add comment noting M2-α extends `stats`. |
| `rust/crates/tracemiku-cli/src/main.rs` (modify) | `stats` subcommand: load `Trace` (not just `TraceMeta`), emit JSON with `records=trace.len()` + the M1 TraceMeta fields + `modules_total` + `modules_truncated`. New `--all-modules` and `--top-modules N` flags to mirror Python. |
| `scripts/m2_alpha_parity.py` (new) | Parity differ: runs `python -m viewer stats <call_dir>` and `cargo run --bin tracemiku-cli -- stats <call_dir>`, parses both outputs, compares field-by-field, fails on any mismatch. |
| `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md` (modify) | Update §13.2 `trace.py` row from `🟡 M1: TraceMeta done; full Trace mmap M2` to `✅ M2-α (records mmap + parity)`. |
| `TODO.md` (modify) | Append M2-α completion bullets under existing `## 🚧 进行中 (2026-05-03 — Analysis v2)` section. |

---

## Task 1: Add memmap2 + bytemuck deps to tracemiku-core

**Files:**
- Modify: `rust/crates/tracemiku-core/Cargo.toml`

The workspace `Cargo.toml` already pins `memmap2 = "0.9"` and `bytemuck = { version = "1", features = ["derive"] }`, but `tracemiku-core/Cargo.toml` does not yet pull them. Tasks 2-3 fail to compile without them, so this is the first dependency edit.

- [ ] **Step 1: Append the two deps to `[dependencies]`**

Open `rust/crates/tracemiku-core/Cargo.toml`. Find the `[dependencies]` block. After the existing `tracing.workspace = true` line, append:

```toml
memmap2.workspace = true
bytemuck.workspace = true
```

Final `[dependencies]` block should look like:

```toml
[dependencies]
anyhow.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tracing.workspace = true
memmap2.workspace = true
bytemuck.workspace = true

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 2: Verify build still passes**

```bash
cd rust && cargo build -p tracemiku-core 2>&1 | tail -3 ; cd ..
```

Expected: `Finished \`dev\` profile [optimized + debuginfo] target(s) in N.NNs`. If cargo reports unused deps, that's fine — Tasks 2-3 will use them.

- [ ] **Step 3: Commit**

```bash
git add rust/crates/tracemiku-core/Cargo.toml
git commit -m "build(core): add memmap2 + bytemuck deps for Trace mmap parser"
```

---

## Task 2: Define Record POD struct (TDD)

**Files:**
- Create: `rust/crates/tracemiku-core/src/trace/record.rs`
- Modify: `rust/crates/tracemiku-core/src/trace/mod.rs`

The trace.bin record layout is committed-contract (`docs/PER_CALL_TRACE_DESIGN.md` and Python's `viewer/trace.py:15-22`). 272 bytes per record:

```
offset 0:    pc        (u64)
offset 8:    x0..x30   (31 × u64 — x0..x28 + fp + lr)
offset 256:  sp        (u64)
offset 264:  nzcv      (u32)
offset 268:  inst      (u32)  // raw 4-byte ARM64 little-endian
total: 272 bytes, 8-byte aligned
```

- [ ] **Step 1: Write the failing test**

Append to `rust/crates/tracemiku-core/tests/common/mod.rs` (file already exists from Task 7 of M0+M1):

```rust
// re-export of the helper module currently defined; existing helpers stay.
```

(No edit needed yet — Task 4 adds the synth_trace_dir fixture. For Task 2 the test lives directly in the unit-test module of `record.rs`.)

Create `rust/crates/tracemiku-core/src/trace/record.rs` with this initial empty-but-compilable shell so the test target exists:

```rust
//! 272-byte fixed-layout trace record.
//!
//! On-disk layout matches the Frida agent's emit: `[pc, x0..x28, fp, lr, sp,
//! nzcv, inst]` where every register slot is u64 little-endian and `nzcv` /
//! `inst` are u32. Total 272 bytes (33 × 8 + 2 × 4). Layout is a committed
//! contract — see `docs/PER_CALL_TRACE_DESIGN.md`.

use bytemuck::{Pod, Zeroable};

/// Bytes per record. Stable across all trace.bin files this codebase reads.
pub const REC_SIZE: usize = 272;

/// Number of u64 register slots stored per record (x0..x28 + fp + lr).
pub const REC_NUM_REGS: usize = 31;

#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable, Debug)]
pub struct Record {
    pub pc: u64,
    pub regs: [u64; REC_NUM_REGS],
    pub sp: u64,
    pub nzcv: u32,
    pub inst: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    #[test]
    fn record_size_is_272() {
        assert_eq!(size_of::<Record>(), REC_SIZE,
                   "Record must be exactly 272 bytes — on-disk contract");
    }

    #[test]
    fn record_alignment_is_8() {
        assert_eq!(align_of::<Record>(), 8,
                   "Record must be 8-byte aligned for bytemuck::cast_slice from u8 mmap slice");
    }

    #[test]
    fn record_field_offsets() {
        // Verify the field offsets match the wire layout.
        let r = Record::zeroed();
        let base = &r as *const Record as usize;
        assert_eq!(&r.pc as *const _ as usize - base, 0);
        assert_eq!(&r.regs as *const _ as usize - base, 8);
        assert_eq!(&r.sp as *const _ as usize - base, 8 + 31 * 8);  // 256
        assert_eq!(&r.nzcv as *const _ as usize - base, 264);
        assert_eq!(&r.inst as *const _ as usize - base, 268);
    }
}
```

Then update `rust/crates/tracemiku-core/src/trace/mod.rs`. Current content:

```rust
//! Trace-side data structures. M1 has only metadata; M2 adds the
//! actual `Trace` (mmap'd record stream).

pub mod meta;

pub use meta::{TraceMeta, ModuleInfo, CallInfo, MetaError};
```

Replace with:

```rust
//! Trace-side data structures.
//!
//! - [`meta`] — meta.json parser (M1)
//! - [`record`] — 272-byte on-disk record layout (M2-α)
//! - `trace` — mmap'd record stream (M2-α, added by Task 3)

pub mod meta;
pub mod record;

pub use meta::{TraceMeta, ModuleInfo, CallInfo, MetaError};
pub use record::{Record, REC_SIZE, REC_NUM_REGS};
```

- [ ] **Step 2: Run the test — should PASS**

```bash
cd rust && cargo test -p tracemiku-core --lib trace::record 2>&1 | tail -10 ; cd ..
```

Expected: `test result: ok. 3 passed; 0 failed`.

If `record_size_is_272` fails: padding from a misordered field. The order in the struct above (pc, regs, sp, nzcv, inst) places the two u32s (nzcv, inst) at the end which packs into 8 bytes naturally. Do not rearrange.

If the `Pod` derive complains: bytemuck's safety check. Confirm `[u64; 31]` doesn't introduce padding — it shouldn't on any sane target since u64 alignment is 8 and the array is 248 bytes (31 × 8).

- [ ] **Step 3: Add register-name accessor**

Append to `rust/crates/tracemiku-core/src/trace/record.rs` (after the `Record` struct, before the `#[cfg(test)] mod tests`):

```rust
impl Record {
    /// Read register by canonical name. Returns `None` if name is not one of
    /// `x0..x28`, `fp`, `lr`, `sp`, `pc`, `nzcv`. Mirrors Python `Record.reg`.
    pub fn reg(&self, name: &str) -> Option<u64> {
        match name {
            "pc" => Some(self.pc),
            "sp" => Some(self.sp),
            "nzcv" => Some(self.nzcv as u64),
            "fp" => Some(self.regs[29]),
            "lr" => Some(self.regs[30]),
            _ => {
                // x0..x28
                if let Some(rest) = name.strip_prefix('x') {
                    if let Ok(i) = rest.parse::<usize>() {
                        if i <= 28 {
                            return Some(self.regs[i]);
                        }
                    }
                }
                None
            }
        }
    }
}
```

Append a test inside the `mod tests` block (before the closing `}`):

```rust
    #[test]
    fn reg_lookup_by_name() {
        let mut r = Record::zeroed();
        r.pc = 0x100200;
        r.regs[0] = 0xdead;     // x0
        r.regs[28] = 0xbeef;    // x28
        r.regs[29] = 0xcafe;    // fp
        r.regs[30] = 0xbabe;    // lr
        r.sp = 0xfffe;
        r.nzcv = 0b1010;

        assert_eq!(r.reg("pc"), Some(0x100200));
        assert_eq!(r.reg("x0"), Some(0xdead));
        assert_eq!(r.reg("x28"), Some(0xbeef));
        assert_eq!(r.reg("fp"), Some(0xcafe));
        assert_eq!(r.reg("lr"), Some(0xbabe));
        assert_eq!(r.reg("sp"), Some(0xfffe));
        assert_eq!(r.reg("nzcv"), Some(0b1010));
        assert_eq!(r.reg("x29"), None, "x29 (fp alias) not supported by name");
        assert_eq!(r.reg("xx"), None);
        assert_eq!(r.reg(""), None);
    }
```

- [ ] **Step 4: Re-run tests**

```bash
cd rust && cargo test -p tracemiku-core --lib trace::record 2>&1 | tail -10 ; cd ..
```

Expected: `test result: ok. 4 passed; 0 failed`.

- [ ] **Step 5: cargo fmt + clippy clean**

```bash
cd rust && cargo fmt --all && cargo clippy -p tracemiku-core --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-core/src/trace/
git commit -m "$(cat <<'EOF'
feat(core): Record POD struct — 272-byte on-disk trace record

#[repr(C)] + bytemuck::Pod for zero-copy mmap cast. Layout asserted at
compile time via size_of/align_of tests. Field offsets verified against
the on-disk wire contract (pc=0, regs=8, sp=256, nzcv=264, inst=268).

Public REC_SIZE / REC_NUM_REGS constants. Record::reg(name) accessor
mirrors Python viewer.trace.Record.reg, returning Option for unknown
names instead of raising KeyError.
EOF
)"
```

---

## Task 3: Trace::load — open + mmap + validate

**Files:**
- Create: `rust/crates/tracemiku-core/src/trace/trace.rs`
- Modify: `rust/crates/tracemiku-core/src/trace/mod.rs`

`Trace` opens a per-call directory, locates `trace.bin`, mmaps it, validates that `file_size % 272 == 0`, and stores a `Mmap` plus the record count. No record-access methods yet — Task 5 adds those.

- [ ] **Step 1: Write the failing integration test**

Modify `rust/crates/tracemiku-core/tests/common/mod.rs` to add a `synth_trace_dir()` helper. The current file (post-M0+M1) has only `synth_meta_only_dir()`. Append (do not replace):

```rust
/// Build a synth per-call trace dir with N records of all-zero registers
/// + monotonically-increasing PCs. Used by Task 3+ tests.
pub fn synth_trace_dir(num_records: usize) -> SynthFixture {
    use std::io::Write;

    let tmp = tempfile::tempdir().expect("mkdtemp");
    let run = tmp.path().join("run");
    fs::create_dir(&run).unwrap();
    fs::create_dir(run.join("calls")).unwrap();
    let cd = run.join("calls").join(format!("call_001_tid100_{}r_2ms", num_records));
    fs::create_dir(&cd).unwrap();

    // Write `num_records` records of 272 bytes each. PC = 0x100000 + 4*i,
    // all regs zero, sp = 0x7000, nzcv = 0, inst = 0xd503201f (NOP).
    let mut bf = fs::File::create(cd.join("trace.bin")).unwrap();
    for i in 0..num_records {
        let mut buf = [0u8; 272];
        let pc = 0x100000u64 + 4 * (i as u64);
        buf[0..8].copy_from_slice(&pc.to_le_bytes());
        // regs[0..31] already zero
        let sp = 0x7000u64;
        buf[256..264].copy_from_slice(&sp.to_le_bytes());
        // nzcv (264..268) = 0
        let inst = 0xd503201fu32; // NOP
        buf[268..272].copy_from_slice(&inst.to_le_bytes());
        bf.write_all(&buf).unwrap();
    }

    let per_call = serde_json::json!({
        "callIdx": 1, "tid": 100, "records": num_records, "ms": 2,
        "retval": "0x0", "truncated": false,
        "last_insn_is_ret": true,
    });
    fs::write(cd.join("meta.json"),
              serde_json::to_string_pretty(&per_call).unwrap()).unwrap();

    let run_meta = serde_json::json!({
        "pkg": "tst", "so": "libt", "method": "f", "cmd": 1,
        "module": {"name": "libt.so", "base": "0x100000", "size": 0x10000},
        "fn_addr": "0x100000"
    });
    fs::write(run.join("meta.json"),
              serde_json::to_string_pretty(&run_meta).unwrap()).unwrap();

    SynthFixture { _tmp: tmp, call_dir: cd }
}
```

Create `rust/crates/tracemiku-core/tests/trace_parser.rs`:

```rust
mod common;

use tracemiku_core::prelude::*;

#[test]
fn loads_synth_trace_with_9_records() {
    let fix = common::synth_trace_dir(9);
    let trace = Trace::load(&fix.call_dir).expect("load synth trace");
    assert_eq!(trace.len(), 9);
}

#[test]
fn loads_empty_trace_zero_records() {
    let fix = common::synth_trace_dir(0);
    let trace = Trace::load(&fix.call_dir).expect("load empty trace");
    assert_eq!(trace.len(), 0);
}

#[test]
fn rejects_truncated_trace_bin() {
    use std::fs::OpenOptions;
    use std::io::Write;
    let fix = common::synth_trace_dir(3);
    // Append 5 stray bytes — total file size is no longer a multiple of 272.
    let mut f = OpenOptions::new().append(true).open(fix.call_dir.join("trace.bin")).unwrap();
    f.write_all(b"\x00\x01\x02\x03\x04").unwrap();
    drop(f);

    let err = Trace::load(&fix.call_dir).expect_err("truncated trace must fail");
    let msg = format!("{err:#}");
    assert!(msg.contains("not a multiple of 272") || msg.contains("REC_SIZE"),
            "error should explain layout violation, got: {msg}");
}

#[test]
fn missing_trace_bin_yields_error() {
    let fix = common::synth_trace_dir(3);
    std::fs::remove_file(fix.call_dir.join("trace.bin")).unwrap();
    let err = Trace::load(&fix.call_dir).expect_err("missing trace.bin must fail");
    let msg = format!("{err:#}");
    assert!(msg.contains("trace.bin"), "error should mention trace.bin, got: {msg}");
}
```

- [ ] **Step 2: Run tests — should FAIL with "Trace does not exist"**

```bash
cd rust && cargo test -p tracemiku-core --test trace_parser 2>&1 | tail -10 ; cd ..
```

Expected: compile error: `Trace`/`Trace::load` not found.

- [ ] **Step 3: Implement Trace**

Create `rust/crates/tracemiku-core/src/trace/trace.rs`:

```rust
//! Memory-mapped trace.bin reader.
//!
//! Opens `<call_dir>/trace.bin`, mmaps it, validates that the file size is a
//! multiple of [`REC_SIZE`], and exposes record access by index. Zero-copy:
//! `record(idx)` returns a `Record` value bytemuck-cast from the mmap slice
//! without any allocation.

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use memmap2::Mmap;

use crate::trace::record::{Record, REC_SIZE};

/// Memory-mapped per-call trace.
pub struct Trace {
    call_dir: PathBuf,
    /// Owned mmap; lives as long as `Trace`. Drop closes the underlying fd.
    mmap: Mmap,
    /// `mmap.len() / REC_SIZE`. Cached at construction.
    n: usize,
}

impl Trace {
    /// Open `<call_dir>/trace.bin` and mmap it. Validates that the file size
    /// is a multiple of [`REC_SIZE`].
    pub fn load(call_dir: &Path) -> Result<Self> {
        let bin = call_dir.join("trace.bin");
        let f = File::open(&bin)
            .with_context(|| format!("open trace.bin at {}", bin.display()))?;
        let len = f.metadata()
            .with_context(|| format!("stat trace.bin at {}", bin.display()))?
            .len() as usize;

        if len == 0 {
            // mmap on a 0-byte file is not portable. Construct an empty trace
            // by mmaping anyway with workaround? memmap2 allows MmapOptions.
            // Simpler: bail out early with a synthetic empty mmap.
            return Ok(Self {
                call_dir: call_dir.to_path_buf(),
                mmap: empty_mmap()?,
                n: 0,
            });
        }

        if len % REC_SIZE != 0 {
            return Err(anyhow!(
                "trace.bin size {} is not a multiple of {} (REC_SIZE) — \
                 corrupted trace or truncated write",
                len, REC_SIZE,
            ));
        }

        // SAFETY: we own the file, the mmap is read-only, and Mmap will keep
        // the underlying fd alive via its internal handle.
        let mmap = unsafe { Mmap::map(&f) }
            .with_context(|| format!("mmap trace.bin at {}", bin.display()))?;

        Ok(Self {
            call_dir: call_dir.to_path_buf(),
            n: len / REC_SIZE,
            mmap,
        })
    }

    /// Number of records in the trace.
    pub fn len(&self) -> usize { self.n }

    /// True iff `len() == 0`.
    pub fn is_empty(&self) -> bool { self.n == 0 }

    /// Per-call directory this trace was loaded from.
    pub fn call_dir(&self) -> &Path { &self.call_dir }

    /// Raw mmap bytes (read-only). Exposed for tests that need to verify
    /// on-disk content; production code should prefer `record(i)`.
    #[doc(hidden)]
    pub fn raw(&self) -> &[u8] { &self.mmap }
}

/// Build a 0-length mmap for empty-file traces. Memmap2 doesn't allow mmap
/// of zero-length files, so we mmap a single-page anonymous region and
/// claim length 0 via slice subscripting at access time (since we never
/// access record(i) when n=0, this region is never read).
fn empty_mmap() -> Result<Mmap> {
    use memmap2::MmapOptions;
    // Map a 1-byte anonymous region; we won't use it.
    let mmap = MmapOptions::new().len(1).map_anon()
        .context("alloc anon mmap for empty trace placeholder")?;
    // Convert MmapMut → Mmap via make_read_only.
    Ok(mmap.make_read_only().context("make placeholder mmap read-only")?)
}

// Suppress `call_dir` field-unused warnings until Task 6 reads it.
#[allow(dead_code)]
fn _trace_field_use(t: &Trace) -> &Path { t.call_dir() }
```

Then update `rust/crates/tracemiku-core/src/trace/mod.rs` to declare and re-export `trace`:

```rust
//! Trace-side data structures.
//!
//! - [`meta`] — meta.json parser (M1)
//! - [`record`] — 272-byte on-disk record layout (M2-α)
//! - [`trace`] — mmap'd record stream (M2-α)

pub mod meta;
pub mod record;
pub mod trace;

pub use meta::{TraceMeta, ModuleInfo, CallInfo, MetaError};
pub use record::{Record, REC_SIZE, REC_NUM_REGS};
pub use trace::Trace;
```

Also update `rust/crates/tracemiku-core/src/prelude.rs` to add `Trace`:

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

- [ ] **Step 4: Run tests — should PASS (4 of them)**

```bash
cd rust && cargo test -p tracemiku-core --test trace_parser 2>&1 | tail -10 ; cd ..
```

Expected: `test result: ok. 4 passed; 0 failed`.

If `loads_empty_trace_zero_records` fails because `Mmap::map_anon` lacks `make_read_only`: switch to `MmapMut::map_anon`+`make_read_only` (memmap2 ≥ 0.7 supports this). If still failing, replace `empty_mmap` with the simpler approach: store `Option<Mmap>` and treat `None` as length-0:

```rust
pub struct Trace {
    call_dir: PathBuf,
    mmap: Option<Mmap>,
    n: usize,
}
// ...later, raw() returns &[] when None
```

Pick whichever the available memmap2 version supports cleanly. Both pass the test.

- [ ] **Step 5: cargo fmt + clippy clean**

```bash
cd rust && cargo fmt --all && cargo clippy -p tracemiku-core --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-core/src/trace/ rust/crates/tracemiku-core/tests/
git commit -m "$(cat <<'EOF'
feat(core): Trace::load — mmap + layout validation

memmap2 read-only mmap of <call_dir>/trace.bin. Validates that file size
is a multiple of REC_SIZE; rejects truncated traces with a clear error.
Empty (0-byte) trace handled via anonymous mmap placeholder so n=0 is
representable without Option<Mmap> noise in callers.

4 integration tests cover: 9-record load, 0-record edge case, truncated
file rejection, missing trace.bin error.
EOF
)"
```

---

## Task 4: Trace::record(idx) — zero-copy bytemuck cast

**Files:**
- Modify: `rust/crates/tracemiku-core/src/trace/trace.rs`
- Modify: `rust/crates/tracemiku-core/tests/trace_parser.rs`

`Trace::record(idx)` returns a `Record` by value, copying 272 bytes from the mmap. Cheap — capstone-rs in M2-β will operate on the raw `inst` u32 directly, no need for &Record references.

- [ ] **Step 1: Add the failing test**

Append to `rust/crates/tracemiku-core/tests/trace_parser.rs`:

```rust
#[test]
fn record_idx_returns_correct_pc() {
    let fix = common::synth_trace_dir(5);
    let t = Trace::load(&fix.call_dir).unwrap();

    // Synth fixture writes pc = 0x100000 + 4*i.
    assert_eq!(t.record(0).pc, 0x100000);
    assert_eq!(t.record(1).pc, 0x100004);
    assert_eq!(t.record(4).pc, 0x100010);
    assert_eq!(t.record(0).inst, 0xd503201f); // NOP
    assert_eq!(t.record(0).sp, 0x7000);
    assert_eq!(t.record(0).regs[0], 0);  // synth fixture writes zeros
}

#[test]
fn record_idx_out_of_range_panics() {
    let fix = common::synth_trace_dir(3);
    let t = Trace::load(&fix.call_dir).unwrap();

    let r = std::panic::catch_unwind(|| t.record(3));
    assert!(r.is_err(), "record(len()) must panic with index out of bounds");
}

#[test]
fn pc_fast_path_matches_record_pc() {
    let fix = common::synth_trace_dir(5);
    let t = Trace::load(&fix.call_dir).unwrap();
    for i in 0..t.len() {
        assert_eq!(t.pc(i), t.record(i).pc, "pc fast path must agree at idx {i}");
    }
}

#[test]
fn inst_fast_path_matches_record_inst() {
    let fix = common::synth_trace_dir(5);
    let t = Trace::load(&fix.call_dir).unwrap();
    for i in 0..t.len() {
        assert_eq!(t.inst(i), t.record(i).inst);
    }
}
```

- [ ] **Step 2: Run — failing red**

```bash
cd rust && cargo test -p tracemiku-core --test trace_parser 2>&1 | tail -15 ; cd ..
```

Expected: 4 of the 8 tests fail (compile error: `record` / `pc` / `inst` methods don't exist).

- [ ] **Step 3: Implement record/pc/inst accessors**

Append to the `impl Trace` block in `rust/crates/tracemiku-core/src/trace/trace.rs` (right after `pub fn raw(...)`):

```rust
    /// Read record at index `i`. Panics if `i >= len()`.
    ///
    /// Zero-copy: bytemuck-casts the relevant 272-byte slice directly. The
    /// returned `Record` is a stack-allocated value; mutating it does not
    /// affect the mmap.
    pub fn record(&self, i: usize) -> Record {
        let off = i.checked_mul(REC_SIZE)
            .expect("record index overflow");
        let end = off.checked_add(REC_SIZE)
            .expect("record offset+size overflow");
        let slice = &self.mmap[off..end];
        // bytemuck::from_bytes verifies size + alignment at runtime.
        *bytemuck::from_bytes::<Record>(slice)
    }

    /// Fast PC-only path. Avoids constructing a full `Record`. Useful for
    /// scans where only PC matters (e.g. `idxs-for-pc`).
    pub fn pc(&self, i: usize) -> u64 {
        let off = i * REC_SIZE;
        u64::from_le_bytes(self.mmap[off..off + 8].try_into().unwrap())
    }

    /// Fast inst-only path. Returns the raw 4-byte ARM64 little-endian
    /// instruction word. Capstone will decode this in M2-β.
    pub fn inst(&self, i: usize) -> u32 {
        let off = i * REC_SIZE + 268;
        u32::from_le_bytes(self.mmap[off..off + 4].try_into().unwrap())
    }
```

The `i` bounds check is implicit via the slice index — accessing `self.mmap[off..end]` with `i >= self.n` will panic with "index out of bounds", which is what `record_idx_out_of_range_panics` asserts.

Add `use crate::trace::record::REC_SIZE;` near the top of `trace.rs` (it's already imported via the existing `use crate::trace::record::{Record, REC_SIZE};` from Task 3). Also import `bytemuck` is automatic via the prelude / direct path.

- [ ] **Step 4: Run tests — green**

```bash
cd rust && cargo test -p tracemiku-core --test trace_parser 2>&1 | tail -10 ; cd ..
```

Expected: `test result: ok. 8 passed; 0 failed`.

- [ ] **Step 5: cargo fmt + clippy clean**

```bash
cd rust && cargo fmt --all && cargo clippy -p tracemiku-core --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-core/src/trace/trace.rs rust/crates/tracemiku-core/tests/trace_parser.rs
git commit -m "$(cat <<'EOF'
feat(core): Trace::record / pc / inst accessors — bytemuck zero-copy

record(i) bytemuck-casts the 272-byte mmap slice into Record by value
(stack-allocated; no heap). pc(i) and inst(i) skip the cast for hot
scan paths that only need one field.

Out-of-bounds access panics via the natural slice index, matching the
Python `Trace.record(i)` IndexError contract.
EOF
)"
```

---

## Task 5: Trace::iter — sequential record iterator

**Files:**
- Modify: `rust/crates/tracemiku-core/src/trace/trace.rs`
- Modify: `rust/crates/tracemiku-core/tests/trace_parser.rs`

A no-allocation iterator simplifies sequential walks (Task 8 CLI stats does this; Task 9 parity script's Python side does `for r in trace: ...`).

- [ ] **Step 1: Add the test**

Append to `rust/crates/tracemiku-core/tests/trace_parser.rs`:

```rust
#[test]
fn iter_visits_every_record_in_order() {
    let fix = common::synth_trace_dir(7);
    let t = Trace::load(&fix.call_dir).unwrap();

    let pcs: Vec<u64> = t.iter().map(|r| r.pc).collect();
    let expected: Vec<u64> = (0..7).map(|i| 0x100000 + 4 * i as u64).collect();
    assert_eq!(pcs, expected);
}

#[test]
fn iter_count_matches_len() {
    let fix = common::synth_trace_dir(13);
    let t = Trace::load(&fix.call_dir).unwrap();
    assert_eq!(t.iter().count(), t.len());
}

#[test]
fn iter_on_empty_trace_yields_nothing() {
    let fix = common::synth_trace_dir(0);
    let t = Trace::load(&fix.call_dir).unwrap();
    assert_eq!(t.iter().count(), 0);
}
```

- [ ] **Step 2: Implement the iterator**

Append to `rust/crates/tracemiku-core/src/trace/trace.rs` (after the `impl Trace` block):

```rust
impl Trace {
    /// Sequential iterator over records. No allocation.
    pub fn iter(&self) -> RecordIter<'_> {
        RecordIter { trace: self, idx: 0 }
    }
}

pub struct RecordIter<'t> {
    trace: &'t Trace,
    idx: usize,
}

impl<'t> Iterator for RecordIter<'t> {
    type Item = Record;
    fn next(&mut self) -> Option<Record> {
        if self.idx >= self.trace.n {
            return None;
        }
        let r = self.trace.record(self.idx);
        self.idx += 1;
        Some(r)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.trace.n - self.idx;
        (rem, Some(rem))
    }
}

impl<'t> ExactSizeIterator for RecordIter<'t> {}
```

- [ ] **Step 3: Run tests**

```bash
cd rust && cargo test -p tracemiku-core --test trace_parser 2>&1 | tail -10 ; cd ..
```

Expected: `test result: ok. 11 passed; 0 failed`.

- [ ] **Step 4: cargo fmt + clippy clean**

```bash
cd rust && cargo fmt --all && cargo clippy -p tracemiku-core --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 5: Commit**

```bash
git add rust/crates/tracemiku-core/src/trace/trace.rs rust/crates/tracemiku-core/tests/trace_parser.rs
git commit -m "feat(core): Trace::iter — ExactSizeIterator over records"
```

---

## Task 6: Real-trace integration test (#[ignore] by default)

**Files:**
- Create: `rust/crates/tracemiku-core/tests/real_trace.rs`

Validates the parser against the 4.2 GB / 15.4M-record real-trace fixture. Marked `#[ignore]` so `cargo test` stays fast; opt-in via `cargo test --ignored`. Skips with a print if the fixture path is missing (CI / fresh checkout without the trace).

- [ ] **Step 1: Create the test file**

`rust/crates/tracemiku-core/tests/real_trace.rs`:

```rust
//! Real-trace integration: load the 4.2GB debug_minimal trace and assert
//! basic invariants. #[ignore] by default — opt in with `cargo test --ignored`.
//!
//! Path is resolved relative to the workspace root (assumed to be 3 levels
//! up from CARGO_MANIFEST_DIR). Skips with a print if the fixture is absent.

use std::path::PathBuf;
use std::time::Instant;

use tracemiku_core::prelude::*;

const REAL_TRACE_REL: &str =
    "../../../traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms";
const EXPECTED_RECORDS: usize = 15_426_904;

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
fn loads_real_4_2gb_trace_and_counts_records() {
    let Some(p) = real_trace_path() else {
        eprintln!("skip: real trace fixture not found at {REAL_TRACE_REL} — run `git lfs pull` or generate it");
        return;
    };

    let t0 = Instant::now();
    let t = Trace::load(&p).expect("load 4.2GB trace");
    let load_ms = t0.elapsed().as_millis();
    eprintln!("Trace::load took {load_ms}ms (mmap is constant-time; should be <50ms)");

    assert_eq!(t.len(), EXPECTED_RECORDS,
               "record count must match the dir name (15426904r)");

    // Spot-check first + last + middle PC values: just non-zero / sensible.
    let first = t.record(0);
    let last = t.record(t.len() - 1);
    let mid = t.record(t.len() / 2);
    assert!(first.pc != 0, "first PC must be non-zero");
    assert!(last.pc != 0, "last PC must be non-zero");
    assert!(mid.pc != 0, "middle PC must be non-zero");

    // Walk the iterator, count again — verifies size_hint + iteration.
    let walk_t = Instant::now();
    let counted = t.iter().count();
    let walk_ms = walk_t.elapsed().as_millis();
    eprintln!("Trace::iter().count() took {walk_ms}ms (expected: <500ms for 15.4M records)");
    assert_eq!(counted, EXPECTED_RECORDS);

    // Time pc-only scan — should be much faster than full record scan.
    let pc_t = Instant::now();
    let pc_sum: u64 = (0..t.len()).map(|i| t.pc(i)).fold(0u64, |a, b| a.wrapping_add(b));
    let pc_ms = pc_t.elapsed().as_millis();
    eprintln!("pc-only scan: {pc_ms}ms (sum={pc_sum:#x})");
    assert!(pc_ms < walk_ms + 500, "pc fast path should be at least competitive with full iter");
}
```

- [ ] **Step 2: Verify the test compiles + the synth tests still pass**

```bash
cd rust && cargo test -p tracemiku-core --test real_trace 2>&1 | tail -5 ; cd ..
```

Expected: `1 ignored` (the test is ignored by default). The compile must succeed.

```bash
cd rust && cargo test -p tracemiku-core --test trace_parser 2>&1 | tail -5 ; cd ..
```

Expected: `11 passed`.

- [ ] **Step 3: Run the real-trace test opt-in**

```bash
cd rust && cargo test -p tracemiku-core --test real_trace -- --ignored --nocapture 2>&1 | tail -20 ; cd ..
```

Expected: passes; printlns show `Trace::load took <50ms`, `iter count <500ms`, `pc-only scan <500ms`. Records count: `15_426_904`.

If the fixture is missing, the test prints `skip:` and exits 0 — that's the intentional fallback.

- [ ] **Step 4: cargo fmt + clippy clean**

```bash
cd rust && cargo fmt --all && cargo clippy -p tracemiku-core --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 5: Commit**

```bash
git add rust/crates/tracemiku-core/tests/real_trace.rs
git commit -m "$(cat <<'EOF'
test(core): real-trace integration — load 4.2GB trace, count records

#[ignore] by default; opt-in via cargo test --ignored. Resolves trace
path relative to CARGO_MANIFEST_DIR; skips gracefully if the fixture is
absent (CI / fresh checkout).

Asserts trace.len() == 15_426_904 (cross-checks the dir-name record
count against an mmap-derived count) and times mmap, full iter, and
pc-only scan to validate zero-copy + bytemuck performance claims.
EOF
)"
```

---

## Task 7: Wire Trace into AppState (groundwork — no endpoint yet)

**Files:**
- Modify: `rust/crates/tracemiku-server/src/state.rs`

Future M2-β endpoints (`/api/records`, `/api/cfg`) need `Trace`, not just `TraceMeta`. Pre-wire `AppState` to hold both, even though no endpoint reads `Trace` yet.

This is intentionally scoped to "build it, don't expose it" — the M2-α atomic deliverable is the CLI's `stats` parity, not a new endpoint. M2-β plan re-enters this file to mount routes.

- [ ] **Step 1: Modify AppState**

Open `rust/crates/tracemiku-server/src/state.rs`. Current content (post-M1):

```rust
use std::path::PathBuf;
use std::sync::Arc;

use tracemiku_core::prelude::TraceMeta;

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppStateInner>,
}

pub struct AppStateInner {
    pub trace_dir: PathBuf,
    pub meta: TraceMeta,
}

impl AppState {
    pub fn load(trace_dir: PathBuf) -> anyhow::Result<Self> {
        let meta = TraceMeta::load(&trace_dir)?;
        Ok(Self {
            inner: Arc::new(AppStateInner { trace_dir, meta }),
        })
    }
}
```

Replace with:

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
    /// Loaded eagerly at startup. Mmap is cheap (constant time); bumping it
    /// to lazy would add Mutex/RwLock complexity for no perf win.
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

- [ ] **Step 2: Verify the existing meta endpoint test still passes**

```bash
cd rust && cargo test -p tracemiku-server --test meta_endpoint 2>&1 | tail -5 ; cd ..
```

Expected: `1 passed`. The existing test fixture writes a trace.bin (empty in M1, but the new `Trace::load` accepts 0-byte files via the empty-mmap fallback from Task 3).

If the test fails because the fixture's `trace.bin` is missing or unsupported, update the fixture builder in `rust/crates/tracemiku-server/tests/meta_endpoint.rs` (`synth_call_dir`) to also write at least one 272-byte record. The simplest fix: add `let mut buf = vec![0u8; 272 * 9]; for i in 0..9 { let pc = 0x100000u64 + 4 * i; buf[i*272..i*272+8].copy_from_slice(&pc.to_le_bytes()); } fs::write(cd.join("trace.bin"), &buf).unwrap();` in place of the empty `fs::write(cd.join("trace.bin"), &[]).unwrap();` line.

- [ ] **Step 3: Add a state-level test that confirms Trace is wired**

Append to `rust/crates/tracemiku-server/tests/meta_endpoint.rs`:

```rust
#[test]
fn app_state_loads_trace_eagerly() {
    let (_tmp, call_dir) = synth_call_dir();
    let state = tracemiku_server::AppState::load(call_dir).expect("load AppState");
    // The synth fixture has 9 records (or 0 if the fixture writes empty trace.bin).
    let n = state.inner.trace.len();
    assert!(n == 0 || n == 9, "expected 0 or 9 records, got {n}");
}
```

This test is intentionally permissive about whether the fixture writes 9 or 0 records — different tests in the suite may use different fixtures.

- [ ] **Step 4: Run server tests**

```bash
cd rust && cargo test -p tracemiku-server 2>&1 | tail -10 ; cd ..
```

Expected: 2 passed (meta_endpoint_returns_synth_trace_metadata + app_state_loads_trace_eagerly).

- [ ] **Step 5: cargo fmt + clippy clean**

```bash
cd rust && cargo fmt --all && cargo clippy --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 6: Commit**

```bash
git add rust/crates/tracemiku-server/
git commit -m "$(cat <<'EOF'
feat(server): AppState now holds Trace alongside TraceMeta

Eager mmap at startup — mmap is constant time, so making it lazy would
only add Mutex/RwLock complexity. Future M2-β endpoints will read
state.inner.trace for /api/records, /api/cfg, etc.

Plus one new test asserting trace.len() resolves through the loaded
state (permissive: synth fixture may write 0-byte or 9-record trace.bin).
EOF
)"
```

---

## Task 8: CLI stats — full parity with `python -m viewer stats`

**Files:**
- Modify: `rust/crates/tracemiku-cli/src/main.rs`

The M1 `stats` subcommand only loads `TraceMeta`. After M2-α, it should load `Trace` too and emit a JSON shape that matches Python's `viewer stats` (see `viewer/__main__.py:42-76`):

```json
{
  "path": "...",
  "records": <from Trace::len(), NOT from meta.records>,
  "method": "...",
  "cmd": ...,
  "fn_addr": "0x...",
  "module": {...},
  "modules": [...],
  "modules_total": ...,
  "modules_truncated": ...
}
```

Plus `--all-modules` and `--top-modules N` flags.

- [ ] **Step 1: Replace main.rs**

Open `rust/crates/tracemiku-cli/src/main.rs`. Replace the entire content with:

```rust
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "tracemiku-cli",
    about = "traceMiku v2 CLI (subcommands populated incrementally per milestone)",
    version,
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print trace metadata as JSON. Mirrors `python -m viewer stats`.
    Stats {
        /// Per-call trace directory.
        trace_dir: std::path::PathBuf,
        /// Show ALL modules (overrides --top-modules).
        #[arg(long)]
        all_modules: bool,
        /// Limit modules list to top-N by size. Default 10.
        #[arg(long, default_value_t = 10)]
        top_modules: usize,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Stats { trace_dir, all_modules, top_modules }) => {
            let meta = tracemiku_core::prelude::TraceMeta::load(&trace_dir)?;
            let trace = tracemiku_core::prelude::Trace::load(&trace_dir)?;

            let modules_sorted: Vec<&tracemiku_core::prelude::ModuleInfo> = {
                let mut m: Vec<_> = meta.modules.iter().collect();
                m.sort_by_key(|x| std::cmp::Reverse(x.size));
                m
            };

            let target_name = meta.module.as_ref().map(|m| m.name.as_str());
            let modules_total = modules_sorted.len();

            let modules_out: Vec<&tracemiku_core::prelude::ModuleInfo> = if all_modules {
                modules_sorted.clone()
            } else {
                let n = top_modules.max(1);
                let mut kept: Vec<_> = if let Some(tn) = target_name {
                    modules_sorted.iter().copied().filter(|m| m.name == tn).take(1).collect()
                } else {
                    Vec::new()
                };
                let already = kept.iter().map(|m| m.name.as_str()).collect::<std::collections::HashSet<_>>();
                let need = n.saturating_sub(kept.len());
                kept.extend(
                    modules_sorted.iter().copied()
                        .filter(|m| !already.contains(m.name.as_str()))
                        .take(need),
                );
                kept
            };

            let modules_truncated = modules_out.len() < modules_total;

            let out = serde_json::json!({
                "path": trace_dir.display().to_string(),
                "records": trace.len(),
                "method": meta.method,
                "cmd": meta.cmd,
                "fn_addr": meta.fn_addr,
                "module": meta.module,
                "modules": modules_out,
                "modules_total": modules_total,
                "modules_truncated": modules_truncated,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }
        None => {
            eprintln!("(M2-α: only `stats` subcommand available; M3 fills the rest)");
            Ok(())
        }
    }
}
```

- [ ] **Step 2: Smoke against the synth fixture**

```bash
cd rust && cargo run --bin tracemiku-cli -- stats /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms 2>&1 | head -25 ; cd ..
```

Expected output (key fields):

```json
{
  "path": "/tmp/.../call_001_tid100_9r_2ms",
  "records": 9,
  "method": "f",
  "cmd": 1,
  "fn_addr": "0x100000",
  "module": {
    "name": "libt.so",
    "base": "0x100000",
    "size": 65536,
    "end": "0x110000"
  },
  "modules": [...],
  "modules_total": 1,
  "modules_truncated": false
}
```

If `/tmp/tracemiku_smoke/...` is missing, regenerate via `uv run python scripts/build_smoke_trace.py`.

- [ ] **Step 3: cargo fmt + clippy clean**

```bash
cd rust && cargo fmt --all && cargo clippy --all-targets -- -D warnings 2>&1 | tail -5 ; cd ..
```

- [ ] **Step 4: Commit**

```bash
git add rust/crates/tracemiku-cli/src/main.rs
git commit -m "$(cat <<'EOF'
feat(cli): stats — parity with `python -m viewer stats`

stats now loads both TraceMeta + Trace; records field comes from
trace.len() (mmap-derived) so the count is cross-checked against
meta.json. Adds --all-modules and --top-modules N flags mirroring
Python's behavior. Output includes modules_total + modules_truncated.

Sets up the parity-check surface for scripts/m2_alpha_parity.py.
EOF
)"
```

---

## Task 9: Parity script — Rust vs Python `stats`

**Files:**
- Create: `scripts/m2_alpha_parity.py`

Runs both `python -m viewer stats <call_dir>` and `cargo run --bin tracemiku-cli -- stats <call_dir>`, parses both JSONs, compares field-by-field, fails on any mismatch.

- [ ] **Step 1: Write the script**

`scripts/m2_alpha_parity.py`:

```python
"""M2-α parity differ — Python `viewer stats` vs Rust `tracemiku-cli stats`.

Usage:
    uv run python scripts/m2_alpha_parity.py <call_dir>
    uv run python scripts/m2_alpha_parity.py /tmp/tracemiku_smoke/run/calls/call_001_*

Runs both implementations, compares the JSON output field-by-field,
prints a diff and exits 1 on any mismatch. Used during M2-α to validate
the Rust port matches Python's reference behavior.

Allowed deviations (auto-normalized before compare):
- `path` may differ in resolution (symlinks, relative-vs-absolute) → both
  passed through Path.resolve() before compare.
- `modules` ordering — both sides sort by size desc, but identical-size
  ties may shuffle. Compared as a set of (name, base, size) tuples.
"""
import json
import shlex
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def run_python(call_dir: Path) -> dict:
    out = subprocess.check_output(
        ["uv", "run", "python", "-m", "viewer", "stats", str(call_dir)],
        cwd=REPO_ROOT,
    )
    return json.loads(out)


def run_rust(call_dir: Path) -> dict:
    out = subprocess.check_output(
        ["cargo", "run", "--quiet", "--bin", "tracemiku-cli", "--",
         "stats", str(call_dir)],
        cwd=REPO_ROOT / "rust",
    )
    return json.loads(out)


def normalize(d: dict) -> dict:
    out = dict(d)
    out["path"] = str(Path(out["path"]).resolve())
    if "modules" in out:
        # Compare modules as a frozenset of name+base+size triples (order-insensitive).
        out["modules"] = sorted(
            out["modules"],
            key=lambda m: (m["name"], m["base"], m["size"]),
        )
    return out


def diff(py: dict, rs: dict) -> list[str]:
    """Return a list of human-readable mismatch lines, empty on full match."""
    p, r = normalize(py), normalize(rs)
    diffs: list[str] = []
    keys = set(p.keys()) | set(r.keys())
    for k in sorted(keys):
        if k not in p:
            diffs.append(f"  rust-only field: {k!r} = {r[k]!r}")
            continue
        if k not in r:
            diffs.append(f"  python-only field: {k!r} = {p[k]!r}")
            continue
        if p[k] != r[k]:
            diffs.append(f"  field {k!r} differs:")
            diffs.append(f"    python: {p[k]!r}")
            diffs.append(f"    rust:   {r[k]!r}")
    return diffs


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    call_dir = Path(sys.argv[1]).resolve()
    if not call_dir.exists():
        print(f"call_dir not found: {call_dir}", file=sys.stderr)
        sys.exit(2)

    print(f"# parity check on {call_dir.name}", file=sys.stderr)
    py = run_python(call_dir)
    rs = run_rust(call_dir)
    diffs = diff(py, rs)
    if diffs:
        print("MISMATCH:", file=sys.stderr)
        for line in diffs:
            print(line, file=sys.stderr)
        sys.exit(1)
    print(f"OK — {len(py)} fields match", file=sys.stderr)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run parity on the synth trace**

```bash
uv run python scripts/m2_alpha_parity.py /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms
```

Expected: `OK — N fields match`. If MISMATCH, investigate field-by-field — likely culprits:
- `cmd: 1` (Python int) vs `cmd: 1` (Rust i64) → both serialize to JSON `1`, should match.
- `module.size: 65536` vs `module.size: 65536` → match.
- `fn_addr: "0x100000"` (Python uses `hex()`) vs `fn_addr: "0x100000"` (Rust) → match.
- `path` differs: Python uses absolute, Rust may use what was passed. The normalize step's `Path.resolve()` should handle this — both sides pass through.

If a real mismatch appears (e.g., `modules_total` only on Rust), update Python or Rust to align — typically Python is the reference; align Rust to match.

- [ ] **Step 3: Run parity on the real trace**

```bash
uv run python scripts/m2_alpha_parity.py traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms
```

Expected: `OK — N fields match`. The Python load ~7s, Rust ~50ms. Total wall-clock ~10-20s including cargo build.

- [ ] **Step 4: Commit**

```bash
chmod +x scripts/m2_alpha_parity.py
git add scripts/m2_alpha_parity.py
git commit -m "$(cat <<'EOF'
test(m2): parity differ for `stats` — Python vs Rust JSON match

scripts/m2_alpha_parity.py runs both implementations on the same
trace, normalizes path resolution + modules ordering, fails loudly on
any field mismatch. Validated on synth trace + real 4.2GB trace.

Will be re-run after each M2-β/γ/δ task that touches the stats output
to catch regressions.
EOF
)"
```

---

## Task 10: Update spec parity matrix + TODO.md

**Files:**
- Modify: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`
- Modify: `TODO.md`

- [ ] **Step 1: Update §13.2 trace.py row**

Open `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`. Find the line:

```
| `trace.py` (Trace, Record, mmap parser, REC_SIZE) | `tracemiku-core::trace` | 🟡 M1: TraceMeta done; full Trace mmap M2 | memmap2 + bytemuck zero-copy |
```

Replace with:

```
| `trace.py` (Trace, Record, mmap parser, REC_SIZE) | `tracemiku-core::trace` | ✅ M2-α | memmap2 + bytemuck zero-copy; 15 unit/integration tests + scripts/m2_alpha_parity.py |
```

- [ ] **Step 2: Update TODO.md M2 progress**

Open `TODO.md`. Find the existing `## 🚧 进行中 (2026-05-03 — Analysis v2 — Rust core + TS frontend)` section. After the last `M1 ...` bullet (`M1 e2e smoke ...`) and before `M2-M7: 见 spec`, add:

```markdown
- M2-α `tracemiku-core::trace::{Record, Trace}` + mmap parser: ✅ 2026-05-03
- M2-α `tracemiku-cli stats` parity vs `python -m viewer stats`: ✅ (scripts/m2_alpha_parity.py)
```

Then change `M2-M7: 见 spec §9 milestones, plans 待写` to:

```markdown
- M2-β (next): capstone-rs disasm + Index + CFG + /api/records + /api/cfg + RecordsPanel
- M2-γ: MemShadow + taint + symbols + calltree
- M2-δ: FunctionIndex + decompiler::backend stub + final M2 parity
- M3-M7: 见 spec §9 milestones
```

- [ ] **Step 3: Final verification — full test suite**

```bash
cd rust && cargo test --workspace 2>&1 | tail -5 ; cd ..
cd frontend && npm run typecheck && npm run build 2>&1 | tail -5 ; cd ..
uv run python scripts/m2_alpha_parity.py /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms 2>&1 | tail -3
```

Expected: all tests pass, frontend builds clean, parity prints `OK`.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md TODO.md
git commit -m "$(cat <<'EOF'
docs(v2): mark M2-α complete in spec parity matrix + TODO.md

trace.py row in §13.2 → ✅ M2-α. TODO.md gains M2-α completion bullets
plus pointers to M2-β/γ/δ split.

M2-α delivers: Record POD struct, Trace mmap parser, CLI stats parity
with python -m viewer stats, all on the 4.2GB real-trace fixture.
Next plan: M2-β (capstone disasm + Index + CFG + first new endpoints).
EOF
)"
```

---

## Self-Review

**1. Spec coverage:**

| Spec section | Covered by |
|---|---|
| §4 Data structures (Record / Trace) | Tasks 2-5 |
| §3 Architecture (memmap2 + bytemuck zero-copy) | Tasks 1-3 |
| §11 Decisions D-relevant (D2 single-binary deploy unchanged; D5 mmap kept) | Task 3 (Trace::load uses memmap2) |
| §13.2 trace.py row | Task 10 |
| §8 Testing strategy (cargo test green + 1 real-trace integration) | Tasks 2-6, plus Task 9 parity script |
| §9 M2 milestone (Trace parser + Index + CFG + ...) | M2-α subset only — Trace parser portion. Index/CFG/etc are M2-β+. |

Out-of-scope (deferred to M2-β+):
- capstone-rs disasm, Index def-use chains, CFG, MemShadow, taint, symbols, calltree, FunctionIndex, /api/records endpoint, RecordsPanel frontend.

**2. Placeholder scan:** No `TBD`, `TODO`, `implement later`, `similar to Task N`, `fill in details`. Every code step has full code blocks. Every bash step has the exact command + expected output.

**3. Type consistency:**
- `Record` — same field names + types in Tasks 2 (definition) and 4 (record(idx) return) and 6 (real-trace assertions). Field offsets verified by Task 2 Step 3 test.
- `Trace` — `load(call_dir)`, `len()`, `record(idx)`, `pc(idx)`, `inst(idx)`, `iter()` — all referenced consistently across Tasks 3-6 and 8.
- `REC_SIZE = 272`, `REC_NUM_REGS = 31` — consistent with Python's `viewer/trace.py:15-16`.
- AppState's `inner.trace: Trace` (Task 7) matches the Trace type from Task 3.

**4. Atomic deliverable check:** Task 9 (parity script) on the real 4.2GB trace produces `OK — N fields match` — that is the M2-α success signal. No earlier task can be skipped without breaking the chain.

---

**Plan complete and saved to `docs/superpowers/plans/2026-05-03-analysis-v2-m2-alpha.md`.**

Two execution options:

**1. Subagent-Driven (recommended)** — fresh subagent per task with two-stage review between. Same workflow as M0+M1.

**2. Inline Execution** — execute in this session with checkpoints.

**Which approach?**
