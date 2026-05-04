# Analysis v2 — M3-λ Implementation Plan (MemShadow v3 Binary Sidecar)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development if available. In Codex sessions where the `superpowers:*` skills are not installed, execute with native tools and keep DONE/BLOCKED reporting.

**Goal:** Add a Rust-native MemShadow sidecar so large traces do not rebuild byte-level memory shadow on every server start.

1. `tracemiku-core::memshadow` can save/load `<call_dir>/trace.bin.memshadow.v3.bin`.
2. Sidecar load is validated by trace size and schema magic/version.
3. Server `AppState::load` uses load-or-build semantics.
4. Corrupt or stale sidecars are ignored and regenerated.

**Out of scope:**

- Reading Python `.memshadow.v2.npz`; old sidecars are regenerable and explicitly replaced by v3.
- Parallel/rayon MemShadow build changes.
- External writes parity (`external_writes.bin`) unless already present in Rust MemShadow.
- Public REST endpoint for sidecar stats.

**Binary schema v3:**

- Header:
  - magic: `TMMSV3\0\0`
  - version: `u32 = 3`
  - trace_size: `u64`
  - writes_len: `u64`
  - reads_len: `u64`
  - byte_addr_len: `u64`
- MemRec arrays:
  - repeated writes then reads: `idx:u64, addr:u64, size:u32, value:u64`
- Byte map:
  - per address in sorted order: `addr:u64, event_len:u64`
  - repeated events: `idx:u64, byte:u8, kind:u8` where `r=0,w=1,x=2`

**Branch:** `refactor/function-index-handoff`. Stream commits.

---

## File Structure

| File | Role |
|---|---|
| `rust/crates/tracemiku-core/src/memshadow.rs` | Add sidecar read/write/load-or-build APIs and tests support. |
| `rust/crates/tracemiku-core/tests/memshadow_tests.rs` | Roundtrip, stale, corrupt sidecar tests. |
| `rust/crates/tracemiku-server/src/state.rs` | Use `MemShadow::load_or_build`. |
| `TODO.md` + spec | Mark M3-λ done and move next pointer. |

---

## Task 1: Core sidecar I/O

- [ ] Add constants, sidecar path helper, binary read/write helpers.
- [ ] Implement `try_load_sidecar(trace) -> Option<MemShadow>`.
- [ ] Implement `save_sidecar(trace)` and `load_or_build(trace)`.
- [ ] Keep `build_from_trace(trace)` as a cold-build API for tests and callers that want no filesystem side effects.

**Verify:** `cargo test -p tracemiku-core --test memshadow_tests`

**Commit:** `feat(core): add memshadow v3 sidecar`

---

## Task 2: Server load integration

- [ ] Switch `AppState::load` from `build_from_trace` to `load_or_build`.
- [ ] Keep existing `/api/strings`, `/api/mem-dump`, taint, and decompiler consumers unchanged.

**Verify:** `cargo test -p tracemiku-server`

**Commit:** Fold into Task 1 if the change is tiny.

---

## Task 3: Docs and final verification

- [ ] Mark M3-λ complete in TODO/spec and move next pointer to M3-μ.
- [ ] Run:

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo build -p tracemiku-core
cargo build -p tracemiku-server
cargo test -p tracemiku-core --test memshadow_tests
cargo test -p tracemiku-core
cargo test -p tracemiku-server
cargo clippy -p tracemiku-core -p tracemiku-server --tests
```

**Commit:** `docs(v2): mark M3-λ complete`

---

## Self-Review

- [ ] Invalid/corrupt sidecars never fail server startup.
- [ ] Successful sidecar writes are best-effort and atomic within the call directory.
- [ ] v2 Python `.npz` files are not read or migrated.
- [ ] Trace format remains unchanged.
