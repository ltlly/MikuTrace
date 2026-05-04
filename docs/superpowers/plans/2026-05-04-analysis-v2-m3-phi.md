# Analysis v2 — M3-phi Implementation Plan (Mem Flow)

**Goal:** Port Python/webui `mem-flow` to Rust v2 as a read-only MemShadow-backed query.

1. `/api/mem-flow`
2. `tracemiku-cli mem-flow`
3. Server and CLI smoke coverage

**Out of scope:** frontend Memory diff/flow UI, crypto detectors, trace diff.

---

## Architecture

- Use `AppState.inner.memshadow.bytes` as the source of byte-level event history.
- Match Python query semantics:
  - `addr`, `count`
  - optional `idx_lo`, `idx_hi`
  - `events_per_byte`
  - `writers_only`, `readers_only`
- Decorate each event from `Trace`, `decode`, and `SymbolMap` with `pc`, `rel`, `func`, and `asm`.
- Cap returned events per byte by keeping the newest events.

---

## Tasks

- [x] Add server route and tests.
- [x] Add CLI wrapper and smoke test.
- [x] Run server/CLI tests and clippy.
- [x] Update TODO/spec status.
