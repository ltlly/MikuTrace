# Analysis v2 — M3-sigma Implementation Plan (Call Chain)

**Goal:** Add the simple LR-walking call-chain surface to Rust v2.

1. Add `/api/call-chain?idx=&depth=`.
2. Add `tracemiku-cli call-chain`.
3. Cover both with synthetic tests.

**Out of scope:** full frame-pointer unwinding and frontend panel work.

---

## Tasks

- [ ] Add server route and test.
- [ ] Add CLI wrapper and smoke test.
- [ ] Run server/CLI tests and clippy.
- [ ] Update TODO/spec status.
