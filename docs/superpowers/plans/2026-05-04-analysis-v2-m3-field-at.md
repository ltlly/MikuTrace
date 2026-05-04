# Analysis v2 — M3 Field At Implementation Plan

**Goal:** Add Rust v2 field-at wire shape while BN backend remains M6-gated.

1. `/api/field-at`
2. `tracemiku-cli field-at`
3. Server and CLI smoke coverage

**Out of scope:** Actual BN field inference.

---

## Tasks

- [ ] Add server route returning stable `hit:false` fallback.
- [ ] Add CLI wrapper and smoke test.
- [ ] Run server/CLI tests and clippy.
- [ ] Update TODO/spec status.
