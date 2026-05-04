# Analysis v2 — M3-chi Implementation Plan (Search PC Compatibility)

**Goal:** Restore the legacy all-hit PC search shape in Rust v2.

1. `/api/search-pc`
2. `tracemiku-cli search-pc`
3. Server and CLI smoke coverage

**Out of scope:** PC index acceleration; the current linear scan matches existing `/api/idxs-for-pc`.

---

## Tasks

- [x] Add `/api/search-pc` route and tests.
- [x] Add CLI wrapper and smoke test.
- [x] Run server/CLI tests and clippy.
- [x] Update TODO/spec status.
