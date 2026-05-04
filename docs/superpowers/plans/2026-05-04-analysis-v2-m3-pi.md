# Analysis v2 — M3-pi Implementation Plan (Memory Query Endpoints)

**Goal:** Close the MemShadow/Index-backed memory query endpoints that do not depend on BN, LLIL, JNI metadata, or long-running jobs.

1. Add `/api/last-write-of-addr`.
2. Add `/api/idxs-touching-addr` and `/api/idxs-touching-range`.
3. Add `/api/find-mem-pattern`.
4. Add matching CLI route wrappers for the new endpoints.

**Out of scope:**

- `mem-flow`, `mem-diff`, and `data-chase` graph traversal.
- Hash/JNI/crypto detectors.
- Frontend Memory diff/Xref panels.

---

## Tasks

- [x] Add server routes and tests.
- [x] Add CLI wrappers and smoke tests.
- [x] Run server/CLI tests and clippy.
- [x] Update TODO/spec status for the covered rows only.
