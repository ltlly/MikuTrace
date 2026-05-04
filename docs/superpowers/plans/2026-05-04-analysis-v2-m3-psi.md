# Analysis v2 — M3-psi Implementation Plan (OLLVM Detect VM)

**Goal:** Expose the already-ported OLLVM VM dispatcher heuristic through Rust v2.

1. `/api/ollvm-detect-vm`
2. `tracemiku-cli ollvm-detect-vm`
3. Server and CLI smoke coverage

**Out of scope:** VM bytecode decoding, BN sidecar integration.

---

## Tasks

- [x] Add server route and tests.
- [x] Add CLI wrapper and smoke test.
- [x] Run server/CLI tests and clippy.
- [x] Update TODO/spec status.
