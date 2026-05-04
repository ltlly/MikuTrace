# Analysis v2 — M3-crypto Implementation Plan (Crypto Scan)

**Goal:** Port the MemShadow-backed crypto primitive constant scanner to Rust v2.

1. `/api/crypto-scan`
2. `tracemiku-cli crypto-scan`
3. Server and CLI smoke coverage

**Out of scope:** hash finalization and input brute-force detectors.

---

## Tasks

- [x] Add server route and tests.
- [x] Add CLI wrapper and smoke test.
- [x] Run server/CLI tests and clippy.
- [x] Update TODO/spec status.
