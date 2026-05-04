# Analysis v2 — M3-crypto Implementation Plan (Crypto Scan)

**Goal:** Port the MemShadow-backed crypto primitive constant scanner to Rust v2.

1. `/api/crypto-scan`
2. `tracemiku-cli crypto-scan`
3. Server and CLI smoke coverage

**Out of scope:** hash finalization and input brute-force detectors.

---

## Tasks

- [ ] Add server route and tests.
- [ ] Add CLI wrapper and smoke test.
- [ ] Run server/CLI tests and clippy.
- [ ] Update TODO/spec status.
