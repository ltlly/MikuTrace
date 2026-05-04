# Analysis v2 — M3 Hash Input Search Implementation Plan

**Goal:** Port hash input candidate search to Rust v2.

1. `POST /api/hash-input-search`
2. `tracemiku-cli hash-input-search`
3. Server and CLI smoke coverage

**Out of scope:** Broad crypto-analysis UX and trace differential analysis.

---

## Tasks

- [x] Add Rust hash/HMAC/CRC dependencies and server route.
- [x] Add CLI wrapper and POST helper.
- [x] Add server/CLI tests.
- [x] Run server/CLI tests and clippy.
- [x] Update TODO/spec status.
