# Analysis v2 — M3 String Provenance Implementation Plan

**Goal:** Port `/api/string-provenance` to Rust v2.

1. Per-byte latest value/kind from MemShadow
2. Per-byte writer/read indices from Index memory ops
3. Server integration coverage

**Out of scope:** CLI wrapper; Python only exposes this as a web API.

---

## Tasks

- [x] Add server route and tests.
- [x] Run server tests and clippy.
- [x] Update TODO/spec status.
