# Analysis v2 — M3 JObject History Implementation Plan

**Goal:** Port jobject lifecycle filtering to Rust v2.

1. `/api/jobj-history`
2. `tracemiku-cli jobj-history`
3. Server and CLI smoke coverage

**Out of scope:** JNI string buffer recovery.

---

## Tasks

- [x] Add server route and tests.
- [x] Add CLI wrapper and smoke test.
- [x] Run server/CLI tests and clippy.
- [x] Update TODO/spec status.
