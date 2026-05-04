# Analysis v2 — M3 JNI Strings Implementation Plan

**Goal:** Port JNI string operation listing and observable buffer recovery to Rust v2.

1. `/api/jni-strings`
2. `tracemiku-cli jni-strings`
3. Server and CLI smoke coverage

**Out of scope:** Agent-side hook capture changes and BN-backed field inference.

---

## Tasks

- [x] Add server route and tests.
- [x] Add CLI wrapper and smoke test.
- [x] Run server/CLI tests and clippy.
- [x] Update TODO/spec status.
