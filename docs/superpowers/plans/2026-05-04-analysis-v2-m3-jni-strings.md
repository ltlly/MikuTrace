# Analysis v2 — M3 JNI Strings Implementation Plan

**Goal:** Port JNI string operation listing and observable buffer recovery to Rust v2.

1. `/api/jni-strings`
2. `tracemiku-cli jni-strings`
3. Server and CLI smoke coverage

**Out of scope:** Agent-side hook capture changes and BN-backed field inference.

---

## Tasks

- [ ] Add server route and tests.
- [ ] Add CLI wrapper and smoke test.
- [ ] Run server/CLI tests and clippy.
- [ ] Update TODO/spec status.
