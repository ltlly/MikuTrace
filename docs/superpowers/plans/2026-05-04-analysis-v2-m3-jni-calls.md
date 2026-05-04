# Analysis v2 — M3 JNI Calls Implementation Plan

**Goal:** Port JNI vtable call detection to Rust v2.

1. `/api/jni-calls`
2. `tracemiku-cli jni-calls`
3. Server and CLI smoke coverage

**Out of scope:** jobject history and string-buffer recovery.

---

## Tasks

- [ ] Add server route and tests.
- [ ] Add CLI wrapper and smoke test.
- [ ] Run server/CLI tests and clippy.
- [ ] Update TODO/spec status.
