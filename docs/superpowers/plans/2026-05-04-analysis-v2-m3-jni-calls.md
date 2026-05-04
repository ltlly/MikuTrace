# Analysis v2 — M3 JNI Calls Implementation Plan

**Goal:** Port JNI vtable call detection to Rust v2.

1. `/api/jni-calls`
2. `tracemiku-cli jni-calls`
3. Server and CLI smoke coverage

**Out of scope:** jobject history and string-buffer recovery.

---

## Tasks

- [x] Add server route and tests.
- [x] Add CLI wrapper and smoke test.
- [x] Run server/CLI tests and clippy.
- [x] Update TODO/spec status.
