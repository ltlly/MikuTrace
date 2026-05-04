# Analysis v2 — M3 JNI Events Implementation Plan

**Goal:** Port `/api/jni-events` to Rust v2 as the base jni_hooks.jsonl reader.

1. Load per-call `jni_hooks.jsonl`
2. Filter by `id`, `idx_lo`, and `idx_hi`
3. Server integration coverage

**Out of scope:** vtable-call reconstruction and JNI string buffer recovery.

---

## Tasks

- [x] Add server route and tests.
- [x] Run server tests and clippy.
- [x] Update TODO/spec status.
