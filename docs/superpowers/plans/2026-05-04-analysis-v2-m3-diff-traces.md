# Analysis v2 — M3 Diff Traces Implementation Plan

**Goal:** Port trace differential output analysis to Rust v2.

1. `POST /api/diff-traces`
2. `tracemiku-cli diff-traces`
3. Server and CLI smoke coverage

**Out of scope:** Non-JNI-output diff sources and frontend visualization.

---

## Tasks

- [x] Add server route and output extraction from `jni_hooks.jsonl`.
- [x] Add CLI wrapper using POST helper.
- [x] Add server/CLI tests.
- [x] Run server/CLI tests and clippy.
- [x] Update TODO/spec status.
