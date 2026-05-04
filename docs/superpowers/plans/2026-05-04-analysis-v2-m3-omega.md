# Analysis v2 — M3-omega Implementation Plan (Function Summary)

**Goal:** Port the LLM-friendly function overview endpoint to Rust v2.

1. `/api/fn-summary`
2. `tracemiku-cli fn-summary`
3. Server and CLI smoke coverage

**Out of scope:** BN/HLIL fields, richer callgraph analysis.

---

## Tasks

- [x] Add server route and tests.
- [x] Add CLI wrapper and smoke test.
- [x] Run server/CLI tests and clippy.
- [x] Update TODO/spec status.
