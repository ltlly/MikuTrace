# Analysis v2 — M3-tau Implementation Plan (Data Chase)

**Goal:** Port the single-path backward data chase workflow to Rust v2.

1. Add `/api/data-chase?start=&reg=&max_steps=&exclude_regs=`.
2. Add `tracemiku-cli data-chase`.
3. Cover terminal/reg/mem-load paths with synthetic tests.

**Out of scope:** full taint fanout, mem-flow timelines, and frontend xref UI.

---

## Tasks

- [x] Add server route and tests.
- [x] Add CLI wrapper and smoke test.
- [x] Run server/CLI tests and clippy.
- [x] Update TODO/spec status.
