# Analysis v2 — M3-omicron Implementation Plan (Fork Events)

**Goal:** Port the already-recorded fork lifecycle metadata into Rust v2.

1. `TraceMeta` reads per-call `meta.json::fork_events`.
2. `GET /api/fork-events?status=` returns the legacy count/events shape.
3. `tracemiku-cli fork-events` wraps the route JSON unchanged.

**Out of scope:**

- Device-side Frida fork hook changes.
- Run-level aggregation across multiple call dirs.
- Frontend Forks panel.

---

## Tasks

- [x] Extend Rust meta parsing.
- [x] Add server route and tests.
- [x] Add CLI wrapper and smoke test.
- [x] Run relevant core/server/CLI tests and clippy.
- [x] Update TODO/spec status.
