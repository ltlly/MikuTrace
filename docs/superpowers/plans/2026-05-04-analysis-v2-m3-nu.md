# Analysis v2 — M3-nu Implementation Plan (Inspect Endpoint Sweep)

**Goal:** Close a small set of remaining v2 inspect endpoints that are already backed by Rust core state.

1. Add `/api/search` for regex search over decoded instruction text.
2. Add `/api/so-stats` for per-module record counts.
3. Add `/api/reg-value-at` / `/api/reg-at-idx` for cursor register lookup.

**Out of scope:**

- Memory-flow endpoints (`idxs-touching-*`, `last-write-of-addr`, `mem-flow`).
- Fork/JNI/hash/crypto endpoints.
- OpenAPI generation.
- Frontend panels for these endpoints.

**Branch:** `refactor/function-index-handoff`. Stream commits.

---

## Tasks

- [ ] Add route modules and wire them into `routes::router`.
- [ ] Add focused server tests with synthetic traces.
- [ ] Run server build/tests/clippy.
- [ ] Mark spec rows complete while leaving unrelated rows untouched.

**Verify:**

```bash
cd /home/ltlly/Code/traceMiku/rust
cargo build -p tracemiku-server
cargo test -p tracemiku-server
cargo clippy -p tracemiku-server --tests
```
