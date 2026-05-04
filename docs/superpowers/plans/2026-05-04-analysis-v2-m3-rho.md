# Analysis v2 — M3-rho Implementation Plan (Navigation Endpoints)

**Goal:** Close the remaining trace/CFG navigation endpoints that are directly backed by existing Rust v2 state.

1. Add `/api/block-for-pc`.
2. Add `/api/block`.
3. Add `/api/loops`.
4. Add `/api/backtrace`.

**Out of scope:**

- Frontend Backtrace/Xref panel polish.
- `call-chain` LR walking.
- BN-derived asm tokens or HLIL.

---

## Tasks

- [x] Add server route module and tests.
- [x] Run server tests and clippy.
- [x] Update TODO/spec status for covered endpoint rows.
