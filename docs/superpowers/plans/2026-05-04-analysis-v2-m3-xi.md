# Analysis v2 — M3-xi Implementation Plan (CLI Inspect Wrappers)

**Goal:** Mirror the shipped inspect/search routes in `tracemiku-cli` so AI-friendly JSON exploration does not require a browser.

1. Add REST-backed wrappers for `/api/idxs-for-pc`, `/api/search`, `/api/so-stats`, and `/api/reg-value-at`.
2. Keep wrapper output identical to the server route JSON.
3. Add smoke coverage on synthetic traces.

**Out of scope:**

- Memory-flow CLI commands.
- Fork/JNI/hash/crypto CLI commands.
- Python dispatcher cutover.

---

## Tasks

- [ ] Add CLI subcommands.
- [ ] Add smoke tests.
- [ ] Run `cargo test -p tracemiku-cli` and `cargo clippy -p tracemiku-cli --tests`.
- [ ] Mark CLI rows complete in TODO/spec where covered.
