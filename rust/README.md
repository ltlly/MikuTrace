# traceMiku v2 — Rust analysis stack

3 crates: `tracemiku-core` (lib), `tracemiku-server` (axum bin), `tracemiku-cli` (clap bin).

## Quick start (M1 smoke)

```bash
# Build release server
cd rust && cargo build --release --bin tracemiku-server

# Generate synth trace (one-time; no Python package deps)
uv run python ../scripts/build_smoke_trace.py

# Run server
./target/release/tracemiku-server /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms

# In another terminal, run frontend dev server
cd ../frontend && npm install && npm run dev
# Open http://127.0.0.1:5173/
```

## Tests

```bash
cd rust && cargo test --workspace
```

## Format + lint

```bash
cd rust && cargo fmt --all && cargo clippy --all-targets -- -D warnings
```
