# traceMiku Rust Workspace

The Rust workspace is the active analysis/runtime stack.

```text
crates/tracemiku-core/     trace parser, disasm, indexes, CFG, taint, MemShadow, decompiler
crates/tracemiku-server/   axum API server, static Solid frontend, BN sidecar bridge
crates/tracemiku-cli/      JSON CLI wrappers and filesystem commands
```

## Build And Test

From the repository root, prefer the Makefile gates:

```bash
make test-v2
make test-fast
```

From this directory:

```bash
cargo fmt --all --check
cargo test --workspace
cargo build -p tracemiku-server
```

## Run The Server

The top-level wrapper is the normal entry point:

```bash
./tracemiku web <call_dir> --port 18900
./tracemiku web <call_dir> --so /path/to/libtarget.so --port 18900
```

For direct debug runs:

```bash
cargo run -p tracemiku-server -- <call_dir> --host 0.0.0.0 --port 18900 --static-dir ../frontend/dist
```

Set `TRACEMIKU_BN_SO=/path/to/libtarget.so` for BN-backed HLIL/CFG. Override
the sidecar command with `TRACEMIKU_BN_SIDECAR` when the default
`tracemiku-bn-sidecar` is not on `PATH`.

## Development Rules

- CPU-heavy route work must be off the Tokio reactor via `spawn_blocking` or a
  bounded worker path.
- New routes must be classified in
  `crates/tracemiku-server/tests/api_infra_tests.rs`.
- Large responses need explicit caps and truncation metadata.
- User-visible web changes should pass `cd ../frontend && npm run build` and,
  when possible, `uv run python ../scripts/frontend_event_smoke.py <base>`.
