# traceMiku

traceMiku is an Android real-device ARM64 instruction-level trace toolchain.

The analysis v2 cutover is complete: Python `viewer/`, the old FastAPI `webui/`,
and the old pytest parity suite have been removed. Runtime analysis now lives in
Rust crates plus the Solid frontend.

## Layout

```text
tracer/                         Frida device agents
frontend/                       Solid + Vite SPA
rust/crates/tracemiku-core/     trace parser, disasm, CFG, taint, MemShadow, LLIL
rust/crates/tracemiku-server/   axum API server, static frontend, BN sidecar bridge
rust/crates/tracemiku-cli/      Rust JSON CLI wrappers and filesystem commands
tools/hooks/                    JSON hook/type specs
examples/                       sample target metadata/specs
docs/                           design notes and parity history
```

`./tracemiku` remains the top-level convenience wrapper:

```bash
./tracemiku trace --pkg com.example.app --so libtarget.so --method nativeFn --out traces/run1
./tracemiku list traces/run1 --json
./tracemiku info traces/run1/calls/call_001_tid1_100r_1ms --json
./tracemiku web traces/run1/calls/call_001_tid1_100r_1ms --port 18900
./tracemiku view traces/run1/calls/call_001_tid1_100r_1ms
```

`web` and `view` both start the Rust v2 server and serve `frontend/dist`.
For BN-backed HLIL, pass the target SO:

```bash
./tracemiku web <call_dir> --so /path/to/libtarget.so
```

The wrapper maps `--so` to `TRACEMIKU_BN_SO`. The BN sidecar command defaults to
`tracemiku-bn-sidecar` and can be overridden with `TRACEMIKU_BN_SIDECAR`.

## Rust CLI

The Rust CLI can be run directly during development:

```bash
cd rust
cargo run -p tracemiku-cli -- info <call_dir> --json
cargo run -p tracemiku-cli -- records <call_dir> --start 0 --count 50
cargo run -p tracemiku-cli -- functions <call_dir>
cargo run -p tracemiku-cli -- dec-summary <call_dir>
cargo run -p tracemiku-cli -- dec-fn <call_dir> trace:F0 --tier hot
```

## Development

```bash
cd frontend && npm run build
cd rust && cargo test -p tracemiku-core
cd rust && cargo test -p tracemiku-server
cd rust && cargo test -p tracemiku-cli
```

The Rust server serves API routes under `/api/*`, `/openapi.json`, `/ws/jobs`,
and falls back to the built SPA in `frontend/dist`.

## Trace Format

`trace.bin` records are 272 bytes. Per-call directories use:

```text
calls/<idx>_tid<T>_<records>r_<ms>ms/
```

Format changes require an explicit meta version bump and migration path.
