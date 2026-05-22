# traceMiku Rust Workspace

> **[English](#english)** | **[中文](#中文)**

---

## English

The Rust workspace is the active analysis/runtime stack.

```text
crates/tracemiku-core/     trace parser, disasm, indexes, CFG, taint, MemShadow, decompiler
crates/tracemiku-server/   axum API server, static Solid frontend, BN sidecar bridge
crates/tracemiku-cli/      JSON CLI wrappers and filesystem commands
```

### Build And Test

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

### Run The Server

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

### Development Rules

- CPU-heavy route work must be off the Tokio reactor via `spawn_blocking` or a
  bounded worker path.
- New routes must be classified in
  `crates/tracemiku-server/tests/api_infra_tests.rs`.
- Large responses need explicit caps and truncation metadata.
- User-visible web changes should pass `cd ../frontend && npm run build` and,
  when possible, `uv run python ../scripts/frontend_event_smoke.py <base>`.

---

## 中文

Rust workspace 是当前活跃的分析/运行时技术栈。

```text
crates/tracemiku-core/     trace 解析、反汇编、索引、CFG、污点、MemShadow、反编译器
crates/tracemiku-server/   axum API 服务器、静态 Solid 前端、BN sidecar 桥
crates/tracemiku-cli/      JSON CLI 包装和文件系统命令
```

### 构建和测试

推荐从仓库根使用 Makefile:

```bash
make test-v2
make test-fast
```

从本目录:

```bash
cargo fmt --all --check
cargo test --workspace
cargo build -p tracemiku-server
```

### 启动服务器

顶层包装器是正常入口:

```bash
./tracemiku web <call_dir> --port 18900
./tracemiku web <call_dir> --so /path/to/libtarget.so --port 18900
```

直接 debug 运行:

```bash
cargo run -p tracemiku-server -- <call_dir> --host 0.0.0.0 --port 18900 --static-dir ../frontend/dist
```

设置 `TRACEMIKU_BN_SO=/path/to/libtarget.so` 启用 BN HLIL/CFG。
sidecar 命令可通过 `TRACEMIKU_BN_SIDECAR` 环境变量覆盖。

### 开发规则

- CPU 密集型路由工作必须通过 `spawn_blocking` 或有界工作者路径离开 Tokio reactor。
- 新路由必须在 `crates/tracemiku-server/tests/api_infra_tests.rs` 中分类。
- 大响应需要显式上限和截断元数据。
- 影响用户可见 web 行为的更改应通过 `cd ../frontend && npm run build`，
  条件允许时还应跑 `uv run python ../scripts/frontend_event_smoke.py <base>`。
