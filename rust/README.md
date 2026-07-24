# Rust 工作区

Rust 是 traceMiku 分析语义的唯一实现源。

## Crate

- `tracemiku-core`：trace、反汇编、索引、CFG、污点、MemShadow、符号和 IL。
- `tracemiku-cli`：结构化命令与高层分析编排。
- `tracemiku-server`：Axum API、后台任务、前端静态文件和 BN sidecar。

依赖方向必须保持 `core <- cli/server`。core 不依赖 Web、CLI 参数或目标专用配置；
route 不应复制分析语义。

## 构建与测试

```bash
cd rust
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo run -p tracemiku-cli -- --help
```

从仓库根目录运行 `make test-v2` 可同时验证 Python 入口、Rust、前端和 CLI/API 一致性。

## 开发约束

- CPU 密集任务使用有界 `spawn_blocking` 路径。
- API 响应必须有类型化状态、资源上限和截断信息。
- sidecar 缓存必须使用 trace 内容指纹失效。
- 新分析先进入 core 并有单测，再接 CLI 和 server。
- 不在 `tracemiku-cli/src/main.rs` 继续堆积新领域；新增命令应放入按领域拆分的模块。
