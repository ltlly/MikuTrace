# Rust 工作区

- `tracemiku-core`：全部分析语义、查询与响应模型。
- `tracemiku-cli`：clap 参数、core 调用与输出。

用户入口为仓库根目录 `./tracemiku`。上下文、缓存和契约测试位置见
[架构](../docs/CLI_FIRST_DESIGN.md)，验证要求见 [AGENTS.md](../AGENTS.md#验证)。

```bash
cd rust
cargo build -p tracemiku-cli --bin tracemiku-cli
cargo test --workspace
cargo clippy --workspace --lib -- -D warnings
```
