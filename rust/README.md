# Rust 工作区

Rust 是 traceMiku 分析语义的唯一实现源，工作区仅包含两个 crate：

- `tracemiku-core`：trace、索引、CFG、污点、MemShadow、replay，以及 `analysis/`
  中的同步查询和 `analysis/reports/` 中的 VM、lineage、输出来源报告。
- `tracemiku-cli`：clap 参数、core 调用、JSON 序列化与文件输出。

依赖方向是 `CLI → core`。两者均不启动 Web 服务或反编译器。采集与离线分析的边界
见 [设计契约](../docs/CLI_FIRST_DESIGN.md)。统一用户入口位于仓库根目录 `tracemiku`。

## 构建与验证

```bash
cd rust
cargo fmt --check
cargo clippy --workspace --lib -- -D warnings
cargo test --workspace
```

仓库根目录的 `make test-contract` 验证命令发现、core 查询、统一入口一致性、输出
schema、host 与采集格式；`make test-v2` 另含 agent 类型检查。它们都不需要真机。

## 开发约束

- 新分析先进入 core 并有语义测试；CLI 只处理参数、编排与输出。
- 查询同步执行且保留资源上限、截断元数据和错误详情；不能引入服务或轮询状态。
- `AnalysisContext` 按需构建重索引，组合查询复用同一个上下文。
- 持久缓存使用 trace 内容指纹失效；缓存状态不能改变分析结果。
- 输出模型在 core；CLI 契约测试与 schema 生成器直接引用这些模型。
- 命令增删或改名同步更新 `docs/FEATURES.md` 和 `scripts/contract_audit.py`；参数和
  默认值随 clap 定义自动进入统一入口的能力清单。
