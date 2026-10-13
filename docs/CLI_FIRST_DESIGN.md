# 采集与 CLI 架构

```text
./tracemiku → Python host → Frida agent → trace/sidecar
./tracemiku → Rust CLI → tracemiku-core ← trace/sidecar
```

| 位置 | 职责 |
|---|---|
| `tracer/src/` | Stalker/CModule、ring、调用边界、sidecar、插件 |
| `tracemiku`、`tracemiku_{device,transport,target,commands}.py` | 统一入口、采集、回传、profile 与能力发现 |
| `rust/crates/tracemiku-core/src/` | 格式、索引、CFG、污点、MemShadow、replay |
| core `analysis/`、`analysis/reports/` | 类型化查询、输出回溯、lineage、VM 与目录报告 |
| `rust/crates/tracemiku-cli/src/` | clap、core 调用、JSON 与文件输出 |
| `tools/hooks/`、`examples/<target>/` | 目标配置和专用脚本 |

Rust 工作区只有 core 与 CLI。静态工具独立使用，协作坐标为 `(SO, offset)`、绝对 PC
和符号；本仓库不管理反编译器。

## 查询与输出

`AnalysisContext::load` 加载 trace、索引、元数据和符号；CFG、MemShadow、调用关系等
由 `OnceLock` 按需构建。组合报告复用上下文；查询同步返回结果。
`analysis::Query` 和 `execute` 分派领域函数。索引缓存按输入内容指纹失效，可重建。

响应类型位于 core `analysis/`，组合报告模型位于 `analysis/reports/output_*.rs`。
[已生成 schema](schema/) 只覆盖部分报告；动态 JSON 也受 CLI `contract_*` 测试约束。
退出码与结果状态见 [CLI 约定](FEATURES.md#约定)。

各查询有独立的条数、窗口或深度限制，尚无统一总内存/输出预算；全量索引和部分报告
仍随 trace 规模增长。剩余工作见 [TODO](../TODO.md)。

## 数据与验证

[Trace 格式](PER_CALL_TRACE_DESIGN.md) 连接 agent、host 和 core；
[内存来源](memory-completeness-design.md) 约束 dump、export、lineage 与 replay。

core 单测及 `tests/analysis/` 验证语义；CLI `contract_*` 验证二进制输出，
`contract_offline` 比较统一入口与 core；host/TypeScript 测试覆盖采集和传输契约。
真机验证独立执行，命令见 [AGENTS.md](../AGENTS.md#验证)。
