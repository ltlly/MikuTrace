# traceMiku 工程约束

开始工作先读本文件和 [TODO.md](TODO.md)。其他智能体入口只引用本文件。
文档、提交说明和用户文字默认中文；不加模型署名或共同作者尾注。

## 边界

- 只维护 Android ARM64 采集与离线分析 CLI；不引入 Web、HTTP、终端 UI、反编译桥接或项目专用 MCP server。
- 依赖方向：采集格式 → `tracemiku-core` → CLI。分析语义及响应模型放 core；CLI 只处理参数、编排和输出。
- 用户统一调用 `./tracemiku`；不要求直接运行内部 Rust 二进制。本地分析不依赖 LLM。
- 包名、SO 版本、固定偏移及目标专用 hook 只放 `tools/hooks/` 或 `examples/<target>/`。
- `trace.bin` 固定 272 字节/条；目录固定为 `calls/call_<序号>_tid<线程>_<记录数>r_<耗时>ms/`。格式变更须版本化、迁移和兼容测试。
- 新功能须包含资源上限、失败语义、结构化输出和相邻层测试；截断和未知证据必须显式表达。采集还须有失败降级路径。

## 修改规则

- 用代码、测试和调用关系确认行为；优先复用已有抽象，在产生错误的最底层修复。
- 不为假想兼容性保留双实现、别名或废弃路径；确有外部兼容承诺须写测试。
- 源文件超过 1500 行原则上不增加职责，超过 2500 行先拆分。
- 命令增删或改名同步更新 [FEATURES.md](docs/FEATURES.md)。用法只在此汇总；参数以 `--help` 为准，机器清单由 `capabilities` 生成。
- README 只放定位和快速开始；专题文档只放当前契约。未完成工作只放 TODO，完成历史由 Git 保存。

## 验证

| 改动 | 最低验证 |
|---|---|
| Rust | `make fmt`；core 语义变化另跑相关单测和 `cd rust && cargo test -p tracemiku-core` |
| CLI 输出 | 先更新 `contract_*` 与 `scripts/contract_audit.py`，再跑 `make test-contract`（含统一入口/core 一致性） |
| host | `make test-fast` |
| agent 或数据格式 | `npm --prefix tracer run typecheck`、`make test-v2`、`make test-device`；核对 agent、host、meta、core、CLI 全链路 |

交付须包含验证结果；未跑真机须明确剩余采集风险。

## Git

保留用户已有改动，按明确文件列表暂存。未经确认禁止 `reset --hard`、`clean -fd*`、
强推或删除分支。
