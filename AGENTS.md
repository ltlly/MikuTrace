# traceMiku AI 工程规范

本文件是仓库内所有编码智能体的唯一工程约束。其他智能体入口只能引用本文件，
不得复制一份独立规则。项目文档、提交说明和面向用户的文字默认使用中文；代码标识、
协议字段和行业通用缩写保留英文。

## 项目定位

traceMiku 是 Android 真机 ARM64 指令级动态追踪与分析工具。核心价值是静态工具无法
提供的运行时事实：真实执行路径、间接跳转目标、寄存器值、运行时内存、跨函数来源和
调用边界。项目通过 `(SO, 静态偏移)` 与 IDA、Ghidra、Binary Ninja 等静态工具协作，
不绑定其中任何一家。

维护范围为 trace 采集与离线分析 CLI，设计契约见 `docs/CLI_FIRST_DESIGN.md`，
未完成工作只记录在 `TODO.md`。

当前运行架构：

- `tracer/`：Frida 设备端采集器。入口是由 TypeScript 编译生成的 `_agent.js`。
- `rust/crates/tracemiku-core/`：Trace 解析、反汇编、索引、CFG、污点和 MemShadow
  分析的唯一实现源。
- `rust/crates/tracemiku-cli/`：面向 AI 和脚本的结构化 JSON 命令。
- `tracemiku`：统一入口；不要要求用户直接调用内部 Rust 二进制。

## 不可破坏的边界

- 不恢复 Web UI、HTTP/OpenAPI、反编译桥接或终端 UI。
- 不增加项目专用 MCP server。AI 入口是统一 CLI 的结构化输出。
- 不把淘宝、xsign、`libsgmainso`、固定偏移等目标知识写进 core；目标配置只能放在
  `tools/hooks/` 或 `examples/<target>/`。
- `trace.bin` 单条记录固定为 272 字节。格式变化必须增加版本、迁移路径和兼容测试。
- 每次调用目录固定为 `calls/call_<序号>_tid<线程>_<记录数>r_<耗时>ms/`。
- 分析查询必须有资源上限；大输出必须有截断元数据，未知证据不能补造。
- 设备端采集必须有明确内存上限、记录上限和失败降级路径。

## 架构规则

目标依赖方向为：

```text
设备事件/trace 格式 -> tracemiku-core -> CLI
```

分析语义必须先进入 core。CLI 只做参数解析、编排和序列化，不能独立修补结果。
跨层改动必须验证 agent、host、`meta.json`、core 和统一 CLI 链路。

反编译由外部静态工具独立提供。本仓库不维护本地反编译管线，也不通过 CLI 接入
或管理反编译器；协作使用模块偏移、符号与运行时证据。LLM 调用必须可选。

## AI 开发纪律

- 开始工作先读本文件和 `TODO.md`。`TODO.md` 只保存未完成路线图，不记录完成流水账。
- 修改前先用代码、测试和调用关系确认事实，不能根据文件名猜测。
- 优先修改已有抽象；只有能消除真实重复或隔离稳定边界时才新增抽象。
- 不为假想兼容性保留双实现、别名或废弃路径。确有外部兼容承诺时必须写测试。
- 新功能必须同时包含失败语义、资源上限、结构化输出和相邻层测试。
- 修复应位于产生错误的最底层，不允许在路由或 UI 用字符串替换掩盖语义错误。
- 不新增第二份路线图、完成报告、阶段计划或智能体专属规则。
- 单个源文件超过 1500 行后原则上禁止继续增加职责；超过 2500 行必须先拆分。
- 文档只描述当前事实、稳定契约和未完成决策。完成过程由 Git 历史保存。
- 功能使用说明的唯一汇总在 `docs/FEATURES.md`：新增/删除/改名命令必须同步更新
  对应分组与示例；参数细节不复制，以 `./tracemiku <cmd> --help` 为准，机器可读
  清单由 `./tracemiku capabilities` 自动生成。README 只做定位与快速开始，
  `docs/` 专题文档只写设计契约，禁止在多处重复维护同一命令的用法。
- 不写“由某 AI 生成”、模型署名或共同作者尾注。

## 验证要求

按风险选择最小但充分的验证集合：

```bash
make fmt
make test-fast
make test-contract
make test-v2
npm --prefix tracer run typecheck
make test-device
```

- core 语义变化：相关单测 + `cargo test -p tracemiku-core`。
- CLI 输出变化：输出字段名/类型/结构是 AI 消费契约，必须先更新
  `contract_*` 契约测试与 `scripts/contract_audit.py` 声明，再跑
  `make test-contract` 全链路（含统一入口与 core 一致性）。
- agent/格式变化：TypeScript 检查、设备测试和完整链路验证。
- 无法运行真机测试时，交付说明必须明确剩余采集风险。

## CLI 使用准则

使用专用命令；统一入口不提供 Web 启动、BN 展示、通用 `api/query` 或旧别名。全部分析命令经统一入口透传（Python 层只实现设备采集与少量编排命令），
功能目录见 `docs/FEATURES.md`，机器可读清单用 `./tracemiku capabilities`：

```bash
./tracemiku list traces/run1 --json
./tracemiku info <call_dir> --json
./tracemiku records <call_dir> --start 0 --count 50 --regs x0,x1,sp
./tracemiku taint-bwd <call_dir> --start 100 --reg x0
./tracemiku resolve <call_dir> --so libfoo.so --off 0x1234
./tracemiku cfg <call_dir> --fn sym:f_root
```

地址和偏移默认按十六进制解析，
需要十进制时使用命令帮助所示的显式格式。

CLI 输出是 AI 消费方的稳定契约：基础查询响应类型位于 core 的 `analysis/`，
部分报告模型位于 `analysis/reports/output_*.rs`，其余动态 JSON 也必须由
`rust/crates/tracemiku-cli/tests/contract_*.rs` 的 schema 校验与语义断言锁定。
修改任何命令输出必须同步更新契约测试并跑通 `make test-contract`。

## Git 安全

- 保留用户已有改动，不得重置或覆盖不属于当前任务的文件。
- 禁止未经确认使用 `git reset --hard`、`git clean -fd*`、强推或删除分支。
- 使用明确文件列表暂存，避免无差别 `git add .`。
- “完成”表示实现、验证和可审查交付均已完成，不是仅写出第一版代码。
