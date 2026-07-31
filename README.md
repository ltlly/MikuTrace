# traceMiku

traceMiku 是面向 Android 真机 ARM64 的指令级动态追踪和运行时分析工具。它记录真实
执行路径，并提供 CFG、调用树、寄存器与内存查询、污点追踪、数据来源、密码特征扫描、
本地三层 IL 和 Web 交互分析。

项目不试图替代 IDA、Ghidra 或 Binary Ninja。静态工具负责完整代码结构，traceMiku
通过统一的 `(SO, 静态偏移)` 坐标补充真实跳转目标、运行时值、解密后内存和跨函数
数据来源。

## 目录

```text
tracer/                         Frida 设备端采集器
rust/crates/tracemiku-core/     分析语义和数据模型
rust/crates/tracemiku-cli/      JSON CLI
rust/crates/tracemiku-server/   Axum API 与静态站点
frontend/                       Solid Web UI
tools/hooks/                    目标相关 JSON 配置
examples/                       示例配置与算法验证
docs/                           当前契约和专题指南
```

## 环境

- Python 3.11+ 与 `uv`
- Rust 工具链由 `rust/rust-toolchain.toml` 固定
- Node.js 与 npm
- 真机采集需要 adb、root 和 Frida 17.x

安装前端和采集器依赖：

```bash
npm --prefix frontend install
npm --prefix tracer install
npm --prefix tracer run build
```

`_agent.js` 是默认采集器，由 `tracer/src/` 编译生成；仓库内的
`agent_cmodule_v5.js` 只用于 `--mode legacy` 回退。

## 快速开始

```bash
# 环境诊断
./tracemiku doctor --pkg com.example.app

# 采集指定导出函数
./tracemiku trace --pkg com.example.app --so libtarget.so \
  --method nativeFn --out traces/run1

# 不启用 Stalker 的轻量调用探测
./tracemiku probe --pkg com.example.app --so libtarget.so --duration 10

# 查看采集结果
./tracemiku list traces/run1 --json
./tracemiku info traces/run1/calls/<call_dir> --json

# 启动 Web UI
./tracemiku web traces/run1/calls/<call_dir> --port 18900
```

需要 Binary Ninja HLIL/CFG 时传入目标 SO：

```bash
./tracemiku web <call_dir> --so /path/to/libtarget.so --port 18900
```

## 面向 AI 的查询

CLI 是首选自动化入口，输出为结构化 JSON：

```bash
./tracemiku resolve <call_dir> --so libtarget.so --off 0x1234
./tracemiku indirect-targets <call_dir> --so libtarget.so --off 0x1234
./tracemiku reg-at <call_dir> --reg x0 --so libtarget.so --off 0x1234
./tracemiku mem-export <call_dir> --so libtarget.so --off 0x2000 --len 0x100
./tracemiku coverage <call_dir> --fn trace:F0
./tracemiku taint-bwd <call_dir> --start 1000 --reg x0
./tracemiku dec <call_dir> --summary
```

地址和偏移默认按十六进制解析（`10` 即 `0x10`），需要十进制时加 `d` 前缀（`d16`）。
完整命令以 `./tracemiku --help` 和子命令 `--help` 为准。已有专用命令时不要使用通用
`api`，也不要仅为查询而启动 Web server。

## 分析边界

`MemShadow` 只对观测到的字节负责。来源 `w`、`r`、`x`、`i` 分别表示 trace store、
trace load、外部写和初始快照；`??` 表示未知，绝不能当作零。详情见
[内存完整性设计](docs/memory-completeness-design.md)。

TraceIR、本地 LLIL -> MLIL -> HLIL 和 trace 增强反编译管线均为当前能力，区别见
[反编译架构](docs/trace-decompiler-design.md)。Trace 目录及二进制格式见
[Trace 数据契约](docs/PER_CALL_TRACE_DESIGN.md)。

## 开发与测试

```bash
make test-fast       # Python 检查 + Rust core/CLI
make test-contract   # 契约审计 + CLI/server/core 契约测试 + tracer 格式契约 + CLI/API 一致性
make test-v2         # Rust 全工作区 + 前端构建 + CLI/API 一致性
npm --prefix tracer run typecheck
make test-device     # 需要 Android 设备
```

契约测试（`make test-contract`）是黑盒/公共接口级：CLI 的每个命令输出和 server
的每个 route 都必须在 `scripts/contract_audit.py` 声明的契约测试文件中有 schema
校验与语义断言覆盖；tracer 的 272 字节记录格式有独立的 TS 契约测试；CLI 与 server
同分析结果逐字段一致（`scripts/rust_cli_web_parity.py`）。CLI 输出由
`rust/crates/tracemiku-cli/src/output_types*.rs` 的类型化模型序列化，字段名与结构
是 AI 消费方的稳定契约，改动必须同步更新契约测试。

工程规则见 [AGENTS.md](AGENTS.md)，当前路线图见 [TODO.md](TODO.md)，性能基线见
[BENCHMARKS.md](BENCHMARKS.md)。
