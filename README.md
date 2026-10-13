# traceMiku

traceMiku 是面向 Android 真机 ARM64 的指令级动态追踪和离线分析工具，为 AI 与脚本
提供真实执行路径、间接跳转目标、寄存器值、运行时内存和跨函数数据来源。

项目通过 `(SO, 静态偏移)` 与 IDA、Ghidra、Binary Ninja 等专业静态工具协作。
静态工具独立使用；traceMiku 专注采集与运行时证据，CLI 不接入反编译器。

## 架构

```text
tracer/                       Frida TypeScript 设备端采集器
tracemiku*.py + tracemiku      Python 采集编排与统一入口
rust/crates/tracemiku-core/   解析、索引、查询与全部分析语义
rust/crates/tracemiku-cli/    参数解析与结构化 JSON 输出
tools/hooks/、examples/        目标配置、可信插件与使用示例
```

分析命令直接调用 core，不启动服务。架构与契约见
[采集与 CLI 设计](docs/CLI_FIRST_DESIGN.md)，完整功能与命令选择见
[功能目录](docs/FEATURES.md)。

## 环境与快速开始

分析已有 trace 需要 Python 3.11+ 与 Rust 工具链（由 `rust/rust-toolchain.toml` 固定），
不需要设备或 Frida 会话。统一入口在需要时构建 Rust CLI：

```bash
./tracemiku capabilities
./tracemiku capabilities --command records
./tracemiku list traces/run1 --json
./tracemiku info traces/run1/calls/<call_dir> --json
./tracemiku records traces/run1/calls/<call_dir> --start 0 --count 50 --regs x0,x1,sp
```

真机采集另需 adb、root、Frida 17.x 和 `uv`；构建 agent 需要 Node.js/npm：

```bash
uv sync
npm --prefix tracer install
npm --prefix tracer run build
./tracemiku doctor --pkg com.example.app
./tracemiku trace --pkg com.example.app --so libtarget.so \
  --method nativeFn --out traces/run1
```

默认 attach 已运行的进程。spawn、调用探测、目标 profile、插件和中断恢复的用法集中在
[功能目录](docs/FEATURES.md)，参数以各命令的 `--help` 为准。

## 数据与证据

每次调用保存为 `calls/call_<序号>_tid<线程>_<记录数>r_<耗时>ms/`，包含 `trace.bin`
和 `meta.json`，以及可选的 JNI、外部写、内存快照等 sidecar。每条 trace 记录固定
272 字节，寄存器表示指令执行前状态。也可用符合契约的其他采集器提供数据。

内存来源 `w/r/x/i` 分别表示 trace store、trace load、外部写与初始快照；`??` 表示未知，
不能当作零或已验证值。启发式结论、未观测路径与截断结果都需要结合证据边界理解。

- [Trace 数据契约](docs/PER_CALL_TRACE_DESIGN.md)
- [内存完整性设计](docs/memory-completeness-design.md)
- [设备端入口与数据通路](tracer/README.md)

## 开发与验证

```bash
make test-fast       # host 检查、采集插件契约、Rust core/CLI 测试
make test-contract   # schema、命令审计、core/统一入口一致性及采集格式契约
make test-v2         # 离线全链路测试，含 agent 类型检查
make test-device     # 需要 Android 真机
```

离线测试不启动 HTTP 服务，也不依赖前端或反编译器。真机采集稳定性与性能需要独立
验证。工程规则见 [AGENTS.md](AGENTS.md)，工作区说明见 [rust/README.md](rust/README.md)，
未完成工作见 [TODO.md](TODO.md)，测量边界见 [BENCHMARKS.md](BENCHMARKS.md)。
