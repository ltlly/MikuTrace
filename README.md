# traceMiku

Android ARM64 指令级采集与离线分析 CLI，为 AI 和逆向工程师提供执行路径、寄存器、
运行时内存及跨函数数据来源。通过 `(SO, 静态偏移)` 与外部静态工具对齐。

## 快速开始

离线分析需要 Python 3.11+ 和 [指定版本的 Rust](rust/rust-toolchain.toml)。
统一入口按需构建 Rust CLI：

```bash
./tracemiku capabilities
./tracemiku capabilities --command records
./tracemiku list traces/run1 --json
./tracemiku records traces/run1/calls/<call_dir> --start 0 --count 50 --regs x0,x1,sp
```

采集另需 root Android、adb、Frida 17.x、uv 和 Node.js/npm：

```bash
uv sync
make agent
./tracemiku doctor --pkg com.example.app
./tracemiku trace --pkg com.example.app --so libtarget.so --export sign --out traces/run1
./tracemiku trace --target-profile examples/custom_target/target.json --out traces/run2
```

当需要按调用参数、寄存器或目标协议过滤采集（例如仅当第 1 个参数 `args[0]` 为 `70102` 时才采集）时，通过 `--target-profile` 挂载 `agent_plugins` 编写 `beforeTrace` 钩子（返回 `false` 或 `{ skip: true }` 跳过当前调用，完整示例见 [examples/custom_target/agent.js](examples/custom_target/agent.js)）：

```javascript
module.exports = {
  apiVersion: 1,
  beforeTrace(ctx) {
    if (ctx.args[0].toInt32() !== 70102) return false;
  },
};
```

## 文档

- [命令目录与用法](docs/FEATURES.md)，参数查 `./tracemiku <cmd> --help`。
- [架构](docs/CLI_FIRST_DESIGN.md)、[Trace 格式](docs/PER_CALL_TRACE_DESIGN.md)、[内存来源](docs/memory-completeness-design.md)。
- [采集器](tracer/README.md)、[Rust 工作区](rust/README.md)、[反检测边界](docs/anti-detection-catalog.md)。
- [工程约束与验证](AGENTS.md)、[未完成工作](TODO.md)。
