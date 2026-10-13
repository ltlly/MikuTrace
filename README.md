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
```

## 文档

- [命令目录与用法](docs/FEATURES.md)，参数查 `./tracemiku <cmd> --help`。
- [架构](docs/CLI_FIRST_DESIGN.md)、[Trace 格式](docs/PER_CALL_TRACE_DESIGN.md)、[内存来源](docs/memory-completeness-design.md)。
- [采集器](tracer/README.md)、[Rust 工作区](rust/README.md)、[反检测边界](docs/anti-detection-catalog.md)。
- [工程约束与验证](AGENTS.md)、[未完成工作](TODO.md)。
