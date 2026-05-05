# References

traceMiku 的当前实现是 Rust/Solid analysis v2。Python `viewer/`、旧
FastAPI `webui/`、legacy terminal UI 和 Python parity 测试已经从运行时架构里移除。本文件只保留
仍然有工程参考价值的外部资料和本项目当前测试入口。

## Dynamic Taint

| Source | Use |
|---|---|
| Newsome & Song, "Dynamic Taint Analysis for Automatic Detection..." | 经典 taint 传播模型 |
| Schwartz, Avgerinos, Brumley, "All You Ever Wanted to Know..." | 动态 taint 与符号执行综述 |
| Triton | 指令级 taint / symbolic execution 语义和测试用例参考 |
| angr | VEX IR 上的数据流、CFG 和 symbolic execution 参考 |
| DECAF / libdft64 | 全系统和 Pin taint 的性能/精度取舍参考 |

traceMiku 采用离线 trace replay taint：输入是已采集的 `trace.bin`，优先保证真实设备
路径、交互延迟和可解释性。它不追踪隐式流；内存 taint 以 byte overlap 和 MemShadow
为基础。

## Def-Use / SSA

- Cytron et al., "Efficiently Computing Static Single Assignment Form..."
- LLVM LiveVariables / MemorySSA
- Capstone `regs_access()`，但 ARM64 def/use 仍需要项目内 fixup 和测试兜底。

## CFG

- Cifuentes & Van Emmerik, "Recovery of Jump Table Case Statements..."
- Schwartz, Lee, Woo, Brumley, "Native x86 Decompilation..."
- Trace-based CFG 对间接跳转和混淆更稳，但只覆盖真实执行路径；静态 dead path 需要
  Binary Ninja 等静态后端补充。

## Binary Ninja

当前集成不是 traceMiku MCP server，而是本地 sidecar：

- 环境变量：`TRACEMIKU_BN_SO=/path/to/libtarget.so`
- sidecar crate：`rust/crates/tracemiku-bn-sidecar`
- server routes：`/api/hlil-for-pc`、`/api/bn-cfg-svg-for-pc`、
  `/api/asm-tokens-for-pcs`

当当前 trace PC 不在 BN 函数内时，sidecar 会尝试快速创建 user function，再取 HLIL /
Pseudo C / BN CFG。LLM 相关 UI 可以按产品状态隐藏，但 BN HLIL/Pseudo C 本身属于当前
Web UI 的静态参考能力。

## Decompiler / LLM References

- Tenet trace format：兼容性和 UI 交互参考。
- LLM4Decompile / CodeInverter：结构化 IR 喂给模型的实验参考。
- D810 / Tigress / Syntia / msynth：反 OLLVM、VM 和混淆结构识别参考。

当前 trace decompiler 的实时入口是 Rust server API 和 Solid `Decompile` / `HLIL`
面板。LLM 调用路径可以存在于 CLI/API，但默认 UI 不应暴露高延迟或未稳定的 LLM 控件。

## Current Test Entry Points

```bash
make test-fast
make test-v2
make smoke-web
make smoke-ui

cd rust
cargo test --workspace
npm --prefix frontend run build
```

新功能需要落到相邻层的测试：Rust core 单测、server route 测试、frontend smoke，或者
真实 trace probe。跨 agent、host、`meta.json`、Rust core、Rust server 和浏览器展示的
端到端变化还需要真实设备验证。
