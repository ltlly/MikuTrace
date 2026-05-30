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
| Mozilla rr (USENIX ATC'17) | record-and-replay / time-travel 调试；"在一次具体记录的执行之上做分析" 的范式锚点，框定 traceMiku 整个 trace-aware 论题和 reverse-stepping 特性 |

traceMiku 采用离线 trace replay taint：输入是已采集的 `trace.bin`，优先保证真实设备
路径、交互延迟和可解释性。它不追踪隐式流；内存 taint 以 byte overlap 和 MemShadow
为基础。这是一种 record-and-replay 风格的离线分析（参考 rr），DBI 采集走 Frida
Stalker，分析在 host 侧的 `trace.bin` 上离线进行。

## Def-Use / SSA

- Cytron et al., "Efficiently Computing Static Single Assignment Form..."
- LLVM LiveVariables / MemorySSA
- Capstone `regs_access()`，但 ARM64 def/use 仍需要项目内 fixup 和测试兜底。

## Type Inference

- Noonan et al., **retypd** (PLDI'16)：基于约束的类型恢复，是 traceMiku 类型推断的
  静态基线。**trace-driven extension direction**：在 retypd 约束上叠加观测到的值域 /
  指针约束（value 落在已映射模块区间 → pointer，high-32 永不置位 → i32，deref 到可
  打印字节 → char*），把 usage-only 推断升级为 observed-value 推断。
- Lee, Avgerinos, Brumley, **TIE** (NDSS'11)：二进制上的可扩展类型推断。**trace-driven
  extension direction**：用观测值集合直接定 bool（`{0,1}`）/窄整型 / 指针，而不是只靠
  静态使用约束。

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

## Trace-Aware Decompiler Thesis

traceMiku 的反编译器不是又一个静态反编译器，差异点全部来自它持有一条真实执行轨迹
（per-block 的并发输入/输出已被记录）。可落地的 trace-only 能力：

- **Concretize observed values** — 把每次执行都相同的运行时值折叠进 IL（解密后的
  key、加载的全局、算出来的指针变成可读常量），而不是停留在符号表达式。
- **Prune never-executed paths** — 从相邻记录 PC 推出 executed-edge 集合，剪掉从未
  走过的分支再做结构化，比静态情形更容易消 goto。
- **100% indirect control-flow resolution** — `blr`/`br xN` 的真实目标直接来自下一条
  记录的 PC，无需间接跳转表恢复或猜测。
- **Struct recovery from observed addresses** — 按运行时观测到的 base 指针聚类内存
  访问，恢复真实字段 offset/宽度/嵌套指针。
- **CFF / VM linearization** — 沿被执行的单条路径把 OLLVM control-flow flattening 的
  dispatcher 或 VM handler 循环线性化成顺序代码。

因为每个 block 的具体 I/O 已被记录，上面这些综合任务严格比相关论文的黑盒威胁模型更
简单。当前 trace decompiler 的实时入口是 Rust server API 和 Solid `Decompile` /
`HLIL` 面板。LLM 调用路径可以存在于 CLI/API，但默认 UI 不应暴露高延迟或未稳定的 LLM
控件。

## LLM Decompilation

| Source | Year | Relevance |
|---|---|---|
| LLM4Decompile | 2024 (EMNLP) | LLM 反编译；Ref-mode 精炼已有反编译输出 + re-executability 指标，可作 TraceIR/`/api/dec/*` 与 eval 工具的度量基线 |
| SLaDe | 2024 (CGO) | 200M ARM 聚焦的本地小模型反编译 + 类型推断，契合 TraceIR 的 ARM64/单机本地路径 |
| DIRTY | 2022 (USENIX Security) | Transformer 对反编译输出做 rename/retype，是变量改名/设类型 UX 与类型推断的基线 |
| ReSym | 2024 (CCS, Distinguished Paper) | LLM + Prolog 一致性聚合做变量/结构体恢复；trace 提供它要推断的真实 base 地址 |
| Nova | 2025 | 分层注意力汇编 LLM，可作 TraceIR 序列化 / 模型选项参考 |

## Deobfuscation / Synthesis

| Source | Year | Relevance |
|---|---|---|
| Syntia | 2017 (USENIX Security) | 基于 I/O 的 MCTS 程序综合（MBA / VM handler），对应 `mlil/deobfuscate.rs` |
| Xyntia | 2021 (DATE) | ILS 黑盒综合，Syntia 的快速后继，per-block 适合 spawn_blocking |
| QSynth | 2020 (BAR) | 离线表驱动 greybox 综合，延迟最低的 cache-friendly 变体 |
| Yadegari et al. | 2015 (IEEE S&P) | trace + taint 去混淆，沿执行路径展平 VM/CFF — traceMiku 已同时有 trace 与 taint 引擎 |

## Structuring (control-flow recovery)

| Source | Year | Relevance |
|---|---|---|
| SAILR | 2024 (USENIX Security) | 编译器感知结构化，大幅减少 goto（angr 内）；用于 `hlil/pass_restructure.rs` 的现代化与按执行路径结构化 |
| Yakdan et al., DREAM "No More Gotos" | 2015 (NDSS) | 无 goto 结构化的奠基工作 |
| Schwartz et al., Phoenix | 2013 (USENIX Security) | 语义保持的结构化算法，ipostdom 合并规则 |

D810 / Tigress / msynth 仍作为反 OLLVM、VM 和混淆结构识别的工程参考。Tenet trace
format 作为 trace 兼容性和 UI 交互参考。

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
