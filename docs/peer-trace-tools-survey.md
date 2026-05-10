# Peer Trace Tools Survey & Trace‑Centric Decompilation Research

> Status: research only, no code changes.
> Scope: 同类项目 `imj01y/trace-ui`、`lidongyooo/GumTrace` 的设计调研，
> 与 traceMiku 当前 v2 (Rust core + Solid UI + 可选 BN sidecar) 的对比，
> 以及面向 trace 场景的反编译/反混淆研究综述。
> 写作日期: 2026‑05‑10。

---

## 1. 同类项目快照

### 1.1 `lidongyooo/GumTrace` —— 设备端采集 + 离线 taint

| 维度 | 内容 |
|---|---|
| 定位 | ARM64 真机指令级追踪器，Android + iOS |
| 形态 | 注入目标进程的 `.so` (C/C++)，CMake≥3.10，依赖 Frida Gum 17.8.x 静态库 |
| 引擎 | Frida Gum **Stalker** 做 instrumentation，**Capstone** 解析操作数 |
| 输出 | 文本日志，约 **1 GB / 3 s** 真机吞吐；10 MB 内存缓冲降 IO |
| 行格式 | `[module] 0xABS!0xREL mnemonic operands; reg=val mem_r=addr mem_w=addr`，函数调用展开为 `call func: name(args) -> ret` |
| 高层捕获 | BL/BLR/BR/B 自动调用拦截 + 符号匹配；SVC syscall trace；JNI 参数解析；iOS `objc_msgSend` 类/selector 解析 |
| 离线分析 | 自带 `src/taint/` 子项目，CLI + **010 Editor 插件 `TaintTracker.1sc`**，支持寄存器/内存/NZCV 双向 taint，零分配解析 GB 级日志 |
| 可视化 | 官方点名 **Trace UI** 作为配套查看器 |
| 工程指标 | 327 ★ / 119 fork，7 个 release，活跃维护 |

**做得好的地方**

* **极简数据流**: 行式文本日志，跨工具友好，文本过滤 / `grep` / 自写脚本可直接接入。
* **设备端只管"快和窄"**: 10 MB buffer + 系统模块自动排除，专注 target SO，减少噪音。
* **JNI / ObjC 在采集端就解析掉**: 不把符号还原成本扔给查看器。
* **taint 与采集解耦**: 离线工具独立编译、独立运行，不与 viewer 强绑定，给 010 Editor 这种重量级工具一个直接入口。

**潜在弱点**

* 文本日志在记录密度上有上限，亿级行需要外部工具索引。
* 没有自带的 CFG/函数视图，需要 Trace UI 才能拿到全貌。
* 跨 trace diff、多 fork、per‑call 切片这些更结构化的概念由配套 viewer 而非格式承担。

---

### 1.2 `imj01y/trace-ui` —— 单机桌面 viewer，主打"亿行流畅"

| 维度 | 内容 |
|---|---|
| 定位 | ARM64 trace 可视化与分析的桌面工具 |
| 形态 | **Tauri 2 + React 19 + Vite** 桌面 app；后端是 Rust workspace，4 crates |
| Crates | `trace-parser` (GumTrace + unidbg 自动检测) / `trace-core` (索引、taint、调用树、内存、寄存器、字符串、crypto) / `trace-mcp` (MCP 协议) / `trace-cli` (独立 MCP server) |
| 关键工程 | mmap 零拷贝 + `@tanstack/react-virtual` 虚拟滚动；**bincode 持久化缓存**，2400 万行索引 ~15 s，二次秒开；Canvas 做语法高亮 |
| 数据格式 | GumTrace + **Unidbg**（含官方修改版 `AssemblyCodeDumper.java`），自动检测 |
| Taint | 在预构建依赖图上做 **BFS 反向传播**，独立的 data / control 依赖开关，Filter / Highlight 双模式 |
| Crypto 扫描 | 28 种 magic 常量（AES/DES/SM3/MD5/SHA/CRC32/TEA/RC4 …） |
| 调用树 | 自动识别 BL/BLR/RET，支持函数重命名、折叠、聚合 |
| 字符串 | 从内存写出口提取，含 xref 与 hex/text |
| DEF/USE | 点寄存器名画 def/use 箭头 |
| AI 集成 | **MCP Server，10 个 tool**：`open_trace`, `get_trace_lines`, `get_memory`, `search_instructions`, `taint_analysis`, `get_tainted_lines`, `get_call_tree`, `analyze_function`, `get_strings`, `analyze_crypto` |
| UX | 14 主题、IDA 风格快捷键 (`;` 注释、Alt+1‑5 高亮)、minimap、navigation 历史 |
| 协议 | License 自 v0.5.4 起改为 "Personal Use License"，商用需授权 |

**做得好的地方**

* **可扩展 4‑crate 架构和 traceMiku 几乎同构**: `parser / core / mcp / cli`，能让 Rust core 复用到桌面、CLI、AI 三个面，没有把分析逻辑锁在 UI 里。
* **MCP 选择 10 个高粒度 tool 一次曝光**: 比传统 REST 更适合 LLM agent，配合 IDE 内 agent 用得舒服。
* **持久化缓存做到产品级**: bincode 落盘，二次打开秒级，避免每次重算依赖图。这是同类工具最容易忽视的细节。
* **24 M 行 / 15 s 索引** 这种公开性能数字立得住，是说服用户"敢拿大 trace 进来"的关键信号。
* **依赖图驱动的 BFS taint** + control / data 拆开，比传统 trace 内单步 taint 在大文件上更快、更有解释性。
* **DEF/USE 箭头**、字符串面板、调用树合并、磁盘缓存、IDA 风格快捷键 —— 把"小工具的人体工学"全做齐，让每一个常用动作都有键盘路径。

**潜在弱点 / 限制**

* 目标主要是"读 trace"，**不做设备端采集**，依赖 GumTrace / Unidbg 给上游。
* x86/x64 暂未提及；core 假设 ARM64。
* MCP 是双刃剑: 把 trace 投给外部 LLM 会出现合规和成本问题，且 MCP 行为只在桌面 app 注册，远程协作场景偏弱。
* **桌面分发**比 Web 部署更难做"一键拉别人来看 trace"，远程协作和共享 URL 的能力天然弱。
* 商业许可调整后社区贡献意愿可能下降。

---

### 1.3 横向对照: Tenet / Frinet / Hooah‑Trace

为避免只在两个项目之间打圈，列入业界三个常被引用的同类品。

| 项目 | 形态 | 采集 | UI | 强项 | 弱项 |
|---|---|---|---|---|---|
| `gaasedelen/tenet` | IDA 插件 | 不带（用户自己跑 DBI） | IDA 内部 timeline + paint trail + memory R/W 时间线 | 与 IDA 数据共享、breakpoint over memory | 仅 IDA 7.5+，仅 x86/x64，纯 viewer |
| `synacktiv/frinet` | Frida 端 + 改版 Tenet | Frida Stalker + JS / 原生 callback，~400k ips | IDA + Tenet 增强（Call Tree、memory search） | 多平台多架构、IDA 原生体验 | 强依赖 IDA、不是独立 viewer |
| `iGio90/Hooah-Trace` | 库 / TS API | Frida Stalker (ARM64 + x86_64) | 终端彩色块树 | 灵活、按指令类型过滤、易嵌入脚本 | 没有 GUI、没有持久索引、规模上限低 |

---

## 2. 项目共性总结

把 GumTrace、Trace UI、Tenet、Frinet、Hooah‑Trace 五者并列看，**共性极其稳定**，
说明 trace 工具链已经收敛出一套事实上的"必备清单"：

1. **采集与查看分离**
   设备端只做"快、稳、窄"的 instrumentation；分析全部下沉到 host，
   因为 trace 一旦写出，唯一的瓶颈就是 host 的 IO/CPU，不是设备。
   traceMiku 也是这样组织：`tracer/` 不做 IR/CFG，全部留给 Rust core。

2. **mmap + 虚拟滚动 + 索引落盘**
   亿行 trace 的"看"由三件套支撑，谁少一个谁就被淘汰。Trace UI 把它做到极致，
   bincode 落盘是它"二次秒开"的关键。

3. **指令 + 寄存器 + 内存 + 调用 四件**齐全
   行格式都覆盖：地址、模块、汇编、`reg=val`、`mem_r/mem_w`、调用上下文。
   GumTrace 在采集层就把 JNI / ObjC / SVC 解析为 high‑level 名字，
   Trace UI 在 viewer 层补 BL/BLR/RET 调用树。

4. **依赖图 / SSA‑lite + 反向 taint**
   反向 taint 已成标配，因为它给"这个值是怎么来的"这种逆向核心问题最直接的答案。
   Trace UI 把 taint 跑在预构建的依赖图上 + BFS，是性能与可解释性的折中。

5. **小而强的搜索面**
   字符串提取（从内存写）、crypto magic 扫描、指令模式搜索 —— 这三件几乎所有
   工具都做了，因为它们对"找入口、找算法"立竿见影。

6. **键盘优先、IDA 风格**
   `;` 注释、`G` 跳转、`Alt+数字` 高亮、forward/back history。
   逆向工程师的肌肉记忆已经被 IDA / Hex‑Rays 锁定，不沿用就要付教育成本。

7. **AI / 脚本接入面** 在迅速成型
   Trace UI 选 MCP；GumTrace 通过 010 插件 + CLI；Frinet 借 IDAPython。
   把"trace 能做什么分析"暴露为可被外部 agent 调用的工具列表，是 2025‑26 年的
   分水岭。

---

## 3. 与 traceMiku 当前架构的对比

### 3.1 设计同构

下面这部分 traceMiku 已经做了，与同类项目对齐：

| 同类必备 | traceMiku 对应 | 备注 |
|---|---|---|
| 采集 / 查看分离 | `tracer/agent_cmodule_v5.js` ↔ `rust/crates/tracemiku-core` | 分得很干净，agent 只产 `trace.bin + meta.json` |
| mmap 解析 | `core/trace/` mmap parser | 272 字节定长记录，零拷贝索引 |
| Reg / Mem 索引 | `index.rs`, `memshadow.rs` | 含 sparse 字节级 MemShadow 边车 |
| 函数模型 | `function_index.rs` (`trace:` / `sym:` / `bn:` 三类 ID) | 比 Trace UI 的纯 trace 函数更宽 |
| CFG 重建 | `cfg.rs` + 服务端 `cfg.rs` / `cfg_svg.rs` | 含 large‑graph overview + edge 计数披露 |
| Taint | `taint.rs` 双向 + dependency metadata | 与 Trace UI 思路同构 |
| 调用树 | `calltree.rs` + `routes/call_tree.rs` | 已有路由 |
| 字符串、crypto、xref | `strings.rs` / `crypto_scan.rs` / `xref/` | 业界必备项已经齐备 |
| LLIL 路径 | `core/llil/` (lift/SSA/常折/DCE/restructure 等多 pass) + `routes/llil_*` | 比同类多一条 in‑house C‑like pseudo 通道 |
| Decompiler 路径 | `core/decompiler/` (ir/builder/render/prompt/backend/vm_candidate/type_anchor) | 把 trace 折叠为函数/块/loop/anchor 的 TraceIR |
| BN sidecar | `bn_sidecar.rs` + `routes/bn_*` | 提供静态 HLIL/CFG 补全 |
| 高级分析 | `dep_graph`, `mem_flow`, `forward_taint`, `backward_taint`, `string_provenance`, `hash_finalize`, `ollvmdet`, `fork_events`, `jni_*`, `data_chase`, `diff_traces`, `timeline_diff` | 这是 traceMiku 比 Trace UI 走得更深的一段 |
| Web 优先 UI | Solid + Vite，52 个 server 路由覆盖各 panel | 与 Trace UI 桌面路线相反 |

### 3.2 traceMiku 比同类项目领先的部分

1. **per‑call 切片是格式级原语**
   `calls/call_<idx>_tid<T>_<records>r_<ms>ms/` 是 schema 一部分，
   GumTrace / Trace UI 是把整段 trace 当一份大文件在切。
   per‑call 让 fork / 多线程 / 多次同函数调用变成一等公民。
2. **三类函数 ID** (`trace:` / `sym:` / `bn:`)
   把"trace 看到的"、"符号告诉我们的"、"BN 静态识别的"作为不同来源并存，
   匹配真实逆向工作流。Trace UI 只有 trace 维度的函数。
3. **可选 BN sidecar**
   静态 HLIL / Pseudo C / CFG 与 trace 联动，trace 没覆盖的代码也能看，
   且能在 trace PC 没有 BN 函数时**创建 user function 后重试**，把
   "trace 与静态视图脱节"这一逆向常见痛点直接收掉。
4. **TraceIR + in‑house LLIL 双通道**
   `core/llil/` 是不依赖 LLM 的 C‑like pseudo，`core/decompiler/` 是给人 + LLM 的
   高层摘要 IR。其它项目仅在"渲染汇编 + taint"层面停下。
5. **专项分析**
   `hashfin.rs`、`ollvmdet.rs`、`fork_events`、`jni_events`、`jobj_history`、
   `string_provenance`、`hash_input_search`、`timeline_diff` 等明显是从对抗
   xsign / OLLVM / 加固 SO 这种**真实工作负载**反推出来的接口。
   Trace UI 走的是"通用 trace viewer"，没有这些。
6. **Web 优先 + 标准 OpenAPI**
   `/openapi.json` + 52 路由是 LLM 友好且远程协作友好的设计，比 Trace UI 桌面 +
   MCP 的方案天然更适合多人共享一段 trace。

### 3.3 traceMiku 可以从同类项目吸收的部分

下面这些是同类项目做得好、traceMiku 当前**值得评估**的方向（**仅评估，不在本调研中实施**）：

1. **持久化缓存的"产品级体验"**
   Trace UI bincode 全量落盘，二次秒开。traceMiku 已经有 warmer 与 spawn_blocking
   设计，但要明确"哪些索引是磁盘可缓存的、放在哪、何时失效"，并把它做成用户可见
   的"打开 N 秒 → 缓存 OK"反馈。
2. **更显式的虚拟滚动 / 行级懒加载承诺**
   Trace UI 公布了"24 M 行 15 s 索引"。traceMiku 可以在 README/BENCHMARKS.md
   增加"目标性能数字 + 实测数字"对照表，把性能口径变成可验证的契约。
3. **DEF/USE 点寄存器画箭头** 这种交互
   traceMiku 已经有 `last_write_of_reg` / `next_use_of_reg` 后端，
   差一个"在 records panel 直接点寄存器名画连线"的 UI 形态。
4. **Crypto magic 扫描的"可视化结果列表"**
   `crypto_scan.rs` 已有；可借鉴 Trace UI 的"扫描结果是一个独立面板，
   每条带跳转锚点"的呈现方式。
5. **MCP / Tool 化暴露面的明确决策**
   CLAUDE.md 已经有"不做 MCP，走 CLI + REST + SDK"的硬规则。
   值得在 README 里明确解释 trade‑off，避免让外部用户与 Trace UI 比较时
   误以为是漏洞。CLI JSON 输出已经在做，可以补一份"MCP‑style 工具列表"映射文档，
   让接入 LLM 的人一眼看见对应关系。
6. **采集端的 high‑level 解析**
   GumTrace 在设备端就把 JNI / ObjC / SVC 解析成可读名字。
   traceMiku 现在 JNI 相关解析多在 host 侧，可以评估：哪些信息只有设备能拿
   （argv 字符串、jstring 内容、ObjC selector），适合在 agent 写入 `meta.json`
   或独立 sidecar 文件，避免 host 侧再做一次 JVM/Runtime 复原。
7. **Forward/back navigation 历史**
   IDA 风格 history。traceMiku 已经有 `g` 跳转，缺一个统一的 history stack。
8. **"Personal Use License" 的反面教材**
   不要走这条路。维持 OSS license，对一个面向研究者社区的工具是流量基础。

---

## 4. 面向 trace 场景的反编译/反混淆研究综述

这部分回到用户问题的另一半：**针对 trace 数据的"反编译"思路**。
本节把学术界 + 工业界的主流路线整理为四类，并标注对 traceMiku 的适用度。

### 4.1 路线 A: Trace‑Informed 静态反编译 (Tenet / Frinet 方式)

**核心思想**: trace 不当反编译输入，而当**静态反编译的"动态注释"**。
寄存器值、内存读写、call/ret 时间线在 IDA / BN 的静态视图上"上色"。

**代表**: Tenet 的 timeline paint、Frinet 的 Call Tree。

**优点**: 工程量小、与现有 RE 工作流（IDA / BN / Ghidra）兼容。
**缺点**: 不产出独立 IR / Pseudo C，实质上是把 trace 当上下文，没有"反编译输出"。

**对 traceMiku 的对应**: BN sidecar + HLIL panel 已经是 A 路线，
完成度已经追上业界。

---

### 4.2 路线 B: 从 Trace 抽 DFG/SSA + 符号执行 (Triton / QBDI 方式)

**核心思想**: 把 trace 当一条线性的指令流，对每条指令构造 SSA 变量，
用符号执行/常量传播提取**数据流图 (DFG)**，再做 taint 切片或表达式简化。

**代表**: Quarkslab "Exploring Execution Trace Analysis" 中的 QBDI + Triton 流程。
**典型应用**: 虚拟化保护 (VMProtect / Themida) 的 handler 提取、
混淆 MBA 表达式的化简、加密算法的 buffer 还原。

**关键能力**

* **Trace → SSA**: 每个寄存器的每次写入是一个新 SSA 名字，内存按字节抽象。
* **符号化**: 用户挑一个 sink (寄存器/内存)，引擎反向把所有定义它的 op 收集为
  symbolic expression。
* **Slicing**: 用 taint 把"无关于此 sink 的指令"剪掉，保留最小可读路径。
* **简化**: Z3/Triton 化简，或用 Syntia 这种 program synthesis 用 I/O 对找等价
  更短表达式（特别擅长 MBA）。

**优点**: 直接针对反混淆问题；能把"几千条 obfuscated op 化简成几行"。
**缺点**: SMT / synthesis 速度慢、可能有"看起来对但不等价"的解，需要验证；
单 trace 只覆盖一条路径，多分支需要多 trace 拼接。

**对 traceMiku 的对应**: `core/llil/ssa.rs` + 多 pass (`pass_constfold`,
`pass_dce`, `pass_uidf`, `pass_var_unify`, `pass_typelat`, `pass_restructure`)
就是 B 路线的"in‑house 简化版"，没有外接 SMT，因此速度快、可解释。
**可演进方向**：把 sink → backward DFG 这条路径打通到 UI（已经有 dep_graph
路由），并选择性接入外部 SMT/Synthesis 做"难化简块"的离线 batch，而非交互
路径，避免破坏延迟保证。

---

### 4.3 路线 C: 虚拟化反混淆 (Trace‑Based Devirtualization)

**核心思想**: 针对 VMP / Themida / xsign 一类**custom VM**，用 trace 抓取
handler 序列，识别 dispatcher，再以"VPC → handler"为模型重建被保护代码的
原始 CFG/IR。

**代表论文 / 工具**

* Yadegari & Debray, "Generic Approach to Automatic Deobfuscation" — taint +
  symbolic execution → simplified trace。
* Salwan / Bardin / Potet, "Symbolic Deobfuscation" (DIMVA 2018) — Triton 路线
  的代表。
* Zeng et al., "Deobfuscation of Virtualization‑Obfuscated Code" — 三模块：
  trace 分析 → 符号执行 → 编译优化产出 C。
* "Pushan" (2026) — **trace‑free** + VPC‑sensitive 符号模拟，**首个**把
  虚拟化代码反编译为高质量 C pseudocode 的方法。
* "Control‑Flow Deobfuscation using Trace‑Informed Compositional Program
  Synthesis" (POPL 2024) — 用 dynamic trace 推 CFG skeleton，再 per‑block
  synthesis，86% 的 case 与原程序"几乎相同"。

**关键能力**

* **Handler 识别**: 用频次 / call/ret pattern / dispatcher 形态做聚类。
* **VM Bytecode 重建**: 把 handler 编号映射回"虚拟指令"。
* **CFG 重建**: 在 VPC 上做"哪个 VPC 跳哪个 VPC"的边集合。
* **Per‑block 合成**: 对每个 handler 用 program synthesis 求等价语义短表达式。

**对 traceMiku 的对应**: `core/decompiler/vm_candidate.rs` + `ollvmdet.rs` 已经
布点，明显是面向 OLLVM / 虚拟化保护的初期识别基础设施。
**可演进方向**：

* 做"handler 签名库"：常见 OLLVM bogus control flow / dispatcher 形态做模式匹配。
* 把 per‑call 切片自然延伸为 per‑VPC 切片：当识别到 VM dispatcher，
  把 trace 重切成"每条虚拟指令一段"，这与现有 per‑call 目录架构是同构的。
* 评估 Pushan 思路：trace‑free + VPC 敏感的离线 batch，作为"重型"分析路径。

---

### 4.4 路线 D: LLM / 神经网络辅助反编译

**核心思想**: 把 trace 或 disassembly 投给 LLM，让模型直接输出 pseudo‑C，
或在传统 IR → pseudo 阶段使用 LLM 改善变量命名 / 重构。

**代表**

* `LLM4Decompile` (NDSS 2025) — 直接 binary → C 的 LLM。
* `DecompileBench` — 用运行时一致性（替换函数后整个程序仍能跑）评估反编译质量，
  比 BLEU 这种文本匹配更靠谱。
* "Disassembling Obfuscated Executables with LLM" (USENIX 2024) — 用 LLM 改善
  对抗反汇编的 C 代码恢复。

**优点**: 命名 / 注释自然语言层非常强；能补 SMT 化简器写不出来的 idiom。
**缺点**: 易"幻觉等价"——产出的代码看似合理但语义不等价，必须有验证回路；
trace 全文一次喂给 LLM 既贵又对 context window 有压力。

**对 traceMiku 的对应**: `core/decompiler/prompt.rs` + `routes/dec_llm_call.rs` +
`llil_llm.rs` 已经留好接口，
当前的设计要求"UI 默认隐藏 LLM 入口直到延迟稳定"。
**可演进方向**:

* 维持 TraceIR 摘要小而稳，**LLM 喂的是摘要不是 raw trace**。
* 加"反向验证"通道：让 LLM 给 pseudo‑C 时同时给出"它认为关键的几个 trace
  断言"，host 用 trace 实际值核对一致性，只有通过的才信任。
* 借鉴 DecompileBench：把"replace 后能否复跑出同样结果"作为离线 bench 标准，
  而不是只看 pseudo 长得像不像 C。

---

### 4.5 路线综合判断（针对 traceMiku 的口径）

| 路线 | 当前状态 | 短期 ROI | 长期 ROI | 风险 |
|---|---|---|---|---|
| A: Trace‑annotated 静态反编译 | 已具备（BN sidecar + HLIL） | 持续打磨 | 中 | 依赖 BN |
| B: Trace → SSA / DFG | 已具备（in‑house LLIL 多 pass） | 把 backward DFG → UI | 高 | 复杂 IR 维护成本 |
| C: VM / OLLVM 反混淆 | 初步（vm_candidate, ollvmdet） | per‑VPC 切片 | 极高（对真实 hardened SO 决定胜负） | 算法工程量大 |
| D: LLM 辅助 | 已留接口 | 摘要 → LLM；离线验证 | 中‑高 | 幻觉、成本、隐私 |

把 ROI / 风险综合起来看，traceMiku 现在最值得**先把 B 路线在 UI 端走通**
（因为后端基础最完整、用户感知最直接），同时**研究 C 路线的 per‑VPC 切片**
（因为这是与 xsign / OLLVM 这类真实工作负载直接相关的差异化能力）。
A 与 D 维持当前节奏即可。

---

## 5. 一页总结

* 同类项目 (GumTrace, Trace UI, Tenet, Frinet, Hooah‑Trace) 已经收敛出
  "采集/查看分离 + mmap+索引落盘 + 双向 taint + 调用树 + 字符串/crypto 扫描 +
  IDA 风格快捷键 + AI/脚本接入面"的事实标准。
* traceMiku 在所有"业界标准面"已经达到或超过；独有的优势是 **per‑call 切片**、
  **三类函数 ID**、**BN sidecar 联动**、**TraceIR + in‑house LLIL 双反编译通道**、
  **针对加固 SO 的专项路由 (hashfin/ollvmdet/jni_*/fork/timeline_diff)**、
  **Web 优先的远程协作形态**。
* 同类项目可以借鉴的具体点：**bincode 持久化缓存的产品级体验**、
  **公开的性能口径**、**DEF/USE 点选画箭头交互**、
  **统一的 forward/back history**、**MCP vs CLI/REST 的对外解释清晰化**。
* trace 反编译研究上，**B (DFG/SSA + 符号化简)** 与 **C (Trace‑informed
  devirtualization)** 是 traceMiku 最值得加深的两个方向；
  **D (LLM)** 应保持"摘要喂模型 + 离线验证"的纪律；
  **A (静态注释)** 已经稳定。

---

## 参考链接

### 同类项目
- [imj01y/trace-ui (GitHub)](https://github.com/imj01y/trace-ui)
- [lidongyooo/GumTrace (GitHub)](https://github.com/lidongyooo/GumTrace)
- [gaasedelen/tenet (GitHub)](https://github.com/gaasedelen/tenet)
- [synacktiv/frinet (GitHub)](https://github.com/synacktiv/frinet)
- [iGio90/Hooah-Trace (GitHub)](https://github.com/iGio90/Hooah-Trace)

### Frida Stalker 与 trace 工具背景
- [Frida Stalker docs](https://frida.re/docs/stalker/)
- [Tenet: A Trace Explorer for Reverse Engineers (RET2 blog)](https://blog.ret2.io/2021/04/20/tenet-trace-explorer/)
- [Plugin focus: Frinet — Hex-Rays](https://hex-rays.com/blog/plugin-focus-frinet)
- [Frinet: reverse-engineering made easier (Synacktiv)](https://www.synacktiv.com/en/publications/frinet-reverse-engineering-made-easier)

### Trace 反编译 / 反混淆研究
- [Exploring Execution Trace Analysis — Quarkslab](https://blog.quarkslab.com/exploring-execution-trace-analysis.html)
- [Symbolic Deobfuscation: from virtualized code back to the original (DIMVA 2018, Salwan/Bardin/Potet)](https://shell-storm.org/talks/DIMVA2018-deobfuscation-salwan-bardin-potet.pdf)
- [Deobfuscation of Virtualization‑Obfuscated Code Through Symbolic Execution and Compilation Optimization (Zeng et al., ICICS 2017)](https://cis.temple.edu/~qzeng/papers/deobfuscation-icics2017.pdf)
- [Pushan: Trace‑Free Deobfuscation of Virtualization‑Obfuscated Binaries (arXiv 2603.18355)](https://arxiv.org/html/2603.18355)
- [Control‑Flow Deobfuscation using Trace‑Informed Compositional Program Synthesis (POPL 2024)](https://dl.acm.org/doi/10.1145/3689789)
- [LLM4Decompile (GitHub)](https://github.com/albertan017/LLM4Decompile)
- [DecompileBench (arXiv 2505.11340)](https://arxiv.org/html/2505.11340v1)
- [Code Deobfuscation: Intertwining Dynamic, Static and Symbolic Approaches (BlackHat EU 2016)](https://blackhat.com/docs/eu-16/materials/eu-16-David-Code-Deobfuscation-Intertwining-Dynamic-Static-And-Symbolic-Approaches.pdf)
