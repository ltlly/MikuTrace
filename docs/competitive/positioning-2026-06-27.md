# traceMiku 战略定位文档

> **数据质量勘误（主控审阅后补）**：
> 1. 本报告的 self-audit 子 agent 因故返回了占位数据（summary="test"），故"真实定位/护城河"是基于 CLAUDE.md + GumTrace 实测 + 前沿扫描三方交叉得出，**未经逐行代码核实**。结论方向与已知代码一致（尤其 `decompile_trace` 传空 `TraceContext` 这点，与 memory `project_decompiler_trace_gap` 吻合），但矩阵里 traceMiku 的具体评级应视为"待代码复核"。
> 2. 生态调研 agent（Tenet/Unicorn-Trace/QBDI）schema 校验失败，相关单元格主要来自前几轮对话已索引的资料，非本轮独立深挖。
> 3. **已过时**：报告多处称"MemShadow 无初始快照"——这在 2026-06-27 本 session 已实现（`--snapshot-mem` + `MemSnapshot` 的 `i` 层，真机验证通过，见 `docs/memory-completeness-design.md`）。即下方 R2 的一半（初始快照）已落地，剩 syscall/JNI 建模。


> 说明：本文 selfAudit 输入为占位数据（summary="test"），故"真实定位"与"护城河"基于 CLAUDE.md 项目上下文、GumTrace/Trace-UI 实测调研与前沿扫描三方交叉得出，而非自评原文。

## 1. traceMiku 真实定位

traceMiku 是目前唯一一个把"真机 ARM64 指令级捕获 → 分析核心（CFG/taint/MemShadow/FunctionIndex）→ 三层自研 IL 反编译器（LLIL/MLIL/HLIL）→ Web/REST/CLI 多面"串成单一管线的工具。这是它的结构性优势，但也要诚实承认：在**单项能力**上它几乎样样都不是第一——吞吐被 GumTrace 的原生 `.so`（每 3 秒 1GB）碾压，trace 导航体验被 Tenet 的 omniscient navigation 甩开，内存完整性远未达到 Tenet/TTD/rr 的可重放标准（MemShadow 是稀疏的，无初始快照、无 syscall/JNI 建模），而最核心的"trace 增强反编译"这块招牌目前其实是空的——`decompile_trace` 传入的是空 `TraceContext`，反编译器本质仍是纯静态（见 memory: project_decompiler_trace_gap）。所以 traceMiku 当前是"拼图最全但每块都没磨亮"的工具：管线完整性是真护城河，但护城河里的水还没放满。

## 2. 横向对比矩阵

| 维度 | traceMiku | GumTrace (+Trace-UI) | Tenet | Unicorn-Trace | QBDI |
|---|---|---|---|---|---|
| 真机捕获 | **STRONG** Frida agent + CModule | **STRONG** 原生 .so 注入 | ABSENT 仅导入 trace | ABSENT 纯模拟 | **STRONG** 真机 DBI |
| 抗反调试 | PARTIAL Stalker RWX 可被检测，有 doctor 预检 | PARTIAL 排除系统库+跳过 LSE 防死锁 | N/A 离线分析 | STRONG 模拟环境对目标不可见 | PARTIAL DBI 可被探测 |
| 吞吐 | PARTIAL 272B 二进制记录+SPSC ring，无公开基准 | **STRONG** 1GB/3s，10MB buffer+后台 flush | PARTIAL 明确"不可扩展/实验性" | PARTIAL 模拟受控但慢 | PARTIAL-STRONG |
| 内存完整性 | PARTIAL 稀疏 MemShadow+completeness，无初始快照 | PARTIAL 仅 mem_r/mem_w 地址，靠增量镜像重建串 | **STRONG** omniscient，可逆向重构任意点 | **STRONG** 全内存可控，天然可重放 | ABSENT 需自建 |
| 分析核心 (CFG/taint) | **STRONG** CFG+FunctionIndex+taint+MemShadow+symbols | PARTIAL 仅 call tree；Trace-UI 有逆向 taint+DAG | PARTIAL 逆向 reg/mem dataflow，无 CFG | ABSENT 裸引擎 | ABSENT 裸框架 |
| 反编译器 | **STRONG** 自研三层 LLIL/MLIL/HLIL→C | ABSENT 无任何 IL/伪 C | ABSENT 无 lifting | ABSENT | ABSENT |
| trace 增强反编译 | PARTIAL 有 TraceContext 钩子但**目前传空**（真实=ABSENT） | ABSENT | ABSENT | ABSENT | ABSENT |
| AI 友好 | **STRONG** CLI-JSON+REST+TraceIR LLM 面（按规则不做 MCP） | **STRONG** Trace-UI 内置 MCP（10 工具） | ABSENT | ABSENT | ABSENT 仅库 |
| UI/导航 | PARTIAL Solid Web，导航弱于 Tenet | **STRONG** Trace-UI 亿级行虚拟滚动+bincode 索引 | **STRONG** omniscient 导航金标准 | ABSENT | ABSENT |

## 3. 我们的护城河 (moat)

只有 traceMiku 在做、或能独占去做的事，按可辩护性排序：

1. **trace→结构化 C 的完整闭环（管线唯一性）**。GumTrace 只有捕获、Trace-UI 只有浏览、Tenet 只有导航、LLM4Decompile 只有静态反编译——没有任何一家把"真机 trace"和"三层 IL 反编译器"接在一起。traceMiku 已经拥有 `agent→core→LLIL/MLIL/HLIL→TraceIR` 全链路（CLAUDE.md Code Map），**集成本身就是别人补不齐的壁垒**：要追上 traceMiku，GumTrace 得从零写一个三层反编译器，Tenet 得从零写真机捕获。

2. **trace-grounded 反编译（运行时 ground truth 灌进 lifter）**。前沿扫描的核心结论：把观测到的寄存器/内存值喂进 lifter 去解析 `br/blr` 间接跳转、去虚化调用、恢复类型，这件事**在主流工具里几乎是空白**——Tenet 有值但不接 lifter（明确"无 lifting 集成"），LLM4Decompile/Control-Flow-Augmented 全是静态输入。traceMiku 的 `TraceContext` 钩子已经在三层 IL 里预留好位置，把空 context 填上真实值，就是站在开放前沿而非追赶。这是护城河里最该立刻放水的一格。

3. **trace-grounded 的 LLM 逆向面**。已发表的 LLM 反编译器几乎全部以 asm/伪码/CFG 等静态输入，把具体运行时值（寄存器快照、解析后的指针、循环次数、去虚化目标）喂进 prompt 让模型基于事实而非幻觉推理——这块领域近乎空白。traceMiku 的 TraceIR 骨架天然适配，且按项目规则走 CLI+REST+SDK 而非 MCP，定位清晰。

## 4. 我们落后的地方（诚实清单）

- **trace 导航 UX 落后 Tenet 一个身位**。Tenet 的 omniscient navigation + 双向 reg/mem dataflow 是金标准，traceMiku 的 Web 记录导航（ArrowUp/Down、`g` 命令栏）只是基础款，没有"任意点反向重构状态"的体验。
- **吞吐无基准、且架构上吃 JS agent 亏**。GumTrace 原生 C/C++ 喊出 1GB/3s，traceMiku 的 CModule 路径有 SPSC ring 但**没有公开过任何对照数字**，无法回答"我们到底慢多少"。
- **格式封闭、互操作性差**。Trace-UI 能自动识别 GumTrace + unidbg 两种格式；traceMiku 的 272B `trace.bin` 是封闭契约，既不能吃别人的 trace，也不能把自己的 trace 导给 Tenet/Trace-UI。生态孤岛。
- **VM 去虚化完全缺席**。PUSHAN（trace-free 全 CFG 恢复）、VMPredator（trace+memory 语义锚点）、VMDragonSlayer（taint+符号+ML）已是 2026 SOTA，针对 libsgmainso 这类 Android LiteVM/AVMP 目标 traceMiku 目前零能力。
- **内存完整性达不到可重放**。稀疏 MemShadow 缺初始映射快照、缺 syscall/JNI 返回值建模，无法把 trace 变成可重新模拟执行的工件——这是 foundational gap，不是快活。

## 5. 建议路线图

按"打在护城河上"排序。每项含 价值 / 难度 / 为什么是我们做。

**R1. 闭合 trace-grounded 反编译回路（填满 TraceContext）**
价值：极高——直接把第 2 条护城河从 PARTIAL 拉到 STRONG，且兑现产品最大卖点。难度：中——管线和钩子已存在（`il_pipeline` + `TraceContext`），主要是把 index.rs/memshadow 的观测值接进 LLIL/MLIL/HLIL，用真实值解析间接跳转与去虚化。为什么是我们：**唯一同时拥有真机 trace 和三层 IL 的玩家**，别人想做得先补两端。**这是第一优先级，不做这个其他都是锦上添花。**

**R2. 可重放快照 + syscall/JNI 返回建模 + 每函数 completeness oracle**
价值：极高——把"被动 trace"升级成"可执行工件"，是前沿扫描点名的"最大杠杆点"。难度：高——需要初始映射区快照、内核/runtime 边界建模。为什么是我们：MemShadow 的 completeness 字段已是正确直觉，把它从"够不够看"propagate 到"够不够重放"，且要传导进反编译/去虚化输出诚实标注覆盖盖缺口。

**R3. trace-grounded LLM 逆向面（扩展 TraceIR）**
价值：高——抢占近乎空白的"trace 接地 LLM"赛道，差异化明确。难度：中——TraceIR 骨架已在，主要是把具体 reg/mem 值、解析指针、循环次数注入 prompt。为什么是我们：已有 LLM-friendly skeleton + 项目坚持 CLI/REST 而非 MCP，定位不与 Trace-UI 的 MCP 撞车。

**R4. trace-seeded VM 去虚化（Android LiteVM/AVMP）**
价值：高（直击用户真实目标 libsgmainso）。难度：高。为什么是我们：2026 共识是 **trace-SEEDED 而非 trace-LIMITED**——用 trace 定位 VPC/dispatcher/handler 表/context base（这是静态工具只能猜的 ground truth），再对每个 handler 符号化 lift 一次成 CFG（PUSHAN/VMPredator 路线）。traceMiku 的 per-call trace+CFG+taint 正好是种子来源。**注意：必须配符号化补全或诚实暴露覆盖缺口**，纯 trace replay 只覆盖跑到的 handler。

**R5. 格式互操作，而不是重造 Tenet/Trace-UI**
价值：中高（破生态孤岛，且省下重写导航 UI 的人力）。难度：低-中。为什么是我们：**这里要明确停止抄袭**——不要从零重建 Tenet 的 omniscient navigation UI，也不要追 Trace-UI 的亿级虚拟滚动。正确姿势是 import GumTrace/unidbg trace + export 到 Tenet 标准格式，让用户在 Tenet 里做导航、回 traceMiku 做反编译。互操作比重造便宜十倍。

**R6. 吞吐基准化 + 诚实数字**
价值：中（解决"我们到底慢多少"的盲区，指导是否要原生捕获路径）。难度：低。为什么是我们：自家管线，最容易出对照基准。先量化再决定要不要为追 GumTrace 的原生吞吐而投入——**不要默认把"每秒多少行"当头条指标去和 GumTrace 硬拼**，traceMiku 的价值在分析深度不在原始吞吐。

## 6. 一句话战略

> 别人有捕获、有导航、或有反编译，只有 traceMiku 能把真机 trace 的运行时 ground truth 灌进三层 IL 反编译器和 LLM —— 我们不比谁跑得快，我们做唯一一个 trace→结构化 C→AI 的闭环。