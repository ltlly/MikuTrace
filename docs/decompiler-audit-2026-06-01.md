# traceMiku 反编译器审计报告

> 基于 Ghidra 11.x 反编译器源码分析（`docs/ghidra-decompiler-analysis.md`）与当前 traceMiku 实现的系统对比
> 审计日期：2026-06-01
> 方法：9 路并行 Workflow 代理，覆盖 LLIL/MLIL/HLIL/管线/类型系统/Pass/反编译器模块/测试/CFG 9 个子系统

---

## 目录

1. [执行摘要](#1-执行摘要)
2. [当前状态](#2-当前状态)
3. [严重差距（4 项）](#3-严重差距)
4. [高优先级差距（6 项）](#4-高优先级差距)
5. [中优先级差距（10 项）](#5-中优先级差距)
6. [低优先级差距（6 项）](#6-低优先级差距)
7. [子系统详细对比](#7-子系统详细对比)
8. [立即行动（第 1-2 周）](#8-立即行动)
9. [中期路线图（第 2-6 周）](#9-中期路线图)
10. [长期愿景（第 2-3 月以上）](#10-长期愿景)
11. [traceMiku 的独特优势](#11-tracemiku-的独特优势)

---

## 1. 执行摘要

traceMiku 反编译器自 5 月 30 日审计以来取得了重大进展：

- **Phase 0 完成**：真实 TraceContext（寄存器、内存、branch_taken、next_pc）已连接到路由到管线的路径（`1a711e6`）
- **Phase 1 完成**：观察到的运行时值显示为内联 IL 注释（`76d34e1`）
- **4/28 原始改进项已关闭**

然而，以 Ghidra 反编译器的 17 个子系统参考架构为基准，差距仍然很大：

- **SSA** 仅限块内（无跨块 Phi，无支配边界放置）
- **简化引擎** 有 4 条规则 vs Ghidra 的 120+
- **类型系统** 有 5 个原始格点 vs Ghidra 的 18+24 子类型层次结构
- **HLIL 结构化器** 仅发出 While/DoWhile（无 For/Switch/Break/Continue）
- **17 个 Ghidra 参考子系统中有 13 个完全没有等效实现**

**最具影响力的前进路径**：首先完成 trace 驱动的优势（具体值折叠、路径修剪、观察到的结构恢复），然后再尝试匹配 Ghidra 花了 20 多年构建的静态反编译器功能。

---

## 2. 当前状态

### 2.1 已完成（自 2026-05-30 审计以来）

| 项目 | 提交 | 状态 |
|------|------|------|
| TraceContext 连接到路由到管线 | `1a711e6` | ✅ |
| LLIL 中观察到的运行时值 | `76d34e1` | ✅ |
| HLIL Break/Continue 发射 | 已完成 | ✅ |
| HLIL For/Switch 恢复（保守） | 已完成 | ✅ |
| Trace 感知的已执行边特化 | 已完成 | ✅ |
| HTTP 压缩 + index.html 缓存 | 已完成 | ✅ |
| 反向/时间旅行步进 | 已完成 | ✅ |
| Trace 观察点 | 已完成 | ✅ |
| `algo_fde_radixsort` 栈溢出修复 | 已完成 | ✅ |

### 2.2 反编译器文件地图

```
rust/crates/tracemiku-core/src/
├── llil/
│   ├── expr.rs          — LLIL 操作码（~30 个）和表达式类型
│   ├── lifter.rs        — ARM64 → LLIL 提升器
│   ├── ssa.rs           — 块内 SSA 构造（仅限单块）
│   ├── pass_phi.rs      — Phi 放置（基础，非 Bilardi-Pingali）
│   ├── pass_uidf.rs     — 使用-定义链 + 观察值收集
│   ├── pass_typelat.rs  — 类型格（5 个格点）
│   └── render.rs        — LLIL 文本渲染器
├── mlil/
│   ├── expr.rs          — MLIL 操作码（~25 个）
│   ├── lower.rs         — LLIL → MLIL 降级
│   └── render.rs        — MLIL 文本渲染器
├── hlil/
│   ├── expr.rs          — HLIL 操作码（~20 个，含 For/Switch/Case/Break/Continue 构造函数）
│   ├── pass_restructure.rs — 控制流结构化（CollapseStructure + TraceDAG-like）
│   ├── pass_simplify.rs — 代数简化（4 条规则）
│   ├── pass_type_inference.rs — 类型传播
│   ├── pass_struct_recovery.rs — 结构体访问检测（仅 base+非负常量）
│   ├── pass_ghidra_full.rs — 62 个 Action 存根（55/62 实际运行）
│   └── render.rs        — HLIL C-like 渲染器
├── decompiler/
│   ├── il_pipeline.rs   — LLIL→MLIL→HLIL 管线编排
│   ├── builder.rs       — TraceIR 构建器
│   └── render.rs        — TraceIR 渲染器
├── cfg.rs               — CFG 构造和边分类
├── function_index.rs    — 稳定函数模型（trace:/sym:/bn:）
└── memshadow.rs         — 字节级内存影子（已缓存，未被反编译器使用）
```

---

## 3. 严重差距

### 3.1 🔴 将观察到的运行时值具体化为 IL 常量（Phase 1b 未完成）

**当前状态**：Phase 1 完成 — 观察到的注释呈现为注释（例如 `/* observed x0=0x1234 */`），但常量折叠器仍然仅使用静态数据。`collect_observed_values`（pass_uidf.rs）和 `is_const()` 已存在但未连接到 constfold 路径。

**影响**：反编译器可读性方面的头号优势未实现。对于每个所有观察值相同的 SSA 定义，应将具体立即数替换为带注释的常量 `0x1234 /* observed */`。这会将不透明的解密密钥、加载的全局变量和计算的指针转换为可读常量。

**参考**：Ghidra 的 RuleCollapseConstants + EmulateSnippet 常量传播

**建议**：
- 将已存在的 `collect_observed_values`（pass_uidf.rs）+ `is_const()` 连接到 `il_pipeline.rs:135` constfold 路径
- 在 Phase 1 主循环中添加一个 ConcretizationPass，将 SetReg/SetVar 重写为观察到的常量操作数
- 工作量：中等（3-4 天）

### 3.2 🔴 路径特化：修剪未执行的分支，线性化分发器（Phase 2 不完整）

**当前状态**：`branch_taken` 已填充，`specialize_trace_control_flow` 已用 Gotos + 修剪注释替换条件分支，但 HLIL 结构化器的 `build_cfg`（pass_restructure.rs:110）从不过滤执行情况。OLLVM 平面分发器仍然是非结构化的 goto。

**影响**：OLLVM/VM 去平坦化的杠杆。使用已执行的边，结构化器看到的是一个线性 CFG — goto 消除变得微不足道。

**参考**：Ghidra 的 CollapseStructure + TraceDAG（带 BadEdgeScore），Yadegari S&P'15，SAILR USENIX'24

**建议**：
- 在 `il_pipeline.rs` 中从连续记录 PC 派生已执行边集
- 在构建 CFG 之前，修剪从未执行的边
- 将分发器循环（状态变量上的 switch）折叠为带修剪注释的线性序列
- 工作量：高（1-2 周）

### 3.3 🔴 HLIL 结构化：For/Switch/Break/Continue 未接线 + 仅一跳收敛

**当前状态**：结构化器仅发出 While/DoWhile（LoopKind 枚举在 pass_restructure.rs:354 只有 2 个变体）。`HlilOp::For/Switch/Case/Break/Continue` 变体和构造函数存在于 `expr.rs` 中，但从未被 pass_restructure.rs 发出。收敛检查（`check_convergence` 第 814 行）仅一跳 — 多块 if/else 分支降级为 goto 尾部。

**影响**：直接违反 CLAUDE.md 的"消除 goto"和"各层必须在结构上有所不同"的要求。For/Switch 恢复代码已编写（在 pass_restructure.rs 中大约 +400 行）但被保守门控从未触发。

**参考**：Ghidra 的 CollapseStructure（ruleBlockIfElse, ruleBlockWhileDo, ruleBlockDoWhile, ruleBlockSwitch 等）+ SAILR No-More-Gotos（后支配者合并选择）

**建议**：
- 将一跳收敛替换为直接后支配者合并选择（在反向 CFG + 虚拟出口上计算 `compute_dominators`，按照 SAILR No-More-Gotos 规则）
- 添加 Switch 检测（同一条件变量上的 If 链）
- 在循环体收集期间连接 For/Break/Continue 发射（已在第 418-434 行的 `collect_block_body_with_loop_flow` 中为 break/continue 完成）
- 工作量：高（2-3 周）

### 3.4 🔴 SSA 仅限块内 — 无跨块 Phi 放置，无支配边界

**当前状态**：`ssa_block`（ssa.rs:42）将一个线性块转换为带版本寄存器的 SSA，但没有跨块 SSA 构造。不存在 Phi（MULTIEQUAL）操作码。LLIL 类型格在块内 SSA 名称上操作。每个块边界都会破坏 SSA — 跨越控制流边的变量无法被跟踪。所有下游分析（类型推断、常量传播、值具体化）在每个跳转目标处都会失去精度。

**参考**：Ghidra 的 Heritage（Bilardi-Pingali 增广支配树用于 Phi 放置 + Cytron 1991 用于重命名）+ MULTIEQUAL(60) + INDIRECT(61) 操作码

**建议**：
- 将 llil 和 hlil O(n²) 支配者替换为共享的 Cooper-Harvey-Kennedy O(n) 实现
- 计算支配边界
- 在迭代支配边界插入 MULTIEQUAL（Phi）操作码
- 添加 INDIRECT 操作码用于栈/间接变量合并
- 将 MULTIEQUAL/INDIRECT 添加到 LlilOp 和 HlilOp
- 这也解锁了变量合并（Varnode→HighVariable）
- 工作量：高（2-3 周）

---

## 4. 高优先级差距

### 4.1 🟠 类型系统：5 个原始格点 vs Ghidra 的 18+24 层次结构

LLIL 类型格（pass_typelat.rs）仅有 {Any, Int, Ptr, Handle, Bool, Conflict} — 无符号性、无大小跟踪、无浮点、无结构/数组/联合、无 FuncPtr。Ghidra 风格的 TypePropagationPass（pass_type_inference.rs）根据使用上下文对变量进行分类，但格点不携带宽度或复合结构。

**建议**：扩展 TypeKind 以匹配 Ghidra 的 type_metatype.hh。添加子类型跟踪。实现 TypeOp 规则传播（从 Ghidra 的 typeop.hh 开始 15 条最高频规则）。连接观察值分类。

### 4.2 🟠 简化规则：4 条 vs Ghidra 的 120+ oppool1 规则

简化引擎（pass_simplify.rs）仅有 IdentityOp、SubToAdd、DoubleNeg 和 ComparisonFold。缺少：常量算术折叠、按位恒等式、移位恒等式、符号/零扩展折叠、比较链、分配律等。

**建议**：实现按操作码索引的规则表。首先添加最高频规则：ConstBinop、BitwiseIdentity、ExtensionChain、SignBit、ShiftIdentity。目标 30-40 条规则作为初始里程碑。

### 4.3 🟠 无变量合并：Varnode→HighVariable→VariableGroup 链缺失

变量命名是临时的 SSA 版本号（x0#1, x0#2）。没有 Varnode 作为跨越 SSA 版本的存储位置的概念，没有作为共享存储的 Varnode 联合的 HighVariable，也没有 VariableGroup 合并。

**建议**（跨块 SSA 之后）：定义 Varnode 为（space, offset, size）。实现 HighVariable 合并规则。使用不相交集合并实现 VariableGroup 分区。

### 4.4 🟠 Trace 数据未在类型/结构推理中使用 — MemShadow 加载值被反编译器忽略

MemShadow（memshadow.rs）重建加载和存储值，并在共享状态上缓存，但反编译器在 `il_pipeline.rs` 中从不读取 `inner.memshadow_if_ready()`。结构恢复 pass（pass_struct_recovery.rs）仅匹配 base+非负常量 — 无缩放索引，拒绝负偏移，忽略观察到的内存地址。

**建议**：将 MemShadow 连接到 IL 渲染。按观察到的运行时基指针聚类内存访问。添加缩放索引模式。添加对帧相对访问的负偏移支持。

### 4.5 🟠 支配者计算在 llil.rs 和 hlil/pass_restructure.rs 中均为 O(n²)

两者都使用带重复的 BTreeSet，而非 Cooper-Harvey-Kennedy O(n) 共享引擎。不可归约区域退化为平面 goto。

**建议**：在共享的 `cfg.rs` 中实现 Cooper-Harvey-Kennedy（约 120 行 Rust）。两个子系统都使用它。

### 4.6 🟠 无参数识别

函数参数未被发现、分类或排名。Ghidra 的 ParamMeasure 排名（walkforward/walkbackward + calculateRank + 7 级排名）没有等效实现。

**建议**：利用 trace 值（调用点的 x0-x7，函数入口的寄存器值）比 Ghidra 的静态方法更精确。实现 ParamMeasure 排名。

---

## 5. 中优先级差距

| # | 差距 | 影响 | 工作量 |
|---|------|------|--------|
| 5.1 | **无跳转表恢复** — Ghidra 的 PathMeld + EmulateFunction 没有等效实现。Trace 记录了每个已执行的分支目标，但 switch 检测不使用它们 | Switch 语句显示为 if-else 链或 goto | 中高（2-3 周） |
| 5.2 | **无多精度运算合并** — Ghidra 的 64 位/128 位多精度算术合并缺失 | 64 位操作显示为 32 位对 | 高（3-4 周） |
| 5.3 | **无基于令牌的 C 渲染** — 所有 3 个 IL 渲染器产生纯文本。无语法高亮元数据，无地址到令牌的映射。前端重命名使用脆弱的正则表达式 .replace | 无单次点击变量高亮，无右键类型设置传播 | 中等（2-3 周） |
| 5.4 | **无 P-code 注入/CALLOTHER 扩展点** — 无法为未知或平台特定指令建模 | 系统调用、JNI 调用未建模 | 中等（1-2 周） |
| 5.5 | **无多调用值差分** — 无法将值分类为常量 vs 输入依赖 | 参数恢复和防止过度特化折叠被阻止 | 中高（2-3 周） |
| 5.6 | **无 ScoreUnionFields 联合解析** — 在不同偏移处作为不同类型访问的内存未被识别为联合候选 | 联合访问显示为不相关的变量 | 中等（2-3 周） |
| 5.7 | **无位域变换** — 子字节寄存器访问模式的 INSERT/ZPULL/SPULL 操作缺失 | 位域访问被错误渲染 | 中等（1-2 周） |
| 5.8 | **测试无语义字符串匹配验证** — 反编译器测试检查结构属性（计数、非空），但不检查语义正确性 | 回归未被发现 | 中等（1-2 周） |
| 5.9 | **分支偏差和循环计数未在 IL 中显示** — 边执行计数存在但未渲染或用于热/冷路径注释 | 丢失执行频率上下文 | 低（1 周） |
| 5.10 | **间接 br（br xN）目标未解析到 IL/CFG** — blr 目标在文本中注释，但 br xN 分发未获得目标解析 | VM/OLLVM 分发器仍然不透明 | 中等（1-2 周） |

---

## 6. 低优先级差距

| # | 差距 |
|---|------|
| 6.1 | 无用户定义类型数据库 — 前端解析的 C 类型定义未持久化或传播到后端分析 |
| 6.2 | 无从调用点推断函数调用签名 — 调用点的参数类型未用于反向推断被调用者原型 |
| 6.3 | TraceIR 循环体未在渲染中填充 — LoopIR/InductionVarIR 结构存在但 builder.rs 从不填充它们 |
| 6.4 | TraceIR 提示中无 LLM fewshot 示例 — 提示没有工作示例或结构化输出模式 |
| 6.5 | 反编译 eval 工具不测量语义准确性 — 仅检查覆盖率和时间统计 |
| 6.6 | 前端反编译面板无键盘导航与 IDA/Ghidra 的对等性 — 伪代码中无行光标，变量重命名/设置类型未持久传播到后端 |

---

## 7. 子系统详细对比

### 7.1 LLIL vs Ghidra P-code

| 维度 | Ghidra P-code | traceMiku LLIL |
|------|--------------|----------------|
| 操作码数量 | 74 | ~30 |
| 浮点支持 | 完整 IEEE 754 | 无 |
| SSA 原生支持 | MULTIEQUAL + INDIRECT | 块内 SetReg + phi extra |
| 行为模拟 | evaluate + recover（反向） | 仅正向 |
| 三元操作 | PTRADD（三元） | 无 |
| 位操作 | INSERT/ZPULL/SPULL | 无 |
| 扩展机制 | CALLOTHER + UserPcodeOp | 无 |
| 常量模板 | ConstTpl（13 种） | 文字常量 |
| 支配者算法 | Cooper-Harvey-Kennedy O(n) | BTreeSet O(n²) |
| Phi 放置 | Bilardi-Pingali 增广支配树 | 基础 Cytron |

### 7.2 MLIL vs Ghidra HighVariable

| 维度 | Ghidra | traceMiku MLIL |
|------|--------|----------------|
| 变量模型 | Varnode→HighVariable→VariableGroup 三层 | 基于 SSA 版本的变量 |
| 寄存器消除 | 通过 HighVariable 合并 | 部分（SetReg → SetVar） |
| 数据流覆盖 | Cover（活跃范围）+ dirty 惰性计算 | 无 |
| 变量合并 | Merge（强制 + 推测，4 层 mergeTest） | 无 |
| 存储重叠处理 | VariableGroup + VariablePiece | 无 |

### 7.3 HLIL vs Ghidra 结构化 CFG

| 维度 | Ghidra | traceMiku HLIL |
|------|--------|----------------|
| 算法范式 | 迭代折叠 + TraceDAG + BadEdgeScore | 递归 walk + CollapseStructure-lite |
| 结构化结构 | if/else, while, do-while, for, switch, inf-loop | While, DoWhile（For/Switch 构造函数存在但未发射） |
| 非结构化处理 | TraceDAG + 多维评分 | 一跳收敛（不足以处理多块分支） |
| 循环检测 | LoopBody::extend() + visitCount 机制 | 基础反向 BFS |
| AND/OR 条件 | ruleBlockOr | 未实现 |
| 多尾循环 | mergeIdenticalHeads | 不支持 |
| goto 优先级 | BadEdgeScore 多维 | 仅显式 Goto |
| 条件否定 | negateCondition | 无 |

### 7.4 Pass 管线 vs Ghidra Action 框架

| 维度 | Ghidra | traceMiku |
|------|--------|-----------|
| 管线组织 | Action/Group/Pool 树状组合 | pass_ghidra_full.rs 中 62 个存根（55 个活动） |
| 选择性管线 | GroupList clone 选择性包含 | 无条件全执行 |
| 定点迭代 | 四层 rule_repeatapply | 单次遍历 |
| 规则引擎 | 120+ Rule + 按操作码索引 | 4 条规则，线性扫描 |
| 变换机制 | TransformManager 占位符+提交 | 直接修改数据结构 |
| 断点/调试 | Action 状态机支持断点 | 无 |

### 7.5 类型系统 vs Ghidra 类型

| 维度 | Ghidra | traceMiku |
|------|--------|-----------|
| 类型种类 | 18 meta + 24 sub + 复合 | 6 种 TypeKind（Any/Int/Ptr/Handle/Bool/Conflict） |
| 复合类型 | struct, union, array, enum, typedef | 无 |
| 大小角色 | 核心属性，类型比较第二关键字 | 不使用 |
| 有符号性 | 有符号/无符号区分 | 无区分 |
| 指针层级 | PTR→STRUCT/ARRAY submeta + TypePointerRel | 仅有 Ptr |
| 类型工厂 | typecache[9][8] O(1) | 无工厂 |
| 传播规则 | 70+ 按操作码推断 | 基础格合并 |
| Union 解析 | ScoreUnionFields BFS 双向 | 无 |
| BitField | INSERT/ZPULL/SPULL | 无 |

---

## 8. 立即行动

**第 1-2 周：**

1. **完成 Phase 1b** — 将观察值常量折叠到 IL 中
   - 将 `collect_observed_values` pass 连接到 `il_pipeline.rs` 的 constfold 路径
   - 具有相同观察值的 SSA 定义被替换为具体立即数（注释为 `/* observed = 0xHEX */`）
   - 影响/努力比最高的项目

2. **将 MemShadow 加载/存储值连接到 IL 渲染**
   - 反编译器已有 `contexts.mem_reads/mem_writes` 填充（`trace_context_for_idx` 在 llil_pipeline.rs:258-259）
   - 在 LLIL/MLIL 渲染器中添加 `[x8+0x10]=0x5678` 注释

3. **修复 HLIL 结构化器中的一跳收敛**
   - 将 `check_convergence`（pass_restructure.rs:814-827）替换为直接后支配者合并选择
   - 消除多块 if/else 分支的残留 goto

4. **添加 10 条最高频的简化规则**
   - ConstBinop：当两个操作数都是立即数时，对所有二元操作进行常量折叠
   - BitwiseIdentity：x&x→x, x|x→x, x&0→0, x|-1→-1 等
   - ExtensionChain：sext(zext(x))→zext(x)
   - SignBit：x>>(n-1) 用于全位复制
   - ShiftIdentity：x<<0→x

5. **Trace 驱动的 Switch 检测**
   - 在 `il_pipeline.rs` 中从连续记录 PC 收集所有观察到的跳转目标
   - 构建目标到 PC 的分组
   - 当分发 PC 跳转到 N 个不同目标时，发射 Switch/Case HLIL 节点

---

## 9. 中期路线图

**第 2-3 周：实现跨块 SSA 及 Phi 放置**
- 重构 llil.rs 和 hlil/pass_restructure.rs，使用共享的 Cooper-Harvey-Kennedy O(n) 支配者引擎
- 计算支配边界
- 在迭代支配边界插入 MULTIEQUAL 操作码
- 添加 INDIRECT 用于栈变量合并
- 编写约 30 个匹配 Ghidra SSA 测试模式的测试用例

**第 3-4 周：路径特化（Phase 2）**
- 从连续记录 PC 派生已执行边集
- HLIL 结构化器构建 CFG 前，修剪从未执行的边
- 将分发器循环折叠为带修剪注释的线性序列
- 连接到新的 Switch/Case 发射

**第 3-5 周：类型系统扩展**
- 将 TypeKind 从 6 扩展到 18 种元类型
- 添加子类型跟踪（有符号/无符号/浮点/字符）
- 实现 TypeOp 规则传播（从 Ghidra 的 typeop.hh 开始 15 条最高频规则）
- 连接观察值分类：bool（{0,1}）、窄 int、指针（在映射模块范围内）

**第 5-6 周：变量合并**
- 实现 Varnode 抽象（空间+偏移+大小元组）
- 实现 HighVariable 合并规则（相同存储、phi 连接、复制隐含）
- 使用不相交集合并实现 VariableGroup 分区
- 目标：非平凡函数减少 50%+ 变量数

**第 6 周：结构恢复 v2**
- 按观察到的运行时基指针聚类内存访问
- 添加缩放索引模式（base + index*scale）
- 添加对帧相对访问的负偏移支持
- 生成结构体定义并为字段访问注释 `field_name` 元数据

---

## 10. 长期愿景

**第 2 个月：完成 Ghidra 风格 6 阶段管线**
- 连接 `pass_ghidra_full.rs` 中所有 62 个 Action 存根
- 实现函数原型恢复的 ActionActiveParam/ActiveReturn
- 实现 SIMD 和公共子表达式消除的 ActionLaneDivide/MultiCse

**第 2 个月：基于令牌的 C 渲染**
- 定义 CToken（text, kind, pc, op_index）
- 重构所有 3 个渲染器以发射 `Vec<CToken>` 而非 String
- 前端获得单次点击变量高亮、右键类型设置和持久重命名传播，无需正则表达式技巧

**第 2-3 个月：多调用值差分 + 参数识别**
- 比较同一函数在多次记录调用中的表现
- 将值分类为常量 vs 输入依赖
- 实现正式参数发现的 ParamMeasure 排名

**第 3 个月：Union 和 BitField 分析**
- 为作为不同类型访问的内存位置实现 ScoreUnionFields
- 实现子字节访问模式的 INSERT/ZPULL/SPULL 变换
- 添加多精度运算合并（64→128 位）

**第 3 个月：TraceIR 升级（如果 LLM 路径被启用）**
- 在 builder 中填充 LoopIR/InductionVarIR
- 在提示中添加 fewshot 示例和结构化 JSON 输出
- 实现逐指令完整寄存器值注释

**持续进行：向 120+ 目标扩展简化规则**
- 每条添加的规则都会逐步改善反编译输出质量
- 按在 libsgmainso 反编译中观察到的频率优先排序

---

## 11. traceMiku 的独特优势

Ghidra 永远无法获得的差异化能力：

1. **观察到的运行时值**：在每个执行指令处知道实际的寄存器和内存值。一旦完全连接（Phase 1b+），traceMiku 的输出对于任何已执行路径都严格比 Ghidra 更具信息量。

2. **100% 间接目标解析**：`blr x8`、`br x16` — traceMiku 从下一条记录的 PC 知道确切目标。Ghidra 必须静态近似或失败。已为 blr 目标注释连接；剩余差距是 br（switch/跳转表）和将已解析目标馈送到 CFG。

3. **针对去混淆的执行路径修剪**：OLLVM/VM 平坦化产生数百个从未执行的基本块。traceMiku 可以全部修剪它们。静态去混淆器必须猜测哪些边是真实的 — traceMiku 知道。Phase 2 实现将使这成为产品的定义性差异化因素。

4. **观察到的内存聚类用于结构恢复**：Ghidra 的 ReSym 风格推断猜测基指针。traceMiku 记录实际的运行时地址，因此结构体字段分组变成简单的聚类问题，而不是约束求解问题。

5. **逐指令分支方向**：`branch_taken` 字段（现已填充）精确告诉反编译器采取了哪条路径。这实现了单路径反编译 — 仅显示实际执行的内容，注释为"备用路径已修剪"。对于恶意软件分析和 OLLVM 目标至关重要。

6. **用于 MBA/VM 综合的具体 I/O**：traceMiku 记录逐块输入/输出寄存器值。这使得混淆算术表达式的程序综合（Syntia/Xyntia）严格更容易 — 综合器看到具体的示例，而不是从位向量逻辑猜测语义。

---

> 报告生成日期：2026-06-01
> 基于 Ghidra 11.x 反编译器源码分析（`docs/ghidra-decompiler-analysis.md`）与 9 路并行 Workflow 代码库检查
> 为 traceMiku 反编译器增强提供优先排序的路线图
