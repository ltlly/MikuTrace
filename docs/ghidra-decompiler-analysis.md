# Ghidra 反编译器核心引擎 —— 深度技术分析

> 基于 Ghidra 11.x 源码（C++ 核心引擎 + Java 集成层）的全面分析
> 研究日期：2026-06-01
> 源码基线：Ghidra/Features/Decompiler/src/decompile/cpp/（约 60,000 行 C++）+ 对应 Java 集成层
> 目的：为 traceMiku 反编译器增强提供精确的技术参考

---

## 目录

1. [总体架构与设计哲学](#第1章-总体架构与设计哲学)
2. [P-code 中间表示](#第2章-p-code-中间表示)
3. [Action/Pass 管线框架](#第3章-actionpass-管线框架)
4. [Funcdata: 函数数据模型](#第4章-funcdata-函数数据模型)
5. [SSA 构建与数据流](#第5章-ssa-构建与数据流)
6. [控制流结构化](#第6章-控制流结构化)
7. [跳转表恢复](#第7章-跳转表恢复)
8. [类型恢复与传播](#第8章-类型恢复与传播)
9. [规范化与优化](#第9章-规范化与优化)
10. [函数参数识别与调用约定](#第10章-函数参数识别与调用约定)
11. [序列化与编解码](#第11章-序列化与编解码)
12. [输出渲染](#第12章-输出渲染)
13. [Java/C++ 集成架构](#第13章-javac-集成架构)
14. [外部接口与进程管理](#第14章-外部接口与进程管理)
15. [P-code 注入与扩展机制](#第15章-p-code-注入与扩展机制)
16. [浮点处理与多精度运算](#第16章-浮点处理与多精度运算)
17. [测试体系](#第17章-测试体系)
18. [Java UI 交互模型](#第18章-java-ui-交互模型)
19. [为 traceMiku 增强的路线图](#第19章-为-tracemiku-增强的路线图)
20. [附录](#附录)

---

## 第1章 总体架构与设计哲学

### 1.1 反编译器在 Ghidra 中的定位

Ghidra 反编译器（Decompiler）是 Ghidra 平台的核心分析组件之一。它将机器码转换为高级 C 语言伪代码，是逆向工程师理解二进制代码的主要入口。反编译器本身是一个独立的 C++ 可执行文件（`decompile`），通过 stdin/stdout 管道与 Ghidra Java 主进程通信，形成经典的 **进程外分析** 架构。

反编译器包含约 60,000 行 C++ 核心代码和约 15,000 行 Java 集成代码，覆盖了从机器指令解码到 C 代码输出的完整管线。

### 1.2 核心设计原则

**原则 1: P-code 作为统一中间表示**

所有机器指令首先被翻译为 P-code（一种精简的 RISC 风格中间语言），后续所有分析均在 P-code 层面进行。这种设计将架构差异隔离在翻译层，使分析算法与指令集完全解耦。P-code 操作码共计 74 个（CPUI_MAX=75，编号 0 为保留值，1-74 为有效操作码）。

**原则 2: SSA 形式保证数据流精度**

反编译器强制将所有 P-code 转换为静态单赋值（SSA）形式。每个 Varnode（P-code 中的变量节点）最多被写入一次。控制流汇合点通过 MULTIEQUAL（Phi 节点）操作码引入新版本。这种设计使得使用-定义（use-def）关系查询成为 O(1) 操作。

**原则 3: Action/Pass 管线化分析**

反编译器将分析过程组织为 Action（动作）的有序序列，每个 Action 执行一个独立的分析任务（如 SSA 构建、死代码消除、类型推断等）。Action 可以嵌套形成 ActionGroup，支持重复执行（定点迭代）直到收敛。这种设计使得反编译管线高度模块化，不同分析目标（如完整反编译 vs 仅参数恢复 vs 跳转表分析）可以通过选择不同的 Action 子集实现。

**原则 4: 不变性中间表示**

分析过程中的中间表示变更遵循 Transform 模式：先构建"占位符"（placeholder）节点集描述变更后的未来状态，再通过 `createOps → createVarnodes → removeOld → placeInputs` 五步一次性提交，保证变更的原子性。

### 1.3 组件全景图

```
+------------------------------------------------------------------+
|                     Ghidra Java 主进程                             |
|  DecompInterface → DecompileProcess → DecompileCallback           |
|       |                   |                     |                  |
|       |    XML/管道协议    |                     |                  |
|       +-------------------+---------------------+                  |
|                           |                                        |
|               decompile (C++ 独立进程)                              |
|                           |                                        |
|          +----------------+------------------+                     |
|          |                                   |                     |
|   ArchitectureGhidra                    SleighEngine               |
|   (外部接口桥接)                       (指令翻译)                  |
|          |                                   |                     |
|    +-----+----+                    +----+-----+-----+              |
|    |          |                    |    |     |      |             |
| Scope    LoadImage              Construct  Pcode  DecisionTree     |
| (符号)   (字节)                (语义模板) (编译)  (解码)          |
|                                                         |          |
|                                             Funcdata (函数模型)     |
|                                                         |          |
|           +------------------+----------+------+--------+          |
|           |                  |          |       |                   |
|      VarnodeBank         PcodeOpBank  BlockGraph  Merge            |
|      (SSA变量)          (操作序列)   (控制流)   (变量合并)         |
|           |                                                         |
|     ActionDatabase (Pass 管线)                                     |
|           |                                                         |
|    +------+------+------+------+------+                            |
|    |      |      |      |      |      |                            |
| Heritage DeadCode InferTypes Block PrintC                           |
| (SSA构建) (消除) (类型) (结构化) (C输出)                           |
+------------------------------------------------------------------+
```

### 1.4 反编译流程总览

```
阶段0: 初始化
  原始机器码
     │ SLEIGH 解码 (Sleigh::oneInstruction)
     ▼
  原始 P-code 序列 (Funcdata)
     │ FlowInfo::generateBlocks()
     ▼
  基本块 CFG (BlockGraph)

阶段1: SSA 构建
  BlockGraph + P-code
     │ ActionHeritage (多遍 Heritage)
     │ MULTIEQUAL 插入 (Bilardi-Pingali 增广支配树)
     ▼
  SSA 形式 (Varnode + def-use 链)

阶段2: 类型恢复与分析
  SSA 形式
     │ ActionDeadCode → ActionInferTypes → ActionStackPtrFlow
     │ ActionActiveParam → ActionReturnRecovery
     ▼
  类型化 SSA

阶段3: 代数简化
  类型化 SSA
     │ oppool (120+ Rules, 定点迭代)
     │ 常量折叠、拷贝传播、子变量分析
     ▼
  简化 SSA

阶段4: 控制流结构化
  简化 SSA + CFG
     │ CollapseStructure (迭代折叠)
     │ TraceDAG (goto 消除)
     │ BlockIf/BlockWhileDo/BlockSwitch
     ▼
  结构化 CFG

阶段5: 变量合并与输出
  结构化 CFG
     │ Merge (Varnode → HighVariable)
     │ PrintC (C 代码生成)
     ▼
  C 伪代码 (Emit XML Token 流)
```

---

## 第2章 P-code 中间表示

### 2.1 P-code 设计目标

P-code 是 Ghidra 反编译器的核心中间语言，设计目标是：

1. **架构无关性**：所有 CPU 指令翻译为统一的 RISC 风格操作，隔离架构差异
2. **SSA 兼容性**：原生支持 MULTIEQUAL（Phi）操作，可直接构建 SSA 形式
3. **语义完整性**：74 个操作码覆盖整数、浮点、控制流、内存、特殊语义等全部操作
4. **可扩展性**：CALLOTHER 作为通用扩展点，支持处理器特殊操作和注入 P-code

关键设计特征：所有操作均有明确的输入/输出 Varnode，所有 Varnode 大小确定（compile-time 已知）。

### 2.2 操作码完整目录

P-code 共有 74 个操作码（枚举名 CPUI_*，定义于 `opcodes.hh`），按功能分为 11 组：

**数据移动类（3 个）**

| 枚举名 | 字符串 | 说明 |
|--------|--------|------|
| CPUI_COPY (1) | COPY | 变量复制，最基础的单目操作 |
| CPUI_LOAD (2) | LOAD | 从指针加载，需指定地址空间 |
| CPUI_STORE (3) | STORE | 存储到指针，需指定地址空间 |

**控制流类（7 个）**

| 枚举名 | 字符串 | 说明 |
|--------|--------|------|
| CPUI_BRANCH (4) | BRANCH | 无条件分支 |
| CPUI_CBRANCH (5) | CBRANCH | 条件分支 |
| CPUI_BRANCHIND (6) | BRANCHIND | 间接分支（跳转表） |
| CPUI_CALL (7) | CALL | 绝对地址调用 |
| CPUI_CALLIND (8) | CALLIND | 间接调用 |
| CPUI_CALLOTHER (9) | CALLOTHER | 用户自定义操作（扩展点） |
| CPUI_RETURN (10) | RETURN | 函数返回 |

**整数比较类（6 个）**

| 枚举名 | 字符串 | 说明 |
|--------|--------|------|
| CPUI_INT_EQUAL (11) | INT_EQUAL | 等于 |
| CPUI_INT_NOTEQUAL (12) | INT_NOTEQUAL | 不等于 |
| CPUI_INT_SLESS (13) | INT_SLESS | 有符号小于 |
| CPUI_INT_SLESSEQUAL (14) | INT_SLESSEQUAL | 有符号小于等于 |
| CPUI_INT_LESS (15) | INT_LESS | 无符号小于（兼作借位指示） |
| CPUI_INT_LESSEQUAL (16) | INT_LESSEQUAL | 无符号小于等于 |

**扩展类（2 个）**：CPUI_INT_ZEXT(17), CPUI_INT_SEXT(18)

**整数算术类（17 个）**：CPUI_INT_ADD(19), CPUI_INT_SUB(20), CPUI_INT_CARRY(21), CPUI_INT_SCARRY(22), CPUI_INT_SBORROW(23), CPUI_INT_2COMP(24), CPUI_INT_NEGATE(25), CPUI_INT_XOR(26), CPUI_INT_AND(27), CPUI_INT_OR(28), CPUI_INT_LEFT(29), CPUI_INT_RIGHT(30), CPUI_INT_SRIGHT(31), CPUI_INT_MULT(32), CPUI_INT_DIV(33), CPUI_INT_SDIV(34), CPUI_INT_REM(35), CPUI_INT_SREM(36)

**布尔类（4 个）**：CPUI_BOOL_NEGATE(37), CPUI_BOOL_XOR(38), CPUI_BOOL_AND(39), CPUI_BOOL_OR(40)

**浮点比较类（5 个）**：CPUI_FLOAT_EQUAL(41), CPUI_FLOAT_NOTEQUAL(42), CPUI_FLOAT_LESS(43), CPUI_FLOAT_LESSEQUAL(44), CPUI_FLOAT_NAN(46)。编号 45 为历史废弃槽位。

**浮点算术类（7 个）**：CPUI_FLOAT_ADD(47), CPUI_FLOAT_DIV(48), CPUI_FLOAT_MULT(49), CPUI_FLOAT_SUB(50), CPUI_FLOAT_NEG(51), CPUI_FLOAT_ABS(52), CPUI_FLOAT_SQRT(53)

**浮点转换类（6 个）**：CPUI_FLOAT_INT2FLOAT(54), CPUI_FLOAT_FLOAT2FLOAT(55), CPUI_FLOAT_TRUNC(56), CPUI_FLOAT_CEIL(57), CPUI_FLOAT_FLOOR(58), CPUI_FLOAT_ROUND(59)

**SSA 与数据流类（10 个）**

| 枚举名 | 编译时名称 | 说明 |
|--------|-----------|------|
| CPUI_MULTIEQUAL (60) | BUILD | SSA Phi 节点（控制流汇合） |
| CPUI_INDIRECT (61) | DELAY_SLOT | 间接影响的复制 |
| CPUI_PIECE (62) | PIECE | 拼接（concatenate） |
| CPUI_SUBPIECE (63) | SUBPIECE | 截断/位段提取 |
| CPUI_CAST (64) | MACROBUILD | 数据类型转换 |
| CPUI_PTRADD (65) | LABELBUILD | 数组索引 |
| CPUI_PTRSUB (66) | CROSSBUILD | 子字段访问 |
| CPUI_SEGMENTOP (67) | SEGMENTOP | 分段地址查表 |
| CPUI_CPOOLREF (68) | CPOOLREF | 常量池引用 |
| CPUI_NEW (69) | NEW | 对象分配 |

**位操作类（5 个）**：CPUI_INSERT(70), CPUI_ZPULL(71), CPUI_POPCOUNT(72), CPUI_LZCOUNT(73), CPUI_SPULL(74)

### 2.3 操作码名称的双层映射

操作码名称存在编译时/运行时双层语义（`opcodes.cc`），通过宏重映射实现：

```cpp
#define BUILD      CPUI_MULTIEQUAL   // 编译时：构建 Phi 汇合点
#define DELAY_SLOT CPUI_INDIRECT     // 编译时：标记延迟槽
#define CROSSBUILD CPUI_PTRSUB       // 编译时：跨段构造
#define MACROBUILD CPUI_CAST          // 编译时：宏构造
#define LABELBUILD CPUI_PTRADD        // 编译时：标签构造
```

`opcode_name` 数组按字典序排列（非枚举值序），`opcode_indices` 排序数组存储对应关系。`get_opcode(nm)` 用二分查找 O(log n)，`get_opname(opc)` 直接索引 O(1)。

### 2.4 Varnode 抽象

Varnode（`varnode.hh:57-354`）是 P-code 中最基本的变量单元，三重标识为 `(AddrSpace, offset, size)`。

**地址空间体系**（`space.hh:30-38`）定义了 7 种基础类型：

| 类型 | 枚举值 | 说明 | 快捷字符 |
|------|--------|------|----------|
| IPTR_CONSTANT | 0 | 常量值编码为偏移量 | # |
| IPTR_PROCESSOR | 1 | RAM、ROM、寄存器 | 按名称 |
| IPTR_SPACEBASE | 2 | 虚拟栈空间（基址寄存器+偏移） | s |
| IPTR_INTERNAL | 3 | Unique 临时变量池 | u |
| IPTR_FSPEC | 4 | FuncCallSpecs 引用空间 | f |
| IPTR_IOP | 5 | PcodeOp 引用空间 | i |
| IPTR_JOIN | 6 | 虚拟合并空间（分散存储的逻辑变量） | j |

**关键空间**：
- **Unique Space**：临时寄存器池，偏移量单调递增分配。布局定义了 RUNTIME_BOOLEAN_INVERT(0x00), RUNTIME_RETURN_LOCATION(0x80), RUNTIME_BITRANGE_EA(0x100), INJECT(0x200), ANALYSIS(0x10000000)
- **Join Space**：表示分散存储的逻辑变量（如结构体字段分散在多个寄存器中），通过物理片段支持，最多 MAX_PIECES=64
- **Constant Space**：常量值直接编码为偏移，大小无实际意义

**SSA 三种状态**（`varnode.cc:43-53`）：

| 状态 | flags | 说明 |
|------|-------|------|
| Free | 无 input/written | 未插入 SSA 树，无定义 |
| Input | input | 函数的 SSA 输入节点 |
| Written | written | 由 PcodeOp 定义的 SSA 节点 |

`VarnodeBank::xref()` 实现自动去重：当 Varnode 从 free 转为 input/written 时，若已存在同 `(space, offset, size)` 的 Varnode，自动将旧 Varnode 的所有读取者重定向到新 Varnode。

### 2.5 VarnodeBank 双重排序索引

VarnodeBank（`varnode.hh:366-418`）维护两个排序集合：

1. **VarnodeLocSet**（按位置排序）：`(AddrSpace → offset → size → 定义类型 → SeqNum)`
2. **VarnodeDefSet**（按定义排序）：`(定义类型(input/written/free) → 地址或SeqNum)`

### 2.6 Varnode → HighVariable 三层抽象

```
Varnode (SSA 级别，单次写入)
  └── HighVariable (C 源码级别，多次写入合并)
        └── VariableGroup / VariablePiece (处理变量间的重叠关系)
```

HighVariable（`variable.hh:112-233`）由多个 Varnode 组成，其 Cover（代码覆盖范围）不能相交。合并通过 `Merge` 类实现（`merge.hh`、`merge.cc`）。

### 2.7 OpBehavior：正向求值 + 反向恢复

OpBehavior（`opbehavior.hh:44`）定义了操作码的数学语义：

```cpp
virtual uintb evaluateUnary(int4 sizeout, int4 sizein, uintb in1) const;
virtual uintb evaluateBinary(int4 sizeout, int4 sizein, uintb in1, uintb in2) const;
virtual uintb recoverInputBinary(int4 slot, int4 sizeout, uintb out, int4 sizein, uintb in) const;
```

支持反向恢复的操作（用于常量传播）包括：COPY, INT_ADD, INT_SUB, INT_NEGATE, INT_2COMP, INT_LEFT, INT_RIGHT, INT_SRIGHT, INT_ZEXT, INT_SEXT。不支持的操作抛出 `EvaluationError`。

**浮点行为的可插拔架构**：所有浮点 OpBehavior 通过 `Translate::getFloatFormat(sizein)` 获取体系结构特定的 FloatFormat，将浮点语义与架构解耦。

### 2.8 ConstTpl 常量模板

ConstTpl（`semantics.hh:34`）定义 13 种常量类型，允许同一模板中混用静态字面量和运行时解析值：

| 类型 | 说明 | 解析方式 |
|------|------|----------|
| real | 字面常量 | 直接返回 value_real |
| handle | 动态句柄 | 运行时从 FixedHandle 提取 |
| j_start | 当前指令地址 | walker.getAddr().getOffset() |
| j_next | 下一条指令地址 | walker.getNaddr().getOffset() |
| j_curspace | 当前地址空间 | walker.getCurSpace() |
| spaceid | 地址空间指针 | 直接返回 |
| j_relative | 相对常量 | 直接返回 |
| j_flowref | 流引用地址 | walker.getRefAddr() |
| j_flowdest | 流目标地址 | walker.getDestAddr() |

### 2.9 与 traceMiku IL 的对比

| 维度 | Ghidra P-code | traceMiku LLIL | traceMiku MLIL | traceMiku HLIL |
|------|--------------|----------------|----------------|----------------|
| 操作码数量 | 74 | ~30 | ~25 | ~20 |
| 浮点支持 | 完整 IEEE 754 | 无 | 无 | 无 |
| SSA 原生支持 | MULTIEQUAL + INDIRECT | 块内 + 跨块 SSA | 变量基 | 变量基 |
| 行为模拟 | evaluate + recover | 仅正向 | 仅正向 | - |
| 三元操作 | PTRADD(三元) | 无 | 无 | - |
| 位操作 | INSERT/ZPULL/SPULL | 无 | 无 | - |
| 扩展机制 | CALLOTHER + UserPcodeOp | 无 | 无 | 无 |
| 常量模板 | ConstTpl(13种) | 文字常量 | 文字常量 | 文字常量 |
| 结构化控制流 | 无（由 PrintC 处理）| 无 | if/while/for | if/while/for/switch |
| 变量抽象 | Varnode→HighVariable | SSA 变量 | MLIL 变量 | HLIL 变量 |

**关键差距**：
1. traceMiku 缺少 MULTIEQUAL（Phi 节点）的显式表示，其 SSA 使用 SetReg + phi extra 而非独立操作码
2. traceMiku 缺少 INDIRECT（间接影响）抽象，CALL/STORE 的内存副作用未在数据流中建模
3. traceMiku 缺少 CALLOTHER 扩展点，无法处理系统调用和 JNI 调用的语义建模
4. traceMiku 没有 PIECE/SUBPIECE/INSERT/ZPULL 等位操作，限制了位域分析能力

---

## 第3章 Action/Pass 管线框架

### 3.1 Action 类继承体系

Action（`action.hh:52`）是反编译分析的可组合单元，继承体系为：

```
Action (基类)
├── ActionGroup (Action 容器，action.hh:143)
│   └── ActionRestartGroup (可重启的 ActionGroup，action.hh:173)
├── ActionPool (Rule 容器，action.hh:262)
└── 43+ 具体 Action 子类 (coreaction.hh:33-1098)
```

### 3.2 ActionDatabase 管线管理

ActionDatabase（`action.hh:298`）是单例模式，管理所有 root Action：

- `map<string, ActionGroupList> groupmap`：root Action 名 → GroupList 映射
- `map<string, Action *> actionmap`：名称 → Action 实例映射

**6 个预定义 root Action**（`coreaction.cc:5566-5604`）：

| 名称 | 用途 | 包含的 Group 数 |
|------|------|---------------|
| "decompile" | 完整反编译管线 | 30+ |
| "jumptable" | 仅跳转表恢复 | 11 |
| "normalize" | 规范化（跨函数标准化比较） | 17 |
| "paramid" | 参数识别 | 较少 |
| "register" | 寄存器分析 | 3 (base, analysis, subvar) |
| "firstpass" | 第一遍分析 | 1 (base only) |

不同管线通过 GroupList 从 universal Action 中 `clone()` 出选择性包含的子组件实现。

### 3.3 GroupList 选择性克隆机制

`Action::clone(grouplist)`（`action.cc:391`）：

1. 遍历 ActionGroup 的所有子 Action
2. 对每个子 Action 调用 `clone(grouplist)`
3. ActionPool 的 `clone()` 检查每个 Rule 的 group 是否在 grouplist 中
4. Rule 的 group 命中则复制该 Rule 到新 ActionPool
5. ActionGroup/ActionRestartGroup 递归复制所有子组件

### 3.4 Action 生命周期状态机

```
status_start → status_breakstarthit → status_repeat → status_mid → status_end → status_actionbreak
```

行为属性（`action.hh:55-62`）：

```cpp
rule_repeatapply = 4   // 重复应用直到不再产生变更
rule_onceperfunc = 8   // 每个函数只应用一次
rule_oneactperfunc = 16 // 每个函数最多产生一次变更
rule_debug = 32        // 调试打印
```

`Action::perform()`（`action.cc:298-362`）实现定点迭代循环：每次 `apply()` 返回变更计数，若 `lcount < count` 且 `rule_repeatapply` 为真，则继续循环。

### 3.5 四层定点迭代结构

反编译管线由四层嵌套的定点循环驱动：

```
ActionRestartGroup (maxrestarts=1, rule_onceperfunc)
│
├─ fullloop (rule_repeatapply)        ← 第1层：外围恢复循环（通常执行 1-3 次）
│  │
│  ├─ mainloop (rule_repeatapply)     ← 第2层：核心 SSA→简化→类型化循环（通常 2-5 次）
│  │  ├─ ActionHeritage
│  │  ├─ ActionDeadCode
│  │  ├─ ActionInferTypes
│  │  ├─ ...
│  │  ├─ stackstall (rule_repeatapply) ← 第3层：代数简化+子变量循环（通常 3-10 次）
│  │  │  └─ oppool (rule_repeatapply)  ← 第4层：最内层 Rule 匹配循环
│  │  │     └─ 120+ Rules 依次对每个 PcodeOp 尝试匹配
│  │  └─ ...
│  │
│  └─ fullloop 尾部 (mainloop 无变更时执行一次)
│     ├─ ActionLikelyTrash
│     ├─ ActionSwitchNorm
│     └─ ActionActiveReturn
│
├─ Phase 2: 后处理与清理
│
└─ Phase 3: 变量合并与输出
```

每层在变更计数为零时自动终止，保证收敛性。

### 3.6 反编译 Pass 完整列表

以下是 universal Action（`coreaction.cc:5609-5898`）的完整 Pass 列表：

**Phase 0: 初始化**

```
ActionStart("base")                         — 标记处理开始
ActionConstbase("base")                     — 注入常量基址/跟踪寄存器
ActionNormalizeSetup("normalanalysis")      — 规范化准备
ActionDefaultParams("base")                 — 加载子函数原型
ActionExtraPopSetup("base")                 — 栈指针变化桩
ActionPrototypeTypes("protorecovery")       — 锁定输入/输出类型
ActionFuncLink("protorecovery")             — 参数 link/桩插入
ActionFuncLinkOutOnly("noproto")            — 仅输出 link（无原型恢复）
```

**Phase 1A: fullloop 循环**

```
ActionUnreachable("base")                   — 去除不可达块
ActionVarnodeProps("base")                  — 只读/volatile 处理 + 零值替换
ActionHeritage("base")                      — SSA 构建 ★ 核心
ActionParamDouble("protorecovery")          — 双精度参数处理
ActionSegmentize("base")                    — 段 Pcode 转换
ActionInternalStorage("base")               — 内部存储常量检测
ActionForceGoto("blockrecovery")            — 强制 goto 覆盖
ActionDirectWrite(true/false)               — 直接写属性传播
ActionActiveParam("protorecovery")          — 活跃参数恢复
ActionReturnRecovery("protorecovery")       — 返回值恢复
ActionRestrictLocal("localrecovery")        — 限制局部变量范围
ActionDeadCode("deadcode")                  — 死代码消除
ActionDynamicMapping("dynamic")             — 动态映射符号
ActionSpacebase("base")                     — 栈指针标记和类型
ActionNonzeroMask("analysis")               — 非零掩码计算
ActionInferTypes("typerecovery")            — 类型推断与传播 ★ 核心
ActionRestructureVarnode("localrecovery")   — 局部栈变量重组

// stackstall 内层循环
ActionPool "oppool1" (120+ Rules)           — 代数简化
ActionLaneDivide("base")                    — 向量寄存器 lane 拆分
ActionMultiCse("analysis")                  — MULTIEQUAL CSE
ActionShadowVar("analysis")                 — 影子变量检测
ActionDeindirect("deindirect")              — 间接调用解析
ActionStackPtrFlow("stackptrflow")          — 栈指针线性方程组求解

ActionRedundBranch("deadcontrolflow")       — 冗余分支移除
ActionBlockStructure("blockrecovery")       — 基本块结构修复
ActionConstantPtr("typerecovery")           — 常量指针→全局符号
ActionPool "oppool2"                        — 第二轮规则
ActionDeterminedBranch("unreachable")       — 确定分支（常量条件）
ActionUnreachable("unreachable")            — 再次清理不可达块
ActionNodeJoin("nodejoin")                  — 节点合并
ActionConditionalExe("conditionalexe")      — 条件执行分析
ActionConditionalConst("analysis")          — 条件常量传播
```

**Phase 1B: fullloop 尾部**

```
ActionLikelyTrash("protorecovery")          — 垃圾寄存器处理
ActionDirectWrite(true/false)
ActionDeadCode("deadcode")
ActionDoNothing("deadcontrolflow")          — 空块移除
ActionSwitchNorm("switchnorm")              — 跳转表规范化
ActionReturnSplit("returnsplit")            — 返回分割
ActionUnjustifiedParams("protorecovery")    — 不对齐参数修正
ActionStartTypes("typerecovery")            — 启动类型恢复
ActionActiveReturn("protorecovery")         — 活跃返回值检查
```

**Phase 2: 清理阶段**

```
ActionMappedLocalSync("localrecovery")      — 局部符号最终同步
ActionStartCleanUp("cleanup")               — 标记清理开始
ActionPool "cleanup" (20 Rules)             — 清理规则集
```

**Phase 3: 变量合并与输出**

```
ActionPreferComplement(true)                — 补集优化
ActionStructureTransform(true)              — 结构化变换
ActionNormalizeBranches("normalizebranches")
ActionAssignHigh("merge")                   — 创建 HighVariable
ActionMergeRequired("merge")                — 必要合并
ActionMarkExplicit("merge")                 — 标记显式变量
ActionMarkImplied("merge")                  — 标记隐式变量
ActionMergeMultiEntry("merge")              — 多 SymbolEntry 合并
ActionMergeCopy("merge")                    — COPY 合并
ActionDominantCopy("merge")                 — 主导 COPY 优化
ActionDynamicSymbols("dynamic")             — 动态符号最终绑定
ActionMarkIndirectOnly("merge")             — 标记 INDIRECT-only 输入
ActionMergeAdjacent("merge")                — 相邻位置合并
ActionMergeType("merge")                    — 同类型合并
ActionHideShadow("merge")                   — 影子 COPY 隐藏
ActionCopyMarker("merge")                   — COPY 标记为不打印
ActionLateDoNothing("blockrecovery")        — 后期空块移除
ActionBlockStructure("blockrecovery")       — 最终块结构
ActionPreferComplement(false)               — 补集优化（不允许修改）
ActionStructureTransform(false)             — 结构化变换（不允许修改）
ActionOutputPrototype("localrecovery")      — 设置输出原型
ActionInputPrototype("fixateproto")         — 输入原型固化
ActionMapGlobals("fixateglobals")           — 全局变量映射
ActionDynamicSymbols("dynamic")             — 最终动态符号
ActionNameVars("merge")                     — 变量命名
ActionSetCasts("casts")                     — 类型转换插入
ActionFinalStructure("blockrecovery")       — 最终控制流结构化
ActionPrototypeWarnings("protorecovery")    — 原型警告
ActionStop("base")                          — 标记处理完成
```

### 3.7 Rule 系统

Rule（`action.hh:194`）是实现局部模式匹配的基础单元。120+ 个 Rule 通过 `getOpList()` 声明处理的 OpCode，由 `ActionPool::addRule()` 建立 per-opcode 索引。

**核心匹配循环**（`action.cc:822-875`）：

```
processOp():
  for each op in function:
    opc = op.code()
    while rule_index < perop[opc].size():
      rule = perop[opc][rule_index++]
      res = rule.applyOp(op, data)
      if res > 0:
        if op.isDead(): break
        if op.code() changed:
          opc = op.code()
          rule_index = 0  // OpCode 变了，重新开始
```

**Rule 分组机制**：每个 Rule 构造时绑定到一个 group name（如 "analysis", "deadcode", "typerecovery"）。`clone()` 时检查 group 是否在 grouplist 中，不在则跳过。

### 3.8 Transform 变换机制

TransformManager（`transform.hh:156`）实现"占位符 + 提交"的变换模式，避免变换过程中的中间状态不一致。

**TransformVar 类型**（`transform.hh:36-41`）：

| 类型 | 值 | 含义 |
|------|-----|------|
| piece | 1 | 新 Varnode 是原始 Varnode 的一部分 |
| preexisting | 2 | 原始数据流中已存在 |
| normal_temp | 3 | 新 unique 临时变量 |
| piece_temp | 4 | 逻辑子片段（不保留物理地址） |
| constant | 5 | 新常量 Varnode |
| constant_iop | 6 | 特殊 iop 常量（编码 PcodeOp 引用） |

**apply() 五阶段提交流程**（`transform.cc:756-765`）：

1. `createOps()` — 创建/修改所有新 PcodeOp，do-while 循环处理延迟插入
2. `createVarnodes(inputList)` — 创建所有新 Varnode
3. `removeOld()` — 删除被替换的旧 PcodeOp
4. `transformInputVarnodes(inputList)` — 转换输入 Varnode
5. `placeInputs()` — 设置所有 op 的输入 Varnode + specialHandling

### 3.9 与 traceMiku 的对比

| 维度 | Ghidra | traceMiku |
|------|--------|-----------|
| 管线组织 | Action/Group/Pool 树状组合 | 硬编码 pass 顺序 |
| 选择性管线 | GroupList clone 选择性包含 | 无条件全执行 |
| 定点迭代 | 四层 rule_repeatapply | 单次遍历 |
| 规则引擎 | 120+ Rule + per-opcode 索引 | 无通用规则引擎 |
| 变换机制 | TransformManager 占位符+提交 | 直接修改数据结构 |
| 断点/调试 | Action 状态机支持断点 | 无 |

**建议**：traceMiku 应实现通用的 Rule 框架和可组合的 Pass 管线，特别是 ActionPool 的 per-opcode 规则索引和定点迭代机制。

---

## 第4章 Funcdata: 函数数据模型

### 4.1 Funcdata 结构

Funcdata（`funcdata.hh:56-627`）是单函数反编译的总数据容器，包含：

**核心标识**：
- `Architecture *glb`：全局架构配置，提供类型工厂、地址空间管理、Loader
- `string name / displayName`：函数名
- `Address baseaddr`：函数入口地址
- `int4 size`：函数体字节大小

**16 种函数状态标志**（`funcdata.hh:57-74`）：

| 标志 | 含义 |
|------|------|
| highlevel_on | Varnode 已分配 HighVariable |
| blocks_generated | 基本块已生成 |
| blocks_unreachable | 存在不可达块 |
| processing_started / processing_complete | 处理生命周期 |
| typerecovery_on / typerecovery_start | 类型恢复 |
| no_code | 无可用代码体 |
| jumptablerecovery_on / jumptablerecovery_dont | 跳转表恢复 |
| restart_pending | 需要重新开始 |
| unimplemented_present / baddata_present | 错误标记 |
| double_precis_on | 双精度恢复 |
| typerecovery_exceeded | 类型传播达上限 |
| normalization_on | 规范化处理 |

**数据流核心**：
- `VarnodeBank vbank`：Varnode 容器，包含双重排序索引（LocSet + DefSet）
- `PcodeOpBank obank`：PcodeOp 容器
- `Heritage heritage`：SSA 构建管理器

**控制流**：
- `BlockGraph bblocks`：非结构化基本块图
- `BlockGraph sblocks`：结构化块层次

**变量系统**：
- `Merge covermerge`：变量范围交集算法

**外部交互**：
- `FuncProto funcp`：函数原型
- `ScopeLocal *localmap`：局部变量作用域
- `vector<FuncCallSpecs *> qlst`：子函数调用规格列表
- `vector<JumpTable *> jumpvec`：跳转表列表

### 4.2 Varnode 详细属性

Varnode（`varnode.hh:57-354`）的核心成员：

```cpp
uint4 flags;                    // 32 位布尔属性集合
int4 size;                      // 字节大小
uint4 create_index;             // 创建时的单调递增序号
Address loc;                    // 存储位置或常量值
PcodeOp *def;                   // 定义操作（SSA 中最多一个）
HighVariable *high;             // 所属高层变量
SymbolEntry *mapentry;          // 关联的符号条目
Datatype *type;                 // 数据类型
list<PcodeOp *> descend;        // 所有使用此 Varnode 的 PcodeOp（def-use 链）
Cover *cover;                   // 代码覆盖范围
uintb consumed;                 // 哪些位被消费
uintb nzm;                      // 已知为零的位掩码
```

**关键标志位**（部分）：
- `mark`：遍历标记（防循环）
- `constant`：是常量
- `input`：SSA 输入节点
- `written`：有定义操作
- `implied / explicit`：临时变量标记
- `typelock / namelock`：数据类型/名称已锁定
- `addrtied`：高层变量与地址绑定
- `directwrite`：受合法输入直接影响
- `indirect_creation`：间接创建的值
- `return_address`：存储返回地址
- `coverdirty`：Cover 信息过期

### 4.3 HighVariable → VariableGroup 升维模型

```
Varnode (SSA 级别)
  │ Merge 合并（Cover 交集不相交则合并）
  ▼
HighVariable (C 级别)
  │ VariableGroup（处理重叠）
  ▼
VariablePiece (组内片段)
```

HighVariable 由多个 Varnode 组成（代表同一变量的多次写入），其 Cover 是成员 Cover 的并集。核心合并约束：内部 Cover 不能相交。

**惰性更新模式**：HighVariable 的 flags/type/cover/symbol 都通过 dirty 标志（`flagsdirty/typedirty/coverdirty/symboldirty`）实现惰性计算。Varnode 属性变更通过 `setFlags()` 自动向上传播到 HighVariable 的 dirty 标志。

### 4.4 与 traceMiku 的对应

| Ghidra 概念 | traceMiku 对应 |
|------------|---------------|
| Funcdata | LLIL/MLIL/HLIL FunctionContext |
| Varnode | LLIL SSA 变量 |
| PcodeOp | LLIL 指令 |
| HighVariable | MLIL 变量 |
| BlockGraph (bblocks) | LLIL CFG |
| BlockGraph (sblocks) | HLIL 结构化 CFG |
| Heritage | pass_phi.rs + pass_uidf.rs |
| Merge | 变量合并（待实现） |
| FuncProto | 函数原型（待实现） |
| JumpTable | 跳转表恢复（待实现） |
| Cover | 无对应（需要实现） |

---

## 第5章 SSA 构建与数据流

### 5.1 SSA 构建算法选择

Ghidra 的 SSA 构建采用两个经典论文的组合（`heritage.hh:198-206`）：

- **Phi 放置**：Gianfranco Bilardi 和 Keshav Pingali，"The Static Single Assignment Form and its Computation", 1999。此算法需要增广支配树（Augmented Dominator Tree）。
- **变量重命名**：Cytron, Ferrante, Rosen, Wegman, Zadeck，"Efficiently Computing Static Single Assignment Form and the Control Dependence Graph", ACM TOPLAS 13(4), 1991。

这与标准的 Cytron 全算法不同——Ghidra 用 Bilardi-Pingali 增广支配树算法替换了标准 Cytron 的 Phi 放置，降低了复杂度。

### 5.2 支配树算法：Cooper-Harvey-Kennedy (2001)

支配树本身使用 Cooper, Harvey, Kennedy (2001) 迭代 finger 算法（`block.cc:1958-2036`）：

- 节点按 reverse post-order 排列（反映在 index 字段）
- 使用 "finger" 算法计算 LCA（最近公共祖先）
- 反复迭代直到 `immed_dom` 收敛
- 时间复杂度通常远小于 O(n^2)

```cpp
BlockGraph::calcForwardDominator():
  // 节点已按 reverse post-order 排列
  // finger 算法: intersector = findCommonBlock(finger1, finger2)
  // 收敛后更新所有 idom
```

### 5.3 BUILDADT：增广支配树构建

`Heritage::buildADT()`（`heritage.cc:2316-2385`）是 Bilardi-Pingali 算法的核心：

**第1步**：构建标准支配树
```
bblocks.buildDomTree(domchild)
maxdepth = bblocks.buildDomDepth(depth)
```

**第2步**：识别上向边（Up-edges）
- 遍历所有入边，若 `u != v->getImmedDom()`，则 `(u, v)` 是上向边
- 维护 `b[u->index]`（源头计数）和 `t[x->index]`（目标 idom 计数）

**第3步**：识别边界节点（Boundary Nodes）。从后向前遍历 reverse post-order：
```
a[i] = b[i] - t[i] + SUM(a[child_j])
z[i] = 1 + SUM(z[child_j])

if domchild[i].size() == 0 or z[i] > a[i] + 1:
    flags[i] |= boundary_node
    z[i] = 1
```

当子支配域大小超过上向边数量时，节点成为边界节点。

**第4步**：构建增广边（Augmented Edges）
```
z[i] = (idom[i] 是边界节点) ? idom[i]->index : z[idom[i]->index]

for each up-edge u -> v:
    j = idom(v)->index
    k = u->index
    while (j < k):
        augment[k].push_back(v)  // 增广边 k -> v
        k = z[k]                 // 沿 z-link 跳跃
```

增广边的数学意义：一条从控制流图中"跳过"边界节点的短路路径，使 Phi 放置复杂度从 O(|DF| * |V|) 降至 O(S + |V| * |DF|)，其中 S 是增广边数量。

### 5.4 Phi 节点放置：calcMultiequals

`Heritage::calcMultiequals()`（`heritage.cc:2439-2466`）：

```
1. 将所有写入 Varnode 的块插入优先队列（优先级 = 支配树深度）
2. 确保入口块在队列中
3. while 队列非空:
     bl = pq.extract()
     visitIncr(bl, bl)  // 递归访问增广边
4. 清除标记
```

`visitIncr()`（`heritage.cc:2394-2428`）：

```
visitIncr(qnode, vnode):
  for each augment[vnode]:
    if idom(v)->index < qnode->index:
      if v 未 merged: 加入 merge[] 列表
      if v 未 marked: 标记并入队
  if vnode 不是边界节点:
    递归处理子节点
```

### 5.5 重命名算法

`Heritage::renameRecurse()`（`heritage.cc:2479-2562`）实现 Cytron 1991 经典算法的直接移植：

1. VariableStack（`map<Address, vector<Varnode *>>`）维护每个地址的版本栈
2. 遍历基本块中所有 PcodeOp：先替换读取（使用栈顶版本），再压入写入
3. 填充后继块的 MULTIEQUAL 输入
4. 递归处理支配子节点
5. 弹出写入（恢复栈状态）

**INDIRECT 特殊处理**（`heritage.cc:2507-2516`）：当 INDIRECT 的存储操作与当前操作是同一个时，使用栈中前一个版本（`stack[stack.size()-2]`），因为 INDIRECT 的输入和输出"同时发生"。

### 5.6 Heritage 多遍机制

`Heritage::heritage()`（`heritage.cc:2663-2758`）支持多遍（Multi-Pass）：

1. 不同地址空间可有不同的 heritage 延迟（通过 `HeritageInfo` 控制）
2. 通常先处理寄存器（delay=0），后处理栈（delay>0）
3. 每遍包含：collect（收集 free Varnode）→ placeMultiequals → rename

**Guard 机制**：在重命名前插入额外的数据流节点：
- `guardCalls()`：为 CALL 插入 INDIRECT
- `guardStores()`：为 STORE 插入 INDIRECT
- `guardLoads()`：为 LOAD 插入 COPY
- `guardReturns()`：为 RETURN 插入 COPY

这些 guard 操作实质上是**在 SSA 构建前插入额外数据流节点**，确保重命名算法能正确处理内存别名的间接效应。

### 5.7 SIZE 规范化

传统 SSA 要求所有写入和读取使用相同大小的变量。Ghidra 通过自动插入 PIECE/SUBPIECE 来处理大小不匹配：

- `normalizeReadSize()`：为过小的读取创建 SUBPIECE
- `normalizeWriteSize()`：为过小的写入创建 SUBPIECE + PIECE 拼接
- `refinement()`：找到所有 Varnode 边界的公共细化，分割所有读写输入

### 5.8 LoadGuard 值集分析

LoadGuard（`heritage.cc:870-898`）保护动态栈访问（通过非恒定的指针 + 索引的 LOAD/STORE）：

- `establishRange()`：基于部分值集分析建立保护范围
- `finalizeRange()`：使用完整 widening 分析精确化范围
- 使用 `ValueSetSolver` 进行值集传播

### 5.9 与 traceMiku 的对比与增强

| 维度 | Ghidra | traceMiku |
|------|--------|-----------|
| 支配树算法 | Cooper-Harvey-Kennedy (O(n)) | 集合交集 (O(n^2)) |
| Phi 放置 | Bilardi-Pingali 增广支配树 | Cytron 标准迭代 |
| 内存 SSA | INDIRECT + LoadGuard | 无 |
| 多遍机制 | HeritageInfo per-space delay | 单次执行 |
| 大小规范化 | PIECE/SUBPIECE 自动插入 | 无 |
| 常量检测 | 静态值集分析 | pass_uidf.rs trace 运行时值 |

**traceMiku 的独特优势**：
- `pass_uidf.rs` 利用 trace 运行时值收集 SSA 定义的观测值，支持 `is_const()` 检测
- 可直接用 trace 值替换 SSA 定义为常量（比 Ghidra 的静态推理更精确）
- 间接调用目标可直接从 trace 记录解析
- 内存别名可从 trace 记录的 STORE/LOAD 地址精确确定

**建议升级路径**：
1. 将支配者算法升级为 Cooper-Harvey-Kennedy（约 120 行 Rust）
2. 引入 MULTIEQUAL 专用操作码（替代 SetReg + phi extra）
3. 实现内存 SSA（为 STORE/LOAD 创建 INDIRECT-like 节点）
4. 在常量折叠阶段注入 trace 值

---

## 第6章 控制流结构化

### 6.1 FlowBlock 体系

FlowBlock（`block.hh:73-364`）是控制流图的原子单元：

```
FlowBlock (抽象基类)
├── BlockGraph (结构化容器)
│   ├── BlockList (顺序执行)
│   ├── BlockCondition (AND/OR 组合条件)
│   ├── BlockIf (if/if-else/if-goto)
│   ├── BlockWhileDo (while/for)
│   ├── BlockDoWhile (do-while)
│   ├── BlockInfLoop (无限循环)
│   ├── BlockSwitch (switch/case)
│   ├── BlockGoto (单 goto)
│   └── BlockMultiGoto (多 goto)
├── BlockBasic (原始基本块)
└── BlockCopy (镜像/替身)
```

### 6.2 FlowBlock 核心成员

```cpp
uint4 flags         // block_flags 位掩码（20+ 种状态标志）
int4 index          // 逆后序编号（reverse post-order）
int4 visitcount     // 算法遍历计数
int4 numdesc        // 生成树后代节点数
FlowBlock *parent   // 父块
FlowBlock *immed_dom // 直接支配节点
FlowBlock *copymap  // BlockCopy 反向引用
vector<BlockEdge> intothis  // 入边列表
vector<BlockEdge> outofthis // 出边列表
```

`BlockEdge` 设计精巧——边是双向维护的：

```cpp
struct BlockEdge {
  uint4 label;           // edge_flags 位掩码
  FlowBlock *point;      // 边的另一端
  int4 reverse_index;    // 对端对应边的索引（O(1) 交叉引用）
};
```

**edge_flags 四分类**（生成树边类型）：
- `f_tree_edge`：生成树中的边
- `f_forward_edge`：向前跨越的边
- `f_cross_edge`：跨越子树的边
- `f_back_edge`：回边（定义循环）
- `f_irreducible`：必须移除才能使图可归约的边

### 6.3 CFG 构建两阶段

**阶段一**：FlowInfo::generateOps() + generateBlocks()
1. 逐指令生成 P-code
2. `fillinBranchStubs()` → `collectEdges()` → `splitBasic()` → `connectBasic()`
3. 输出：BlockBasic CFG

**阶段二**：BlockGraph 层次化
1. 创建 BlockCopy 镜像图
2. 迭代折叠节点（CollapseStructure）

### 6.4 支配树关键算法

**生成树构造**（`block.cc:1009-1136`——Tarjan 算法）：
1. DFS 遍历（非递归栈），按 visitcount 分类边
2. 计算 numdesc（后代计数）
3. 按逆后序排列节点

**不可归约边检测**（`block.cc:1147-1199`——Tarjan 算法）：
1. 逆向遍历前序列表
2. 收集回边，构建 reachunder 集合
3. 若边源节点不满足 `(x->visitcount > y->visitcount) || (x->visitcount + x->numdesc <= y->visitcount)`，则不可归约
4. 标记为 `f_irreducible`

### 6.5 CollapseStructure 折叠算法

`CollapseStructure::collapseAll()`（`blockaction.cc:1877-1893`）采用迭代折叠策略：

```
1. orderLoopBodies()        — 标记所有自然循环
2. collapseConditions()     — 折叠 AND/OR 条件
3. while 还有未折叠块:
     a. collapseInternal(NULL)   — 反复应用规则直到卡住
     b. selectGoto()             — 选择最可能的 goto 边
     c. collapseInternal(bl)     — 从标记处重新折叠
```

**规则执行顺序**（`collapseInternal()`，`blockaction.cc:1768-1851`）：

1. `ruleBlockGoto` — 已标记 goto 边的折叠
2. `ruleBlockCat` — 串联单出单入块
3. `ruleBlockProperIf` — 仅 then 分支的 if
4. `ruleBlockIfElse` — if-else 结构
5. `ruleBlockWhileDo` — while 循环
6. `ruleBlockDoWhile` — do-while 循环
7. `ruleBlockInfLoop` — 无限循环
8. `ruleBlockSwitch` — switch 语句
9. `ruleBlockIfNoExit` — 无出口 if（return/break）
10. `ruleCaseFallthru` — case fall-through

**ruleBlockIfElse 的具体条件**（`blockaction.cc:1416-1444`）：
- 块有 2 条出边，都是决策边
- true 子句和 false 子句都仅有 1 条入边和 1 条出边
- 出边指向相同 merge 块
- 必要时翻转条件（negateCondition）

### 6.6 TraceDAG 算法

TraceDAG（`blockaction.hh:88-181`, `blockaction.cc:499-1014`）是 Ghidra 最核心的结构化算法。其核心洞察力：**结构化代码的控制流 — 除循环回边外 — 形成一个 DAG**。

**数据结构**：
- **BranchPoint**：CFG 中多出边节点
- **BlockTrace**：单路径追踪记录，从 BranchPoint 沿一条出边向前推进
  - `destnode`：当前目标节点
  - `edgelump`：多条边汇聚为一条"虚拟边"
  - `flags`：`f_active`（活跃）或 `f_terminal`（终止）

**pushBranches() 流程**：
```
1. 从 root BranchPoint 创建初始 BlockTrace
2. while 有 active trace：
   a. checkRetirement(trace) → retireBranch()
      （所有兄弟 trace 都到达同一节点则折叠）
   b. checkOpen(trace) → openBranch()
      （创建新 BranchPoint，分裂为多条子 trace）
   c. 如果既不能 retire 也不能 open：
      → missedactivecount++
   d. 如果死锁（missedactivecount >= activecount）：
      → selectBadEdge() 选择最可能的非结构化边
      → removeTrace() 标记为 likely goto
```

### 6.7 BadEdgeScore 评分系统

`selectBadEdge()` 按多维评分选择"最不适合结构化"的边：

1. **siblingedge**：越少兄弟 trace 指向同一 exit 越可能是 bad edge
2. **terminal**：目标节点是终端节点（无出口）→ 不太可能是 switch 的 bad edge
3. **distance**：BranchPoint 间 DAG 距离越短越可能是 bad edge
4. **depth**：BranchPoint 深度越浅越可能是 bad edge

### 6.8 LoopBody 循环检测

LoopBody（`blockaction.hh:46-76`）扩展了 Tarjan 自然循环：

- `findBase()`：从 head 反向 BFS 标记循环体
- `extend()`：向前扩展，只包含所有入边都在体内的块（visitCount == sizeIn）
- `findExit()`：选择循环出口（优先级：tail 出边 > head 出边 > 体内部块出边）
- `orderTails()`：将 exit 边指向 exitblock 的 tail 设为 preferred tail
- `labelExitEdges()`：标记退出边，按优先级排列

**边的优先级排序**：
1. 体内部块的退出边（最高优先级标记为 goto）
2. head 的退出边
3. tail 的退出边（最低——最被"保护"）
4. 回边（最低优先级——最被保护）

### 6.9 与 traceMiku 的对比

| 维度 | Ghidra | traceMiku LLIL | traceMiku HLIL |
|------|--------|---------------|---------------|
| 算法范式 | 迭代折叠 + DAG 追踪 | 递归 walk | 递归 walk |
| 非结构化处理 | TraceDAG + BadEdgeScore | 缺失 | 缺失 |
| 循环体扩展 | extend() visitCount | 简单反向 BFS | 简单反向 BFS |
| Switch 识别 | checkSwitchSkips | 未实现 | 未实现 |
| AND/OR 条件 | ruleBlockOr | 未实现 | 未实现 |
| 多 tail 循环 | mergeIdenticalHeads | 不支持 | 不支持 |
| goto 生成 | 优先级排序 | 仅显式 Goto | 仅显式 Goto |
| 条件翻转 | negateCondition | 无 | 无 |

**可直接采用的 Ghidra 算法**：
1. **TraceDAG**：最高优先级，用于非结构化 goto 的自动发现
2. **LoopBody::extend()**：正确的循环体扩展（visitCount 机制）
3. **BadEdgeScore**：多维评分选择最优 goto
4. **checkSwitchSkips()**：处理 jumptable default 边

---

## 第7章 跳转表恢复

### 7.1 整体架构

Ghidra 的跳转表恢复是一个**多阶段、多模型、试探性降级**的流水线。核心组件：

1. JumpTable：跳转表主容器，持有 JumpModel 指针
2. JumpModel 抽象基类 + 6 个派生实现
3. PathMeld：多路径交汇分析引擎
4. GuardRecord：边界守卫检测
5. EmulateFunction：轻量级路径模拟器
6. SubvariableFlow：子变量裁剪

### 7.2 JumpModel 试错降级链

```
JumpAssisted → JumpBasic → JumpBasic2 → JumpModelTrivial
   (编译器伪操作)  (基础表)  (带默认路径)   (退化模型)
```

**JumpBasic** 覆盖 95%+ 的编译跳转表模式，恢复分为 7 个阶段：

| 阶段 | 方法 | 说明 |
|------|------|------|
| 1 | findDeterminingVarnodes | DFS 遍历 P-code 数据依赖树，收集候选 switch 变量 |
| 2 | analyzeGuards | 逆向回溯 CBRANCH（最多 2 级 + 2 级 pullback），CircleRange 推导约束 |
| 3 | findSmallestNormal | 遍历 PathMeld 公共 Varnode，选范围最小者为归一化 switch 变量 |
| 4 | buildAddresses | EmulateFunction 模拟计算每个归一化值对应的目标地址 |
| 5 | findUnnormalized | 从 normSV 回溯寻找非归一化 switch 变量（switchSV） |
| 6 | buildLabels | backup2Switch 逆向模拟恢复原始 case 值 |
| 7 | foldInNormalization/foldInGuards | 中间代码变死代码，消除卫士 CBRANCH |

### 7.3 PathMeld：多路径交汇引擎

PathMeld（`jumptable.hh:66-103`, `jumptable.cc:787-1046`）是跳转表检测的前置分析器：

1. 从 BRANCHIND 出发，沿 P-code 数据流逆向遍历，收集所有数据通路
2. 求公共 Varnode 交集（`commonVn`），只有出现在所有路径上的 Varnode 才是候选
3. 有序融合：将不同路径的 PcodeOp 按执行顺序合并为 `opMeld` 列表

**核心约束**："分裂-重入"——一条路径可从公共路径分裂出去，但必须最终重入公共路径。不能重入的分裂路径被丢弃。

### 7.4 GuardRecord 边界守卫

GuardRecord（`jumptable.hh:133-158`）描述 CBRANCH 如何约束 switch 变量：

- `range`：导致进入 switch 路径的 CircleRange（支持回绕，如 8-bit 变量从 250 到 5）
- `bitsPreserved`：quasiCopy 保留的低位比特数
- `unrolled`：标记跨多个基本块的展开循环

**quasiCopy 分析**（`jumptable.cc:719-785`）：追溯 COPY/INT_AND/INT_OR/INT_SEXT/INT_ZEXT/PIECE/SUBPIECE 操作链，找出 Varnode 的原始源头。

**valueMatch**（`jumptable.cc:637-675`）：判断 GuardRecord 与当前 Varnode 的匹配程度，返回 0（不匹配）、1（匹配）、2（匹配且 pending 无中间写入）。

### 7.5 EmulateFunction 轻量级模拟

`EmulateFunction::emulatePath`（`jumptable.cc:216-254`）：模拟执行 PathMeld 中的所有 PcodeOp，使用 `varnodeMap` 存储中间值。CALL/CALLIND/CALLOTHER 被跳过；BRANCH/CBRANCH/BRANCHIND 抛出异常阻止模拟。

### 7.6 SubvariableFlow 子变量裁剪

SubvariableFlow（`subflow.hh:43-131`）在跳转表恢复后期将 switch 变量缩减为实际逻辑大小：

- `trySwitchPull()`（`subflow.cc:319-331`）：检查 `switchVarConsume` 掩码，创建 `parameter_patch` 类型的 PatchRecord
- `switchVarConsume` 由 JumpTable 的 `foldInNormalization` 计算：`minimalmask(switchVN->getNZMask())`

### 7.7 多阶段重试与哨兵值

- `checkForMultistage → recoverMultistage`（带 save/restore 保护）
- `partialTable=true` → 触发 FlowInfo 额外恢复轮次
- `JumpValues::NO_LABEL` = `0xBAD1ABE1BAD1ABE1`：无法逆向计算的 case 值哨兵

### 7.8 与 traceMiku 的关联

traceMiku 拥有 Ghidra 无法获得的优势——运行时 trace 可以精确记录 BRANCHIND 的实际目标地址和 switch 变量的运行时值：

- 不需要 EmulateFunction 模拟（直接用 trace 值）
- 不需要 PathMeld 公共变量交集（直接观测 switch 变量）
- 不需要 GuardRecord 范围分析（直接观测边界检查的结果值）
- 地址表可直接从 trace 目标地址收集

---

## 第8章 类型恢复与传播

### 8.1 双层类型体系

Ghidra 的类型系统由两层构成：

**Meta-Type（18 种，无尺寸模板，`type.hh:80-100`）**：

| 枚举值 | 含义 | 编号（越小越特化） |
|--------|------|-------------------|
| TYPE_VOID | 占位符 | 17 |
| TYPE_SPACEBASE | 地址空间视为结构体 | 16 |
| TYPE_UNKNOWN | 未知低层类型 | 15 |
| TYPE_INT | 有符号整数 | 14 |
| TYPE_UINT | 无符号整数 | 13 |
| TYPE_BOOL | 布尔 | 12 |
| TYPE_CODE | 可执行代码 | 11 |
| TYPE_FLOAT | 浮点 | 10 |
| TYPE_PTR | 指针 | 9 |
| TYPE_PTRREL | 相对指针 | 8 |
| TYPE_ARRAY | 数组 | 7 |
| TYPE_ENUM_UINT/INT | 枚举 | 6/5 |
| TYPE_STRUCT | 结构体 | 4 |
| TYPE_UNION | 联合体 | 3 |
| TYPE_PARTIALENUM/STRUCT/UNION | 部分类型片段 | 2/1/0 |

**Sub-Meta-Type（24 种特化）**：对 meta-type 的进一步细化。如 TYPE_INT 可特化为 SUB_INT_CHAR（signed char）、SUB_INT_PLAIN（普通 int）、SUB_INT_ENUM（有符号枚举）。Submeta 数值越低越特化，在类型传播中优先级越高。

### 8.2 TypeFactory 缓存矩阵

TypeFactory（`type.hh:827`）维护多层缓存：

```cpp
Datatype *typecache[9][8];  // [size=0-8] x [metatype=FLOAT..VOID] 矩阵 → O(1) 查找
DatatypeSet tree;            // 按 compareDependency 排序的功能集合
DatatypeNameSet nametree;    // 按名称+ID 排序的名称集合
```

类型去重通过两棵 std::set：有名类型按名称+ID 查找，无名类型按 compareDependency 查找。

### 8.3 Per-OpCode 类型推断

70+ TypeOp 子类（`typeop.hh`, `typeop.cc`），每个 P-code OpCode 有其专属的类型推断规则。

`propagateType()` 是核心传播方法。以 INT_ADD 为例（`typeop.cc:1183-1203`）：

1. 若传入类型是 INT/UINT：仅当常量偏移时才传播
2. 若传入类型是 PTR：必须传播 input<->output
3. 调用 `propagateAddPointer(offset, op, inslot, ptr->getPtrTo()->getAlignSize())` 判断常量类型：
   - PTRADD：slot==0 有效，offset = const * multiplier
   - PTRSUB：slot==0 有效，offset = op->getIn(1)->getOffset()
   - INT_ADD：检查另一操作数是否为常量；若非常量且 sz!=1 则阻止
4. 通过 `pointer->downChain(typeOffset, ...)` 沿结构体/数组层级下钻

**其他关键 TypeOp 规则**：

- **LOAD**（`typeop.cc:488-501`）：从指针到值的类型推导；`propagateToPointer`/`propagateFromPointer` 需要检测 ptr->ptr 链防止无限递归
- **STORE**（`typeop.cc:559+`）：检查被指类型和值类型的尺寸匹配
- **PIECE**（`typeop.cc:2076-2096`）：处理 near/far 指针，计算字节偏移（考虑大小端）后递归 getSubType
- **SUBPIECE**（`typeop.cc:2163-2188`）：处理复合类型提取，若 UNION 则先 resolveTruncation

### 8.4 ScoreUnionFields 评分框架

Union 类型解析的核心算法（`unionresolve.hh:86`, `unionresolve.cc`）：

- **BFS 双向传播**：maxPasses=6, threshold=256（Trial 总数超限停止）, maxTrials=1024（绝对上限）
- **评分规则**：每种 PcodeOp 有专门评分分支——例如 LOAD 指针对应 +10, INT_SEXT 暗示有符号 +2, BOOL_* 匹配 +10, 不匹配 -10
- **得分最高字段胜出**：`computeBestIndex()` 选择最高分字段
- **偏见机制**：Union 解析默认偏向具体字段（`scores[0] -= 1`）
- **ResolveCache**：在不同上下文间共享 Union 分辨率，保持一致性

### 8.5 类型冲突解决策略

- **锁定优先**：`isTypeLock()` 标记的 Varnode 类型不可覆盖
- **得分竞争**：非锁定推断通过得分竞争
- **偏见机制**：Union 解析中默认偏向具体字段
- **大小匹配**：类型大小不匹配直接 -10 分
- **操作语义匹配**：通过大量操作特定的评分规则编码类型学知识
- **传播边界**：最大 6 层传播，超限则基于当前证据决策

### 8.6 BitField 变换

**BitFieldInsertTransform**（`bitfield.hh`, `bitfield.cc`）：
将经典位域插入模式 `x = (x & ~mask) | ((value << pos) & mask)` 转换为显式 INSERT op。采用逆向（use-def）跟踪，支持 followHoles=true 处理匿名位域。

**BitFieldPullTransform**：
将提取模式 `result = (x >> pos) & mask` 转换为 ZPULL/SPULL op。采用正向（def-use）跟踪，followHoles=false 避免假 pull。

**RulePullAbsorb**：ZPULL/SPULL 创建后的代数简化（如 `SPULL >> signbit == 0` → `0 <= SPULL`）
**RuleInsertAbsorb**：INSERT 创建后的代数简化（如 `INSERT(x & mask, p, n)` → `INSERT(x, p, n)`）

### 8.7 与 traceMiku 的对比

| 维度 | Ghidra | traceMiku |
|------|--------|-----------|
| 类型种类 | 18 meta + 24 sub + 复合 | 6 种 TypeKind (Any/Int/Ptr/Handle/Bool/Conflict) |
| 复合类型 | struct, union, array, enum, typedef | 无 |
| 大小角色 | 核心属性，类型比较第二关键字 | 不使用 |
| signedness | signed/unsigned 区分 | 无区分 |
| 指针层级 | PTR→STRUCT/ARRAY submeta + TypePointerRel | 仅有 Ptr |
| 类型工厂 | typecache[9][8] O(1) | 无工厂 |
| 传播规则 | 70+ per-opcode 推断 | 简单格合并 |
| Union 解析 | ScoreUnionFields BFS 双向 | 无 |
| BitField | INSERT/ZPULL/SPULL | 无 |

**traceMiku 的类型系统改进路线**：

1. **阶段1**：扩展 TypeKind 对标 Ghidra meta-type（添加 Void, Float, Signed/Unsigned Int, Struct, Union, Enum 等）
2. **阶段2**：实现 TypeFactory 缓存矩阵和去重
3. **阶段3**：实现 Per-OpCode 类型推断规则（特别是 INT_ADD 的指针算术检测）
4. **阶段4**：利用 trace 值驱动类型锚定（运行时寄存器值推断 signedness，内存访问模式推断结构体布局）

---

## 第9章 规范化与优化

### 9.1 代数简化 Rule 集合

ActionPool "oppool1" 包含 120+ 个 Rule（`ruleaction.hh:1610`, `ruleaction.cc:11031`），关键 Rule 分类：

| 类别 | 代表 Rule | 功能 |
|------|----------|------|
| 死代码 | RuleEarlyRemoval | 移除无用 Varnode |
| 常量折叠 | RuleCollapseConstants | 编译时常量计算 |
| 拷贝传播 | RulePropagateCopy | COPY 链消除 |
| 表达式合并 | RuleCollectTerms | 合并同类项 |
| 位掩码 | RuleAndMask, RuleOrMask | 位与/位或简化 |
| 算术变换 | RuleSub2Add, RuleZextEliminate | 减转加、零扩消除 |
| 除法优化 | RuleDivOpt, RuleModOpt | 乘法逆元识别 |
| 栈变量 | RuleLoadVarnode, RuleStoreVarnode | 栈 LOAD/STORE 模式匹配 |
| 指针 | RulePtrArith, RulePtrFlow | 指针算术和指针流 |
| 条件移动 | RuleConditionalMove | CSEL/CMOV 识别 |
| 子变量 | RuleSubvar* 系列 | 子变量裁剪 |
| 位域 | RuleBitFieldStore 等 | 位域操作识别 |
| 双精度 | RuleDoubleIn/RuleDoubleOut | 多精度操作合并入口 |
| 浮点 | RuleFloat* 系列 | 浮点变换 |

### 9.2 多精度运算合并

`double.hh/double.cc`（3647 行）实现了将拆分的高低位操作合并为双宽度操作。

**SplitVarnode 三种形态**：
1. 常量形态：`lo==null && hi==null`，`val` 保存常量值
2. 完整拆分：`lo!=null && hi!=null`，从同一 `whole` 通过 SUBPIECE 派生
3. 零扩展：`lo!=null && hi==null`，高位隐含为零

**各运算合并 Form 类**：

| Form 类 | 识别模式 | 输出 |
|---------|----------|------|
| AddForm | `reshi=hi1+hi2+zext(CARRY)`, `reslo=lo1+lo2` | 双宽度 INT_ADD |
| SubForm | `reshi=hi1+(-hi2)+(-zext(BORROW))`, `reslo=lo1+(-lo2)` | 双宽度 INT_SUB |
| LogicalForm | `reshi=hi1&hi2`, `reslo=lo1&lo2` | 双宽度逻辑 |
| LessThreeWay | `res = hiless \|\| (hiequal && loless)` 三路分支 | 双宽度比较 |
| Equal1/2/3Form | 分支链/布尔合并/与-1比较 | 双宽度等值 |
| ShiftForm | 高低位移位+溢出拼接 | 双宽度移位 |
| MultForm | Karatsuba 风格拆分乘法 | 双宽度乘法 |

**checkForCarry()** 识别进位标志的三种 P-code 形式：
- 直接 CPUI_INT_CARRY 操作
- 比较模拟：`lo1 + lo2 < lo1` 转换为零扩展
- 与 -1 比较：`lo1 != 0` 相当于 carry=-1

### 9.3 128-bit 运算原语

`multiprecision.hh/multiprecision.cc` 实现了 Knuth Algorithm D（多精度除法）：

1. 使用 `split64_32()` 将 64-bit 字拆分到 32-bit "数字"数组
2. 规范化左移 s = count_leading_zeros(v[n-1])
3. D1-D8：逐位计算商数字（qhat），包含修正步骤
4. `pack32_64()` 打包回 64-bit

### 9.4 Unify 约束求解器

`unify.hh/unify.cc` 实现了一个**回溯式约束满足问题（CSP）求解器**，用于声明式模式匹配和重写。

**核心组件**：
- **UnifyState**：tagged union 支持 4 种绑定类型（PcodeOp*, Varnode*, uintb*, BlockBasic*）
- **三种搜索遍历**：TraverseCountState（线性）、TraverseDescendState（下游使用者）、TraverseGroupState（组合遍历器的栈式回溯）
- **ConstraintGroup 回溯算法**：三态状态机（state=-1 首次初始化, 0 stepping, 1 push 下一个子约束）
- **ConstraintOr**：顺序尝试无依赖分支
- **UnifyCPrinter**：将约束树编译为等价 C++ 代码

### 9.5 Merge：Varnode → HighVariable 合并

`merge.hh/merge.cc` 实现两类合并策略：

**强制合并**：MULTIEQUAL/INDIRECT 的输入输出、全局/栈 Varnode。Cover 冲突时通过 `trimOpInput/trimOpOutput` 插入 COPY 裁剪数据流。

**推测合并**：同一 op 的输入输出、同类型 Varnode。Cover 冲突时放弃，不修改数据流。

**Dominant COPY 优化**（`buildDominantCopy()`）：找到同一源 Varnode 的多个 COPY 的公共支配块，创建支配 COPY 消除冗余。

**mergeTest 四层过滤**：Basic → Required → Adjacent → Speculative

---

## 第10章 函数参数识别与调用约定

### 10.1 ParamMeasure 排名系统

ParamMeasure（`paramid.hh`, `paramid.cc`）定义 7 级排名：

| 排名 | 枚举值 | 含义 |
|------|--------|------|
| 1 | DIRECTWRITEWITHOUTREAD/BESTRANK | 直接写入无读取（最佳输出） |
| 2 | DIRECTREAD | 直接读取（输入） |
| 2 | DIRECTWRITEWITHREAD | 直接写入并有读取（输出） |
| 3 | DIRECTWRITEUNKNOWNREAD | 写入但读取未知 |
| 4 | SUBFNPARAM/THISFNPARAM | 传递给子函数/当前函数参数 |
| 5 | SUBFNRETURN/THISFNRETURN | 子函数返回/当前函数返回 |
| 6 | INDIRECT | 间接创建 |
| 7 | WORSTRANK | 最差排名 |

**walkforward**（识别输入，maxdepth=10）：沿数据流前向追，BRANCH/CBRANCH → DIRECTREAD，CALL → SUBFNPARAM

**walkbackward**（识别输出）：沿定义链反向追，默认分支先 walkforward 检查有无读取——有则 DIRECTWRITEWITHREAD，无则最佳 DIRECTWRITEWITHOUTREAD

**calculateRank 双模式**：best=true 寻找最优点（取 min），best=false 寻找最差路径（取 max）

### 10.2 ParamEntry 资源模型

ParamEntry（`fspec.hh:84-155`）是调用约定描述的最小单元：

- **独占模式**（isExclusion=true, alignment=0）：整个范围只存放一个参数（如 x0）
- **共享模式**（isExclusion=false, alignment>0）：按 alignment 对齐分配多个参数（如栈 8 字节槽）
- **GroupID 系统**：用于参数排序和资源分配，`status[group]` 记录已使用槽数

### 10.3 ParamList 多态体系

```
ParamList (抽象基类)
├── ParamListStandard (标准有序)
│   ├── ParamListStandardOut (标准输出)
│   └── ParamListRegisterOut (寄存器无序输出)
├── ParamListRegister (寄存器无序输入)
└── ParamListMerged (多模型合并)
```

**fillinMap 六阶段**：buildTrialMap → forceExclusionGroup → separateSections → forceNoUse → forceInactiveChain → markUsed

### 10.4 ProtoModelMerged 多模型评分

ScoreProtoModel 评分系统：
- slot 空洞：penalty[0]=16, penalty[1]=10, penalty[2]=7, penalty[3]=5, penalty[4+]=3
- slot 重叠：mismatchpenalty=20
- 总分越低越好

### 10.5 与 traceMiku 的关联

**traceMiku 运行时优势**：
- 寄存器参数：直接观察 x0-x7 在函数入口的实际值
- 栈参数：直接知道 SP 值，精确计算偏移
- 可变参数：直接观察调用点压栈的数量和值
- 间接调用目标：PC trace 直接给出 CALLIND 目标

**可移植组件**：ParamEntry 系统、fillinMap 算法、ScoreProtoModel 评分

---

## 第11章 序列化与编解码

### 11.1 三层抽象

Ghidra 的序列化系统采用三层抽象设计：

**第一层**：ElementId/AttributeId 标识系统（`marshal.hh`）——全局静态注册 + `initialize()` 填充哈希表，O(1) 查找

**第二层**：Encoder/Decoder 接口层——纯虚接口，支持顺序遍历和按名查找两种模式

**第三层**：具体编码实现——XmlEncode/XmlDecode（文本 XML）和 PackedEncode/PackedDecode（紧凑二进制）

### 11.2 XML 解析器自实现

Ghidra 实现了完整的自包含 XML 解析器（`xml.cc`, 2510 行）：
- Bison LALR(1) 语法（70 规则/151 状态）
- XmlScan 字符扫描器（9 种状态模式：CharData/CData/AttValueSingle/AttValueDouble/Comment/CharRef/Name/SName/Single）
- SAX 接口（ContentHandler）+ DOM 树构建
- 支持 UTF-8 编码

### 11.3 PackedFormat 紧凑二进制协议

反编译器进程间通信使用自定义二进制协议（`marshal.cc`）：

```
Header 字节：01x/10x/11x 三态编码
  01xiiiii = ELEMENT_START
  10xiiiii = ELEMENT_END
  11xiiiii = ATTRIBUTE

整数编码：7-bit 可变长，最多 10 字节（70-bit）
  长度码 0 = 值为 0
  长度码 1-10 = 7到70位宽

8 种类型码：boolean, signed_pos, signed_neg, unsigned, address_space, special_space, string

PackedDecode 使用 ByteChunk 链表存储（每块 1024 字节），Position 三指针迭代器
```

### 11.4 差分序列化

`FuncProto::encodeEffect()` 仅存储与 ProtoModel 默认值不同的 EffectRecord，反序列化时合并覆盖。`encodeLikelyTrash()` 同理。

### 11.5 Address 编码

所有地址通过 `(space, offset, size)` 三元组编码。FspecSpace 将 FuncCallSpecs 对象指针编码为地址（IPTR_FSPEC 类型）。

---

## 第12章 输出渲染

### 12.1 RPN 栈驱动的表达式生成

`PrintC`（`printc.cc`, 3536 行）使用反向波兰表示法（RPN）栈生成 C 表达式：

1. `pushOp(tok)`：操作符推入栈顶，决定是否需要括号
2. `pushAtom(vn)`：叶子节点推入，触发自动弹出
3. `recurse()`：隐式 Varnode 递归展开
4. `parentheses()`：根据相邻 OpToken 类型/优先级/结合性决定是否加括号

### 12.2 OpToken 优先级系统

46 个静态 OpToken 覆盖 C 全操作符（优先级 2-70），6 种 token 类型：
binary, unary_prefix, postsurround, presurround, space, hiddenfunction。

支持 negate 翻转（如 `less_than ↔ greater_equal`）用于布尔否定优化。

### 12.3 修改栈系统

16 种打印修饰符（`force_hex/force_dec/force_pointer/print_load_value/comma_separate/flat/negatetoken/hide_thisparam/pending_brace` 等），支持嵌套上下文。

### 12.4 常量推入中央调度

`pushConstant` 按元类型分支：TYPE_UINT/INT → `push_integer`（进制自动判定 `mostNaturalBase`）/`pushCharConstant`/`pushEnumConstant`；TYPE_BOOL → `pushBoolConstant`；TYPE_PTR → NULL/字符串/函数名；TYPE_FLOAT → INFINITY/NAN/科学记数

### 12.5 控制流美化

- **emitBlockIf**：PendingBrace 机制实现 "else if" 合并
- **emitBlockWhileDo**：支持溢出语法 `while(true){if(cond)break}`
- **emitForLoop**：自动检测 init/cond/iterate 三部分
- **emitBlockSwitch**：case/default 标签生成

### 12.6 Emit 标记系统

11 种语法高亮颜色：keyword(0), comment(1), type(2), funcname(3), var(4), const(5), param(6), global(7), default(8), error(9), special(10)

### 12.7 ClangToken 模型（Java 侧）

10 种 Token 子类：ClangVariableToken（Varnode+PcodeOp 引用）、ClangOpToken、ClangSyntaxToken、ClangFuncNameToken（HighFunction+PcodeOp）、ClangTypeToken（DataType 查找）、ClangCommentToken、ClangLabelToken、ClangBreak、ClangFieldToken、ClangBitFieldToken、ClangCaseToken

**Token → 地址映射**：ClangVariableToken/ClangFuncNameToken 通过关联的 PcodeOp 提供 `getMinAddress()/getMaxAddress()`

### 12.8 注释系统

CommentSorter 三键排序：`(block_index, op_order, unique_pos)` 将注释精确放置到输出正确位置。CommentDatabaseGhidra 通过 ArchitectureGhidra 向 Java 端请求注释并缓存。

### 12.9 与 traceMiku 的对比

| 维度 | Ghidra PrintC | traceMiku HLIL 渲染 |
|------|--------------|-------------------|
| 表达式生成 | RPN 栈 + 优先级判括号 | 直接拼接字符串 |
| 类型声明 | buildTypeStack 前后缀分离 | 简单拼接 |
| 语法高亮 | 11 色 XML 标记 | 无标记系统 |
| Token→地址 | Varnode/PcodeOp 关联 | 无映射 |
| 控制流美化 | 6 种循环 + else if 合并 | 基本 goto |
| 变量着色 | 全局/局部/参数/volatile | 统一颜色 |

**建议**：traceMiku 应实现基于 Token 模型的输出，使每个 Token 映射到 trace 记录，从而支持 hover 显示运行时值（这是 traceMiku 相对于 Ghidra 的独特优势）。

---

## 第13章 Java/C++ 集成架构

### 13.1 进程通信模型

Ghidra 反编译器采用 **C++ 独立进程 + Java 管道通信** 架构：

```
Ghidra Java 主进程
  ├── DecompInterface (门面)
  │     └── DecompileProcess (原生进程句柄)
  │           ├── stdin  → 写入命令和参数
  │           ├── stdout ← 读取响应和查询
  │           └── stderr ← 诊断输出
  │
  └────────── 管道 ──────────
              │
  decompile (C++ 独立进程)
    └── ArchitectureGhidra
          ├── istream sin (来自 Java)
          ├── ostream sout (去往 Java)
          └── 回调查询 (17 种 COMMAND_*)
```

### 13.2 通信协议

使用基于**标记字节**的二进制协议（`ghidra_arch.hh`）：

| 标记 | 含义 |
|------|------|
| 0,0,1,2 | command_start |
| 0,0,1,3 | command_end |
| 0,0,1,8 | query_response_start |
| 0,0,1,9 | query_response_end |
| 0,0,1,10 | exception_start |
| 0,0,1,11 | exception_end |
| 0,0,1,12 | byte_start |
| 0,0,1,13 | byte_end |
| 0,0,1,14 | string_start |
| 0,0,1,15 | string_end |

### 13.3 17 种回调查询

C++ 反编译器通过 ArchitectureGhidra 向 Java 端发起 17 种查询：

```
COMMAND_GETMAPPEDSYMBOLS   — 地址映射符号查询（最重要）
COMMAND_GETBYTES            — 读取内存字节
COMMAND_GETPCODE            — 指令 P-code 生成
COMMAND_GETPCODEEXECUTABLE  — 可执行 P-code 脚本
COMMAND_GETCOMMENTS         — 获取注释
COMMAND_GETCALLFIXUP        — 调用约定注入
COMMAND_GETCALLOTHERFIXUP   — UserOp 注入
COMMAND_GETCALLMECH         — 调用机制注入
COMMAND_GETCPOOLREF         — 常量池引用解析
COMMAND_GETEXTERNALREF      — 外部引用解析
COMMAND_GETNAMESPACEPATH    — 命名空间路径查询
COMMAND_GETREGISTER         — 寄存器描述查询
COMMAND_GETREGISTERNAME     — 寄存器名称查询
COMMAND_GETSTRINGDATA       — 字符串数据查询
COMMAND_GETCODELABEL        — 代码标签查询
COMMAND_GETDATATYPE         — 数据类型查询
COMMAND_GETUSEROPNAME       — UserOp 名称查询
COMMAND_GETTRACKEDREGISTERS — 寄存器追踪值查询
```

### 13.4 DecompInterface 完整生命周期

```java
new DecompInterface()
  → setOptions(options)
  → setSimplificationStyle("decompile")
  → openProgram(program)
      ├── 创建 DecompileCallback
      ├── initializeProcess()
      │     ├── 启动/获取原生进程
      │     ├── 编码 translator/pspec/cspec/coretypes
      │     ├── 发送选项和输出配置
      │     └── isReady() 验证
      └── 完成
  → decompileFunction(func, timeoutSecs, monitor)
      ├── 选择编解码器 (处理 overlay 空间)
      ├── 发送 "decompileAt" 命令
      └── new DecompileResults(decoder)
  → closeProgram() / dispose()
```

### 13.5 进程自动恢复

`DecompileProcess` 状态检查 + 自动恢复：`isReady()` 失败 → `restart()` + `reinitialize()`；超时 → `GTimerMonitor` 回调 → `dispose()`；取消 → `stopProcess()` 杀进程。

### 13.6 与 traceMiku 架构的对比

| 维度 | Ghidra | traceMiku |
|------|--------|-----------|
| 核心语言 | C++ (引擎) + Java (UI) | Rust (全栈) |
| 通信方式 | stdin/stdout 管道 + XML | HTTP/WebSocket (axum) |
| 进程模型 | 独立进程 + 回调查询 | 进程内分析 |
| 启动延迟 | 进程启动 + 初始化 | 无需 |
| 崩溃隔离 | 天然隔离 | 同一进程 |
| 内存效率 | IPC 拷贝 | 直接访问 |
| 符号查询 | 17 种回调，按需加载 | 内存内直接访问 |
| 类型系统 | Java 端管理，按需同步 | Rust 原生 |

---

## 第14章 外部接口与进程管理

### 14.1 Module-Command 模式

`interface.hh` 定义了通用命令行交互框架：

- **IfaceStatus**：控制台状态机，维护 comlist（命令注册表）和 datamap（模块数据）
- **IfaceCommand**：可执行命令抽象，通过 token 序列匹配输入，支持前缀模糊匹配
- **IfaceData**：模块级共享数据容器
- **IfaceCapability**：命令分组插件，自动发现与注册

### 14.2 Database → Scope → Symbol 三层体系

```
Database (全局符号表)
  ├── Scope (全局域)
  │   ├── Symbol (符号: 名称+类型+标志)
  │   │   └── SymbolEntry (存储位置映射)
  │   │       ├── Address addr (存储地址)
  │   │       ├── uint8 hash (动态 hash)
  │   │       ├── int4 offset (在 Symbol 内的偏移)
  │   │       └── RangeList uselimit (代码有效范围)
  │   └── Scope (命名空间子域)
  ├── resolvemap (地址→命名空间)
  ├── idmap (ID→Scope)
  └── flagbase (内存属性)
```

### 14.3 SymbolEntry 的多片存储与代码敏感映射

- **多片存储**：`precislo/precishi` 标志标识高低片
- **动态存储**：通过 `hash` 定位，用于寄存器变量和临时变量
- **代码敏感**：`uselimit` 使同一内存地址在不同代码段映射不同 Symbol

### 14.4 Scope 作用域链查询

6 个静态 stack 方法：`stackAddr`, `stackContainer`, `stackClosestFit`, `stackFunction`, `stackExternalRef`, `stackCodeLabel`。沿作用域链向上递归查找。

### 14.5 ScopeGhidra 代理远程查询

三级查找：`cache → holes → remote query`

- 先查本地 `ScopeInternal *cache`
- 再查 `holes` rangemap（negative caching，已确认的"空洞"）
- 最后通过 `ghidra->getMappedSymbolsXML()` 发起远程查询

### 14.6 命名空间懒加载

`reresolveScope(scopeId)`：若本地无对应 Scope，通过 `getNamespacePath` 查询路径，递归创建 Scope 链。使用 CRC32 确定性命名空间 ID 哈希支持跨会话持久化。

### 14.7 对 traceMiku 的参考价值

1. **SymbolEntry 的 uselimit 概念**：对应 traceMiku 中"同一内存地址在不同执行点可能代表不同符号"
2. **懒加载符号解析**：cache → hole → remote query 三级查找可直接借鉴
3. **Scope 作用域链**：对 traceMiku 的变量作用域建模有参考意义

---

## 第15章 P-code 注入与扩展机制

### 15.1 InjectPayload 四种类型

P-code 注入（`pcodeinject.hh`）是 Ghidra 的核心扩展机制：

| 类型 | 值 | 触发时机 | 用途 |
|------|-----|----------|------|
| CALLFIXUP_TYPE | 1 | 分析 CALL 指令时 | 替换已知库函数（memcpy, strlen） |
| CALLOTHERFIXUP_TYPE | 2 | 遇到 CALLOTHER 时 | 翻译 UserOp 为标准 P-code |
| CALLMECHANISM_TYPE | 3 | 跨函数边界时 | 注入参数传递/返回值 P-code |
| EXECUTABLEPCODE_TYPE | 4 | 脚本评估时 | 计算常量、解析跳转表 |

### 15.2 双路径注入架构

| 维度 | SLEIGH 路径 | Ghidra 路径 |
|------|------------|------------|
| P-code 存储 | C++ 本地 ConstructTpl | Java 端按需生成 |
| 编译时机 | 启动时一次性解析 | 注入时实时请求 |
| 可用信息 | 仅规范文件 | 全部 Ghidra Java 分析结果 |
| 内存/延迟 | 预编译模板，内存大，注入 O(1) | 占位符，内存小，需 IPC |

### 15.3 InjectContext 参数绑定

```cpp
class InjectContext {
    Architecture *glb;
    Address baseaddr;    // inst_start
    Address nextaddr;    // inst_next
    Address calladdr;    // inst_dest
    vector<VarnodeData> inputlist;
    vector<VarnodeData> output;
};
```

`setupParameters()` 将模板占位符替换为 InjectContext 中的实际 Varnode。

### 15.4 ManualCallFixup 动态注册

`PcodeInjectLibrary::manualCallFixup(name, snippet)` 和 `manualCallOtherFixup(...)` 允许运行时动态注册 P-code 注入片段。

### 15.5 与 traceMiku 的关联

**traceMiku 的独特价值**：

1. **TraceCallFixup**：用 trace 值替换已知库函数调用——当 trace 记录了 `malloc(1024)` 的返回值时，直接注入常量
2. **TraceInjectContext**：为 IL 提升器提供运行时值查询
3. **混合 LoadImage**：优先从 trace 提供字节（运行时真实值），回退到原始文件字节
4. **CapabilityPoint 模式**：可用于注册 `tools/hooks/` 下的自定义扩展

---

## 第16章 浮点处理与多精度运算

### 16.1 FloatFormat IEEE 754 仿真

FloatFormat（`float.hh/float.cc`, 693 行）实现 IEEE 754 编码/解码：

**五类编码分类**：normalized(0), infinity(1), zero(2), nan(3), denormalized(4)

**核心三段转换**：编码 → 宿主 double → 运算 → 宿主 double → 编码。所有运算通过宿主 CPU 的双精度 FPU 执行。

**最近偶数舍入**：遵循 IEEE 754 标准。`printDecimal()` 实现往返转换保证算法，确保最短唯一表示。

### 16.2 多精度运算合并入口

`RuleDoubleIn` 和 `RuleDoubleOut`（`double.cc`）利用 SUBPIECE/PIECE 的 `isPrecisHi/isPrecisLo` 标记扫描。

`SplitVarnode::applyRuleIn()` 作为核心调度器，按 opcode 分派给对应 Form 类。

### 16.3 仿真框架

```
Emulate (抽象基类)
├── EmulateMemory (MemoryState 后端)
│   └── EmulatePcodeCache (SLEIGH 集成 + 断点)
│       └── EmulatePcodeOp (语法树内)
└── EmulateSnippet (常量传播片段)
```

EmulateSnippet 对 traceMiku 参考价值最高——后者有真实 trace 值，可直接验证优化正确性。

### 16.4 与 traceMiku 的关联

- 浮点处理：traceMiku 可直接使用 trace 中的 IEEE 754 编码作为实际浮点值
- 多精度合并：Form 类模式匹配可直接作为 pass 参考实现
- 仿真框架：不需要 Ghidra 的符号执行（有真实 trace），但可用 EmulateSnippet 模式验证 IL 优化

---

## 第17章 测试体系

### 17.1 测试结构

Ghidra 反编译器的测试分为两层：

**C++ 单元测试**（`unittests/`，7 个文件）：

| 文件 | 测试对象 | TEST 数量 |
|------|----------|----------|
| testcirclerange.cc | CircleRange 值域推理引擎 | ~60 |
| testfloatemu.cc | FloatFormat IEEE 754 仿真 | ~30 |
| testfuncproto.cc | ProtoModel 多架构调用规约 | ~15 |
| testmarshal.cc | 序列化编解码器 | ~18 |
| testtypes.cc | CastStrategy、枚举匹配 | ~7 |
| testparamstore.cc | 多架构参数存储分配 | ~4（+大量子断言） |
| testmultiprec.cc | 128-bit 大整数运算 | ~5 |

**数据驱动测试**（`datatests/`，83 个 XML 文件）：输入 `(binary + spec) → 控制台命令 → stringmatch 正则验证`

测试覆盖了所有主要领域：循环恢复、Switch 识别、结构体/Bitfield/Union 重建、浮点转换和打印、整数显示格式、函数内联、除/模优化、条件常量传播、else-if 折叠、ccmp 布尔表达式、Volatile/MMIO 处理等。

### 17.2 traceMiku 测试差距

| 维度 | Ghidra | traceMiku |
|------|--------|-----------|
| 验证方式 | 正则匹配输出 C 代码 | 覆盖率 + 输出非空 |
| 浮点 | floatconv/floatcast/floatprint | 无 |
| 多架构 | x86-64/x86-32/ARM32/AARCH64/MIPS/PPC/68000 | 仅 ARM64 |
| 除/模优化 | divopt(68) + modulo(40) | 无 |
| Bitfield | 位域读写/比较/递增/范围 | 无 |
| Union | 嵌套 union + 栈上 union 数组 | 无 |
| 显示格式 | convert + displayformat | 无 |
| 函数内联 | inline.xml | 无 |

**关键差距**：traceMiku 的验证只检查覆盖率，不检查**输出内容的语义正确性**。

### 17.3 循环恢复规则（从测试中提取）

- **for-loop 恢复**：需迭代变量初始化为 0、有界递增迭代；迭代变量在迭代语句后**不能**有活跃用途（否则保持 while）
- **do-while 识别**：底部条件检查
- **while-true + break**：溢出循环语法
- **Switch 恢复**：支持直接表/间接表/if 中嵌套/loop 中 switch/结构体字段作为 switch 变量

### 17.4 建议

traceMiku 应引入类似 Ghidra 的 `stringmatch` 机制进行输出语义验证，优先增加浮点、位域、Union 和除/模优化识别测试。

---

## 第18章 Java UI 交互模型

### 18.1 MVC 三层架构

```
DecompilerController (Controller)
  ├── DecompilerPanel (View - Swing JPanel)
  │     ├── IndexedScrollPane (虚拟滚动画板)
  │     ├── DecompilerMarginProvider[] (左侧边栏)
  │     ├── DecompilerHoverProvider (悬停提示)
  │     └── ClangHighlightController (高亮控制)
  └── DecompilerManager (Model - 异步反编译调度)
```

### 18.2 Token 类型分发器

`tryToGoto()` 通过 instanceof 链处理点击：

| Token 类型 | 动作 |
|------------|------|
| ClangFuncNameToken | 跳到被调用函数 |
| ClangLabelToken | 跳转到 goto 目标标签 |
| ClangVariableToken | 解析地址后跳转 |
| ClangSyntaxToken | 括号匹配跳转 |
| ClangCommentToken | 解析地址/标量跳转 |

### 18.3 三层高亮系统

```
1. Context Highlights (上下文) — 临时，光标跟随，自动清除
2. Secondary Highlights (二级) — 持久，中键/右键，跨函数保留
3. Service Highlights (服务) — 插件注入，生命周期由注册管理
```

**高亮颜色混合**：`blend()` 累加，每新颜色以 0.8 权重混合，最多 5 种。

**中键高亮**：`NameTokenMatcher` 按文本名匹配所有同名引用，toggle 模式。

### 18.4 悬停提示优先级链

| 优先级 | 服务 | 功能 |
|--------|------|------|
| 50 | ReferenceDecompilerHover | "引用到"的代码/数据 |
| 30 | ScalarValueDecompilerHover | hex/dec/ascii 显示 |
| 30 | FunctionSignatureDecompilerHover | 函数签名预览 |
| 20 | DataTypeDecompilerHover | 数据类型详情 |

### 18.5 异步反编译队列

- **单后台任务** + **pending 替换**
- **500ms 防抖**（SwingUpdateManager）
- **智能合并**：同函数仅更新位置，不同函数取消重启
- **缓存**：Guava Cache, softValues, 按 Function 键，仅缓存 completed 结果
- **取消**：`cancelCurrentAction()` → `DecompInterface.stopProcess()`
- **光标跳转平滑动画**：`pow(distance, 0.8) * 100ms`，插值滚动 + 精确终止
- **updateId 防过期**：每次 add 高亮递增，`PendingHighlightUpdate` 校验一致性

### 18.6 对 traceMiku Web UI 的启示

1. **Token 模型**：在 Rust 侧实现等效模型，支持 11 色语法高亮和地址映射
2. **三层高亮**：Context（光标跟随） + User（手动标记） + Service（插件注入）
3. **异步队列**：tokio::spawn + abort handle + 防抖
4. **HoverService 链**：优先级竞争，先到先得。traceMiku 可以最高优先级注入运行时值显示
5. **边栏扩展点**：行号 + trace 覆盖率指示器
6. **平滑滚动**：CSS transition 实现

---

## 第19章 为 traceMiku 增强的路线图

### 19.1 立即可改进（1-2 周）

这些改进基于 Ghidra 源码的直接参考，可在现有架构上实施：

**1. 升级支配者算法**
- 将 `pass_phi.rs` 中 O(n^2) 集合交集替换为 Cooper-Harvey-Kennedy (2001) 迭代 finger 算法
- 约 120 行 Rust 代码
- 参考 `block.cc:1958-2036`

**2. 引入 MULTIEQUAL 专用操作码**
- 在 LLIL 操作码中新增 MULTIEQUAL（替代当前 SetReg + phi extra）
- 参考 `opcodes.hh` CPUI_MULTIEQUAL(60)

**3. Trace 值常量折叠**
- 在 `pass_uidf.rs` 中，当 `is_const()` 返回 true 时，替换对应 SSA 定义为常量
- 比 Ghidra 的静态值集分析更精确

**4. Token ↔ Trace Record 映射**
- 在 HLIL Token 模型中存储 Varnode/PcodeOp 引用
- 通过这些引用查找 trace.bin 对应的运行时记录
- 使 Hover 显示运行时值成为可能

**5. 测试语义验证**
- 在 `decomp_verify_tests.rs` 中添加 `assert!(output.contains("if"))` 等语义断言
- 参考 Ghidra 的 `stringmatch` 正则匹配方法

### 19.2 中期目标（2-4 周）

**6. 实现通用 Rule 框架**
- 参照 ActionPool 的 per-opcode 规则索引机制
- 实现 `Rule` trait：`get_op_list() -> Vec<OpCode>`, `apply_op(op, data) -> bool`
- 实现定点迭代循环直到无变更

**7. TraceDAG 结构化算法**
- 在 `pass_restructure.rs` 中实现 TraceDAG 算法
- BranchPoint, BlockTrace, BadEdgeScore 评分系统
- 这是消除 goto 的关键突破
- 参考 `blockaction.cc:499-1014`

**8. 循环体正确扩展**
- 将简单 reverse BFS 升级为 `LoopBody::extend()` 的 visitCount 机制
- 参考 `blockaction.cc:40-438`

**9. 内存 SSA（基础实现）**
- 为 STORE 操作插入 INDIRECT-like 的数据流中断点
- 为 LOAD 操作插入 guard COPY
- 实现单遍 heritage（寄存器 → 栈）

**10. 类型系统扩展**
- 扩展 TypeKind 枚举对标 Ghidra meta-type（添加 Void, Float, Signed/Unsigned, Struct, Union, Enum）
- 实现 TypeFactory 缓存矩阵
- 实现 INT_ADD 的指针算术检测（`propagateAddPointer`）

### 19.3 长期愿景（1-3 月）

**11. 完整类型推断管线**
- 实现 70+ OpCode 的 per-opcode 类型推断规则
- 实现 Union 延迟解析（`ScoreUnionFields` + `ResolveCache`）
- 实现 BitFieldInsertTransform/BitFieldPullTransform
- 实现常量指针→全局符号推断
- 实现结构体字段访问的 PIECE/SUBPIECE 模式识别

**12. 多精度运算合并**
- 实现 SplitVarnode 数据结构和六种初始化路径
- 实现 AddForm/SubForm/LessThreeWay/EqualForm/MultForm/ShiftForm
- 实现连续 LOAD/STORE 合并
- 参考 `double.hh/double.cc`（3647 行）

**13. 跳转表恢复**
- 实现 EmulateFunction 轻量级路径模拟器
- 实现 GuardRecord 边界守卫分析
- 实现 switchVarConsume 掩码推断
- 利用 trace 值替代部分模拟（直接使用运行时目标地址）

**14. 函数参数识别**
- 实现 ParamMeasure 排名系统（walkforward/walkbackward + calculateRank）
- 实现 ParamEntry 资源模型（独占/共享 + GroupID）
- 利用 trace 运行时值精确识别参数

**15. 可组合 Action 管线**
- 实现 Action/ActionGroup/ActionPool 树状管线
- 实现 GroupList 选择性克隆
- 实现四层定点迭代
- 预定义 "decompile" / "fast" / "paramid" 等管线

### 19.4 traceMiku 的独特优势

Ghidra 永远无法获得的差异化能力：

**1. 运行时值悬停**
每个 LLIL/MLIL/HLIL Token 都可以通过 trace 记录查找对应的运行时值，在悬停时显示。Ghidra 的 HoverService 只能显示静态类型和引用信息。

**2. Trace 引导的常量折叠**
Ghidra 依赖静态值集分析推断常量。traceMiku 直接从真实执行中读取值，常量检测无 false positive。

**3. 精确的内存别名消歧**
Ghidra 的 LoadGuard 通过值集分析估计 STORE/LOAD 别名范围。traceMiku 直接从 trace 记录获取实际地址，100% 精确。

**4. 间接调用目标解析**
Ghidra 的 BRANCHIND 恢复依赖复杂的跳转表分析。traceMiku 直接从 PC trace 知道目标地址。

**5. 执行路径约束**
Ghidra 分析所有可能路径（包括从未执行的死路径），可能产生误报。traceMiku 可以只分析实际执行的路径。

**6. 混合静态/动态分析验证**
traceMiku 可以用 trace 值验证优化前后 IL 变换的正确性——在 trace 上下文中仿真优化前后的序列，比较结果一致性。

**7. 自适应反编译精度**
基于 trace 覆盖率，对高频执行热路径应用更激进的分析/优化，对冷路径保持保守。

---

## 附录

### 附录 A: P-code 操作码完整参考

（见第 2.2 节完整列表）

### 附录 B: Action/Pass 完整列表

（见第 3.6 节完整列表）

### 附录 C: 关键类索引

| 类名 | 头文件 | 行数(约) | 职责 |
|------|--------|---------|------|
| Action | action.hh | 328 | Action 基类，定点迭代引擎 |
| ActionDatabase | action.hh | 298 | 单例管线管理器 |
| ActionPool | action.hh | 262 | Rule 容器，per-opcode 索引 |
| Rule | action.hh | 194 | 局部模式匹配基类 |
| Funcdata | funcdata.hh | 627 | 单函数总数据容器 |
| Varnode | varnode.hh | 354 | SSA 变量节点 |
| VarnodeBank | varnode.hh | 418 | Varnode 容器，双重排序索引 |
| HighVariable | variable.hh | 233 | C 级变量（多次写入合并） |
| FlowBlock | block.hh | 364 | 控制流图原子单元 |
| BlockGraph | block.hh | 452 | CFG 容器，支配树/循环分析 |
| Heritage | heritage.hh | 342 | SSA 构建管理器 |
| Datatype | type.hh | 1037 | 类型系统基类 |
| TypeFactory | type.hh | 827 | 类型工厂，缓存矩阵，去重 |
| TypeOp | typeop.hh | 930 | Per-OpCode 类型推断 |
| JumpTable | jumptable.hh | 649 | 跳转表主容器 |
| JumpModel | jumptable.hh | 374 | 跳转表模型基类 |
| PathMeld | jumptable.hh | 103 | 多路径交汇引擎 |
| PrintC | printc.hh | 378 | C 代码生成引擎 |
| Emit | prettyprint.hh | - | 11 色语法高亮发射器 |
| InjectPayload | pcodeinject.hh | - | P-code 注入抽象基类 |
| Architecture | architecture.hh | - | 处理器架构抽象 |
| ArchitectureGhidra | ghidra_arch.hh | - | Ghidra C++ 进程总控 |
| DecompInterface | DecompInterface.java | - | Java 反编译门面 |
| DecompileProcess | DecompileProcess.java | - | C++ 进程句柄 |
| DecompileCallback | DecompileCallback.java | - | 17 种回调查询处理器 |
| ClangToken | ClangToken.java | 332 | Java Token 基类，11 色常量 |
| ClangTokenGroup | ClangTokenGroup.java | 203 | Java Token 树形容器 |
| DecompilerPanel | DecompilerPanel.java | 1618 | Java UI 核心 View |

### 附录 D: 术语表（中英对照）

| 中文 | 英文 | 说明 |
|------|------|------|
| 中间表示 | Intermediate Representation (IR) | P-code 或 traceMiku IL |
| 静态单赋值 | Static Single Assignment (SSA) | 每个变量最多写入一次 |
| 动作/Pass | Action/Pass | 一个独立的分析步骤 |
| 定点迭代 | Fixed-Point Iteration | 重复应用直到输出不变 |
| 支配树 | Dominator Tree | 控制流必经节点树 |
| 支配边界 | Dominance Frontier | Phi 节点放置的理论基础 |
| 增广支配树 | Augmented Dominator Tree | Bilardi-Pingali 算法核心 |
| 控制流图 | Control Flow Graph (CFG) | 基本块的有向图 |
| 逆后序 | Reverse Post-Order (RPO) | 节点排序 |
| 不可归约图 | Irreducible Graph | 含不可归约边的 CFG |
| 自然循环 | Natural Loop | 由回边定义的循环 |
| 变量合并 | Variable Merging | Varnode → HighVariable |
| 继承传递 | Heritage | SSA 构建的 Ghidra 术语 |
| 间接操作 | INDIRECT | 内存间接影响的 SSA 抽象 |
| 类型推断 | Type Inference/Propagation | 自动推导变量类型 |
| 控制流结构化 | Control Flow Structuring | goto 消除 → if/while/for |
| 跳转表恢复 | Jump Table Recovery | switch 语句重建 |
| 调用约定 | Calling Convention | 函数参数/返回值传递规范 |
| 规范化 | Normalization | P-code 代数简化 |
| 常数折叠 | Constant Folding | 编译时常量计算 |
| 拷贝传播 | Copy Propagation | COPY 链消除 |
| 死代码消除 | Dead Code Elimination | 无副作用的未使用代码移除 |
| C 代码生成 | C Code Emission | PrintC 输出引擎 |
| 语法高亮 | Syntax Highlighting | 11 色 Token 着色 |
| 管道协议 | Pipe Protocol | C++/Java 进程通信 |
| 回调 | Callback | C++ 向 Java 发起的数据查询 |
| P-code 注入 | P-code Injection | 运行时插入替代 P-code 序列 |
| 浮点格式 | FloatFormat | IEEE 754 编码/解码抽象 |
| 多精度合并 | Double Precision Merging | 拆分操作 → 双宽度操作 |
| 部分类型 | Partial Type | 结构体/联合体/枚举的子片段 |
| 位域 | BitField | 结构体中位级字段 |
| 联合体解析 | Union Resolution | ScoreUnionFields 评分框架 |

---

> 文档完成日期：2026-06-01
> 基于 Ghidra 11.x 反编译器源码分析
> 为 traceMiku 反编译器增强提供技术参考
