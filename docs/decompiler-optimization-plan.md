# 反编译器优化计划

> 创建: 2026-05-14 | 基于 BN vs traceMiku 对比分析

## 目标

1. Call 调用参数分析 — 从 trace 数据推导函数签名
2. 提升所有汇编 — ARM64 lifter 覆盖率 93% → 98%+
3. 修复 IF 比较器 — 标志消除 (nzcv→直接比较)
4. Ghidra Pass 复刻 — clone Ghidra 源码, 完整复刻 decompiler passes
5. Pass 调度框架 — orchestration & dependency management
6. CLI + Web 接入 — CLI(AI友好) + Web(人类友好)

## 进度追踪

### Phase 1: 基础修复 (P0)

| # | 任务 | 状态 | 测试 | Review |
|---|---|---|---|---|
| 1.1 | ARM64 lifter: smull/umull | pending | - | - |
| 1.2 | ARM64 lifter: ldrsw/ldrsh/ldrb/ldrh variants | pending | - | - |
| 1.3 | ARM64 lifter: mrs/msr (system regs) | pending | - | - |
| 1.4 | ARM64 lifter: adr/adrp fix | pending | - | - |
| 1.5 | Flag elim: cbnz/cbz → direct comparison | pending | - | - |
| 1.6 | Flag elim: b.cond with folded flags | pending | - | - |
| 1.7 | HLIL: If structured rendering (not goto) | pending | - | - |

### Phase 2: Call 参数分析 (P0)

| # | 任务 | 状态 | 测试 | Review |
|---|---|---|---|---|
| 2.1 | Trace-based call argument extraction (x0-x7) | pending | - | - |
| 2.2 | Call target name resolution (symbols + BN) | pending | - | - |
| 2.3 | Multi-return value analysis | pending | - | - |
| 2.4 | Call signature inference | pending | - | - |

### Phase 3: Ghidra Pass 复刻 (P1)

| # | 任务 | 状态 | 测试 | Review |
|---|---|---|---|---|
| 3.1 | Clone + 分析 Ghidra decompiler 源码 | pending | - | - |
| 3.2 | Pass: DeadCodeElimination | pending | - | - |
| 3.3 | Pass: ConstantPropagation | pending | - | - |
| 3.4 | Pass: RuleBasedCollapse (SIMD/patterns) | pending | - | - |
| 3.5 | Pass: StackVariableRecovery | pending | - | - |
| 3.6 | Pass: StructuralAnalysis (if/while/for) | pending | - | - |
| 3.7 | Pass: TypePropagation | pending | - | - |
| 3.8 | Pass: ExpressionSimplification | pending | - | - |
| 3.9 | Pass: FuncSignature inference | pending | - | - |
| 3.10 | Pass: ControlFlowDecompilation | pending | - | - |
| 3.11 | Pass: DataTypeRecovery | pending | - | - |

### Phase 4: Pass 调度框架 (P1)

| # | 任务 | 状态 | 测试 | Review |
|---|---|---|---|---|
| 4.1 | Pass trait + registry | pending | - | - |
| 4.2 | Pass dependency DAG | pending | - | - |
| 4.3 | Pass pipeline builder | pending | - | - |
| 4.4 | Iterative pass scheduling (fixpoint) | pending | - | - |

### Phase 5: CLI + Web 接入 (P1)

| # | 任务 | 状态 | 测试 | Review |
|---|---|---|---|---|
| 5.1 | CLI: AI-friendly JSON/YAML output | pending | - | - |
| 5.2 | CLI: streaming decompile for large functions | pending | - | - |
| 5.3 | Web: Pseudo C panel with HLIL | pending | - | - |
| 5.4 | Web: Decompile view with control flow viz | pending | - | - |
| 5.5 | Web: Variable rename/label UI | pending | - | - |

## 架构决策

- **不做破坏性兼容**: LLIL/MLIL/HLIL expr 类型可扩展但不可删除字段
- **Pass 调度参照 Ghidra**: PassManager with dependency graph + fixpoint iteration
- **CLI 输出**: JSON 为 primary, YAML 为 human-readable 备选
- **Web 输出**: 渐进式渲染, streaming response
