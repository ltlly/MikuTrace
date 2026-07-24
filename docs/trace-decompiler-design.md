# 反编译与 IL 架构

traceMiku 的反编译能力服务于运行时分析，不与成熟静态反编译器争夺完整静态代码恢复。
项目保留三条职责不同的路径，公共语义位于 `tracemiku-core`。

## 三条路径

### TraceIR

`tracemiku-core::decompiler` 生成面向摘要和可选 LLM 的函数、块、循环、调用和 VM 候选
结构。`/api/dec/*` 暴露该模型。模型调用是可选能力，不能影响本地分析可用性。

### 本地三层 IL

```text
ARM64 -> LLIL -> MLIL -> HLIL -> C-like tokens
```

- LLIL：寄存器、flag、load/store 和底层控制流。
- MLIL：变量化、SSA、类型传播、结构访问和低层噪声消除。
- HLIL：if/else、循环、switch、break/continue 和 C-like token。

三层必须有可观察的语义差异。如果输出几乎相同，应检查 lowering 和 pass 调度，而不是
在 renderer 中修字符串。

### Trace 增强管线

`decompiler::il_pipeline` 将真实寄存器、执行边、间接目标和 MemShadow 事实注入三层
管线。运行时值必须附 provenance；一次调用中的常量不能未经多调用验证就当成算法常量。

## Pass 规则

- Pass 接收类型化 IR，返回明确的 changed/statistics，不能依赖渲染文本。
- 通用 pipeline 负责简化、常量传播、DCE、类型、结构、bitfield、多精度和控制流恢复。
- 新算法优先参考 Ghidra、Binary Ninja、Phoenix、DREAM、SAILR 等已有实现。
- CPU 密集型反编译必须离开 Tokio reactor，并具有记录数、深度和输出大小上限。
- 每个修复至少包含单元语义测试；跨层变化还要验证 CLI、route 与前端 token。

## 静态与动态边界

trace 能确定本次执行的值和边，但不能证明未执行路径不存在。静态后端用于补充全路径、
符号和类型；动态数据用于 concretization、真实间接边、路径偏置和来源。两者冲突时必须
在输出中展示来源，不得静默覆盖。

## 评估

```bash
cd rust
cargo run --example decompile_trace --release -- <call_dir>
cargo test -p tracemiku-core semantic_decompile
```

评估应同时报告覆盖率、耗时、结构化控制流、未知 intrinsic、来源完整性和截断状态，
不能只比较渲染文本是否相似。
