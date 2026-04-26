# 学术参考与开源工具

traceMiku 的污点追踪、def-use 链、CFG 重建、内存 shadow 都基于经典文献和工业级工具的算法。**复用其测试用例**避免每次都靠你手动发现 bug。

## 污点追踪 (Taint Analysis)

### 文献
- **Newsome & Song (2005)** "Dynamic Taint Analysis for Automatic Detection, Analysis, and Signature Generation of Exploits on Commodity Software" — TaintCheck 原始论文，定义 taint 传播规则
- **Schwartz, Avgerinos, Brumley (2010)** "All You Ever Wanted to Know About Dynamic Taint Analysis and Forward Symbolic Execution (but Might Have Been Afraid to Ask)" — 综述
- **Triton 系统论文** (Saudel & Salwan, SSTIC 2015) "Triton: A Dynamic Symbolic Execution Framework"

### 开源实现（可复用 / 借鉴）
| 工具 | 说明 | 复用价值 |
|---|---|---|
| **Triton** ([JonathanSalwan/Triton](https://github.com/JonathanSalwan/Triton)) | C++/Python 符号执行 + taint，工业级 | 可作为 trace 后端 backend；其 [src/testers](https://github.com/JonathanSalwan/Triton/tree/master/src/testers) 大量测试用例可直接借鉴 |
| **angr** ([angr/angr](https://github.com/angr/angr)) | Python，VEX IR 上的 taint+symbolic | 测试集 [angr/tests](https://github.com/angr/angr-doc/tree/master/examples) |
| **BAP** ([BinaryAnalysisPlatform/bap](https://github.com/BinaryAnalysisPlatform/bap)) | OCaml，formal IR + taint | 论文复现良好 |
| **DECAF** ([sycurelab/DECAF](https://github.com/sycurelab/DECAF)) | QEMU 全系统 taint | 性能参考 |
| **libdft64** ([AngoraFuzzer/libdft64](https://github.com/AngoraFuzzer/libdft64)) | Pin tool，x86_64 | 比特粒度 taint 实现 |

### 我们的实现 vs 上面工具
- **本项目** = trace-replay-based taint（离线分析已采集的 trace），更快但失真：忽略隐式流（implicit flow）、近似内存 taint
- 如需精度更高，trace 采集后送给 **Triton** 做 trace replay：Triton 接受 trace 文件、对每条指令应用其 taint 规则。我们的 trace.bin 可转换为 Triton 输入（PR welcome）

## Def-Use 链 / SSA

### 经典算法
- Cytron et al. (1991) "Efficiently Computing Static Single Assignment Form and the Control Dependence Graph" — 标准 SSA 构造
- Aho/Sethi/Ullman 龙书 第 9 章 Data-Flow Analysis

### 复用
- **LLVM** 的 `LiveVariableAnalysis` / `MemorySSA`
- **Capstone-Engine** 的 `regs_access()` API（我们已经用，但有 bug — `cmp` 类指令把 operand 误标为 def，已在 disasm.py 用 fixup 修复）

## CFG 重建

### 文献
- Cifuentes & Van Emmerik (2001) "Recovery of Jump Table Case Statements from Binary Code"
- Schwartz, Lee, Woo, Brumley (2013) "Native x86 Decompilation Using Semantics-Preserving Structural Analysis and Iterative Control-Flow Structuring"
- **trace-based CFG** 优势在 Andriesse et al. (2016) "An In-Depth Analysis of Disassemblers on x86/x64"  — 静态反汇编对间接跳转无能为力，trace 天然抗混淆

### 开源
- **Ghidra Decompiler** 的 [Sugiyama-style layout](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/Decompiler) — krash 的 CFG 布局参考
- **angr CFGFast/CFGEmulated**
- **Binary Ninja's Function/MediumLevelIL**（推荐配合本项目使用，见下）

## Binary Ninja Headless 集成（强烈推荐）

本项目通过 MCP server 已集成 Binary Ninja headless，可作为 **静态参考 + symbol resolution** 后端。例如：

```python
# Future enhancement: viewer/bn_bridge.py
# - 导入 BN 项目，对 trace 上的每个 PC 拿 LLIL/MLIL/HLIL
# - 把 trace 寄存器值叠加到 BN 伪代码 (像 IDA Lighthouse)
# - 用 BN.get_functions_containing(addr) 替代我们 trace-based 的 sym 推断
```

可调用的 MCP 工具 (mcp__binary_ninja_headless_mcp__*)：
- `binary_functions_at` — 获取函数定义
- `binary_get_function_il_at` — 获取 LLIL/MLIL
- `xref_code_refs_to/from` — 静态 xref（trace 没覆盖到的部分）

**计划**：让 viewer 的 CFG tab 可选 fallback 到 BN headless 的 CFG，这样就能看到 trace 没走过的 dead 路径。

## 反汇编

- **Capstone** 5.0 — 我们的核心
- **Keystone** — 用于测试合成（已集成在 `tests/synth.py`）
- **Triton** 自带反汇编器（基于 LLVM）

## 测试套件 (本项目)

```bash
# 跑全部 34 个测试 (~0.1s)
python3 -m pytest tests/ -v
```

| 文件 | 覆盖 |
|---|---|
| `tests/synth.py` | 用 keystone 真编码 ARM64 汇编合成 trace |
| `tests/test_disasm.py` | def/use 提取、cmp/tst capstone bug fixup、分支分类 |
| `tests/test_index.py` | reg_defs/reg_uses、def_chain、use_chain、mem_writes |
| `tests/test_memshadow.py` | 内存 shadow 写/读捕获、??占位、字符串提取 |
| `tests/test_cfg.py` | 线性/分支/循环 CFG 重建、执行计数 |
| `tests/test_taint.py` | 正向/反向污点、cmp 链、去重 |
| `tests/test_real_trace.py` | 真实 doCommand_70102 trace 端到端 sanity check |

**新功能 = 新测试**：每加一个 viewer/tracer 功能必须配套 testcase，避免回归。

### 借鉴 Triton 测试集
未来可以把 [Triton/src/testers](https://github.com/JonathanSalwan/Triton/tree/master/src/testers) 里的：
- `test_taint_engine.py`
- `test_register.py`
- `test_memory.py`

转换为我们的 trace 格式后跑，自动获得几百个测试用例。
