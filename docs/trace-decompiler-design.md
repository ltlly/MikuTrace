# Trace Decompiler Design — Three-Layer IL Architecture

> 配套研究：[`docs/trace-decompiler-research.md`](trace-decompiler-research.md)。
> 本文档描述当前 Rust/Solid analysis v2 的三层 IL 反编译器实现。
> 旧 Python `viewer/decompiler/` 设计已归档。

## Architecture Overview

traceMiku 的反编译器有四条边界清晰的路线，其中三条不使用 LLM：

| Route | Purpose | Backend | LLM Required |
|---|---|---|---|
| **Three-Layer IL Pipeline** | LLIL→MLIL→HLIL lowering, C-like pseudocode | `tracemiku-core::{llil,mlil,hlil}` | No |
| **TraceIR** | 结构化函数/块/循环/调用 IR, 供人或 LLM 阅读 | `tracemiku-core::decompiler` + `/api/dec/*` | Optional |
| **Binary Ninja Sidecar** | 静态 HLIL/Pseudo C/CFG 参考 | `TRACEMIKU_BN_SO` + `bn_sidecar.rs` | No |
| **Trace-Enhanced Decompiler** | 三层 IL + 运行时 trace 值 (寄存器、内存、执行计数) | `decompiler::il_pipeline` | No |

## Three-Layer IL Architecture (参考 Binary Ninja)

三层 IL 设计直接参考 Binary Ninja 的 LLIL/MLIL/HLIL 架构：

```
         ARM64 Instructions
                │
                ▼
    ┌──────────────────────┐
    │  LLIL (Low-Level IL) │  ← 寄存器型, 一对一映射 ARM64
    │  llil::lift_arm64()  │    NZCV 标志模型
    │  llil::ssa_block()   │    块内 SSA 变换
    │  llil::pass_flag_*() │    标志消除 (NZCV → 直接比较)
    │  llil::pass_phi()    │    φ 节点 & 跨块 SSA
    └──────────┬───────────┘
               │ llil→mlil lowering
               ▼
    ┌──────────────────────┐
    │  MLIL (Medium-Level) │  ← 变量型 (SetVar/Var)
    │  mlil::lower_llil()  │    无标志操作
    │  mlil::expr::MlilOp  │    LoadStruct/StoreStruct
    │  mlil::render_*()    │    变量命名统一
    └──────────┬───────────┘
               │ mlil→hlil lowering
               ▼
    ┌──────────────────────┐
    │  HLIL (High-Level)   │  ← 结构化控制流
    │  hlil::lower_mlil()  │    If/While/DoWhile
    │  hlil::expr::HlilOp  │    VarDeclare/VarInit
    │  hlil::render::*()   │    Deref 替代 Load
    └──────────────────────┘
               │
               ▼
         C-like Pseudocode
```

### LLIL — Low-Level IL (寄存器型)

ARM64 指令一对一翻译为 LLIL 表达式树。每个指令产生 1-N 个 LLIL 节点。

**核心表达类型** (`llil::expr::LlilOp`):
- `SetReg`, `Reg` — 寄存器读写
- `SetFlag`, `Flag`, `FlagCond` — NZCV 标志模型
- `Load`, `Store` — 内存访问
- `Goto`, `Jump`, `If`, `Call`, `Tailcall`, `Ret` — 控制流
- `Add/Sub/Mul/And/Or/Xor/Lsl/Lsr/Asr/...` — 算术
- `Csel`, `Sx`, `Zx`, `LowPart` — 选择/扩展
- `Intrinsic` — 未识别指令

**Pass 管线**:
1. `ssa_block()` — 块内 SSA 变换 (x0 → x0#1, x0#2)
2. `flag_elim_block()` — NZCV 标志消除, FlagCond → 直接比较
3. `constfold_block()` — 常量折叠
4. `dce_block()` — 死代码消除
5. `typelat_block()` — 类型格推导 (Ptr/Int/Unknown)
6. `unify_vars()` — 变量命名 (x0#0 → arg_0, x19#0 → cs_x19)
7. `struct_recover_block()` — 结构体形状恢复
8. `restructure_cfg()` — CFG 重组 (if/else, while/do-while 检测)

**LLIL 覆盖率**: 支持 ~95% 常见 ARM64 指令 (mov, add, sub, mul, and/or/xor, lsl/lsr/asr, ldr/str, adr/adrp, b/bl/blr/ret, cmp, csel, sxtb/sxth/sxtw, madd/msub, extr 等)。

### MLIL — Medium-Level IL (变量型)

LLIL 转换为变量型、无标志的中间表示。

**关键变换** (`mlil::lower::lower_llil_to_mlil`):
- `SetReg(x0#1, val)` → `SetVar(arg_0, val)`
- `Reg(x0#1)` → `Var(arg_0)`
- `SetFlag(z, ...)` → 被消除 (已由 flag_elim 折叠)
- `Load(Add(base, 0x10))` → `LoadStruct(base, offset=0x10)` (结构体检测)
- `Store(Add(base, 0x8), val)` → `StoreStruct(base, offset=0x8, val)`

**新增表达类型** (`mlil::expr::MlilOp`):
- `SetVar/Var/SetVarField/VarField` — 变量访问
- `LoadStruct/StoreStruct` — 结构体字段访问
- `AddressOf/AddressOfField` — 取地址

**结构体访问检测**: `detect_base_offset()` 自动识别 `Add(base, const)` 模式，转换为结构体访问。仅接受非负小偏移量，大偏移量或负向偏移视为指针算术。

### HLIL — High-Level IL (结构化控制流)

MLIL 转换为结构化、类 C 的高层表示。

**关键变换** (`hlil::lower::lower_mlil_to_hlil`):
- `SetVar(v, val)` → `Assign(Var(v), val)`
- `Load(addr)` → `Deref(addr)` — 内存加载 → 解引用
- `LoadStruct(base, off)` → `DerefField(base, off)` — 结构体字段解引用
- `Store(addr, val)` → `Assign(Deref(addr), val)` — 内存存储 → 赋值给解引用
- `StoreStruct(base, off, val)` → `Assign(DerefField(base, off), val)`
- `If(cond, t, f)` → `If(cond, then_body, else_body)` — 结构化条件

**新增表达类型** (`hlil::expr::HlilOp`):
- `Block/If/While/DoWhile/For` — 结构化控制流
- `VarDeclare/VarInit` — 变量声明和初始化
- `Deref/DerefField` — 解引用 (替代 Load)
- `Assign` — 赋值 (替代 SetVar)
- `StructField/ArrayIndex` — 结构体/数组访问
- `Break/Continue` — 循环控制
- `Label/Goto` — 非结构化回退

**HLIL 渲染器**: 生成带缩进的类 C 输出，支持块作用域、while/if-else 嵌套。

```c
int64_t result = 0;
int64_t i = 0;
while ((i < 0xa)) {
    result = (result + i);
    i = (i + 1);
}
return;
```

### 全流水线入口

```rust
// 静态反编译 (无 trace 数据)
let output = decompiler::il_pipeline::decompile_static(&[(pc, inst), ...]);

// Trace 增强反编译 (带运行时值)
let output = decompiler::il_pipeline::decompile_trace(
    &insns, &trace_contexts, "function_name",
);
```

输出结构 `TraceDecompileOutput` 包含:
- `llil_ssa_text`, `mlil_text`, `hlil_text` — 三层文本输出
- `llil_coverage` — LLIL 覆盖率 (非 Intrinsic 比例)
- `trace_contexts` — 每条指令的运行时值 (寄存器前后值、执行次数)
- `mlil_lower_stats`, `hlil_lower_stats` — 各层 lowering 统计

## Performance Benchmarks

在真实 trace 上的实测结果:

### Test Setup

- **Trace 1**: `boundary_stat_launch2` — 8.88M records, 21,962 unique PCs, 2.42 GB, 816 函数段
- **Trace 2**: `multiso_real` — 7.88M records, 13,679 unique PCs, 2.14 GB, 567 函数段
- **Hardware**: x86_64 Linux, release build

### Performance (per function)

| Metric | trace 1 (8.8M records) | trace 2 (7.8M records) |
|---|---|---|
| Trace read + PC dedup | 2.35s | 2.49s |
| Avg decompile time/fn (200-600 insn) | 3-6ms | 2-4ms |
| Avg time per instruction (all 3 layers) | 8.24 µs | 9.23 µs |
| Largest function (1,943 insns) | 19.6ms | — |
| Largest function (586 insns) | — | 6.9ms |

### Coverage (LLIL lifter)

| Trace | Best | Worst | Median |
|---|---|---|---|
| trace 1 | 98.2% | 35.8% | ~88-95% |
| trace 2 | 98.2% | 93.2% | ~94-98% |

### Layer Expansion Ratio

| Transformation | Ratio | Explanation |
|---|---|---|
| ARM64→LLIL | ~1.2:1 | 每指令平均 1.2 个 LLIL 节点 (带标志) |
| LLIL→MLIL | 0.8-0.9:1 | 标志消除和合并压缩 |
| MLIL→HLIL | 0.9-1.0:1 | 结构变换保持近似大小 |
| **ARM64→HLIL** | **~0.95:1** | 端到端近似 1:1 |

## Trace Integration Advantages

traceMiku 反编译器相比传统静态反编译器的独特优势:

### 1. 实际执行路径

Trace 数据提供**真实执行过的**指令，静态反编译器必须猜测可达性。间接跳转/调用在 trace 中是**确定性的**。

### 2. 运行时值注入

每层都可以注入 `TraceContext`:
- **寄存器值**: 解析间接调用目标 (`br x8` → 已知的 0x7000 处函数)
- **内存值**: 解析指针链 (`ldr x0, [x0, #0x20]` → 实际值)
- **执行计数**: 标注热/冷路径，识别循环体

### 3. 反混淆

- OLLVM 扁平化 CFG 在 trace 中**自然展开**
- 死代码自动排除 (未执行)
- 虚调用解析为具体调用

### 4. JNI 类型推导

JNI hooks 提供 Java 侧类型信息，可从 `GetStringUTFChars`/`FindClass` 等调用反向推导 native 函数参数类型。

## Data Flow

```text
trace.bin + meta.json
  └─ tracemiku-core Trace / Index / CFG / MemShadow / Taint / CallTree
       ├─ il_pipeline.rs (LLIL→MLIL→HLIL, trace-enhanced)
       │    └─ Pseudo C tab (no LLM)
       ├─ TraceIR builder
       │    └─ /api/dec/summary, /api/dec/fn/{id} (LLM-optional)
       ├─ in-house LLIL renderer
       │    └─ LLIL SSA tab
       └─ BN sidecar, optional
            └─ /api/hlil-for-pc, /api/bn-cfg-svg-for-pc
```

所有重 CPU 路由必须移出 async runtime，并有响应上限或截断字段。前端需要把
`truncated`、`hidden_edges`、`stopped_at_max` 等状态显示给用户，不能把部分结果伪装成
完整分析。

## TraceIR Contract (LLM-friendly route)

摘要层默认小而稳定：

```yaml
trace:
  records: 2066291
  truncated: false
fns:
  - { id: F0, name: sub_547b0, blocks: 12, entry_idx: 84, exit_idx: 510 }
loops:
  - { id: L0, fn: F0, header_block: B4, iters: 256 }
hot_path:
  - F0
anchors:
  - { kind: string, idx: 421, addr: 0x740fd72f80, len: 113 }
```

函数层按需展开：

```yaml
fn:
  id: F0
  name: sub_547b0
  trace: { entry_idx: 84, exit_idx: 510, exec_count: 1 }
  blocks:
    - id: B0
      pc: 0x75f63067b0
      exec_count: 1
      exits:
        - { dst: B1, kind: cond, taken: 1, not_taken: 0 }
      asm:
        - { idx: 84, asm: "sub sp, sp, #0x30" }
  calls:
    - { idx: 120, name: sub_54fe8, ret_idx: 180 }
```

稳定 ID 比展示顺序更重要。前端和外部脚本应使用 `idx`、`pc`、`fn id` 做定位，不解析 UI
文本。

## BN Sidecar Behavior

BN sidecar 是可选静态后端：

```bash
TRACEMIKU_BN_SO=/path/to/libtarget.so ./tracemiku web <call_dir> --port 18900
```

当当前 trace PC 没有 BN 函数覆盖时，sidecar 可以创建 user function 并立即重试 HLIL /
Pseudo C / CFG 请求。前端要显示 created/timeout/error 状态，避免用户误以为 trace 里没有
函数。

## Frontend Interaction Contracts

- `g` 跳转支持 `#240` / `240` 到 trace index，`0x1234` 到该 PC 第一次出现的位置。
- Functions tab 单击选择函数并切 CFG 到手动模式；双击跳到该函数入口第一次执行。
- CFG sync 开启时跟随当前 trace 函数；手动选函数会暂停 sync。
- CFG Ctrl+滚轮以鼠标指针位置为锚点缩放。
- 大函数 CFG 可以显示 overview，并明确展示已绘制/隐藏 edge 数。
- HLIL 与 Pseudo C 都需要缩进和统一代码字体。

## Decompile Eval Tool

```bash
# Run on any call directory
cargo run --example decompile_trace --release -- \
  traces/<dataset>/calls/<call_dir> \
  --max-fns 20 --min-records 30

# Output: per-function coverage, layer counts, timing, and HLIL samples
```

## Test Gates

```bash
cd rust
cargo test --workspace                              # 244 tests (as of 2026-05-13)
cargo run --example decompile_trace --release -- <call_dir>
npm --prefix frontend run build
uv run python scripts/frontend_event_smoke.py http://127.0.0.1:18900
```

涉及 BN 的改动还要用 `TRACEMIKU_BN_SO` 跑一遍 HLIL/Pseudo C/CFG 请求。涉及 LLM 的改动
不能影响默认 UI 启动和非 LLM decompiler 路径。

## Source Layout

```text
rust/crates/tracemiku-core/src/
  llil/                             Low-Level IL
    expr.rs                         LlilOp enum (58 ops), LlilExpr tree
    lift.rs                         ARM64 → LLIL lifter (~600 lines, ~50 mnemonics)
    ssa.rs                          块内 SSA 变换
    pass_flag_elim.rs               NZCV 标志折叠
    pass_constfold.rs               常量折叠
    pass_dce.rs                     死代码消除
    pass_typelat.rs                 类型格推导
    pass_var_unify.rs               变量统一命名 (VarNameMap)
    pass_struct.rs                  结构体形状恢复
    pass_restructure.rs             CFG 重组 (if/else, while/do-while)
    pass_phi.rs                     φ 节点生成
    pass_uidf.rs                    用户信息值收集
    render.rs                       C-like 渲染
    util.rs                         辅助函数

  mlil/                             Medium-Level IL
    expr.rs                         MlilOp enum (62 ops), MlilExpr tree
    lower.rs                        LLIL → MLIL lowering (结构体检测, 标志消除)
    render.rs                       MLIL C-like 渲染
    mod.rs

  hlil/                             High-Level IL
    expr.rs                         HlilOp enum (63 ops), HlilExpr tree
    lower.rs                        MLIL → HLIL lowering (Deref, Assign, 结构化)
    render.rs                       HLIL C-like 渲染 (缩进, 块作用域)
    mod.rs

  decompiler/
    il_pipeline.rs                  全流水线 + trace 增强 (decompile_trace/static)
    ir.rs                           TraceIR 数据类型
    builder.rs                      TraceIR 构建
    backend.rs                      后端 trait
    ...
```
