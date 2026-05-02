# Trace Decompiler IL Pipeline 设计 (路线 B v2)

> 配套 [`trace-decompiler-design.md`](trace-decompiler-design.md) §7.0 普适性原则.
> 用户反馈触发的方向调整: 把 LLM 退到可选层, 加真正的 IL 多级 pipeline.
> 调研基础: [`trace-decompiler-research.md`](trace-decompiler-research.md).

## 0. 为什么 v2

v1 (DEC1-DEC4) 的"TraceIR"实际是 dataclass 容器 + 启发式标注, 不是 IL.
传统反编译器 (BN/Ghidra/IDA) 都是 multi-pass IL pipeline:

| 工具 | IL 层 |
|---|---|
| BN | LLIL → MLIL → HLIL (各级 SSA) |
| Ghidra | PCode (low + high), 多 pass |
| IDA | microcode (mb..mc 多级) |

我们之前没有任何 IL 变换 pass. 直接 dataclass → markdown → LLM, 把语义识别
全推给 LLM. 这违背 §7.0 "机器做 evidence, LLM 做语义" 原则的"机器"那一半 —
**机器只做了组织, 没做分析**.

## 1. 真机实测瓶颈 (15.4M records / 4GB trace)

```
load (mmap)               0.0s
build_cfg (numpy bitmask) 6.0s   blocks=3228 edges=7800
build_from_trace (sym)    5.3s
build_call_tree           12.8s  87 frames (OLLVM br 替代 ret, 配对率 0.0006%)
build_trace_ir            待测   预期超 60s
```

观察:
- **calltree 12.8s 但只配对 87 frame** — OLLVM trace 上 Python per-record decode
  开销主导, 且产出极少. 必须 numpy 化或抛弃 (用 cfg-based 子 fn 切分代替).
- **cfg 6s on numpy 路径** — 可接受, 但 build_cfg 还有 Python state machine
  for call_stack 的 pass 2, 是 cold-path 主要开销.
- **memshadow 没测** — 之前 60K trace 上 ~30s, 15M 上估值 ~12 分钟, 必须 lazy /
  增量化, 不能默认全建.

## 2. 路线 B v2 — IL 多级 pipeline

### 2.1 三层 IL 设计 (借鉴 BN, 简化适配 trace)

```
ARM64 raw inst (raw, per-record, 14M+)
        │
        │  pass 1: lift  (capstone + 自写 ARM64→TLIL semantics)
        ▼
TLIL (low IL, ~3K static templates × N exec_count)
  e.g. STORE [sp + 0x10], x0
       LOAD  x1, [x0 + 0x8]
       ADD   x2 := x1 + 0x10
       BR.eq target=0x...
        │
        │  pass 2: SSA (linear trace 极简, version by trace position)
        ▼
TLIL_SSA
  x0_v3 = x1_v2 + 0x10
        │
        │  pass 3: const_fold + dce
        ▼
TLIL_clean
  (常量折叠, 死代码 / 跳板消除)
        │
        │  pass 4: type_lattice  (bottom-up 推 int / ptr / handle)
        ▼
TMLIL (medium IL, expr tree)
  result = (uint64_t*)(x19_ptr + 0x40) + cmd_idx
        │
        │  pass 5: struct_recovery (memshadow + offset 聚类)
        ▼
TMLIL_typed
  result = ctx->commands[cmd_idx]
        │
        │  pass 6: control flow restructure (loop / if / switch)
        ▼
THLIL (high IL — 接近 C)
  for (i = 0; i < 4; i++) {
    if (cmd_resolve(ctx, i) == 0) {
      ...
    }
  }
        │
        ├─→ render markdown (默认输出, 给人 / IDE 看)
        ├─→ render Tenet (兼容 IDA Tenet plugin)
        └─→ optional: LLM bundle (用户主动按 "AI 解读" 才调)
```

### 2.2 跟 v1 关系

**保留** v1:
- `viewer/cfg.py` / `calltree.py` / `memshadow.py` / `ollvmdet.py` — 真分析模块
- `viewer/decompiler/{ir, builder, render}.py` 接口层 — render 仍是 final layer
- §7.0 普适性原则
- LLM adapter (DEC2) — 退化为可选叙事层

**新增** v2:
```
viewer/decompiler/il/
├── ops.py             # IL operation enum (ADD/SUB/LOAD/STORE/CALL/BR/...)
├── tlil.py            # TLIL node dataclass + TraceIL container
├── lift.py            # ARM64 (capstone) → TLIL, 跟 trace 关联 (per-record idx)
├── ssa.py             # SSA construction (linear-trace simplified)
├── pass_constfold.py
├── pass_dce.py
├── pass_typelat.py    # type lattice (int / ptr / handle / unknown)
├── pass_struct.py     # struct field 提升 (memshadow + offset cluster)
├── restructure.py     # loop / if / switch IL
├── render_md.py       # IL → markdown (替换当前 render_func_md asm 段)
└── tests/
```

### 2.3 不做什么 (避免 scope creep)

- 不写完整 ARM64 lifter (复用 capstone disasm + 我们写~50 个 op semantics 即可)
- 不做 SMT (路线 B v1 也排除)
- 不做 emit binary
- 不做完整 control flow restructuring (Cooper-Ferrante 完整算法太重,
  先做 dominance-based loop / if 检测, 复杂结构降级输出 goto)

## 3. 数据规模设计

### 3.1 静态骨架 + 动态计数 (核心原则, 跟 Larus 1999 一致)

15M records / 3228 静态块. 一个块平均 ~5 instructions, 即 ~16K 静态 instruction.
TLIL node count ≈ **16K**, 不是 14M. 这是稀疏静态骨架.

每个 TLIL node 挂 dynamic counters:
- exec_count
- 输入 reg 的 first/min/max/last 实测值 (4 个 sample, 不是全部)
- 输出 reg 的 same

数据规模: 16K nodes × ~200B/node = **3MB IR**. 可塞 RAM.

### 3.2 lift 性能预算

15M records × ~5μs/record (capstone decode + lift) = 75s. **不能默认全 lift**.

策略:
- **静态 lift**: 一个 PC 只 lift 一次 (16K static PCs → 0.08s). 这个永远做.
- **动态注解**: numpy bitmask 标 PC 命中位置 (16K × N hits, ~50MB). 不存值.
- **样本值**: 对 hot PC (top 100), 走 trace 抓 first/min/max/last reg 值. ~10s.

### 3.3 IR 复用 v1 dataclass

v1 BlockIR.asm 字符串 → 改 `tlil_ops: list[TlilOp]`. v1 渲染层把 tlil_ops 转
asm 字符串 (backward compat). 新渲染层用 IL 直接 emit C-like 代码.

## 4. 8-pass 实施顺序

| pass | LOC | 依赖 | 增量价值 |
|---|---|---|---|
| 1. lift (ARM64→TLIL) | ~600 | capstone | **基础**, 后面所有 pass 依赖 |
| 2. SSA | ~150 | lift | 让后续 pass 容易写 |
| 3. constfold | ~100 | SSA | 立即看到效果: `mov x0,#1; add x0,x0,#2 → x0=3` |
| 4. dce | ~120 | SSA | 删 prologue 寄存器保存, 删 OLLVM 跳板 |
| 5. typelat | ~250 | SSA + JNI hooks | reg 类型推导, 比 LLM 强 |
| 6. struct | ~250 | typelat + memshadow | 把 `[x8+0x80]` 变 `mutex.__lock` |
| 7. restructure | ~400 | cfg + SSA | 真把 loop 变 `for`, if 变 `if` (而不是 goto) |
| 8. render | ~200 | restructure | C-like 输出 (markdown 包) |

总: ~2070 LOC. 1.5-2 周.

## 5. 优先级 (ROI 排序)

**immediate (做了立即看到反编译质量飞跃)**:
- pass 1 lift — 没它什么都做不了
- pass 3 constfold — 大量 OLLVM 混淆代码立即变干净
- pass 4 dce — prologue/epilogue 自动消失

**high (传统反编译器核心)**:
- pass 2 SSA — 让 3/4 写起来简单
- pass 6 struct — 用户最常需要的"`[x+offset]` 是啥"

**medium (加分项)**:
- pass 5 typelat — 跟现有 type_anchor 互补
- pass 7 restructure — 没它就是带 goto 的 SSA 输出, 但 LLM 能补

**low (deferred)**:
- pass 8 dedicated render — render 沿用现有 markdown.py 渲染 IL list 即可

建议 ship 顺序: **lift → constfold → dce → SSA → struct → restructure → typelat → render**.
每个 pass 单独 commit, 每个 pass 后跑真机 trace 看输出质量进步.

## 6. AI 退到可选层

UI 改:
- "Build IR" 按钮 → 真做 8-pass IL pipeline (慢, 但每次按只跑一次, 缓存)
- "AI 解读" 单独按钮 (默认禁用) → 拿 IL 输出再喂 LLM 出叙事
- 默认输出: IL → C-like markdown (机器算法直接出, 0 token)
- AI 是奖励, 不是必需

token cache 仍保留 (DEC4), 但默认每次 "Build IR" 只跑机器, 不调 LLM.

## 7. 普适性自查 (§7.0 PR review checklist 套到 IL)

- [ ] 不 hardcode 任何 SO 名 / opcode 编码 / fn 偏移
  - lift.py 的 ARM64 op 表是 ARM64 ISA, 不是任何特定 SO
- [ ] 没"只支持 X" 限定
  - typelat 算法用 lattice, 不绑 JNI; 用户 spec JSON 加任意 sink
- [ ] 用户可扩展
  - struct recovery 阈值 / typelat 顶层类型表 都配置化
- [ ] 不替 LLM/用户做语义决定
  - IL 输出有 confidence; restructure 失败降级 goto, 不强行套结构
- [ ] 反例 case docstring 标
  - 每个 pass 都列已知失败模式 (e.g. constfold 不处理 vector op)

## 8. 风险

| 风险 | 影响 | 缓解 |
|---|---|---|
| ARM64 ISA 太大写不完 lift | 卡 pass 1 | 只 lift 实际命中的 ~50 个 op (top 95% trace 覆盖率), 剩下走 unknown_op 占位 |
| restructure 算法在 OLLVM 上失败 | pass 7 输出乱 | 失败降级 goto, 不强行 |
| 性能 — 全 trace 8 pass 超 5 分钟 | 用户等不及 | 静态骨架 lift, 动态计数 numpy. 第一次慢 (建 cache), 后续 ms 级 |
| LLM 退到可选, 用户不爱 | 已有 UI 期望 | 默认仍显示 "AI 解读" 按钮但不自动点 |

## 9. 跟 v1 commit 的关系

v1 14 commits **全部保留**, 不 revert. v2 在 v1 上 **加层**:
- v1 builder.py 改成 `_build_legacy_ir()` (向后兼容, CLI 选项可切)
- 新 `_build_il_ir()` 是 v2 的入口
- 默认走 v2 (用户期望传统 RE 体验)
- `tracemiku dec --legacy` 走 v1 (markdown + LLM, 适合短 trace + AI 助手)

## 10. 下一步 ship 计划

完成 build_trace_ir on 15M trace 实测 → 写 §1 数据 → 进 pass 1 lift.

每 pass 1 commit, 每 commit 跑 4GB trace 测时间 + 输出质量. ROI 不达
预期的 pass 推后或砍.
