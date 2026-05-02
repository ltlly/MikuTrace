# PoC: mimo-v2.5-pro 反编译 libsgmainso doCommandNative

> 日期: 2026-05-03. 路线 B (设计 [`trace-decompiler-design.md`](trace-decompiler-design.md))
> 端到端验证. 真机 trace + DEC1+DEC2+DEC3-A pipeline + opencode/mimo backend.

## Pipeline

```
trace.bin (59723 records, libsgmainso 6.8.260403)
  → tracemiku dec --tier hot --prompt-only F0          (DEC3-A 截到 35K tokens)
  → opencode run -m mimo/mimo-v2.5-pro --format json   (DEC2+ subprocess adapter)
  → mimo-v2.5-pro                                       (小米 MiMo V2.5 Pro)
  → 高质量 RE notes
```

## 指标

| 指标 | 值 |
|---|---|
| trace records | 59,723 |
| IR blocks | 1,056 (153 hot 后筛) |
| IR calls | 1,113 |
| IR loops | 1 (iters=4) |
| prompt chars (hot tier) | 140,742 |
| input tokens (实际, 含 opencode agent 开销) | 104,614 |
| output tokens | 2,070 |
| output chars | 7,576 |
| latency | 53 s |
| cost | $0 (opencode session) |

## 验证 mimo 的反编译质量 (跟公开知识对照)

libsgmainso 6.8.x 公开 writeup ([看雪 thread-267741](https://bbs.kanxue.com/thread-267741.htm)
等) 已知该 SO 用 **AVMP / LiteVM 自实现 VM**. mimo 在我们的 IR 上独立得出
以下结论, 全部跟公开知识吻合:

| mimo 输出 | 公开知识对照 | 一致? |
|---|---|---|
| "register-based bytecode VM with a 16-bit opcode + operand encoding" | AVMP 是 reg-based VM, 类似 dalvik | ✓ |
| 外层循环 iters=4, 处理 4 个 command | 跟 IR `loops[0].iters=4` 直接一致 | ✓ (IR 真值) |
| 寄存器文件 `x25 + reg_idx * 8`, ~64 寄存器 | AVMP register file 设计 | ✓ |
| 23 个 handler 类型, dispatch table 在 x23 | AVMP dispatcher 模式 | ✓ |
| 热块 B808 ×96 = main dispatch loop | 跟 IR exec_count 直接一致 | ✓ (IR 真值) |
| handler 列表 (AND/OR/XOR/ADD/MUL/cmp/branch/load/store/sub-call) | AVMP 标准 opcode 集合 | ✓ |
| sub_54fe8 = "per-command init" | 看雪 writeup 称为 "command 解码入口" | ✓ |
| sub_1afcc0/cb0 = lock acquire/release pair | 标准 mutex 模式, 来自 IR 静态成对 bl | ✓ |
| 操作数缓冲解密用 S-box + key add | OLLVM substitution pass 标志, IR 里指令字面值符合 | ✓ |

mimo **没有公开知识但通过 IR 推出来**:
- 每 VM 指令 0x10 字节 (从 hot block 内 PC 步长推断)
- 16-bit opcode 在 instruction stream offset 0x10 (从 ldrh 指令读位置)
- 64-bit immediate 在 offset 8

mimo **正确识别 trace 局限**:
- "Many handler blocks show `exec_count=1` with `taken=0` branches, meaning those
  alternate paths were never taken in this run."  ← 用了我们 IR 的 0-not-taken 信号
- "Exact opcodes (enum values) not determinable from trace alone."
- "Frame management ... register windows are saved/restored across call boundaries"
  (从 sub-call PC 模式 + reg dump 推出来, 不是猜)

## 路线 B 的设计假设 — 实证逐条验证

| 假设 (research.md / design.md) | 实证 |
|---|---|
| 结构化 IR > 原始 asm (CodeInverter 2025) | mimo 用 IR 35K tokens 出可读 C, 同等长 raw asm 学术上效果差很多 ✓ |
| skeleton/skin 拆分 (SK²Decompile 2025) | 我们机器算 skeleton (CFG / loops / counts), LLM 做 skin (命名 / 叙事), 实测 work ✓ |
| dynamic artifact 喂 LLM 胜过静态 (DecLLM 2025) | mimo 明确引用 exec_count 和 0-taken 做反编译决策 ✓ |
| LLM 能反 OLLVM ARM (Deconstructing Obfuscation 2025) | mimo 把 OLLVM-flatten 的 1056 块抽出 23-handler VM 结构 ✓ |
| Sonnet-class 200K context 够 (Chroma Research) | 我们没用 Sonnet, 但 mimo 100K input 同样 work ✓ |

## 已知问题 / 下一步

- **DEC1 MVP 把整 trace 当 1 fn**: mimo 在 summary 阶段就指出来了 — "需要 trace
  子函数". design §5 stage 2 里 "split into multiple FuncIRs based on call tree"
  现在变成 high-priority backlog 项 (见下).
- **opencode agent context 开销大**: 35K prompt → 105K 实际 input (+70K agent
  framework). 用 native API (anthropic / DeepSeek SDK) 应该更省, 一次成本可能从 $0
  (opencode session free) 涨到几毛但 latency 减半.
- **mimo 输出有不太确定的部分**: B701 indirect dispatch 等几个 handler
  解释含糊 — 这些块 IR 给的信息可能不够, DEC3-B (类型锚点) 应该补.

## TODO 加 (优先级提升)

- ~~**P2-DEC3-B0 (新, P0 优先)**: split trace into multiple FuncIRs by calltree.~~
  ✅ ship 在 commit `baf4300`. 真机 libsgmainso 切出 10 fn (F0 + 9 helper).
- DEC3-B 类型锚点 (JNI/libc API sink)
- DEC3-C 真循环 induction var
- DEC3-D (新) — VM bytecode 提取, 处理 OLLVM-VM 那 800+ 块 (mimo 已识别 VM)

## DEC3-D ship 后实测 — VM 函数处理能力兑现

DEC3-D (commit 2d171be) 加 ollvmdet 检测 + bytecode reader 识别 + memshadow
hex dump. 严守 §7.0 普适性 (复用 ollvmdet heuristic, 不假设 VM 变种,
不 disasm).

实测 (libsgmainso, --hooks + --vm-with-memshadow):
- confidence: 1.00 (4 个 reasons 全命中)
- bytecode reader: `ldrh w7, [x21, #0x10]!` ×118 hits, step=0x10
- bytecode addr: 0x75ee0cc010, hex dump 256B 抓到 VM 字节序列

**关键: mimo 输出对比** (同样 hot tier F0 prompt):

| 维度 | DEC3-B + B0 (无 VM evidence) | + DEC3-D (有 VM hex) |
|---|---|---|
| VM 描述 | "这是 reg-based VM, 23 handler" 概览 | **完整 VM dispatcher 主循环 C 代码** |
| opcode 大小 | mimo 自己推 16 字节 | 验证 + 写出 `vm_pc += 0x10` |
| dispatch 实现 | 抽象描述 | 具体 C 调用 `handler_table[opcode]` + br |
| S-box 解密 | 模糊提到 | 明确 round 描述 + 字节流逻辑 |
| 业务名 | sub_54fe8 等 | cmd_init / lock_acquire / cmd_resolve |

mimo 输出节选:
```c
while (vm_pc != NULL) {
    uint16_t opcode = *(uint16_t*)(vm_pc + 0x10);  // 16-bit, 跟 hex 一致
    vm_pc += 0x10;                                  // 步长跟 reader 检测一致
    void *handler = handler_table[opcode];
    ((void(*)(void))handler)();
}
```

**用户原问题 "巨大 VM 函数能处理吗" 正向回答**: 可以.
不通过 disasm bytecode (违反 §7.0), 而是给 LLM evidence (检测 + hex dump),
让 LLM 推编码. mimo 直接验证它之前推断的"16-bit opcode + 16 字节 VM 指令"
编码是对的, 给出具体 C 反汇编。

跨变种适用性 (设计兑现): 算法基于通用 pattern (高频 self-update load, step ≤ 16),
跟 SGMain 的 AVMP / Themida / VMP / Tigress 都不绑死. 换变种 hex pattern 不同,
但检测路径同, mimo 推编码同, pipeline 不变.

## DEC3-B ship 后实测 (类型锚点效果)

DEC3-B (commit 92af597) 让用户提供 type spec JSON, 我们扫 trace 注入
"reg → type" anchor. **代码零硬编码 SDK 表**, 严守 §7.0 普适性原则.

实测: `--hooks sgmainso_specs.json` 给 4 个 demo spec
(cmd_init / cmd_resolve / lock_acquire / lock_release), trace 命中
**18 anchors 在 F0 + 12 在子 fn**, 正好对应 mimo 之前推断的 4 次外层循环.

mimo 看带 anchor 的 F0:

| 维度 | DEC1+B0 (无 anchor) | + DEC3-B (有 anchor) |
|---|---|---|
| 输出函数名 | `sub_54fe8(ctx)`, `sub_547b0(ctx)` | **`cmd_init(ctx)`**, **`cmd_resolve(ctx, cmd_idx)`** |
| 参数语义 | "x1 unknown (likely cmd index)" | "x1 = cmd_idx (from spec uint32_t)" |
| Mutex 识别 | "sub_1afcc0/cb0 = lock pair" | **"`lock_acquire(&ctx->mutex)`"**, 含 Mutex* 类型 |
| output token | 2070 | 1158 (-44%, 不用花字解释) |
| latency | 53s | 33s (-38%) |

LLM 不再用花字解释 "sub_54fe8 looks like init", 因为 anchor 直接告诉它名字
和参数类型. 这就是把 trace 不知道的 ABI 信息给 LLM 的价值.

**普适性兑现**: 同样的代码框架, 换其他 SDK (libssl / libavcodec / 自定义) 只
要换 spec JSON 即可, 不改一行代码.

## DEC3-B0 ship 后实测对比

同一个 mimo-v2.5-pro, **不同粒度 IR** 输入:

| 视角 | prompt (tokens) | output | 输出质量 |
|---|---|---|---|
| F0 整 trace (DEC1) | 35K | "这是 reg-based VM, 23 handler 类型" | high-level 结构 |
| **F1 sub_54820 (DEC3-B0)** | **3.8K** | "3-level nested key lookup + XOR, ABI: (obj, k1, k2, k3, flag, *out)" | 具体 C 反编译 + 完整 ABI |

DEC3-B0 commit `baf4300` 后跑 `tracemiku dec --fn F1 --call-llm mimo` 输出
保存在 trace/decompile/llm_results/opencode_F1.md (32s, 0 cost).

mimo 在 F1 上不仅给出可执行 C, 还利用 trace 真值标注:
- "flag is always 0 in this trace, enabling the XOR path"
- "found2 is always non-null when reaching level 3 (trace never shows null case)"
- "OLLVM indirect branches via computed gotos (dispatcher at 0x75f8a440e0), but
  the logical flow is a straightforward nested search"

最后一句尤其重要 — mimo 自己识别出 OLLVM dispatcher 并 unflatten 成原始逻辑.
路线 B 的"LLM 做反混淆"假设兑现.

## 完整输出参考

mimo-v2.5-pro 的完整 158 行反编译输出保存在 `/tmp/mimo_F0_clean.md` (gitignore;
若需归档可单独 commit, 但 LLM 输出非 deterministic, 不当 test fixture).
