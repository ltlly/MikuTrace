# Trace 反编译器研究纪要 (路线 B 选定)

> 调研日期: 2026-05-02. 4 路并行 agent (学术 / 开源 / 工业 / LLM-RE) 交叉印证.
> 决策结论: **走路线 B — "trace → LLM-friendly skeleton IR 生成器"**, 不写传统 19-stage 反编译器.
> 后续设计文档: `docs/trace-decompiler-design.md` (待写).

## 0. 问题陈述

traceMiku Stage-1 已能产出 ARM64 真机指令级 trace (272B/record × 数百万). 现想为该 trace 流加反编译能力 — 输入 `(pc, x0..x30, sp, raw_inst)*`, 输出"这次执行"的高级伪代码. 这跟 IDA/BN/Ghidra/tiny-dec 的静态反编译器是不同物种 (静态消除不确定性, trace 反编译消除冗余 + 保留时间索引).

调研问题: 这个东西**有人做过吗? 应该怎么做?**

## 1. 工作总览 (一图看完)

```
[trace capture] → [trace browse] → [IR lift] → [简化/反混淆] → [structuring] → [pseudocode] → [命名/叙事]
   Frinet/Tenet     Frinet/REVEN    BinRec/PANDA   Syntia/Tigress    static  ←————   static (BN/Ghidra/SLaDe/LLM4Decompile)
   QBDI/Stalker     timeless dbg    .llvm_trace    Triton/d810       only           
   ↑ traceMiku 在这                 ↑ 半死, x86    ↑ 各家不串         ↑ Chisel 2024 唯一靠近
```

**没有任何论文 / 任何开源工具把 6 段全串起来**. 学术最近的是 Chisel (OOPSLA 2024), 工业最接近的是 Frinet (Synacktiv 2024) + D810 (eShard) + Syntia/msynth (Blazytko) 的拼合 — 但**没人拼**. 这是真空地带.

## 2. 学术现状 (8 个方向逐项)

### 2.1 Trace-based decompilation (concrete trace → C)
**结论: 学术圈无 canonical 工作**. 工业工具 (REVEN, QIRA, Tenet, Frinet, TTD) 占领但**没有同行评议论文**. VMHunt (CCS 2018) 和 Pushan (arXiv 2603.18355, 2026) 都是 trace 当种子 + symbolic 主体, 不是 pure trace.

### 2.2 Trace folding / loop summarization
**结论: 经典工作奠基, 没有 trace decompile 化**.
- **Whole Program Paths** — Larus PLDI 1999 — SEQUITUR 压缩全 trace 成 DAG. **直接照抄思想**.
- **Efficient Path Profiling** — Ball & Larus MICRO 1996 — 静态骨架 + 动态边计数. **就是你 cfg.py 的祖宗**.
- **HotpathVM** (VEE 2006) + PyPy tracing JIT (PPPJ 2012) — trace-tree compilation, fold backedge, hoist invariant. **工程上最贴近你"循环展开 → for"的那一步**.

### 2.3 Dynamic deobfuscation (trace-centric)
**结论: 4 篇必读, 大多 hybrid 不是 pure trace**.
- **Coogan-Lu-Debray** "Deobfuscation of Virtualization-Obfuscated Software" CCS 2011 — 等式推理 + trace dataflow. VMP/Themida 实测.
- **Yadegari et al.** "A Generic Approach to Automatic Deobfuscation" S&P 2015 — taint + symbolic + trace simplification, 该领域 canonical.
- **Syntia** — Blazytko USENIX Sec 2017 — MCTS 程序合成, **纯黑盒在 trace I/O window 上跑**. VMP 算术 handler 94%+.
- **Chisel** — Mariano et al. OOPSLA 2024 — trace 提示驱动 CFG 合成 + block-body 程序合成. **跟你设计最贴近的单篇**.

### 2.4 Trace 工具 (BinRec / S2E / Frinet)
- **BinRec** (EuroSys 2020) — 多 trace → LLVM IR → recompile, x86 only, 已半死. **架构最近**.
- **What You Trace is What You Get** (ASPLOS 2024) — BinRec 的 stack recovery 续作.
- **S2E** (ASPLOS 2011) — 名字像但其实是 selective symbolic, 跟 trace decompile 关系小.
- Frinet/Tenet/REVEN/QIRA/TTD — 工业, **无 paper**.

### 2.5 类型推导 (trace 路线)
- **REWARDS** (NDSS 2010) + **Howard** (NDSS 2011) — 从 syscall/lib API sink 反推. **思想直接抄, JNI handle 推导就是这个 pattern**.
- **Type Inference on Executables** — Caballero & Lin, ACM CSUR 2016 (survey).

### 2.6 间接跳转 / VM-flatten CFG 重建
- **Practical Dynamic Reconstruction of CFG** — Rimsa SP&E 2020. 纯 trace, **直接可用**.
- **CaDeCFF** Internetware 2022 — flatten compiler-agnostic.
- **SoK: Automatic Deobfuscation of Virtualization-protected Applications** — Schrittwieser ARES 2021. **VM 反混淆最佳综述**.

### 2.7 Trace IR (sparse static + dynamic count)
**学术上还没有人把 Ball-Larus 路径计数推广成 decompile 用的 IR**. 你的设计在这块**有发表价值**.

### 2.8 Replay-based RE
**学术工业断层**. PANDA (PPREW 2015) + rr (USENIX ATC 2017) 是仅有的 peer-reviewed 系统设计论文. REVEN/QIRA/TTD 全无 paper.

## 3. 开源生态 (按可用性排序)

### 直接可用 (拿来就跑)
- **Syntia** (RUB-SysSec, USENIX 17 paper repo) — MCTS 合成 OLLVM/VMP handler. https://github.com/RUB-SysSec/syntia
- **msynth** (mrphrazer, 2022) — Syntia 的工程化 MBA-only 版. https://github.com/mrphrazer/msynth
- **remill** (lifting-bits, 1.7k★) — ARM64 → LLVM 完整 semantics 库, **可抠 lifter**. https://github.com/lifting-bits/remill
- **Tenet trace 格式** (gaasedelen/tenet) — 文本 `pc,reg=val,mem=val`, 强烈建议输出兼容. https://github.com/gaasedelen/tenet

### 借鉴算法 (代码不直接复用)
- **D810 / D810-ng** (eShard, IDA HexRays plugin) — OLLVM CFG flatten 反混淆的 state-var tracking 算法. 绑 HexRays 不能直接用.
- **Tigress_protection** (JonathanSalwan, 895★) — Triton + LLVM 完整 OLLVM pipeline, 但它输出 binary 不是 C.
- **MODeflattener / ollvm-unflattener** (各 200+★) — Miasm-based, x86 only, flatten 检测启发式可移植.
- **PANDA llvm_trace plugin** (panda-re, 2.7k★) — multi-trace merge into LLVM IR.
- **Triton** (4.2k★) — AST 简化算法 (Z3 / Bitwuzla) 可借鉴.

### 仅参考思路 (不打算复用)
- **Frinet** (Synacktiv, 587★) — 你已有, 只到 trace 浏览, 无 IR/decomp.
- **BinRec** (trailofbits, 149★) — multi-trace merge 算法值得读.
- **miasm** (3.9k★) — IRDst expr tree 设计.
- **Ghidra 11.3 P-Code JIT + TraceRMI** (2025) — emulator IR 与 decompiler IR 同源, 重路径但唯一现成.

### LLM-RE 工具 (全部不吃 trace)
- **LLM4Decompile** (6.6k★) — x86_64 only, asm → C, baseline 必读. https://github.com/albertan017/LLM4Decompile
- **DeGPT** (NDSS 2024) — 后处理优化 Ghidra HLIL.
- **GhidrAssist / GhidraMCP / r2ai / BinAssist** — 全静态.
- **没有任何项目把指令级 trace 喂 LLM** ← 真空.

## 4. 工业 writeups 关键点

### 4.1 真机大 trace 的规模天花板 (公开吐槽)
- **Tenet 作者 ret2 blog 2021**: > 10M 指令"不保证可用" — 直到换原生后端.
- **Quarkslab 2019** "Exploring Execution Trace Analysis": "dumping a trace can rapidly become impractical for very large programs". Symbolic 也救不了.
- **Frida #1337 / #1343**: Stalker crash / leak 是公开痛点.

→ **你 3.8M records 已在临界, 规模设计第一天就要绑死**.

### 4.2 真机 hardened SO 现状
- **看雪 thread-267741 / 273614 / 277665** — libsgmain (5.4/6.5) / libDexHelper (梆梆) 公开 writeup, 全是手工 + unidbg 离线模拟. **没人在真机上做完整 trace decompile**.
- **CYRUS-STUDIO/frida_stalker** + CSDN 2024 — 中文社区低配版: Stalker 抓流 + 人肉对照 IDA 删 dead block. 你正在做的事的 baseline.
- **Quarkslab/Synacktiv/eShard** 都有完整组件, **没人把它们端到端串起来**.

### 4.3 工业为什么不做完整 trace decompile
- 客户付钱要 **key/算法**, 不要可读伪代码 → hook + dump 就够
- 大 trace 规模没解
- 反 anti-debug 在真机不稳

→ **你打 "真机 + 强 OLLVM + 大 trace" 三重组合, 正好踩在所有现成工具失效的交集**. 工业差异化是真实的.

## 5. LLM 时代的转向 (这是路线 B 决策的核心)

四路里 LLM agent 的发现最颠覆传统设计.

### 5.1 实证证据 (4 篇 2025 论文)
- **CodeInverter** (arXiv 2503.07215) — CFG + 数据表 enriched prompt → 6.7B 干翻 100× 大模型. **结构化 IR >> 原始 asm**.
- **SK²Decompile** (arXiv 2509.22114) — skeleton (机器精确) + skin (LLM 命名) **双阶段胜过端到端**. 比 GPT-5-mini 高 21.6%.
- **DecLLM** (ISSTA 2025) — ASAN error / 测试用例当 oracle 喂 LLM, 70% 修复 Ghidra 输出. **dynamic artifact 喂 LLM 显著有效**.
- **"Do Code Semantics Help?"** (EMNLP 2025 Findings) — execution trace 喂 code-LLM 显著帮助代码理解.

### 5.2 LLM 在反混淆上的实测
- **"Deconstructing Obfuscation"** (arXiv 2505.19887) — 8 个商业 LLM 跑 OLLVM, **DeepSeek-R1 在 ARM 上 semantic score 72.31%, 跨架构最稳**.
- **"Can LLMs Recover Program Semantics"** (arXiv 2511.19130) — KLEE SMT + path artifacts 喂 LLM, GPT-4.1-mini 反混淆最强.

### 5.3 上下文规模约束
- Sonnet 4 1M / Gemini 2.5 Pro 2M 看似够, 但 **Chroma Research 实测 200K+ context rot 显著**.
- Alan Sguigna 2025 实战 Intel PT × LLM: **100M 行 IPT → 压成 500M 喂 LLM**, 强调 token 经济性.

### 5.4 Token 经济
- **TOON / 紧凑 YAML** 替代 JSON 省 30–60% token.
- **重复 block 去重**: 只首次完整, 后续指针引用.

### 5.5 Benchmark
- **Decompile-Eval** (LLM4Decompile) — re-executability metric.
- **BinMetric** (IJCAI 2025) — 1000 题 6 任务.
- **Decompile-Bench** (ACL 2025) — million-scale.
- **CREBench** (arXiv 2604.03750) — 加密二进制 RE.

## 6. 路线决策: 为什么是 B

### 路 A: 传统 trace decompiler 本体
BN HLIL 上叠 trace overlay, 折叠死分支, 解析间接, 注入类型, 输出带 idx 的伪代码. **像 D810 + Frinet 合体**, 输出给人.

### 路 B: LLM-friendly trace IR 生成器 (选定)
机器只生成结构化 IR (TOON/紧凑 YAML), 反编译让 Claude/DeepSeek-R1 做. 提供 tool-use endpoint (类似 GhidraMCP 但吃 trace), LLM 主动检索.

### 选 B 的 4 个理由 (4 路调研都指向)
1. **traceMiku 已 60% 完成 IR 部分** (BN/Ghidra 后端 + memshadow + calltree + JNI hooks + taint + ollvmdet) — 差的不是反编译器功能, 是把这堆东西输出成 LLM 能消费的紧凑结构化 IR.
2. **2025 三篇论文 (CodeInverter / SK²Decompile / DecLLM) 集体证明** "结构化 IR 喂 LLM" 胜过传统端到端.
3. **真空市场**: 没有任何工具把指令级 trace 喂给 LLM. 第一个吃螃蟹.
4. **ROI 高**: 不用做 codegen / structuring 后端 — 那是 LLM 已经擅长的, 我们抢不过.

### 选 B 的代价
- 依赖外部 LLM (但你工作流已是 Claude Code, 这不是新增依赖)
- 输出质量受 LLM 能力波动影响 → **必须支持多模型 (Claude / DeepSeek-R1 / Qwen) 切换 + benchmark**
- 必须想清楚 token 预算 (3.8M records 不能直接灌, 必须分层 + 按需检索)

## 7. 设计约束 (从调研锁死的硬约束)

设计文档 (`docs/trace-decompiler-design.md`) 写之前必须遵守:

1. **IR = 稀疏静态骨架 + 动态计数注解** (Larus 1999 + Ball-Larus 1996). 不是 per-record 实例化. 你 cfg.py 的方向就是对的, 推广到全 IR.
2. **输出多层视图**: `summary.md` (函数列表) + `func_<idx>.md` (SSA + 计数 + 锚点) + `raw.jsonl` (按需展开). LLM tool-use 检索, 不是全灌.
3. **Token 预算**: 单次 LLM 请求目标 < 50K tokens, 用紧凑格式 (TOON/YAML) + 函数级粒度.
4. **稳定 ID**: 函数/block 用 `#F12`, `#B7` 这类稳定标识, markdown 锚点可点击.
5. **Tenet 格式兼容**: 主输出之外提供 `.tenet` 导出, 兼容 IDA Tenet plugin (调研里多次出现的事实标准).
6. **不做 SMT**: Triton/SATURN 走过, 真机 hardened 上 timeout, 不是这条路要做的.
7. **不做 emit binary**: BinRec / Tigress_protection 那条路不是目标.
8. **不做 full-system trace**: PANDA 路线过重, userland 单函数即可.
9. **多模型支持**: Claude Sonnet 4 / DeepSeek-R1 / Qwen-Coder 三选一可切, benchmark 有 BinMetric / Decompile-Eval.
10. **Dynamic anchor 必须显式**: 每个 BB 必标 hit count + 寄存器范围样本 + 参数实例 — 这是 LLM 拿不到我们白送的 killer feature.

## 8. 子算法去哪抄 (设计文档要逐个落)

| 子算法 | 抄哪里 | License |
|---|---|---|
| 路径计数 IR | Ball-Larus MICRO 1996 思想 | 算法 free |
| 循环折叠 | HotpathVM VEE 2006 + Larus PLDI 1999 思想 | 算法 free |
| OLLVM flatten state var 识别 | D810 (eshard, Apache-2.0) | Apache-2.0 |
| MBA / handler 还原 | msynth (mrphrazer) | Apache-2.0 |
| 间接跳转 CFG | Rimsa SP&E 2020 (trace 直接 resolve) | 算法 free |
| 类型推导 (JNI sink) | REWARDS / Howard 思想 | 算法 free |
| ARM64 lifter (若需要) | remill semantics 库 | Apache-2.0 |
| trace 文本格式 | Tenet 格式 | 兼容输出 |

## 9. Benchmark 计划

调研已锁定 4 个可用 benchmark, 设计阶段必须接:
- **Decompile-Eval** (LLM4Decompile 自带) — re-executability
- **BinMetric** (IJCAI 2025) — 6 任务覆盖
- **Decompile-Bench** (ACL 2025) — million-scale 函数对
- **CREBench** (arXiv 2604.03750) — 加密二进制专项

自建 baseline:
- libsgmainso 70102 cold-path (你已有 2M records trace)
- libsgmainso doCommandNative fail-path (4675 records)
- 一个 OLLVM 干净 demo (无 anti-debug) 做 sanity

## 10. Open Problems (做出来值一篇会议)

学术线明确点出 4 个空白:
1. **稀疏静态骨架 + 动态计数为主 artifact 的 IR** (Ball-Larus 系列只做 profiling, 没做 decompile)
2. **百万级 trace 的 loop-folding + indirect dispatcher 折叠**
3. **静态 prior + concrete trace evidence 融合的伪代码生成** (Chisel 最接近, 但不集成现成 BN/Ghidra)
4. **JNI handle / Java 侧类型从 native trace 反推** (REWARDS/Howard 没做 JNI)

发会议是 bonus, 不是动机.

## 11. 直接跑过对比的最近邻 repo (待做)

设计阶段进 repo 实测一遍, 写 BENCHMARKS.md:
1. **Frinet** — 你已有 trace, 喂 Frinet → Tenet plugin 看它能不能浏览
2. **D810-ng** — IDA 上跑 libsgmainso 看 unflatten 效果, 算法可移植度
3. **Syntia / msynth** — 拿一个 OLLVM block I/O 试合成
4. **LLM4Decompile** — ARM64 不支持但仍跑 baseline 看 GPT-4 vs 它

## 12. 关键 References (设计文档要全部引用)

### 学术
- Larus PLDI 1999 — https://www.cs.cmu.edu/afs/cs/academic/class/15745-f09/www/papers/p259-larus.pdf
- Ball-Larus MICRO 1996 — https://faculty.cc.gatech.edu/~harrold/6340/cs6340_fall2009/Readings/micro96.pdf
- Coogan-Lu-Debray CCS 2011 — https://www2.cs.arizona.edu/people/debray/Publications/ccs-unvirtualize.pdf
- Yadegari S&P 2015 — https://www2.cs.arizona.edu/~debray/Publications/generic-deobf.pdf
- Syntia USENIX Sec 2017 — https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-blazytko.pdf
- Chisel OOPSLA 2024 — https://www.cs.utexas.edu/~isil/chisel.pdf
- BinRec EuroSys 2020 — https://download.vusec.net/papers/binrec_eurosys20.pdf
- REWARDS NDSS 2010 / Howard NDSS 2011 — https://www.few.vu.nl/~herbertb/papers/howard_ndss11.pdf
- Rimsa SP&E 2020 — https://homepages.dcc.ufmg.br/~fernando/publications/papers/RimsaSPE20.pdf
- SoK Auto Deobf VM ARES 2021 — https://eprints.cs.univie.ac.at/7012/1/3465481.3465772.pdf
- LLM4Decompile EMNLP 2024 — https://arxiv.org/abs/2403.05286
- SLaDe CGO 2024 — https://arxiv.org/abs/2305.12520
- CodeInverter 2025 — https://arxiv.org/abs/2503.07215
- SK²Decompile 2025-09 — https://arxiv.org/abs/2509.22114
- DecLLM ISSTA 2025 — https://dl.acm.org/doi/10.1145/3728958
- Deconstructing Obfuscation 2025 — https://arxiv.org/pdf/2505.19887
- Do Code Semantics Help EMNLP 2025 — https://aclanthology.org/2025.findings-emnlp.548.pdf

### 工业 blog
- Quarkslab — Deobfuscation OLLVM (Romain Thomas 2017) — https://blog.quarkslab.com/deobfuscation-recovering-an-ollvm-protected-program.html
- Quarkslab — Slaying Dragons with QBDI — https://blog.quarkslab.com/slaying-dragons-with-qbdi.html
- Quarkslab — Exploring Execution Trace Analysis 2019 — https://blog.quarkslab.com/exploring-execution-trace-analysis.html
- eShard — D810 unflatten 2022 — https://www.eshard.com/blog/d810-a-journey-into-control-flow-unflattening
- Synacktiv — Frinet SSTIC 2024 — https://www.synacktiv.com/en/publications/frinet-reverse-engineering-made-easier
- ret2 — Tenet 2021 — https://blog.ret2.io/2021/04/20/tenet-trace-explorer/
- Romain Thomas BHAsia 2020 — https://www.romainthomas.fr/publication/20-bh-asia-dbi/asia-20-Thomas-Dynamic-Binary-Instrumentation-Techniques-to-Address-Native-Code-Obfuscation.pdf
- 看雪 libsgmain — https://bbs.kanxue.com/thread-267741.htm / https://bbs.kanxue.com/thread-273614.htm / https://bbs.kanxue.com/thread-277665.htm
- Tim Blazytko synthesis 系列 — https://synthesis.to/

### 关键开源 repo
- Frinet — https://github.com/synacktiv/frinet
- Tenet — https://github.com/gaasedelen/tenet
- D810 — https://gitlab.com/eshard/d810 / https://plugins.hex-rays.com/w00tzenheimer/d810-ng
- Syntia — https://github.com/RUB-SysSec/syntia
- msynth — https://github.com/mrphrazer/msynth
- Triton — https://github.com/JonathanSalwan/Triton
- Tigress_protection — https://github.com/JonathanSalwan/Tigress_protection
- BinRec — https://github.com/trailofbits/binrec-tob
- remill — https://github.com/lifting-bits/remill
- miasm — https://github.com/cea-sec/miasm
- LLM4Decompile — https://github.com/albertan017/LLM4Decompile
- CodeInverter — https://github.com/LiuPeiP-CS/CodeInverter

## 13. Current Status

The research constraints above informed the Rust/Solid analysis v2 decompiler
work. Current live design lives in
[`docs/trace-decompiler-design.md`](trace-decompiler-design.md).

Implementation direction:

1. Keep TraceIR / in-house LLIL / Binary Ninja sidecar as separate routes.
2. Keep LLM calls out of the default UI until latency and failure handling are
   predictable.
3. Treat response caps and visible truncation state as correctness requirements,
   not only performance polish.
