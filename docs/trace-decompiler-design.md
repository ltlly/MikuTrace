# 设计: traceMiku trace decompiler (路线 B — LLM-friendly skeleton IR)

> 配套研究: [`docs/trace-decompiler-research.md`](trace-decompiler-research.md).
> 本文档只写设计, 不重述调研结论. 所有约束引用 research.md §7.

## 0. 一句话定位

机器把 trace 折叠 / 类型推导 / 反 OLLVM, 输出**紧凑结构化 IR**;
反编译这一步交给 Claude / DeepSeek-R1 / Qwen-Coder 等大模型. 不写传统 codegen.

## 1. 目标 / 非目标

### 目标
1. 任意 trace (per-call 目录) → 函数级 IR 包, 可直接喂 LLM 出伪代码
2. 单次 LLM 请求 token 预算 ≤ 50K (Claude / Gemini context rot 200K 后掉)
3. 复用 viewer/ 已有 cfg/calltree/taint/memshadow/decompiler 全部能力, 不重写
4. CLI + Python SDK + REST 三件套, 复用现有 `viewer/` API 风格
5. 对外兼容 Tenet trace 文本格式 (调研里事实标准)
6. 多模型可切 (Claude / DeepSeek-R1 / Qwen-Coder), 标准 benchmark 接 Decompile-Eval / BinMetric

### 非目标 (调研明确排除)
- 传统 19-stage 反编译器 (tiny-dec / SLaDe 路线) — LLM 直接吃 IR 即可
- SMT / symbolic execution — Triton/SATURN 真机 hardened 上 timeout
- emit binary (BinRec / Tigress_protection 路线)
- full-system trace (PANDA 路线)
- 把全 trace 灌给 LLM (3.8M records 灌不进, context rot)
- 自己写 ARM64 lifter — remill 拆出来即可 (大概率不需要, BN HLIL 就够)

## 2. 顶层架构

```
[trace.bin]        [BN/Ghidra .bndb]      [tools/hooks/*.jsonl]
     │                    │                       │
     ▼                    ▼                       ▼
 viewer.load    decompiler.factory          jni_events
     │           (existing static prior)         │
     ├─→ CFG (existing cfg.py)                   │
     ├─→ CallTree (existing calltree.py)         │
     ├─→ Taint/DataChase (existing taint.py)     │
     ├─→ MemShadow (existing memshadow.py)       │
     ├─→ Index (existing index.py)               │
     ▼                                           ▼
 ┌─────────────────────────────────────────────────┐
 │  decompiler.builder.build_trace_ir()  ← NEW    │
 │    + decompiler.loop_fold              ← NEW    │
 │    + decompiler.type_anchor (JNI / API sinks)   │
 └─────────────────────────────────────────────────┘
                         │
                         ▼
                  TraceIR (NEW dataclass)
                         │
            ┌────────────┼────────────┐
            ▼            ▼            ▼
       render.toon  render.yaml  render.tenet
            │            │            │
            ▼            ▼            ▼
       LLM bundle    LLM bundle   IDA Tenet
       (Claude /     (DeepSeek)
        Qwen)
            │
            ▼
   [LLM 反编译] ← user's Claude Code or our optional --call-llm
            │
            ▼
       benchmark/ (Decompile-Eval / 自建 trace-metric)
```

## 3. 核心: TraceIR schema

设计三层视图. LLM 默认看 summary, 需要细节用 tool-use 拉.

### 3.1 顶层 (summary, ~2-5KB)

```yaml
trace:
  records: 4675
  truncated: false
  last_insn_is_ret: true
  module: { name: libsgmainso.so, base: 0x6d52ed1000, size: 0x180000 }
  cmd: 70102
fns:
  - { id: F0, name: sub_57770,  range: [0x57770, 0x57c00], blocks: 12, ic: 1,  oc: 3, hot: false }
  - { id: F1, name: sub_60000,  range: [0x60000, 0x60440], blocks: 8,  ic: 3,  oc: 1, hot: true  }
loops:
  - { id: L0, fn: F1, header_block: B5, iters: 256, induction: x19 }
hot_path:
  - F0 → F1 (256x) → F2
ollvm:
  flatten_score: 0.84   # ollvmdet 输出
  vm_score: 0.12
jni_events: 14
```

字段说明:
- `id` 全局稳定 (`F0`, `B7`, `L0`) — LLM 可反复引用, 是 markdown 锚点
- `ic`/`oc` = inbound/outbound call count
- `hot: true` 当 fn 占 trace > 20% 指令
- `range` 是函数 PC 范围, 不是 trace idx 范围

### 3.2 函数级 (full, ~5-30KB per fn)

```yaml
fn:
  id: F1
  name: sub_60000
  range: [0x60000, 0x60440]
  static:
    bn_signature: "void sub_60000(JNIEnv *env, jobject obj, jbyte *buf, int len)"
    bn_hlil_excerpt: |
      void sub_60000(env, obj, buf, len) {
        int32_t v1 = (*env)->GetByteArrayElements(env, buf, 0);
        ...
      }
    inferred_types: { x0: "JNIEnv*", x1: "jobject", x2: "jbyte*", x3: "int" }
  trace:
    entry_idx: 234
    exit_idx: 1820
    exec_count: 1
    truncated: false
  blocks:
    - id: B5
      pc: 0x60040
      insns: 12
      exec_count: 256
      exits:
        - { dst: B6, kind: cond, taken: 256, not_taken: 0, condition: "x0 != 0" }
      asm_first_exec: |
        ldr x0, [x19, #0x10]
        cbz x0, 0x60100
        ...
      samples:
        x19_in:  0x7fab9c1080
        x0_out:  [0x12345678, 0x12345679, ...]   # first 3 only
    - id: B6
      pc: 0x60080
      ref: B5      # ← 重复块去重: 同一个静态 PC 出现 N 次, 只首次完整 asm
      exec_count: 256
  loops:
    - id: L0
      header: B5
      body: [B5, B6, B7]
      backedge: B7 → B5
      iters: 256
      induction_var: { reg: x19, init: 0x100, delta: 8, exit_cond: "x19 == buf+len" }
      effect_summary: |
        Loop iterates 256 times, each iteration loads 8 bytes from x19,
        XORs with key in x20, stores back to x19. Looks like AES round.
  calls:
    - { idx: 412, fn: F2, name: sub_60500, ret: 0x0 }
    - { idx: 480, fn: F3, name: sub_60800, ret: 0x12345678 }
  jni_anchors:
    - { idx: 421, api: GetByteArrayElements, args: [env, buf, 0], block: B7 }
  data_anchors:
    - { kind: string, idx: 250, addr: 0x7f12340000, value: "ALI_SGMAIN_KEY_2025" }
    - { kind: const,  idx: 280, value: 0x67452301 }   # SHA-1 init H0
  detected:
    - { kind: hash_finalize, scheme: SHA1, at_idx: 1500 }   # hashfin.py 输出
```

字段语义关键点:
- **`ref` 字段实现块去重**: 同一静态块在循环里执行 N 次, 第二次起只标 `ref` + `exec_count`, 不重复 asm
- **`samples`** 给关键 reg 的 first/last 实例值 — LLM 推断类型用得着, 节省 token (不夸张地说, 一个 reg 给 3 个样本就够 LLM 判断 "这是 mem ptr 还是 int")
- **`loops.effect_summary`** 是机器尝试 (基于 induction var + samples 的一句话总结), 让 LLM 跳过 256 次展开
- **`detected`** 来自 `hashfin.py` / `ollvmdet.py` / `crypto-scan` — 已有的检测器结果直接复用
- **`jni_anchors`** 来自 `tools/hooks/*.jsonl`, 是强类型注入点 (research.md §2.5 — REWARDS/Howard 思想)

### 3.3 Block 详情 (raw, ~1-5KB per block) — 按需

```yaml
block:
  id: B7
  fn: F1
  pc: 0x60100
  exec_count: 256
  insns:
    - idx: 412
      pc: 0x60100
      asm: "ldr x0, [x8, #0x80]"
      field: { struct: pthread_mutex_t, field: __lock, offset: 0x80 }   # ← memshadow + BN
      pre:  { x8: 0x7fab9c1080 }
      post: { x0: 0x0 }
    - idx: 413
      pc: 0x60104
      asm: "bl sub_60500"
      branch: { taken: F2, ret_val: 0x0 }
    ...
```

只有 LLM 真正需要 byte 级才返回这个. 默认不放 prompt.

## 4. 分层文件树 (磁盘落地)

trace 目录下生成一个 sibling 子目录:

```
traces/run1/calls/call_002_*/
├── trace.bin                      # 已有
├── meta.json                      # 已有
└── decompile/                     # ← NEW
    ├── trace_ir.toon              # full TraceIR, TOON 格式 (LLM 默认源)
    ├── trace_ir.yaml              # 同上 YAML 版 (人类可读)
    ├── summary.md                 # §3.1 markdown 渲染, ~3KB
    ├── fns/
    │   ├── F0.md                  # §3.2 markdown
    │   ├── F1.md
    │   └── ...
    ├── blocks/
    │   ├── B7.md                  # §3.3 按需展开
    │   └── ...
    ├── trace.tenet                # Tenet 兼容文本 (IDA Tenet plugin 可读)
    └── llm_results/
        ├── claude_F1.md           # LLM 反编译输出 (`--call-llm` 时落)
        └── deepseek_F1.md
```

`summary.md` + `fns/F<id>.md` 是 LLM 主输入. raw blocks 按需 tool-use.

## 5. 模块边界 (复用 vs 新写)

### 复用 (零改动)
- `viewer/trace.py`, `cfg.py`, `calltree.py`, `taint.py`, `memshadow.py`,
  `index.py`, `symbols.py`, `disasm.py`, `display.py`, `hashfin.py`,
  `ollvmdet.py`, `decompiler/backend.py`, `decompiler/backends/binja.py`
- `webui/server.py` 已有 30+ REST endpoint 复用

### 新增模块

```
viewer/decompiler/
├── ir.py             # NEW   ~200 LOC. TraceIR/FuncIR/BlockIR/LoopIR dataclass
├── builder.py        # NEW   ~400 LOC. Trace + 所有 viewer/ 分析器 → TraceIR
├── loop_fold.py      # NEW   ~250 LOC. RLE / suffix-array 风格循环折叠 +
│                            #         induction var detect (Larus/Ball-Larus)
├── type_anchor.py    # NEW   ~150 LOC. JNI hook + libc API sink → reg-type 注入
├── render/
│   ├── __init__.py
│   ├── toon.py       # NEW   ~200 LOC. TOON 紧凑序列化
│   ├── yaml.py       # NEW   ~100 LOC. ruamel.yaml flow-style 紧凑
│   ├── markdown.py   # NEW   ~250 LOC. summary.md / F<id>.md
│   └── tenet.py      # NEW   ~150 LOC. Tenet 文本格式
├── llm_bundle.py     # NEW   ~150 LOC. 一个 fn 拼成 prompt-ready bundle
├── llm_client.py     # NEW   ~200 LOC. Anthropic / DeepSeek / Qwen 三家 adapter
└── benchmark/
    ├── __init__.py
    ├── decompile_eval.py  # NEW  ~150 LOC. LLM4Decompile re-exec metric wrapper
    ├── trace_metrics.py   # NEW  ~200 LOC. branch-classify / loop-detect 自评
    └── runner.py          # NEW  ~150 LOC. CLI: `tracemiku dec-bench`

viewer/__main__.py    # 改   ~150 LOC. 加 dec / dec-bench 子命令
webui/server.py       # 改   ~200 LOC. 加 §6 REST endpoints
webui/schemas.py      # 改   ~150 LOC. 加 pydantic models
examples/llm_cookbook.py  # 改   ~100 LOC. 加 example 11/12
tests/test_decompile_*.py # 新   ~500 LOC. 单元 + 集成
```

总计 ~3300 LOC. 1.5–2 周一个人.

## 6. REST / SDK / CLI 接口

### REST (FastAPI, 加在 webui/server.py)

```
GET  /api/dec/summary                          → trace summary IR
GET  /api/dec/fn/{fn_id}?level=summary|full    → §3.2 函数 IR
GET  /api/dec/block/{block_id}?level=full|raw  → §3.3 block 详情
GET  /api/dec/llm-bundle/{fn_id}?model=claude  → prompt-ready text + meta
POST /api/dec/llm-explain                      → server-side LLM call (opt-in)
       body: { fn_id, model, api_key_env }
       → { c_pseudocode, model, latency_ms, prompt_tokens, output_tokens }
GET  /api/dec/eval/{fn_id}?metric=re-exec      → benchmark score (lab targets)
GET  /api/dec/tenet                            → Tenet 兼容下载
```

### Python SDK (加 viewer/__init__.py 暴露)

```python
from viewer import load, build_trace_ir, render_toon
from viewer.decompiler import LlmBundle, decompile_via_llm

t = load("traces/run1/calls/call_002_*")
ir = build_trace_ir(t)                       # cfg + calltree + taint + memshadow + bn
print(ir.summary())                          # one-line per fn
fn_ir = ir.fn("F1")
bundle = LlmBundle(fn_ir, model="claude-sonnet-4-6")
print(bundle.prompt())                        # what we'd send

# Optional one-call:
result = decompile_via_llm(fn_ir, model="claude-sonnet-4-6")
print(result.c_code)
```

### CLI (加 tracemiku 子命令)

```bash
# 生成 IR (落 decompile/ 子目录)
./tracemiku dec traces/run1/calls/call_002_*

# 单函数 prompt (stdout)
./tracemiku dec traces/run1/calls/call_002_* --fn F1

# 调 LLM (需 ANTHROPIC_API_KEY)
./tracemiku dec traces/run1/calls/call_002_* --fn F1 --call-llm claude

# benchmark (clean OLLVM lab target, 调研 §9)
./tracemiku dec-bench tests/fixtures/lab_ollvm/ --metric re-exec --model claude

# Tenet 导出
./tracemiku dec traces/run1/calls/call_002_* --tenet > /tmp/x.tenet
```

## 7. 关键算法决策

### 7.1 循环折叠 (loop_fold.py)

输入: trace pc 序列 + cfg blocks.
两步:

1. **块序列 RLE**: 按静态 block id 把 trace 编成 `[B0, B1, B5, B6, B7, B5, B6, B7, ...]` (跨 N 次执行). 在 backedge 上检测周期性: 每次回到 header block 是一次迭代. 这一步 O(n).
2. **induction var 检测**: 每次迭代结束在 backedge 处 dump 关键 reg 值, 跑 numpy linear regression 看哪些 reg 是等差/等比. 覆盖 99% 真实代码, 异常情况 (非线性) 标 `induction: complex` 让 LLM 自己看 samples.

源参考: research.md §2.2 (HotpathVM + Larus PLDI 1999 思想). 不抄代码, 算法直接复刻.

### 7.2 类型推导锚点 (type_anchor.py)

API sink 列表 (硬编码 + 可扩展 jsonl):
- JNI: `FindClass(env, name) → x0=JNIEnv*, x1=const char*` 
- libc: `pthread_mutex_lock(m) → x0=pthread_mutex_t*`
- libssl: `EVP_aes_128_ecb() → ret=EVP_CIPHER*`

实现: 看到 `bl <addr>` 且 `<addr>` 在 hook json 里, 把那一刻 reg 类型注入. 然后用现有 `viewer/taint.py` backward-propagate.

源参考: REWARDS NDSS 2010 (research.md §2.5).

### 7.3 块去重 (toon render)

同一静态 PC block 出现 N 次, IR 只渲染第一次完整 asm + samples, 后续 `ref: B5 + exec_count` 即可.
LLM 看到 ref 自己反查. 节省 80%+ token (cold-path 主要消耗在循环上).

### 7.4 token 预算 strategy

| 场景 | 大小 | 策略 |
|---|---|---|
| trace summary | 2–5KB | 必含 |
| 当前关注 fn | 5–30KB | 必含 |
| 调用链上其他 fn | 1–3KB each | summary level 即可 |
| block raw | 1–5KB each | tool-use 按需 |
| 全 fn raw | 大 | 永远不放 prompt |

Claude Sonnet 4 一次请求目标 < 50K tokens.
DeepSeek-R1 64K context, 目标 < 30K.

### 7.5 多模型 adapter (llm_client.py)

```python
class LlmModel(Protocol):
    def call(prompt: str, system: str = "") -> LlmResult: ...

class ClaudeModel(LlmModel):  # anthropic SDK
class DeepSeekModel(LlmModel): # openai-compatible API
class QwenModel(LlmModel):     # 同上 / 本地 vLLM
```

env: `ANTHROPIC_API_KEY` / `DEEPSEEK_API_KEY` / `QWEN_BASE_URL`.

调研锁定模型 (research.md §5.2):
- 默认: **Claude Sonnet 4.6** (1M context, 综合最强)
- ARM 反混淆专项: **DeepSeek-R1** (Deconstructing Obfuscation 实测 ARM 72.31% semantic score)
- 本地无网: **Qwen-Coder** 14B/32B 跑 vLLM

## 8. Benchmark harness

调研锁定 4 个 (research.md §9):
- **Decompile-Eval** (LLM4Decompile, re-executability) — 干净 lab 二进制
- **BinMetric** IJCAI 2025 — 6 任务覆盖
- **Decompile-Bench** ACL 2025 — million-scale 函数对
- **CREBench** arXiv 2604.03750 — 加密二进制专项

自建 baseline:
```
tests/fixtures/decompile/
├── lab_clean_ollvm/        # 自己用 OLLVM 编一个 demo SO + trace
├── libsgmainso_70102_4675/ # fail-path (你已有)
└── libsgmainso_70102_2M/   # cold-path (你已有)
```

自建 metric (`trace_metrics.py`):
- **branch_classify_acc**: LLM 输出的伪代码里, taken/not-taken 标注与 trace ground truth 一致率
- **loop_iters_exact**: LLM 推断的循环次数与 trace 真实迭代数误差
- **call_resolved**: 间接跳转目标 LLM 是否正确写出
- **type_anchor_consistency**: JNI handle 类型 LLM 输出与 hook 实测是否一致

这 4 个 metric 都是 trace 直接给真值, 自动化打分, 不依赖编译.

## 9. 改动清单 (按 ship 阶段)

### Stage 0 — 骨架 + IR (1 周)
1. `ir.py` dataclass + 基础 builder (no loop fold, no type anchor)
2. `render/toon.py` + `render/markdown.py`
3. `tracemiku dec` CLI 可生成 `decompile/` 子目录
4. `tests/test_decompile_ir.py` 跑通 fail-path 4675 records 输出 IR
5. PoC: 手 copy fail-path 的 F0.md 到 Claude Code, 看伪代码出得来不

### Stage 1 — LLM 集成 (3-4 天)
6. `llm_client.py` + Claude / DeepSeek adapter
7. `llm_bundle.py` 拼 prompt
8. `tracemiku dec --call-llm` 一键
9. `webui/server.py` 加 `/api/dec/*` endpoints
10. `examples/llm_cookbook.py` 加 example

### Stage 2 — 折叠 + 类型 (1 周)
11. `loop_fold.py` + induction var detect
12. `type_anchor.py` + JNI / libc sink
13. cold-path 2M records 端到端验证 (token 预算)
14. `render/yaml.py` + `render/tenet.py`

### Stage 3 — Benchmark (3-4 天)
15. `benchmark/trace_metrics.py` 自建 4 个 metric
16. `benchmark/decompile_eval.py` 接 LLM4Decompile
17. `tracemiku dec-bench` 全跑通
18. README / TODO 同步, 出对比表

每 stage 一次 commit, 不允许半路 commit. Stage 间 `pytest tests/` 必须全绿.

## 10. 验证方法

每 stage 必跑:

```bash
# stage 0
./tracemiku dec traces/qunar_drifts_js/calls/_truncated_call_015_*
ls traces/qunar_drifts_js/calls/_truncated_call_015_*/decompile/
cat .../decompile/summary.md         # 看人类是否能读懂

# stage 1
ANTHROPIC_API_KEY=... ./tracemiku dec ... --fn F0 --call-llm claude
diff -u .../decompile/llm_results/claude_F0.md  reference/expected_F0.md

# stage 2
./tracemiku dec traces/doCommand_70102_coldpath/  # 2M records
wc -c .../decompile/fns/F1.md   # 单 fn 必须 < 60KB

# stage 3
./tracemiku dec-bench tests/fixtures/lab_clean_ollvm/ --model claude
# 输出: branch_acc, loop_acc, call_acc, type_acc 4 个分数
```

## 11. 已知约束 / 不做的事

- **不并发调 LLM**: rate limit 难管, 顺序跑就行
- **不缓存 LLM 输出**: 每次都重跑, hash 进文件名 (model + prompt_hash)
- **不做 prompt 调优自动化**: prompt 写在 `llm_bundle.py` 里, 改了重跑即可
- **不支持 OpenAI / GPT-5**: 调研里 ARM 表现没 DeepSeek-R1 强 (Deconstructing Obfuscation 2025), 不值得集成
- **不做 GUI 触发**: web SPA 加一个 "decompile this fn" 按钮即可, 不做交互式 LLM 对话
- **不做 cross-call IR**: 每个 per-call trace 独立 build, viewer/ 已经是 per-call 模型, 跟着走
- **不做 trace merge**: research.md 里 BinRec 那条路有趣, 但本期不做. 后续若需要单独提
- **不发表论文**: research.md §10 提了有学术价值, 但 ROI 低, 工程优先

## 12. 风险 / 不确定项

| 风险 | 影响 | 缓解 |
|---|---|---|
| cold-path 2M records 的 token 预算炸 | stage 2 ship 不了 | 先做循环折叠, 不行就把 fn 切片 (subfn 粒度) |
| LLM 输出语义错但读起来流畅 | benchmark 抓不到 | trace_metrics 4 个机器 metric 兜底 |
| BN 静态 prior 在 hardened SO 上分析失败 | 类型注入断 | 容许 `static: null`, 全靠 trace 锚点 |
| DeepSeek/Qwen API 不稳 | 多模型不可用 | Claude 必跑, 其余 best-effort |
| anti-debug 改过的字节进 IR 误导 | LLM 推错语义 | trace_ir 里标 `tainted_by_anti_debug: true`, 不做静默 |

## 13. 跟 TODO.md 的关系

新加 TODO 项 (放 P2):
- P2-DEC1: stage 0 骨架 + IR
- P2-DEC2: stage 1 LLM 集成
- P2-DEC3: stage 2 折叠 + 类型
- P2-DEC4: stage 3 benchmark
- P2-DEC5: docs/CODE_REVIEW 同步

每条 ship 后从 TODO 删, 跟现有规则一致.

## 14. 当前状态 (开新会话需知)

- 工作目录: `/home/ltlly/Code/traceMiku`
- 研究纪要 commit: `fc7dcd0`
- 设计文档 commit: 本 commit
- 下一步: 起 P2-DEC1, 先在 worktree 里做 (避免污染 main)
- 已有 trace fixture (Stage 0 需要):
  - `traces/qunar_drifts_js/calls/_truncated_call_015_tid0_2970r_?ms` (短)
  - `traces/doCommand_70102_coldpath/` (2M records, Stage 2 需要)
- BN 数据库: `examples/libsgmainso/libsgmainso-6.8.260403.so.bndb` (Stage 0 静态 prior 需要)
- LLM keys (env): 你机器上 `ANTHROPIC_API_KEY` 已有, DeepSeek 需配
