# traceMiku — 安卓真机 ARM64 指令级 trace 全栈工具

> **目标**: 抓任意 app 任意 SO 任意函数的真机 ARM64 指令级 trace, pwndbg 风格离线分析,
> Web/CLI/Python SDK 三件套对 LLM 友好。

## 项目布局

```
traceMiku/
├── tracemiku           # 顶层 CLI (trace/web/list/info/finalize)
├── tracemiku-view      # 旧入口 (deprecated, 见 TUI 章节)
├── tracer/             # Stage-1 在设备上采集 ARM64 指令级 trace
├── viewer/             # 离线分析 core 库 + CLI 子命令 + Python SDK
├── webui/              # 单页 Web SPA (主 UI) — FastAPI + vanilla JS
├── tools/              # 单文件 Frida 辅助脚本 + JSON hook 配置
│   ├── hooks/          # JSON-driven JNI hook specs (libart_jni.json 等)
│   ├── detect_suicide.js / patch_sgmainso_tgkill.js
│   ├── hide_rwx_maps.js / probe_deep_safe.js
│   └── regen_jni_offsets.py
├── examples/           # llm_cookbook.py + 已知 SO 偏移样例 (libsgmainso/)
├── tests/              # pytest 单元 + 集成测试 (30 文件 / 341 测试)
├── docs/               # 设计 + 排坑文档
├── TODO.md             # 唯一 backlog 入口
└── traces/             # 已采集 trace 输出 (gitignored)
```

**UI 方向**: Web 是主 UI; CLI/Python SDK/REST API 是 LLM 友好接口三件套;
TUI (`viewer/app.py`) **已冻结, 不再维护**。

## 一行安装

```bash
# 假设已有 root 安卓 + Florida frida-server 跑在 6699 端口
cd /home/ltlly/Code/traceMiku
python3 -m pip install --user fastapi 'pydantic>=2' uvicorn capstone frida numpy textual
chmod +x tracemiku tracemiku-view
```

### 推荐: patched frida-server (Android 14+ 必装)

stock frida 17.x 在 Pixel 7 / Android 16 + OLLVM 大库 (TB libsgmainso 等) trace
~4500 条后 SIGTRAP 杀进程, tombstone 报 `Unable to allocate code slab`. 仓库自带
patched 版本 + 一键安装:

```bash
# 推荐: stealth 版 (codeslab fallback + anti-detect 重命名 frida → miku)
./vendor/frida-patched/install-stealth.sh   # → /data/local/tmp/.miku-srv, forward 6699
```

详细成因和 patch 解释见 [`docs/frida-codeslab-patch.md`](docs/frida-codeslab-patch.md).
codeslab patch 把 TB 70102 cold-path trace 从 stock 的 1805 条 + SIGTRAP 提到
**3,858,484 条 + 进程零崩溃**.

stealth 版另外把 12 个 target-可见 frida 字符串 (`gum-js-loop` → `miku-js-loop`,
`re.frida.server` → `re.miku.server` 等) 改成 `miku` 主题, 躲常见 anti-frida
静态扫描. wire protocol 不动, host stock frida-tools 直接兼容.
详见 [`vendor/frida-patched/README.md`](vendor/frida-patched/README.md).

## 快速上手 (per-call)

每次目标函数调用 → 一个独立 trace 子目录, 目录名带 records/ms 一眼看出长短.
fail-path (~4675 条) 与 cold-path (~2M 条) 互不污染, 事后挑要分析的那次.

```bash
# 列出已有 run
./tracemiku list

# 一行抓 TB cold-path: 清数据 → 启动 → 自动点"同意" → trace 直到抓到一次 cold-path
./tracemiku trace --pkg com.taobao.taobao --so libsgmainso \
  --fn-offset 0x57770 --cmd 70102 --duration 120 \
  --cold-launch --out traces/run1

# 列出本 run 内所有 calls, records 降序 (最长的 cold-path 排第一)
./tracemiku list traces/run1

# 看某次 call 的完整性 (truncated / last_insn_is_ret 一眼)
./tracemiku info traces/run1/calls/call_002_tid12345_2066291r_50342ms

# 单页 Web SPA 打开 (推荐: IDA 风格左 trace + 右 CFG)
./tracemiku web traces/run1
./tracemiku web traces/run1/calls/call_002_tid12345_2066291r_50342ms
```

### per-call 目录结构

```
traces/run1/
├── meta.json                       # 顶层 meta + calls[] 概要 + modules
├── log.txt
└── calls/
    ├── call_001_tid12345_4675r_98ms/      # idx_tid_records_ms
    │   ├── trace.bin
    │   └── meta.json                       # 含 truncated/last_insn_is_ret
    ├── call_002_tid12345_2066291r_50342ms/ ← cold-path
    │   ├── trace.bin
    │   └── meta.json
    └── _truncated_call_003_tid12345_500r_?ms/  ← teardown 强制结束
```

每个 `calls/<...>/meta.json` 必含: `truncated` (bool), `last_insn_is_ret` (bool),
`records`, `ms`, `retval`, `first_pc`, `last_pc`. 顶层 `meta.json` 还含
`modules` 数组 (所有已加载 SO 的 base/size/name, agent 启动时 enumerateModules
推送), 给多 SO 指针 classify 用。

判定真完整 = `truncated == false && last_insn_is_ret == true`.

### 其他 trace 模式

```bash
# 任意 app 任意 SO 任意函数 (动态注册的方法)
./tracemiku trace --pkg com.taobao.taobao --so libsgmainso \
  --method doCommandNative --cmd 70102 --duration 90 --out traces/run2

# SO 内固定偏移 / SO 导出函数
./tracemiku trace ... --fn-offset 0x57770
./tracemiku trace ... --export JNI_OnLoad

# 多 SO 一起 trace (默认只 trace 主 SO, --include-so 把额外 SO 加入 instrument 范围)
./tracemiku trace ... --include-so libsgsecuritybody.so,libutsec.so
```

### Deep-trace + JNI hooks + anti-debug 绕过 (`--trace-deep` 系)

针对 OLLVM + 反调试 SO (libsgmainso 等), 把"系统 .so 调用全跟"用 boundary ptr-diff +
JNI 字符串 hook + 主动反反调试组合实现:

```bash
./tracemiku trace ... \
  --trace-deep \
  --boundary-diff-patterns 'libart.so:NewStringUTF,libart.so:GetStringUTFChars' \
  --jni-hooks tools/hooks/libart_jni.json \
  --patch-suicide \
  --hide-rwx-maps
```

| flag | 作用 | 备注 |
|---|---|---|
| `--trace-deep` | 全模块 instrument, 对 hostile 符号 (linker/libdl) 用 `Stalker.exclude` 而非 include skip | Task #47 |
| `--stalker-exclude-patterns` | 覆盖默认 hostile 名单 | Task #47 |
| `--boundary-diff-patterns` | 在 hostile fn entry/exit 用 Interceptor diff 显式传参指针的内存, 写 `external_writes.bin` 给 viewer MemShadow | Task #48-50, **默认空, 不要塞 pthread/malloc/atomic 否则 Frida 自递归 SIGABRT** |
| `--jni-hooks PATH` | 加载 JSON hook spec, 对 JNIEnv vtable 上的字符串相关函数下 Interceptor; per-call 落盘 `jni_hooks.jsonl` | Task #56, 默认 `tools/hooks/libart_jni.json` 含 6 个 JNI ops |
| `--patch-suicide` | patch 6 处 sgmainso 内联 `svc #0` (tgkill) 防 anti-frida 自杀 | Task #53, **仅对该 SO 版本有效 (offset 硬编码)** |
| `--hide-rwx-maps` | hook libc open/read/pread64 过滤 `/proc/self/maps` 里 anon RWX (Frida block cache) 行 | Task #54 |

JSON hook spec 格式 (`tools/hooks/libart_jni.json`):

```json
{ "kind": "jni_vtable", "hooks": [
    { "id": "NewStringUTF", "vtable_offset": "0x538",
      "args": [{"name":"env","type":"ptr"}, {"name":"bytes","type":"cstring","max_len":512}],
      "ret":  {"type":"ptr"} }, ...
] }
```

支持的 arg type: `ptr / int / long / void / cstring / utf16 / bytes`. Agent 用 `dlsym
JNI_GetCreatedJavaVMs` 直接拿 JNIEnv (Frida 17 删了 `Java` 全局, 必须直接 dlsym).
扩展新 hook 改 JSON 即可, 不用改 JS.

### 反调试 / 多 SO trace 现状 (实战)

抓 libsgmainso 时遇到 4 层 anti-frida:

| 层 | 检测 | 当前对策 | 状态 |
|---|---|---|---|
| L1 | inline `svc #0` (tgkill, x8=131) 自杀 | `--patch-suicide` patch 6 个入口 | ✅ 概率绕过 (sgmainso 有 1067 个 generic svc thunks, 6 个入口不全覆盖, 偶尔仍触发) |
| L2 | scan `/proc/self/maps` 找 anon rwx | `--hide-rwx-maps` 过滤 maps 读 | ✅ |
| L3 | fork 子进程 ptrace 父 + SIGSEGV | (未做, 见 [TODO.md](TODO.md)) | ❌ |
| L4 | scan `frida_agent_main` 等 symbol | (未做, 改名要 rebuild frida-agent) | ❌ |

非反调试 app (xhs / 小红书等) 直接跑 `--trace-deep` 不需要 patch, 已通过隔离测试
(`tools/probe_deep_safe.js`) 证明 deep-trace 实现本身正确, taobao 崩是 SO 反调试特定问题.

### `--cold-launch` (TB 类首启隐私协议自动化)

内置流程: `am force-stop` → `pm clear` → `monkey` 拉起 → `uiautomator dump`
找 `text="同意"` 按钮 → `input tap` → 轮询直到首页. 实测 6s 进首页.

### `--mode {cmodule, cmodule-v3, js}`

- **`cmodule` (默认, v5)**: CModule on_insn → SPSC lock-free ring (17MB) →
  v8 setInterval 10ms → File.write → `/data/data/<pkg>/cache/.miku/trace_NNN.bin`
  → host adb `gzip -1 -c | gunzip` 流式 pull. **采集 ~1.56M rec/s, dropped=0**.
  实测 TB 70102 cold-launch 14 calls / 67M records / dropped=0 / 总 wall 93s.
- `cmodule-v3`: 旧版 send blob via IPC, 不推荐, 留作回归对比。
- `js`: JS putCallout, ~17K rec/s 但 dropped=0. cmodule 编译失败时自动 fallback。

trace.bin 物理格式 (272B/rec) 三种模式相同。

---

## Trace 反编译 (`tracemiku dec` / `dec-bench`, 路线 B)

设计文档: [`docs/trace-decompiler-design.md`](docs/trace-decompiler-design.md)
(包含 §7.0 普适性原则 — 无 hardcoded 变种).
研究: [`docs/trace-decompiler-research.md`](docs/trace-decompiler-research.md).
真机实测: [`docs/poc-mimo-libsgmainso-2026-05.md`](docs/poc-mimo-libsgmainso-2026-05.md).

**定位**: 机器把 trace → 紧凑结构化 IR (markdown), LLM 反编译.
我们做 evidence (CFG / 子 fn 切分 / hot tier / 类型锚点 / VM 候选 /
循环 induction var), LLM 做语义.

### 一行用法

```bash
# 落 IR markdown 到 <trace>/decompile/{summary.md, fns/F<id>.md}
./tracemiku dec traces/run1/calls/call_002_*

# 含类型锚点 (用户 JSON spec, 见 tools/hooks/type_specs_example.json)
./tracemiku dec <trace> --hooks tools/hooks/my_specs.json

# 一键 LLM 反编译 (4 backend 任选, 落 decompile/llm_results/)
./tracemiku dec <trace> --fn F1 --call-llm mimo            # opencode/mimo-v2.5-pro
./tracemiku dec <trace> --fn F1 --call-llm claude          # 需 ANTHROPIC_API_KEY
./tracemiku dec <trace> --fn F1 --call-llm deepseek        # 需 DEEPSEEK_API_KEY
./tracemiku dec <trace> --fn F1 --call-llm qwen            # 需 DASHSCOPE_API_KEY

# 输出 prompt 让你 copy-paste 给任何 chat
./tracemiku dec <trace> --prompt-only F1

# VM 函数处理: 加 memshadow 抓 bytecode hex 喂 LLM 推编码
./tracemiku dec <trace> --vm-with-memshadow --fn F0 --call-llm mimo

# 多模型对比 (落 decompile/bench/<fn>_compare.md)
./tracemiku dec-bench <trace> --models claude,deepseek,mimo --fn F1
```

### 输出文件结构

```
<trace>/decompile/
├── summary.md                       # trace 顶层 (~3KB) — fn 列表 + VM 候选
├── fns/
│   ├── F0.md                        # 主 fn IR (~30-150KB)
│   ├── F1.md                        # 子 fn (calltree 切的 helper)
│   └── ...
├── llm_results/                     # --call-llm 时落
│   ├── opencode_F1.md
│   └── claude_F1.md
└── bench/                           # dec-bench 时落
    └── F1_compare.md                # 多模型对比表
```

### 能力速览 (实测真机 libsgmainso 59723 records)

| 能力 | stage | 实测 |
|---|---|---|
| trace → markdown IR | DEC1 | 1056 块, 0.5s |
| 多 LLM backend (Claude/DeepSeek/Qwen/mimo) | DEC2 | 4 模型可切 |
| hot/warm/cold 块分级 | DEC3-A | 506KB → 139KB (-73%) |
| calltree 切子 fn | DEC3-B0 | 1 fn → 10 fn |
| 类型锚点 (JSON-spec driven) | DEC3-B | mimo 输出业务名 cmd_init / lock_acquire |
| VM 候选 + bytecode hex evidence | DEC3-D | mimo 给完整 VM dispatcher C 代码 |
| 循环 induction var (numpy regression) | DEC3-C | arith / complex 自动分类 |
| 多模型对比 | DEC4 | latency / token / 关键词命中 表格 |

详见 [`docs/poc-mimo-libsgmainso-2026-05.md`](docs/poc-mimo-libsgmainso-2026-05.md).

---

## Web SPA (主分析入口)

```bash
./tracemiku web traces/run1                       # auto port + 自动开浏览器
./tracemiku web traces/run1 --port 8080
./tracemiku web traces/run1 --no-browser          # 远程 / SSH 隧道场景
./tracemiku web traces/run1 --so /path/to/lib.so  # 加载 BN backend, 启用 HLIL
```

### 左侧 vtab 列表

`Functions` · `Backtrace` · `Call Tree` (P0-1) · `Forks` (P1-C M6) ·
`Strings` · `Taint` · `Cross Ref` · `SO Filter` · `Settings`

### 核心功能

- **反汇编流**: 每条带计数器圆点 + #idx + 地址 + func+offset + asm + 注释。
  圆点颜色: 灰=1 / 蓝=2-9 / 绿=10-99 / 黄=100-999 / 红=1000+。
- **CFG**: graphviz `dot -Tsvg` 服务端渲染, 单函数模式, cursor 跨函数自动切。
  分支配色 / 调用-返回边 / Tarjan SCC loop 高亮。
- **BN-CFG** (有 `--so`): BN HLIL 静态 CFG + trace overlay 覆盖率, 红色虚线
  标 dynamic-only 边 (OLLVM 间接跳真 target 但 BN 没标的)。
- **HLIL** (有 `--so`): BN HLIL 行级 + token 级着色, 当前 PC 高亮。
- **Call Tree**: bl/ret 配对建嵌套调用树, 点击跳 enter idx, max_depth 防 OLLVM
  自递归爆炸 (P0-1).
- **Forks**: agent 抓的 fork-event 列表, 按 attach_status 过滤,
  失败 fork 红色 + miku-shield 引导 (P1-C M6).
- **Taint**: forward / backward + `--data-only` / `--through-mem` /
  `--cross-fn-call` (frame_depth 标注), stopped_at_max 截断时显"加载全部"按钮.
- **寄存器**: pwndbg 风注释 `[func+0xN]` / `→ "string"` / `[SP+0xN]` /
  `(JavaHeap)` / `(libart?)`, 多级 deref。**`field_at` hint**: ldr/str
  指令的 base reg 自动注释 `[struct.field]` (有 `--so` 且 BN 后端 ready 时)。
- **内存**: hex+ascii dump, write 字节绿色, 双击跳第一次 write。
- **快捷键**: j/k 单步, PgDn/PgUp 翻 20, g/G 跳头尾, `:N` 跳 #N, 鼠标点
  CFG 块 / trace 行联动。

### 性能

- 后端 FastAPI + 前端 vanilla JS (无构建工具)。CFG 子进程跑避 GIL。
- numpy `pc_array()` 零拷贝映射 mmap PC 列, `idxs-for-pc` 322ms → 14ms (23x)。
- 100 并发 `/api/record` 2656 req/s。
- 大 trace (>1.6M 行) 自动 decoupled scroll 突破浏览器 33M-px div 上限。

---

## CLI (LLM/scripting 入口)

`viewer/__main__.py` 提供 31 个子命令, 全部默认 JSON 输出 (LLM 用 BashTool
一行调用). 完整列表见 [viewer/README.md](viewer/README.md). 速览:

```bash
# 元信息 / 索引 / 搜索
python -m viewer stats <trace>                            # 完整元信息
python -m viewer export <trace> --format sqlite           # SQLite + pc index
python -m viewer search-pc <trace> 0x... [--limit N]
python -m viewer idxs-for-pc <trace> 0x... [--cursor N --limit M]
python -m viewer search-asm <trace> 'regex'
python -m viewer records <trace> --start N --count M
python -m viewer reg-at-idx <trace> --idx N [--regs ...]
python -m viewer call-chain <trace> --idx N [--depth K]   # LR-walking caller

# 污点追踪 / 数据流 (反向 OLLVM 主路径)
python -m viewer taint-fwd/bwd <trace> --start N --reg x0 \
       [--max 5000] [--data-only] [--through-mem] \
       [--cross-fn-call] [--summary-by-fn]
python -m viewer data-chase <trace> --start N --reg x0    # 单路径 chase

# 内存
python -m viewer mem-dump <trace> --addr 0x... [--count N --cursor N]
python -m viewer mem-diff <trace> --idx N --addr 0x... --size N
python -m viewer mem-writes-in-range <trace> --idx-lo A --idx-hi B
python -m viewer mem-flow <trace> --addr 0x... --count N  # per-byte timeline
python -m viewer last-write-of-addr <trace> --addr 0x... --before-idx N
python -m viewer find-mem-pattern <trace> --bytes-hex AA BB [--idx-lo/hi]

# 加密 / 算法识别 (闭环 crypto 工作流)
python -m viewer crypto-scan <trace>                      # 22 IV/SBOX patterns
python -m viewer hash-finalize-detect <trace>             # 找 hash 输出位置
python -m viewer hash-input-search <trace> --target-bytes ABCD --inputs hello
python -m viewer auto-phase-detect <trace>                # heuristic 算法阶段
python -m viewer ollvm-detect-vm <trace>                  # OLLVM VM dispatcher hint
python -m viewer diff-traces TRACE1 TRACE2 [...]          # 跨 trace byte-diff

# JNI / 函数 / fork
python -m viewer jni-calls <trace> [--in-fn ...]
python -m viewer jni-strings <trace>
python -m viewer jobj-history <trace> --jobject 0x...
python -m viewer fn-summary <trace> --fn ...
python -m viewer reg-timeline <trace> --reg x0 --start 0 --end 1000
python -m viewer so-stats <trace>
python -m viewer fork-events <trace> [--status success/failed_*]  # P1-C

# BN HLIL 字段语义 (需 --so)
python -m viewer field-at <trace> --pc 0x... --reg x8 --offset 0x80 \
       --so /path/to/lib.so
```

每条命令的 `--help` 写得像 MCP tool description, LLM agent 能直接挑工具。

---

## Python SDK

`viewer/__init__.py` 显式 export 公共 API, 直接 `from viewer import ...`:

```python
from viewer import load, build_cfg, build_from_trace, decode
from viewer import Index, MemShadow, forward_taint, backward_taint

t = load("traces/run1/calls/call_002_*/")
print(len(t), "records")
print(t.meta.module.name)             # libsgmainso-6.8.260403.so

sym = build_from_trace(t)             # PC → function name (auto-loads
                                       # examples/<so>/known_offsets.json)
idx = Index(t); idx.build()           # cross-reference index
mem = MemShadow(t); mem.build()       # byte-level memory shadow

cfg = build_cfg(t)                    # block-CFG from trace
print(cfg.block_count, "blocks")

hits = forward_taint(t, start_idx=100, taint_reg="x0", index=idx)
chain = backward_taint(t, idx=200, taint_reg="x0", index=idx)
```

完整示例: [`examples/llm_cookbook.py`](examples/llm_cookbook.py) — 10 个
self-contained .py 例子 (load_trace / count_blocks / find_pc / taint_x0 /
backward_taint / find_strings / mem_dump / classify_branch / hot_pcs /
full_trace_summary)。

```bash
python examples/llm_cookbook.py all              # 跑所有例子
python examples/llm_cookbook.py fn-summary       # 跑单个
```

---

## REST API + OpenAPI Schema

Web server 同时是 LLM 友好的 REST API:

```bash
./tracemiku web traces/run1 --port 8080 --no-browser
curl http://localhost:8080/api/meta
curl http://localhost:8080/openapi.json | jq .       # 完整 schema
```

**29 个 endpoints** 全部带 strict Pydantic Union schema:
- 单 shape: `/api/meta` / `/api/records` / `/api/record/{idx}` / `/api/search`
  / `/api/idxs-for-pc` / `/api/reg-value-at` / `/api/asm-tokens-for-pcs`
  / `/api/field-at` / `/api/reg-timeline` / `/api/mem-diff`
- 多 shape (Union with Literal status): `/api/cfg` / `/api/block` / `/api/loops`
  / `/api/cfg-svg` / `/api/backtrace` / `/api/idxs-for-block`
  / `/api/forward-taint` / `/api/backward-taint` / `/api/strings`
  / `/api/string-provenance` / `/api/mem-dump` / `/api/last-write-of-reg`
  / `/api/idxs-touching-{addr,range}` / `/api/fn-summary`
  / `/api/hlil-for-pc` / `/api/bn-cfg-svg-for-pc` / `/api/bn-cfg-for-pc`

`/openapi.json` 用 `anyOf` 准确反映每种 endpoint 的多 shape, LLM client / 前端
codegen 直接消费。

详细字段请看 `webui/schemas.py` 或访问 `/docs` (FastAPI Swagger UI)。

---

## 性能

### 离线分析 (viewer/CLI/Web)
| 操作 | 4500 条 | 67000 条 | 2.06M 条 (实测) |
|---|---|---|---|
| mmap 加载 | <1ms | <1ms | <1ms |
| 完整 def/use 索引 | 20ms | 300ms | ~5s |
| CFG 重建 (子进程) | 20ms | 250ms | ~4s |
| 正向污点 (cap=500) | 5ms | 50ms | ~50ms |
| `idxs-for-pc` | <1ms | <1ms | 14ms (numpy vec) |
| Web 视图渲染 (每帧) | <10ms | <10ms | <10ms (viewport-only) |

### 在线 trace 采集 (`--mode`)
| mode | 实现 | 实测最大单次 trace | 适用 |
|---|---|---|---|
| `cmodule` (默认 v5) | CModule on_insn + 设备落盘 + gzip pull | **67M records / 14 calls / dropped=0** | 默认 |
| `js` | JS putCallout | 2,066,291 条 / 562 MB ✓ TB cold-path | cmodule 编译失败 fallback |
| `cmodule-v3` | cmodule + send blob (IPC) | drop ~91% | 仅回归对比, 不推荐 |

---

## 架构

```
traceMiku/
├── tracemiku           # 顶层 CLI (trace/web/list/info/finalize)
├── tracer/             # Stage-1 设备端采集
│   ├── agent_cmodule_v5.js  # 默认: CModule + SPSC ring + gzip pull
│   ├── agent_cmodule_v3.js  # 回归对比 (cmodule + IPC blob)
│   └── agent_generic.js     # JS callout 备选
├── viewer/             # core 库 + CLI 子命令 + Python SDK
│   ├── __init__.py     # 公共 API exports
│   ├── __main__.py     # 12 个 CLI 子命令
│   ├── trace.py        # mmap binary trace 解析 + addr_of helper
│   ├── disasm.py       # capstone 包装 + def/use 提取 (lru_cache 200K)
│   ├── index.py        # reg_defs/reg_uses + mem_addr 索引
│   ├── symbols.py      # 函数符号 + auto_known_offsets discovery
│   ├── memshadow.py    # 稀疏内存 shadow + 字符串提取
│   ├── cfg.py          # 从 trace 重建 BB-CFG + Tarjan SCC + dot
│   ├── taint.py        # 正向/反向污点 (heap-based, O(|hits|·log N))
│   ├── display.py      # pwndbg 风格智能解引用 + multi-module classify
│   ├── decompiler/     # BN/Ghidra/IDA backend 抽象 + binja 实现
│   └── app.py          # textual TUI (deprecated, 不维护)
├── webui/              # 主 UI: 单页 Web SPA
│   ├── server.py       # FastAPI: 29 endpoints, mmap 后端, CFG 子进程
│   ├── schemas.py      # 严格 Pydantic Union schemas + OpenAPI
│   ├── cfg_render.py   # 共享 dot/HTML render helpers
│   ├── index.html      # 单页应用 (HTML + 样式)
│   └── app.js          # vanilla JS, 无构建工具
├── examples/
│   ├── llm_cookbook.py             # 10 个 SDK 示例
│   └── libsgmainso/known_offsets.json  # sample 已知函数偏移
└── tests/              # 30 文件 / 341 unit + integration tests
```

## TUI (deprecated, 不维护)

历史 textual TUI 在 `viewer/app.py`, 仍可用 `python -m viewer <dir>` 或
`tracemiku view <dir>` 启动, 但不再加新功能, 出 bug 不修。新功能一律先在
Web 上做。彻底弃用后会一起删 (`viewer/app.py` + `cfg.py:write_dot`
+ `cfg.py:textual_summary`)。

## 关键技术点

### Trace 采集 (避坑)

1. **Stalker.exclude libc/libart**: ARM64 LDXR/STXR 之间插桩会清除 exclusive
   monitor, atomic 死锁。必须排除全部 system 库。
2. **on_spawn 回调里别调 init**: spawn-gated 进程被 SIGSTOP,
   `enumerateModules` 永久 block。init 必须推到主线程异步跑。
3. **Florida frida-server**: 默认 frida-server 的 `/frida-{uuid}` socket 被
   TB 类反调试秒杀。
4. **冷启 vs warm**: TB 类 sgmain 同一 cmd 在不同时机走不同路径 — `monkey`
   直启第一次 70102 走 fail-path (~4675 条), 真业务请求触发的 70102 走
   cold-path 真算 sign (~200 万条)。`--cold-launch` 自动 force-stop+pm clear+
   点同意, 抓真业务请求的 cold-path。
5. **CModule import 语义**: `extern T name;` (无 `*`) → name 的 STORAGE 在
   JS 传入指针; `extern T *name;` 错。
6. **多模块端到端**: agent 启动时 `Process.enumerateModules()` →
   `send({type:"modules"})` → host 写 `top_meta["modules"]` → viewer
   `meta.modules` → `display.collect_modules_from_trace` 多 SO classify。改这条
   链路必须验证全链路 (memory `feedback_e2e_pipeline_audit`)。

### 反调试 / 多线程异步

- 统一 agent 自动 hook `pthread_create` 跟所有新线程
- 通过 JNIEnv vtable[215] 拿到 `RegisterNatives` (libart 不导出)
- 已运行过 RegisterNatives 的进程: 用 `--fn-offset` 直接 hook 偏移

### 性能

- 二进制固定格式 272 字节/记录 (PC + 31×GPR + SP + raw inst)
- mmap + 按需 record() 读取
- viewport-only 渲染 (Web 大 trace 100 行 viewport, TUI 30 行)
- capstone 反汇编 lru_cache(200000)
- numpy `pc_array()` 零拷贝 PC 列, vectorized scan 替代 Python loop
- 子进程独立 GIL build CFG / pc_inst / pc_to_block / block_idxs

## 已知限制 / Backlog

详见 [`TODO.md`](TODO.md). 简要:

- NEON/FP 寄存器未记录 (P1, 需 record 格式 v2)
- 字符串只能从 MemShadow 抠 (设计如此)
- CFG 布局用 graphviz dot
- TUI 冻结, Web 唯一 UI
- Anti-debug L3+ 未突破 (libsgmainso fork+ptrace+SIGSEGV)
- page-dirty 模式 (Task #52) 暂不做, 实战命中率低

## 文档

- [`TODO.md`](TODO.md) — 唯一 backlog 入口 (新增条目都加这里)
- [`viewer/README.md`](viewer/README.md) — Python SDK + CLI 详细说明
- [`tracer/README.md`](tracer/README.md) — 采集器内部细节
- [`docs/frida-codeslab-patch.md`](docs/frida-codeslab-patch.md) — patched
  frida-server 原理
- [`docs/PER_CALL_TRACE_DESIGN.md`](docs/PER_CALL_TRACE_DESIGN.md) — per-call
  trace dir 设计
- [`docs/CLI_GAPS.md`](docs/CLI_GAPS.md) — 实战 LLM 逆向时发现的 CLI 缺口清单
- [`docs/PDF_FEATURE_PARITY.md`](docs/PDF_FEATURE_PARITY.md) — krash PDF 功能
  对照 (历史参考)
- [`tests/COVERAGE.md`](tests/COVERAGE.md) — 测试覆盖盘点
- [`CODE_REVIEW.md`](CODE_REVIEW.md) — 2026-05-01 代码审查报告 (大部分已实施)

## 来源 / 感谢

- 看雪 [krash 时间无关调试](https://bbs.kanxue.com/thread-273055.htm) — UI 设计参考
- 看雪 [FANGG3 ATTD 系列](https://bbs.kanxue.com/thread-281555-1.htm) — trace 格式
- [Ylarod/Florida](https://github.com/Ylarod/Florida) — frida-server 反检测 fork
- [zer0def/undetected-frida](https://github.com/zer0def/undetected-frida) — 同上
- IDA tenet 插件 trace 格式
