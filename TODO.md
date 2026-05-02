# traceMiku Backlog / TODO

> 唯一 backlog 入口. README / tracer-README / CODE_REVIEW 等文档不再各自维护待办,
> 新增条目一律加到这里. 已完成的从这里删, 不留 strikethrough.

## 最近实施 (2026-05-02 post xsign-RE session)

### 第一轮 P0 (基础设施)

- `mem-writes-in-range --idx-lo A --idx-hi B [--src-byte 0xNN] [--addr-lo/hi]`:
  整段 mem 写出列表, 反向定位算法生成阶段. vectorized numpy mask, 200 hits ~30ms.
- `mem-flow --addr 0x... --count N [--writers-only|--readers-only] [--idx-lo/hi]`:
  每 byte 完整事件 timeline (R/W kind + idx + asm). 第二轮加 writers/readers 过滤.
- `crypto-scan`: 一发扫 22 标准加密原语 (SHA1/SHA256/MD5/AES SBOX+invSBOX+Rcon/TEA/
  ChaCha20/HMAC ipad/opad/**SM3 IV/SM4 FK/Blake2 IV/CRC32**). LE 字节序内置.
- `taint-bwd --through-mem`: byte 级 mem overlap, 穿 8B-store + 1B-load 错配.
- `MemShadow` sidecar 持久化 (`<trace.bin>.memshadow.v2.npz`): cold 37s → warm 6s
  (6× speedup), 后续 find-mem-pattern 0.08s/次. 实测 8 次扫描 200s → 7.5s (27×).

### 第二轮 P0/P1 (反 OLLVM 实战补强)

- `taint-fwd --through-mem`: 对称 backward, byte 级 store→load 穿透.
- `reg-at-idx --idx N --regs x0,x14,...`: thin wrapper "reg 在 idx N 是多少".
- `call-chain --idx N [--depth K]`: LR 反查 caller 链 (best-effort, OLLVM 自递归
  会停).
- `find-mem-pattern --idx-lo --idx-hi`: 命中按 first_idx 范围过滤.
- `hash-input-search --target-bytes ... --inputs ... --keys ... --algos ... --combos ...`:
  brute-force hash 输入候选爆破 (sha1/md5/sha256/hmac-* × plain/prefix_key/...).
- `auto-phase-detect`: heuristic timeline 标算法阶段 (jni IO + crypto IV +
  byte-stream + base64).

## P0 — 实战卡过的功能缺口

(空 — 当前没有 P0)

---

## P1 — 待办

### Tracer / Agent

- **page-dirty 模式 (Task #52)** — `--ext-mem-mode=page` 用 `/proc/self/clear_refs` +
  `/proc/self/pagemap` soft-dirty bit 在 hostile sym call 边界做 exhaustive 内存 diff.
  填补 `--trace-deep` 下 boundary ptr-diff (#47/#48) 漏抓 "hostile fn 写没传参的全局/TLS"
  的理论 case.
  - **思路**: onEnter 写 `4\n` 到 clear_refs 清进程 dirty bit; onLeave 扫 pagemap,
    bit 55 置位的页 dump 整 4096B 进 `external_writes.bin`.
  - **坑**:
    1. clear_refs 是进程级, 别的线程会污染脏位 — 需要"进 hostile 前 snapshot, 出来再
       snapshot, diff" 双 buffer, 但又会扰动 ART GC 的 access tracking;
    2. 不能并发多 hostile call 进同 hook (clear_refs 互覆盖), 全局锁;
    3. anon RWX (Frida block cache 8MB) 必脏, scan 时按 `/proc/self/maps` 的名字
       过滤 `frida-agent` / `[anon:...]` / Frida codeslab.
  - **判定**: 当前 SO 行为分析的 hostile 写主要是 JNI string ops + libart object create —
    已被 #56 (JSON-driven JNI hooks) 覆盖. #52 处理的是理论 correctness 漏洞,
    实际命中率 < 5%. **观望: 等出现 "MemShadow 显示某地址值跟运行时不符" 的具体 case
    再做**.

- **NEON / FP 寄存器 record 格式 v2** — 当前 trace.bin 272 字节只装 GPR (x0..x28 + fp/lr/sp).
  OLLVM 用 SIMD 算 jump table / 加密时 viewer 看不到. 改 record 物理格式破坏向后兼容,
  得加 `meta.json` 的 `record_version: 2` 标志, viewer/disasm/index 全链路改 stride.

- **WebSocket streaming trace** — 边采边看, 取代当前 "采完 → gzip pull → web 打开" 两步流程.
  对 cold-path 长 trace 体验差距很大 (用户等 50s gzip pull 才能开始看).

- **C/C++ 原生 tracer (`libgumTraceMiku.so`)** — 目标 50K+ rec/s 流, 减少 JS bridge
  开销和 GC 抖动. 参考 [revercc/gumTVM](https://github.com/revercc/gumTVM).
  当前 v5 cmodule 已经 1.56M rec/s dropped=0, 这条主要是为了砍 frida-server 依赖.

### Anti-debug 多层突破

实战 (taobao libsgmainso) 已被 L1 (tgkill svc 自杀) + L2 (rwx maps 扫描) 突破后,
还剩 L3+:

- **L3: fork+ptrace+SIGSEGV** — TBreakPad 日志显示 fork 子进程 ptrace 父进程然后父发
  SIGSEGV. 需要要么 hook fork/clone 阻断子进程, 要么劫持父进程的 sa_sigaction handler
  让 SIGSEGV 不致命. 风险高, 容易死锁.

- **L4+: 检测 frida-agent.so symbol** — `frida_agent_main` 在 maps 里直接可见,
  改名要 rebuild frida-agent. 当前 stealth server 只动了 12 个字符串 (`gum-js-loop`
  → `miku-js-loop` 等), agent.so 内部 symbol 没动.

- **L5: glib 线程名 (`gmain` / `gdbus`)** — 不是 frida 自己创建, 是 glib 内部, 改它要
  patch glib 或 hook prctl(PR_SET_NAME).

### Viewer / Webui

- **viewer 集成 jni_hooks.jsonl** — Task #56 落盘的 JNI hook events (`call_NNN/jni_hooks.jsonl`)
  目前 viewer 没读. 应该:
  - `Trace.jni_events` 属性懒加载;
  - Web SPA 加左侧 "JNI Calls" tab, 点击跳到对应 trace_idx;
  - reg-display 时 `[x?]` 如果命中过 NewStringUTF/GetStringUTFChars 的 ret/arg, 直接显示
    `→ "<utf8>"`.

- **viewer 集成 external_writes.bin** — Task #50 已经让 MemShadow 加载它, 但 hex dump /
  string finder 的展示没区分 "x kind (external write)" vs "w kind (in-trace write)".
  应该在 hex dump 用第三种颜色标 external (灰底? 紫底?).

### CLI gaps (来自 docs/CLI_GAPS.md, 仍 open)

- **Gap-G** — `taint-fwd / taint-bwd --cross-fn-call`: 遇 `bl <fn>` 自动追到 `fn` 的
  ret reg 上次 def. 当前 taint 只在单函数内追, 跨 bl 就断.

### 反向追踪 OLLVM 卡点遗留 (P2 — 工程量大或前置缺数据)

- **`ollvm-detect-vm`** — 启发式找 VM dispatcher (高 entry count + `ldr [base, idx, lsl#3]`
  + indirect br + `ldrh [...,#N]!` 自增 pattern). xsign session 已确认 sub_169a10/sub_150e6c
  这俩是 OLLVM VM. 标注后所有反向追踪可跳过 VM 内部, 只看 VM bytecode 流.

- **`ollvm-vm-trace --vm-ip-reg x21 --idx-range A..B`** — 给定 VM IP 寄存器, dump
  trace 中该 reg 的 distinct values 序列 = VM bytecode PC 序列. 配合 dispatch table
  反向能看到 VM 程序执行路径.

- **`ollvm-vm-decode --fn FN --idx-range A..B`** — 给定 dispatcher 把 trace 中 x21 (VM IP)
  序列 dump 成 VM bytecode listing 并解释执行还原原始 IL. 真正穿透 OLLVM 的工具, **人天级
  工程量**.

- **`diff-traces TRACE1 TRACE2... --on-pc 0x...`** — 多 trace 在同 PC 对比寄存器值.
  不变 = device-stable key; 变化 = nonce. 前置: 多次 trace 数据 — 当前只 1 trace.

- **`hash-finalize-detect`** — auto-find SHA-1/MD5 finalize 模式 (5×u32 byte-swap +
  连续 20-byte store 输出). 当前 hash 输入找到了 (crypto-scan IV 命中) 但**输出位置**
  没自动定位 — 这个会补齐.

- **`jni-flow --idx N`** — JNI hook events 跟 trace navigation 集成. 给 idx 直接显示
  trace 指令 + arg regs + jsonl 解码值 + arg backward-trace 一跳.

- **`mem-snapshot --addr A --count K --at-idx N`** — 取 idx N 时刻的 mem 状态 (alias
  for mem-dump --cursor). 当前 mem-dump --cursor 已能用, 这是个 UX rename.

## CLI 已做但未同步到 Web (REST API gap)

下面命令在 CLI 可用 (`viewer.__main__`), 但 webui/server.py 没对应的 `/api/*`
endpoint. 同步后 Web SPA 也能用 + LLM via REST 也能调:

| CLI 命令 | 等价 endpoint 名 | 备注 |
|---|---|---|
| `mem-writes-in-range` | `/api/mem-writes-in-range` | numpy vectorized, fast |
| `mem-flow` | `/api/mem-flow` | per-byte timeline |
| `crypto-scan` | `/api/crypto-scan` | 22 patterns 一发 |
| `reg-at-idx` | `/api/reg-at-idx` | 简化 records 调用 |
| `call-chain` | `/api/call-chain` | LR 反查 caller |
| `hash-input-search` | `/api/hash-input-search` | 候选爆破 — POST 因 inputs 数组 |
| `auto-phase-detect` | `/api/auto-phase-detect` | heuristic timeline, 同 trace 缓存 |
| `taint-bwd --through-mem` (flag) | `/api/backward-taint` 加 `through_mem` 参数 | 现 endpoint 缺 flag |
| `taint-fwd --through-mem` (flag) | `/api/forward-taint` 加 `through_mem` 参数 | 同上 |
| `find-mem-pattern --idx-lo/hi` (flags) | `/api/find-mem-pattern` 加 `idx_lo/hi` | 同上 |
| `mem-flow --writers-only/readers-only` (flags) | (新 endpoint) | 同 mem-flow 新增 |

实施: 每个 endpoint 加 Pydantic Response schema + handler. 估时 ~半天.

---

## P2 — 想做但不阻塞

- **server.py 1588 行拆分**: `webui/cfg_render.py` + `webui/api_*.py` 域拆分 (CODE_REVIEW #1).
  阻塞: `make_app` 的 1300 行闭包要重构成 class. 估时 1-2 天.

- **`Index.def_chain`/`use_chain` 改用 stdlib `bisect`** (CODE_REVIEW #7). 顺手做, 不单立 PR.

- **`MemShadow` 改 word-level events numpy 结构化数组** — 当前 dict[byte_addr] 在 6.8M
  trace 上占 GB 级内存 (CODE_REVIEW #12). 4GB 实际超限再做.

- **CFG 布局换 ghidra Decompiler Layout** — 当前用 graphviz `dot`, 复杂函数布局丑.

---

## 已知限制 (不打算修)

- **NEON/FP 寄存器没记** → 见 P1 record v2.
- **字符串只能从 MemShadow 抠** — trace 没读到的字节没法识别字符串. 设计如此.
- **TUI (`viewer/app.py`) 冻结** — Web 是唯一 UI. TUI bug 不修, 出问题就 deprecate 删除
  整个文件 + `cfg.py:write_dot` + `cfg.py:textual_summary`.
