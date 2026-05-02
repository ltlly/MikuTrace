# traceMiku Backlog / TODO

> 唯一 backlog 入口. README / tracer-README / CODE_REVIEW 等文档不再各自维护待办,
> 新增条目一律加到这里. 已完成的从这里删, 不留 strikethrough.
>
> 项目哲学 (从批注收敛): **全量信息 > 性能**, **真实业务场景 > 社区曝光**.
> 1GB trace 可忍受, 不做 selective insn; 不为 SEO 做 drcov; 不做 CTF 伪需求.

---

## 已实施 (2026-05-02)

### 反 OLLVM 实战补强 — CLI 工具批

- `mem-writes-in-range --idx-lo A --idx-hi B [--src-byte 0xNN] [--addr-lo/hi]`:
  整段 mem 写出列表, 反向定位算法生成阶段. vectorized numpy mask, 200 hits ~30ms.
- `mem-flow --addr 0x... --count N [--writers-only|--readers-only] [--idx-lo/hi]`:
  每 byte 完整事件 timeline (R/W kind + idx + asm).
- `crypto-scan`: 一发扫 22 标准加密原语 (SHA1/SHA256/MD5/AES SBOX+invSBOX+Rcon/TEA/
  ChaCha20/HMAC ipad/opad/**SM3 IV/SM4 FK/Blake2 IV/CRC32**). LE 字节序内置.
- `taint-bwd --through-mem` + `taint-fwd --through-mem`: byte 级 mem overlap, 穿
  8B-store + 1B-load 错配.
- `find-mem-pattern --idx-lo --idx-hi`: 命中按 first_idx 范围过滤.
- `reg-at-idx --idx N --regs ...`: thin wrapper "reg 在 idx N 是多少".
- `call-chain --idx N [--depth K]`: LR 反查 caller 链 (best-effort, OLLVM 自递归会停).
- `hash-input-search`: brute-force hash 输入候选爆破.
- `auto-phase-detect`: heuristic timeline 标算法阶段.
- `diff-traces`: 跨 N traces byte-level diff + alias-group + nibble-level 自动检测.
- `MemShadow` sidecar 持久化 (`.memshadow.v2.npz`): cold 37s → warm 6s (6× 加速).

### 解耦项目特定目标 (2026-05-02 code review)

- agent_cmodule_v5/v3.js 删 `soPattern: "libsgmainso"` / `fnOffset: 0x57770` 默认.
- `SGMAIN_TGKILL_SVC_OFFSETS` → JSON spec 文件 `tools/hooks/sgmainso_6.8.260403_suicide.json`.
- `_hideMaps_filterLine` 中 `'libsgmain'` 硬编码 → `STATE.soPattern` 动态匹配.
- 8 处 docstring + webui dropdown 抽象化.
- `viewer/decompiler/smoke_test.py` 硬编码绝对路径 → env override.
- `tests/test_meta_modules.py` fixture 名抽象化.

---

# 待办优先级

## ✅ P0 — 全部完成 (2026-05-02 single session)

| # | 项 | 状态 | commit |
|---|---|---|---|
| 1 | Tree View 调用层次 UI (web SPA) | ✅ | 23c0829 |
| 2 | viewer 集成 jni_hooks.jsonl | ✅ | 6ff4860 |
| 3 | Web 同步 11 个 CLI endpoint (4 batches) | ✅ | b9cd80c, 2788a47, f29afdf, 6b04e3c |
| 4 | viewer 集成 external_writes 视觉区分 | ✅ | 174d063 |
| 5 | taint cap=5000 + stopped_at_max + 加载全部按钮 | ✅ | 644b316 |
| 6 | trace 报错提示反调试 + miku-shield URL | ✅ | ba14908 |

## ✅ P1 — 大部分完成 (同 session 续)

| # | 项 | 状态 | commit | 备注 |
|---|---|---|---|---|
| A | taint --cross-fn-call (frame_depth 标注) | ✅ | 416c4fa | viewer-only, 全量 propagation 待真机 |
| B | hash-finalize-detect (闭环 crypto-scan) | ✅ | fbf735d | u32x5 / byte_seq, window-based |
| D | ollvm-detect-vm heuristic | ✅ | 4328364 | confidence-scored, 仅 detect 不 decode |
| C | fork tracing M7 (viewer read fork_events) | ✅ partial | 5976c51 | M1-M6/M8 待真机 |

**P1 真机依赖项推迟**:
- P1-C M1: agent hook fork/clone/vfork/clone3 → 写 fork_events 到 meta.json
- P1-C M2: host spawn-gating attach child + 注入 agent (复用 RPC opts)
- P1-C M3: attach 失败 fallback (proc 轮询 + exit code)
- P1-C M6: Web SPA Forks tab UI
- P1-C M8: 真机集成测试 (synth fork + anti-debug fork)

**累计**: 14 commits, +426 tests, 测试 426 pass + 1 skip.

下面是 P0 原始设计 spec (保留作历史 / next session 参考):

### P0-1: Tree View 调用层次 UI

Web SPA 加左侧 "Call Tree" tab. 从 trace 用 bl/ret 配对建栈, 输出嵌套调用树.
点击节点跳到对应 trace_idx. Frinet 标配功能.

### P0-2: viewer 集成 jni_hooks.jsonl

- `Trace.jni_events` 属性懒加载 (jni_hooks.jsonl per-call dir 已落盘);
- Web SPA 加左侧 "JNI Calls" tab, 点击跳到对应 trace_idx;
- reg-display 时 `[x?]` 如果命中过 NewStringUTF/GetStringUTFChars 的 ret/arg, 直接
  显示 `→ "<utf8>"`.

### P0-3: Web 同步 11 个 CLI endpoint

下面命令在 CLI 可用, 但 webui/server.py 没对应的 `/api/*`:

| CLI 命令 | 等价 endpoint | 备注 |
|---|---|---|
| `mem-writes-in-range` | `/api/mem-writes-in-range` | numpy vectorized |
| `mem-flow` | `/api/mem-flow` | per-byte timeline |
| `crypto-scan` | `/api/crypto-scan` | 22 patterns 一发 |
| `reg-at-idx` | `/api/reg-at-idx` | 简化 records 调用 |
| `call-chain` | `/api/call-chain` | LR 反查 caller |
| `hash-input-search` | `/api/hash-input-search` | POST (因 inputs 数组) |
| `auto-phase-detect` | `/api/auto-phase-detect` | heuristic timeline |
| `diff-traces` | `/api/diff-traces` | 多 trace 输入 |
| `taint-bwd --through-mem` (flag) | `/api/backward-taint` 加 `through_mem` | endpoint 缺 flag |
| `taint-fwd --through-mem` (flag) | `/api/forward-taint` 加 `through_mem` | 同上 |
| `find-mem-pattern --idx-lo/hi` (flags) | `/api/find-mem-pattern` 加 `idx_lo/hi` | 同上 |

每 endpoint: Pydantic Response schema + handler.

### P0-4: viewer 集成 external_writes 视觉区分

Task #50 已让 MemShadow 加载 external_writes.bin (kind="x"), 但 hex dump / string
finder 的展示没区分 "x kind (external write)" vs "w kind (in-trace write)". 应在
hex dump 用第三种颜色 (灰底 / 紫底).

### P0-5: taint cap + truncated 警告 + web "加载全部" 按钮

第三轮我用 `--max 30` 截断 chain, 误以为 OLLVM 卡死, 实际 4410 跳才到底. 改:

- **CLI**:
  - `taint-fwd` / `taint-bwd` 默认 `--max` 从 500 加到 **5000**;
  - chain 截到 cap 时输出 `"stopped_at_max": true` flag;
  - 加 `--summary-by-fn` flag 直接出函数分布.
- **Web SPA**:
  - taint 结果列表上方加 `[已截断: 显示 5000/?, 加载全部]` 按钮;
  - 点击后重发请求带 `--max 50000` 或无上限, 加载完整 chain;
  - 配合 `stopped_at_max` flag, 按钮只在截断时出现.

`mem-snapshot --addr A --count K --at-idx N` 是 `mem-dump --cursor` 的 UX alias,
顺便加上.

### P0-6: trace 报错提示反调试 + 推荐工具

trace 失败 (SIGILL / SIGABRT / target crash / TimedOut) 时, host CLI 应该:

- 检测到 `tombstone` 含 `SI_USER` + 1 帧 (anti-debug 自杀指纹) → 提示 "可能是反调试,
  推荐 miku-shield (eBPF, github.com/ltlly/miku-shield) 或自写 Frida bypass 脚本"
- 检测到 spawn TimedOut → 提示 "可能 spawn-gating 时间过长, 检查 frida-server"
- 检测到 SIGABRT in frida-agent.so → 提示 "Frida 自递归崩溃, 检查 boundary-diff
  pattern 是否含 pthread/malloc"
- 一般失败附 `tools/detect_suicide.js` 路径让用户先 detect

实现: `tracemiku` host 抓 process exit + adb logcat 后做模式匹配, 出诊断建议.
**这是 traceMiku 跟 miku-shield 唯一的官方"耦合点" — 错误诊断时引用兄弟工具.**

---

## 🎯 P1 — 本季度 (3 天 ~ 2 周)

### P1-A: `taint-fwd/bwd --cross-fn-call` (必须做, 3-5d) ★

**用户要求**: 污点追踪必须全量, 跨 `bl` 不能断.

当前 `data-chase` 部分覆盖 (单路径), 但 taint 主路径在 `bl` 处断. 需求:
- `bl <fn>` 时: 把 tainted 入参 (x0..x7) 转成"目标函数入口处的同名 reg taint"
- `ret` 时: ret reg (x0/v0) taint 传回上一帧
- 跨函数路径 callee 内部的 def/use 也要追

参考: 前沿论文 + 开源库:
- HardTaint (OOPSLA 2024) 跨函数处理章节
- TaintGrind (Valgrind 模块) 函数边界处理
- libdft64 跨函数 wrapper 设计

实现里程碑:
- M1: agent 不动, 只在 viewer 端 reg-frame 转换 (callee 入参 = caller bl 前的 x0..x7)
- M2: callee 内部 taint 走标准流程, ret 时 transfer ret reg
- M3: 测试场景 — TB libsgmainso 看 doCommandNative 跨 bl 后 chain 长度从 4410 → ?

### P1-B: hash-finalize-detect (2d)

闭环 crypto-scan 工作流. SHA-1/MD5 finalize 模式 (5×u32 byte-swap + 连续 20-byte
store 输出) auto-find. 当前 hash 输入找到了 (crypto-scan IV 命中) 但**输出位置**
没自动定位 — 这个会补齐.

### P1-C: fork / multi-process tracing (5d) ★

#### 决定 (已全部锁定)

| 决定 | 选择 |
|---|---|
| child 进入方式 | **spawn-gated**: child SIGSTOP, agent 注入后 resume |
| trace 输出组织 | **parent_pid/child_pid 两份独立 trace dir**, viewer 可同时 load (要同时看完整功能实现) |
| JNI hooks 在 child 是否重装 | **是, 都装** (child 也可能调 JNI; 反调试 fork 也是功能实现的一部分, 不区别对待) |
| child 减速导致 parent 崩溃 (F5) 处理 | **`--child-trace-mode=full\|safe` 选项, 默认 `full`** (= 抓到啥算啥, 红色警告). 用户遇到 F5 改 `safe` 重跑 (= 超 1s 自动 detach 保 parent) |
| `clone(2)` flags 区分 | **fork-like (`CLONE_THREAD==0`) 走本 P1-C 流程; thread-like (`CLONE_THREAD==1`) 仍走现有 `pthread_create` follow 路径** |

#### 关键洞察

Frida 17 spawn-gating 后, **child 不会"提前退出来不及 attach"** —— 它一直在 SIGSTOP
挂着, host 可无限等. **真正的风险是 timing detection** (parent 期望 child 50ms 退出,
我们慢吞吞 attach 用 2s, 父进程 timing-based 反调试触发).

#### 7 种失败模式 (F1-F7), 每种都要可观测

| ID | 场景 | 我们能拿到 | 缺失 | 用户提示 |
|---|---|---|---|---|
| F1 | 全程成功 | 一切 | — | 正常 |
| F2 | child 跑得比 agent init 还快 | parent PC, child PID, runtime, exit code | 指令 trace | "child 提前退出, agent 注入太慢" |
| F3 | child 自己 ptrace 父了 → attach 冲突 | parent PC, child PID, attach error | 指令 + exit code | "推 miku-shield 处理 ptrace 类反调试" |
| F4 | raw `clone(SIGCHLD)` Frida 没拦 | parent PC (额外 hook), child PID | 全部 child trace | "raw clone, 试 --extra-fork-syscalls" |
| F5 | parent 因 child 减速崩 | parent 崩前最后 idx, child 已抓部分 | 完整业务流程 | "timing detection, 改 `--child-trace-mode=safe`" |
| F6 | child SIGKILL 提前死 | parent PC, child PID, exit signal | 部分 trace | "child 被强杀, 可能业务正常" |
| F7 | spawn-gating 在该 Android 版本不 work | parent PC (从 fork hook), child PID 不知 | 全部 child 信息 | "检查 Frida 版本 / 升 Android" |

#### Tier 1 最低保证 (永远能拿到)

无论失败多惨, agent 在父进程 hook `fork` / `clone` / `vfork` / `clone3` syscall,
**永远记录** fork-event:

```json
{
  "type": "fork-event",
  "trace_idx": 1234567,           // 父 trace 中 fork 点 idx
  "parent_pc": "0x7608ed1234",    // fork 调用绝对 PC
  "parent_pc_rel": "0x6b234",     // SO 内偏移
  "parent_func": "sub_1a200",     // 哪个函数 fork 的
  "syscall": "clone",             // fork / vfork / clone / clone3
  "clone_flags": "0x1200011",     // 解 flags 区分 fork vs thread
  "is_fork_like": true,           // CLONE_THREAD==0 才进 P1-C
  "child_pid": 12345,             // fork 返回值
  "ts": 1730000000123,
  "attach_status": "success",     // F1-F7 状态
  "instructions_traced": 87234,
  "exit_code": 0,                 // 或 signal number (负数)
  "runtime_ms": 234,
  "notes": "..."
}
```

`attach_status` 取值: `success` / `success_partial` / `failed_ptrace_conflict` /
`failed_spawn_gate_unavailable` / `failed_unknown` / `not_attempted` (用户 `--no-fork-trace`).

#### attach 失败 fallback

- **agent 端 mandatory**: `Interceptor.attach(_fork/_clone/_vfork/_clone3)`,
  记录 fork-event Tier 1 (parent PC + child PID), **不依赖 spawn-gating**.
- **host 端 fallback**: spawn-gating 拦不到 / attach 失败时, 通过 `adb shell ps -p <pid>`
  轮询 + `/proc/<pid>/stat` 拿 child runtime + exit code (Tier 3 数据), 即没指令也有
  时间线和退出原因.

#### 用户可见的"知情" 输出

##### CLI 实时输出 (每次 fork 一段)

```
[trace] 14:23:01 [FORK] parent_idx=1234567 +0x6b234 (sub_1a200) → child pid=12345
[trace] 14:23:01 [FORK]   ✓ attached, agent injected (clone flags=0x1200011, fork-like)
[trace] 14:23:03 [FORK]   ⚠ child exited too fast (45ms < agent_init=120ms), no instructions
[trace] 14:23:03 [FORK]   notes: 可能 anti-debug short-lived check, 推 miku-shield 抓 syscall
```

##### Trace 完成后 fork summary

```
[trace] === Fork Summary ===
[trace] Total fork-like:   7   (thread-like clones 走 pthread_create, 不计)
[trace]   ✓ Fully traced:  3   (children of call_002, call_004, call_006)
[trace]   ⚠ Partial:       1   (child of call_003, 87 insns)
[trace]   ✗ Attach failed: 2   (F3 ptrace conflict / F7 spawn-gate unavailable)
[trace]   ⚠ Parent crashed:1   (F5 — child of call_005 减速 → parent timing detection)
[trace] 详见 traces/run1/calls/<dir>/meta.json `fork_events` 字段
[trace] 提示: 多个 child 抓不全, 可能这个 SO 用 fork-based anti-debug.
[trace]       推 miku-shield (eBPF kernel) 处理 fork 反调试: github.com/ltlly/miku-shield
```

##### Web SPA "Forks" tab

- 主 timeline 上每个 fork 点画 ⏎ 标记, 点击展开 fork 详情
- 表格: parent_idx, parent_func+offset, child_pid, status, runtime, instructions, [跳 child trace]
- 失败 fork **红色标出**, hover 显示具体 failure mode + 建议

##### CLI: `viewer fork-events <trace>`

```
viewer fork-events traces/run1
→ [{ all fork events with status, JSON list }]
```

LLM agent 一行调用查 fork 状态.

#### 实施分解 (M1-M8)

| 步骤 | 工作量 | 输出 |
|---|---|---|
| M1 | 0.5d | agent hook fork/clone/vfork/clone3 + 发 IPC fork-event Tier 1; clone flags 解析区分 fork-like vs thread-like |
| M2 | 1d | host 接 child 事件 + spawn-gating attach + 注入 agent (复用同 RPC opts) |
| M3 | 0.5d | attach 失败 fallback (proc 轮询 + exit code, Tier 3 数据) |
| M4 | 0.5d | child 独立 trace dir `call_NNN_pid_tid_...` + per-call meta.json `fork_events` 字段 |
| M5 | 0.5d | CLI 实时警告 + trace 末 fork summary 表 |
| M6 | 1d | Web SPA "Forks" tab + 主 timeline ⏎ 标记 + 红色失败标 + 跳 child trace |
| M7 | 0.5d | `viewer fork-events` 子命令 (CLI / `/api/fork-events`) |
| M8 | 1d | 测试: synth fork + 真机 anti-debug fork 模拟 (用 detect_suicide.js 改造) + 回归 |

**总计 ≈ 5.5d** (单人串行).

#### --child-trace-mode 选项细节

```
tracemiku trace ... --child-trace-mode=full     # 默认: 抓到啥算啥, F5 红警告但继续
tracemiku trace ... --child-trace-mode=safe     # F5 防御: child 超 1s 强 detach, 保 parent
tracemiku trace ... --no-fork-trace             # 禁用 P1-C, 只在 parent 记录 fork-event Tier 1
```

#### 参考

- Frida 17 `Process.spawn(child)` API + `enableChildGating`
- Linux kernel `clone(2)` flags (CLONE_THREAD / CLONE_VM / CLONE_FILES / SIGCHLD)
- Android Bionic `__bionic_clone` wrapper (调用 `clone` 系统调用)
- HardTaint 跨进程 taint 处理章节

### P1-D: ollvm-detect-vm 启发式提示 (3d)

启发式找 VM dispatcher: 高 entry count + `ldr [base, idx, lsl#3]` + indirect br +
`ldrh [...,#N]!` 自增 pattern.

**只做 detect, 不做 decode**. 输出形式:

```
viewer ollvm-detect-vm <trace>
→ {
    "candidates": [
      {"fn": "sub_169a10", "entry_count": 2791, "confidence": 0.85,
       "reason": "indirect br + 8-byte aligned load + 自增 IP pattern",
       "hint": "可能是 OLLVM VM dispatcher, 反向追踪时建议 skip 内部"}
    ]
  }
```

只标"可能是 OLLVM 或 VM", 因为高 block exec count + indirect dispatch 是充分非必要
特征. 用户最终判断.

### P1 内总耗时 ≈ 2 周 (并行做)

---

## 💡 P2 — 战略 / 待讨论

### P2-A: NEON / FP register record format v2 (1 周, 破坏向后兼容)

**确认要做**: 用户接受 "不在乎向后兼容, 能全量采集所有信息".

设计:
- `--include-neon` 选项 (默认关), 开启后 record 格式 v2, 加 32 个 V0..V31 (每 16 字节)
- record 物理大小 272 → 784 字节 (2.9x), trace.bin 大小 16GB → 47GB on 67M record
- `meta.json` 加 `record_version: 2` 标志, viewer 自适应 stride
- **自动检测**: tracemiku trace 时如发现 instruction 含 NEON reg (`v0`-`v31` /
  `s0`-`s31` / `d0`-`d31` / `q0`-`q31`), trace 完后日志输出: "目标函数包含 NEON
  指令, 当前未采 NEON 寄存器, 建议加 --include-neon 重新采集"
- 以下指令算 NEON: `fmul/fadd/...`, `add/sub/and/orr` with v?.? operand,
  `ld1/ld2/ld3/ld4`, `st1/st2/st3/st4`, `dup`, `umov`, `ins`, etc.

实现: agent CModule 加 NEON regfile 读取 (ARM64 fpsimd state), record 格式 v2 写
入; viewer trace.py / disasm.py / index.py / display.py 全链路 stride 改;
host CLI 自动检测扫描 disasm result 后发警告.

### P2-B: Native `libgumTraceMiku.so` (调研先于实现)

**用户问题**: "我好奇他对于 fork 多线程等怎么处理"

调研 task (1 周):
- 看 [revercc/gumTVM](https://github.com/revercc/gumTVM) 怎么处理 fork (子进程
  agent 怎么继承?)
- 看 multi-thread Stalker.follow 在 native 层怎么协调 (我们 v5 cmodule 已 SPSC,
  但只单 ring; 多线程要 per-thread ring 还是共享 ring?)
- 看砍 frida-server 后是用什么注入机制 (ptrace? PT_INTERP hijack?)
- 输出: 调研报告, 决定要不要开 native tracer

ROI: 中等. 主要为长期独立化准备 (砍 frida-server 依赖). 阻塞: miku-shield
方向决定后再启动.

### P2-C: anti-debug L3 fork+ptrace+SIGSEGV 突破 (3-5d)

**判定**: miku-shield (独立项目) 出后这层自动失效, traceMiku 这边**不再做**.

如果 miku-shield 短期不可用, fallback: P0-6 提示 + 用户自写 Frida bypass.

---

## ❄ 暂不做 (deferred, 不是 cancel)

| 项 | 原因 |
|---|---|
| **page-dirty 模式 (#52)** | 实际命中率 < 5%, 等出现具体 case 再做. JNI hooks 已覆盖主要 hostile 写场景. |
| **server.py 1588 行拆分** | 1300 行闭包要重构成 class, 高风险低收益. |
| **MemShadow word-level numpy 结构化数组** | 当前 dict 在 6.8M trace 上 GB 级内存可扛, 等 4GB 实际超限再做. |
| **CFG 布局换 ghidra Decompiler Layout** | graphviz `dot` 凑合用. |
| **`Index.def_chain` / `use_chain` 改用 stdlib `bisect`** | 微优化 5-10x 不影响用户. |
| **L5 glib `gmain` / `gdbus` 线程名** | miku-shield 出后自动失效. |

---

## 🚫 别做 (用户明确否决)

| 项 | 原因 |
|---|---|
| **P0-3 旧: drcov / EZCOV 输出** | 业务用不到, 不为 SEO 做事 |
| **P1-A 旧: HardTaint pointer-only selective** | 1GB 内可忍, 要全量信息 |
| **P1-B 旧: WebSocket streaming** | 采集崩了一半数据没了, 边采边看不符合场景 |
| **P1-D 旧: Pwntools/pwndbg 兼容** | 安卓 App pwndbg 是伪需求 |
| **P1-F 旧: VarBERT 集成** | 未来可能基于 trace 自写反编译器 |
| **P2-E 旧: 接 D-810-ng OLLVM VM decode** | 不做集成 |
| **P2-F 旧: dAngr symbolic execution** | angr 在加固 SO 几乎全 timeout, 投入产出不划算 |
| **P2-G 旧: ollvm-vm-trace** | VM IP 不一定在寄存器 (内存/栈/全局/交替/内联) |
| **P2-H 旧: Frida 17 unrooted Android** | LSP 和 repack 检测比 root 更严, 没 ETM 硬件 |
| **P2-I 旧: ARM CoreSight ETM** | 没硬件 |
| **自己写 OLLVM VM 反编译器** | 过度工程 |
| **重 link frida-agent.so 重命名 internal symbol** | miku-shield 路线替代 |
| **完整重做 frida-server** | stealth rename 已是恰当成本 |
| **分布式多机抓 trace** | 单机 + multi-process (P1-C) 已足够 |
| **TUI 任何新功能** | TUI 冻结决定不变 |

---

## 已知限制 (设计如此, 不修)

- **NEON/FP 寄存器没记** → 见 P2-A record v2 (现在确认要做).
- **字符串只能从 MemShadow 抠** — trace 没读到的字节没法识别字符串. 设计如此.
- **TUI (`viewer/app.py`) 冻结** — Web 是唯一 UI.

---

## miku-shield 边界 (独立项目, 不在 traceMiku 名下)

`miku-shield` 已独立成 GitHub 仓库 (`~/Code/miku-shield`), 是 traceMiku 的姐妹
项目, 不在本 TODO 维护范围. **traceMiku 跟 miku-shield 的唯一耦合点**:

- **P0-6 trace 报错提示**: 检测到 anti-debug 指纹时引用 miku-shield URL.
- README 加段 "L3+ 反调试推荐 miku-shield".

不做:
- ❌ tracemiku 自动 spawn miku-shield daemon (耦合度过高)
- ❌ 统一 CLI `miku trace` / `miku shield` (用户群不同)

---

# 待探讨

(按用户标记 "再探讨"; 下次 session 继续)

- miku-shield 与 traceMiku 协作的更多场景? (除 P0-6 错误诊断外)
- 自研反编译器路线 (vs 接 VarBERT) 的长期规划?
- P1-C 跨函数 taint 的 callee 选择策略 (走 trace 实际进入的还是 sym 静态调用图)?

---

# 关键参考资源

## 同类项目对照

- **Frinet** (Synacktiv SSTIC 2024) — https://github.com/synacktiv/frinet
- **Lighthouse** — https://github.com/gaasedelen/lighthouse
- **eDBG** (ShinoLeah) — https://github.com/ShinoLeah/eDBG (eBPF kernel breakpoint)

## 论文 / 研究

- **HardTaint** (OOPSLA 2024) — https://arxiv.org/abs/2402.17241
- **Purifire / "To Unpack or Not to Unpack"** (arXiv 2509.16340)
- **XTrace** (字节跳动 arXiv 2512.21555, 2025-12)

## 实操文档

- **DetectFrida** (darvincisec) — https://github.com/darvincisec/DetectFrida
- **NVISO: Patching ARM64 .init_array** —
  https://blog.nviso.eu/2025/10/14/patching-android-arm64-library-initializers-for-easy-frida-instrumentation-and-debugging/
- **PolyTracker TDAG** — https://github.com/trailofbits/polytracker
