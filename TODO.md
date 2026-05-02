# traceMiku Backlog / TODO

> 唯一 backlog 入口. README / tracer-README / CODE_REVIEW 等文档不再各自维护待办,
> 新增条目一律加到这里. 已完成的从这里删, 不留 strikethrough.
>
> 项目哲学 (从批注收敛): **全量信息 > 性能**, **真实业务场景 > 社区曝光**.
> 1GB trace 可忍受, 不做 selective insn; 不为 SEO 做 drcov; 不做 CTF 伪需求.

---

# 进度概览

## ✅ 已完成 (2026-05-02 single session)

### P0 (6/6) — 全部 ship + tests pass

| # | 项 | commit |
|---|---|---|
| P0-5 | taint cap=5000 + stopped_at_max + 加载全部按钮 + DoS clamp | 644b316 |
| P0-3 | Web 同步 11 个 CLI endpoint (4 batches A-D) | b9cd80c · 2788a47 · f29afdf · 6b04e3c |
| P0-2 | viewer 集成 jni_hooks.jsonl (Trace.jni_events lazy + display annot) | 6ff4860 |
| P0-4 | hex dump 紫色区分 external write (kind='x') | 174d063 |
| P0-6 | trace 失败诊断 + miku-shield URL hint | ba14908 |
| P0-1 | Call Tree tab (bl/ret pair walking) | 23c0829 |

### P1 (3.5/4) — A/B/D 全 ship, C 进行中

| # | 项 | commit | 备注 |
|---|---|---|---|
| P1-A | taint --cross-fn-call (frame_depth 标注) | 416c4fa | viewer-only, 全量 propagation 待真机 |
| P1-B | hash-finalize-detect (闭环 crypto-scan) | fbf735d | u32x5 / byte_seq, window-based |
| P1-D | ollvm-detect-vm heuristic | 4328364 | confidence-scored, 仅 detect 不 decode |
| P1-C M1 | agent fork hook (libc fork/clone/__bionic_clone) | 3406512 | **真机 PASS**, vfork 因 Bionic 调用约定不抓 |
| P1-C M7 | viewer fork-events read (CLI + /api + Trace.meta) | 5976c51 | 接收 agent 落盘 fork_events |

### 反 OLLVM 实战补强 — CLI 工具批 (基础已落地)

- `mem-writes-in-range`: numpy mask, 200 hits ~30ms
- `mem-flow`: per-byte event timeline (含 readers_only / writers_only)
- `crypto-scan`: 22 标准原语 (SHA1/SHA256/MD5/AES SBOX+invSBOX+Rcon/TEA/
  ChaCha20/HMAC ipad/opad/SM3/SM4/Blake2/CRC32, LE 字节序内置)
- `taint-bwd/fwd --through-mem`: byte 级 mem overlap
- `find-mem-pattern --idx-lo/hi`: first_idx 范围过滤
- `reg-at-idx`, `call-chain`, `hash-input-search`, `auto-phase-detect`,
  `diff-traces`, `hash-finalize-detect`, `ollvm-detect-vm`, `fork-events`
- `MemShadow` sidecar 持久化 (`.memshadow.v2.npz`): cold 37s → warm 6s

### 解耦项目特定目标

- agent_cmodule_v5/v3.js 删 hardcoded `soPattern: "libsgmainso"` / `fnOffset`
- `SGMAIN_TGKILL_SVC_OFFSETS` → JSON spec (`tools/hooks/<so>_suicide.json`)
- `_hideMaps_filterLine` 用 STATE.soPattern 动态匹配
- 8 处 docstring + webui dropdown 抽象化

**累计 (含 M1 真机)**: 16 commits, 426 unit tests pass + 1 skip + 1 manual smoke (real device).

---

## ⏳ 进行中: P1-C fork tracing M2-M8

M1+M7 已 ship + 真机验证. 剩余 milestone:

| 步骤 | 工作量 | 输出 | 真机依赖 |
|---|---|---|---|
| M2 | 1d | host 接 child 事件 + spawn-gating attach + 注入 agent | ✓ |
| M3 | 0.5d | attach 失败 fallback (proc 轮询 + exit code, Tier 3) | ✓ |
| M4 | 0.5d | child 独立 trace dir `call_NNN_pid_tid_...` + per-call meta `fork_events` | ✓ (M1 已写部分) |
| M5 | 0.5d | CLI 实时警告 + trace 末 fork summary 表 | 部分 |
| M6 | 1d | Web SPA "Forks" tab + 主 timeline ⏎ 标记 + 跳 child trace | — |
| M8 | 1d | 测试: synth fork + 真机 anti-debug fork 模拟 (detect_suicide.js 改造) | ✓ |

**已知 gap (P1-C)**:
- vfork() 在 Bionic 上 hook 不到 (特殊调用约定 bypass Interceptor.onLeave). 已 deprecated, 实际反调试场景几乎不用 → 不修.
- M2 需要 Frida 17 child-gating, 待验证 miku-srv 是否支持.
- F5 (parent 因 child 减速崩) 需要 timing detection 真机复现.

---

# P1-C 设计 spec (M2-M8 实施参考)

## 决定 (已全部锁定)

| 决定 | 选择 |
|---|---|
| child 进入方式 | **spawn-gated**: child SIGSTOP, agent 注入后 resume |
| trace 输出组织 | **parent_pid/child_pid 两份独立 trace dir**, viewer 可同时 load |
| JNI hooks 在 child 是否重装 | **是, 都装** (反调试 fork 也是功能实现一部分) |
| F5 处理 | **`--child-trace-mode=full\|safe`, 默认 `full`** (= 抓到啥算啥, 红警告). 改 `safe` = 超 1s detach 保 parent |
| `clone(2)` flags 区分 | **fork-like (`CLONE_THREAD==0`) 走 P1-C; thread-like 仍走 `pthread_create` follow** |

## 7 种失败模式 (F1-F7)

| ID | 场景 | 拿到 | 缺失 | 用户提示 |
|---|---|---|---|---|
| F1 | 全程成功 | 一切 | — | 正常 |
| F2 | child 跑得比 agent init 还快 | parent PC, child PID, runtime, exit | 指令 trace | "child 提前退出" |
| F3 | child 自己 ptrace 父了 | parent PC, child PID, attach error | 指令 + exit | "推 miku-shield" |
| F4 | raw `clone(SIGCHLD)` Frida 没拦 | parent PC (额外 hook), child PID | 全部 child trace | "试 --extra-fork-syscalls" |
| F5 | parent 因 child 减速崩 | parent 崩前 idx | 完整业务 | "改 `--child-trace-mode=safe`" |
| F6 | child SIGKILL 提前死 | parent PC, child PID, exit signal | 部分 trace | "child 被强杀" |
| F7 | spawn-gating 不 work | parent PC, child PID 不知 | 全部 child | "检查 Frida / 升 Android" |

## Tier 1 最低保证 (M1 已实现)

```json
{
  "type": "fork-event",
  "trace_idx": 1234567,
  "parent_pc": "0x7608ed1234",
  "parent_pc_rel": "0x6b234",
  "parent_in_target": true,
  "parent_module": "libtarget.so",
  "syscall": "clone",
  "clone_flags": "0x1200011",
  "is_fork_like": true,
  "child_pid": 12345,
  "ts": 1730000000123,
  "attach_status": "not_attempted"
}
```

`attach_status`: `not_attempted` (M1, 当前) → `success` / `success_partial` /
`failed_ptrace_conflict` / `failed_spawn_gate_unavailable` / `failed_unknown` (M2/M3 后).

## 用户可见输出 (M5/M6 待实现)

### CLI 实时 (每 fork 一段) — M5

```
[trace] [FORK] parent_idx=1234567 +0x6b234 (sub_1a200) → child pid=12345
        ✓ attached, agent injected (clone flags=0x1200011, fork-like)
        ⚠ child exited too fast (45ms < agent_init=120ms), no instructions
        notes: 可能 anti-debug short-lived check, 推 miku-shield
```

### Trace 完成后 fork summary — M5

```
=== Fork Summary ===
Total fork-like:   7
  ✓ Fully traced:  3
  ⚠ Partial:       1   (child of call_003, 87 insns)
  ✗ Attach failed: 2   (F3 ptrace conflict / F7 spawn-gate unavailable)
  ⚠ Parent crashed:1   (F5 — child of call_005 → timing detection)
提示: 多个 child 抓不全, 可能这个 SO 用 fork-based anti-debug.
      推 miku-shield: github.com/ltlly/miku-shield
```

### Web SPA "Forks" tab — M6

- 主 timeline 上每个 fork 点画 ⏎ 标记, 点击展开
- 表格: parent_idx · parent_func+offset · child_pid · status · runtime · instructions · [跳 child trace]
- 失败 fork 红色, hover 显示具体 failure mode + 建议

### CLI / `/api/fork-events` — M7 已 ship

```bash
viewer fork-events traces/run1
viewer fork-events traces/run1 --status failed_ptrace_conflict
GET /api/fork-events?status=failed_ptrace_conflict
```

## --child-trace-mode 选项

```
tracemiku trace ... --child-trace-mode=full     # 默认: 抓到啥算啥, F5 红警告
tracemiku trace ... --child-trace-mode=safe     # F5 防御: child 超 1s 强 detach
tracemiku trace ... --no-fork-trace             # 禁用 P1-C, 仅 parent 记录 Tier 1
```

## 参考

- Frida 17 `Process.spawn(child)` API + `enableChildGating`
- Linux kernel `clone(2)` flags (CLONE_THREAD/CLONE_VM/CLONE_FILES/SIGCHLD)
- Android Bionic `__bionic_clone` wrapper
- HardTaint 跨进程 taint 处理章节

---

# P2 — 战略 / 待讨论

## P2-A: NEON / FP register record format v2 (1 周)

**确认要做** (用户接受 "不在乎向后兼容, 全量采集"):
- `--include-neon` 选项, 开启后 record v2 加 32 个 V0..V31 (16B each)
- record 大小 272 → 784 字节, trace.bin 16GB → 47GB on 67M rec
- `meta.json` 加 `record_version: 2`, viewer 自适应 stride
- **自动检测**: trace 完毕 disasm 扫到 v?/s?/d?/q? operand → 日志提示
  "目标含 NEON, 建议加 --include-neon 重采"

实现: agent CModule 加 NEON regfile 读取 (ARM64 fpsimd state) + record v2 写入;
viewer trace.py / disasm.py / index.py / display.py 全链路 stride 改;
host CLI 自动检测扫描后发警告.

## P2-B: Native `libgumTraceMiku.so` (调研先于实现)

**用户问题**: "好奇他对 fork 多线程怎么处理"

调研 task (1 周):
- 看 [revercc/gumTVM](https://github.com/revercc/gumTVM) 怎么处理 fork
- 多线程 Stalker.follow native 层协调 (per-thread ring 还是共享 ring?)
- 砍 frida-server 后注入机制 (ptrace? PT_INTERP hijack?)
- 输出: 调研报告决定是否开 native tracer

ROI 中等. 主要为长期独立化准备. 阻塞: miku-shield 方向决定后启动.

## P2-C: anti-debug L3 fork+ptrace+SIGSEGV 突破 (3-5d)

**判定**: miku-shield 出后这层自动失效, traceMiku **不再做**.
miku-shield 短期不可用 → fallback: P0-6 提示 + 用户自写 Frida bypass.

---

# ❄ 暂不做 (deferred, 不是 cancel)

| 项 | 原因 |
|---|---|
| **page-dirty 模式 (#52)** | 实际命中率 < 5%, 等出现具体 case 再做 |
| **server.py 1588 行拆分** | 1300 行闭包要重构成 class, 高风险低收益 |
| **MemShadow word-level numpy 结构化数组** | 当前 dict 在 6.8M trace 上 GB 级可扛, 等 4GB 超限再做 |
| **CFG 布局换 ghidra Decompiler Layout** | graphviz `dot` 凑合用 |
| **`Index.def_chain` / `use_chain` 改 stdlib `bisect`** | 微优化 5-10x 不影响用户 |
| **L5 glib `gmain` / `gdbus` 线程名** | miku-shield 出后自动失效 |
| **taint 跨函数全量 propagation** | P1-A 已加 frame_depth 标注; 全量 propagation 待真机验证后再扩展 |

---

# 🚫 别做 (用户明确否决)

| 项 | 原因 |
|---|---|
| drcov / EZCOV 输出 | 业务用不到, 不为 SEO 做事 |
| HardTaint pointer-only selective | 1GB 内可忍, 要全量信息 |
| WebSocket streaming | 采集崩了一半数据没了, 边采边看不符合场景 |
| Pwntools/pwndbg 兼容 | 安卓 App pwndbg 是伪需求 |
| VarBERT 集成 | 未来可能基于 trace 自写反编译器 |
| D-810-ng OLLVM VM decode | 不做集成 |
| dAngr symbolic execution | 加固 SO 几乎全 timeout, 投入产出不划算 |
| ollvm-vm-trace | VM IP 不一定在寄存器 (内存/栈/全局/交替/内联) |
| Frida 17 unrooted Android | LSP 和 repack 检测比 root 更严, 没 ETM 硬件 |
| ARM CoreSight ETM | 没硬件 |
| 自己写 OLLVM VM 反编译器 | 过度工程 |
| 重 link frida-agent.so 重命名 internal symbol | miku-shield 路线替代 |
| 完整重做 frida-server | stealth rename 已是恰当成本 |
| 分布式多机抓 trace | 单机 + multi-process (P1-C) 已足够 |
| TUI 任何新功能 | TUI 冻结决定不变 |

---

# 已知限制 (设计如此, 不修)

- **NEON/FP 寄存器没记** → 见 P2-A record v2 (确认要做).
- **vfork() 在 Bionic 上 hook 不到** (P1-C M1) — 已 deprecated, 实际反调试场景不影响.
- **字符串只能从 MemShadow 抠** — trace 没读到的字节没法识别字符串.
- **TUI (`viewer/app.py`) 冻结** — Web 是唯一 UI.

---

# miku-shield 边界 (独立项目, 不在 traceMiku 名下)

`miku-shield` (~/Code/miku-shield, github.com/ltlly/miku-shield) 是 traceMiku 的姐妹
项目, 不在本 TODO 维护. **唯一耦合点**:

- **P0-6 trace 报错提示**: 检测到 anti-debug 指纹时引用 miku-shield URL.
- README 加段 "L3+ 反调试推荐 miku-shield".

不做:
- ❌ tracemiku 自动 spawn miku-shield daemon
- ❌ 统一 CLI `miku trace` / `miku shield` (用户群不同)

---

# 待探讨

- miku-shield 与 traceMiku 协作的更多场景? (除 P0-6 错误诊断外)
- 自研反编译器路线 (vs 接 VarBERT) 的长期规划?
- P1-A 跨函数 taint 的 callee 选择策略 (走 trace 实际进入的还是 sym 静态调用图)?

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
