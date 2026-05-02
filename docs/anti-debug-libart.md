# libsgmainso 6.8.260403 anti-debug — libart integrity check

实测复盘 (2026-05-02, Taobao com.taobao.taobao + cmd 70102 doCommandNative).

## 结论

`--trace-deep` 触发 anti-debug; 不用 `--trace-deep` trace 跑完整 (15.4M records).

## 实验对照

| 配置 | records | 结果 |
|---|---|---|
| minimal (无 deep/hide/patch/jni-hooks) | 15.4M | ✓ ret=0x787a681615 |
| `--patch-suicide` 单独 | 7.7M+ | ✓ |
| `--hide-rwx-maps` 单独 | 9.7M | ✓ |
| **`--trace-deep` 单独** | **60k** | ✗ SI_USER (kernel-injected) |
| Bare Frida attach (无 Stalker) | n/a | ✓ 0 kill events 25s |

## 根因架构

```
MainThread (MTOPSDK Request, tid 我们 trace 的)         AntiDebugThread (我们没 trace)
─────────────────────────────────────────              ─────────────────────────────────
doCommandNative (libsgmainso+0x57770)                   periodic loop:
  ↓ 跑 cmd 70102 业务逻辑                                  sleep(N ms)
  ↓                                                       ┌─ 检查项 (--trace-deep 触发):
  blr sub_145f9c (= JavaVM->GetEnv)                       │   inline-patch detection:
  ↓                                                       │   读 libart .text bytes 与
  ret  ←─── tgkill(pid, main_tid, SIGSEGV) ──────────────┤   /system/lib64/libart.so
                                                          │   disk image 比对.
       (signal 到达, 主线程 trace 在 ret 处停住)          │   因为 Stalker per-symbol
                                                          │   exclude libart 时, 在
                                                          │   excluded symbol BOUNDARY
                                                          │   inline-hook libart .text →
                                                          │   bytes mismatch → 检测.
                                                          └─ 命中 → tgkill self-kill
```

## 主线程零 libart 写, 也零 .text 读

- 成功 trace (15.4M records) 和失败 trace (1M records, --follow-workers) 主线程 mem ops 中:
  - libart `.data/.got` 范围读: 56 次 (正常 JNI vtable lookup)
  - libart `.text` 范围读/写: **0 次**
- 检测一定在另一个 thread (我们没 trace 到的 anti-debug worker)

## tgkill dispatcher 架构

`patch-suicide` 现在打的 6 个 inline `svc #0` 是 **dispatcher 末端**, 不是反调试 caller:

```
anti-debug detection fn (worker thread, 未 trace)
  ↓ 检测命中, 决定调 tgkill
  ↓
sub_45bbe0(syscall_args_struct, extra)   ← libsgmainso+0x5bbe0, generic syscall wrapper
  ↓ if (arg1) sub_454eac(*arg1, arg1[2], arg1[4], arg1[6], arg2)
  ↓
sub_454eac (1 of 6 dispatchers)   ← 走 OLLVM 状态机, 末端 mov x8, x6; svc #0
  ↓
svc #0    ← patch-suicide patch 此处 → nop. 但 anti-debug 可能调其他 dispatcher.
```

**为什么 patch-suicide 不够**: anti-debug 走的 dispatcher 可能是另一组 (我们没枚举完整).
`movz x?, #131` 共 38 处 (rd=8: 21, rd=5: 5, rd=9: 10), 但只 6 处直接 `movz x8, #131; svc`,
其他通过 OLLVM 算法间接到 x6/x8. 完整 patch 需逆所有 dispatcher.

## 根本对策

| 路径 | 难度 | 效果 |
|---|---|---|
| **不用 `--trace-deep`** (当前 fix, P0-6 已 ship) | ✓ | 主流程通跑 |
| **hook libc `tgkill`/`tkill`/`kill`/`pthread_kill`/`raise`** | 简单 | 拦所有 signal-based 自杀 (新 flag `--block-self-kill`) |
| **逆向 anti-debug worker 函数 patch 检测点** | 难 (每版本逆) | 精准 |
| **miku-shield (eBPF)** | 规划中 | 根治 — kernel 层无 ptrace, 无 RWX, 不可见 |

## 主线程死亡点不是检测点

trace 总停在 `sub_145f9c` ret 是巧合: kill signal wall-clock 到达时主线程恰在执行
那条 `ret`. 死亡 PC 跟检测 PC 无关.

## 用 P0-6 自动诊断

更新后 `tracemiku_diag.diagnose_trace_failure()` 在 SI_USER + 深栈 + `cli_args.trace_deep=True`
时自动建议关 `--trace-deep`. 真机 verify_diag 重现确认输出.

```
=== Trace 死前诊断 (P0-6) ===
诊断: SI_USER + 深栈 — anti-debug 检测到 Frida 痕迹后 self-kill ...
强烈建议: 关 --trace-deep 重跑. ...
```
