"""Trace-failure diagnostics: match tombstone/logcat/exception signatures
to actionable hints. Pure function — no side effects, no IO.

Used by `tracemiku trace` host CLI when attach/init fails or target crashes.
The main signal for L3+ anti-debug is SI_USER (kernel-injected) + a 1- or
2-frame stack ending in tgkill — classic self-suicide pattern.

This module is the ONLY official coupling point between traceMiku and
miku-shield: on confirmed L3+ anti-debug, hints recommend the sister
project URL (github.com/ltlly/miku-shield) for eBPF kernel breakpoint.
"""

from __future__ import annotations
import re

MIKU_SHIELD_URL = "https://github.com/ltlly/miku-shield"


def diagnose_trace_failure(
    logcat: str = "",
    tombstone: str = "",
    exception: Exception | None = None,
    cli_args: dict | None = None,
) -> list[str]:
    """Return user-facing hints (中文) based on observed failure indicators.

    Inputs:
      logcat:    last N lines of `adb logcat -d` output
      tombstone: contents of /data/tombstones/tombstone_NN if present
      exception: Python exception caught at attach/init/teardown
      cli_args:  dict of CLI flags (trace_deep, patch_suicide, hide_rwx_maps,
                 jni_hooks etc) — used to suggest scaling back invasive flags.
    """
    hints: list[str] = []
    cli_args = cli_args or {}

    if tombstone:
        # SI_USER → kernel-injected signal (tgkill/kill from userspace, not a fault).
        # Combined with a 1- or 2-frame backtrace ending in tgkill = self-suicide.
        si_user = "SI_USER" in tombstone or "code 0 (SI_USER)" in tombstone
        bt_lines = re.findall(r"^\s*#\d+\s+pc\s+\S+\s+(\S+)", tombstone, flags=re.M)
        if si_user and len(bt_lines) <= 2:
            hints.append(
                "诊断: 检测到 SI_USER + 浅栈 — 典型 L3+ 反调试自杀指纹 "
                "(tgkill/kill 自送 SIGSEGV 阻断 frida)."
            )
            hints.append(
                f"建议: eBPF kernel-breakpoint 工具 miku-shield 可绕过此层. "
                f"{MIKU_SHIELD_URL}"
            )
            hints.append(
                "或自写 Frida bypass: hook tgkill/kill 系列 syscall 在 svc 前替换 nop."
            )
        elif si_user:
            # SI_USER + DEEP backtrace = anti-debug detected something Frida-related
            # (Stalker block-cache rewrites in libart, /proc/self/maps, etc.) and called
            # self-kill via a non-trivial code path. Most common cause: --trace-deep
            # follows libart → Stalker rewrites libart code → a hardened SO's integrity
            # check detects the rewrite → tgkill self-kill.
            hints.append(
                "诊断: SI_USER + 深栈 — anti-debug 检测到 Frida 痕迹后 self-kill "
                "(常见: Stalker 重写 libart 代码段被 CRC 校验抓到)."
            )
            if cli_args.get("trace_deep"):
                hints.append(
                    "强烈建议: 关 --trace-deep 重跑. trace-deep 让 Stalker 跟进 libart, "
                    "block-cache rewrites 容易被 anti-debug 校验抓. 实测重防护 SO "
                    "在深度模式下跑几万条记录就会触发自杀 (关 --trace-deep 可跑完 "
                    "千万级记录)."
                )
            else:
                hints.append(
                    "建议: 试 miku-shield (eBPF, 无 ptrace 无 RWX 痕迹) 或自写更窄的 "
                    "Stalker include 范围, 减少跟踪到 libart/libc 的可能."
                )
        # SIGABRT in libfrida-agent.so → Frida 自递归崩溃
        if (
            "SIGABRT" in tombstone or "signal 6" in tombstone
        ) and "libfrida-agent.so" in tombstone:
            hints.append(
                "诊断: SIGABRT in libfrida-agent.so — Frida 自递归崩溃, "
                "可能 boundary-diff pattern 含 pthread/malloc/atomic 系列被自身命中."
            )
            hints.append(
                "建议: 检查 --boundary-diff-syms / --hostile-syms 不要含 "
                "pthread_*/malloc/free/atomic_load*."
            )

    if exception is not None:
        cls = exception.__class__.__name__
        msg = str(exception).lower()
        if cls == "TimedOutError" or "timed out" in msg or "spawn" in msg.lower():
            hints.append(
                "诊断: spawn-gating 超时 — 可能 frida-server 未跑 / Android 版本不支持 "
                "spawn-gating / app 启动太慢被 anti-debug 检测."
            )
            hints.append(
                "建议: adb shell ps -A | grep frida-server 确认 server 在跑; "
                "用 --attach-pid <pid> 跳过 spawn-gating 直接 attach 已运行进程."
            )
        elif "process not found" in msg or "no such" in msg.lower():
            hints.append(
                "诊断: 目标进程不存在或已退出 — 反调试可能在 attach 前已干掉 frida-server, "
                "或 app 启动失败."
            )

    if logcat:
        # Look for tombstones generated during this session
        if "Tombstone written" in logcat or "tombstoned: received crash" in logcat:
            hints.append(
                "提示: logcat 显示 tombstone 已生成, "
                "用 `adb shell ls /data/tombstones/` 找最新的 dump 看具体 backtrace."
            )

    return hints
