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


def diagnose_trace_failure(logcat: str = "",
                           tombstone: str = "",
                           exception: Exception | None = None) -> list[str]:
    """Return user-facing hints (中文) based on observed failure indicators.

    Inputs:
      logcat:    last N lines of `adb logcat -d` output
      tombstone: contents of /data/tombstones/tombstone_NN if present
      exception: Python exception caught at attach/init/teardown
    """
    hints: list[str] = []

    if tombstone:
        # SI_USER → kernel-injected signal (tgkill/kill from userspace, not a fault).
        # Combined with a 1- or 2-frame backtrace ending in tgkill = self-suicide.
        si_user = "SI_USER" in tombstone or "code 0 (SI_USER)" in tombstone
        bt_lines = re.findall(r"^\s*#\d+\s+pc\s+\S+\s+(\S+)", tombstone, flags=re.M)
        if si_user and len(bt_lines) <= 2:
            hints.append(
                "诊断: 检测到 SI_USER + 浅栈 — 典型 L3+ 反调试自杀指纹 "
                "(tgkill/kill 自送 SIGSEGV 阻断 frida).")
            hints.append(
                f"建议: eBPF kernel-breakpoint 工具 miku-shield 可绕过此层. "
                f"{MIKU_SHIELD_URL}")
            hints.append(
                "或自写 Frida bypass: hook tgkill/kill 系列 syscall 在 svc 前替换 nop.")
        # SIGABRT in libfrida-agent.so → Frida 自递归崩溃
        if ("SIGABRT" in tombstone or "signal 6" in tombstone) and \
           "libfrida-agent.so" in tombstone:
            hints.append(
                "诊断: SIGABRT in libfrida-agent.so — Frida 自递归崩溃, "
                "可能 boundary-diff pattern 含 pthread/malloc/atomic 系列被自身命中.")
            hints.append(
                "建议: 检查 --boundary-diff-syms / --hostile-syms 不要含 "
                "pthread_*/malloc/free/atomic_load*. 见 ANALYSIS_XSIGN.md.")

    if exception is not None:
        cls = exception.__class__.__name__
        msg = str(exception).lower()
        if cls == "TimedOutError" or "timed out" in msg or "spawn" in msg.lower():
            hints.append(
                "诊断: spawn-gating 超时 — 可能 frida-server 未跑 / Android 版本不支持 "
                "spawn-gating / app 启动太慢被 anti-debug 检测.")
            hints.append(
                "建议: adb shell ps -A | grep frida-server 确认 server 在跑; "
                "用 --attach-pid <pid> 跳过 spawn-gating 直接 attach 已运行进程.")
        elif "process not found" in msg or "no such" in msg.lower():
            hints.append(
                "诊断: 目标进程不存在或已退出 — 反调试可能在 attach 前已干掉 frida-server, "
                "或 app 启动失败.")

    if logcat:
        # Look for tombstones generated during this session
        if "Tombstone written" in logcat or "tombstoned: received crash" in logcat:
            hints.append(
                "提示: logcat 显示 tombstone 已生成, "
                "用 `adb shell ls /data/tombstones/` 找最新的 dump 看具体 backtrace.")

    return hints
