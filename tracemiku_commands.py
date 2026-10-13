"""统一入口的设备参数与能力发现；分析参数直接来自 Rust clap。"""

import argparse
import json


def build_parser():
    ap = argparse.ArgumentParser(
        prog="tracemiku", description="Android ARM64 trace 采集与离线分析",
        epilog="分析命令: records / resolve / reg-at / mem-export / taint-bwd / vm-ops。"
               "使用 capabilities 查看清单，capabilities --command <name> 查看完整参数。",
    )
    sp = ap.add_subparsers(dest="subcommand", required=True)
    p_caps = sp.add_parser("capabilities", help="发现采集与分析命令")
    p_caps.add_argument("--command", help="仅返回指定命令的完整参数与默认值")
    # trace
    p_tr = sp.add_parser("trace", help="采集 trace")
    p_tr.add_argument("--pkg", required=False, help="目标 app 包名")
    p_tr.add_argument("--attach-pid", type=int, help="直接附加 pid")
    p_tr.add_argument("--so", required=False, help="目标 SO 名子串 (或由 --target-profile 提供)")
    p_tr.add_argument("--target-profile", help="可信目标 JSON 配置；相对脚本路径按配置所在目录解析")
    p_tr.add_argument("--transport", choices=("frida", "adb"), default="frida",
                      help="trace/sidecar 回传通道；frida 不经过设备 fork/exec 且保留源文件")
    p_tr.add_argument("--max-calls", type=int, default=64, help="每会话 call 上限 (1..1024)")
    p_tr.add_argument("--method", help="JNI 注册方法名 (动态注册)")
    p_tr.add_argument("--export", help="SO 导出函数名 (静态导出)")
    p_tr.add_argument("--fn-offset", help="SO 内函数偏移 (16进制如 0x1234)")
    p_tr.add_argument("--cmd", type=int, help="JNI 入口整数参数过滤值 (只 trace 该参数等于此值的调用; 不传则不过滤)")
    p_tr.add_argument("--cmd-arg", type=int, default=None, help="过滤参数下标 0-based (需配合 --cmd 使用, 无目标默认值)")
    p_tr.add_argument("--include-so", default="", dest="include_so",
                      help="逗号分隔, 额外 trace 这些 SO (除目标外). e.g."
                           " 'libfoo,libbar,libcrypto'."
                           " HARD_EXCL (libc/libart/linker etc) 永远排除 — 即使列在这里也忽略.")
    p_tr.add_argument("--trace-deep", action="store_true", dest="trace_deep",
                      help="深度模式: 不再 module-level 排除 libart/libc. 改成 per-symbol "
                           "Stalker.exclude (interpreter/JIT/GC/atomic primitives 这些 LDXR/STXR "
                           "或 ART 自修改不安全的函数). 大部分 libart 函数 (NewStringUTF / "
                           "GetField 等) 现在能被 Stalker 跟到. linker/libdl 仍整 module 排除.")
    p_tr.add_argument("--trace-all", action="store_true", dest="trace_all",
                      help="全量模式: 捕获经过的每一条汇编 — 目标 SO + 所有 userland/vendor SO + "
                           "libc/libm (现在安全, LDXR/STXR 原子死锁已由 transform 内 iter.memoryAccess "
                           "逐指令守卫解决). module 级排除 linker/linker64/libdl (结构性递归) 和 "
                           "ART apex 家族 (libart/libartbase/libartpalette). 注意: ART 解释器/JIT/GC "
                           "是自修改+运行时重定位代码且 runtime stripped, Stalker 无法跟 (实测必 SIGSEGV), "
                           "故活的 Java 字节码执行**不可** trace — 这是 Frida 硬限制, 需硬件 trace (ETM). "
                           "可恢复 stat/time 等 libc 边界写. 反调试默认**关闭** —— "
                           "有反检测的目标需显式加 --patch-suicide / --hide-rwx-maps / "
                           "--block-self-kill.")
    p_tr.add_argument("--trace-exec", action="store_true",
                      help="放开 libc/libm/libdl/libpthread (memcpy/memset 会写输出缓冲), "
                           "但继续排除 libart 与 linker。比 --trace-deep 安全: "
                           "libart 是自修改+stripped 代码, Stalker 跟进必然 SIGSEGV")
    p_tr.add_argument("--stalker-exclude-patterns", default=None, dest="stalker_exclude_patterns",
                      help="逗号分隔, 覆盖默认 Stalker.exclude 名单 (per-symbol). 仅 --trace-deep 下生效.")
    p_tr.add_argument("--boundary-diff-patterns", default=None, dest="boundary_diff_patterns",
                      help="逗号分隔, 在这些函数装 Interceptor 抓内存写 (boundary ptr-diff). "
                           "**严禁包含 pthread/malloc/atomic** — Frida 自己用这些, attach 会崩进程. "
                           "默认空. 不需要 --trace-deep; 可用于 stat@@/stat64@@ 这类外部输出结构.")
    p_tr.add_argument("--ext-write-cap", type=int, default=0, dest="ext_write_cap",
                      help="external_writes.bin 事件总量上限 (0 = 不设限). 默认 0.")
    p_tr.add_argument("--patch-suicide", action="store_true", dest="patch_suicide",
                      help="启用 anti-anti-frida tgkill svc → nop patching. 必须通过 "
                           "--suicide-patch-spec PATH 显式传 JSON spec. 仅 --trace-deep 下生效.")
    p_tr.add_argument("--suicide-patch-spec", default=None,
                      dest="suicide_patch_spec",
                      help="JSON spec for tgkill svc patches (offset list per SO version). "
                           "目标/版本相关 spec 放在 tools/hooks/ 或 examples/ 中, 不作为通用默认值.")
    p_tr.add_argument("--hide-rwx-maps", action="store_true", dest="hide_rwx_maps",
                      help="在 libc open/read 拦截 /proc/self/maps, 过滤 rwxp 匿名段 — 让反检测"
                           "看不到 Frida Stalker block cache 的 rwx. 通用反检测绕过, 不依赖目标 SO.")
    p_tr.add_argument("--block-self-kill", action="store_true", dest="block_self_kill",
                      help="hook libc kill/tgkill/tkill/pthread_kill/raise/abort, 阻断 signal 自杀路径；"
                           "默认关，和 --patch-suicide 的 inline SVC patch 互补。")
    p_tr.add_argument("--enable-fork-hook", action="store_true", dest="enable_fork_hook",
                      help="hook libc fork/vfork/clone/__bionic_clone, 抓 fork-event Tier 1 "
                           "(parent_pc, child_pid, clone_flags) 写到 meta.json fork_events. "
                           "P1-C M1; 反调试 fork 检测必开. 默认关.")
    p_tr.add_argument("--no-fork-poll-child", action="store_false", dest="fork_poll_child",
                      default=True,
                      help="禁用 child 进程 lifecycle 后台轮询 (Tier 3 数据). 默认开 — "
                           "agent fork hook 抓到 child PID 后, 起一个后台线程 adb shell "
                           "/proc/<pid>/stat 直到 child 退出, 记录 runtime_ms / last_state. "
                           "P1-C M3 fallback.")
    p_tr.add_argument("--child-trace-mode", default="off", dest="child_trace_mode",
                      choices=["off", "full", "safe"],
                      help="P1-C M2 child race-attach. off (默认) = 只 Tier 1 fork-event; "
                           "full = agent fork-event 一到立即 attach child PID + 注入 same agent. "
                           "短命 child (anti-debug 50-200ms) 可能 attach 不上, 标 "
                           "failed_short_lived. safe = 当前实现同 full (限制语义待后续实现). "
                           "注意: Frida enable_spawn_gating 不抓 fork() 子进程 "
                           "(只对 device.spawn() 后裔生效, 实测 2026-05), 故走 race-attach.")
    p_tr.add_argument("--jni-hooks", default="tools/hooks/libart_jni.json", dest="jni_hooks",
                      help="JSON 描述要 hook 的 JNI vtable 函数 (offset/参数类型/返回类型). "
                           "默认 = libart string fns. 设 'none' 关闭. 输出 jni_hooks.jsonl per-call. "
                           "Interceptor 不依赖 Stalker, 给重防护 app 的备选方案 (低反检测面).")
    p_tr.add_argument("--semantic-events", action="store_true", dest="semantic_events",
                      help="开启采集侧语义事件 sidecar: syscall/libc/JNI 事件写入 per-call "
                           "semantic_events.jsonl. 默认关闭, 不影响 trace.bin 272B 主格式.")
    p_tr.add_argument("--simd-sidecar", action="store_true", dest="simd_sidecar",
                      help="开启可选 SIMD/Q 寄存器快照 sidecar, per-call 输出 simd_trace.bin. "
                           "默认关闭, 避免放大采集数据量.")
    p_tr.add_argument("--simd-sample-stride", type=int, default=1, dest="simd_sample_stride",
                      help="SIMD sidecar 采样步长: 1=每条指令保存 q0-q31, N=每 N 条保存一次. "
                           "仅 --simd-sidecar 生效.")
    p_tr.add_argument("--snapshot-mem", action="store_true", dest="snapshot_mem",
                      help="trace 开始时 (目标函数入口, t=0) 快照真实设备内存到 memory_snapshot.bin. "
                           "MemShadow 用作 `i` 层 fallback, 补齐 trace 窗口之前初始化的数据 "
                           "(已解密的 VM 字节码表 / .rodata 常量 / 嵌入密钥 等). "
                           "捕获目标 SO 各段 + 可读 rw-/匿名/堆区. 见 docs/memory-completeness-design.md.")
    p_tr.add_argument("--snapshot-max-mb", type=int, default=512, dest="snapshot_max_mb",
                      help="--snapshot-mem 的字节预算上限 (MB), 默认 512. 保护设备不被大快照拖垮.")
    p_tr.add_argument("--ring-recs", type=int, default=0,
                      help="Stalker ring 容量(条, 默认由 --max-records 推导; "
                           "上限 4194304 ≈ 1.14GB)。窗口被静默截断时用它放大")
    p_tr.add_argument("--max-records", type=int, default=5000000)
    p_tr.add_argument("--pull-after-session-end", action="store_true",
                      help="等采集会话结束再拉取 (默认每个 call 结束立刻拉: 被 trace 的"
                           "目标会拖死设备侧 adbd, 之后只能重启 adb server 才能恢复)")
    p_tr.add_argument("--no-stop-after-trace", dest="stop_after_trace",
                      action="store_false", default=True,
                      help="采集结束后不停掉目标进程 (默认停, 以恢复被拖死的 adb 通道; "
                           "仅对本工具 spawn/launch 的 app 生效)")
    p_tr.add_argument("--follow-workers", action="store_true",
                      help="跟踪 pthread_create 新生成的 worker 线程 (异步函数才需要; 默认关，不然重防护 app 易闪退)")
    p_tr.add_argument("--max-worker-threads", type=int, default=4, dest="max_worker_threads",
                      help="--follow-workers 最多跟踪的新线程数，默认 4，agent clamp 上限 32")
    p_tr.add_argument("--no-workers", action="store_true", help="(deprecated, 默认就是不跟)")
    p_tr.add_argument("--duration", type=int, default=120)
    p_tr.add_argument("--out", required=True, help="输出目录")
    p_tr.add_argument("--remote", default=None,
                      help="frida-server TCP 地址 (如 127.0.0.1:6699). "
                           "不传则默认走 USB 连接.")
    p_tr.add_argument("--launch", action="store_true",
                      help="非破坏式启动 app: force-stop+monkey 后立刻 attach, 不执行 pm clear")
    p_tr.add_argument("--spawn", action="store_true",
                      help="Frida spawn-gating 模式, 行为与 frida 直接 spawn 一致: "
                           "enable_spawn_gating → device.spawn(pkg) 挂起 → attach + agent init → resume. "
                           "不 force-stop/不 pm clear; 需 --pkg, 与 --launch/--attach-pid 互斥")

    # doctor (pre-flight device check)
    p_doc = sp.add_parser("doctor", help="检查设备 trace 前置条件 (adb/root/frida/SELinux)")
    p_doc.add_argument("--pkg", default=None, help="目标 app 包名 (检查是否安装)")
    p_doc.add_argument("--out", default=None, help="trace 输出目录 (检查是否可写)")

    # probe (lightweight Interceptor-only counting, no Stalker)
    p_pb = sp.add_parser("probe",
                         help="轻量级 Interceptor 导出函数计数 (不启动 Stalker, 无 trace.bin)")
    p_pb.add_argument("--pkg", default=None, help="目标 app 包名 (进程名子串)")
    p_pb.add_argument("--attach-pid", type=int, default=None, help="直接附加 pid")
    p_pb.add_argument("--so", required=True, help="目标 SO 名子串")
    p_pb.add_argument("--filter", default=None,
                      help="导出函数名过滤子串 (只 hook 包含该子串的导出)")
    p_pb.add_argument("--duration", type=int, default=10,
                      help="采集时长秒数 (默认 10)")
    p_pb.add_argument("--top", type=int, default=30,
                      help="只显示 top N 调用频次最高的 (默认 30)")
    p_pb.add_argument("--remote", default=None,
                      help="frida-server TCP 地址. 不传则走 USB")
    p_pb.add_argument("--json", action="store_true",
                      help="额外输出完整 JSON 结果")

    return ap


def command_parsers(parser):
    return next(action.choices for action in parser._actions
                if isinstance(action, argparse._SubParsersAction))


def _argument_descriptor(action):
    flags = action.option_strings
    long = next((flag[2:] for flag in flags if flag.startswith("--")), None)
    short = next((flag[1:] for flag in flags if len(flag) == 2), None)
    kind = "Set"
    if isinstance(action, argparse._StoreTrueAction):
        kind = "SetTrue"
    elif isinstance(action, argparse._StoreFalseAction):
        kind = "SetFalse"
    elif isinstance(action, argparse._AppendAction):
        kind = "Append"
    default = action.default
    defaults = [] if default is None or default == argparse.SUPPRESS else [
        default if isinstance(default, str) else json.dumps(default)
    ]
    return {
        "id": action.dest, "long": long, "short": short,
        "positional": not flags, "required": action.required,
        "action": kind, "help": action.help or "", "default_values": defaults,
        "possible_values": [str(value) for value in action.choices or []],
    }


def capabilities_response(parser, rust_capabilities, selected=None):
    subparsers = next(action for action in parser._actions
                      if isinstance(action, argparse._SubParsersAction))
    about = {action.dest: action.help for action in subparsers._choices_actions}
    commands = {
        command["name"]: dict(command, implementation="rust")
        for command in rust_capabilities["commands"]
    }
    for name, subparser in subparsers.choices.items():
        commands[name] = {
            "name": name, "about": about[name], "implementation": "host",
            "args": [_argument_descriptor(action) for action in subparser._actions
                     if action.dest != "help"],
            "subcommands": [],
        }
    if selected is not None and selected not in commands:
        return {"status": "error", "error": {
            "code": "unknown_command", "message": f"未知命令: {selected[:256]}"
        }}, 2
    if selected is None:
        listing = [{"name": name, "about": (command.get("about") or "").split("\n", 1)[0][:256],
                    "implementation": command["implementation"]}
                   for name, command in sorted(commands.items())]
    else:
        listing = [commands[selected]]
    result = dict(rust_capabilities, schema_version=2, tool="tracemiku", commands=listing)
    result["output_contract"] = dict(
        result["output_contract"],
        discovery="capabilities lists commands; capabilities --command <name> describes arguments",
    )
    return result, 0
