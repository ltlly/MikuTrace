"""统一入口的设备参数与能力发现；分析参数直接来自 Rust clap。"""

import argparse
import json


def build_parser():
    ap = argparse.ArgumentParser(
        prog="tracemiku", description="Android ARM64 trace 采集与离线分析",
        epilog="分析命令: records / resolve / mem-dump / mem-accesses / taint-bwd / experimental。"
               "使用 capabilities 查看清单，capabilities --command <name> 查看完整参数。",
    )
    sp = ap.add_subparsers(dest="subcommand", required=True)
    p_caps = sp.add_parser("capabilities", help="发现采集与分析命令")
    p_caps.add_argument("--command", help="仅返回指定命令的完整参数；子命令用空格连接，如 'experimental vm-ops'")
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
    p_tr.add_argument("--cmd", type=int, help="JNI 入口整数参数过滤值，须同时指定 --cmd-arg")
    p_tr.add_argument("--cmd-arg", type=int, default=None, help="过滤参数下标（从 0 开始），无目标默认值")
    p_tr.add_argument("--include-so", default="", dest="include_so",
                      help="额外采集的 SO 名子串，逗号分隔；不能覆盖硬排除")
    p_tr.add_argument("--trace-deep", action="store_true", dest="trace_deep",
                      help="以符号级排除替代部分系统模块排除；linker/libdl 仍整模块排除")
    p_tr.add_argument("--trace-all", action="store_true", dest="trace_all",
                      help="采集除 linker/libdl 和 ART 家族外的模块；不覆盖 ART 内部执行")
    p_tr.add_argument("--trace-exec", action="store_true",
                      help="扩展执行模块范围；保留 ART/linker 排除")
    p_tr.add_argument("--stalker-exclude-patterns", default=None, dest="stalker_exclude_patterns",
                      help="覆盖 --trace-deep 的符号排除名单，逗号分隔")
    p_tr.add_argument("--boundary-diff-patterns", default=None, dest="boundary_diff_patterns",
                      help="边界差分函数名，逗号分隔；默认空。勿包含 pthread/malloc/atomic，避免 Frida 重入崩溃")
    p_tr.add_argument("--ext-write-cap", type=int, default=0, dest="ext_write_cap",
                      help="外部写事件总量上限，默认 0（不限量）")
    p_tr.add_argument("--patch-suicide", action="store_true", dest="patch_suicide",
                      help="按 --suicide-patch-spec 修改匹配的内联 SVC 指令")
    p_tr.add_argument("--suicide-patch-spec", default=None,
                      dest="suicide_patch_spec",
                      help="目标版本的 patch JSON，存放于 tools/hooks/ 或 examples/")
    p_tr.add_argument("--hide-rwx-maps", action="store_true", dest="hide_rwx_maps",
                      help="通过 libc open/read 过滤 /proc/self/maps 的 rwxp 匿名段")
    p_tr.add_argument("--block-self-kill", action="store_true", dest="block_self_kill",
                      help="拦截 libc 自杀信号函数；不覆盖内联 SVC")
    p_tr.add_argument("--enable-fork-hook", action="store_true", dest="enable_fork_hook",
                      help="捕获 fork/vfork/clone 事件，写入 meta.json 的 fork_events")
    p_tr.add_argument("--no-fork-poll-child", action="store_false", dest="fork_poll_child",
                      default=True,
                      help="禁用 adb 子进程状态轮询；Frida 回传模式本身不启动轮询")
    p_tr.add_argument("--child-trace-mode", default="off", dest="child_trace_mode",
                      choices=["off", "full", "safe"],
                      help="adb 模式的 child race-attach；off 关闭，full/safe 当前行为相同。短命进程可能 attach 失败")
    p_tr.add_argument("--jni-hooks", default="tools/hooks/libart_jni.json", dest="jni_hooks",
                      help="JNI vtable hook JSON；默认 libart string 函数，none 关闭；输出 per-call jni_hooks.jsonl")
    p_tr.add_argument("--semantic-events", action="store_true", dest="semantic_events",
                      help="采集 syscall/libc/JNI 语义事件到 semantic_events.jsonl")
    p_tr.add_argument("--simd-sidecar", action="store_true", dest="simd_sidecar",
                      help="采集 SIMD/Q 寄存器到 simd_trace.bin")
    p_tr.add_argument("--simd-sample-stride", type=int, default=1, dest="simd_sample_stride",
                      help="SIMD 采样步长；1 表示每条指令，需 --simd-sidecar")
    p_tr.add_argument("--snapshot-mem", action="store_true", dest="snapshot_mem",
                      help="目标函数入口采集初始内存，写 memory_snapshot.bin，作为 MemShadow 的 i 层")
    p_tr.add_argument("--snapshot-max-mb", type=int, default=512, dest="snapshot_max_mb",
                      help="初始快照总字节预算（MiB），默认 512")
    p_tr.add_argument("--ring-recs", type=int, default=0,
                      help="ring 容量（条），默认按 --max-records 推导，上限 4194304")
    p_tr.add_argument("--max-records", type=int, default=5000000, help="单次调用记录上限（条）；达到上限后标记截断")
    p_tr.add_argument("--pull-after-session-end", action="store_true",
                      help="会话结束后再拉取；默认每个 call 结束即拉取")
    p_tr.add_argument("--no-stop-after-trace", dest="stop_after_trace",
                      action="store_false", default=True,
                      help="adb 模式收尾时保留本工具 spawn/launch 的进程；默认 force-stop")
    p_tr.add_argument("--follow-workers", action="store_true",
                      help="跟踪新建 pthread worker，默认关闭")
    p_tr.add_argument("--max-worker-threads", type=int, default=4, dest="max_worker_threads",
                      help="worker 线程上限，默认 4，agent 上限 32")
    p_tr.add_argument("--duration", type=int, default=120, help="等待采集的会话时长（秒），到时结束会话并回收结果")
    p_tr.add_argument("--out", required=True, help="输出目录")
    p_tr.add_argument("--remote", default=None,
                      help="frida-server TCP 地址 (如 127.0.0.1:6699). "
                           "不传则默认走 USB 连接.")
    p_tr.add_argument("--launch", action="store_true",
                      help="force-stop + monkey 启动后 attach，保留应用数据")
    p_tr.add_argument("--spawn", action="store_true",
                      help="spawn 挂起后 attach/init，再 resume；需 --pkg，与 --launch/--attach-pid 互斥")

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
            "name": name, "about": about[name], "implementation": "host", "stability": "stable",
            "args": [_argument_descriptor(action) for action in subparser._actions
                     if action.dest != "help"],
            "subcommands": [],
        }
    chosen = None
    if selected is not None:
        parts = selected.split()
        chosen = commands.get(parts[0]) if parts else None
        implementation = chosen.get("implementation") if chosen else None
        for part in parts[1:]:
            chosen = next((child for child in chosen.get("subcommands", [])
                           if child["name"] == part), None) if chosen else None
        if chosen is None:
            return {"status": "error", "error": {
                "code": "unknown_command", "message": f"未知命令: {selected[:256]}"
            }}, 2
        chosen = dict(chosen, implementation=implementation)
    if selected is None:
        def summary(command, implementation):
            result = {"name": command["name"],
                      "about": (command.get("about") or "").split("\n", 1)[0][:256],
                      "implementation": implementation,
                      "stability": command.get("stability", "stable")}
            if command.get("subcommands"):
                result["subcommands"] = [summary(child, implementation)
                                         for child in command["subcommands"]]
            return result
        listing = [summary(command, command["implementation"])
                   for _, command in sorted(commands.items())]
    else:
        listing = [chosen]
    result = dict(rust_capabilities, schema_version=2, tool="tracemiku", commands=listing)
    result["output_contract"] = dict(
        result["output_contract"],
        discovery="capabilities lists commands; capabilities --command <name> describes arguments",
    )
    return result, 0
