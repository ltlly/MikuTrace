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
    p_tr.add_argument("--max-calls", type=int, default=1, help="采集完整调用次数，默认 1；每次都等待函数自然返回")
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
                      help="捕获 fork/vfork/clone 事件，写入 fork_events.jsonl")
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
    p_tr.add_argument("--ring-recs", type=int, default=0,
                      help="native 写盘缓冲容量（条），默认 4096；与采集条数无关，上限 4194304")
    p_tr.add_argument("--follow-workers", action="store_true",
                      help="跟踪新建 pthread worker，默认关闭")
    p_tr.add_argument("--max-worker-threads", type=int, default=4, dest="max_worker_threads",
                      help="worker 线程上限，默认 4，agent 上限 32")
    p_tr.add_argument("--device-dir", help="设备上目标进程可写的新建目录；使用前验证目标写入和 root 回读")
    p_tr.add_argument("--out", required=True, help="新采集输出目录；已有结果使用 recover")
    p_tr.add_argument("--remote", default=None,
                      help="frida-server TCP 地址 (如 127.0.0.1:6699). "
                           "不传则默认走 USB 连接.")
    p_tr.add_argument("--launch", action="store_true",
                      help="force-stop + monkey 启动后 attach，保留应用数据")
    p_tr.add_argument("--spawn", action="store_true",
                      help="spawn 挂起后 attach/init，再 resume；需 --pkg，与 --launch/--attach-pid 互斥")

    p_rec = sp.add_parser("recover", help="恢复设备封口结果的压缩回传，不重新执行目标函数")
    p_rec.add_argument("run", help="含 recovery.json 的采集目录")

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
