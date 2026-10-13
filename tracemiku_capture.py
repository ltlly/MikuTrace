"""设备完整调用采集编排。采集器独立于 host，封口后统一交给 spool 恢复链路。"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
import uuid
from contextlib import suppress
from pathlib import Path

from tracemiku_common import adb_command, atomic_json
from tracemiku_device import launch_start
from tracemiku_spool import AdbSpool, recover_run
from tracemiku_target import HostPlugin


def _control_source(address):
    # 控制脚本的卸载不会卸载 eternalized 采集器。NativeFunction 默认 cooperative，
    # 进入另一个脚本的 NativeCallback 前释放当前 JS 锁。
    return """
const bridge = new NativeFunction(ptr(__CONTROL_ADDRESS__), 'pointer', ['pointer']);
function call(method, args) {
    const request = JSON.stringify({ method, args });
    if (request.length > 65536) throw new Error('control request exceeds 64KiB');
    const response = JSON.parse(bridge(Memory.allocUtf8String(request)).readUtf8String());
    if (!response.ok) throw new Error(response.error);
    return response.value;
}
rpc.exports = {
    startCapture: () => call('startCapture', []),
    stopCapture: () => call('stopCapture', []),
    stats: () => call('stats', []),
    pluginCall: (id, payload) => call('pluginCall', [id, payload]),
    disposePlugins: () => call('disposePlugins', []),
};
""".replace("__CONTROL_ADDRESS__", json.dumps(address))


def _agent_options(args, root, profile):
    def json_file(path):
        path = Path(path)
        if not path.is_absolute():
            path = root / path
        return json.loads(path.read_text())

    jni = json_file(args.jni_hooks).get("hooks", []) if args.jni_hooks and args.jni_hooks != "none" else []
    if args.patch_suicide and not args.suicide_patch_spec:
        raise ValueError("--patch-suicide requires --suicide-patch-spec")
    suicide = json_file(args.suicide_patch_spec) if args.patch_suicide else None
    patterns = lambda value: [part.strip() for part in (value or "").split(",") if part.strip()]
    return {
        "soPattern": args.so, "methodName": args.method, "exportName": args.export,
        "fnOffset": int(args.fn_offset, 16) if args.fn_offset else None,
        "cmdArg": args.cmd_arg, "cmdValue": args.cmd,
        "ringRecs": args.ring_recs,
        "maxCalls": args.max_calls,
        "targetPlugins": profile["agent_plugins"] if profile else [],
        "followWorkers": args.follow_workers, "maxWorkerThreads": args.max_worker_threads,
        "pkg": args.pkg, "includeSoPatterns": patterns(args.include_so),
        "deepTrace": args.trace_deep, "execOnly": args.trace_exec, "traceAll": args.trace_all,
        "stalkerExcludePatterns": patterns(args.stalker_exclude_patterns),
        "boundaryDiffPatterns": patterns(args.boundary_diff_patterns),
        "patchSuicide": args.patch_suicide, "suicidePatchSpec": suicide,
        "hideRwxMaps": args.hide_rwx_maps, "blockSelfKill": args.block_self_kill,
        "jniHooks": jni, "enableForkHook": args.enable_fork_hook,
        "semanticEvents": args.semantic_events, "simdSidecar": args.simd_sidecar,
        "simdSampleStride": args.simd_sample_stride, "snapshotMem": args.snapshot_mem,
    }


def _select_adb_serial():
    if os.environ.get("ANDROID_SERIAL"):
        return os.environ["ANDROID_SERIAL"]
    result = subprocess.run(adb_command("devices"), capture_output=True, text=True,
                            timeout=30, check=True)
    ready = [line.split()[0] for line in result.stdout.splitlines()[1:]
             if len(line.split()) >= 2 and line.split()[1] == "device"]
    if len(ready) != 1:
        raise ValueError("需要唯一 ADB 设备；多设备时请设置 ANDROID_SERIAL")
    os.environ["ANDROID_SERIAL"] = ready[0]
    return ready[0]


def capture(args, root, rust_json, log):
    """返回稳定 JSON；日志由入口写 stderr，完整性最终取自设备 manifest。"""
    if not args.so or not (args.method or args.export or args.fn_offset):
        raise ValueError("需要 --so 和 --method/--export/--fn-offset 之一")
    if sum(bool(value) for value in (args.spawn, args.launch, args.attach_pid)) > 1:
        raise ValueError("--spawn/--launch/--attach-pid 互斥")
    if (args.spawn or args.launch) and not args.pkg:
        raise ValueError("--spawn/--launch 需要 --pkg")
    if args.cmd is not None and args.cmd_arg is None:
        raise ValueError("--cmd 需要 --cmd-arg")
    if not 1 <= args.max_calls <= 2**53 - 1:
        raise ValueError("--max-calls 必须是正整数")
    if args.simd_sample_stride < 1:
        raise ValueError("--simd-sample-stride 必须是正整数")
    profile = getattr(args, "_target_profile", None)
    opts = _agent_options(args, root, profile)
    out = Path(args.out).resolve()
    if (out / "recovery.json").exists() or (out / "calls").exists():
        raise ValueError("输出目录已有采集数据；请使用 recover 恢复或换一个新目录")
    out.mkdir(parents=True, exist_ok=True)
    (out / "calls").mkdir()
    serial = _select_adb_serial()
    spool = AdbSpool(log)
    # 工具可用性在触发调用前确认，压缩本身必须等设备封口。
    spool.shell("command -v gzip && command -v sha256sum && command -v dd", timeout=30)
    import frida
    device = (frida.get_device_manager().add_remote_device(args.remote) if args.remote
              else frida.get_usb_device(timeout=10))
    plugin = HostPlugin(profile["host_plugin"]) if profile and profile["host_plugin"] else None
    plugin_results = []
    if plugin:
        plugin_results.append({"phase": "prepare", "result": plugin.call("prepare", {"args": args})})
    pid = args.attach_pid
    spawned = False
    resumed = False
    session = collector = control = None
    eternal = False
    interrupted = threading.Event()
    detached = threading.Event()
    failure = []
    previous_handler = signal.signal(signal.SIGINT, lambda *_: interrupted.set())
    recovery = {"schema_version": 1, "serial": serial, "sessions": []}
    top_meta = {"pkg": args.pkg, "so": args.so, "method": args.method, "export": args.export,
                "fn_offset": args.fn_offset, "per_call": True, "tracemiku_cli": True,
                "transport": "adb-gzip", "started_at": time.time(), "calls": [],
                "spawned": bool(args.spawn), "host_plugin_results": plugin_results}
    atomic_json(out / "meta.json", top_meta)

    def on_message(message, _data):
        if message.get("type") == "error":
            failure.append(str(message.get("description", "agent error"))[:1000])
        elif message.get("type") == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict) and payload.get("type") == "log":
                log(payload["msg"])

    try:
        if args.spawn:
            # spawn 自身已挂起目标；全局 spawn gating 会卡住 ADB 的恢复命令。
            pid = device.spawn([args.pkg])
            spawned = True
        elif args.launch:
            pid = launch_start(args.pkg)
        elif pid is None and args.pkg:
            matches = [process.pid for process in device.enumerate_processes() if process.name == args.pkg]
            if len(matches) == 1:
                pid = matches[0]
            else:
                values = subprocess.run(adb_command("shell", "pidof", args.pkg),
                                        capture_output=True, text=True, timeout=30, check=False).stdout.split()
                if len(values) == 1:
                    pid = int(values[0])
        if pid is None:
            raise ValueError("找不到唯一目标进程；请用 --attach-pid 或 --spawn")
        session = device.attach(pid)
        session.on("detached", lambda *_: detached.set())
        collector = session.create_script((root / "tracer" / "_agent.js").read_text())
        collector.on("message", on_message)
        collector.load()
        prepared = collector.exports_sync.prepare_spool({
            "sessionId": uuid.uuid4().hex, "pkg": args.pkg, "traceDir": args.device_dir,
        })
        spool.verify_preflight(prepared)
        recovery["sessions"].append(prepared)
        atomic_json(out / "recovery.json", recovery)
        result = collector.exports_sync.init(opts)
        if result in ("no-cmodule", "no-dlopen") or failure:
            raise RuntimeError(f"agent init failed: {result}; {failure}")
        address = collector.exports_sync.control_address()
        collector.eternalize()
        eternal = True
        control = session.create_script(_control_source(address))
        control.load()
        control.exports_sync.start_capture()
        if spawned:
            device.resume(pid)
            resumed = True
        log(f"采集器已就绪 pid={pid}，等待 {args.max_calls} 次完整调用自然返回；无条数/时长上限")
        if plugin:
            plugin_results.append({"phase": "on_ready", "result": plugin.call("on_ready", {
                "args": args, "script": control, "session": session, "device": device, "pid": pid,
            })})
        last_progress = None
        while not interrupted.is_set() and not detached.is_set():
            if failure:
                raise RuntimeError(f"agent failed; 设备源保留，请检查 manifest: {failure[-1]}")
            stats = control.exports_sync.stats()
            if stats.get("error"):
                raise RuntimeError(f"agent failed: {stats['error']}")
            blocked = stats.get("blockedIo", [])
            progress = (stats.get("head"), stats.get("completedCalls"),
                        tuple((item["path"], item["errno"]) for item in blocked))
            if progress != last_progress:
                log(f"已记录 {stats.get('head', 0):,} 条，已封口 {stats.get('completedCalls', 0)} 次调用")
                if blocked:
                    log(f"设备 I/O 背压中，生产线程等待存储恢复，不跳过记录: {blocked}")
                last_progress = progress
            if stats.get("completedCalls", 0) >= args.max_calls:
                break
            time.sleep(0.5)
        if not detached.is_set():
            control.exports_sync.stop_capture()
        if plugin and not detached.is_set():
            plugin_results.append({"phase": "finish", "result": plugin.call("finish", {
                "args": args, "script": control, "session": session, "pid": pid,
            })})
        # 不对正在执行的函数执行 unfollow/kill。Ctrl+C 仅离开等待，设备继续封口。
        if interrupted.is_set() or detached.is_set():
            log("host 已停止等待；设备采集器继续当前调用。使用 recover 获取封口结果")
    finally:
        signal.signal(signal.SIGINT, previous_handler)
        if control:
            with suppress(Exception):
                control.unload()
        if collector and not eternal:
            with suppress(Exception):
                collector.unload()
        if session:
            with suppress(Exception):
                session.detach()
        if spawned and not resumed:
            device.kill(pid)
        top_meta["stopped_at"] = time.time()
        atomic_json(out / "meta.json", top_meta)
    return recover_run(out, rust_json, spool=spool, log=log)
