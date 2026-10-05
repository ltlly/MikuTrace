"""可信目标配置/插件加载。目标知识仅来自用户文件，不进入 core。"""

import importlib.util
import json
import pathlib
import threading
import uuid

MAX_FILE_BYTES = 1024 * 1024
MAX_PLUGINS = 8
MAX_CONFIG_BYTES = 64 * 1024
TARGET_FIELDS = {"pkg", "so", "method", "export", "fn_offset", "cmd", "cmd_arg"}
CAPTURE_FIELDS = {
    "max_records", "max_calls", "duration", "jni_hooks", "follow_workers", "max_worker_threads",
    "hide_rwx_maps", "block_self_kill", "trace_deep", "trace_all", "include_so",
    "semantic_events", "snapshot_mem", "snapshot_max_mb", "simd_sidecar",
}


def _read(path):
    with path.open("rb") as fp:
        contents = fp.read(MAX_FILE_BYTES + 1)
    if len(contents) > MAX_FILE_BYTES:
        raise ValueError(f"目标文件超过 1MiB: {path}")
    return contents.decode("utf-8")


def _keys(value, allowed, name):
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError(f"{name} 包含未知字段或不是对象")


def load_target(path):
    path = pathlib.Path(path).resolve()
    doc = json.loads(_read(path))
    _keys(doc, {"schema_version", "target", "capture", "transport", "agent_plugins",
                "host_plugin"}, "target profile")
    if type(doc.get("schema_version")) is not int or doc["schema_version"] != 1:
        raise ValueError("目标配置 schema_version 必须为 1")
    target = doc.get("target", {})
    capture = doc.get("capture", {})
    _keys(target, TARGET_FIELDS, "target")
    _keys(capture, CAPTURE_FIELDS, "capture")
    for key, value in {**target, **capture}.items():
        if key in {"cmd", "cmd_arg", "max_records", "max_calls", "duration", "max_worker_threads", "snapshot_max_mb"}:
            if type(value) is not int:
                raise ValueError(f"{key} 必须是整数")
        elif key in {"pkg", "so", "method", "export", "fn_offset", "jni_hooks", "include_so"}:
            if not isinstance(value, str) or not value or len(value) > 4096:
                raise ValueError(f"{key} 必须是非空字符串")
        elif type(value) is not bool:
            raise ValueError(f"{key} 必须是布尔值")
    transport = doc.get("transport", "frida")
    if transport not in ("frida", "adb"):
        raise ValueError("transport 必须为 frida 或 adb")
    specs = doc.get("agent_plugins", [])
    if not isinstance(specs, list) or len(specs) > MAX_PLUGINS:
        raise ValueError("agent_plugins 最多 8 个")
    plugins = []
    ids = set()
    for spec in specs:
        _keys(spec, {"id", "path", "config"}, "agent plugin")
        plugin_id = spec.get("id")
        if not isinstance(plugin_id, str) or not plugin_id or len(plugin_id) > 64 or plugin_id in ids:
            raise ValueError("plugin id 必须唯一且长度在 1..64")
        ids.add(plugin_id)
        script_path = spec.get("path")
        if not isinstance(script_path, str) or not script_path:
            raise ValueError("plugin path 必须是非空字符串")
        config = spec.get("config", {})
        if not isinstance(config, dict) or len(json.dumps(config).encode()) > MAX_CONFIG_BYTES:
            raise ValueError("plugin config 必须是对象且不超过 64KiB")
        plugins.append({"id": plugin_id, "source": _read(path.parent / script_path), "config": config})
    host = doc.get("host_plugin")
    if host is not None:
        _keys(host, {"path", "config"}, "host plugin")
        if not isinstance(host.get("path"), str) or not host["path"]:
            raise ValueError("host plugin path 必须是非空字符串")
        config = host.get("config", {})
        if not isinstance(config, dict) or len(json.dumps(config).encode()) > MAX_CONFIG_BYTES:
            raise ValueError("host config 必须是对象且不超过 64KiB")
        host = {"path": str((path.parent / host["path"]).resolve()), "config": config}
        _read(pathlib.Path(host["path"]))
    if "jni_hooks" in capture and capture["jni_hooks"] != "none":
        capture["jni_hooks"] = str((path.parent / capture["jni_hooks"]).resolve())
    return {"path": str(path), "target": target, "capture": capture,
            "transport": transport, "agent_plugins": plugins, "host_plugin": host}


def apply_target(args, profile, explicit):
    """CLI 显式参数覆盖 profile；默认值不覆盖用户文件。"""
    for key, value in {**profile["target"], **profile["capture"],
                       "transport": profile["transport"]}.items():
        if key not in explicit:
            setattr(args, key, value)
    return args


class HostPlugin:
    """模块为可信任的任意 Python 代码；不是沙箱。

    各生命周期最多等待 30 秒。超时即失败，不能强杀 Python 线程，调用方
    必须中止采集；不要让插件的后台线程在 timeout 后继续修改 session。
    """

    def __init__(self, spec):
        self.config = spec["config"]
        self.module = None
        self.path = spec["path"]

    def call(self, phase, context, timeout=30):
        results = []
        errors = []

        def run():
            try:
                if self.module is None:
                    spec = importlib.util.spec_from_file_location("miku_target_" + uuid.uuid4().hex, self.path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    if getattr(module, "API_VERSION", None) != 1:
                        raise ValueError("host plugin API_VERSION 必须为 1")
                    self.module = module
                fn = getattr(self.module, phase, None)
                result = fn({**context, "config": self.config}) if fn else None
                encoded = json.dumps(result, ensure_ascii=False, allow_nan=False)
                if len(encoded.encode()) > MAX_CONFIG_BYTES:
                    raise ValueError("host plugin 输出超过 64KiB")
                results.append(result)
            except BaseException as exc:
                errors.append(exc)

        th = threading.Thread(target=run, daemon=True, name="miku-target-" + phase)
        th.start()
        th.join(timeout)
        if th.is_alive():
            raise TimeoutError(f"host plugin {phase} 超时 {timeout}s；采集中止")
        if errors:
            raise RuntimeError(f"host plugin {phase}: {str(errors[0])[:500]}") from errors[0]
        return results[0]
