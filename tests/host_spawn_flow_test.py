"""Host-side unit tests for `tracemiku trace --spawn`.

No device needed: frida is mocked and `_check_device` is replaced, so we can
lock the spawn-gating order (enable -> spawn -> attach -> load -> init ->
resume) and the failure/teardown cleanup (kill + disable_spawn_gating).
Also covers host-side message semantics: duplicate trace-end idempotency and
stale _pending_call_* directory cleanup on reuse.
"""

import importlib.machinery
import importlib.util
import json
import sys
import types
from argparse import Namespace

import pytest


def _load_tracemiku():
    loader = importlib.machinery.SourceFileLoader("tracemiku_main", "tracemiku")
    spec = importlib.util.spec_from_loader("tracemiku_main", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class FakeScript:
    def __init__(self, fail_init=False, init_result="waiting-dlopen"):
        self.loaded = False
        self.unloaded = False
        self.fail_init = fail_init
        self.init_result = init_result
        self.message_cb = None
        # (payload, data) 列表: load() 时按序投递, 模拟 agent 消息流
        self.messages = []

    def on(self, event, cb):
        if event == "message":
            self.message_cb = cb

    def load(self):
        self.loaded = True
        for payload, data in self.messages:
            assert self.message_cb is not None
            self.message_cb({"type": "send", "payload": payload}, data)

    @property
    def exports_sync(self):
        return _FakeRpc(self)


class _FakeRpc:
    def __init__(self, script):
        self.script = script

    def init(self, opts):
        if self.script.fail_init:
            raise RuntimeError("mock init failure")
        return self.script.init_result

    def stats(self):
        return {}

    def force_flush(self):
        return "ok"


class FakeSession:
    def __init__(self, script):
        self.script = script
        self.detached = False
        self.detach_cb = None

    def create_script(self, src):
        return self.script

    def on(self, event, cb):
        if event == "detached":
            self.detach_cb = cb

    def detach(self):
        self.detached = True


class FakeDevice:
    def __init__(self, script):
        self.script = script
        self.calls = []
        self.gating = False
        self.sessions = {}

    def enable_spawn_gating(self):
        self.calls.append("enable_spawn_gating")
        self.gating = True

    def spawn(self, argv):
        self.calls.append(("spawn", argv))
        return 4242

    def attach(self, pid):
        self.calls.append(("attach", pid))
        sess = FakeSession(self.script)
        self.sessions[pid] = sess
        return sess

    def resume(self, pid):
        self.calls.append(("resume", pid))

    def kill(self, pid):
        self.calls.append(("kill", pid))

    def disable_spawn_gating(self):
        self.calls.append("disable_spawn_gating")
        self.gating = False


def _args(tmp_path, spawn=True, **over):
    base = Namespace(
        launch=False,
        spawn=spawn,
        attach_pid=None,
        pkg="com.example.app",
        cmd=None,
        cmd_arg=None,
        so="libtarget",
        method="nativeFn",
        export=None,
        fn_offset=None,
        max_records=1000,
        follow_workers=False,
        max_worker_threads=4,
        include_so="",
        trace_deep=False,
        trace_all=False,
        stalker_exclude_patterns=None,
        boundary_diff_patterns=None,
        ext_write_cap=0,
        patch_suicide=False,
        suicide_patch_spec=None,
        hide_rwx_maps=False,
        block_self_kill=False,
        jni_hooks="none",
        enable_fork_hook=False,
        semantic_events=False,
        simd_sidecar=False,
        simd_sample_stride=1,
        snapshot_mem=False,
        snapshot_max_mb=512,
        out=str(tmp_path / "run"),
        remote=None,
        duration=0,
        child_trace_mode="off",
        fork_poll_child=True,
    )
    for k, v in over.items():
        setattr(base, k, v)
    return base


@pytest.fixture
def frida_mock(monkeypatch):
    script = FakeScript()
    device = FakeDevice(script)
    fake = types.ModuleType("frida")
    fake.get_device_manager = lambda: types.SimpleNamespace(
        add_remote_device=lambda addr: device
    )
    fake.get_usb_device = lambda timeout=10: device
    monkeypatch.setitem(sys.modules, "frida", fake)
    return device, script


def test_spawn_flow_order_and_cleanup(frida_mock, tmp_path, monkeypatch):
    mod = _load_tracemiku()
    device, _ = frida_mock
    monkeypatch.setattr(mod, "_check_device", lambda **kw: (0, 0, []))

    rc = mod.cmd_trace(_args(tmp_path))

    assert rc == 0
    assert device.calls == [
        "enable_spawn_gating",
        ("spawn", ["com.example.app"]),
        ("attach", 4242),
        ("resume", 4242),
        "disable_spawn_gating",
    ]
    top_meta = json.loads((tmp_path / "run" / "meta.json").read_text())
    assert top_meta["spawned"] is True


def test_spawn_init_failure_kills_and_disables(frida_mock, tmp_path, monkeypatch):
    mod = _load_tracemiku()
    device, script = frida_mock
    script.fail_init = True
    monkeypatch.setattr(mod, "_check_device", lambda **kw: (0, 0, []))

    rc = mod.cmd_trace(_args(tmp_path))

    assert rc == 2
    assert ("kill", 4242) in device.calls
    assert "disable_spawn_gating" in device.calls
    assert device.gating is False


def test_spawn_rejects_launch_combination(frida_mock, tmp_path, monkeypatch):
    mod = _load_tracemiku()
    monkeypatch.setattr(mod, "_check_device", lambda **kw: (0, 0, []))

    rc = mod.cmd_trace(_args(tmp_path, launch=True))

    assert rc == 2


def test_spawn_no_cmodule_aborts_without_resume(frida_mock, tmp_path, monkeypatch):
    """init 返回 no-cmodule: 立即以非零码退出, 不 resume 挂起进程, gating 收口."""
    mod = _load_tracemiku()
    device, script = frida_mock
    script.init_result = "no-cmodule"
    monkeypatch.setattr(mod, "_check_device", lambda **kw: (0, 0, []))

    rc = mod.cmd_trace(_args(tmp_path))

    assert rc == 2
    # 挂起的 spawn 进程直接 kill, 不能 resume 后空跑满 duration
    assert ("resume", 4242) not in device.calls
    assert ("kill", 4242) in device.calls
    assert "disable_spawn_gating" in device.calls
    assert device.gating is False


def _trace_end_payload(call_idx=1, tid=111, truncated=True, ms=50, total=10):
    return {
        "type": "trace-end", "callIdx": call_idx, "tid": tid,
        "retval": "0x0", "ms": ms, "total": total, "dropped": 0,
        "truncated": truncated,
    }


def test_duplicate_trace_end_finalizes_once(frida_mock, tmp_path, monkeypatch):
    """双 trace-end 守卫 (host 侧): 同 callIdx 的第二个 trace-end 必须被幂等忽略.

    模拟 watchdog/maxRecords 先发 trace-end(truncated:true), 目标函数真正返回时
    agent 再发第二个 trace-end(truncated:false) — 只允许 finalize 一次.
    """
    mod = _load_tracemiku()
    _device, script = frida_mock
    monkeypatch.setattr(mod, "_check_device", lambda **kw: (0, 0, []))
    script.messages = [
        ({"type": "trace-begin", "callIdx": 1, "tid": 111, "ts": 1}, None),
        (_trace_end_payload(1, truncated=True), None),
        (_trace_end_payload(1, truncated=False), None),
    ]

    rc = mod.cmd_trace(_args(tmp_path))

    assert rc == 0
    calls_dir = tmp_path / "run" / "calls"
    call_dirs = [d for d in calls_dir.iterdir() if d.is_dir()]
    # 只有第一个 trace-end (truncated=true) 产生目录; 第二个被忽略, 无幽灵 _dup 目录
    assert len(call_dirs) == 1
    assert call_dirs[0].name.startswith("_truncated_call_001")
    top_meta = json.loads((tmp_path / "run" / "meta.json").read_text())
    assert len(top_meta["calls"]) == 1


def test_pending_call_dir_reuse_clears_stale_files(frida_mock, tmp_path, monkeypatch):
    """_pending_call_NNN 复用前必须清空上一 run 的残留事件文件 (append 打开)."""
    mod = _load_tracemiku()
    _device, script = frida_mock
    monkeypatch.setattr(mod, "_check_device", lambda **kw: (0, 0, []))
    stale_dir = tmp_path / "run" / "calls" / "_pending_call_001"
    stale_dir.mkdir(parents=True)
    (stale_dir / "semantic_events.jsonl").write_text("STALE_FROM_PREVIOUS_RUN\n")
    (stale_dir / "trace.bin").write_bytes(b"\x00" * 272)
    script.messages = [
        ({"type": "trace-begin", "callIdx": 1, "tid": 111, "ts": 1}, None),
        (_trace_end_payload(1, truncated=False), None),
    ]

    rc = mod.cmd_trace(_args(tmp_path))

    assert rc == 0
    calls_dir = tmp_path / "run" / "calls"
    call_dirs = [d for d in calls_dir.iterdir() if d.is_dir()]
    assert len(call_dirs) == 1
    final_dir = call_dirs[0]
    # 残留文件不得混入新 run (本 run 未发 semantic-events, 该文件不应存在)
    assert not (final_dir / "semantic_events.jsonl").exists()
    for f in final_dir.iterdir():
        if f.is_file():
            assert "STALE_FROM_PREVIOUS_RUN" not in f.read_text(errors="replace")
