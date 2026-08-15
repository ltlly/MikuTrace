"""Host-side unit tests for `tracemiku trace --spawn`.

No device needed: frida is mocked and `_check_device` is replaced, so we can
lock the spawn-gating order (enable -> spawn -> attach -> load -> init ->
resume) and the failure/teardown cleanup (kill + disable_spawn_gating).
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
    def __init__(self, fail_init=False):
        self.loaded = False
        self.unloaded = False
        self.fail_init = fail_init

    def on(self, *a, **k):
        pass

    def load(self):
        self.loaded = True

    @property
    def exports_sync(self):
        return _FakeRpc(self)


class _FakeRpc:
    def __init__(self, script):
        self.script = script

    def init(self, opts):
        if self.script.fail_init:
            raise RuntimeError("mock init failure")
        return "waiting-dlopen"

    def stats(self):
        return {}

    def force_flush(self):
        return "ok"


class FakeSession:
    def __init__(self, script):
        self.script = script
        self.detached = False

    def create_script(self, src):
        return self.script

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
        mode="cmodule",
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
