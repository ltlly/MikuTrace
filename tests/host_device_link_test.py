"""设备链路回归: adb 端点选择 / su 探测降级 / 拉取事务性常量。

覆盖 2026-10 真机 (OPD2404/Android16/KSU) 上确认的阻塞点:
- 设备只在非默认 adb server 上可见时, 各调用点必须带上 -P / -s
- Stalker 满载时 root 探测会超时, 不得让整条拉取链失败, 且结论只探测一次
"""
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load_tracemiku():
    import tracemiku_common
    return tracemiku_common


# ── adb_command: 端点选择 ────────────────────────────────────────────────

def test_adb_command_empty_env_is_unset(monkeypatch):
    mod = _load_tracemiku()
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", "")
    monkeypatch.setenv("ANDROID_SERIAL", "")
    assert mod.adb_command("shell", "id") == ["adb", "shell", "id"]


def test_adb_command_default_prefix(monkeypatch):
    mod = _load_tracemiku()
    monkeypatch.delenv("ANDROID_ADB_SERVER_PORT", raising=False)
    monkeypatch.delenv("ANDROID_SERIAL", raising=False)
    assert mod.adb_command("shell", "id") == ["adb", "shell", "id"]


def test_adb_command_injects_port_and_serial(monkeypatch):
    mod = _load_tracemiku()
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", "5038")
    monkeypatch.setenv("ANDROID_SERIAL", "33cfd6d3")
    assert mod.adb_command("shell", "id") == [
        "adb", "-P", "5038", "-s", "33cfd6d3", "shell", "id",
    ]


@pytest.mark.parametrize("bad", ["0", "65536", "abc"])
def test_adb_command_rejects_bad_port(monkeypatch, bad):
    mod = _load_tracemiku()
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", bad)
    with pytest.raises(ValueError):
        mod.adb_command("shell", "id")


def test_device_module_shares_adb_endpoint_semantics(monkeypatch):
    """tracemiku_device 必须用同一套端点语义, 且不硬编码 adb 前缀。"""
    import tracemiku_device

    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", "5038")
    assert tracemiku_device.adb_command("shell", "id")[:3] == ["adb", "-P", "5038"]
    src = (ROOT / "tracemiku_device.py").read_text()
    assert '["adb",' not in src
    assert '["adb",\n' not in src


def test_usable_devices_requires_exact_state():
    """"unauthorized / offline / no permissions" 都不能算已连接。"""
    import tracemiku_device

    out = (
        "List of devices attached\n"
        "AAA   device product:x\n"
        "BBB   unauthorized\n"
        "CCC   offline\n"
        "DDD   no permissions; see http://developer.android.com/tools/device.html\n"
    )
    assert tracemiku_device.usable_devices(out, None) == ["AAA"]
    assert tracemiku_device.usable_devices(out, "BBB") == []
    assert tracemiku_device.usable_devices(out, "AAA") == ["AAA"]


# ── su 探测: 超时/异常降级 + 只探测一次 ─────────────────────────────────

def _probe_with(mod, monkeypatch, result):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    return calls


class _R:
    def __init__(self, stdout, rc=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = rc


def test_su_detector_probes_once_and_caches(monkeypatch):
    mod = _load_tracemiku()
    calls = _probe_with(mod, monkeypatch, _R("uid=2000(shell) gid=2000(shell)"))
    detect = mod.make_su_detector()
    assert detect() is True
    assert detect() is True
    assert len(calls) == 1, "探测结论必须缓存, 不能每次拉取重探"


def test_su_detector_detects_root_shell(monkeypatch):
    mod = _load_tracemiku()
    _probe_with(mod, monkeypatch, _R("uid=0(root) gid=0(root)"))
    assert mod.make_su_detector()() is False


def test_su_detector_timeout_degrades_to_su(monkeypatch):
    mod = _load_tracemiku()
    calls = _probe_with(mod, monkeypatch, subprocess.TimeoutExpired("adb", 5))
    detect = mod.make_su_detector()
    assert detect() is True
    assert detect() is True
    assert len(calls) == 1


def test_su_detector_oserror_degrades_to_su(monkeypatch):
    mod = _load_tracemiku()
    _probe_with(mod, monkeypatch, OSError("no adb"))
    assert mod.make_su_detector()() is True


def test_su_detector_nonzero_rc_counts_as_needs_su(monkeypatch):
    mod = _load_tracemiku()
    _probe_with(mod, monkeypatch, _R("", rc=1))
    assert mod.make_su_detector()() is True


def test_detectors_are_independent_per_collection(monkeypatch):
    """两个采集不得共享 su 结论 (设备可能不同)。"""
    mod = _load_tracemiku()
    _probe_with(mod, monkeypatch, _R("uid=0(root) gid=0(root)"))
    assert mod.make_su_detector()() is False
    _probe_with(mod, monkeypatch, _R("uid=2000(shell) gid=2000(shell)"))
    assert mod.make_su_detector()() is True


def test_transfer_budget_is_a_chunk_not_a_capture_limit():
    from tracemiku_spool import CHUNK_BYTES, TRANSFER_IDLE_SECONDS
    assert CHUNK_BYTES % 272 == 0
    assert CHUNK_BYTES > 0
    assert TRANSFER_IDLE_SECONDS > 0


def test_launch_diagnostics_do_not_pollute_capture_json(monkeypatch, capsys):
    from types import SimpleNamespace

    import tracemiku_device

    monkeypatch.setattr(tracemiku_device.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(tracemiku_device.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout="4242", stderr=""))
    assert tracemiku_device.launch_start("dev.fixture") == 4242
    output = capsys.readouterr()
    assert output.out == ""
    assert "[launch]" in output.err
