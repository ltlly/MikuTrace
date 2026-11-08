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


@pytest.mark.parametrize("identity", ["dev.fixture", {"identifier": "dev.fixture"}])
def test_resolve_pid_uses_package_metadata_with_localized_main_name(monkeypatch, identity):
    from types import SimpleNamespace

    import tracemiku_device

    processes = [
        SimpleNamespace(pid=20, name="dev.fixture:push", parameters={"applications": [identity]}),
        SimpleNamespace(pid=42, name="千问", parameters={"applications": [identity]}),
        SimpleNamespace(pid=99, name="dev.fixture", parameters={"applications": ["dev.other"]}),
    ]
    def enumerate_processes(*, scope):
        assert scope == "metadata"
        return processes
    device = SimpleNamespace(enumerate_processes=enumerate_processes)
    monkeypatch.setattr(tracemiku_device.subprocess, "run", lambda *args, **kwargs: pytest.fail("unexpected adb"))
    assert tracemiku_device.resolve_running_pid("dev.fixture", device) == 42


def test_resolve_pid_application_identity_handles_setargv0_and_renamed_child(monkeypatch):
    from types import SimpleNamespace

    import tracemiku_device

    processes = [SimpleNamespace(pid=pid, name=name, parameters={"applications": ["dev.fixture"]})
                 for pid, name in [(42, "renamed-main"), (43, "renamed-worker")]]
    def enumerate_applications(*, identifiers, scope):
        assert identifiers == ["dev.fixture"] and scope == "minimal"
        return [SimpleNamespace(identifier="dev.fixture", name="千问", pid=42)]
    device = SimpleNamespace(enumerate_processes=lambda **kwargs: processes,
                             enumerate_applications=enumerate_applications)
    monkeypatch.setattr(tracemiku_device.subprocess, "run", lambda *args, **kwargs: pytest.fail("unexpected adb"))
    assert tracemiku_device.resolve_running_pid("dev.fixture", device) == 42


@pytest.mark.parametrize("pids, expected", [("42\n", 42), ("42\n43\n", None), ("", None)])
def test_resolve_pid_proc_fallback_is_exact_bounded_and_uses_selected_device(monkeypatch, pids, expected):
    from types import SimpleNamespace

    import tracemiku_device

    monkeypatch.setenv("ANDROID_SERIAL", "fixture-serial")
    monkeypatch.setenv("ANDROID_ADB_SERVER_PORT", "5038")
    commands = []
    def run(command, **kwargs):
        commands.append(command)
        assert kwargs["timeout"] == 30
        return SimpleNamespace(returncode=0, stdout=pids, stderr="")
    monkeypatch.setattr(tracemiku_device, "make_su_detector", lambda: lambda: True)
    monkeypatch.setattr(tracemiku_device.subprocess, "run", run)
    device = SimpleNamespace(enumerate_processes=lambda **kwargs: [
        SimpleNamespace(pid=43, name="dev.fixture:push", parameters={"applications": ["dev.fixture"]}),
    ])
    assert tracemiku_device.resolve_running_pid("dev.fixture", device) == expected
    assert commands[0][:7] == ["adb", "-P", "5038", "-s", "fixture-serial", "shell", commands[0][-1]]
    import shlex
    shell = shlex.split(commands[0][-1])
    assert shell[:2] == ["su", "-c"]
    assert "/proc/[0-9]*/cmdline" in shell[2]
    assert "read -r -d '' argv0" in shell[2]
    assert '[ "$argv0" = dev.fixture ]' in shell[2]


def test_resolve_pid_proc_first_field_does_not_match_suffix_or_arguments(tmp_path, monkeypatch):
    import tracemiku_device

    proc = tmp_path / "proc"
    for pid, cmdline in [(42, b"dev.fixture\0--flag\0"), (43, b"dev.fixture:push\0"),
                         (44, b"other\0dev.fixture\0"), (45, b"dev.fixture.extra\0")]:
        directory = proc / str(pid)
        directory.mkdir(parents=True)
        (directory / "cmdline").write_bytes(cmdline)
    actual_run = subprocess.run
    def run(command, **kwargs):
        script = command[-1].replace("/proc/", str(proc) + "/")
        return actual_run(["bash", "-c", script], **kwargs)
    monkeypatch.setattr(tracemiku_device, "make_su_detector", lambda: lambda: False)
    monkeypatch.setattr(tracemiku_device.subprocess, "run", run)
    assert tracemiku_device.resolve_running_pid("dev.fixture") == 42
