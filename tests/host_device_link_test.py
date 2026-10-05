"""设备链路回归: adb 端点选择 / su 探测降级 / 拉取事务性常量。

覆盖 2026-10 真机 (OPD2404/Android16/KSU) 上确认的阻塞点:
- 设备只在非默认 adb server 上可见时, 各调用点必须带上 -P / -s
- Stalker 满载时 root 探测会超时, 不得让整条拉取链失败, 且结论只探测一次
"""
import importlib.util
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load_tracemiku():
    import importlib.machinery

    loader = importlib.machinery.SourceFileLoader("tracemiku_main", str(ROOT / "tracemiku"))
    spec = importlib.util.spec_from_loader("tracemiku_main", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


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


def test_pull_retries_with_backoff():
    """目标进程活着时 adb 通道会被拖死, 死后立刻恢复: 拉取必须重试。"""
    _load_tracemiku()
    src = (ROOT / "tracemiku").read_text()
    assert "PULL_RETRY_DELAYS" in src
    assert "_pull_with_retry" in src, "拉取必须有重试阶梯"
    delays = mod_delays()
    assert len(delays) >= 2 and delays == tuple(sorted(delays)), "重试间隔必须递增"
    assert max(delays) >= 30, "要给目标进程自杀并释放 adb 通道留足时间"


def mod_delays():
    import importlib.machinery

    loader = importlib.machinery.SourceFileLoader("tm2", str(ROOT / "tracemiku"))
    spec = importlib.util.spec_from_loader("tm2", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m.PULL_RETRY_DELAYS


def test_pull_budgets_are_generous():
    """满载 trace 时 adb shell 显著变慢, 探测超时应远大于 5s。"""
    mod = _load_tracemiku()
    assert mod.ADB_PROBE_TIMEOUT >= 20
    assert mod.PULL_ATTEMPT_TIMEOUT >= 120
    assert mod.PULL_MAX_BYTES > 0
    assert mod.PULL_STAGE_TIMEOUT > 0
    assert mod.PULL_GATE_TIMEOUT > 0


def test_transfer_is_transactional():
    """传输必须先写 .part, 成功才替换; 且不得使用 adb exec-out 长连接。"""
    _load_tracemiku()
    src = (ROOT / "tracemiku").read_text()
    body = src[src.index("def adb_pull_device_trace("):]
    body = body[: body.index("\n    def ")]
    assert 'part = dst_path + ".part"' in body, "必须先写 .part"
    assert "os.replace(part, dst_path)" in body, "必须提交式替换"
    assert "os.unlink(part)" in body, "失败路径必须清理临时文件"
    # 提交(原子替换)必须早于删除设备源文件
    assert body.index("os.replace(part, dst_path)") < body.rindex("quote(device_path))")
    # 不得真的构造 exec-out 调用 (文档里提到它是可以的)
    assert 'adb_command("exec-out"' not in body, "传输不得使用 adb exec-out 长连接"
    assert "Popen" not in body, "传输不得留长连接子进程"
    assert 'adb_command("pull"' in body, "必须走 adb pull 完成传输"
    assert "expect_records" in body, "必须按 agent 上报的记录数校验字节数"


def test_transfer_disconnects_stdin():
    """adb exec-out 会把 stdin 传给设备端; 不切断会让 su/gzip 一直等输入。"""
    src = (ROOT / "tracemiku").read_text()
    assert 'stdin=subprocess.DEVNULL' in src
    assert src.count("stdin=subprocess.DEVNULL") >= 3, "探测/传输/删除三处都要切断 stdin"


def test_trace_never_reports_records_zero_as_complete():
    """拉取失败不得写出 records=0 的完成 call。"""
    src = (ROOT / "tracemiku").read_text()
    assert '"records": None if is_pending' in src
    assert 'trace_exit_code = 2' in src, "有 pending 时退出码必须非零"
    assert "./tracemiku finalize" in src, "必须打印恢复命令"
