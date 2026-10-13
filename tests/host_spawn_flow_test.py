"""采集生命周期：先探测路径，再独立化采集器，最后启用目标调用。"""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tracemiku_capture as capture_module
from tracemiku_commands import build_parser


@pytest.fixture
def environment(tmp_path, monkeypatch):
    sequence = []
    root = tmp_path / "repo"
    (root / "tracer").mkdir(parents=True)
    (root / "tracer/_agent.js").write_text("// FakeScript executes the lifecycle")
    prepared = {"deviceDir": "/private/session", "manifestPath": "/private/session/session.json",
                "sessionId": "a" * 32, "pid": 4242}
    class Rpc:
        def __init__(self, kind):
            self.kind = kind
        def prepare_spool(self, opts):
            sequence.append("prepare")
            prepared["sessionId"] = opts["sessionId"]
            return prepared
        def init(self, opts):
            sequence.append("init")
            assert "maxRecords" not in opts
            assert opts["maxCalls"] == 1
            return env.init_result
        def control_address(self):
            return "0x1234"
        def start_capture(self):
            sequence.append("start")
        def stats(self):
            sequence.append("stats")
            return env.stats
        def stop_capture(self):
            sequence.append("stop-new-calls")
            return "stopped"
    class Script:
        def __init__(self, kind):
            self.kind = kind
            self.exports_sync = Rpc(kind)
        def on(self, *args):
            pass
        def load(self):
            sequence.append(f"load-{self.kind}")
        def eternalize(self):
            sequence.append("eternalize")
        def unload(self):
            sequence.append(f"unload-{self.kind}")
    class Session:
        scripts = 0
        def on(self, *args):
            pass
        def create_script(self, source):
            self.scripts += 1
            return Script("collector" if self.scripts == 1 else "control")
        def detach(self):
            sequence.append("detach")
    class Device:
        def spawn(self, args):
            sequence.append("spawn")
            return 4242
        def attach(self, pid):
            sequence.append("attach")
            return Session()
        def resume(self, pid):
            sequence.append("resume")
        def kill(self, pid):
            sequence.append("kill")
    class Spool:
        def __init__(self, log):
            pass
        def shell(self, *args, **kwargs):
            return "gzip sha256sum dd"
        def verify_preflight(self, opts):
            sequence.append("verify-preflight")
            if env.preflight_error:
                raise PermissionError("root cannot read the actual spool")
    env = SimpleNamespace(sequence=sequence, root=root, init_result="armed", preflight_error=False,
                          stats={"completedCalls": 1, "head": 30})
    device = Device()
    monkeypatch.setitem(sys.modules, "frida", SimpleNamespace(get_device_manager=lambda:
        SimpleNamespace(add_remote_device=lambda address: device)))
    monkeypatch.setattr(capture_module, "AdbSpool", Spool)
    monkeypatch.setattr(capture_module, "_select_adb_serial", lambda: "test-serial")
    def recover(out, rust_json, **kwargs):
        sequence.append("recover")
        descriptor = json.loads((Path(out) / "recovery.json").read_text())
        assert descriptor["sessions"] == [prepared]
        return {"schema_version": 1, "status": "ok", "out": str(out), "calls": [], "pending": [], "error": None}
    monkeypatch.setattr(capture_module, "recover_run", recover)
    return env


def args(tmp_path):
    return build_parser().parse_args(["trace", "--spawn", "--pkg", "dev.fixture",
        "--so", "libfixture.so", "--export", "entry", "--jni-hooks", "none",
        "--remote", "127.0.0.1:6699", "--out", str(tmp_path / "out")])


def test_spawn_preflight_eternalize_start_resume_and_post_capture_transfer(environment, tmp_path):
    env = environment
    result = capture_module.capture(args(tmp_path), env.root, None, lambda message: None)
    assert result["status"] == "ok"
    assert env.sequence == ["spawn", "attach", "load-collector", "prepare", "verify-preflight",
        "init", "eternalize", "load-control", "start", "resume", "stats", "stop-new-calls",
        "unload-control", "detach", "recover"]
    assert "unload-collector" not in env.sequence, "host 生命周期不能结束设备采集器"
    assert "kill" not in env.sequence, "完整返回后不需要 force-stop 应用"


def test_failed_path_preflight_never_arms_or_resumes(environment, tmp_path):
    env = environment
    env.preflight_error = True
    with pytest.raises(PermissionError):
        capture_module.capture(args(tmp_path), env.root, None, lambda message: None)
    assert "init" not in env.sequence and "start" not in env.sequence
    assert "resume" not in env.sequence and "kill" in env.sequence
    assert "eternalize" not in env.sequence


def test_cmodule_failure_has_no_active_collector(environment, tmp_path):
    env = environment
    env.init_result = "no-cmodule"
    with pytest.raises(RuntimeError, match="no-cmodule"):
        capture_module.capture(args(tmp_path), env.root, None, lambda message: None)
    assert "eternalize" not in env.sequence and "resume" not in env.sequence
    assert "unload-collector" in env.sequence and "kill" in env.sequence


def test_existing_pending_data_is_never_cleared(environment, tmp_path):
    env = environment
    source = tmp_path / "out/calls/_pending_call_001/trace.bin"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"must survive")
    with pytest.raises(ValueError, match="已有采集数据"):
        capture_module.capture(args(tmp_path), env.root, None, lambda message: None)
    assert source.read_bytes() == b"must survive"
    assert env.sequence == []


def test_deferred_agent_failure_is_reported_without_killing_resumed_app(environment, tmp_path):
    env = environment
    env.stats = {"completedCalls": 0, "head": 0, "error": "export missing after dlopen"}
    with pytest.raises(RuntimeError, match="export missing"):
        capture_module.capture(args(tmp_path), env.root, None, lambda message: None)
    assert "resume" in env.sequence and "kill" not in env.sequence
    assert "unload-control" in env.sequence and "detach" in env.sequence
    assert (tmp_path / "out/recovery.json").is_file()


def test_spawn_and_attach_remain_mutually_exclusive(environment, tmp_path):
    options = args(tmp_path)
    options.attach_pid = 100
    with pytest.raises(ValueError, match="互斥"):
        capture_module.capture(options, environment.root, None, lambda message: None)
