"""可信目标加载与窗口 1 回传契约；无需设备。"""
import json
import pathlib
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from tracemiku_target import HostPlugin, apply_target, load_target
from tracemiku_transport import FridaTransport


class Script:
    def __init__(self, contents, fault=None):
        self.contents = contents
        self.fault = fault
        self.ops = []
        self.offset = 0
        self.receiver = FridaTransport(self, timeout=1, chunk_bytes=4096)

    def post(self, message):
        p = message["payload"]
        self.ops.append(p["op"])
        response = {"type": "spool-response", "id": p["id"], "op": p["op"]}
        data = None
        if p["op"] == "cancel":
            return
        if self.fault == "timeout":
            return
        if p["op"] == "open":
            response["size"] = len(self.contents)
        if p["op"] == "read":
            assert p["offset"] == self.offset
            response["offset"] = p["offset"]
            data = self.contents[p["offset"]:p["offset"] + p["count"]]
            self.offset += len(data)
            if self.fault == "offset":
                response["offset"] += 1
            if self.fault == "short":
                data = data[:-1]
        if self.fault == "error":
            response["error"] = "device read failed"
        self.receiver.on_message({"type": "send", "payload": response}, data)


def test_binary_transaction_multichunk_and_zero_fork(tmp_path):
    contents = bytes(range(256)) * 100
    scr = Script(contents)
    dst = tmp_path / "trace.bin"
    assert scr.receiver.pull("/spool/trace.bin", dst, expect_bytes=len(contents)) == len(contents)
    assert dst.read_bytes() == contents
    assert scr.ops == ["open"] + ["read"] * 7 + ["close"]
    assert not (tmp_path / "trace.bin.part").exists()


@pytest.mark.parametrize("fault", ["offset", "short", "error", "timeout"])
def test_transfer_failure_preserves_destination_and_spool(tmp_path, fault):
    scr = Script(b"a" * 10000, fault=fault)
    dst = tmp_path / "trace.bin"
    dst.write_bytes(b"original")
    with pytest.raises((RuntimeError, TimeoutError)):
        scr.receiver.pull("/spool/trace.bin", dst)
    assert dst.read_bytes() == b"original"
    assert not (tmp_path / "trace.bin.part").exists()
    assert scr.ops[-1] == "cancel"
    assert "unlink" not in scr.ops


def test_budget_alignment_and_expected_size(tmp_path):
    for kwargs in ({"expect_bytes": 200}, {"record_size": 272}):
        scr = Script(b"a" * 100)
        with pytest.raises(RuntimeError):
            scr.receiver.pull("/spool/trace.bin", tmp_path / "trace.bin", **kwargs)
        assert "read" not in scr.ops
    scr = Script(b"a" * 100)
    scr.receiver.max_bytes = 10
    with pytest.raises(RuntimeError):
        scr.receiver.pull("/spool/trace.bin", tmp_path / "trace.bin")


def test_existing_part_is_not_overwritten_or_deleted(tmp_path):
    dst = tmp_path / "trace.bin"
    part = tmp_path / "trace.bin.part"
    part.write_bytes(b"other transaction")
    scr = Script(b"abc")
    with pytest.raises(FileExistsError):
        scr.receiver.pull("/spool/trace.bin", dst)
    assert part.read_bytes() == b"other transaction"


def profile(tmp_path, **overrides):
    path = tmp_path / "target.json"
    path.write_text(json.dumps({"schema_version": 1, "target": {"so": "libdemo.so", "export": "entry"}, **overrides}))
    return path


def test_profile_relative_plugins_and_explicit_precedence(tmp_path):
    (tmp_path / "agent.js").write_text("module.exports = {apiVersion: 1};")
    path = profile(tmp_path, capture={"max_records": 42}, agent_plugins=[{
        "id": "demo", "path": "agent.js", "config": {"a": 1},
    }])
    doc = load_target(path)
    args = types.SimpleNamespace(so="override", export=None, max_records=100)
    apply_target(args, doc, {"so"})
    assert args.so == "override"
    assert args.export == "entry"
    assert args.max_records == 42
    assert args.transport == "frida"
    assert doc["agent_plugins"][0]["source"].startswith("module.exports")


@pytest.mark.parametrize("overrides", [
    {"schema_version": 2}, {"unknown": 1}, {"transport": "auto"},
    {"capture": {"max_records": True}}, {"capture": {"evil": 1}},
    {"agent_plugins": [{}] * 9}, {"host_plugin": {"path": "missing.py"}},
])
def test_profile_rejects_invalid_config(tmp_path, overrides):
    with pytest.raises((ValueError, OSError)):
        load_target(profile(tmp_path, **overrides))


def test_profile_rejects_large_source_and_duplicate_id(tmp_path):
    script = tmp_path / "agent.js"
    spec = {"id": "demo", "path": script.name}
    script.write_text("x" * (1024 * 1024 + 1))
    with pytest.raises(ValueError):
        load_target(profile(tmp_path, agent_plugins=[spec]))
    script.write_text("module.exports = {apiVersion: 1};")
    with pytest.raises(ValueError):
        load_target(profile(tmp_path, agent_plugins=[spec, spec]))


def test_host_plugin_lifecycle_version_failure_timeout(tmp_path):
    path = tmp_path / "host.py"
    path.write_text("API_VERSION=1\ndef prepare(ctx): return {'value': ctx['config']['v']}\n")
    hook = HostPlugin({"path": str(path), "config": {"v": 7}})
    assert hook.call("prepare", {}) == {"value": 7}
    assert hook.call("finish", {}) is None
    path.write_text("API_VERSION=2\n")
    with pytest.raises(RuntimeError, match="API_VERSION"):
        HostPlugin({"path": str(path), "config": {}}).call("prepare", {})
    path.write_text("API_VERSION=1\ndef prepare(ctx):\n import time\n time.sleep(0.1)\n")
    with pytest.raises(TimeoutError):
        HostPlugin({"path": str(path), "config": {}}).call("prepare", {}, timeout=0.01)
