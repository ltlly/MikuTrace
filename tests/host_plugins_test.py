"""可信目标加载与插件生命周期；无需设备。"""
import json
import pathlib
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from tracemiku_target import HostPlugin, apply_target, load_target


def profile(tmp_path, **overrides):
    path = tmp_path / "target.json"
    path.write_text(json.dumps({"schema_version": 1, "target": {"so": "libdemo.so", "export": "entry"}, **overrides}))
    return path


def test_profile_relative_plugins_and_explicit_precedence(tmp_path):
    (tmp_path / "agent.js").write_text("module.exports = {apiVersion: 1};")
    path = profile(tmp_path, capture={"max_calls": 42, "trace_init": True}, agent_plugins=[{
        "id": "demo", "path": "agent.js", "config": {"a": 1},
    }])
    doc = load_target(path)
    args = types.SimpleNamespace(so="override", export=None, max_calls=100, trace_init=False)
    apply_target(args, doc, {"so"})
    assert args.so == "override"
    assert args.export == "entry"
    assert args.max_calls == 42
    assert args.trace_init is True
    assert not hasattr(args, "transport")
    assert doc["agent_plugins"][0]["source"].startswith("module.exports")


@pytest.mark.parametrize("overrides", [
    {"schema_version": 2}, {"unknown": 1}, {"transport": "auto"},
    {"capture": {"max_calls": True}}, {"capture": {"evil": 1}},
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
