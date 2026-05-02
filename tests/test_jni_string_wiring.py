"""Pin tests for JSON-driven JNI hook wiring.

之前 (Task #30) bug: agent flush 函数没被调; 修复后 trace-end 前必 flush.
后来 (Task #56) 重构成 JSON 驱动: 配置文件 tools/hooks/libart_jni.json 描述
要 hook 的 JNI vtable 函数, agent 用通用 installer 装 Interceptor, 输出走
type='jni-hooks' (event schema = {id, trace_idx, args:{...}, ret}). 旧
'jni-strings' type 仍兼容 (host dispatcher 接两个).
"""
import json, pathlib, re, pytest

HERE = pathlib.Path(__file__).resolve().parent.parent
AGENT_JS = HERE / "tracer" / "agent_cmodule_v5.js"
HOST_PY = HERE / "tracemiku"
HOOKS_JSON = HERE / "tools" / "hooks" / "libart_jni.json"


def _read(p): return pathlib.Path(p).read_text()


# ── JSON config ─────────────────────────────────────────────────────────────

def test_default_hooks_json_exists():
    assert HOOKS_JSON.exists(), f"默认 hooks 配置缺失: {HOOKS_JSON}"
    doc = json.loads(HOOKS_JSON.read_text())
    assert "hooks" in doc and isinstance(doc["hooks"], list)
    assert len(doc["hooks"]) >= 6   # 至少含 NewString/UTF + GetUTF{Length,Chars,Region} + ReleaseUTF


def test_default_hooks_json_schema_valid():
    """每个 hook 必含 id / vtable_offset / args / ret."""
    doc = json.loads(HOOKS_JSON.read_text())
    for h in doc["hooks"]:
        assert "id" in h, f"hook missing id: {h}"
        assert "vtable_offset" in h, f"{h['id']} missing vtable_offset"
        # vtable_offset 必须能 parseInt (16 进制 string)
        int(h["vtable_offset"], 16)
        assert "args" in h and isinstance(h["args"], list)
        for a in h["args"]:
            assert "name" in a and "type" in a, f"{h['id']} arg incomplete: {a}"
            assert a["type"] in ("ptr","int","long","void","cstring","utf16","bytes")
        assert "ret" in h and "type" in h["ret"]


# ── Agent 侧 ─────────────────────────────────────────────────────────────────

def test_agent_defines_install_and_flush():
    src = _read(AGENT_JS)
    assert "function installJniHooksOnce(" in src, "缺新 installJniHooksOnce"
    assert "function flushJniHookEvents(" in src, "缺新 flushJniHookEvents"
    # 兼容别名
    assert "function flushJniStringEvents(" in src, "缺旧 flushJniStringEvents 兼容"
    assert "function installJniStringHooksOnce(" in src, "缺旧 installJniStringHooksOnce 兼容"


def test_agent_flush_called_before_every_trace_end():
    """每条 send({type:'trace-end' ...}) 之前不远处必有 flush 调用 (alias 也可)."""
    src = _read(AGENT_JS)
    trace_end_sends = list(re.finditer(
        r'send\(\s*\{\s*type:\s*"trace-end"', src))
    assert len(trace_end_sends) >= 2
    for m in trace_end_sends:
        # 600-char window covers flushJni + flushExt + flushFork before trace-end
        before = src[max(0, m.start() - 600):m.start()]
        assert ("flushJniHookEvents" in before or "flushJniStringEvents" in before), (
            f"trace-end @{m.start()} 之前没 JNI flush call")


def test_agent_flush_sends_jni_hooks_message():
    """flushJniHookEvents 必须 send({type:'jni-hooks', ...})."""
    src = _read(AGENT_JS)
    m = re.search(r'function\s+flushJniHookEvents\s*\([^)]*\)\s*\{(.*?)^\}',
                  src, re.S | re.M)
    assert m, "找不到 flushJniHookEvents 函数体"
    body = m.group(1)
    assert '"jni-hooks"' in body, f"应 send type='jni-hooks', got:\n{body[:300]}"


def test_agent_flush_resets_buffer():
    src = _read(AGENT_JS)
    m = re.search(r'function\s+flushJniHookEvents\s*\([^)]*\)\s*\{(.*?)^\}',
                  src, re.S | re.M)
    body = m.group(1)
    assert re.search(r'jniHookEvents\s*=\s*\[\]', body), \
        f"flush 后必须 reset jniHookEvents=[], body:\n{body[:300]}"


def test_agent_uses_jni_hook_specs_from_opts():
    """RPC init 必须从 opts.jniHooks 读 spec, 不再硬编码 vtable offsets."""
    src = _read(AGENT_JS)
    assert "STATE.jniHookSpecs" in src
    assert "opts.jniHooks" in src
    # 旧 hardcoded HOOK_OFFSETS map 必须被移除
    assert 'const HOOK_OFFSETS' not in src or '0x520:' not in src, \
        "agent 不应再硬编码 vtable offset map"


def test_agent_resolves_jnienv_without_java_module():
    """Frida 17 删了 Java 全局, 必须用直接 dlsym (JNI_GetCreatedJavaVMs)."""
    src = _read(AGENT_JS)
    assert "JNI_GetCreatedJavaVMs" in src, "必须用 JNI_GetCreatedJavaVMs (Frida 17 兼容)"


# ── Host 侧 ──────────────────────────────────────────────────────────────────

def test_host_dispatcher_handles_jni_hooks():
    src = _read(HOST_PY)
    # 必须有 t == 'jni-hooks' 分支 (旧 jni-strings 也兼容)
    assert re.search(r't\s*==\s*["\']jni-hooks["\']', src), \
        "tracemiku 缺 'jni-hooks' dispatcher"


def test_host_writes_jsonl_per_call():
    src = _read(HOST_PY)
    assert "jni_hooks.jsonl" in src, "host 应写 jni_hooks.jsonl per-call dir"
    assert "jni_fp" in src, "host 应有 jni_fp session attr"


def test_host_loads_jni_hooks_json():
    """tracemiku CLI 必须能加载 --jni-hooks PATH 并传给 agent."""
    src = _read(HOST_PY)
    assert "--jni-hooks" in src
    assert '"jniHooks":' in src, "AGENT_OPTS 缺 jniHooks"
    assert "jh_doc" in src or 'json.loads' in src   # 至少有 JSON load


# ── 端到端 schema ───────────────────────────────────────────────────────────

def test_jni_event_schema_uses_named_args():
    """agent push 的事件 schema = {id, trace_idx, args:{...}, ret}."""
    src = _read(AGENT_JS)
    # _makeJsonHookHandler 内部 push 的字面量
    m = re.search(
        r'STATE\.jniHookEvents\.push\(\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}\s*\)',
        src, re.S)
    assert m, "找不到 jniHookEvents.push({...})"
    body = m.group(1)
    for field in ("id", "trace_idx", "args", "ret"):
        assert field in body, f"event 缺字段 {field!r}: {body[:300]}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
