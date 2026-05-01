"""Pin tests for JNI string hook wiring (Task #30).

之前 bug: agent 定义了 flushJniStringEvents 但全仓 0 调用, 事件 push 到
STATE.jniStringEvents 后从不发给 host. 修复: trace-end 前调 flush, host 接
'jni-strings' 写到 sess meta. 本测试静态扫源码确保 wiring 不再断:

1. agent: flushJniStringEvents 必须在每条 trace-end 前被调
2. host: tracemiku 的消息 dispatcher 必须有 'jni-strings' 分支
3. finalize_call 流程把 jni_strings 写进 meta.json (通过 setdefault)
"""
import json, pathlib, re, pytest

HERE = pathlib.Path(__file__).resolve().parent.parent
AGENT_JS = HERE / "tracer" / "agent_cmodule_v5.js"
HOST_PY = HERE / "tracemiku"


def _read(p):
    return pathlib.Path(p).read_text()


# ── Agent 侧 ─────────────────────────────────────────────────────────────────

def test_agent_defines_flush_function():
    src = _read(AGENT_JS)
    assert "function flushJniStringEvents(" in src, "flushJniStringEvents 定义缺失"


def test_agent_flush_called_before_every_trace_end():
    """每条 send({type:'trace-end' ...}) 之前不远处必有 flushJniStringEvents 调用."""
    src = _read(AGENT_JS)
    # 找 trace-end send 的所有位置
    trace_end_sends = list(re.finditer(
        r'send\(\s*\{\s*type:\s*"trace-end"', src))
    assert len(trace_end_sends) >= 2, (
        f"应至少 2 处 trace-end (onLeave + watchdog), got {len(trace_end_sends)}")
    # 每个之前 200 字符内应有 flushJniStringEvents
    for m in trace_end_sends:
        before = src[max(0, m.start() - 400):m.start()]
        assert "flushJniStringEvents(" in before, (
            f"trace-end @{m.start()} 之前 400 字符没找到 flushJniStringEvents — "
            f"该 trace-end 路径会丢 JNI string 数据.\n"
            f"context: ...{before[-200:]}")


def test_agent_flush_sends_jni_strings_message():
    """flushJniStringEvents 内部必须 send({type:'jni-strings', ...})."""
    src = _read(AGENT_JS)
    m = re.search(r'function\s+flushJniStringEvents\s*\([^)]*\)\s*\{(.*?)^\}',
                  src, re.S | re.M)
    assert m, "无法定位 flushJniStringEvents 函数体"
    body = m.group(1)
    assert 'type:' in body and '"jni-strings"' in body, (
        f"flushJniStringEvents 必须 send type='jni-strings', body:\n{body[:300]}")


def test_agent_flush_resets_buffer():
    """flush 后必须清空 STATE.jniStringEvents (防重复 send)."""
    src = _read(AGENT_JS)
    m = re.search(r'function\s+flushJniStringEvents\s*\([^)]*\)\s*\{(.*?)^\}',
                  src, re.S | re.M)
    body = m.group(1)
    # 至少一处把 jniStringEvents 设回 [] 或类似
    assert re.search(r'jniStringEvents\s*=\s*\[\]', body), (
        f"flush 后应 reset jniStringEvents=[], body:\n{body[:300]}")


def test_agent_jni_event_pushes_after_install():
    """installJniStringHooksOnce 设了 jniStringEvents=[], 之后 hook onLeave push."""
    src = _read(AGENT_JS)
    assert "STATE.jniStringEvents = []" in src
    assert re.search(r'jniStringEvents\s*\.\s*push\s*\(', src), (
        "hook onLeave 应 push 事件到 jniStringEvents")


# ── Host 侧 ──────────────────────────────────────────────────────────────────

def test_host_dispatcher_handles_jni_strings():
    src = _read(HOST_PY)
    # 必须有 t == "jni-strings" 分支 (或 elif 'jni-strings' in ...)
    assert re.search(r't\s*==\s*["\']jni-strings["\']', src), (
        "tracemiku host dispatcher 缺 'jni-strings' 分支 — agent 数据落到 else 兜底 log")


def test_host_writes_jni_strings_to_meta():
    src = _read(HOST_PY)
    # handler 必须把 events 写到 sess_files[ci]["meta"]["jni_strings"]
    # 用 setdefault('jni_strings', [...]) 或 直接赋值
    assert "jni_strings" in src, "host 应在 meta 里写 jni_strings 字段"
    # finalize_call json.dump(md) 已经存在 — md 自带 jni_strings 字段会落盘


# ── 端到端 schema ──────────────────────────────────────────────────────────

def test_jni_event_schema_in_agent():
    """agent push 的事件应至少含 fn, head, jstring, buf, content 字段
    (host 之后用这些做 trace idx 关联 + content 显示).
    """
    src = _read(AGENT_JS)
    # 找 makeJniStringHook 内 ev = { ... } 字面量
    m = re.search(r'const\s+ev\s*=\s*\{([^}]+)\}', src)
    assert m, "无法在 makeJniStringHook 找到 ev = { ... }"
    ev_body = m.group(1)
    for field in ("fn", "head", "jstring", "buf", "content"):
        assert field in ev_body, f"event 缺字段 {field!r}: {ev_body}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
