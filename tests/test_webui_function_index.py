"""Endpoint contract tests for /api/functions (FunctionIndex)."""
import time

from fastapi.testclient import TestClient


def _client(trace_dir):
    from webui.server import make_app
    return TestClient(make_app(trace_dir))


def _wait_cfg(c, timeout=10.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if c.get("/api/cfg").json().get("status") == "ready":
            return
        time.sleep(0.1)
    raise AssertionError("cfg never ready")


def test_api_functions_returns_unified_index(trace_root_two_callees):
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    r = c.get("/api/functions").json()
    assert "functions" in r
    assert "counts" in r
    fns = r["functions"]
    assert isinstance(fns, list) and len(fns) >= 1
    counts = r["counts"]
    for k in ("trace-ir", "symbol", "bn"):
        assert k in counts and isinstance(counts[k], int)
    assert sum(counts.values()) == len(fns)
    for f in fns:
        for required in ("id", "name", "source", "blocks"):
            assert required in f, (required, f)
        assert f["source"] in {"trace-ir", "symbol", "bn"}
        if f["source"] == "trace-ir":
            assert f["id"].startswith("trace:")
            assert f["trace_ir_id"]
        elif f["source"] == "symbol":
            assert f["id"].startswith("sym:")
        else:
            assert f["id"].startswith("bn:")


def test_api_functions_no_duplicate_names(trace_root_two_callees):
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    fns = c.get("/api/functions").json()["functions"]
    names = [f["name"] for f in fns]
    assert len(names) == len(set(names))
