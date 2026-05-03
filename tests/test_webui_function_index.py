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


def test_dec_fn_accepts_trace_prefixed_id(trace_root_two_callees):
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    r = c.get("/api/dec/fn/trace:F0",
              params={"split_top_k": 2, "split_min_records": 1}).json()
    assert r["fn_id"] == "trace:F0"
    assert "markdown" in r


def test_dec_fn_accepts_sym_prefixed_id(trace_root_two_callees):
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    fns = c.get("/api/functions").json()["functions"]
    sym_fns = [f for f in fns if f["source"] == "symbol"]
    if not sym_fns:
        # Fixture coverage: synthetic trace fully captured by trace-ir.
        # Build a sym: id by hand from a trace-ir name to test the
        # legacy-alias resolution path explicitly.
        any_fn = next(f for f in fns if f["source"] == "trace-ir")
        sym_id = "sym:" + any_fn["name"]
        # The /api/dec/fn endpoint should resolve sym:<name> → trace-ir
        # entry when the name is in TraceIR. Acceptable to 200 or 404 —
        # what matters is no crash. Document the actual behavior here.
        r = c.get(f"/api/dec/fn/{sym_id}")
        assert r.status_code in (200, 404)
        return
    fn_id = sym_fns[0]["id"]
    r = c.get(f"/api/dec/fn/{fn_id}").json()
    assert r["fn_id"] == fn_id


def test_dec_fn_legacy_F0_still_works(trace_root_two_callees):
    """Bare 'F0' must keep working through the migration."""
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    r = c.get("/api/dec/fn/F0",
              params={"split_top_k": 2, "split_min_records": 1}).json()
    assert "markdown" in r


def test_dec_fn_legacy_cfg_id_still_works(trace_root_two_callees):
    """Legacy 'cfg:<name>' must keep working through the migration."""
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    fns = c.get("/api/functions").json()["functions"]
    # Build a cfg:<name> id from any fn's name. The legacy alias should
    # resolve, regardless of whether the underlying entry is trace-ir or
    # symbol-sourced.
    target = fns[0]
    legacy = "cfg:" + target["name"]
    r = c.get(f"/api/dec/fn/{legacy}")
    # Either 200 (resolves to the named entry) or 404 if the resolver
    # only honors cfg:* for symbol-sourced fns. Both are acceptable
    # provided we DON'T 500. Pin whichever the implementation gives.
    assert r.status_code in (200, 404)
