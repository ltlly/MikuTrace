"""Equivalence snapshots: lock current payload shape so the FunctionIndex
refactor cannot silently regress.

Each test pins the fields that MUST remain stable; an intentional change
to the schema requires deliberately editing the matching assertion here.
"""
import time

from fastapi.testclient import TestClient


def _client(trace_dir):
    from webui.server import make_app
    return TestClient(make_app(trace_dir))


def _wait_cfg(client, timeout=10.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        r = client.get("/api/cfg").json()
        if r.get("status") == "ready":
            return r
        time.sleep(0.1)
    raise AssertionError(f"cfg never became ready: {r}")


# ── /api/cfg ────────────────────────────────────────────────────────────────

def test_api_cfg_baseline_shape(trace_root_two_callees):
    c = _client(trace_root_two_callees)
    r = _wait_cfg(c)
    assert r["status"] == "ready"
    assert r["block_count"] >= 3
    assert r["edge_count"] >= 0
    assert isinstance(r["funcs"], list)
    names = {f["name"] for f in r["funcs"]}
    assert {"f_root", "f_alpha", "f_beta"}.issubset(names)
    for f in r["funcs"]:
        assert set(f.keys()) == {"name", "blocks"}
        assert isinstance(f["blocks"], int) and f["blocks"] > 0


def test_api_cfg_filter_by_function(trace_root_two_callees):
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    r = c.get("/api/cfg", params={"fn": "f_alpha"}).json()
    assert r["status"] == "ready"
    assert isinstance(r["blocks"], list)
    for b in r["blocks"]:
        assert b["func"] == "f_alpha"


# ── /api/dec/summary ────────────────────────────────────────────────────────

def test_api_dec_summary_includes_trace_and_symbol_sources(trace_root_two_callees):
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    j = c.get("/api/dec/summary",
              params={"split_top_k": 2, "split_min_records": 1}).json()
    by_source = {}
    for f in j["fns"]:
        by_source.setdefault(f["source"], []).append(f)
    assert "trace-ir" in by_source, by_source
    for f in by_source["trace-ir"]:
        assert f["id"].startswith("F"), f["id"]
        assert f["entry_idx"] is not None
    if "symbol" in by_source:
        for f in by_source["symbol"]:
            assert f["id"].startswith("cfg:"), f["id"]


# ── /api/dec/fn/{id} ────────────────────────────────────────────────────────

def test_api_dec_fn_traceir_id_works(trace_root_two_callees):
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    j = c.get("/api/dec/summary",
              params={"split_top_k": 2, "split_min_records": 1}).json()
    trace_fns = [f for f in j["fns"] if f["source"] == "trace-ir"]
    assert trace_fns, "expected at least one trace-ir fn in summary"
    fn = trace_fns[0]
    r = c.get(f"/api/dec/fn/{fn['id']}").json()
    assert r["fn_id"] == fn["id"]
    assert r["name"] == fn["name"]
    assert "markdown" in r


def test_api_dec_fn_symbol_id_works(trace_root_two_callees):
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    j = c.get("/api/dec/summary",
              params={"split_top_k": 2, "split_min_records": 1}).json()
    sym_fns = [f for f in j["fns"] if f["source"] == "symbol"]
    if not sym_fns:
        # Acceptable: fixture's symbols may be fully covered by trace-ir
        # split. Don't assert their presence, only that IF present they work.
        return
    fn = sym_fns[0]
    r = c.get(f"/api/dec/fn/{fn['id']}").json()
    assert r["fn_id"] == fn["id"]
    assert "markdown" in r


# ── /api/llil/render scope ──────────────────────────────────────────────────

def test_llil_render_scope_body_excludes_callees(trace_root_two_callees):
    c = _client(trace_root_two_callees)
    payload = {"fn_id": "F0", "scope": "body",
               "split_top_k": 0, "split_min_records": 1}
    r = c.post("/api/llil/render", json=payload).json()
    assert r["ok"] is True, r
    assert r["stats"]["scope"] == "body"
    assert r["stats"]["body_only"] is True


def test_llil_render_scope_trace_keeps_callees(trace_root_two_callees):
    c = _client(trace_root_two_callees)
    payload = {"fn_id": "F0", "scope": "trace",
               "split_top_k": 0, "split_min_records": 1}
    r = c.post("/api/llil/render", json=payload).json()
    assert r["ok"] is True, r
    assert r["stats"]["scope"] == "trace"
    assert r["stats"]["body_only"] is False


def test_llil_render_body_only_alias_maps_to_scope_body(trace_root_two_callees):
    """Compat alias: {body_only: true} → scope='body'."""
    c = _client(trace_root_two_callees)
    payload = {"fn_id": "F0", "body_only": True,
               "split_top_k": 0, "split_min_records": 1}
    r = c.post("/api/llil/render", json=payload).json()
    assert r["ok"] is True, r
    assert r["stats"]["scope"] == "body"
    assert r["stats"]["body_only"] is True


def test_llil_render_body_only_false_alias_maps_to_scope_trace(trace_root_two_callees):
    """Compat alias: {body_only: false} → scope='trace'."""
    c = _client(trace_root_two_callees)
    payload = {"fn_id": "F0", "body_only": False,
               "split_top_k": 0, "split_min_records": 1}
    r = c.post("/api/llil/render", json=payload).json()
    assert r["ok"] is True, r
    assert r["stats"]["scope"] == "trace"
    assert r["stats"]["body_only"] is False
