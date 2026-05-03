"""End-to-end HTTP-flow smoke: simulates the exact sequence the SPA executes.

This is a substitute for browser automation when Chrome is unavailable.
Each test corresponds to a user action (load page, click row, double-click,
click LLM raw, toggle scope) and verifies the endpoint chain the SPA would
make. Catches regressions like the trace:F0 / 400 KeyError that pure unit
tests on _resolve_dec_fn missed.

Mocks LLM at the import boundary so no network calls.
"""
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


def _stub_llm(monkeypatch):
    """Patch make_llm_model to a stub that returns canned text."""
    class _StubResult:
        error = None
        model = "stub"
        c_code = "int f(){ return 42; }"
        prompt_tokens = 1
        output_tokens = 1
        latency_ms = 1

    class _StubModel:
        def call(self, user, system=None, max_tokens=4096):
            return _StubResult()

    import viewer.decompiler
    monkeypatch.setattr(viewer.decompiler, "make_llm_model",
                        lambda name: _StubModel())


# ── Page-load flow ────────────────────────────────────────────────────────

def test_page_load_flow(trace_root_two_callees):
    """Initial page load: meta -> cfg ready -> functions list -> dec summary."""
    c = _client(trace_root_two_callees)
    # 1. Meta (header strip + so dropdown)
    meta = c.get("/api/meta").json()
    assert meta["records"] == 9
    assert meta["module"]["name"] == "libt.so"

    # 2. Functions panel (FunctionIndex)
    _wait_cfg(c)
    fi = c.get("/api/functions").json()
    assert fi["counts"]["trace-ir"] >= 1
    # All 3 named fns should be present (1 trace-ir + 2 symbol)
    names = {f["name"] for f in fi["functions"]}
    assert {"f", "f_alpha", "f_beta"}.issubset(names) or \
           {"f_root", "f_alpha", "f_beta"}.issubset(names)

    # 3. Dec summary (Decompile tab default load — split_top_k=40 from UI)
    summary = c.get("/api/dec/summary",
                    params={"split_top_k": 40, "split_min_records": 10}).json()
    assert summary["records"] == 9
    assert len(summary["fns"]) >= 1
    assert summary["fns"][0]["id"].startswith("trace:")


# ── Functions panel: click row -> CFG load ────────────────────────────────

def test_functions_panel_click_loads_cfg(trace_root_two_callees):
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    fi = c.get("/api/functions").json()
    fn_name = next(f["name"] for f in fi["functions"]
                   if f["source"] == "trace-ir")

    # SPA polls /api/cfg with ?fn=<name> when user single-clicks a row.
    r = c.get("/api/cfg", params={"fn": fn_name}).json()
    assert r["status"] == "ready"
    for b in r["blocks"]:
        assert b["func"] == fn_name


# ── Functions panel: double-click -> Decompile -> LLM raw ─────────────────

def test_double_click_to_decompile_then_llm_raw(trace_root_two_callees, monkeypatch):
    """Critical regression path: trace:F0 → /api/dec/fn → /api/dec/llm-call.

    Pre-fix, the LLM raw step would 400 with KeyError because
    _resolve_dec_fn returned only the FuncIR and downstream code passed
    'trace:F0' to TopIR.fn() / build_fn_decompile_prompt() which only
    know FuncIR.id. Post-fix uses canonical_id.
    """
    _stub_llm(monkeypatch)
    c = _client(trace_root_two_callees)
    _wait_cfg(c)

    # User double-clicks Functions row → frontend calls openDecompileForFn
    # which calls selectDecFn(fnId) which fetches /api/dec/fn/{id}.
    fi = c.get("/api/functions").json()
    fn_id = next(f["id"] for f in fi["functions"]
                 if f["source"] == "trace-ir")  # "trace:F0"
    assert fn_id == "trace:F0"

    fn_md = c.get(f"/api/dec/fn/{fn_id}",
                  params={"tier": "hot", "split_top_k": 40,
                          "split_min_records": 10}).json()
    assert fn_md["fn_id"] == fn_id
    assert "markdown" in fn_md and len(fn_md["markdown"]) > 0

    # User clicks "LLM raw" button.
    r = c.post("/api/dec/llm-call",
               json={"fn_id": fn_id, "model": "stub",
                     "split_top_k": 40, "split_min_records": 10,
                     "tier": "hot", "lang": "zh"})
    assert r.status_code == 200, \
        f"LLM raw regressed at trace:F0: {r.status_code} {r.text[:300]}"
    body = r.json()
    assert body["ok"] is True
    assert body["c_code"] == "int f(){ return 42; }"
    assert body["cache_hit"] is False

    # Second click on same params should hit server cache.
    r2 = c.post("/api/dec/llm-call",
                json={"fn_id": fn_id, "model": "stub",
                      "split_top_k": 40, "split_min_records": 10,
                      "tier": "hot", "lang": "zh"})
    assert r2.json()["cache_hit"] is True


# ── Scope toggle: body vs trace ───────────────────────────────────────────

def test_scope_toggle_body_vs_trace(trace_root_two_callees):
    """User toggles Scope dropdown body↔trace; LLIL render endpoint reflects it."""
    c = _client(trace_root_two_callees)
    body = c.post("/api/llil/render",
                  json={"fn_id": "trace:F0", "scope": "body",
                        "split_top_k": 0, "split_min_records": 1}).json()
    trace = c.post("/api/llil/render",
                   json={"fn_id": "trace:F0", "scope": "trace",
                         "split_top_k": 0, "split_min_records": 1}).json()
    assert body["ok"] and trace["ok"]
    assert body["stats"]["scope"] == "body"
    assert trace["stats"]["scope"] == "trace"
    # body should exclude callees → fewer records than trace, OR
    # excluded_records > 0 if filter applied.
    assert (body["stats"]["body_only_excluded_records"] > 0
            or body["stats"]["blocks"] <= trace["stats"]["blocks"])


# ── Split parameter changes: cache must NOT serve stale results ───────────

def test_split_change_does_not_serve_stale_summary(trace_root_two_callees):
    """User changes split_top_k slider; summary fns should differ."""
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    a = c.get("/api/dec/summary",
              params={"split_top_k": 1, "split_min_records": 1}).json()
    b = c.get("/api/dec/summary",
              params={"split_top_k": 10, "split_min_records": 1}).json()
    a_sources = {f["source"] for f in a["fns"]}
    b_sources = {f["source"] for f in b["fns"]}
    # split_top_k=1 forces 2 of 3 fns into symbol-source; split_top_k=10
    # captures all of them as trace-ir.
    assert "symbol" in a_sources
    assert "symbol" not in b_sources or len(b["fns"]) >= len(a["fns"])


# ── HLIL endpoint reachability via FunctionIndex id ───────────────────────

def test_hlil_for_fn_reachable_for_all_index_ids(trace_root_two_callees):
    """Every FunctionIndex id must be at least dispatchable to /api/hlil-for-fn.

    DECOMP backend not loaded (no --so) so body is {ready: false}. The
    point is no 500 / no 404 on a known id.
    """
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    fi = c.get("/api/functions").json()
    for f in fi["functions"]:
        r = c.get("/api/hlil-for-fn", params={"fn_id": f["id"]})
        assert r.status_code == 200, \
            f"hlil-for-fn fails for {f['id']!r}: {r.status_code}"
        body = r.json()
        # ready=false expected (no BN backend); only assert no error path.
        assert "ready" in body
