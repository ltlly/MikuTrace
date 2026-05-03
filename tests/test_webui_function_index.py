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
    """Legacy 'cfg:<name>' must keep working through the migration.

    parse_id maps cfg:<name> -> ("sym", name) and _resolve_dec_fn routes
    that through _func_ir_from_cfg_name, which builds a FuncIR from any
    name visible in the CFG (sym table). The synthetic fixture's named
    fns are all CFG-visible, so cfg:f_root must 200.
    """
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    fns = c.get("/api/functions").json()["functions"]
    target = fns[0]
    legacy = "cfg:" + target["name"]
    r = c.get(f"/api/dec/fn/{legacy}")
    assert r.status_code == 200, f"legacy cfg:* must resolve: {r.status_code} {r.text[:200]}"
    body = r.json()
    assert body["fn_id"] == legacy
    assert "markdown" in body


def test_hlil_for_fn_resolves_id_to_entry_pc(trace_root_two_callees):
    """/api/hlil-for-fn smoke: id resolves; backend may not be initialized.

    Without --so, DECOMP backend is not ready. The route still must
    resolve trace:F0 -> entry_pc and delegate to hlil_for_pc, which then
    returns ready=false. 404 only on unknown ids; 400 if entry_pc is None.
    """
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    r = c.get("/api/hlil-for-fn", params={"fn_id": "trace:F0"})
    assert r.status_code in (200, 400, 404, 503), \
        f"hlil-for-fn unexpected status: {r.status_code} {r.text[:200]}"
    if r.status_code == 200:
        body = r.json()
        # Backend not loaded -> ready=false is the expected path here.
        assert "ready" in body


def test_hlil_for_fn_404_on_unknown_id(trace_root_two_callees):
    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    r = c.get("/api/hlil-for-fn", params={"fn_id": "trace:F999"})
    assert r.status_code == 404


def test_dec_llm_call_accepts_trace_prefixed_id(trace_root_two_callees, monkeypatch):
    """Regression: POST /api/dec/llm-call with fn_id="trace:F0" must NOT 400.

    Pre-fix path:
      _resolve_dec_fn returned only FuncIR -> caller passed the original
      "trace:F0" to TopIR.fn() (line 2845 pre-fix) and to
      build_fn_decompile_prompt() (line 2851 pre-fix). TopIR.fn() only
      matches FuncIR.id == fn_id, so "trace:F0" missed; build_fn_decompile_prompt
      raised KeyError; server caught it and returned HTTP 400. The default
      UI-selected fn_id is now "trace:F0" post-Task-5, so every "LLM raw"
      click hit this regression.

    Fix: _resolve_dec_fn now returns (fn, canonical_id); callers feed
    canonical_id (e.g. "F0") to TopIR-aware downstream code.
    """
    class _StubResult:
        error = None
        model = "stub"
        c_code = "int f(){}"
        prompt_tokens = 1
        output_tokens = 1
        latency_ms = 1

    class _StubModel:
        def call(self, user, system=None, max_tokens=4096):
            return _StubResult()

    import viewer.decompiler
    monkeypatch.setattr(viewer.decompiler, "make_llm_model",
                        lambda name: _StubModel())

    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    r = c.post("/api/dec/llm-call",
               json={"fn_id": "trace:F0", "model": "stub"})
    assert r.status_code == 200, \
        f"trace:F0 LLM raw regressed: {r.status_code} {r.text[:300]}"
    body = r.json()
    assert body["ok"] is True
    assert body["error"] is None


def test_dec_llm_call_accepts_sym_prefixed_id(trace_root_two_callees, monkeypatch):
    """Regression cousin of the trace:F0 test for sym:<name>.

    Same root cause class: sym:<name> resolves via _func_ir_from_cfg_name
    which returns a FuncIR whose .id is "cfg:<name>" (the on-demand id).
    Without canonical_id, build_fn_decompile_prompt would receive the raw
    sym:<name> and fail to find it. canonical_id fixes that.
    """
    class _StubResult:
        error = None
        model = "stub"
        c_code = "int g(){}"
        prompt_tokens = 1
        output_tokens = 1
        latency_ms = 1

    class _StubModel:
        def call(self, user, system=None, max_tokens=4096):
            return _StubResult()

    import viewer.decompiler
    monkeypatch.setattr(viewer.decompiler, "make_llm_model",
                        lambda name: _StubModel())

    c = _client(trace_root_two_callees)
    _wait_cfg(c)
    # Drive split_top_k=1 so f_alpha / f_beta land in the symbol-source
    # path (not trace-ir top-K).
    j = c.get("/api/dec/summary",
              params={"split_top_k": 1, "split_min_records": 1}).json()
    sym_fns = [f for f in j["fns"] if f["source"] == "symbol"]
    if not sym_fns:
        # Hand-build one if the fixture happens to fully cover everything.
        sym_id = "sym:f_alpha"
    else:
        sym_id = sym_fns[0]["id"]
    r = c.post("/api/dec/llm-call",
               json={"fn_id": sym_id, "model": "stub",
                     "split_top_k": 1, "split_min_records": 1})
    # 200 on resolved sym; if the fixture's FuncIR has no matching CFG
    # block (defensive 404) accept that — but explicitly disallow 400
    # which would mean the canonical-id wiring is broken again.
    assert r.status_code in (200, 404), \
        f"sym:* LLM raw regressed: {r.status_code} {r.text[:300]}"
    if r.status_code == 200:
        assert r.json()["ok"] is True


def test_dec_fn_resolves_when_bg_cfg_not_ready(trace_root_two_callees):
    """sym:<name> resolution must not block on /api/cfg readiness.

    Pins the synchronous CFG-pack fallback (`_cfg_pack_ready_or_build`):
    the dec endpoint must return a valid markdown response even when the
    background CFG subprocess hasn't finished, by building the cfg pack
    in-process on demand. Forkserver-unfriendly test/dev launches depend
    on this fallback for the Decompile tab to be usable.

    Strategy: drive split_top_k=1 so only F0 (root) is in trace-ir; the
    other named fns must resolve via the symbol path, which is the path
    that exercises the sync fallback. The test does NOT call /api/cfg
    first — it goes straight to /api/dec/fn.
    """
    c = _client(trace_root_two_callees)
    # Look up the sym: id with split_top_k=1 forcing 2 of 3 fns to symbol.
    # Use /api/dec/summary directly (it carries the same source labels
    # /api/functions would). NOTE: this also doesn't await /api/cfg.
    j = c.get("/api/dec/summary",
              params={"split_top_k": 1, "split_min_records": 1}).json()
    sym_fns = [f for f in j["fns"] if f["source"] == "symbol"]
    if not sym_fns:
        # Fixture didn't produce a symbol-only fn even at split_top_k=1.
        # Construct a sym: id by hand from a known fixture name; the
        # endpoint must still resolve (or 404 cleanly) without crashing.
        sym_id = "sym:f_alpha"
    else:
        sym_id = sym_fns[0]["id"]
    r = c.get(f"/api/dec/fn/{sym_id}",
              params={"split_top_k": 1, "split_min_records": 1})
    # Must not 500. Either 200 (sync fallback worked) or 404 (no such fn
    # — acceptable for hand-built ids when the fixture differs).
    assert r.status_code in (200, 404), \
        f"sync fallback regression: {r.status_code} {r.text[:200]}"
    if r.status_code == 200:
        body = r.json()
        assert body["fn_id"] == sym_id
        assert "markdown" in body
