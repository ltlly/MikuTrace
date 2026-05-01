"""webui frontend smoke tests via Playwright + 任何 Chromium-based 浏览器.

Ubuntu 26.04 没 Playwright 官方 chromium 二进制 — 探测多个本机 chromium-based
路径作 executable_path. 测前端基础渲染、滚动、列宽拖拽、cursor 同步、错误响应不弹炸.

浏览器探测顺序:
  1. PLAYWRIGHT_BROWSER_EXECUTABLE  环境变量 (CI / 用户指定)
  2. 系统 PATH 上的 chromium-based: chromium / google-chrome / microsoft-edge
  3. 常见 hard-coded 路径
默认全 skip if 没找到 + 给出明确提示.

跑 -m slow (启 webui server + headless 浏览器 ~5-15s).
"""
import json, os, shutil, struct, threading, time, pathlib, pytest


HERE = pathlib.Path(__file__).resolve().parent.parent

# 候选 chromium-based 浏览器 (按优先级). 找到第一个可执行的.
_BROWSER_CANDIDATES = [
    # PATH 上的命令名
    "chromium", "chromium-browser",
    "google-chrome", "google-chrome-stable",
    "microsoft-edge", "microsoft-edge-stable",
    "brave-browser", "vivaldi",
    # 常见绝对路径
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
]


def _find_browser() -> str | None:
    """Return executable path for any chromium-based browser on this machine.
    Order: env override > PATH lookup > hardcoded macOS paths."""
    override = os.environ.get("PLAYWRIGHT_BROWSER_EXECUTABLE")
    if override and pathlib.Path(override).exists():
        return override
    for cand in _BROWSER_CANDIDATES:
        if "/" in cand:
            if pathlib.Path(cand).exists():
                return cand
        else:
            found = shutil.which(cand)
            if found:
                return found
    return None


_BROWSER = _find_browser()


pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(_BROWSER is None, reason=(
        "未找到 chromium-based 浏览器. "
        "装 chromium / google-chrome / microsoft-edge, "
        "或设 PLAYWRIGHT_BROWSER_EXECUTABLE=/path/to/browser")),
]


def _make_synth_trace(tmp_path):
    """合成 22-record trace (3× block A + B), 让 webui 有数据可显示."""
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_fe"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    n = 0
    a_asm = ["nop"]*5 + ["br x14"]
    b_asm = ["nop"]*3 + ["ret"]
    for blocks in [(0, a_asm)]*3 + [(0x100, b_asm)]:
        bstart, asm_list = blocks
        for asm in asm_list:
            inst, _ = ks.asm(asm)
            ii = int.from_bytes(bytes(inst), "little")
            bf.write(struct.pack("<Q", base + bstart))
            for _ in range(31): bf.write(struct.pack("<Q", 0))
            bf.write(struct.pack("<Q", 0x7000))
            bf.write(struct.pack("<I", 0))
            bf.write(struct.pack("<I", ii))
            bstart += 4; n += 1
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": n, "ms": 1, "retval": "0x0",
               "truncated": False, "last_insn_is_ret": True},
              open(cd / "meta.json", "w"))
    json.dump({"pkg": "tst", "so": "libt", "method": "f", "cmd": 1,
               "module": {"name": "libt.so", "base": hex(base), "size": 0x10000},
               "fn_addr": hex(base)},
              open(run / "meta.json", "w"))
    return cd


@pytest.fixture(scope="module")
def webui_url(tmp_path_factory):
    """启动 uvicorn + webui FastAPI app 在后台线程, yield URL."""
    import uvicorn
    tmp = tmp_path_factory.mktemp("fe")
    cd = _make_synth_trace(tmp)
    from webui.server import make_app
    app = make_app(cd)

    # 找空闲端口
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()

    config = uvicorn.Config(app, host="127.0.0.1", port=port,
                            log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # 等 server ready
    import urllib.request
    for _ in range(40):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=0.5)
            break
        except Exception:
            time.sleep(0.1)
    else:
        pytest.fail("webui server 没起来")

    yield f"http://127.0.0.1:{port}"
    server.should_exit = True


@pytest.fixture(scope="module")
def browser():
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=_BROWSER, headless=True,
                              args=["--no-sandbox", "--disable-gpu"])
        yield b
        b.close()


@pytest.fixture
def page(browser, webui_url):
    p = browser.new_page(viewport={"width": 1600, "height": 900})
    p.goto(webui_url, wait_until="networkidle", timeout=10_000)
    yield p
    p.close()


# ── basic render ────────────────────────────────────────────────────────────

def test_index_html_loads(page, webui_url):
    """主页 HTML 应含核心 mount 点."""
    title = page.title()
    assert "miku" in title.lower() or "trace" in title.lower(), f"title={title!r}"
    # 关键元素: stream / stream-header / asm-col / cmdbar
    for sel in ("#stream", "#stream-header", "#asm-col", "#cmdbar"):
        assert page.query_selector(sel) is not None, f"缺 {sel} 元素"


def test_no_console_errors_on_load(browser, webui_url):
    """加载页面期间不应有 JS console error."""
    p = browser.new_page()
    errors = []
    p.on("pageerror", lambda exc: errors.append(str(exc)))
    p.on("console", lambda msg: msg.type == "error" and errors.append(msg.text))
    p.goto(webui_url, wait_until="networkidle", timeout=10_000)
    p.wait_for_timeout(500)
    p.close()
    assert not errors, f"页面加载出错: {errors[:5]}"


def test_disasm_rows_render(page):
    """async API 拉到 records 后, 应有 .row-insn 出现 (排除 placeholder)."""
    page.wait_for_selector(".row-insn:not(.placeholder)", timeout=5_000)
    rows = page.query_selector_all(".row-insn:not(.placeholder)")
    assert len(rows) >= 5, f"应至少 5 条 trace 行渲染, got {len(rows)}"


# ── 列宽拖拽 (新功能 Bug #32 fix) ────────────────────────────────────────────

def test_stream_header_has_resize_handles(page):
    """每列右沿应有 .col-resize 把柄."""
    handles = page.query_selector_all("#stream-header .col-resize")
    # idx / pc / func 三列
    assert len(handles) >= 3, f"应有 ≥3 col-resize 把柄, got {len(handles)}"


def test_col_resize_persists_to_localStorage(page, webui_url):
    """模拟拖动 idx 列右沿 → localStorage 写入."""
    # 当前 css var 默认值 60
    initial = page.evaluate("getComputedStyle(document.getElementById('asm-col')).getPropertyValue('--col-idx')")
    handle = page.query_selector("#stream-header .col-resize[data-col=idx]")
    assert handle is not None
    box = handle.bounding_box()
    # 拖右移 30px
    page.mouse.move(box["x"] + 2, box["y"] + 5)
    page.mouse.down()
    page.mouse.move(box["x"] + 32, box["y"] + 5, steps=5)
    page.mouse.up()
    page.wait_for_timeout(100)

    new_w = page.evaluate("getComputedStyle(document.getElementById('asm-col')).getPropertyValue('--col-idx')")
    assert new_w != initial, f"--col-idx 应变化 (initial={initial} new={new_w})"
    # localStorage 持久化
    stored = page.evaluate("localStorage.getItem('tracemiku-col-widths')")
    assert stored is not None, "拖动后应写入 localStorage"
    parsed = json.loads(stored)
    assert "idx" in parsed


# ── cursor 同步 ─────────────────────────────────────────────────────────────

def test_cursor_active_class_set(page):
    """初始 cursor=0 → idx=0 行有 .active class."""
    page.wait_for_selector(".row-insn:not(.placeholder)", timeout=5_000)
    page.wait_for_timeout(200)
    active = page.query_selector(".row-insn.active")
    assert active is not None, "应有一行带 .active"
    idx = active.get_attribute("data-idx")
    assert idx == "0", f"初始 cursor 应是 0, got {idx}"


def test_keyboard_navigation_j_advances_cursor(page):
    """按 j 键应使 cursor +1."""
    page.wait_for_selector(".row-insn:not(.placeholder)", timeout=5_000)
    page.wait_for_timeout(200)
    page.keyboard.press("j")
    page.wait_for_timeout(100)
    active = page.query_selector(".row-insn.active")
    if active:
        idx = active.get_attribute("data-idx")
        assert idx == "1", f"按 j 后 cursor 应=1, got {idx}"


# ── settings 持久化 ─────────────────────────────────────────────────────────

def test_settings_localstorage_key():
    """简单验证 STATE.settings 用的 localStorage key 存在 (硬编码不应 typo)."""
    # 静态检查 app.js 含 'tracemiku-settings'
    app_js = (HERE / "webui" / "app.js").read_text()
    assert "tracemiku-settings" in app_js
    assert "tracemiku-col-widths" in app_js
    assert "tracemiku-hidden-sos" in app_js


# ── API error 不炸 console ─────────────────────────────────────────────────

def test_unknown_reg_does_not_break_page(browser, webui_url):
    """直接请求 /api/reg-value-at?reg=bogus → 200 status='error'."""
    p = browser.new_page()
    resp = p.request.get(f"{webui_url}/api/reg-value-at?idx=0&reg=bogus")
    assert resp.status == 200
    body = resp.json()
    assert body["status"] == "error"
    p.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "slow"])
