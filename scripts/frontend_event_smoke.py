"""Browser-level frontend event smoke for a running traceMiku web server.

This complements the static frontend audits by exercising the actual DOM event
paths that previously regressed: keyboard cursor movement, row clicks, CFG sync,
context-menu cancellation, range selection, and column/panel drag resizing.

It requires a working Playwright browser. The current CI/container may only be
able to py_compile this file; run it manually on a machine with Chromium/Chrome:

    uv run python scripts/frontend_event_smoke.py http://127.0.0.1:18900
    uv run python scripts/frontend_event_smoke.py http://127.0.0.1:18900 --browser chromium
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


DEFAULT_TIMEOUT_MS = 30_000


@dataclass(frozen=True)
class TracePoint:
    idx: int
    func: str | None


def q(path: str, **params: Any) -> str:
    clean = {k: str(v) for k, v in params.items() if v is not None}
    if not clean:
        return path
    return f"{path}?{urllib.parse.urlencode(clean)}"


def get_json(base_url: str, path: str, timeout_s: float = 30.0) -> Any:
    with urllib.request.urlopen(base_url.rstrip("/") + path, timeout=timeout_s) as resp:
        body = resp.read()
        return json.loads(body.decode("utf-8"))


def pick_cross_function_points(base_url: str) -> tuple[TracePoint, TracePoint] | None:
    meta = get_json(base_url, "/api/meta")
    total = int(meta.get("records") or 0)
    if total <= 1:
        return None

    starts = [
        0,
        max(0, total // 8),
        max(0, total // 4),
        max(0, total // 2),
        max(0, (total * 3) // 4),
        max(0, total - 1000),
    ]
    first: TracePoint | None = None
    by_func: dict[str, TracePoint] = {}
    for start in starts:
        resp = get_json(base_url, q("/api/records", start=start, count=1000))
        for row in resp.get("records", []):
            idx = int(row.get("idx") or 0)
            func = row.get("func")
            if first is None:
                first = TracePoint(idx=idx, func=func if isinstance(func, str) else None)
            if isinstance(func, str) and func:
                by_func.setdefault(func, TracePoint(idx=idx, func=func))
            if len(by_func) >= 2:
                points = list(by_func.values())
                return points[0], points[1]
    if first is None:
        return None
    return first, TracePoint(idx=min(total - 1, first.idx + 1), func=first.func)


def debug_values(page: Any) -> dict[str, str]:
    return page.evaluate(
        """() => {
            const out = {};
            for (const row of document.querySelectorAll('.debug-overlay .debug-row')) {
                const key = row.querySelector('span')?.textContent?.trim();
                const value = row.querySelector('code')?.textContent?.trim();
                if (key) out[key] = value ?? '';
            }
            return out;
        }"""
    )


def debug_value(page: Any, key: str) -> str:
    return str(debug_values(page).get(key, ""))


def wait_debug_value(page: Any, key: str, expected: str, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> None:
    page.wait_for_function(
        """({ key, expected }) => {
            for (const row of document.querySelectorAll('.debug-overlay .debug-row')) {
                const label = row.querySelector('span')?.textContent?.trim();
                const value = row.querySelector('code')?.textContent?.trim();
                if (label === key) return value === expected;
            }
            return false;
        }""",
        arg={"key": key, "expected": expected},
        timeout=timeout_ms,
    )


def selected_idx(page: Any) -> int:
    text = page.locator(".records-row.selected .idx").first.text_content(timeout=DEFAULT_TIMEOUT_MS)
    return int(str(text).strip())


def wait_selected_idx(page: Any, idx: int, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> None:
    wait_debug_value(page, "selectedIdx", str(idx), timeout_ms=timeout_ms)


def jump_to_idx(page: Any, idx: int) -> None:
    page.keyboard.press(":")
    cmd = page.locator("#cmd-input")
    cmd.fill(str(idx))
    page.keyboard.press("Enter")
    wait_selected_idx(page, idx)


def css_number(page: Any, selector: str, prop: str) -> float:
    raw = page.eval_on_selector(selector, "(el, prop) => getComputedStyle(el).getPropertyValue(prop)", prop)
    return float(str(raw).strip().removesuffix("px"))


def drag_by(page: Any, selector: str, dx: int, dy: int = 0) -> None:
    box = page.locator(selector).first.bounding_box(timeout=DEFAULT_TIMEOUT_MS)
    if box is None:
        raise RuntimeError(f"{selector} has no bounding box")
    x = box["x"] + box["width"] / 2
    y = box["y"] + box["height"] / 2
    page.mouse.move(x, y)
    page.mouse.down()
    page.mouse.move(x + dx, y + dy, steps=8)
    page.mouse.up()


def run_smoke(page: Any, base_url: str, timeout_ms: int) -> list[str]:
    checks: list[str] = []
    points = pick_cross_function_points(base_url)

    page.add_init_script(
        """{
            localStorage.setItem('tracemiku-debug', '1');
            localStorage.removeItem('tracemiku-layout-v4');
            localStorage.removeItem('tracemiku-layout-v3');
            localStorage.removeItem('tracemiku-layout-v2');
        }"""
    )
    page.goto(base_url, wait_until="domcontentloaded", timeout=timeout_ms)
    page.wait_for_selector(".records-row", timeout=timeout_ms)
    page.wait_for_selector(".debug-overlay", timeout=timeout_ms)
    checks.append("loaded rows and debug overlay")

    start = int(debug_value(page, "selectedIdx") or "0")
    page.keyboard.press("ArrowDown")
    wait_selected_idx(page, start + 1, timeout_ms)
    page.keyboard.press("PageDown")
    wait_selected_idx(page, start + 21, timeout_ms)
    page.keyboard.press("Home")
    wait_selected_idx(page, 0, timeout_ms)
    checks.append("keyboard ArrowDown/PageDown/Home moves cursor")

    row = page.locator(".records-row").nth(5)
    target_idx = int(str(row.locator(".idx").text_content(timeout=timeout_ms)).strip())
    row.click(timeout=timeout_ms)
    wait_selected_idx(page, target_idx, timeout_ms)
    checks.append("records row click selects target idx")

    loading_samples = page.evaluate(
        """async () => {
            const viewport = document.querySelector('.records-virtual');
            if (!viewport) throw new Error('records viewport missing');
            viewport.scrollTop = Math.min(viewport.scrollTop + 720, viewport.scrollHeight - viewport.clientHeight);
            viewport.dispatchEvent(new Event('scroll', { bubbles: true }));
            const samples = [];
            const started = performance.now();
            while (performance.now() - started < 800) {
                samples.push(Boolean(document.querySelector('.records-loading')));
                await new Promise((resolve) => setTimeout(resolve, 50));
            }
            return samples;
        }"""
    )
    if any(bool(v) for v in loading_samples):
        raise RuntimeError(f"records loading marker flickered during cached scroll: {loading_samples}")
    page.wait_for_selector(".records-row", timeout=timeout_ms)
    checks.append("records scroll keeps cached rows visible during range refetch")

    left_before = css_number(page, "#layout", "--left-w")
    drag_by(page, ".layout-splitter-left", 36)
    left_after = css_number(page, "#layout", "--left-w")
    if left_after <= left_before:
        raise RuntimeError(f"left splitter did not grow: before={left_before} after={left_after}")

    asm_before = css_number(page, "#asm-col", "--col-asm")
    drag_by(page, "#stream-header .hd-asm .col-resize", 36)
    asm_after = css_number(page, "#asm-col", "--col-asm")
    if asm_after <= asm_before:
        raise RuntimeError(f"asm column did not grow: before={asm_before} after={asm_after}")
    checks.append("panel and asm column drag resize updates CSS variables")

    reg = page.locator(".records-row.selected .op-reg").first
    if reg.count() == 0:
        reg = page.locator(".op-reg").first
    reg.click(button="right", timeout=timeout_ms)
    page.wait_for_selector(".reg-context-menu", timeout=timeout_ms)
    page.keyboard.press("Escape")
    page.wait_for_selector(".reg-context-menu", state="hidden", timeout=timeout_ms)
    checks.append("register context menu opens and Escape cancels it")

    page.wait_for_selector(".memory-hex-table .mem-byte", timeout=timeout_ms)
    cell0 = page.locator(".memory-hex-table .mem-byte").nth(0)
    cell3 = page.locator(".memory-hex-table .mem-byte").nth(3)
    b0 = cell0.bounding_box(timeout=timeout_ms)
    b3 = cell3.bounding_box(timeout=timeout_ms)
    if b0 is None or b3 is None:
        raise RuntimeError("memory byte cells have no bounding boxes")
    page.mouse.move(b0["x"] + b0["width"] / 2, b0["y"] + b0["height"] / 2)
    page.mouse.down()
    page.mouse.move(b3["x"] + b3["width"] / 2, b3["y"] + b3["height"] / 2, steps=4)
    page.mouse.up()
    page.wait_for_function("() => document.querySelectorAll('.mem-byte.selected').length >= 2", timeout=timeout_ms)
    cell3.click(button="right", timeout=timeout_ms)
    page.wait_for_selector(".memory-context-menu", timeout=timeout_ms)
    page.locator(".memory-context-menu h3", has_text="writers").wait_for(timeout=timeout_ms)
    page.locator(".memory-context-menu h3", has_text="readers").wait_for(timeout=timeout_ms)
    page.keyboard.press("Escape")
    page.wait_for_selector(".memory-context-menu", state="hidden", timeout=timeout_ms)
    checks.append("memory range selection opens provenance menu and Escape cancels it")

    page.locator('.vtab[data-rtab="hlil"]').click(timeout=timeout_ms)
    page.wait_for_selector(".hlil-panel", timeout=timeout_ms)
    if page.locator(".hlil-panel select").count() != 0:
        raise RuntimeError("HLIL panel should follow cursor without a function selector")
    page.locator(".hlil-controls", has_text="cursor #").wait_for(timeout=timeout_ms)
    checks.append("HLIL tab follows current cursor without reselecting a function")

    page.locator('.vtab[data-rtab="dec"]').click(timeout=timeout_ms)
    page.wait_for_selector(".decompiler-panel", timeout=timeout_ms)
    dec_text = page.locator(".decompiler-panel").inner_text(timeout=timeout_ms)
    if "call LLM" in dec_text or "LLIL → LLM" in dec_text:
        raise RuntimeError("Decompile panel exposed LLM controls")
    page.locator(".decompiler-panel button", has_text="render LLIL").wait_for(timeout=timeout_ms)
    checks.append("Decompile tab is visible without LLM controls")

    page.keyboard.press("g")
    cmd = page.locator("#cmd-input")
    cmd.fill("query records ret")
    page.keyboard.press("Enter")
    page.wait_for_selector(".query-panel", timeout=timeout_ms)
    page.locator(".query-panel", has_text="Trace Query").wait_for(timeout=timeout_ms)
    page.locator(".query-table").wait_for(timeout=timeout_ms)
    checks.append("command palette routes query records ret into Trace Query panel")

    page.locator(".task-toggle").click(timeout=timeout_ms)
    page.wait_for_selector(".task-center", timeout=timeout_ms)
    page.locator(".task-center", has_text="Task Center").wait_for(timeout=timeout_ms)
    checks.append("Task Center opens and surfaces recent analysis tasks")
    page.locator(".task-center-head button", has_text="close").click(timeout=timeout_ms)
    page.wait_for_selector(".task-center", state="hidden", timeout=timeout_ms)

    page.locator('.vtab[data-rtab="cfg"]').click(timeout=timeout_ms)
    page.wait_for_selector(".cfg-panel", timeout=timeout_ms)
    cfg_source = page.locator(".cfg-controls select").first
    cfg_source.select_option("bn-asm", timeout=timeout_ms)
    page.wait_for_function(
        """() => {
            const panel = document.querySelector('.cfg-panel');
            return panel && panel.textContent && panel.textContent.includes('BN ASM CFG');
        }""",
        timeout=timeout_ms,
    )
    cfg_source.select_option("trace", timeout=timeout_ms)
    checks.append("CFG source selector switches to BN ASM CFG and back")

    page.wait_for_selector(".cfg-svg-frame", timeout=timeout_ms)
    page.wait_for_selector('.cfg-svg-canvas > svg g[data-tracemiku-panzoom]', state="attached", timeout=timeout_ms)
    zoom_anchor = page.evaluate(
        """async () => {
            const frame = document.querySelector('.cfg-svg-frame');
            const canvas = document.querySelector('.cfg-svg-canvas');
            const svg = document.querySelector('.cfg-svg-canvas > svg');
            const group = document.querySelector('.cfg-svg-canvas > svg g[data-tracemiku-panzoom]');
            if (!frame || !canvas || !svg || !group) throw new Error('CFG frame/canvas/svg missing');
            const viewBoxRaw = svg.getAttribute('viewBox');
            const viewBox = viewBoxRaw
                ? viewBoxRaw.trim().split(/[\\s,]+/).map(Number)
                : [0, 0, Number.parseFloat(svg.getAttribute('width') || '0'), Number.parseFloat(svg.getAttribute('height') || '0')];
            if (viewBox.length !== 4 || viewBox.some((part) => !Number.isFinite(part)) || viewBox[2] <= 0 || viewBox[3] <= 0) {
                throw new Error(`bad CFG viewBox: ${viewBoxRaw}`);
            }
            const parse = () => {
                const t = group.getAttribute('transform') || '';
                const m = t.match(/translate\\((-?[0-9.eE+-]+)\\s+(-?[0-9.eE+-]+)\\) scale\\(([0-9.eE+-]+)\\)/);
                if (!m) throw new Error(`bad CFG transform: ${t}`);
                return { x: Number(m[1]), y: Number(m[2]), scale: Number(m[3]) };
            };
            const rect = frame.getBoundingClientRect();
            const svgRect = svg.getBoundingClientRect();
            const svgCssWidth = Number(svg.getAttribute('data-tracemiku-css-width')) || svgRect.width;
            const svgCssHeight = Number(svg.getAttribute('data-tracemiku-css-height')) || svgRect.height;
            const userUnitsPerCssX = viewBox[2] / svgCssWidth;
            const userUnitsPerCssY = viewBox[3] / svgCssHeight;
            const clientX = rect.left + rect.width * 0.63;
            const clientY = rect.top + rect.height * 0.37;
            const mx = (clientX - svgRect.left) * userUnitsPerCssX;
            const my = (clientY - svgRect.top) * userUnitsPerCssY;
            const before = parse();
            const beforeContent = { x: (mx - before.x) / before.scale, y: (my - before.y) / before.scale };
            frame.dispatchEvent(new WheelEvent('wheel', {
                bubbles: true,
                cancelable: true,
                ctrlKey: true,
                deltaY: -120,
                clientX,
                clientY,
            }));
            await new Promise((resolve) => requestAnimationFrame(resolve));
            const after = parse();
            const afterContent = { x: (mx - after.x) / after.scale, y: (my - after.y) / after.scale };
            return {
                cssTransform: getComputedStyle(canvas).transform,
                scaled: after.scale > before.scale,
                dx: afterContent.x - beforeContent.x,
                dy: afterContent.y - beforeContent.y,
            };
        }"""
    )
    if zoom_anchor["cssTransform"] != "none":
        raise RuntimeError(f"CFG canvas still uses CSS transform: {zoom_anchor}")
    if not zoom_anchor["scaled"] or abs(zoom_anchor["dx"]) > 0.05 or abs(zoom_anchor["dy"]) > 0.05:
        raise RuntimeError(f"CFG ctrl-wheel zoom did not keep cursor anchor stable: {zoom_anchor}")
    checks.append("CFG ctrl-wheel zoom is vector-rendered and anchored at the cursor")

    if points and points[0].func and points[1].func and points[0].func != points[1].func:
        jump_to_idx(page, points[0].idx)
        wait_debug_value(page, "cursorHint.func", points[0].func, timeout_ms)
        wait_debug_value(page, "cfg.fnName", points[0].func, timeout_ms)
        jump_to_idx(page, points[1].idx)
        wait_debug_value(page, "cursorHint.func", points[1].func, timeout_ms)
        wait_debug_value(page, "cfg.fnName", points[1].func, timeout_ms)
        checks.append(f"CFG sync follows cross-function cursor jump {points[0].func}->{points[1].func}")
    else:
        checks.append("CFG sync cross-function check skipped: no two named funcs in sampled records")

    return checks


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run browser event smoke against a running traceMiku web URL.")
    parser.add_argument("base_url", help="running traceMiku web URL, e.g. http://127.0.0.1:18900")
    parser.add_argument("--browser", choices=["chromium", "firefox", "webkit"], default="chromium")
    parser.add_argument("--executable", help="optional browser executable path")
    parser.add_argument("--headful", action="store_true", help="show browser window")
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001 - print actionable environment error.
        print(f"FAIL playwright is not importable: {exc}", file=sys.stderr)
        return 2

    try:
        with sync_playwright() as p:
            browser_type = getattr(p, args.browser)
            launch_kwargs: dict[str, Any] = {"headless": not args.headful}
            if args.executable:
                launch_kwargs["executable_path"] = args.executable
            try:
                browser = browser_type.launch(**launch_kwargs)
            except PlaywrightError as exc:
                print(
                    "FAIL browser event smoke could not launch Playwright browser. "
                    "Install a supported browser, or pass --executable /path/to/chrome. "
                    f"Original error: {exc}",
                    file=sys.stderr,
                )
                return 2
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                checks = run_smoke(page, args.base_url.rstrip("/"), args.timeout_ms)
            except PlaywrightError as exc:
                print(f"FAIL frontend event smoke Playwright error: {exc}", file=sys.stderr)
                return 1
            finally:
                browser.close()
    except Exception as exc:  # noqa: BLE001 - smoke failure should be concise.
        print(f"FAIL frontend event smoke: {exc}", file=sys.stderr)
        return 1

    print(f"OK frontend event smoke base={args.base_url.rstrip('/')} checks={len(checks)}")
    for check in checks:
        print(f"  - {check}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
