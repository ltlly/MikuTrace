"""Static guard for frontend interaction/layout regressions.

This is intentionally not a browser replacement. It pins UI affordances that
were previously reported as regressions and are cheap to verify from source:
hidden Decompile/LLM entry points, draggable columns/panels, themed scrollbars,
Memory defaults, CFG loading guards, and long-output wrapping.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "frontend" / "src"


def read(rel: str) -> str:
    return (SRC / rel).read_text()


def require(name: str, ok: bool, failures: list[str]) -> None:
    if not ok:
        failures.append(name)


def main() -> int:
    app = read("App.tsx")
    css = read("styles/base.css")
    cfg = read("panels/cfg/CfgPanel.tsx")
    memory = read("panels/memory/MemoryPanel.tsx")
    registers = read("panels/registers/RegistersPanel.tsx")
    taint = read("panels/taint/TaintPanel.tsx")

    failures: list[str] = []

    require("App does not import visible DecompilerPanel", "DecompilerPanel" not in app, failures)
    require("App has no visible LLM controls", "call LLM" not in app and "LLIL → LLM" not in app, failures)
    require("right tabs are cfg/regs/hlil only", re.search(r'type RightTab\s*=\s*"cfg"\s*\|\s*"regs"\s*\|\s*"hlil"', app) is not None, failures)

    require("left panel splitter exists", "layout-splitter-left" in app and 'startPanelResize("left"' in app, failures)
    require("right panel splitter exists", "layout-splitter-right" in app and 'startPanelResize("right"' in app, failures)
    require("bottom panel splitter exists", 'id="bottom-resize"' in app and 'startPanelResize("bottom"' in app, failures)
    for col in ("dot", "idx", "pc", "func", "asm"):
        require(f"asm column resize {col}", f'startAsmColResize("{col}"' in app, failures)

    require("CFG header avoids stale no-fn label", 'cfgDisplayFn() || "select function"' in app, failures)
    require("CFG fetch has debounce", "CFG_FETCH_DEBOUNCE_MS" in cfg and "window.setTimeout" in cfg, failures)
    require("CFG fetch has sequence guard", "let graphSeq = 0" in cfg and "seq !== graphSeq" in cfg, failures)
    require("CFG fetch aborts stale request", "let graphAbort: AbortController | undefined" in cfg and "abort.signal.aborted" in cfg, failures)
    require("CFG fetch passes abort signal", "fetchCfgSvg({" in cfg and "signal: abort.signal" in cfg, failures)
    require("CFG loading clears stale graph", "setGraph(null)" in cfg and "setGraphLoading(true)" in cfg, failures)
    require("CFG cleanup aborts in-flight graph", "onCleanup(() =>" in cfg and "graphAbort?.abort()" in cfg, failures)
    require("CFG response records request function", "requestFn: string" in cfg and "setGraph({ ...resp, requestFn" in cfg, failures)
    require("CFG highlight rejects stale graph", "g.requestFn !== fnName()" in cfg and "graph() !== g" in cfg, failures)
    require("CFG loading spinner is rendered", 'class="cfg-loading"' in cfg and 'class="cfg-spinner"' in cfg, failures)

    require("Memory defaults to 128 bytes", "createSignal(128)" in memory, failures)
    require("Memory register picker is data-driven", "<select" in memory and "sortedRegNames(r().regs)" in memory, failures)
    require("Memory accepts x30/lr/sp register addresses", "x30" in memory and "lr" in memory and "sp" in memory and "REG_ADDR_RE" in memory, failures)
    require("Memory context closes on outside click", "closeOnPointer" in memory and "closest(\".memory-context-menu\")" in memory, failures)
    require("Memory context closes on Escape", 'e.key === "Escape"' in memory, failures)
    for col in ("addr", "hex", "ascii"):
        require(f"Memory column resize {col}", f'startResize("{col}"' in memory, failures)

    for col in ("name", "value", "delta", "note"):
        require(f"Registers column resize {col}", f'startResize("{col}"' in registers, failures)

    require("Taint default view is tree", 'createSignal<ViewMode>("tree")' in taint, failures)
    require("Taint tree exposes dependency parents", "parentLabel(row)" in taint and "taint_depth" in taint, failures)

    require("global themed scrollbar Firefox", "scrollbar-width: thin" in css and "scrollbar-color:" in css, failures)
    require("global themed scrollbar WebKit", "*::-webkit-scrollbar-thumb" in css and "*::-webkit-scrollbar-track" in css, failures)
    require("controls inherit mono font", "button,\ninput,\nselect,\ntextarea" in css and "font-family: var(--font-mono)" in css, failures)
    require("CFG loading uses themed spinner", ".cfg-loading" in css and ".cfg-spinner" in css and "@keyframes cfg-spin" in css, failures)
    require("String provenance long text wraps", ".string-prov-summary code" in css and "word-break: break-all" in css, failures)
    require("String provenance table scrolls horizontally", ".string-prov-scroll" in css and "overflow-x: auto" in css, failures)
    require("Taint tree wraps long asm", ".taint-tree-asm" in css and "overflow-wrap: anywhere" in css, failures)

    if failures:
        print("Frontend UI static audit failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("OK frontend UI audit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
