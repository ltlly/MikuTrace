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
    records = read("panels/records/RecordsPanel.tsx")
    settings = read("panels/settings/SettingsPanel.tsx")
    string_prov = read("panels/strings/StringProvenancePanel.tsx")
    taint = read("panels/taint/TaintPanel.tsx")
    xref = read("panels/xref/XrefPanel.tsx")

    failures: list[str] = []

    require("App does not import visible DecompilerPanel", "DecompilerPanel" not in app, failures)
    require("App has no visible LLM controls", "call LLM" not in app and "LLIL → LLM" not in app, failures)
    require("right tabs are cfg/regs/hlil only", re.search(r'type RightTab\s*=\s*"cfg"\s*\|\s*"regs"\s*\|\s*"hlil"', app) is not None, failures)

    require("left panel splitter exists", "layout-splitter-left" in app and 'startPanelResize("left"' in app, failures)
    require("right panel splitter exists", "layout-splitter-right" in app and 'startPanelResize("right"' in app, failures)
    require("bottom panel splitter exists", 'id="bottom-resize"' in app and 'startPanelResize("bottom"' in app, failures)
    for col in ("dot", "idx", "pc", "func", "asm"):
        require(f"asm column resize {col}", f'startAsmColResize("{col}"' in app, failures)
    require(
        "ASM keyboard navigation keys are wired",
        'window.addEventListener("keydown", onKey)' in app
        and 'if (isEditableTarget(e.target)) return' in app
        and 'e.key === "j" || e.key === "ArrowDown"' in app
        and "jumpToIdx(selectedIdx() + 1)" in app
        and 'e.key === "k" || e.key === "ArrowUp"' in app
        and "jumpToIdx(selectedIdx() - 1)" in app
        and 'e.key === "PageDown"' in app
        and "jumpToIdx(selectedIdx() + 20)" in app
        and 'e.key === "PageUp"' in app
        and "jumpToIdx(selectedIdx() - 20)" in app
        and 'e.key === "Home" || e.key === "g"' in app
        and "jumpToIdx(0)" in app
        and 'e.key === "End" || e.key === "G"' in app
        and "jumpToIdx(Math.max(0, totalRecords() - 1))" in app,
        failures,
    )
    require(
        "Records keep stable row object references",
        "function sameRecordRow" in records
        and "const rowObjectCache = new Map<number, RecordRow>()" in records
        and "const cached = rowObjectCache.get(row.idx)" in records
        and "sameRecordRow(cached, row)" in records
        and "return cached" in records
        and "rowObjectCache.set(row.idx, row)" in records,
        failures,
    )
    require(
        "Records row object cache is bounded",
        "rowObjectCache.size > 5000" in records
        and "rowObjectCache.delete(k)" in records,
        failures,
    )
    require(
        "Records register context menu closes and aborts stale fetches",
        "function cancelRegContext" in records
        and "regContextAbort?.abort()" in records
        and "function closeRegContext" in records
        and "closest(\".reg-context-menu\")" in records
        and 'e.key === "Escape"' in records
        and 'document.addEventListener("pointerdown", closeOnPointer)' in records
        and 'document.addEventListener("keydown", closeOnKey)' in records
        and "current?.token === token" in records,
        failures,
    )

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
    require(
        "Memory supports byte range selection",
        'createSignal<{ anchor: string; head: string } | null>(null)' in memory
        and 'createSignal<string | null>(null)' in memory
        and "function selectedBounds" in memory
        and "function startSelect" in memory
        and "function extendSelect" in memory
        and "isSelected(b.addr)" in memory
        and "setSelection({ anchor, head: addr })" in memory,
        failures,
    )
    require(
        "Memory context queries selected range provenance",
        "fetchIdxsTouchingRange(bounds.lo, bounds.size, props.idx" in memory
        and "fetchMemWritesInRange({" in memory
        and "idxLo: 0" in memory
        and "idxHi: props.idx" in memory
        and "addrLo: bounds.lo" in memory
        and "addrHi: addToAddr(bounds.hi, 1)" in memory,
        failures,
    )
    require(
        "Memory context separates readers writers and write details",
        "<h3>writers</h3>" in memory
        and "<h3>readers</h3>" in memory
        and "<h3>write details</h3>" in memory
        and "writers_before" in memory
        and "writers_after" in memory
        and "readers_before" in memory
        and "readers_after" in memory
        and "ctx().writes?.truncated" in memory
        and "partial result" in memory,
        failures,
    )

    for col in ("name", "value", "delta", "note"):
        require(f"Registers column resize {col}", f'startResize("{col}"' in registers, failures)
    require(
        "Registers expose selected/changed/def/use row states",
        "selected: sameSelected(reg, props.selectedReg)" in registers
        and "changed: changed()" in registers
        and "def: regListHas(r().regs_def, reg)" in registers
        and "use: regListHas(r().regs_use, reg)" in registers,
        failures,
    )
    require(
        "Registers understand fp/lr aliases",
        'if (reg === "fp") return "x29"' in registers
        and 'if (reg === "lr") return "x30"' in registers
        and 'if (reg === "x29") return "fp"' in registers
        and 'if (reg === "x30") return "lr"' in registers
        and "regs.includes(reg) || regs.includes(alias)" in registers
        and "aliasReg(a) === b || aliasReg(b) === a" in registers,
        failures,
    )
    require(
        "Registers show pwndbg-style value annotations",
        "function regNote" in registers
        and 'return "zero"' in registers
        and 'return "pc"' in registers
        and 'return changed ? "stack changed" : "stack"' in registers
        and 'return changed ? "stack ptr changed" : "stack ptr"' in registers
        and 'return changed ? "ptr changed" : "ptr?"' in registers
        and 'return changed ? "changed" : ""' in registers
        and "r().regs_annotated?.[reg] || regNote(reg, value, r().regs, changed())" in registers,
        failures,
    )
    require(
        "Registers show previous-value deltas",
        "function deltaNote" in registers
        and 'const sign = now > prev ? "+" : "-"' in registers
        and '<td class="reg-delta">{deltaNote(value, before())}</td>' in registers,
        failures,
    )
    require(
        "Registers double-click jumps to last write with stale guard",
        "fetchLastWriteOfReg(idxAtStart, reg)" in registers
        and "let lastWriteSeq = 0" in registers
        and "const seq = ++lastWriteSeq" in registers
        and "const idxAtStart = props.idx" in registers
        and "seq !== lastWriteSeq || !props.active || props.idx !== idxAtStart" in registers
        and "props.onSelect(r.idx)" in registers
        and "onDblClick={() => void jumpLastWrite(reg)}" in registers
        and 'title="double-click to jump to last write"' in registers,
        failures,
    )
    require(
        "Registers rows use aligned grid columns",
        ".reg-diff-table tr" in css
        and "display: grid" in css
        and "grid-template-columns: var(--reg-col-name" in css
        and ".reg-diff-table th:not(:last-child)" in css
        and ".reg-diff-table tbody tr.selected" in css
        and ".reg-diff-table tbody tr.changed" in css
        and ".reg-diff-table tbody tr.def" in css
        and ".reg-diff-table tbody tr.use" in css,
        failures,
    )

    require(
        "Settings exposes debug log controls",
        "debugVisible: boolean" in settings
        and "apiDebug: boolean" in settings
        and "debug overlay" in settings
        and "API debug log" in settings
        and "onApiDebugChange" in settings,
        failures,
    )
    require(
        "Settings displays backend parallelism",
        "workerSummary" in settings
        and "p().available" in settings
        and "p().workers" in settings
        and "frame_depths" in settings
        and "memshadow" in settings,
        failures,
    )
    require(
        "Settings layout is responsive and wraps long values",
        ".settings-grid" in css
        and "repeat(auto-fit" in css
        and ".settings-toggles" in css
        and "grid-column: 1 / -1" in css
        and ".settings-kv dd" in css
        and "overflow-wrap: anywhere" in css,
        failures,
    )

    require(
        "Refs panel uses explicit instruction-text wording",
        "same PC executions" in xref
        and "same instruction text" in xref
        and "regex search over decoded assembly text" in xref
        and "instruction text search failed" in xref
        and "asm refs" not in xref.lower(),
        failures,
    )
    require(
        "Refs help clarifies it is not static xref analysis",
        "不是静态代码引用分析" in app
        and "按解码后的汇编文本做正则搜索" in app
        and "ret 这类通用指令" in app,
        failures,
    )

    require("Taint default view is tree", 'createSignal<ViewMode>("tree")' in taint, failures)
    require("Taint tree exposes dependency parents", "parentLabel(row)" in taint and "taint_depth" in taint, failures)
    require(
        "Taint uses traceIdx wording instead of ambiguous start label",
        "traceIdx" in taint and "from traceIdx" in taint and "narrow traceIdx/reg/options" in taint,
        failures,
    )

    require("global themed scrollbar Firefox", "scrollbar-width: thin" in css and "scrollbar-color:" in css, failures)
    require("global themed scrollbar WebKit", "*::-webkit-scrollbar-thumb" in css and "*::-webkit-scrollbar-track" in css, failures)
    require("controls inherit mono font", "button,\ninput,\nselect,\ntextarea" in css and "font-family: var(--font-mono)" in css, failures)
    require("CFG loading uses themed spinner", ".cfg-loading" in css and ".cfg-spinner" in css and "@keyframes cfg-spin" in css, failures)
    require("String provenance long text wraps", ".string-prov-summary code" in css and "word-break: break-all" in css, failures)
    require("String provenance table scrolls horizontally", ".string-prov-scroll" in css and "overflow-x: auto" in css, failures)
    require(
        "String provenance separates writer and reader columns",
        "<th>writers</th>" in string_prov
        and "<th>readers</th>" in string_prov
        and 'idxButtons(b, "w")' in string_prov
        and 'idxButtons(b, "r")' in string_prov
        and ".string-prov-table th:nth-child(5)" in css
        and ".string-prov-table th:nth-child(6)" in css
        and "table-layout: fixed" in css,
        failures,
    )
    require(
        "Taint tree grid avoids overlapping columns",
        ".taint-tree-row" in css
        and "grid-template-areas:" in css
        and '"idx fn why"' in css
        and '"asm asm asm"' in css
        and ".taint-tree-why" in css
        and ".taint-tree-asm" in css,
        failures,
    )
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
