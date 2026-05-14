import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js";
import type { Accessor } from "solid-js";

import { fetchIdxsForPc, fetchLlilPipeline, fetchRecords, fetchRegValueAt } from "~/api/client";
import type { PipelineResponse } from "~/api/types";
import { createGuardedResource } from "~/utils/resourceGuards";
import type { UiTaskReporter } from "~/utils/taskCenter";

export interface PseudoCPanelProps {
  selectedFn: Accessor<string>;
  active: boolean;
  selectedIdx: Accessor<number>;
  onSelectIdx?: (idx: number) => void;
  onNavigateFn?: (fnId: string) => void;
  onTaskUpdate?: UiTaskReporter;
}

type IlLevel = "hlil" | "mlil" | "llil";

interface PipelineSource {
  fn_id: string;
  max_records: number;
}

const DEFAULT_MAX_RECORDS = 500;

function sourceKey(s: PipelineSource, showText: boolean): string {
  return `${s.fn_id}\0${s.max_records}\0${showText}`;
}

export default function PseudoCPanel(props: PseudoCPanelProps) {
  const [maxRecords, setMaxRecords] = createSignal(DEFAULT_MAX_RECORDS);
  const [collapsed, setCollapsed] = createSignal(false);
  const [copied, setCopied] = createSignal(false);
  const [expandedView, setExpandedView] = createSignal(false);
  const [showText, setShowText] = createSignal(false);
  const [ilLevel, setIlLevel] = createSignal<IlLevel>("hlil");
  let copyTimer: ReturnType<typeof setTimeout> | undefined;

  // New state for P1 features
  const [highlightedPc, setHighlightedPc] = createSignal<number | null>(null);
  const [collapsedFoldSet, setCollapsedFoldSet] = createSignal<Set<number>>(new Set());
  const [renaming, setRenaming] = createSignal<{ oldName: string; newName: string } | null>(null);
  const [renamedVars, setRenamedVars] = createSignal<Record<string, string>>({});
  const [typedVars, setTypedVars] = createSignal<Record<string, string>>({});
  const [typeMenu, setTypeMenu] = createSignal<{ name: string; x: number; y: number } | null>(null);
  const [tooltipVar, setTooltipVar] = createSignal<{ name: string; x: number; y: number } | null>(null);
  const [tooltipValue, setTooltipValue] = createSignal<string | null>(null);
  // Search state
  const [searchQuery, setSearchQuery] = createSignal("");
  const [searchActive, setSearchActive] = createSignal(false);
  const [searchMatchIdx, setSearchMatchIdx] = createSignal(0);

  // Decompile history (back/forward navigation)
  const [historyStack, setHistoryStack] = createSignal<string[]>([]);
  const [historyPos, setHistoryPos] = createSignal(-1);
  let historyPushing = false;

  // Track viewed functions in history
  createEffect(() => {
    const fnId = props.selectedFn();
    if (!fnId) return;
    if (historyPushing) return;
    const stack = historyStack();
    const pos = historyPos();
    // Don't push if it's the same as current
    if (pos >= 0 && stack[pos] === fnId) return;
    // Trim forward history and push new entry
    const next = stack.slice(0, pos + 1);
    next.push(fnId);
    // Cap at 64 entries
    if (next.length > 64) next.shift();
    setHistoryStack(next);
    setHistoryPos(next.length - 1);
  });

  function historyBack() {
    const stack = historyStack();
    const pos = historyPos();
    if (pos <= 0 || !props.onNavigateFn) return;
    historyPushing = true;
    setHistoryPos(pos - 1);
    props.onNavigateFn(stack[pos - 1]);
    setTimeout(() => { historyPushing = false; }, 0);
  }

  function historyForward() {
    const stack = historyStack();
    const pos = historyPos();
    if (pos >= stack.length - 1 || !props.onNavigateFn) return;
    historyPushing = true;
    setHistoryPos(pos + 1);
    props.onNavigateFn(stack[pos + 1]);
    setTimeout(() => { historyPushing = false; }, 0);
  }

  let searchInputEl: HTMLInputElement | undefined;
  let renameInputEl: HTMLInputElement | undefined;
  let highlightEl: HTMLDivElement | undefined;
  let lastHighlightFetch = 0;
  let highlightSeq = 0;
  let tooltipFetchSeq = 0;

  onCleanup(() => {
    if (copyTimer) clearTimeout(copyTimer);
  });

  const source = createMemo<PipelineSource | undefined>((prev) => {
    if (!props.active) return undefined;
    const fnId = props.selectedFn();
    if (!fnId) return undefined;
    const next: PipelineSource = {
      fn_id: fnId,
      max_records: Math.max(1, Math.min(5000, maxRecords())),
    };
    if (prev && sourceKey(prev, showText()) === sourceKey(next, showText())) return prev;
    return next;
  });

  const [resource, currentPipeline] = createGuardedResource<
    PipelineSource,
    PipelineResponse
  >(
    source,
    (s) =>
      fetchLlilPipeline({
        fn_id: s.fn_id,
        max_records: s.max_records,
        include_text: showText(),
      }),
    (r, s) => r.fn_id === s.fn_id,
  );

  // Task reporting
  let lastTaskFnId = "";
  createEffect(() => {
    const s = source();
    if (!props.active || !s) return;
    if (resource.loading) {
      lastTaskFnId = s.fn_id;
      props.onTaskUpdate?.({
        id: "pseudoc",
        surface: "Pseudo C",
        label: s.fn_id,
        status: "running",
        detail: `${s.max_records} records · cursor #${props.selectedIdx()}`,
      });
    }
  });

  createEffect(() => {
    const r = currentPipeline();
    if (!props.active || !r) return;
    props.onTaskUpdate?.({
      id: "pseudoc",
      surface: "Pseudo C",
      label: r.fn_id,
      status: "ready",
      detail: `HLIL ${r.hlil_count} lines · LLIL ${r.llil_coverage.toFixed(0)}% coverage`,
    });
  });

  createEffect(() => {
    if (!props.active || !resource.error) return;
    props.onTaskUpdate?.({
      id: "pseudoc",
      surface: "Pseudo C",
      label: lastTaskFnId || "unknown",
      status: "error",
      detail: String(resource.error),
    });
  });

  function levelText(r: PipelineResponse | undefined): string {
    if (!r) return "";
    switch (ilLevel()) { case "llil": return r.llil_text || ""; case "mlil": return r.mlil_text || ""; default: return r.hlil_text || ""; }
  }

  const lineCount = createMemo(() => {
    const text = levelText(currentPipeline());
    return text ? text.split("\n").length : 0;
  });
  const isLarge = createMemo(() => lineCount() > 500);

  createEffect(() => { if (isLarge()) setCollapsed(true); });

  // Extract PC from a line (first hex address)
  function extractPc(line: string): number | null {
    const m = line.match(/0x([0-9a-f]{8,})/i);
    if (m) return parseInt(m[1], 16);
    return null;
  }

  // Handle line click → jump assembly to that PC
  async function handleLineClick(raw: string) {
    const pc = extractPc(raw);
    if (pc === null || !props.onSelectIdx) return;
    try {
      const pcHex = "0x" + pc.toString(16);
      const cur = props.selectedIdx();
      const resp = await fetchIdxsForPc(pcHex, cur, 30);
      const candidates = [...(resp?.after || []), ...(resp?.before || [])];
      if (candidates.length > 0) {
        let best = candidates[0];
        for (const ix of candidates) {
          if (ix >= cur) { best = ix; break; }
        }
        props.onSelectIdx(best);
      }
    } catch (_) { /* ignore */ }
  }

  // Cursor sync: when selectedIdx changes in Records panel, fetch the
  // PC at that index and highlight the matching decompile line.
  createEffect(() => {
    const idx = props.selectedIdx();
    if (idx < 0 || !props.active) {
      setHighlightedPc(null);
      return;
    }
    const seq = ++highlightSeq;
    const now = Date.now();
    if (now - lastHighlightFetch < 150) return;
    lastHighlightFetch = now;
    fetchRecords({ start: idx, count: 1 })
      .then((resp) => {
        if (seq !== highlightSeq) return;
        const rec = resp?.records?.[0];
        if (rec?.pc) {
          const pc = parseInt(rec.pc, 16);
          if (!isNaN(pc)) setHighlightedPc(pc);
        }
      })
      .catch(() => {});
  });

  // Fold/unfold helpers
  function toggleFold(lineIdx: number) {
    setCollapsedFoldSet((prev) => {
      const next = new Set(prev);
      if (next.has(lineIdx)) next.delete(lineIdx);
      else next.add(lineIdx);
      return next;
    });
  }

  function foldStackDepth(lines: string[], lineIdx: number): number {
    let depth = 0;
    for (let i = 0; i <= lineIdx && i < lines.length; i++) {
      const trimmed = lines[i].trimEnd();
      if (trimmed.endsWith("{")) depth++;
      else if (trimmed === "}" || trimmed.startsWith("}")) depth = Math.max(0, depth - 1);
    }
    return depth;
  }

  // Variable hover handlers
  function handleVarHover(e: MouseEvent) {
    const target = e.target as HTMLElement;
    const varSpan = target.closest?.("[data-var]") as HTMLElement | null;
    if (!varSpan) { setTooltipVar(null); return; }
    const name = varSpan.dataset.var!;
    setTooltipVar({ name, x: e.clientX, y: e.clientY });
    if (/^(x|X)([0-9]|1[0-9]|2[0-9]|30)$/.test(name) || name === "fp" || name === "lr" || name === "sp") {
      const seq = ++tooltipFetchSeq;
      const idx = props.selectedIdx();
      if (idx >= 0) {
        fetchRegValueAt(idx, name)
          .then((resp) => {
            if (seq !== tooltipFetchSeq) return;
            if (resp?.value) setTooltipValue(resp.value);
            else if (resp?.annotation) setTooltipValue(resp.annotation);
            else setTooltipValue(null);
          })
          .catch(() => setTooltipValue(null));
      }
    } else {
      setTooltipValue(null);
    }
  }

  function handleVarOut(e: MouseEvent) {
    const related = e.relatedTarget as HTMLElement;
    if (!related?.closest?.("[data-var]")) {
      setTooltipVar(null);
      setTooltipValue(null);
    }
  }

  // Variable rename: double-click var → inline edit
  function handleVarDblClick(e: MouseEvent) {
    const target = e.target as HTMLElement;
    const varSpan = target.closest?.("[data-var]") as HTMLElement | null;
    if (!varSpan) return;
    const name = varSpan.dataset.var!;
    if (/^(x|X)([0-9]|1[0-9]|2[0-9]|30)$/.test(name) || name === "fp" || name === "lr" || name === "sp") return;
    e.preventDefault();
    setRenaming({ oldName: name, newName: name });
    setTimeout(() => renameInputEl?.focus(), 0);
  }

  function commitRename() {
    const r = renaming();
    if (!r || r.newName === r.oldName || !r.newName.trim()) { setRenaming(null); return; }
    setRenamedVars((prev) => ({ ...prev, [r.oldName]: r.newName.trim() }));
    setRenaming(null);
  }

  function cancelRename() { setRenaming(null); }

  // Variable type: right-click → set type
  function handleVarContext(e: MouseEvent) {
    const target = e.target as HTMLElement;
    const varSpan = target.closest?.("[data-var]") as HTMLElement | null;
    if (!varSpan) { setTypeMenu(null); return; }
    const name = varSpan.dataset.var!;
    e.preventDefault();
    setTypeMenu({ name, x: e.clientX, y: e.clientY });
  }

  function applyVarType(typeName: string) {
    const m = typeMenu();
    if (!m) return;
    setTypedVars((prev) => ({ ...prev, [m.name]: typeName }));
    setTypeMenu(null);
  }

  const highlightedLines = createMemo(() => {
    const text = levelText(currentPipeline());
    const renames = renamedVars();
    if (!text) return [] as { raw: string; html: string; pc: number | null; isCurrent: boolean; lineIdx: number; isFoldOpen: boolean; foldDepth: number }[];
    let processed = text;
    for (const [oldName, newName] of Object.entries(renames)) {
      processed = processed.replace(new RegExp("\\b" + escapeRegExp(oldName) + "\\b", "g"), newName);
    }
    const lines = processed.split("\n");
    const displayLines = expandedView() ? lines : lines.slice(0, 500);
    const curPc = highlightedPc();
    const types = typedVars();

    // Build brace-pair map for fold/unfold
    const foldStack: number[] = [];
    const closeToOpen = new Map<number, number>();
    const openToClose = new Map<number, number>();
    for (let i = 0; i < displayLines.length; i++) {
      const trimmed = displayLines[i].trimEnd();
      if (trimmed.endsWith("{")) {
        foldStack.push(i);
      } else if (trimmed === "}" || trimmed.startsWith("}")) {
        const openIdx = foldStack.pop();
        if (openIdx !== undefined) {
          closeToOpen.set(i, openIdx);
          openToClose.set(openIdx, i);
        }
      }
    }

    const folded = collapsedFoldSet();
    const hidden = new Set<number>();
    for (const [closeIdx, openIdx] of closeToOpen) {
      if (folded.has(openIdx)) {
        for (let j = openIdx + 1; j < closeIdx; j++) hidden.add(j);
      }
    }

    return displayLines.flatMap((raw, lineIdx) => {
      if (hidden.has(lineIdx)) return [];
      const pc = extractPc(raw);
      const isOpen = openToClose.has(lineIdx);
      const depth = foldStackDepth(displayLines, lineIdx);
      return [{
        raw,
        html: highlightLine(raw, types, searchQuery()),
        pc,
        isCurrent: curPc !== null && pc !== null && pc === curPc,
        lineIdx,
        isFoldOpen: isOpen,
        foldDepth: depth,
      }];
    });
  });

  // Search: line indices matching the query
  const searchMatches = createMemo(() => {
    const q = searchQuery().toLowerCase();
    if (!q) return [] as number[];
    const text = levelText(currentPipeline());
    if (!text) return [] as number[];
    const lines = text.split("\n");
    const matches: number[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].toLowerCase().includes(q)) matches.push(i);
    }
    return matches;
  });

  // Search navigation
  function searchNext() {
    const matches = searchMatches();
    if (!matches.length) return;
    const cur = searchMatchIdx();
    setSearchMatchIdx((cur + 1) % matches.length);
  }

  function searchPrev() {
    const matches = searchMatches();
    if (!matches.length) return;
    const cur = searchMatchIdx();
    setSearchMatchIdx((cur - 1 + matches.length) % matches.length);
  }

  function closeSearch() {
    setSearchActive(false);
    setSearchQuery("");
    setSearchMatchIdx(0);
  }

  // Ctrl+F handler
  function handleKeyDown(e: KeyboardEvent) {
    if ((e.ctrlKey || e.metaKey) && e.key === "f") {
      e.preventDefault();
      setSearchActive(true);
      setTimeout(() => searchInputEl?.focus(), 0);
    } else if (e.altKey && e.key === "ArrowLeft") {
      e.preventDefault();
      historyBack();
    } else if (e.altKey && e.key === "ArrowRight") {
      e.preventDefault();
      historyForward();
    } else if (e.key === "Escape" && searchActive()) {
      closeSearch();
    } else if (e.key === "Enter" && searchActive()) {
      e.preventDefault();
      if (e.shiftKey) searchPrev();
      else searchNext();
    }
  }

  // Auto-scroll to search match
  createEffect(() => {
    const matches = searchMatches();
    const matchIdx = searchMatchIdx();
    if (!matches.length || !highlightEl || !searchQuery()) return;
    const lineIdx = matches[matchIdx];
    if (lineIdx !== undefined && highlightEl) {
      const row = highlightEl.children[lineIdx] as HTMLElement | undefined;
      if (row) row.scrollIntoView({ block: "center", behavior: "smooth" });
    }
  });

  // Auto-scroll to the highlighted line
  createEffect(() => {
    const lines = highlightedLines();
    const idx = lines.findIndex((l) => l.isCurrent);
    if (idx >= 0 && highlightEl) {
      const row = highlightEl.children[idx] as HTMLElement | undefined;
      if (row) row.scrollIntoView({ block: "center", behavior: "smooth" });
    }
  });

  function downloadC(r: PipelineResponse) {
    const text = levelText(r);
    if (!text) return;
    const header = [
      "/*",
      ` * Decompiled from traceMiku — ${r.name}`,
      ` * Records: ${r.records} · Unique PCs: ${r.unique_pcs}`,
      ` * HLIL lines: ${r.hlil_count} · MLIL: ${r.mlil_count} · LLIL: ${r.llil_count}`,
      " * Generated by traceMiku decompiler pipeline",
      " */",
      "",
      "// Types used in this function",
      "#include <stdint.h>",
      "#include <stddef.h>",
      "",
    ].join("\n");
    const blob = new Blob([header + text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${r.name.replace(/[^a-zA-Z0-9_-]/g, "_")}.c`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  async function copyToClipboard() {
    const text = levelText(currentPipeline());
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      if (copyTimer) clearTimeout(copyTimer);
      copyTimer = setTimeout(() => setCopied(false), 2000);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      setCopied(true);
      if (copyTimer) clearTimeout(copyTimer);
      copyTimer = setTimeout(() => setCopied(false), 2000);
    }
  }

  return (
    <section class="panel pseudoc-panel" onKeyDown={handleKeyDown} tabIndex={-1}>
      <h2>Decompile</h2>

      <div class="pseudoc-controls">
        <label>records <input type="number" min="1" max="5000" step="100"
          value={maxRecords()}
          onInput={(e) => setMaxRecords(Math.max(1, Math.min(5000, Number(e.currentTarget.value) || DEFAULT_MAX_RECORDS)))} />
        </label>
        <span class="dim small">{props.selectedFn() || "no function selected"} · cursor #{props.selectedIdx()}</span>
        {/* History back/forward */}
        <button type="button" class="pseudoc-history-btn"
          disabled={historyPos() < 1}
          onClick={historyBack}
          title="back (Alt+Left)"
        >◂</button>
        <button type="button" class="pseudoc-history-btn"
          disabled={historyPos() >= historyStack().length - 1}
          onClick={historyForward}
          title="forward (Alt+Right)"
        >▸</button>
        <Show when={searchActive()}>
          <div class="pseudoc-search-bar">
            <input ref={searchInputEl} class="pseudoc-search-input"
              type="text" placeholder="search…"
              value={searchQuery()}
              onInput={(e) => { setSearchQuery(e.currentTarget.value); setSearchMatchIdx(0); }}
            />
            <span class="pseudoc-search-count">
              {searchMatches().length ? `${searchMatchIdx() + 1}/${searchMatches().length}` : "0/0"}
            </span>
            <button type="button" class="pseudoc-search-btn" onClick={searchPrev} title="prev (Shift+Enter)">▲</button>
            <button type="button" class="pseudoc-search-btn" onClick={searchNext} title="next (Enter)">▼</button>
            <button type="button" class="pseudoc-search-btn" onClick={closeSearch} title="close (Escape)">✕</button>
          </div>
        </Show>
      </div>

      <div class="pseudoc-subtabs">
        {(["hlil","mlil","llil"] as IlLevel[]).map((lvl) => (
          <button type="button"
            classList={{"pseudoc-subtab": true, "pseudoc-subtab-active": ilLevel() === lvl}}
            onClick={() => setIlLevel(lvl)}>
            {lvl.toUpperCase()}
          </button>
        ))}
      </div>

      <Show when={!props.selectedFn()}>
        <p class="dim">select a function to decompile</p>
      </Show>

      <Show when={resource.loading}>
        <div class="pseudoc-loading">
          <div class="cfg-spinner" />
          <span class="dim">
            running pipeline for {source()?.fn_id ?? "…"}…
          </span>
        </div>
      </Show>

      <Show when={!resource.loading && resource.error}>
        <p class="err">pipeline failed: {String(resource.error)}</p>
      </Show>

      <Show when={currentPipeline()}>
        {(r) => (
          <>
            <div class="pseudoc-stats">
              <div class="pseudoc-stats-grid">
                <div class="pseudoc-stat">
                  <span class="pseudoc-stat-label">Function</span>
                  <span class="pseudoc-stat-value"><code>{r().name}</code></span>
                </div>
                <div class="pseudoc-stat">
                  <span class="pseudoc-stat-label">Records</span>
                  <span class="pseudoc-stat-value">
                    {r().records.toLocaleString()}
                    <Show when={r().truncated}>
                      <span class="warn-text"> · truncated</span>
                    </Show>
                  </span>
                </div>
                <div class="pseudoc-stat">
                  <span class="pseudoc-stat-label">Unique PCs</span>
                  <span class="pseudoc-stat-value">{r().unique_pcs.toLocaleString()}</span>
                </div>
                <div class="pseudoc-stat">
                  <span class="pseudoc-stat-label">LLIL</span>
                  <span class="pseudoc-stat-value">
                    {r().llil_count.toLocaleString()} lines ·{" "}
                    {(r().llil_coverage * 100).toFixed(1)}% coverage
                  </span>
                </div>
                <div class="pseudoc-stat">
                  <span class="pseudoc-stat-label">MLIL</span>
                  <span class="pseudoc-stat-value">
                    {r().mlil_count.toLocaleString()} lines · struct
                    loads={r().struct_loads} stores={r().struct_stores}
                  </span>
                </div>
                <div class="pseudoc-stat">
                  <span class="pseudoc-stat-label">HLIL</span>
                  <span class="pseudoc-stat-value">{r().hlil_count.toLocaleString()} lines</span>
                </div>
              </div>

              <div class="pseudoc-actions">
                <Show when={!showText() && !resource.loading}>
                  <button type="button" class="pseudoc-btn pseudoc-btn-primary"
                    onClick={() => setShowText(true)}>
                    Show decompiled code
                  </button>
                </Show>
                <Show when={showText()}>
                  <button type="button" class="pseudoc-btn"
                    disabled={!levelText(r())} onClick={copyToClipboard}>
                    {copied() ? "Copied ✓" : "Copy"}
                  </button>
                  <button type="button" class="pseudoc-btn"
                    disabled={!levelText(r())} onClick={() => downloadC(r())}>
                    Download .c
                  </button>
                  <Show when={lineCount() > 500}>
                    <button type="button" class="pseudoc-btn"
                      onClick={() => setExpandedView((v) => !v)}>
                      {expandedView() ? "Show first 500" : `Show all (${lineCount()})`}
                    </button>
                  </Show>
                  <button type="button" class="pseudoc-btn"
                    onClick={() => setCollapsed((v) => !v)}
                    title={collapsed() ? "expand code" : "collapse code"}>
                    {collapsed() ? "Expand" : "Collapse"}
                  </button>
                  <button type="button" class="pseudoc-btn"
                    onClick={() => { setShowText(false); setExpandedView(false); }}>
                    Hide code
                  </button>
                </Show>
              </div>
            </div>

            <Show when={showText() && !collapsed()}>
              <div class="pseudoc-body" classList={{"pseudoc-body-collapsed": collapsed()}}>
                <Show when={levelText(r())} fallback={<p class="dim">no {ilLevel().toUpperCase()} text output</p>}>
                  <div class="pseudoc-code" ref={highlightEl}
                    onMouseOver={handleVarHover}
                    onMouseOut={handleVarOut}
                    onDblClick={handleVarDblClick}
                    onContextMenu={handleVarContext}
                  >
                    <For each={highlightedLines()}>
                      {(line, i) => (
                        <div
                          class="pseudoc-line"
                          classList={{
                            "pseudoc-line-active": line.pc !== null && currentPipeline() != null,
                            "pseudoc-line-current": line.isCurrent,
                          }}
                          onClick={() => handleLineClick(line.raw)}
                          title={line.pc ? `PC: 0x${line.pc.toString(16)} — click to jump` : undefined}
                          style={{ cursor: line.pc ? "pointer" : "default", "padding-left": `${8 + line.foldDepth * 16}px` }}
                        >
                          <span class="pseudoc-ln">{i() + 1}</span>
                          {line.isFoldOpen && (
                            <button type="button" class="pseudoc-fold-btn"
                              onClick={(e) => { e.stopPropagation(); toggleFold(line.lineIdx); }}
                              title={collapsedFoldSet().has(line.lineIdx) ? "expand block" : "collapse block"}
                            >
                              {collapsedFoldSet().has(line.lineIdx) ? "▸" : "▾"}
                            </button>
                          )}
                          <span class="pseudoc-code-text"
                            classList={{ "pseudoc-code-fold-open": line.isFoldOpen }}
                            innerHTML={line.html}
                          />
                        </div>
                      )}
                    </For>
                    <Show when={!expandedView() && lineCount() > 500}>
                      <div class="pseudoc-truncated-hint">
                        … showing first 500 of {lineCount()} lines ·{" "}
                        <button type="button" class="pseudoc-inline-btn"
                          onClick={() => setExpandedView(true)}>
                          show all
                        </button>
                      </div>
                    </Show>
                  </div>
                </Show>
              </div>
            </Show>
          </>
        )}
      </Show>

      {/* Variable hover tooltip */}
      <Show when={tooltipVar()}>
        {(tv) => (
          <div class="pseudoc-tooltip"
            style={{ left: `${tv().x + 12}px`, top: `${tv().y - 8}px` }}
          >
            <code>{tv().name}</code>
            <Show when={tooltipValue()}>
              <span class="pseudoc-tooltip-val"> = {tooltipValue()}</span>
            </Show>
          </div>
        )}
      </Show>

      {/* Inline rename input */}
      <Show when={renaming()}>
        {(r) => (
          <div class="pseudoc-tooltip" style={{ left: "200px", top: "120px" }}>
            rename <code>{r().oldName}</code>:
            <input ref={renameInputEl} class="pseudoc-rename-input"
              value={r().newName}
              onInput={(e) => setRenaming((prev) => prev ? { ...prev, newName: e.currentTarget.value } : null)}
              onKeyDown={(e) => { if (e.key === "Enter") commitRename(); else if (e.key === "Escape") cancelRename(); }}
              onBlur={commitRename}
            />
          </div>
        )}
      </Show>

      {/* Type context menu */}
      <Show when={typeMenu()}>
        {(m) => (
          <div class="pseudoc-type-menu"
            style={{ left: `${m().x}px`, top: `${m().y}px` }}
            onClick={(e) => e.stopPropagation()}
          >
            <div class="pseudoc-type-menu-hdr">set type for <code>{m().name}</code></div>
            {(["int32_t","uint32_t","int64_t","uint64_t","char*","void*","size_t","struct"] as string[]).map((t) => (
              <button type="button" class="pseudoc-type-menu-item" onClick={() => applyVarType(t)}>
                {t}
              </button>
            ))}
            <button type="button" class="pseudoc-type-menu-item" onClick={() => setTypeMenu(null)}>
              cancel
            </button>
          </div>
        )}
      </Show>

      {/* Dismiss type menu on outside click */}
      <Show when={typeMenu()}>
        <div class="pseudoc-type-backdrop" onClick={() => setTypeMenu(null)} />
      </Show>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Syntax highlighting for C-like code
// ---------------------------------------------------------------------------

const C_KEYWORDS = new Set([
  "if", "else", "for", "while", "do", "switch", "case", "default",
  "break", "continue", "return", "goto",
  "int", "long", "short", "char", "float", "double", "void",
  "unsigned", "signed", "const", "volatile", "static", "extern",
  "register", "auto", "sizeof", "typedef", "enum", "struct", "union",
  "true", "false", "null", "NULL",
  "int8_t", "int16_t", "int32_t", "int64_t",
  "uint8_t", "uint16_t", "uint32_t", "uint64_t",
  "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t",
  "bool",
]);

const C_TYPE_KEYWORDS = new Set([
  "int", "long", "short", "char", "float", "double", "void",
  "unsigned", "signed", "struct", "union", "enum",
]);

function highlightLine(line: string, types?: Record<string, string>, searchQuery?: string): string {
  let html = escapeHtml(line).replace(
    /\b(?:0x[0-9a-fA-F]+|[0-9]+(?:\.[0-9]+)?[fFuUlL]{0,3})\b|\b[a-zA-Z_][a-zA-Z0-9_]*\b|\/\/.*$|\/\*[\s\S]*?\*\/|".*?"|'.*?'/g,
    (match) => {
      if (/^(?:0x[0-9a-fA-F]+|[0-9])/.test(match)) {
        return `<span class="tok-lit">${match}</span>`;
      }
      if (match.startsWith("//")) {
        return `<span class="tok-comment">${match}</span>`;
      }
      if (match.startsWith("/*")) {
        return `<span class="tok-comment">${match}</span>`;
      }
      if (match.startsWith('"') || match.startsWith("'")) {
        return `<span class="tok-str">${match}</span>`;
      }
      if (C_KEYWORDS.has(match)) {
        if (C_TYPE_KEYWORDS.has(match)) {
          return `<span class="tok-type">${match}</span>`;
        }
        return `<span class="tok-kw">${match}</span>`;
      }
      const type = types?.[match];
      if (type) {
        return `<span class="tok-var" data-var="${match}" data-type="${type}" title="${type} ${match}">${match}</span>`;
      }
      return `<span class="tok-var" data-var="${match}">${match}</span>`;
    },
  );
  // Highlight search matches (case-insensitive, outside HTML tags)
  if (searchQuery && searchQuery.length > 0) {
    const escaped = escapeRegExp(searchQuery);
    const re = new RegExp(`(${escaped})`, "gi");
    const parts = html.split(/(<[^>]*>)/g);
    html = parts.map((p) => {
      if (p.startsWith("<")) return p;
      return p.replace(re, `<span class="tok-search-match">$1</span>`);
    }).join("");
  }
  return html;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
