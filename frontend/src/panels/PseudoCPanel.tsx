import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js";
import type { Accessor } from "solid-js";

import { fetchIdxsForPc, fetchLlilPipeline, fetchRecords, fetchRegValueAt } from "~/api/client";
import type { PipelineResponse } from "~/api/types";
import { createGuardedResource } from "~/utils/resourceGuards";
import type { UiTaskReporter } from "~/utils/taskCenter";
import { parseCType } from "~/utils/cTypeParser";

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
  include_text: boolean;
}

const DEFAULT_MAX_RECORDS = 500;

function sourceKey(s: PipelineSource): string {
  return `${s.fn_id}\0${s.max_records}\0${s.include_text}`;
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
  // Variable same-name highlighting (single-click to highlight all occurrences)
  const [highlightedVar, setHighlightedVar] = createSignal<string | null>(null);
  // Search state
  const [searchQuery, setSearchQuery] = createSignal("");
  const [searchActive, setSearchActive] = createSignal(false);
  const [searchMatchIdx, setSearchMatchIdx] = createSignal(0);

  // Decompile history (back/forward navigation)
  const [historyStack, setHistoryStack] = createSignal<string[]>([]);
  const [historyPos, setHistoryPos] = createSignal(-1);

  // Decompile diff
  const [diffBaseline, setDiffBaseline] = createSignal<string | null>(null);
  const [diffMode, setDiffMode] = createSignal(false);

  function snapshotBaseline() {
    const text = levelText(currentPipeline());
    setDiffBaseline(text || null);
    setDiffMode(!!text);
  }

  function clearDiff() {
    setDiffBaseline(null);
    setDiffMode(false);
  }

  const diffLines = createMemo(() => {
    if (!diffMode() || !diffBaseline()) return null;
    const text = levelText(currentPipeline());
    if (!text) return null;
    const oldLines = diffBaseline()!.split("\n");
    const newLines = text.split("\n");
    // Simple set-based diff: new lines not in old → added, otherwise same
    const oldSet = new Set(oldLines);
    return newLines.map((line, i) => ({
      line,
      kind: (!oldSet.has(line) ? "added" : i < oldLines.length && oldLines[i] === line ? "same" : "changed") as "added" | "same" | "changed",
    }));
  });
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
    // Emit terminal status so tasks window can dismiss
    props.onTaskUpdate?.({
      id: "pseudoc",
      surface: "Pseudo C",
      label: source()?.fn_id ?? "?",
      status: "cancelled",
      detail: "panel closed",
    });
  });

  // When panel becomes inactive, emit terminal status for any running task
  createEffect(() => {
    if (!props.active && lastTaskFnId) {
      props.onTaskUpdate?.({
        id: "pseudoc",
        surface: "Pseudo C",
        label: lastTaskFnId,
        status: "cancelled",
        detail: "completed",
      });
    }
  });

  const source = createMemo<PipelineSource | undefined>((prev) => {
    if (!props.active) return undefined;
    const fnId = props.selectedFn();
    if (!fnId) return undefined;
    const next: PipelineSource = {
      fn_id: fnId,
      max_records: Math.max(1, Math.min(5000, maxRecords())),
      include_text: showText(),
    };
    if (prev && sourceKey(prev) === sourceKey(next)) return prev;
    return next;
  });

  const [resource, currentPipeline] = createGuardedResource<
    PipelineSource,
    PipelineResponse
  >(
    source,
    (s, signal) =>
      fetchLlilPipeline({
        fn_id: s.fn_id,
        max_records: s.max_records,
        include_text: s.include_text,
      }, signal),
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

  // Handle click on code container: variable clicks toggle same-name highlighting,
  // otherwise navigate to the nearest trace record matching the clicked line's PC.
  function handleCodeClick(e: MouseEvent) {
    const target = e.target as HTMLElement;
    const varSpan = target.closest?.("[data-var]") as HTMLElement | null;
    if (varSpan) {
      const name = varSpan.dataset.var!;
      setHighlightedVar((prev) => prev === name ? null : name);
      return;
    }
    setHighlightedVar(null);
    const lineDiv = target.closest?.(".pseudoc-line") as HTMLElement | null;
    if (!lineDiv) return;
    const raw = lineDiv.dataset.raw;
    if (raw) handleLineClick(raw);
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

  // Goto label double-click: navigate to label definition
  function handleLabelDblClick(e: MouseEvent) {
    const target = e.target as HTMLElement;
    const labelSpan = target.closest?.("[data-label]") as HTMLElement | null;
    if (!labelSpan) return;
    e.preventDefault();
    e.stopPropagation();
    const labelName = labelSpan.dataset.label!;
    const text = levelText(currentPipeline());
    if (!text) return;
    const lines = text.split("\n");
    const targetLineIdx = lines.findIndex(
      (l) => new RegExp("^\\s*" + escapeRegExp(labelName) + ":").test(l)
    );
    if (targetLineIdx < 0) return;
    // Map to displayed line in highlightedLines (accounts for folded/hidden)
    const displayIdx = highlightedLines().findIndex((l) => l.lineIdx === targetLineIdx);
    if (displayIdx >= 0 && highlightEl) {
      const row = highlightEl.children[displayIdx] as HTMLElement | undefined;
      if (row) row.scrollIntoView({ block: "center", behavior: "smooth" });
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

  function isValidVarName(name: string): boolean {
    if (!name) return false;
    if (/^\d+$/.test(name)) return false; // numeric-only
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) return false; // not a C identifier
    if (C_KEYWORDS.has(name)) return false;
    // Check duplicates within current function context
    const text = levelText(currentPipeline());
    if (text) {
      const renames = renamedVars();
      const allRenamed = new Set(Object.values(renames));
      if (allRenamed.has(name)) return false;
    }
    return true;
  }

  function commitRename() {
    const r = renaming();
    if (!r || r.newName === r.oldName) { setRenaming(null); return; }
    const trimmed = r.newName.trim();
    if (!isValidVarName(trimmed)) { setRenaming(null); return; }
    setRenamedVars((prev) => ({ ...prev, [r.oldName]: trimmed }));
    setRenaming(null);
  }

  function cancelRename() { setRenaming(null); }

  // Variable type: right-click → set type (IDA Y key: C type input dialog)
  // Also handles address tokens for xrefs
  const [xrefMenu, setXrefMenu] = createSignal<{ addr: string; x: number; y: number } | null>(null);
  const [xrefResults, setXrefResults] = createSignal<{ addr: string; hits: Array<{ idx: number; pc: string; asm: string }>; loading: boolean } | null>(null);

  function handleVarContext(e: MouseEvent) {
    const target = e.target as HTMLElement;
    const varSpan = target.closest?.("[data-var]") as HTMLElement | null;
    if (varSpan) {
      const name = varSpan.dataset.var!;
      e.preventDefault();
      setTypeMenu({ name, x: e.clientX, y: e.clientY });
      setXrefMenu(null);
      setTimeout(() => typeInputEl?.focus(), 0);
      return;
    }
    // Check for address token (.tok-lit or containing 0x...)
    const litSpan = target.closest?.(".tok-lit") as HTMLElement | null;
    if (litSpan) {
      const m = litSpan.textContent?.match(/0x([0-9a-fA-F]{8,})/);
      if (m) {
        e.preventDefault();
        setXrefMenu({ addr: m[0], x: e.clientX, y: e.clientY });
        setTypeMenu(null);
        return;
      }
    }
    setTypeMenu(null);
    setXrefMenu(null);
  }

  let typeInputEl: HTMLInputElement | undefined;
  const [typeInput, setTypeInput] = createSignal("");
  const [typeError, setTypeError] = createSignal<string | null>(null);
  function applyVarType() {
    const m = typeMenu();
    const t = typeInput().trim();
    if (!m || !t) { setTypeMenu(null); setTypeError(null); return; }
    const result = parseCType(t);
    if (!result.valid) {
      setTypeError(result.error ?? "invalid type");
      return;
    }
    setTypedVars((prev) => ({ ...prev, [m.name]: result.normalized }));
    setTypeMenu(null);
    setTypeInput("");
    setTypeError(null);
  }

  async function fetchXrefs(addr: string) {
    setXrefMenu(null);
    setXrefResults({ addr, hits: [], loading: true });
    try {
      // Use regex search for the address pattern in instruction text
      const resp = await fetch(
        `/api/search?pattern=${encodeURIComponent(addr.replace("0x", "0x"))}&max_results=200`
      );
      if (resp.ok) {
        const data = await resp.json();
        setXrefResults({ addr, hits: data.hits || [], loading: false });
      } else {
        setXrefResults({ addr, hits: [], loading: false });
      }
    } catch {
      setXrefResults({ addr, hits: [], loading: false });
    }
  }

  function closeXrefs() { setXrefResults(null); }

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
        html: highlightLine(raw, types, searchQuery(), highlightedVar()),
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
                  <button type="button" class="pseudoc-btn"
                    disabled={!levelText(r())} onClick={snapshotBaseline}>
                    Snapshot
                  </button>
                  <Show when={diffBaseline()}>
                    <button type="button" class="pseudoc-btn"
                      onClick={() => setDiffMode((v) => !v)}>
                      {diffMode() ? "Hide diff" : "Diff"}
                    </button>
                    <button type="button" class="pseudoc-btn"
                      onClick={clearDiff}>
                      Clear
                    </button>
                  </Show>
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
                {/* Diff mode */}
                <Show when={diffMode() && diffLines()}>
                  <div class="pseudoc-code pseudoc-diff">
                    <For each={diffLines()!}>
                      {(dl, i) => (
                        <div class={`pseudoc-diff-line pseudoc-diff-${dl.kind}`}>
                          <span class="pseudoc-diff-prefix">{dl.kind === "added" ? "+" : dl.kind === "changed" ? "~" : " "}</span>
                          <span class="pseudoc-ln">{i() + 1}</span>
                          <span class="pseudoc-code-text" innerHTML={highlightLine(dl.line, typedVars(), searchQuery(), highlightedVar())} />
                        </div>
                      )}
                    </For>
                  </div>
                </Show>
                {/* Normal mode */}
                <Show when={!diffMode()}>
                <Show when={levelText(r())} fallback={<p class="dim">no {ilLevel().toUpperCase()} text output</p>}>
                  <div class="pseudoc-code" ref={highlightEl}
                    onMouseOver={handleVarHover}
                    onMouseOut={handleVarOut}
                    onDblClick={(e) => { handleLabelDblClick(e); handleVarDblClick(e); }}
                    onContextMenu={handleVarContext}
                    onClick={handleCodeClick}
                  >
                    <For each={highlightedLines()}>
                      {(line, i) => (
                        <div
                          class="pseudoc-line"
                          classList={{
                            "pseudoc-line-active": line.pc !== null && currentPipeline() != null,
                            "pseudoc-line-current": line.isCurrent,
                          }}
                          title={line.pc ? `PC: 0x${line.pc.toString(16)} — click to jump` : undefined}
                          style={{ cursor: line.pc ? "pointer" : "default", "padding-left": `${8 + line.foldDepth * 16}px` }}
                          data-raw={line.raw}
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

      {/* Type input dialog (IDA Y key style): C type expression input */}
      <Show when={typeMenu()}>
        {(m) => (
          <div class="pseudoc-type-menu"
            style={{ left: `${m().x}px`, top: `${m().y}px` }}
            onClick={(e) => e.stopPropagation()}
          >
            <div class="pseudoc-type-menu-hdr">set type for <code>{m().name}</code></div>
            <div class="pseudoc-type-input-row">
              <input ref={typeInputEl} class="pseudoc-rename-input"
                placeholder="int32_t / char* / struct foo* ..."
                value={typeInput()}
                onInput={(e) => { setTypeInput(e.currentTarget.value); setTypeError(null); }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") applyVarType();
                  else if (e.key === "Escape") { setTypeMenu(null); setTypeInput(""); }
                }}
              />
              <button type="button" class="pseudoc-search-btn" onClick={applyVarType}>OK</button>
            </div>
            <Show when={typeError()}>
              <div class="pseudoc-type-err">{typeError()}</div>
            </Show>
          </div>
        )}
      </Show>

      {/* Xref context menu */}
      <Show when={xrefMenu()}>
        {(m) => (
          <div class="pseudoc-type-menu"
            style={{ left: `${m().x}px`, top: `${m().y}px` }}
            onClick={(e) => e.stopPropagation()}
          >
            <div class="pseudoc-type-menu-hdr">address <code>{m().addr}</code></div>
            <button type="button" class="pseudoc-type-menu-item"
              onClick={() => { navigator.clipboard.writeText(m().addr); setXrefMenu(null); }}>
              Copy address
            </button>
            <button type="button" class="pseudoc-type-menu-item"
              onClick={() => fetchXrefs(m().addr)}>
              Find references
            </button>
            <button type="button" class="pseudoc-type-menu-item"
              onClick={() => setXrefMenu(null)}>
              cancel
            </button>
          </div>
        )}
      </Show>

      {/* Xref results panel */}
      <Show when={xrefResults()}>
        {(r) => (
          <div class="pseudoc-xrefs">
            <div class="pseudoc-xrefs-hdr">
              <span>references to <code>{r().addr}</code> ({r().hits.length} hits)</span>
              <button type="button" class="pseudoc-search-btn" onClick={closeXrefs}>✕</button>
            </div>
            <Show when={r().loading}>
              <p class="dim">searching…</p>
            </Show>
            <div class="pseudoc-xrefs-list">
              <For each={r().hits.slice(0, 100)}>
                {(hit) => (
                  <div class="pseudoc-xref-item"
                    onClick={() => props.onSelectIdx?.(hit.idx)}
                    title="click to jump">
                    <span class="pseudoc-xref-idx">#{hit.idx}</span>
                    <code class="pseudoc-xref-pc">{hit.pc}</code>
                    <span class="pseudoc-xref-asm">{hit.asm}</span>
                  </div>
                )}
              </For>
            </div>
          </div>
        )}
      </Show>

      {/* Dismiss type menu on outside click */}
      <Show when={typeMenu() || xrefMenu()}>
        <div class="pseudoc-type-backdrop"
          onClick={() => { setTypeMenu(null); setXrefMenu(null); }} />
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

function highlightLine(line: string, types?: Record<string, string>, searchQuery?: string, highlightVar?: string | null): string {
  // Pre-compute: is this line a label definition (e.g. "loc_1008:")?
  const isLabelLine = /^\s*loc_[0-9a-fA-F]+:/.test(line);

  // Step 1: syntax highlighting on RAW text (before HTML escaping, so
  // entities like &gt; are not split by the regex).
  let html = line.replace(
    /\b(?:0x[0-9a-fA-F]+|[0-9]+(?:\.[0-9]+)?[fFuUlL]{0,3})\b|\b[a-zA-Z_][a-zA-Z0-9_]*\b|\/\/.*$|\/\*[\s\S]*?\*\/|".*?"|'.*?'/g,
    (match) => {
      if (/^(?:0x[0-9a-fA-F]+|[0-9])/.test(match)) {
        return `\x00tok-lit\x00${match}\x00/tok-lit\x00`;
      }
      if (match.startsWith("//")) {
        return `\x00tok-comment\x00${match}\x00/tok-comment\x00`;
      }
      if (match.startsWith("/*")) {
        return `\x00tok-comment\x00${match}\x00/tok-comment\x00`;
      }
      if (match.startsWith('"') || match.startsWith("'")) {
        return `\x00tok-str\x00${match}\x00/tok-str\x00`;
      }
      // Label reference/detection (before C_KEYWORDS so "goto loc_1008" works)
      if (/^loc_[0-9a-fA-F]+$/.test(match)) {
        if (isLabelLine) {
          return `\x00tok-label\x00${match}\x00/tok-label\x00`;
        }
        return `\x00lblref\x00${match}\x00/lblref\x00`;
      }
      if (C_KEYWORDS.has(match)) {
        if (C_TYPE_KEYWORDS.has(match)) {
          return `\x00tok-type\x00${match}\x00/tok-type\x00`;
        }
        return `\x00tok-kw\x00${match}\x00/tok-kw\x00`;
      }
      const type = types?.[match];
      if (type) {
        return `\x00V\x00${match}\x00${type}\x00/V\x00`;
      }
      return `\x00V\x00${match}\x00\x00/V\x00`;
    },
  );
  // Step 2: escape HTML in non-token text
  html = escapeHtml(html);
  // Step 3: convert \x00 markers to real HTML tags
  // Variable token: \x00V\x00name\x00type\x00/V\x00
  html = html.replace(/\x00V\x00([^\x00]*)\x00([^\x00]*)\x00\/V\x00/g, (_m, name, type) => {
    const attrName = escapeAttr(name);
    const hlClass = name === highlightVar ? ' tok-var-highlight' : '';
    if (type) {
      const attrType = escapeAttr(type);
      return `<span class="tok-var${hlClass}" data-var="${attrName}" data-type="${attrType}" title="${attrType} ${attrName}">`;
    }
    return `<span class="tok-var${hlClass}" data-var="${attrName}">`;
  });
  // Label reference markers: \x00lblref\x00name\x00/lblref\x00
  html = html.replace(/\x00lblref\x00([^\x00]+)\x00\/lblref\x00/g, (_m, name) => {
    return `<span class="tok-label" data-label="${escapeAttr(name)}">${name}</span>`;
  });
  // Other token types: \x00tok-XXX\x00 ... \x00/tok-XXX\x00
  html = html.replace(/\x00tok-([^\x00]+)\x00/g, '<span class="tok-$1">');
  html = html.replace(/\x00\/tok-([^\x00]+)\x00/g, '</span>');
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

function escapeAttr(s: string): string {
  return s.replace(/"/g, "&quot;").replace(/&/g, "&amp;").replace(/</g, "&lt;");
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;");
}
