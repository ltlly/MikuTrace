import { createEffect, createMemo, createSignal, For, Show } from "solid-js";

import {
  type DecIrOptions,
  fetchDecFn,
  fetchDecSummary,
  fetchIdxsForPc,
  renderLlil,
} from "~/api/client";
import { extractPc } from "~/utils/asm";
import { createGuardedResource } from "~/utils/resourceGuards";
import type { Accessor, Setter } from "solid-js";

export interface DecompilerPanelProps {
  selectedFn: Accessor<string>;
  onSelectFn: Setter<string>;
  selectedIdx: Accessor<number>;
  onSelectIdx?: (idx: number) => void;
  active: boolean;
}

interface FnSource {
  fnId: string;
  tier: string;
  splitTopK: number;
  splitMinRecords: number;
  withMemshadow: boolean;
}

interface SummarySource {
  splitTopK: number;
  splitMinRecords: number;
  withMemshadow: boolean;
}

function sameDecIrSource(a: SummarySource | undefined, b: SummarySource): boolean {
  return (
    !!a &&
    a.splitTopK === b.splitTopK &&
    a.splitMinRecords === b.splitMinRecords &&
    a.withMemshadow === b.withMemshadow
  );
}

function decIrOptions(s: SummarySource): DecIrOptions {
  return {
    splitTopK: s.splitTopK,
    splitMinRecords: s.splitMinRecords,
    withMemshadow: s.withMemshadow,
  };
}

// ── C token helpers ────────────────────────────────────────────────────────

const KNOWN_REGISTERS = /^(?:x(?:[0-9]|1[0-9]|2[0-9]|3[01])|fp|lr|sp|w(?:[0-9]|1[0-9]|2[0-9]|3[01])|pc|xzr|wzr)$/i;

const C_KEYWORDS = new Set([
  "if", "else", "for", "while", "do", "switch", "case", "default",
  "break", "continue", "return", "goto",
  "int", "long", "short", "char", "float", "double", "void",
  "unsigned", "signed", "const", "volatile", "static", "extern",
  "sizeof", "typedef", "enum", "struct", "union",
  "true", "false", "null", "NULL",
  "int8_t", "int16_t", "int32_t", "int64_t",
  "uint8_t", "uint16_t", "uint32_t", "uint64_t",
  "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t", "bool",
]);

const C_TYPE_KEYWORDS = new Set([
  "int", "long", "short", "char", "float", "double", "void",
  "unsigned", "signed", "struct", "union", "enum",
]);

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeAttr(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** Build an HTML string with syntax-highlighted tokens for one line of LLIL pseudocode. */
function highlightLlilLine(
  line: string,
  typedVars: Record<string, string>,
): string {
  // Step 1: tokenize raw text with sentinel markers
  let html = line.replace(
    /\b(?:0x[0-9a-fA-F]+|[0-9]+(?:\.[0-9]+)?[fFuUlL]{0,3})\b|\b[a-zA-Z_][a-zA-Z0-9_]*\b|\/\/.*$|"[^"]*"/g,
    (match) => {
      // Numeric literal or hex address
      if (/^(?:0x[0-9a-fA-F]+|[0-9])/.test(match)) {
        return `\x00tok-lit\x00${match}\x00/tok-lit\x00`;
      }
      // Comment
      if (match.startsWith("//")) {
        return `\x00tok-comment\x00${match}\x00/tok-comment\x00`;
      }
      // String literal
      if (match.startsWith('"')) {
        return `\x00tok-str\x00${match}\x00/tok-str\x00`;
      }
      // Register
      if (KNOWN_REGISTERS.test(match)) {
        return `\x00tok-reg\x00${match}\x00/tok-reg\x00`;
      }
      // C keyword / type keyword
      if (C_KEYWORDS.has(match)) {
        if (C_TYPE_KEYWORDS.has(match)) {
          return `\x00tok-type\x00${match}\x00/tok-type\x00`;
        }
        return `\x00tok-kw\x00${match}\x00/tok-kw\x00`;
      }
      // Variable (with optional type annotation)
      const type = typedVars[match];
      if (type) {
        return `\x00V\x00${match}\x00${type}\x00/V\x00`;
      }
      return `\x00V\x00${match}\x00\x00/V\x00`;
    },
  );
  // Step 2: HTML-escape non-sentinel text
  html = escapeHtml(html);
  // Step 3: resolve sentinel markers into real HTML tags
  // Variable span: \x00V\x00name\x00type\x00/V\x00
  html = html.replace(/\x00V\x00([^\x00]*)\x00([^\x00]*)\x00\/V\x00/g, (_m, name, type) => {
    const attrName = escapeAttr(name);
    if (type) {
      const attrType = escapeAttr(type);
      return `<span class="tok-var" data-var="${attrName}" data-type="${attrType}" title="${attrType} ${attrName}">${name}</span>`;
    }
    return `<span class="tok-var" data-var="${attrName}">${name}</span>`;
  });
  // Other token kinds: \x00tok-XXX\x00 ... \x00/tok-XXX\x00
  html = html.replace(/\x00tok-([^\x00]+)\x00/g, '<span class="tok-$1">');
  html = html.replace(/\x00\/tok-([^\x00]+)\x00/g, '</span>');
  return html;
}

/** Extract the first hex PC (0x...) from a line of text. */
// ── Component ──────────────────────────────────────────────────────────────

export default function DecompilerPanel(props: DecompilerPanelProps) {
  const [splitTopK, setSplitTopK] = createSignal(40);
  const [splitMinRecords, setSplitMinRecords] = createSignal(10);
  const [withMemshadow, setWithMemshadow] = createSignal(false);
  const [tier, setTier] = createSignal("hot");
  const [llilMaxRecords, setLlilMaxRecords] = createSignal(300);
  const [llilDce, setLlilDce] = createSignal(false);
  const [llilLoading, setLlilLoading] = createSignal(false);
  const [llilError, setLlilError] = createSignal("");
  const [llilOutput, setLlilOutput] = createSignal("");
  let llilSeq = 0;

  // ── New: keyboard-navigable line cursor ─────────────────────────────────
  const [cursorLine, setCursorLine] = createSignal(-1);
  const [renamedVars, setRenamedVars] = createSignal<Record<string, string>>({});
  const [typedVars, setTypedVars] = createSignal<Record<string, string>>({});
  const [renameInput, setRenameInput] = createSignal<{ oldName: string; newName: string } | null>(null);
  const [typeInput, setTypeInput] = createSignal<{ name: string; x: number; y: number } | null>(null);
  const [typeValue, setTypeValue] = createSignal("");
  let llilBodyRef: HTMLDivElement | undefined;
  let renameInputEl: HTMLInputElement | undefined;
  let typeInputEl: HTMLInputElement | undefined;

  // Clear cursor state when panel goes inactive
  createEffect(() => {
    if (!props.active) {
      setCursorLine(-1);
    }
  });

  // ── Split LLIL output into lines, apply variable renames ─────────────────
  const llilLines = createMemo(() => {
    const text = llilOutput();
    if (!text) return [] as string[];
    let processed = text;
    const renames = renamedVars();
    for (const [oldName, newName] of Object.entries(renames)) {
      processed = processed.replace(
        new RegExp("\\b" + escapeRegExp(oldName) + "\\b", "g"),
        newName,
      );
    }
    return processed.split("\n");
  });

  // ── Highlighted HTML for each line, cached per render tick ───────────────
  const llilLinesHtml = createMemo(() => {
    const types = typedVars();
    return llilLines().map((raw) => highlightLlilLine(raw, types));
  });

  // ── Track which llil line contains the header/signature vs body ──────────
  const sigEndLine = createMemo(() => {
    const lines = llilLines();
    // heuristic: the function signature ends at the first '{' or at the first
    // line that looks like a code statement rather than a declaration/header.
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trimEnd();
      if (trimmed.endsWith("{") || trimmed === "{") return i;
    }
    return Math.min(5, lines.length - 1);
  });

  // ── Jump helpers ─────────────────────────────────────────────────────────
  async function jumpToPc(pc: number) {
    if (!props.onSelectIdx) return;
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
    } catch { /* ignore */ }
  }

  async function jumpCurrentLine() {
    const idx = cursorLine();
    const lines = llilLines();
    if (idx < 0 || idx >= lines.length) return;
    const pc = extractPc(lines[idx]);
    if (pc !== null) await jumpToPc(pc);
  }

  // ── Auto-scroll cursor line into view ───────────────────────────────────
  createEffect(() => {
    const idx = cursorLine();
    if (idx < 0 || !llilBodyRef) return;
    const el = llilBodyRef.querySelector<HTMLElement>(`.dec-llil-line[data-i="${idx}"]`);
    if (el) el.scrollIntoView({ block: "center" });
  });

  // ── Keyboard navigation ─────────────────────────────────────────────────
  function handleKeyDown(e: KeyboardEvent) {
    const lines = llilLines();
    if (!lines.length) return;

    if (e.key === "ArrowUp") {
      e.preventDefault();
      setCursorLine((prev) => Math.max(0, prev - 1));
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setCursorLine((prev) => Math.min(lines.length - 1, prev + 1));
    } else if (e.key === "PageUp") {
      e.preventDefault();
      setCursorLine((prev) => Math.max(0, prev - 20));
    } else if (e.key === "PageDown") {
      e.preventDefault();
      setCursorLine((prev) => Math.min(lines.length - 1, prev + 20));
    } else if (e.key === "Home") {
      e.preventDefault();
      if (e.ctrlKey || e.metaKey) setCursorLine(0);
      else {
        // Jump to first non-header line (body start)
        const sigEnd = sigEndLine();
        setCursorLine(Math.min(sigEnd + 1, lines.length - 1));
      }
    } else if (e.key === "End") {
      e.preventDefault();
      setCursorLine(lines.length - 1);
    } else if (e.key === "Enter") {
      e.preventDefault();
      jumpCurrentLine();
    } else if (e.key === "Tab") {
      e.preventDefault();
      const sigEnd = sigEndLine();
      const cur = cursorLine();
      // Toggle between signature region and body region
      if (cur >= 0 && cur <= sigEnd) {
        // In signature: jump to first body line
        setCursorLine(Math.min(sigEnd + 1, lines.length - 1));
      } else {
        // In body or no cursor: jump to first signature line
        setCursorLine(0);
      }
    } else if (e.key === "Escape") {
      setCursorLine(-1);
    }
  }

  // ── Variable rename: double-click var → inline prompt ───────────────────
  function handleVarDblClick(e: MouseEvent) {
    const target = e.target as HTMLElement;
    const varSpan = target.closest?.("[data-var]") as HTMLElement | null;
    if (!varSpan) return;
    const name = varSpan.dataset.var!;
    if (KNOWN_REGISTERS.test(name)) return;
    e.preventDefault();
    setRenameInput({ oldName: name, newName: name });
    setTimeout(() => renameInputEl?.focus(), 0);
  }

  function isValidVarName(name: string): boolean {
    if (!name) return false;
    if (/^\d+$/.test(name)) return false;
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) return false;
    if (C_KEYWORDS.has(name)) return false;
    // Check duplicate within current rename set
    const renames = renamedVars();
    const allRenamed = new Set(Object.values(renames));
    if (allRenamed.has(name)) return false;
    return true;
  }

  function commitRename() {
    const r = renameInput();
    if (!r || r.newName === r.oldName) { setRenameInput(null); return; }
    const trimmed = r.newName.trim();
    if (!isValidVarName(trimmed)) { setRenameInput(null); return; }
    setRenamedVars((prev) => ({ ...prev, [r.oldName]: trimmed }));
    setRenameInput(null);
  }

  function cancelRename() { setRenameInput(null); }

  // ── Variable type: right-click var → set type ───────────────────────────
  function handleVarContext(e: MouseEvent) {
    const target = e.target as HTMLElement;
    const varSpan = target.closest?.("[data-var]") as HTMLElement | null;
    if (varSpan) {
      const name = varSpan.dataset.var!;
      e.preventDefault();
      setTypeValue(typedVars()[name] || "");
      setTypeInput({ name, x: e.clientX, y: e.clientY });
      setTimeout(() => typeInputEl?.focus(), 0);
    }
  }

  function applyVarType() {
    const m = typeInput();
    const t = typeValue().trim();
    if (!m) return;
    if (t) {
      setTypedVars((prev) => ({ ...prev, [m.name]: t }));
    } else {
      // Remove type on empty input
      setTypedVars((prev) => {
        const next = { ...prev };
        delete next[m.name];
        return next;
      });
    }
    setTypeInput(null);
    setTypeValue("");
  }

  // ── Line click: single-click = select, double-click = select + jump ─────
  function handleLineClick(e: MouseEvent, raw: string) {
    // If the click landed on a variable span, let the variable handlers deal
    const target = e.target as HTMLElement;
    if (target.closest?.("[data-var]")) return;
    const lineDiv = target.closest?.(".dec-llil-line") as HTMLElement | null;
    if (!lineDiv) return;
    const i = Number(lineDiv.dataset.i);
    if (!Number.isFinite(i)) return;
    setCursorLine(i);
    if (e.detail >= 2) {
      e.preventDefault();
      const pc = extractPc(raw);
      if (pc !== null) jumpToPc(pc);
    }
  }

  // ── Existing decompiler logic ────────────────────────────────────────────

  function decIrSource(): SummarySource {
    return {
      splitTopK: Math.max(0, Math.min(200, Math.trunc(splitTopK()) || 0)),
      splitMinRecords: Math.max(1, Math.min(100000, Math.trunc(splitMinRecords()) || 1)),
      withMemshadow: withMemshadow(),
    };
  }

  const summarySource = createMemo<SummarySource | undefined>((prev) => {
    if (!props.active) return undefined;
    const next = decIrSource();
    return sameDecIrSource(prev, next) ? prev : next;
  });
  const [summary, currentSummary] = createGuardedResource<SummarySource, Awaited<ReturnType<typeof fetchDecSummary>>>(
    summarySource,
    (s, signal) => fetchDecSummary(decIrOptions(s), signal),
    (r, s) =>
      r.request_split_top_k === s.splitTopK &&
      r.request_split_min_records === s.splitMinRecords &&
      r.request_with_memshadow === s.withMemshadow,
  );

  createEffect(() => {
    if (!props.active) return;
    const first = currentSummary()?.fns[0]?.id;
    if (!props.selectedFn() && first) props.onSelectFn(first);
  });

  const fnSource = createMemo<FnSource | undefined>((prev) => {
    if (!props.active) return undefined;
    const fnId = props.selectedFn();
    if (!fnId) return undefined;
    const ir = decIrSource();
    const next = { fnId, tier: tier(), ...ir };
    return prev &&
      prev.fnId === next.fnId &&
      prev.tier === next.tier &&
      sameDecIrSource(prev, next)
      ? prev
      : next;
  });
  const [fnResp, currentFnResp] = createGuardedResource<FnSource, Awaited<ReturnType<typeof fetchDecFn>>>(
    fnSource,
    (s, signal) => fetchDecFn(s.fnId, s.tier, decIrOptions(s), signal),
    (r, s) =>
      r.request_fn_id === s.fnId &&
      r.request_tier === s.tier &&
      r.request_split_top_k === s.splitTopK &&
      r.request_split_min_records === s.splitMinRecords &&
      r.request_with_memshadow === s.withMemshadow,
  );

  createEffect((prev?: string) => {
    const sig = `${props.selectedFn()}\0${llilMaxRecords()}\0${llilDce()}`;
    if (prev !== undefined && prev !== sig) {
      llilSeq += 1;
      setLlilLoading(false);
      setLlilError("");
      setLlilOutput("");
      setCursorLine(-1);
      // Persist renames/types across re-renders (item 5 & 6 in spec)
    }
    return sig;
  });

  async function runLlil() {
    const fnId = props.selectedFn();
    if (!fnId) return;
    const seq = ++llilSeq;
    const maxRecords = Math.max(1, Math.min(10000, llilMaxRecords()));
    const dce = llilDce();
    setLlilLoading(true);
    setLlilError("");
    setLlilOutput("");
    try {
      const r = await renderLlil({
        fn_id: fnId,
        max_records: maxRecords,
        ssa: true,
        constfold: true,
        flag_elim: true,
        dce,
      });
      if (
        seq !== llilSeq ||
        props.selectedFn() !== fnId ||
        Math.max(1, Math.min(10000, llilMaxRecords())) !== maxRecords ||
        llilDce() !== dce
      ) return;

      // Seed rename/type maps from the API response on first load
      if (r.var_names && Object.keys(r.var_names).length > 0) {
        setRenamedVars((prev) => ({ ...r.var_names, ...prev }));
      }
      if (r.types && Object.keys(r.types).length > 0) {
        setTypedVars((prev) => ({ ...r.types, ...prev }));
      }

      setLlilOutput([
        `fn: ${r.fn_id} · records: ${r.records}${r.truncated ? " · partial result" : ""}`,
        `lift coverage: ${(r.lift_coverage * 100).toFixed(1)}% · intrinsic ${r.lift_intrinsic}/${r.lift_total}`,
        r.flag_elim_pairs.length ? `flag elim: ${r.flag_elim_pairs.length}` : "",
        Object.keys(r.types).length ? `types: ${Object.keys(r.types).length} vars · names: ${Object.keys(r.var_names).length}` : "",
        r.removed_pcs.length ? `dce removed: ${r.removed_pcs.join(", ")}` : "",
        "",
        r.pseudocode,
      ].filter(Boolean).join("\n"));
    } catch (err) {
      if (seq !== llilSeq) return;
      setLlilError(String(err));
    } finally {
      if (seq === llilSeq) setLlilLoading(false);
    }
  }

  return (
    <section class="panel decompiler-panel" tabIndex={-1}>
      <h2>Decompiler</h2>
      <Show when={summary.error}>
        <p class="err">load failed: {String(summary.error)}</p>
      </Show>
      <Show when={summary.loading}>
        <p class="dim">loading summary…</p>
      </Show>
      <Show when={currentSummary()}>
        {(r) => (
          <>
            <div class="dec-controls">
              <label>
                function
                <select value={props.selectedFn()} onChange={(e) => props.onSelectFn(e.currentTarget.value)}>
                  <Show when={props.selectedFn() && !r().fns.some((f) => f.id === props.selectedFn())}>
                    <option value={props.selectedFn()}>{props.selectedFn()}</option>
                  </Show>
                  <For each={r().fns}>
                    {(f) => <option value={f.id}>{f.id} · {f.name}</option>}
                  </For>
                </select>
              </label>
              <label>
                tier
                <select value={tier()} onChange={(e) => setTier(e.currentTarget.value)}>
                  <option value="hot">hot</option>
                  <option value="all">all</option>
                </select>
              </label>
              <label>
                split top
                <input
                  type="number"
                  min="0"
                  max="200"
                  step="1"
                  value={splitTopK()}
                  onInput={(e) => setSplitTopK(Number(e.currentTarget.value) || 0)}
                />
              </label>
              <label>
                min records
                <input
                  type="number"
                  min="1"
                  max="100000"
                  step="1"
                  value={splitMinRecords()}
                  onInput={(e) => setSplitMinRecords(Number(e.currentTarget.value) || 1)}
                />
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={withMemshadow()}
                  onChange={(e) => setWithMemshadow(e.currentTarget.checked)}
                />
                memshadow
              </label>
            </div>
            <p class="dim small">
              {r().records} records · module {r().module_name} · {r().fns.length} function candidates
            </p>
            <Show when={r().truncated}>
              <div class="cap-notice" role="status">
                Decompiler summary is a partial result; adjust split top / min records for a wider inventory.
              </div>
            </Show>
            <div class="dec-grid">
              <div class="dec-function-pane">
                <details class="dec-function-drawer">
                  <summary>functions ({r().fns.length.toLocaleString()})</summary>
                  <div class="dec-function-list">
                    <table class="dec-table">
                      <thead>
                        <tr>
                          <th>id</th>
                          <th>name</th>
                          <th>module</th>
                          <th>blocks</th>
                          <th>calls</th>
                          <th>idx range</th>
                          <th>source</th>
                        </tr>
                      </thead>
                      <tbody>
                        <For each={r().fns}>
                          {(f) => (
                            <tr
                              class={props.selectedFn() === f.id ? "selected" : ""}
                              onClick={() => props.onSelectFn(f.id)}
                            >
                              <td class="dim small">{f.id}</td>
                              <td>{f.name}</td>
                              <td class="dim small">
                                {f.module ?? ""}
                                <Show when={f.entry_rel !== null && f.entry_rel !== undefined}>
                                  <>+0x{f.entry_rel!.toString(16)}</>
                                </Show>
                              </td>
                              <td>{f.blocks}</td>
                              <td>{f.calls}</td>
                              <td class="dim small">
                                {f.entry_idx ?? "?"}..{f.exit_idx ?? "?"}
                              </td>
                              <td class="dim small">{f.source}</td>
                            </tr>
                          )}
                        </For>
                      </tbody>
                    </table>
                  </div>
                </details>
              </div>
              <div
                onKeyDown={handleKeyDown}
                tabIndex={0}
                class="dec-llil-pane"
              >
                <div class="dec-controls">
                  <label>
                    llil records
                    <input
                      type="number"
                      min="1"
                      max="10000"
                      step="50"
                      value={llilMaxRecords()}
                      onInput={(e) => setLlilMaxRecords(Number(e.currentTarget.value) || 300)}
                    />
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={llilDce()}
                      onChange={(e) => setLlilDce(e.currentTarget.checked)}
                      title="Dead Code Elimination: remove LLIL statements whose computed value is never used."
                    />
                    DCE
                  </label>
                  <span class="dim small dec-option-note">dead-code elimination</span>
                  <button type="button" disabled={llilLoading() || !props.selectedFn()} onClick={runLlil}>
                    {llilLoading() ? "rendering…" : "render LLIL"}
                  </button>
                  <Show when={cursorLine() >= 0}>
                    <span class="dim small">
                      line {cursorLine() + 1}/{llilLines().length}
                      <Show when={extractPc(llilLines()[cursorLine()])}>
                        <> · PC {(() => { const pc = extractPc(llilLines()[cursorLine()]); return pc !== null ? "0x" + pc!.toString(16) : ""; })()}</>
                      </Show>
                    </span>
                  </Show>
                </div>
                <Show when={!fnResp.loading && fnResp.error}>
                  <p class="err">fn load failed: {String(fnResp.error)}</p>
                </Show>
                <Show when={llilError()}>
                  <p class="err">llil failed: {llilError()}</p>
                </Show>

                {/* ── Interactive LLIL pseudocode with line cursor ── */}
                <Show when={llilOutput() && llilLines().length > 0}>
                  <div
                    ref={llilBodyRef}
                    class="dec-llil-body"
                    onDblClick={handleVarDblClick}
                    onContextMenu={handleVarContext}
                  >
                    <div class="dec-llil-header dim small">
                      cursor #{props.selectedIdx()} · arrow keys navigate · Enter = jump to asm · Tab = cycle sig/body · Esc = clear · double-click line = select+jump · double-click var = rename · right-click var = set type
                    </div>
                    <For each={llilLines()}>
                      {(raw, i) => (
                        <div
                          class="dec-llil-line"
                          classList={{
                            cur: i() === cursorLine(),
                            "dec-llil-sig": i() <= sigEndLine(),
                          }}
                          data-i={i()}
                          data-pc={(() => { const pc = extractPc(raw); return pc !== null ? "0x" + pc.toString(16) : ""; })()}
                          onClick={(e) => handleLineClick(e, raw)}
                          // eslint-disable-next-line solid/no-innerhtml
                          innerHTML={llilLinesHtml()[i()]}
                        />
                      )}
                    </For>
                  </div>
                </Show>

                {/* fallback: raw pre when body is not yet initialised */}
                <Show when={llilOutput() && llilLines().length === 0}>
                  <pre class="dec-llil">{llilOutput()}</pre>
                </Show>

                <Show when={fnResp.loading}>
                  <p class="dim">loading function markdown…</p>
                </Show>
                <Show when={currentFnResp()}>
                  {(f) => <pre class="dec-markdown">{f().markdown}</pre>}
                </Show>
              </div>
            </div>
          </>
        )}
      </Show>

      {/* ── Inline rename input ── */}
      <Show when={renameInput()}>
        {(r) => (
          <div class="dec-tooltip" style={{ position: "fixed", left: "200px", top: "140px", "z-index": "100" }}>
            rename <code>{r().oldName}</code>:
            <input
              ref={renameInputEl}
              class="dec-rename-input"
              value={r().newName}
              onInput={(e) => setRenameInput((prev) => prev ? { ...prev, newName: e.currentTarget.value } : null)}
              onKeyDown={(e) => {
                if (e.key === "Enter") commitRename();
                else if (e.key === "Escape") cancelRename();
              }}
              onBlur={commitRename}
            />
          </div>
        )}
      </Show>

      {/* ── Type input popup (right-click on variable) ── */}
      <Show when={typeInput()}>
        {(m) => (
          <div
            class="dec-tooltip dec-type-menu"
            style={{ position: "fixed", left: `${m().x}px`, top: `${m().y}px`, "z-index": "100" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div>set type for <code>{m().name}</code></div>
            <div style={{ display: "flex", gap: "4px", "margin-top": "4px" }}>
              <input
                ref={typeInputEl}
                class="dec-rename-input"
                placeholder="int32_t / char* / struct Foo..."
                value={typeValue()}
                onInput={(e) => setTypeValue(e.currentTarget.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") applyVarType();
                  else if (e.key === "Escape") { setTypeInput(null); setTypeValue(""); }
                }}
              />
              <button type="button" onClick={applyVarType}>OK</button>
            </div>
          </div>
        )}
      </Show>
    </section>
  );
}
