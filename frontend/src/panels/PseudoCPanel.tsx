import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js";
import type { Accessor } from "solid-js";

import { fetchLlilPipeline } from "~/api/client";
import type { PipelineResponse } from "~/api/types";
import { createGuardedResource } from "~/utils/resourceGuards";
import type { UiTaskReporter } from "~/utils/taskCenter";

export interface PseudoCPanelProps {
  selectedFn: Accessor<string>;
  active: boolean;
  selectedIdx: Accessor<number>;
  onSelectIdx?: (idx: number) => void;
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

  // Detect large output (> 500 lines)
  const lineCount = createMemo(() => {
    const text = currentPipeline()?.[ilLevel() + "_text" as keyof PipelineResponse];
    if (!text) return 0;
    return text.split("\n").length;
  });
  const isLarge = createMemo(() => lineCount() > 500);

  // Auto-collapse large output
  createEffect(() => {
    if (isLarge()) setCollapsed(true);
  });

  // Highlighted HLIL text lines
  const highlightedLines = createMemo(() => {
    const text = currentPipeline()?.[ilLevel() + "_text" as keyof PipelineResponse];
    if (!text) return [] as { raw: string; html: string }[];
    const lines = text.split("\n");
    const displayLines = expandedView() ? lines : lines.slice(0, 500);
    return displayLines.map((raw) => ({
      raw,
      html: highlightLine(raw),
    }));
  });

  async function copyToClipboard() {
    const text = currentPipeline()?.[ilLevel() + "_text" as keyof PipelineResponse];
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      if (copyTimer) clearTimeout(copyTimer);
      copyTimer = setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
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
    <section class="panel pseudoc-panel">
      <h2>Decompile</h2>

      <div class="pseudoc-controls">
        <label>records <input type="number" min="1" max="5000" step="100"
          value={maxRecords()}
          onInput={(e) => setMaxRecords(Math.max(1, Math.min(5000, Number(e.currentTarget.value) || DEFAULT_MAX_RECORDS)))} />
        </label>
        <span class="dim small">{props.selectedFn() || "no function selected"} · cursor #{props.selectedIdx()}</span>
      </div>

      {/* Sub-tabs: HLIL | MLIL | LLIL */}
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
            {/* Stats bar */}
            <div class="pseudoc-stats">
              <div class="pseudoc-stats-grid">
                <div class="pseudoc-stat">
                  <span class="pseudoc-stat-label">Function</span>
                  <span class="pseudoc-stat-value">
                    <code>{r().name}</code>
                  </span>
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
                  <span class="pseudoc-stat-value">
                    {r().unique_pcs.toLocaleString()}
                  </span>
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
                  <span class="pseudoc-stat-value">
                    {r().hlil_count.toLocaleString()} lines
                  </span>
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
                    disabled={!r().hlil_text} onClick={copyToClipboard}>
                    {copied() ? "Copied ✓" : "Copy"}
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

            {/* HLIL text body — only render when showText */}
            <Show when={showText() && !collapsed()}>
              <div class="pseudoc-body" classList={{"pseudoc-body-collapsed": collapsed()}}>
                <Show when={r().hlil_text} fallback={<p class="dim">no HLIL text output</p>}>
                  <div class="pseudoc-code">
                    <For each={highlightedLines()}>
                      {(line, i) => (
                        <div class="pseudoc-line">
                          <span class="pseudoc-ln">{i() + 1}</span>
                          <span
                            class="pseudoc-code-text"
                            innerHTML={line.html}
                          />
                        </div>
                      )}
                    </For>
                    <Show
                      when={
                        !expandedView() &&
                        lineCount() > 500
                      }
                    >
                      <div class="pseudoc-truncated-hint">
                        … showing first 500 of {lineCount()} lines ·{" "}
                        <button
                          type="button"
                          class="pseudoc-inline-btn"
                          onClick={() => setExpandedView(true)}
                        >
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

function highlightLine(line: string): string {
  return escapeHtml(line).replace(
    /\b(?:0x[0-9a-fA-F]+|[0-9]+(?:\.[0-9]+)?[fFuUlL]{0,3})\b|\b[a-zA-Z_][a-zA-Z0-9_]*\b|\/\/.*$|\/\*[\s\S]*?\*\/|".*?"|'.*?'/g,
    (match) => {
      // Hex/decimal literals
      if (/^(?:0x[0-9a-fA-F]+|[0-9])/.test(match)) {
        return `<span class="tok-lit">${match}</span>`;
      }
      // Single-line comment
      if (match.startsWith("//")) {
        return `<span class="tok-comment">${match}</span>`;
      }
      // Block comment
      if (match.startsWith("/*")) {
        return `<span class="tok-comment">${match}</span>`;
      }
      // String literal
      if (match.startsWith('"') || match.startsWith("'")) {
        return `<span class="tok-str">${match}</span>`;
      }
      // Keywords
      if (C_KEYWORDS.has(match)) {
        if (C_TYPE_KEYWORDS.has(match)) {
          return `<span class="tok-type">${match}</span>`;
        }
        return `<span class="tok-kw">${match}</span>`;
      }
      return match;
    },
  );
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
