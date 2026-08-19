import { createEffect, createMemo, createSignal, onCleanup, Show, For } from "solid-js";
import type { Accessor, Resource } from "solid-js";
import type { FunctionEntry, FunctionsResponse } from "~/api/types";

const SOURCE_LABELS: Record<string, string> = {
  "trace-ir": "trace",
  "symbol": "symbol",
  "bn": "bn",
};

const SOURCE_TITLES: Record<string, string> = {
  "trace-ir": "dynamic trace function",
  "symbol": "symbol map function",
  "bn": "Binary Ninja function",
};

/// 无过滤时最多渲染的函数行数；server 端最多返回 10_000 个。
const MAX_VISIBLE_FUNCTIONS = 500;

export interface FunctionsPanelProps {
  selectedFn: Accessor<string>;
  renames?: Accessor<Map<string, string>>;
  onSelectFn: (fn: FunctionEntry) => void;
  onJumpFn?: (fn: FunctionEntry) => void;
  onRenameFn?: (fn: FunctionEntry) => void;
  active: boolean;
  /// App 层单例 /api/functions resource（避免与 App/CfgPanel 重复请求）。
  functions: Resource<FunctionsResponse | undefined>;
}

export default function FunctionsPanel(props: FunctionsPanelProps) {
  const [fnContext, setFnContext] = createSignal<{ x: number; y: number; fn: FunctionEntry } | null>(null);
  const [filterRaw, setFilterRaw] = createSignal("");

  const filteredFunctions = createMemo(() => {
    const q = filterRaw().trim().toLowerCase();
    const fns = props.functions()?.functions ?? [];
    if (!q) return fns;
    return fns.filter((fn) =>
      fn.name.toLowerCase().includes(q) ||
      fn.id.toLowerCase().includes(q) ||
      (fn.module ?? "").toLowerCase().includes(q),
    );
  });
  const visibleFunctions = createMemo(() => filteredFunctions().slice(0, MAX_VISIBLE_FUNCTIONS));

  createEffect(() => {
    if (!fnContext()) return;
    const closeOnPointer = (e: PointerEvent) => {
      const target = e.target as Element | null;
      if (target?.closest(".fn-context-menu")) return;
      setFnContext(null);
    };
    const closeOnKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setFnContext(null);
    };
    document.addEventListener("pointerdown", closeOnPointer);
    document.addEventListener("keydown", closeOnKey);
    onCleanup(() => {
      document.removeEventListener("pointerdown", closeOnPointer);
      document.removeEventListener("keydown", closeOnKey);
    });
  });
  return (
    <section class="panel">
      <h2>Functions</h2>
      <Show when={props.functions.error}>
        <p class="err">load failed: {String(props.functions.error)}</p>
      </Show>
      <Show when={props.functions.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={props.functions()}>
        {(r) => (
          <>
            <p class="dim small">
              {filteredFunctions().length === r().functions.length
                ? `${r().functions.length} function${r().functions.length === 1 ? "" : "s"}`
                : `${filteredFunctions().length}/${r().functions.length} function${r().functions.length === 1 ? "" : "s"}`}
              :{" "}
              <For each={Object.entries(r().counts).filter(([, n]) => n > 0)}>
                {([src, n], i) => (
                  <span>
                    {i() === 0 ? "" : ", "}
                    <span class="fn-source-tag" title={SOURCE_TITLES[src] ?? src}>
                      {SOURCE_LABELS[src] ?? src}
                    </span>:{n}
                  </span>
                )}
              </For>
              <Show when={r().truncated}>
                {" "}· partial {r().returned_functions ?? r().functions.length}/{r().total_functions} shown
              </Show>
            </p>
            <input
              type="text"
              class="functions-filter"
              placeholder="filter by name/id/module…"
              value={filterRaw()}
              onInput={(e) => setFilterRaw(e.currentTarget.value)}
            />
            <Show when={filteredFunctions().length > visibleFunctions().length}>
              <div class="cap-notice" role="status">
                <span>
                  Showing first {visibleFunctions().length.toLocaleString()} of{" "}
                  {filteredFunctions().length.toLocaleString()} functions; narrow the filter to see more.
                </span>
              </div>
            </Show>
            <ul class="functions-list">
              <For each={visibleFunctions()}>
                {(fn) => {
                  const displayName = () => props.renames?.().get(fn.id) ?? fn.name;
                  const renamed = () => displayName() !== fn.name;
                  return (
                    <li
                      class={props.selectedFn() === fn.id ? "selected" : ""}
                      title={renamed() ? `orig ${fn.name}` : undefined}
                      onClick={() => props.onSelectFn(fn)}
                      onDblClick={() => props.onJumpFn?.(fn)}
                      onContextMenu={(e) => {
                        if (!props.onRenameFn) return;
                        e.preventDefault();
                        e.stopPropagation();
                        props.onSelectFn(fn);
                        setFnContext({
                          x: Math.min(e.clientX, window.innerWidth - 220),
                          y: Math.min(e.clientY, window.innerHeight - 120),
                          fn,
                        });
                      }}
                    >
                      <span class="fn-source-tag" title={SOURCE_TITLES[fn.source] ?? fn.source}>
                        {SOURCE_LABELS[fn.source] ?? fn.source}
                      </span>
                      <span class="fn-name" title={renamed() ? fn.name : undefined}>{displayName()}</span>
                      <Show when={renamed()}>
                        <span class="dim small">orig {fn.name}</span>
                      </Show>
                      <Show when={fn.entry_pc !== null}>
                        <span class="dim small">
                          @ {`0x${fn.entry_pc!.toString(16)}`}
                        </span>
                      </Show>
                      <Show when={fn.module}>
                        <span class="dim small">
                          {fn.module}
                          <Show when={fn.entry_rel !== null && fn.entry_rel !== undefined}>
                            <>+0x{fn.entry_rel!.toString(16)}</>
                          </Show>
                        </span>
                      </Show>
                      <Show when={fn.blocks > 0}>
                        <span class="dim small">{fn.blocks} blocks</span>
                      </Show>
                      <Show when={fn.records > 0}>
                        <span class="dim small">{fn.records.toLocaleString()} recs</span>
                      </Show>
                    </li>
                  );
                }}
              </For>
            </ul>
            <Show when={fnContext()}>
              {(ctx) => (
                <div
                  class="fn-context-menu"
                  style={{ left: `${ctx().x}px`, top: `${ctx().y}px` }}
                  onClick={(e) => e.stopPropagation()}
                  onContextMenu={(e) => e.preventDefault()}
                >
                  <div class="memory-context-title">{props.renames?.().get(ctx().fn.id) ?? ctx().fn.name}</div>
                  <button
                    type="button"
                    onClick={() => {
                      props.onRenameFn?.(ctx().fn);
                      setFnContext(null);
                    }}
                  >
                    rename
                  </button>
                </div>
              )}
            </Show>
          </>
        )}
      </Show>
    </section>
  );
}
