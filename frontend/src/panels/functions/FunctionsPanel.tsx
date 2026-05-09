import { createResource, Show, For } from "solid-js";
import { fetchFunctions } from "~/api/client";
import type { Accessor } from "solid-js";
import type { FunctionEntry } from "~/api/types";

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

export interface FunctionsPanelProps {
  selectedFn: Accessor<string>;
  renames?: Accessor<Map<string, string>>;
  onSelectFn: (fn: FunctionEntry) => void;
  onJumpFn?: (fn: FunctionEntry) => void;
  onRenameFn?: (fn: FunctionEntry) => void;
  active: boolean;
}

export default function FunctionsPanel(props: FunctionsPanelProps) {
  const [resp] = createResource(
    () => (props.active ? "active" : undefined),
    () => fetchFunctions(),
  );
  return (
    <section class="panel">
      <h2>Functions</h2>
      <Show when={resp.error}>
        <p class="err">load failed: {String(resp.error)}</p>
      </Show>
      <Show when={resp.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={resp()}>
        {(r) => (
          <>
            <p class="dim small">
              {r().functions.length} function{r().functions.length === 1 ? "" : "s"}:
              {" "}
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
            <ul class="functions-list">
              <For each={r().functions}>
                {(fn) => {
                  const displayName = () => props.renames?.().get(fn.id) ?? fn.name;
                  const renamed = () => displayName() !== fn.name;
                  return (
                    <li
                      class={props.selectedFn() === fn.id ? "selected" : ""}
                      title={renamed() ? `orig ${fn.name}` : "right-click to rename"}
                      onClick={() => props.onSelectFn(fn)}
                      onDblClick={() => props.onJumpFn?.(fn)}
                      onContextMenu={(e) => {
                        if (!props.onRenameFn) return;
                        e.preventDefault();
                        e.stopPropagation();
                        props.onRenameFn(fn);
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
          </>
        )}
      </Show>
    </section>
  );
}
