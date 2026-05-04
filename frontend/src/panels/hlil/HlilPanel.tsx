import { createEffect, createMemo, createResource, createSignal, For, Show } from "solid-js";
import type { Accessor, Setter } from "solid-js";

import { fetchFunctions, fetchHlilForFn } from "~/api/client";

const SOURCE_TAGS: Record<string, string> = {
  "trace-ir": "TR",
  "symbol": "SY",
  "bn": "BN",
};

export interface HlilPanelProps {
  selectedFn: Accessor<string>;
  onSelectFn: Setter<string>;
}

export default function HlilPanel(props: HlilPanelProps) {
  const [reload, setReload] = createSignal(0);
  const [functions] = createResource(fetchFunctions);

  createEffect(() => {
    const first = functions()?.functions[0]?.id;
    if (!props.selectedFn() && first) props.onSelectFn(first);
  });

  const source = createMemo(() => {
    const fnId = props.selectedFn();
    if (!fnId) return null;
    return { fnId, reload: reload() };
  });
  const [hlil] = createResource(source, (s) => (s ? fetchHlilForFn(s.fnId) : undefined));

  return (
    <section class="panel">
      <h2>HLIL</h2>
      <div class="hlil-controls">
        <label>
          function
          <select value={props.selectedFn()} onChange={(e) => props.onSelectFn(e.currentTarget.value)}>
            <For each={functions()?.functions ?? []}>
              {(fn) => (
                <option value={fn.id}>
                  {SOURCE_TAGS[fn.source] ?? fn.source} · {fn.id} · {fn.name}
                </option>
              )}
            </For>
          </select>
        </label>
        <button type="button" disabled={!props.selectedFn() || hlil.loading} onClick={() => setReload((n) => n + 1)}>
          {hlil.loading ? "loading…" : "reload"}
        </button>
      </div>
      <Show when={functions.error}>
        <p class="err">function list failed: {String(functions.error)}</p>
      </Show>
      <Show when={hlil.error}>
        <p class="err">hlil failed: {String(hlil.error)}</p>
      </Show>
      <Show when={hlil()}>
        {(r) => (
          <Show
            when={r().ready && r().ok}
            fallback={<p class="dim small">{r().error ?? "BN sidecar is not ready"}</p>}
          >
            <p class="dim small">
              {r().fn?.name ?? props.selectedFn()} · {r().lines?.length ?? 0} line{(r().lines?.length ?? 0) === 1 ? "" : "s"}
            </p>
            <table class="hlil-table">
              <tbody>
                <For each={r().lines ?? []}>
                  {(line) => (
                    <tr>
                      <td class="dim small">{line.pc}</td>
                      <td><code>{line.text}</code></td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </Show>
        )}
      </Show>
    </section>
  );
}
