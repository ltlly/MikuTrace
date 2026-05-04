import { createEffect, createMemo, createResource, createSignal, For, onCleanup, Show } from "solid-js";
import type { Accessor, Setter } from "solid-js";

import { fetchFunctions, fetchHlilForFn, fetchIdxsForPc } from "~/api/client";

const SOURCE_TAGS: Record<string, string> = {
  "trace-ir": "TR",
  "symbol": "SY",
  "bn": "BN",
};

export interface HlilPanelProps {
  selectedFn: Accessor<string>;
  onSelectFn: Setter<string>;
  currentIdx: number;
  onSelect: (idx: number) => void;
  active: boolean;
}

interface HlilSource {
  fnId: string;
  reload: number;
}

export default function HlilPanel(props: HlilPanelProps) {
  const [reload, setReload] = createSignal(0);
  let jumpSeq = 0;
  let jumpAbort: AbortController | undefined;

  function cancelJump() {
    jumpSeq += 1;
    jumpAbort?.abort();
    jumpAbort = undefined;
  }

  onCleanup(() => cancelJump());

  const [functions] = createResource(
    () => (props.active ? "active" : undefined),
    () => fetchFunctions(),
  );

  createEffect(() => {
    if (!props.active) return;
    const first = functions()?.functions[0]?.id;
    if (!props.selectedFn() && first) props.onSelectFn(first);
  });

  const source = createMemo<HlilSource | undefined>((prev) => {
    if (!props.active) return undefined;
    const fnId = props.selectedFn();
    if (!fnId) return undefined;
    const next = { fnId, reload: reload() };
    return prev && prev.fnId === next.fnId && prev.reload === next.reload ? prev : next;
  });
  const [hlil] = createResource(source, (s) => (s ? fetchHlilForFn(s.fnId) : undefined));

  async function jumpLine(pc: string) {
    cancelJump();
    const seq = ++jumpSeq;
    const abort = new AbortController();
    jumpAbort = abort;
    try {
      const r = await fetchIdxsForPc(pc, props.currentIdx, 40, abort.signal);
      if (seq !== jumpSeq || abort.signal.aborted) return;
      const candidates = [...r.before, ...r.after];
      if (!candidates.length) return;
      candidates.sort((a, b) => Math.abs(a - props.currentIdx) - Math.abs(b - props.currentIdx));
      props.onSelect(candidates[0]);
    } catch (err) {
      if (abort.signal.aborted) return;
      if (seq !== jumpSeq) return;
      console.warn("HLIL jump failed", err);
    } finally {
      if (jumpAbort === abort) jumpAbort = undefined;
    }
  }

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
                    <tr onClick={() => void jumpLine(line.pc)} title="jump to nearest trace execution">
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
