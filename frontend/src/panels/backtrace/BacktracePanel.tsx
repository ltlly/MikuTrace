import { createEffect, createMemo, createResource, createSignal, For, onCleanup, Show } from "solid-js";

import { fetchBacktrace } from "~/api/client";

interface BacktracePanelProps {
  idx: number;
  onSelect: (idx: number) => void;
  active: boolean;
}

export default function BacktracePanel(props: BacktracePanelProps) {
  const [queryIdx, setQueryIdx] = createSignal<number | undefined>();
  let queryTimer: number | undefined;

  createEffect(() => {
    if (queryTimer !== undefined) {
      window.clearTimeout(queryTimer);
      queryTimer = undefined;
    }
    if (!props.active) {
      setQueryIdx(undefined);
      return;
    }
    const idx = props.idx;
    queryTimer = window.setTimeout(() => {
      queryTimer = undefined;
      setQueryIdx(idx);
    }, 80);
  });
  onCleanup(() => {
    if (queryTimer !== undefined) window.clearTimeout(queryTimer);
  });

  const [resp] = createResource(
    queryIdx,
    (idx) => fetchBacktrace(idx),
  );
  const currentResp = createMemo(() => {
    const r = resp();
    return r && r.idx === props.idx ? r : undefined;
  });

  return (
    <section class="panel">
      <h2>Backtrace</h2>
      <Show when={!resp.loading && resp.error}>
        <p class="err">load failed: {String(resp.error)}</p>
      </Show>
      <Show when={resp.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={currentResp()}>
        {(r) => (
          <>
            <p class="dim small">
              idx {r().idx} · depth {r().depth}
              <Show when={r().truncated}>
                {" "}· showing last {r().returned ?? r().stack.length}
              </Show>
            </p>
            <table class="bt-table">
              <thead>
                <tr>
                  <th>frame</th>
                  <th>call idx</th>
                  <th>call pc</th>
                  <th>callee</th>
                  <th>fn</th>
                </tr>
              </thead>
              <tbody>
                <For each={r().stack}>
                  {(frame, i) => (
                    <tr onClick={() => props.onSelect(frame.call_site_idx)}>
                      <td>{r().depth - r().stack.length + i()}</td>
                      <td>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            props.onSelect(frame.call_site_idx);
                          }}
                        >
                          {frame.call_site_idx}
                        </button>
                      </td>
                      <td><code>{frame.call_pc_fmt ?? frame.call_pc}</code></td>
                      <td><code>{frame.callee_pc_fmt ?? frame.callee_pc ?? ""}</code></td>
                      <td>{frame.fn ?? ""}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </>
        )}
      </Show>
    </section>
  );
}
