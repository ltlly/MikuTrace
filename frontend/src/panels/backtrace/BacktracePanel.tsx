import { createResource, For, Show } from "solid-js";

import { fetchBacktrace } from "~/api/client";

interface BacktracePanelProps {
  idx: number;
  onSelect: (idx: number) => void;
}

export default function BacktracePanel(props: BacktracePanelProps) {
  const [resp] = createResource(() => props.idx, fetchBacktrace);

  return (
    <section class="panel">
      <h2>Backtrace</h2>
      <Show when={resp.error}>
        <p class="err">load failed: {String(resp.error)}</p>
      </Show>
      <Show when={resp.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={resp()}>
        {(r) => (
          <>
            <p class="dim small">idx {r().idx} · depth {r().depth}</p>
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
                    <tr>
                      <td>{i()}</td>
                      <td>
                        <button type="button" onClick={() => props.onSelect(frame.call_site_idx)}>
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
