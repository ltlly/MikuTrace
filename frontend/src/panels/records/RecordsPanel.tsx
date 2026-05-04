import { createResource, createSignal, Show, For } from "solid-js";
import { fetchRecords } from "~/api/client";

const PAGE = 50;

interface RecordsPanelProps {
  selectedIdx: number;
  onSelect: (idx: number) => void;
}

export default function RecordsPanel(props: RecordsPanelProps) {
  const [start, setStart] = createSignal(0);
  const [resp] = createResource(
    () => start(),
    (s) => fetchRecords({ start: s, count: PAGE }),
  );

  return (
    <section class="panel">
      <h2>Records</h2>
      <Show when={resp.error}>
        <p class="err">load failed: {String(resp.error)}</p>
      </Show>
      <Show when={resp.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={resp()}>
        {(r) => (
          <>
            <div class="records-pagination">
              <button
                disabled={start() === 0}
                onClick={() => setStart(Math.max(0, start() - PAGE))}
              >prev</button>
              <span class="dim">
                showing {r().start}–{r().end} of trace
              </span>
              <button
                disabled={r().count < PAGE}
                onClick={() => setStart(r().end)}
              >next</button>
            </div>
            <table class="records-table">
              <thead>
                <tr>
                  <th>idx</th>
                  <th>pc</th>
                  <th>rel</th>
                  <th>asm</th>
                  <th>flags</th>
                </tr>
              </thead>
              <tbody>
                <For each={r().records}>
                  {(row) => (
                    <tr
                      class={row.idx === props.selectedIdx ? "selected" : ""}
                      tabIndex={0}
                      onClick={() => props.onSelect(row.idx)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") props.onSelect(row.idx);
                      }}
                    >
                      <td>{row.idx}</td>
                      <td><code>{row.pc}</code></td>
                      <td><code>{row.rel ?? "—"}</code></td>
                      <td><code>{row.asm}</code></td>
                      <td>
                        {row.is_call ? "📞" : ""}
                        {row.is_ret ? "↩" : ""}
                        {row.is_branch && !row.is_call && !row.is_ret ? "↳" : ""}
                      </td>
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
