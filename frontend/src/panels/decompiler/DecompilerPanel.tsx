import { createResource, For, Show } from "solid-js";

import { fetchDecSummary } from "~/api/client";

export default function DecompilerPanel() {
  const [resp] = createResource(fetchDecSummary);
  return (
    <section class="panel">
      <h2>Decompiler (skeleton)</h2>
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
              {r().records} records · module {r().module_name} · {r().fns.length} fn{r().fns.length === 1 ? "" : "s"}
            </p>
            <table class="dec-table">
              <thead>
                <tr>
                  <th>id</th>
                  <th>name</th>
                  <th>blocks</th>
                  <th>calls</th>
                  <th>idx range</th>
                  <th>source</th>
                </tr>
              </thead>
              <tbody>
                <For each={r().fns}>
                  {(f) => (
                    <tr>
                      <td class="dim small">{f.id}</td>
                      <td>{f.name}</td>
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
          </>
        )}
      </Show>
    </section>
  );
}
