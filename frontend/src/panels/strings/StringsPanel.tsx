import { createSignal, createResource, Show, For } from "solid-js";
import { fetchStrings } from "~/api/client";

export default function StringsPanel() {
  const [minLen, setMinLen] = createSignal(4);
  const [query, setQuery] = createSignal("");
  const [resp] = createResource(
    () => ({ minLen: minLen(), q: query() }),
    async ({ minLen, q }) => fetchStrings(minLen, q),
  );
  return (
    <section class="panel">
      <h2>Strings</h2>
      <div class="strings-controls">
        <label>
          min len
          <input
            type="number"
            min="3"
            max="64"
            value={minLen()}
            onInput={(e) => setMinLen(Number(e.currentTarget.value) || 4)}
          />
        </label>
        <label>
          filter
          <input
            type="text"
            value={query()}
            placeholder="substring…"
            onInput={(e) => setQuery(e.currentTarget.value)}
          />
        </label>
      </div>
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
              {r().count} string{r().count === 1 ? "" : "s"}
              <Show when={r().cursor >= 0}>
                {" "}@ cursor={r().cursor}
              </Show>
            </p>
            <ul class="strings-list">
              <For each={r().strings}>
                {(s) => (
                  <li>
                    <span class="dim small">{s.addr}</span>
                    <span class="dim small">{s.len}</span>
                    <span class="str">{s.str}</span>
                  </li>
                )}
              </For>
            </ul>
          </>
        )}
      </Show>
    </section>
  );
}
