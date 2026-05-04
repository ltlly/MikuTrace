import { createResource, createSignal, For, Show } from "solid-js";

import { fetchIdxsTouchingRange, fetchStrings } from "~/api/client";
import type { StringEntry } from "~/api/types";

interface StringsPanelProps {
  onSelect: (idx: number) => void;
}

export default function StringsPanel(props: StringsPanelProps) {
  const [minLen, setMinLen] = createSignal(4);
  const [query, setQuery] = createSignal("");
  const [jumpErr, setJumpErr] = createSignal("");
  const [resp] = createResource(
    () => ({ minLen: minLen(), q: query() }),
    async ({ minLen, q }) => fetchStrings(minLen, q),
  );

  async function jumpString(s: StringEntry) {
    setJumpErr("");
    try {
      const hits = await fetchIdxsTouchingRange(s.addr, Math.max(1, s.len), 0, 80);
      const target =
        hits.writers_after[0] ??
        hits.readers_after[0] ??
        hits.writers_before[0] ??
        hits.readers_before[0];
      if (target === undefined) {
        setJumpErr(`${s.addr} 没有关联的读写 trace`);
        return;
      }
      props.onSelect(target);
    } catch (err) {
      setJumpErr(String(err));
    }
  }

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
      <Show when={jumpErr()}>
        <p class="err">{jumpErr()}</p>
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
                  <li
                    title="双击跳转到第一次写入/触碰该字符串地址的 trace"
                    onDblClick={() => void jumpString(s)}
                  >
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
