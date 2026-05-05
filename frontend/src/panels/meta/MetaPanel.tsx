import { createResource, Show, For } from "solid-js";
import { fetchMeta } from "~/api/client";

export default function MetaPanel() {
  const [meta] = createResource(fetchMeta);
  return (
    <section class="panel">
      <h2>Trace metadata</h2>
      <Show when={meta.error}>
        <p class="err">load failed: {String(meta.error)}</p>
      </Show>
      <Show when={meta.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={meta()}>
        {(m) => (
          <dl class="kv">
            <dt>path</dt>
            <dd>{m().path}</dd>
            <dt>records</dt>
            <dd>{m().records.toLocaleString()}</dd>
            <dt>method</dt>
            <dd>{m().method || <em class="dim">∅</em>}</dd>
            <dt>cmd</dt>
            <dd>{m().cmd ?? <em class="dim">∅</em>}</dd>
            <dt>fn_addr</dt>
            <dd>{m().fn_addr ?? <em class="dim">∅</em>}</dd>
            <dt>module</dt>
            <dd>
              <Show
                when={m().module}
                fallback={<em class="dim">∅</em>}
              >
                {(mod) => (
                  <code>
                    {mod().name} @ {mod().base}–{mod().end} ({mod().size.toLocaleString()} B)
                  </code>
                )}
              </Show>
            </dd>
            <dt>modules ({m().modules.length})</dt>
            <dd>
              <ul>
                <For each={m().modules}>
                  {(mod) => (
                    <li>
                      <code>{mod.name}</code> @ {mod.base}
                    </li>
                  )}
                </For>
              </ul>
            </dd>
            <dt>regs ({m().regs.length})</dt>
            <dd>
              <code>{m().regs.join(" ")}</code>
            </dd>
          </dl>
        )}
      </Show>
    </section>
  );
}
