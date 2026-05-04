import { createEffect, createResource, createSignal, For, Show } from "solid-js";

import { fetchDecModels, fetchMeta, fetchOpenApi } from "~/api/client";

const DENSE_KEY = "tracemiku.dense";

function initialDense(): boolean {
  return localStorage.getItem(DENSE_KEY) === "1";
}

export default function SettingsPanel() {
  const [dense, setDense] = createSignal(initialDense());
  const [meta] = createResource(fetchMeta);
  const [models] = createResource(fetchDecModels);
  const [openapi] = createResource(fetchOpenApi);

  createEffect(() => {
    localStorage.setItem(DENSE_KEY, dense() ? "1" : "0");
    document.documentElement.dataset.density = dense() ? "dense" : "normal";
  });

  return (
    <section class="panel">
      <h2>Settings</h2>
      <div class="settings-grid">
        <label class="settings-toggle">
          <input
            type="checkbox"
            checked={dense()}
            onChange={(e) => setDense(e.currentTarget.checked)}
          />
          dense tables
        </label>
        <Show when={meta()}>
          {(m) => (
            <div>
              <h3>trace</h3>
              <dl class="kv settings-kv">
                <dt>records</dt>
                <dd>{m().records}</dd>
                <dt>method</dt>
                <dd>{m().method}</dd>
                <dt>modules</dt>
                <dd>{m().modules.length}</dd>
              </dl>
            </div>
          )}
        </Show>
        <Show when={openapi()}>
          {(api) => (
            <div>
              <h3>api</h3>
              <dl class="kv settings-kv">
                <dt>version</dt>
                <dd>{api().info.version}</dd>
                <dt>paths</dt>
                <dd>{Object.keys(api().paths).length}</dd>
              </dl>
            </div>
          )}
        </Show>
        <Show when={models()}>
          {(r) => (
            <div>
              <h3>llm models</h3>
              <ul class="settings-models">
                <For each={r().models}>
                  {(model) => (
                    <li class={r().api_keys_configured[model] ? "ready" : "missing"}>
                      <span>{model}</span>
                      <span>{r().api_keys_configured[model] ? "ready" : "no key"}</span>
                    </li>
                  )}
                </For>
              </ul>
            </div>
          )}
        </Show>
      </div>
      <Show when={meta.error || models.error || openapi.error}>
        <p class="err">
          settings load warning: {String(meta.error || models.error || openapi.error)}
        </p>
      </Show>
    </section>
  );
}
