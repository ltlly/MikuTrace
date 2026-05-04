import { createEffect, createResource, createSignal, For, Show } from "solid-js";

import {
  fetchBgStatus,
  fetchDecompStatus,
  fetchDecModels,
  fetchMeta,
  fetchOpenApi,
} from "~/api/client";

const DENSE_KEY = "tracemiku.dense";

function initialDense(): boolean {
  return localStorage.getItem(DENSE_KEY) === "1";
}

function statusText(item: unknown): string {
  if (!item || typeof item !== "object" || !("status" in item)) return "?";
  return String((item as { status?: unknown }).status ?? "?");
}

interface SettingsPanelProps {
  active: boolean;
  debugVisible: boolean;
  apiDebug: boolean;
  onDebugVisibleChange: (next: boolean) => void;
  onApiDebugChange: (next: boolean) => void;
}

export default function SettingsPanel(props: SettingsPanelProps) {
  const [dense, setDense] = createSignal(initialDense());
  const activeSource = () => (props.active ? "active" : undefined);
  const [meta] = createResource(activeSource, () => fetchMeta());
  const [models] = createResource(activeSource, () => fetchDecModels());
  const [openapi] = createResource(activeSource, () => fetchOpenApi());
  const [bg] = createResource(activeSource, () => fetchBgStatus());
  const [decomp] = createResource(activeSource, () => fetchDecompStatus());

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
        <label class="settings-toggle">
          <input
            type="checkbox"
            checked={props.debugVisible}
            onChange={(e) => props.onDebugVisibleChange(e.currentTarget.checked)}
          />
          debug overlay
        </label>
        <label class="settings-toggle">
          <input
            type="checkbox"
            checked={props.apiDebug}
            onChange={(e) => props.onApiDebugChange(e.currentTarget.checked)}
          />
          API debug log
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
        <Show when={bg() || decomp()}>
          <div>
            <h3>backend</h3>
            <dl class="kv settings-kv">
              <dt>cfg</dt>
              <dd>{statusText(bg()?.cfg)}</dd>
              <dt>index</dt>
              <dd>{statusText(bg()?.index)}</dd>
              <dt>mem</dt>
              <dd>{statusText(bg()?.mem)}</dd>
              <dt>decomp</dt>
              <dd>{decomp()?.status ?? statusText(bg()?.decomp)}</dd>
              <dt>bn so</dt>
              <dd>{decomp()?.so_path ?? "not configured"}</dd>
            </dl>
          </div>
        </Show>
      </div>
      <Show when={meta.error || models.error || openapi.error || bg.error || decomp.error}>
        <p class="err">
          settings load warning:{" "}
          {String(meta.error || models.error || openapi.error || bg.error || decomp.error)}
        </p>
      </Show>
    </section>
  );
}
