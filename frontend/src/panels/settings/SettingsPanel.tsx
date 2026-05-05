import { createEffect, createResource, createSignal, For, onCleanup, Show } from "solid-js";

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

function workerSummary(workers: Record<string, number> | undefined): string {
  if (!workers) return "?";
  return `idx ${workers.index ?? "?"} · sym ${workers.symbols ?? "?"} · cfg ${workers.cfg ?? "?"} · frame ${workers.frame_depths ?? "?"} · mem ${workers.memshadow ?? "?"} · reg ${workers.reg_timeline ?? "?"} · jni ${workers.jni_calls ?? "?"}`;
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
  const [statusTick, setStatusTick] = createSignal(0);
  const [bg] = createResource(
    () => (props.active ? statusTick() : undefined),
    () => fetchBgStatus(),
  );
  const [decomp] = createResource(
    () => (props.active ? statusTick() : undefined),
    () => fetchDecompStatus(),
  );

  createEffect(() => {
    localStorage.setItem(DENSE_KEY, dense() ? "1" : "0");
    document.documentElement.dataset.density = dense() ? "dense" : "normal";
  });

  createEffect(() => {
    if (!props.active) return;
    const timer = window.setInterval(() => setStatusTick((n) => n + 1), 1500);
    onCleanup(() => window.clearInterval(timer));
  });

  return (
    <section class="panel">
      <h2>Settings</h2>
      <div class="settings-grid">
        <div class="settings-section settings-toggles">
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
        </div>
        <Show when={meta()}>
          {(m) => (
            <div class="settings-section">
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
            <div class="settings-section">
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
            <div class="settings-section">
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
          <div class="settings-section">
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
              <Show when={bg()?.parallelism}>
                {(p) => (
                  <>
                    <dt>cores</dt>
                    <dd>{p().available}</dd>
                    <dt>records</dt>
                    <dd>{p().records.toLocaleString()}</dd>
                    <dt>workers</dt>
                    <dd>{workerSummary(p().workers)}</dd>
                  </>
                )}
              </Show>
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
