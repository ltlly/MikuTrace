import { createEffect, createResource, For, Show } from "solid-js";

import { fetchSoStats } from "~/api/client";

interface SoFilterPanelProps {
  hiddenSos: Set<string>;
  onHiddenSosChange: (next: Set<string>) => void;
}

const SO_COLORS = [
  "#79c0ff",
  "#56d4dd",
  "#ffa657",
  "#a5d6ff",
  "#f2cc60",
  "#3fb950",
  "#ff7b72",
  "#58a6ff",
  "#7ee787",
];

function soColor(name: string): string {
  let h = 0;
  for (let i = 0; i < name.length; i += 1) h = ((h << 5) - h + name.charCodeAt(i)) | 0;
  return SO_COLORS[Math.abs(h) % SO_COLORS.length];
}

function soBadge(name: string): string {
  let s = name.replace(/-[0-9.]+\.so$/, "").replace(/\.so$/, "");
  if (s.startsWith("lib")) s = s.slice(3);
  return s.length > 8 ? s.slice(0, 8) : s || "?";
}

export default function SoFilterPanel(props: SoFilterPanelProps) {
  const [stats] = createResource(() => fetchSoStats(200, false));

  createEffect(() => {
    document.body.classList.toggle("multi-so", (stats()?.modules.length ?? 0) >= 2);
  });

  function setHidden(name: string, hidden: boolean) {
    const next = new Set(props.hiddenSos);
    if (hidden) next.add(name);
    else next.delete(name);
    props.onHiddenSosChange(next);
  }

  function showAll() {
    props.onHiddenSosChange(new Set());
  }

  function hideRest() {
    const modules = stats()?.modules ?? [];
    props.onHiddenSosChange(new Set(modules.slice(1).map((m) => m.name)));
  }

  return (
    <section class="panel so-filter-panel">
      <h2>SO Filter</h2>
      <Show when={stats.error}>
        <p class="err">SO stats failed: {String(stats.error)}</p>
      </Show>
      <Show when={stats.loading}>
        <p class="dim">loading SO stats…</p>
      </Show>
      <Show when={stats()}>
        {(s) => (
          <>
            <p class="dim small">
              {s().records.toLocaleString()} records · {s().modules.length}/{s().modules_total} SOs
              {s().unknown_records ? ` · ${s().unknown_records} unmapped` : ""}
            </p>
            <div class="so-filter-actions">
              <button type="button" onClick={showAll}>Show all</button>
              <button type="button" onClick={hideRest}>Hide all but #1</button>
            </div>
            <div class="so-list">
              <For each={s().modules}>
                {(mod) => {
                  const hidden = () => props.hiddenSos.has(mod.name);
                  return (
                    <label class="so-row" classList={{ hidden: hidden() }}>
                      <input
                        type="checkbox"
                        checked={!hidden()}
                        onChange={(e) => setHidden(mod.name, !e.currentTarget.checked)}
                      />
                      <span class="mod-badge" style={{ color: soColor(mod.name) }}>
                        {soBadge(mod.name)}
                      </span>
                      <span class="dim small">{mod.percent.toFixed(1)}%</span>
                      <span class="so-name" title={mod.name}>{mod.name}</span>
                      <span class="dim small">{mod.records.toLocaleString()}</span>
                    </label>
                  );
                }}
              </For>
            </div>
          </>
        )}
      </Show>
    </section>
  );
}
