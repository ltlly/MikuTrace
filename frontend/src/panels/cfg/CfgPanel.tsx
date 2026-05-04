import { createMemo, createResource, createSignal, For, Show } from "solid-js";

import { fetchCfgSvg, fetchFunctions } from "~/api/client";

function clampTimeout(raw: number): number {
  if (!Number.isFinite(raw)) return 60;
  return Math.min(300, Math.max(5, Math.trunc(raw)));
}

export default function CfgPanel() {
  const [fnName, setFnName] = createSignal("");
  const [timeout, setTimeout] = createSignal(60);
  const [reload, setReload] = createSignal(0);
  const [functions] = createResource(fetchFunctions);
  const fnNames = createMemo(() => {
    const names = new Set<string>();
    for (const fn of functions()?.functions ?? []) {
      if (fn.source === "bn") continue;
      if (fn.name) names.add(fn.name);
    }
    return [...names].sort((a, b) => a.localeCompare(b));
  });

  const [graph] = createResource(
    () => ({ fnName: fnName() || undefined, timeout: timeout(), reload: reload() }),
    (opts) => fetchCfgSvg({ fnName: opts.fnName, timeout: opts.timeout }),
  );

  return (
    <section class="panel">
      <h2>Graph</h2>
      <div class="cfg-controls">
        <label>
          function
          <select value={fnName()} onInput={(e) => setFnName(e.currentTarget.value)}>
            <option value="">all traced blocks</option>
            <For each={fnNames()}>{(name) => <option value={name}>{name}</option>}</For>
          </select>
        </label>
        <label>
          dot timeout
          <input
            type="number"
            min="5"
            max="300"
            value={timeout()}
            onInput={(e) => setTimeout(clampTimeout(Number(e.currentTarget.value)))}
          />
        </label>
        <button onClick={() => setReload((n) => n + 1)}>reload</button>
      </div>

      <Show when={functions.error}>
        <p class="err">function list failed: {String(functions.error)}</p>
      </Show>
      <Show when={graph.error}>
        <p class="err">graph load failed: {String(graph.error)}</p>
      </Show>
      <Show when={graph.loading}>
        <p class="dim">rendering graph…</p>
      </Show>

      <Show when={graph()}>
        {(resp) => {
          const r = resp();
          return (
            <>
              {r.status === "ready" && (
                <>
                  <p class="dim small">
                    {r.block_count}/{r.total_block_count} blocks · {r.fn ?? "all"} · cache{" "}
                    {r.cached ? "hit" : "miss"}
                  </p>
                  <div class="cfg-svg-frame" innerHTML={r.svg} />
                </>
              )}
              {r.status === "empty" && (
                <p class="dim">no traced CFG blocks for {r.fn ?? "selected function"}</p>
              )}
              {r.status === "error" && <p class="err">graphviz: {r.err}</p>}
            </>
          );
        }}
      </Show>
    </section>
  );
}
