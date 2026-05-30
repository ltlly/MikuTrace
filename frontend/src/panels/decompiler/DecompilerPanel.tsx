import { createEffect, createMemo, createSignal, For, Show } from "solid-js";

import {
  type DecIrOptions,
  fetchDecFn,
  fetchDecSummary,
  renderLlil,
} from "~/api/client";
import { createGuardedResource } from "~/utils/resourceGuards";
import type { Accessor, Setter } from "solid-js";

export interface DecompilerPanelProps {
  selectedFn: Accessor<string>;
  onSelectFn: Setter<string>;
  active: boolean;
}

interface FnSource {
  fnId: string;
  tier: string;
  splitTopK: number;
  splitMinRecords: number;
  withMemshadow: boolean;
}

interface SummarySource {
  splitTopK: number;
  splitMinRecords: number;
  withMemshadow: boolean;
}

function sameDecIrSource(a: SummarySource | undefined, b: SummarySource): boolean {
  return (
    !!a &&
    a.splitTopK === b.splitTopK &&
    a.splitMinRecords === b.splitMinRecords &&
    a.withMemshadow === b.withMemshadow
  );
}

function decIrOptions(s: SummarySource): DecIrOptions {
  return {
    splitTopK: s.splitTopK,
    splitMinRecords: s.splitMinRecords,
    withMemshadow: s.withMemshadow,
  };
}

export default function DecompilerPanel(props: DecompilerPanelProps) {
  const [splitTopK, setSplitTopK] = createSignal(40);
  const [splitMinRecords, setSplitMinRecords] = createSignal(10);
  const [withMemshadow, setWithMemshadow] = createSignal(false);
  const [tier, setTier] = createSignal("hot");
  const [llilMaxRecords, setLlilMaxRecords] = createSignal(300);
  const [llilDce, setLlilDce] = createSignal(false);
  const [llilLoading, setLlilLoading] = createSignal(false);
  const [llilError, setLlilError] = createSignal("");
  const [llilOutput, setLlilOutput] = createSignal("");
  let llilSeq = 0;

  function decIrSource(): SummarySource {
    return {
      splitTopK: Math.max(0, Math.min(200, Math.trunc(splitTopK()) || 0)),
      splitMinRecords: Math.max(1, Math.min(100000, Math.trunc(splitMinRecords()) || 1)),
      withMemshadow: withMemshadow(),
    };
  }

  const summarySource = createMemo<SummarySource | undefined>((prev) => {
    if (!props.active) return undefined;
    const next = decIrSource();
    return sameDecIrSource(prev, next) ? prev : next;
  });
  const [summary, currentSummary] = createGuardedResource<SummarySource, Awaited<ReturnType<typeof fetchDecSummary>>>(
    summarySource,
    (s, signal) => fetchDecSummary(decIrOptions(s), signal),
    (r, s) =>
      r.request_split_top_k === s.splitTopK &&
      r.request_split_min_records === s.splitMinRecords &&
      r.request_with_memshadow === s.withMemshadow,
  );

  createEffect(() => {
    if (!props.active) return;
    const first = currentSummary()?.fns[0]?.id;
    if (!props.selectedFn() && first) props.onSelectFn(first);
  });

  const fnSource = createMemo<FnSource | undefined>((prev) => {
    if (!props.active) return undefined;
    const fnId = props.selectedFn();
    if (!fnId) return undefined;
    const ir = decIrSource();
    const next = { fnId, tier: tier(), ...ir };
    return prev &&
      prev.fnId === next.fnId &&
      prev.tier === next.tier &&
      sameDecIrSource(prev, next)
      ? prev
      : next;
  });
  const [fnResp, currentFnResp] = createGuardedResource<FnSource, Awaited<ReturnType<typeof fetchDecFn>>>(
    fnSource,
    (s, signal) => fetchDecFn(s.fnId, s.tier, decIrOptions(s), signal),
    (r, s) =>
      r.request_fn_id === s.fnId &&
      r.request_tier === s.tier &&
      r.request_split_top_k === s.splitTopK &&
      r.request_split_min_records === s.splitMinRecords &&
      r.request_with_memshadow === s.withMemshadow,
  );

  createEffect((prev?: string) => {
    const sig = `${props.selectedFn()}\0${llilMaxRecords()}\0${llilDce()}`;
    if (prev !== undefined && prev !== sig) {
      llilSeq += 1;
      setLlilLoading(false);
      setLlilError("");
      setLlilOutput("");
    }
    return sig;
  });

  async function runLlil() {
    const fnId = props.selectedFn();
    if (!fnId) return;
    const seq = ++llilSeq;
    const maxRecords = Math.max(1, Math.min(10000, llilMaxRecords()));
    const dce = llilDce();
    setLlilLoading(true);
    setLlilError("");
    setLlilOutput("");
    try {
      const r = await renderLlil({
        fn_id: fnId,
        max_records: maxRecords,
        ssa: true,
        constfold: true,
        flag_elim: true,
        dce,
      });
      if (
        seq !== llilSeq ||
        props.selectedFn() !== fnId ||
        Math.max(1, Math.min(10000, llilMaxRecords())) !== maxRecords ||
        llilDce() !== dce
      ) return;
      setLlilOutput([
        `fn: ${r.fn_id} · records: ${r.records}${r.truncated ? " · partial result" : ""}`,
        `lift coverage: ${(r.lift_coverage * 100).toFixed(1)}% · intrinsic ${r.lift_intrinsic}/${r.lift_total}`,
        r.flag_elim_pairs.length ? `flag elim: ${r.flag_elim_pairs.length}` : "",
        Object.keys(r.types).length ? `types: ${Object.keys(r.types).length} vars · names: ${Object.keys(r.var_names).length}` : "",
        r.removed_pcs.length ? `dce removed: ${r.removed_pcs.join(", ")}` : "",
        "",
        r.pseudocode,
      ].filter(Boolean).join("\n"));
    } catch (err) {
      if (seq !== llilSeq) return;
      setLlilError(String(err));
    } finally {
      if (seq === llilSeq) setLlilLoading(false);
    }
  }

  return (
    <section class="panel decompiler-panel">
      <h2>Decompiler</h2>
      <Show when={summary.error}>
        <p class="err">load failed: {String(summary.error)}</p>
      </Show>
      <Show when={summary.loading}>
        <p class="dim">loading summary…</p>
      </Show>
      <Show when={currentSummary()}>
        {(r) => (
          <>
            <div class="dec-controls">
              <label>
                function
                <select value={props.selectedFn()} onChange={(e) => props.onSelectFn(e.currentTarget.value)}>
                  <Show when={props.selectedFn() && !r().fns.some((f) => f.id === props.selectedFn())}>
                    <option value={props.selectedFn()}>{props.selectedFn()}</option>
                  </Show>
                  <For each={r().fns}>
                    {(f) => <option value={f.id}>{f.id} · {f.name}</option>}
                  </For>
                </select>
              </label>
              <label>
                tier
                <select value={tier()} onChange={(e) => setTier(e.currentTarget.value)}>
                  <option value="hot">hot</option>
                  <option value="all">all</option>
                </select>
              </label>
              <label>
                split top
                <input
                  type="number"
                  min="0"
                  max="200"
                  step="1"
                  value={splitTopK()}
                  onInput={(e) => setSplitTopK(Number(e.currentTarget.value) || 0)}
                />
              </label>
              <label>
                min records
                <input
                  type="number"
                  min="1"
                  max="100000"
                  step="1"
                  value={splitMinRecords()}
                  onInput={(e) => setSplitMinRecords(Number(e.currentTarget.value) || 1)}
                />
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={withMemshadow()}
                  onChange={(e) => setWithMemshadow(e.currentTarget.checked)}
                />
                memshadow
              </label>
            </div>
            <p class="dim small">
              {r().records} records · module {r().module_name} · {r().fns.length} function candidates
            </p>
            <Show when={r().truncated}>
              <div class="cap-notice" role="status">
                Decompiler summary is a partial result; adjust split top / min records for a wider inventory.
              </div>
            </Show>
            <div class="dec-grid">
              <div class="dec-function-pane">
                <details class="dec-function-drawer">
                  <summary>functions ({r().fns.length.toLocaleString()})</summary>
                  <div class="dec-function-list">
                    <table class="dec-table">
                      <thead>
                        <tr>
                          <th>id</th>
                          <th>name</th>
                          <th>module</th>
                          <th>blocks</th>
                          <th>calls</th>
                          <th>idx range</th>
                          <th>source</th>
                        </tr>
                      </thead>
                      <tbody>
                        <For each={r().fns}>
                          {(f) => (
                            <tr
                              class={props.selectedFn() === f.id ? "selected" : ""}
                              onClick={() => props.onSelectFn(f.id)}
                            >
                              <td class="dim small">{f.id}</td>
                              <td>{f.name}</td>
                              <td class="dim small">
                                {f.module ?? ""}
                                <Show when={f.entry_rel !== null && f.entry_rel !== undefined}>
                                  <>+0x{f.entry_rel!.toString(16)}</>
                                </Show>
                              </td>
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
                  </div>
                </details>
              </div>
              <div>
                <div class="dec-controls">
                  <label>
                    llil records
                    <input
                      type="number"
                      min="1"
                      max="10000"
                      step="50"
                      value={llilMaxRecords()}
                      onInput={(e) => setLlilMaxRecords(Number(e.currentTarget.value) || 300)}
                    />
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={llilDce()}
                      onChange={(e) => setLlilDce(e.currentTarget.checked)}
                      title="Dead Code Elimination: remove LLIL statements whose computed value is never used."
                    />
                    DCE
                  </label>
                  <span class="dim small dec-option-note">dead-code elimination</span>
                  <button type="button" disabled={llilLoading() || !props.selectedFn()} onClick={runLlil}>
                    {llilLoading() ? "rendering…" : "render LLIL"}
                  </button>
                </div>
                <Show when={!fnResp.loading && fnResp.error}>
                  <p class="err">fn load failed: {String(fnResp.error)}</p>
                </Show>
                <Show when={llilError()}>
                  <p class="err">llil failed: {llilError()}</p>
                </Show>
                <Show when={llilOutput()}>
                  <pre class="dec-llil">{llilOutput()}</pre>
                </Show>
                <Show when={fnResp.loading}>
                  <p class="dim">loading function markdown…</p>
                </Show>
                <Show when={currentFnResp()}>
                  {(f) => <pre class="dec-markdown">{f().markdown}</pre>}
                </Show>
              </div>
            </div>
          </>
        )}
      </Show>
    </section>
  );
}
