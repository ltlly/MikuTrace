import { createEffect, createMemo, createResource, createSignal, For, Show } from "solid-js";

import {
  callDecLlm,
  callLlilLlm,
  type DecIrOptions,
  fetchDecFn,
  fetchDecModels,
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

export default function DecompilerPanel(props: DecompilerPanelProps) {
  const [splitTopK, setSplitTopK] = createSignal(40);
  const [splitMinRecords, setSplitMinRecords] = createSignal(10);
  const [withMemshadow, setWithMemshadow] = createSignal(false);
  const summarySource = createMemo<SummarySource | undefined>((prev) => {
    if (!props.active) return undefined;
    const next = decIrSource();
    return sameDecIrSource(prev, next) ? prev : next;
  });
  const [summary, currentSummary] = createGuardedResource<SummarySource, Awaited<ReturnType<typeof fetchDecSummary>>>(
    summarySource,
    (s) => fetchDecSummary(decIrOptions(s)),
    (r, s) =>
      r.request_split_top_k === s.splitTopK &&
      r.request_split_min_records === s.splitMinRecords &&
      r.request_with_memshadow === s.withMemshadow,
  );
  const activeSource = () => (props.active ? "active" : undefined);
  const [models] = createResource(activeSource, () => fetchDecModels());
  const [tier, setTier] = createSignal("hot");
  const [model, setModel] = createSignal("mimo");
  const [lang, setLang] = createSignal("en");
  const [maxTokens, setMaxTokens] = createSignal(4096);
  const [llmLoading, setLlmLoading] = createSignal(false);
  const [llmError, setLlmError] = createSignal("");
  const [llmOutput, setLlmOutput] = createSignal("");
  const [llilLoading, setLlilLoading] = createSignal(false);
  const [llilError, setLlilError] = createSignal("");
  const [llilOutput, setLlilOutput] = createSignal("");
  const [llilLlmLoading, setLlilLlmLoading] = createSignal(false);
  const [llilLlmError, setLlilLlmError] = createSignal("");
  const [llilLlmOutput, setLlilLlmOutput] = createSignal("");
  const [llilMaxRecords, setLlilMaxRecords] = createSignal(300);
  const [llilDce, setLlilDce] = createSignal(false);
  let llmSeq = 0;
  let llilSeq = 0;
  let llilLlmSeq = 0;

  function decIrSource(): SummarySource {
    return {
      splitTopK: Math.max(0, Math.min(200, Math.trunc(splitTopK()) || 0)),
      splitMinRecords: Math.max(1, Math.min(100000, Math.trunc(splitMinRecords()) || 1)),
      withMemshadow: withMemshadow(),
    };
  }

  function decIrOptions(s: SummarySource): DecIrOptions {
    return {
      splitTopK: s.splitTopK,
      splitMinRecords: s.splitMinRecords,
      withMemshadow: s.withMemshadow,
    };
  }

  function sameDecIrSource(a: SummarySource | undefined, b: SummarySource): boolean {
    return (
      !!a &&
      a.splitTopK === b.splitTopK &&
      a.splitMinRecords === b.splitMinRecords &&
      a.withMemshadow === b.withMemshadow
    );
  }

  createEffect(() => {
    if (!props.active) return;
    const first = currentSummary()?.fns[0]?.id;
    if (!props.selectedFn() && first) props.onSelectFn(first);
  });

  createEffect(() => {
    if (!props.active) return;
    const first = models()?.models[0];
    if (first && !models()?.models.includes(model())) setModel(first);
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
    (s) => fetchDecFn(s.fnId, s.tier, decIrOptions(s)),
    (r, s) =>
      r.request_fn_id === s.fnId &&
      r.request_tier === s.tier &&
      r.request_split_top_k === s.splitTopK &&
      r.request_split_min_records === s.splitMinRecords &&
      r.request_with_memshadow === s.withMemshadow,
  );

  createEffect((prev?: string) => {
    const ir = decIrSource();
    const sig = `${props.selectedFn()}\0${tier()}\0${model()}\0${lang()}\0${maxTokens()}\0${ir.splitTopK}\0${ir.splitMinRecords}\0${ir.withMemshadow}`;
    if (prev !== undefined && prev !== sig) {
      llmSeq += 1;
      setLlmLoading(false);
      setLlmError("");
      setLlmOutput("");
    }
    return sig;
  });

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

  createEffect((prev?: string) => {
    const sig = `${props.selectedFn()}\0${model()}\0${lang()}\0${maxTokens()}\0${llilMaxRecords()}`;
    if (prev !== undefined && prev !== sig) {
      llilLlmSeq += 1;
      setLlilLlmLoading(false);
      setLlilLlmError("");
      setLlilLlmOutput("");
    }
    return sig;
  });

  async function runLlm() {
    const fnId = props.selectedFn();
    if (!fnId) return;
    const seq = ++llmSeq;
    const tierAtStart = tier();
    const irAtStart = decIrSource();
    setLlmLoading(true);
    setLlmError("");
    setLlmOutput("");
    try {
      const r = await callDecLlm({
        fn_id: fnId,
        model: model(),
        max_tokens: Math.max(256, Math.min(32768, maxTokens())),
        lang: lang(),
        tier: tierAtStart,
        with_memshadow: irAtStart.withMemshadow,
        split_top_k: irAtStart.splitTopK,
        split_min_records: irAtStart.splitMinRecords,
      });
      if (
        seq !== llmSeq ||
        props.selectedFn() !== fnId ||
        tier() !== tierAtStart ||
        !sameDecIrSource(irAtStart, decIrSource())
      ) return;
      if (r.error) setLlmError(r.error);
      setLlmOutput([
        `model: ${r.model}`,
        `cache: ${r.cache_hit ? "hit" : "miss"} · estimated prompt tokens: ${r.estimated_prompt_tokens}`,
        "",
        r.c_code ?? "",
      ].join("\n"));
    } catch (err) {
      if (seq !== llmSeq) return;
      setLlmError(String(err));
    } finally {
      if (seq === llmSeq) setLlmLoading(false);
    }
  }

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
        r.flag_elim_pairs.length ? `flag elim: ${r.flag_elim_pairs.length} branch${r.flag_elim_pairs.length === 1 ? "" : "es"}` : "",
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

  async function runLlilLlm() {
    const fnId = props.selectedFn();
    if (!fnId) return;
    const seq = ++llilLlmSeq;
    const maxRecords = Math.max(1, Math.min(10000, llilMaxRecords()));
    setLlilLlmLoading(true);
    setLlilLlmError("");
    setLlilLlmOutput("");
    try {
      const r = await callLlilLlm({
        fn_id: fnId,
        model: model(),
        max_tokens: Math.max(256, Math.min(32768, maxTokens())),
        lang: lang(),
        max_records: maxRecords,
      });
      if (
        seq !== llilLlmSeq ||
        props.selectedFn() !== fnId ||
        Math.max(1, Math.min(10000, llilMaxRecords())) !== maxRecords
      ) return;
      if (r.error) setLlilLlmError(r.error);
      setLlilLlmOutput([
        `LLIL -> LLM · ${r.model} · ${r.in_tokens}->${r.out_tokens} tok · ${r.latency_ms}ms`,
        `records: ${r.llil_records} · estimated prompt tokens: ${r.estimated_prompt_tokens}`,
        "",
        r.c_code ?? "",
      ].join("\n"));
    } catch (err) {
      if (seq !== llilLlmSeq) return;
      setLlilLlmError(String(err));
    } finally {
      if (seq === llilLlmSeq) setLlilLlmLoading(false);
    }
  }

  return (
    <section class="panel">
      <h2>Decompiler</h2>
      <Show when={summary.error}>
        <p class="err">load failed: {String(summary.error)}</p>
      </Show>
      <Show when={summary.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={currentSummary()}>
        {(r) => (
          <>
            <p class="dim small">
              {r().records} records · module {r().module_name} · {r().fns.length} fn{r().fns.length === 1 ? "" : "s"}
            </p>
            <Show when={r().truncated}>
              <div class="cap-notice" role="status">
                Decompiler summary is a partial result; increase split top or lower min records before using it as a complete function inventory.
              </div>
            </Show>
            <div class="dec-grid">
              <div>
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
                        <tr
                          class={props.selectedFn() === f.id ? "selected" : ""}
                          onClick={() => props.onSelectFn(f.id)}
                        >
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
              </div>
              <div>
                <div class="dec-controls">
                  <label>
                    model
                    <select value={model()} onChange={(e) => setModel(e.currentTarget.value)}>
                      <For each={models()?.models ?? ["mimo"]}>
                        {(m) => (
                          <option value={m}>
                            {m}{models()?.api_keys_configured[m] === false ? " (no key)" : ""}
                          </option>
                        )}
                      </For>
                    </select>
                  </label>
                  <label>
                    lang
                    <select value={lang()} onChange={(e) => setLang(e.currentTarget.value)}>
                      <option value="en">en</option>
                      <option value="zh">zh</option>
                    </select>
                  </label>
                  <label>
                    max tokens
                    <input
                      type="number"
                      min="256"
                      max="32768"
                      step="256"
                      value={maxTokens()}
                      onInput={(e) => setMaxTokens(Number(e.currentTarget.value) || 4096)}
                    />
                  </label>
                  <button type="button" disabled={llmLoading()} onClick={runLlm}>
                    {llmLoading() ? "calling…" : "call LLM"}
                  </button>
                </div>
                <div class="dec-controls">
                  <label>
                    llil max records
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
                    />
                    dce
                  </label>
                  <button type="button" disabled={llilLoading()} onClick={runLlil}>
                    {llilLoading() ? "rendering…" : "render LLIL"}
                  </button>
                  <button type="button" disabled={llilLlmLoading()} onClick={runLlilLlm}>
                    {llilLlmLoading() ? "calling…" : "LLIL → LLM"}
                  </button>
                </div>
                <Show when={!fnResp.loading && fnResp.error}>
                  <p class="err">fn load failed: {String(fnResp.error)}</p>
                </Show>
                <Show when={fnResp.loading}>
                  <p class="dim">loading fn…</p>
                </Show>
                <Show when={currentFnResp()}>
                  {(f) => <pre class="dec-markdown">{f().markdown}</pre>}
                </Show>
                <Show when={llmError()}>
                  <p class="err">llm failed: {llmError()}</p>
                </Show>
                <Show when={llmOutput()}>
                  <pre class="dec-llm">{llmOutput()}</pre>
                </Show>
                <Show when={llilError()}>
                  <p class="err">llil failed: {llilError()}</p>
                </Show>
                <Show when={llilOutput()}>
                  <pre class="dec-llil">{llilOutput()}</pre>
                </Show>
                <Show when={llilLlmError()}>
                  <p class="err">llil llm failed: {llilLlmError()}</p>
                </Show>
                <Show when={llilLlmOutput()}>
                  <pre class="dec-llil">{llilLlmOutput()}</pre>
                </Show>
              </div>
            </div>
          </>
        )}
      </Show>
    </section>
  );
}
