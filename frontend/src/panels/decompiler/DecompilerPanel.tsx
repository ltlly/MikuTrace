import { createEffect, createMemo, createResource, createSignal, For, Show } from "solid-js";

import { callDecLlm, fetchDecFn, fetchDecModels, fetchDecSummary, renderLlil } from "~/api/client";

export default function DecompilerPanel() {
  const [summary] = createResource(fetchDecSummary);
  const [models] = createResource(fetchDecModels);
  const [selectedFn, setSelectedFn] = createSignal("");
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
  const [llilMaxRecords, setLlilMaxRecords] = createSignal(300);
  const [llilDce, setLlilDce] = createSignal(false);

  createEffect(() => {
    const first = summary()?.fns[0]?.id;
    if (!selectedFn() && first) setSelectedFn(first);
  });

  createEffect(() => {
    const first = models()?.models[0];
    if (first && !models()?.models.includes(model())) setModel(first);
  });

  const fnSource = createMemo(() => {
    const fnId = selectedFn();
    if (!fnId) return null;
    return { fnId, tier: tier() };
  });
  const [fnResp] = createResource(fnSource, (s) => (s ? fetchDecFn(s.fnId, s.tier) : undefined));

  async function runLlm() {
    const fnId = selectedFn();
    if (!fnId) return;
    setLlmLoading(true);
    setLlmError("");
    setLlmOutput("");
    try {
      const r = await callDecLlm({
        fn_id: fnId,
        model: model(),
        max_tokens: Math.max(256, Math.min(32768, maxTokens())),
        lang: lang(),
        tier: tier(),
      });
      if (r.error) setLlmError(r.error);
      setLlmOutput([
        `model: ${r.model}`,
        `cache: ${r.cache_hit ? "hit" : "miss"} · estimated prompt tokens: ${r.estimated_prompt_tokens}`,
        "",
        r.c_code ?? "",
      ].join("\n"));
    } catch (err) {
      setLlmError(String(err));
    } finally {
      setLlmLoading(false);
    }
  }

  async function runLlil() {
    const fnId = selectedFn();
    if (!fnId) return;
    setLlilLoading(true);
    setLlilError("");
    setLlilOutput("");
    try {
      const r = await renderLlil({
        fn_id: fnId,
        max_records: Math.max(1, Math.min(10000, llilMaxRecords())),
        ssa: true,
        constfold: true,
        dce: llilDce(),
      });
      setLlilOutput([
        `fn: ${r.fn_id} · records: ${r.records}${r.truncated ? " · truncated" : ""}`,
        `lift coverage: ${(r.lift_coverage * 100).toFixed(1)}% · intrinsic ${r.lift_intrinsic}/${r.lift_total}`,
        r.removed_pcs.length ? `dce removed: ${r.removed_pcs.join(", ")}` : "",
        "",
        r.pseudocode,
      ].filter(Boolean).join("\n"));
    } catch (err) {
      setLlilError(String(err));
    } finally {
      setLlilLoading(false);
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
      <Show when={summary()}>
        {(r) => (
          <>
            <p class="dim small">
              {r().records} records · module {r().module_name} · {r().fns.length} fn{r().fns.length === 1 ? "" : "s"}
            </p>
            <div class="dec-grid">
              <div>
                <div class="dec-controls">
                  <label>
                    function
                    <select value={selectedFn()} onChange={(e) => setSelectedFn(e.currentTarget.value)}>
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
                          class={selectedFn() === f.id ? "selected" : ""}
                          onClick={() => setSelectedFn(f.id)}
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
                </div>
                <Show when={fnResp.error}>
                  <p class="err">fn load failed: {String(fnResp.error)}</p>
                </Show>
                <Show when={fnResp.loading}>
                  <p class="dim">loading fn…</p>
                </Show>
                <Show when={fnResp()}>
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
              </div>
            </div>
          </>
        )}
      </Show>
    </section>
  );
}
