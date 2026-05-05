import { createMemo, createResource, createSignal, For, Show } from "solid-js";

import { fetchIdxsForPc, fetchRecord, fetchSearch } from "~/api/client";

interface XrefPanelProps {
  idx: number;
  onSelect: (idx: number) => void;
  active: boolean;
}

interface AsmSearchSource {
  pattern: string;
  cursor: number;
}

function refPattern(pc: string | undefined): string {
  if (!pc) return "";
  return pc.toLowerCase();
}

function escapeRegex(text: string | undefined): string {
  return (text ?? "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export default function XrefPanel(props: XrefPanelProps) {
  const [pattern, setPattern] = createSignal("");
  const [submittedSearch, setSubmittedSearch] = createSignal<AsmSearchSource | undefined>();
  const [record] = createResource(
    () => (props.active ? props.idx : undefined),
    (idx) => fetchRecord(idx),
  );
  const currentRecord = createMemo(() => {
    const r = record();
    return r && r.idx === props.idx ? r : undefined;
  });
  const pcSource = createMemo((prev?: { pc: string; idx: number }) => {
    if (!props.active) return undefined;
    const pc = refPattern(currentRecord()?.pc);
    if (!pc) return undefined;
    const next = { pc, idx: props.idx };
    return prev && prev.pc === next.pc && prev.idx === next.idx ? prev : next;
  });
  const [pcRefs] = createResource(pcSource, (s) => (s ? fetchIdxsForPc(s.pc, s.idx, 60) : undefined));
  const defaultAsmPattern = createMemo(() => {
    if (!props.active || !currentRecord()?.asm) return "";
    return `^${escapeRegex(currentRecord()?.asm)}$`;
  });
  const asmSource = createMemo<AsmSearchSource | undefined>((prev) => {
    if (!props.active) return undefined;
    const next = submittedSearch();
    if (!next?.pattern) return undefined;
    return prev && prev.pattern === next.pattern && prev.cursor === next.cursor ? prev : next;
  });
  const [asmRefs] = createResource(asmSource, (s) =>
    s ? fetchSearch(s.pattern, 120, undefined, s.cursor) : undefined,
  );
  const currentPcRefs = createMemo(() => {
    const s = pcSource();
    const r = pcRefs();
    if (!s || !r) return undefined;
    return r.request_pc === s.pc &&
      r.request_cursor === s.idx &&
      r.request_limit === 60
      ? r
      : undefined;
  });
  const currentAsmRefs = createMemo(() => {
    const s = asmSource();
    const r = asmRefs();
    if (!s || !r) return undefined;
    return r.request_pattern === s.pattern &&
      r.request_max_results === 120 &&
      r.request_cursor === s.cursor
      ? r
      : undefined;
  });

  function submitSearch() {
    const p = pattern().trim();
    if (p) setSubmittedSearch({ pattern: p, cursor: props.idx });
  }

  function searchCurrentInstruction() {
    const p = defaultAsmPattern();
    if (p) setSubmittedSearch({ pattern: p, cursor: props.idx });
  }

  return (
    <section class="panel">
      <h2>Refs</h2>
      <div class="xref-controls">
        <label>
          instruction regex
          <input
            type="text"
            value={pattern()}
            placeholder={currentRecord()?.asm ? `current: ${currentRecord()?.asm}` : "mnemonic/op_str regex…"}
            onInput={(e) => setPattern(e.currentTarget.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") submitSearch();
            }}
          />
        </label>
        <div class="xref-buttons">
          <button type="button" onClick={submitSearch} disabled={!pattern().trim()}>
            search
          </button>
          <button type="button" onClick={searchCurrentInstruction} disabled={!defaultAsmPattern()}>
            match current text
          </button>
          <button type="button" onClick={() => setSubmittedSearch(undefined)} disabled={!submittedSearch()}>
            clear
          </button>
        </div>
        <Show when={currentRecord()}>
          {(r) => <span class="dim small">selected idx {r().idx} · pc {r().pc}</span>}
        </Show>
      </div>
      <Show when={!pcRefs.loading && pcRefs.error}>
        <p class="err">pc refs failed: {String(pcRefs.error)}</p>
      </Show>
      <Show when={!asmRefs.loading && asmRefs.error}>
        <p class="err">instruction text search failed: {String(asmRefs.error)}</p>
      </Show>
      <div class="xref-grid">
        <div>
          <h3>same PC executions</h3>
          <Show when={pcRefs.loading}>
            <p class="dim">loading…</p>
          </Show>
          <Show when={currentPcRefs()}>
            {(r) => (
              <>
                <p class="dim small">
                  {r().pc} · before {r().total_before} · after {r().total_after}
                  {r().before_capped || r().after_capped ? " · capped" : ""}
                </p>
                <table class="xref-table xref-exec-table">
                  <thead>
                    <tr>
                      <th>idx</th>
                      <th>where</th>
                      <th>distance</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={r().before}>
                      {(idx) => (
                        <tr
                          class={idx === props.idx ? "selected" : ""}
                          onClick={() => props.onSelect(idx)}
                        >
                          <td>{idx}</td>
                          <td>{idx < props.idx ? "before" : idx > props.idx ? "after" : "current"}</td>
                          <td>{idx === props.idx ? 0 : Math.abs(idx - props.idx)}</td>
                        </tr>
                      )}
                    </For>
                    <For each={r().after}>
                      {(idx) => (
                        <tr
                          class={idx === props.idx ? "selected" : ""}
                          onClick={() => props.onSelect(idx)}
                        >
                          <td>{idx}</td>
                          <td>{idx < props.idx ? "before" : idx > props.idx ? "after" : "current"}</td>
                          <td>{idx === props.idx ? 0 : Math.abs(idx - props.idx)}</td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
                <Show when={r().before.length === 0 && r().after.length === 0}>
                  <p class="dim small">no executions around current cursor</p>
                </Show>
              </>
            )}
          </Show>
        </div>
        <div>
          <h3>same instruction text</h3>
          <Show when={asmRefs.loading}>
            <p class="dim">loading…</p>
          </Show>
          <Show when={!submittedSearch()}>
            <p class="dim small">regex search over decoded assembly text</p>
          </Show>
          <Show when={currentAsmRefs()}>
            {(r) => (
              <>
                <p class="dim small">
                  regex {r().pattern} · around #{r().request_cursor ?? r().cursor ?? 0} · {r().count} hit{r().count === 1 ? "" : "s"}
                </p>
                <table class="xref-table">
                  <thead>
                    <tr>
                      <th>idx</th>
                      <th>pc</th>
                      <th>fn</th>
                      <th>asm</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={r().hits}>
                      {(hit) => (
                        <tr onClick={() => props.onSelect(hit.idx)}>
                          <td>{hit.idx}</td>
                          <td><code>{hit.pc}</code></td>
                          <td>{hit.func ?? ""}</td>
                          <td><code>{hit.asm}</code></td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
                <Show when={r().count === 0}>
                  <p class="dim small">no decoded instruction text matches</p>
                </Show>
              </>
            )}
          </Show>
        </div>
      </div>
    </section>
  );
}
