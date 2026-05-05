import { createEffect, createMemo, createResource, createSignal, For, Show } from "solid-js";

import { fetchIdxsForPc, fetchRecord, fetchSearch } from "~/api/client";
import { createGuardedResource } from "~/utils/resourceGuards";

interface XrefPanelProps {
  idx: number;
  onSelect: (idx: number) => void;
  active: boolean;
}

interface AsmSearchSource {
  pattern: string;
  cursor: number;
  limit: number;
}

interface PcRefSource {
  pc: string;
  idx: number;
  limit: number;
}

const DEFAULT_PC_REF_LIMIT = 60;
const MAX_PC_REF_LIMIT = 5000;
const DEFAULT_ASM_REF_LIMIT = 120;
const MAX_ASM_REF_LIMIT = 5000;

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
  const [pcRefLimit, setPcRefLimit] = createSignal(DEFAULT_PC_REF_LIMIT);
  createEffect(() => {
    props.idx;
    setPcRefLimit(DEFAULT_PC_REF_LIMIT);
  });

  const [record] = createResource(
    () => (props.active ? props.idx : undefined),
    (idx) => fetchRecord(idx),
  );
  const currentRecord = createMemo(() => {
    const r = record();
    return r && r.idx === props.idx ? r : undefined;
  });
  const pcSource = createMemo<PcRefSource | undefined>((prev) => {
    if (!props.active) return undefined;
    const pc = refPattern(currentRecord()?.pc);
    if (!pc) return undefined;
    const next = { pc, idx: props.idx, limit: pcRefLimit() };
    return prev && prev.pc === next.pc && prev.idx === next.idx && prev.limit === next.limit ? prev : next;
  });
  const [pcRefs, currentPcRefs] = createGuardedResource<PcRefSource, Awaited<ReturnType<typeof fetchIdxsForPc>>>(
    pcSource,
    (s) => fetchIdxsForPc(s.pc, s.idx, s.limit),
    (r, s) =>
      r.request_pc === s.pc &&
      r.request_cursor === s.idx &&
      r.request_limit === s.limit,
  );
  const defaultAsmPattern = createMemo(() => {
    if (!props.active || !currentRecord()?.asm) return "";
    return `^${escapeRegex(currentRecord()?.asm)}$`;
  });
  const asmSource = createMemo<AsmSearchSource | undefined>((prev) => {
    if (!props.active) return undefined;
    const next = submittedSearch();
    if (!next?.pattern) return undefined;
    return prev &&
      prev.pattern === next.pattern &&
      prev.cursor === next.cursor &&
      prev.limit === next.limit
      ? prev
      : next;
  });
  const [asmRefs, currentAsmRefs] = createGuardedResource<AsmSearchSource, Awaited<ReturnType<typeof fetchSearch>>>(
    asmSource,
    (s) => fetchSearch(s.pattern, s.limit, undefined, s.cursor),
    (r, s) =>
      r.request_pattern === s.pattern &&
      r.request_max_results === s.limit &&
      r.request_cursor === s.cursor,
  );

  function submitSearch(limit = DEFAULT_ASM_REF_LIMIT) {
    const p = pattern().trim();
    if (p) setSubmittedSearch({ pattern: p, cursor: props.idx, limit });
  }

  function searchCurrentInstruction(limit = DEFAULT_ASM_REF_LIMIT) {
    const p = defaultAsmPattern();
    if (p) setSubmittedSearch({ pattern: p, cursor: props.idx, limit });
  }

  function rerunAsmSearchAtCap() {
    const current = asmSource();
    if (current) {
      setSubmittedSearch({ ...current, limit: MAX_ASM_REF_LIMIT });
    }
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
          <button type="button" onClick={() => submitSearch()} disabled={!pattern().trim()}>
            search
          </button>
          <button type="button" onClick={() => searchCurrentInstruction()} disabled={!defaultAsmPattern()}>
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
                  {r().before_capped || r().after_capped ? " · partial result" : ""}
                </p>
                <Show when={r().before_capped || r().after_capped}>
                  <div class="cap-notice" role="status">
                    <span>
                      Same-PC refs show at most {(r().request_limit ?? pcRefLimit()).toLocaleString()} before and after rows near the cursor.
                    </span>
                    <Show
                      when={(r().request_limit ?? pcRefLimit()) < MAX_PC_REF_LIMIT}
                      fallback={<span class="dim">UI/server cap is {MAX_PC_REF_LIMIT.toLocaleString()} rows per side.</span>}
                    >
                      <button type="button" onClick={() => setPcRefLimit(MAX_PC_REF_LIMIT)}>
                        show {MAX_PC_REF_LIMIT.toLocaleString()}
                      </button>
                    </Show>
                  </div>
                </Show>
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
                  regex {r().pattern} · around #{r().request_cursor ?? r().cursor ?? 0} ·{" "}
                  {r().returned ?? r().count}/{r().total_matches ?? r().count} hit{(r().total_matches ?? r().count) === 1 ? "" : "s"}
                  {r().truncated ? " · partial result" : ""}
                </p>
                <Show when={r().truncated}>
                  <div class="cap-notice" role="status">
                    <span>
                      Instruction text refs stopped at {(r().request_max_results ?? r().max_results_used ?? r().count).toLocaleString()} row cap.
                    </span>
                    <Show
                      when={(r().request_max_results ?? r().max_results_used ?? r().count) < MAX_ASM_REF_LIMIT}
                      fallback={<span class="dim">UI/server cap is {MAX_ASM_REF_LIMIT.toLocaleString()} rows; narrow the regex.</span>}
                    >
                      <button type="button" onClick={rerunAsmSearchAtCap}>
                        show {MAX_ASM_REF_LIMIT.toLocaleString()}
                      </button>
                    </Show>
                  </div>
                </Show>
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
