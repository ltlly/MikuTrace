import { createEffect, createMemo, createSignal, For, Show } from "solid-js";

import { fetchIdxsForPc, fetchSearch } from "~/api/client";
import type { RecordDetail } from "~/api/types";
import { createGuardedResource } from "~/utils/resourceGuards";
import { createVirtualList } from "~/utils/virtualList";

interface XrefPanelProps {
  idx: number;
  onSelect: (idx: number) => void;
  active: boolean;
  /// App 层统一的当前 idx /api/record 响应（含 loading/error 由 App 统一展示策略驱动）。
  record?: RecordDetail;
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
const XREF_ROW_HEIGHT = 20;

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

  const currentRecord = createMemo(() => {
    const r = props.record;
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
    (s, signal) => fetchIdxsForPc(s.pc, s.idx, s.limit, signal),
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
    (s, signal) => fetchSearch(s.pattern, s.limit, signal, s.cursor),
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

  // same-PC 执行历史：before+after 各最多 5000 行，固定行高窗口渲染。
  const execList = createVirtualList(
    () => {
      const r = currentPcRefs();
      return r ? r.before.length + r.after.length : 0;
    },
    XREF_ROW_HEIGHT,
  );
  const execWindowItems = createMemo(() => {
    const w = execList.window();
    const before = currentPcRefs()?.before ?? [];
    const after = currentPcRefs()?.after ?? [];
    const out: number[] = [];
    for (let pos = w.start; pos < w.end; pos += 1) {
      const idx = pos < before.length ? before[pos] : after[pos - before.length];
      if (idx !== undefined) out.push(idx);
    }
    return out;
  });
  // 指令文本搜索命中：最多 5000 行，同样窗口渲染。
  const hitsList = createVirtualList(
    () => currentAsmRefs()?.hits.length ?? 0,
    XREF_ROW_HEIGHT,
  );
  const hitsWindowItems = createMemo(() => {
    const w = hitsList.window();
    const hits = currentAsmRefs()?.hits ?? [];
    return hits.slice(w.start, w.end);
  });

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
        <p class="err">load failed: {String(pcRefs.error)}</p>
      </Show>
      <Show when={!asmRefs.loading && asmRefs.error}>
        <p class="err">load failed: {String(asmRefs.error)}</p>
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
                <div class="vscroll xref-vscroll" ref={execList.ref} onScroll={execList.onScroll}>
                  <table class="xref-table xref-exec-table xref-vtable">
                    <thead>
                      <tr>
                        <th>idx</th>
                        <th>where</th>
                        <th>distance</th>
                      </tr>
                    </thead>
                    <tbody class="vbody" style={{ height: `${execList.window().height}px` }}>
                      <For each={execWindowItems()}>
                        {(idx, i) => (
                          <tr
                            class="vrow"
                            classList={{ selected: idx === props.idx }}
                            style={{ top: `${(execList.window().start + i()) * XREF_ROW_HEIGHT}px` }}
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
                </div>
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
                <div class="vscroll xref-vscroll" ref={hitsList.ref} onScroll={hitsList.onScroll}>
                  <table class="xref-table xref-hits-table xref-vtable">
                    <thead>
                      <tr>
                        <th>idx</th>
                        <th>pc</th>
                        <th>fn</th>
                        <th>asm</th>
                      </tr>
                    </thead>
                    <tbody class="vbody" style={{ height: `${hitsList.window().height}px` }}>
                      <For each={hitsWindowItems()}>
                        {(hit, i) => (
                          <tr
                            class="vrow"
                            style={{ top: `${(hitsList.window().start + i()) * XREF_ROW_HEIGHT}px` }}
                            onClick={() => props.onSelect(hit.idx)}
                          >
                            <td>{hit.idx}</td>
                            <td><code>{hit.pc}</code></td>
                            <td>{hit.func ?? ""}</td>
                            <td><code>{hit.asm}</code></td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </div>
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
