import { createEffect, createMemo, createSignal, For, Show } from "solid-js";

import { fetchIdxsForPc } from "~/api/client";
import type { IdxsForPcResponse, RecordDetail } from "~/api/types";
import { createGuardedResource } from "~/utils/resourceGuards";
import { createVirtualList } from "~/utils/virtualList";

interface TraceForPcPanelProps {
  idx: number;
  onSelect: (idx: number) => void;
  active: boolean;
  /// App 层统一的当前 idx /api/record 响应与加载态。
  record?: RecordDetail;
  recordLoading?: boolean;
  recordError?: unknown;
}

interface IpcSource {
  pc: string;
  idx: number;
  limit: number;
}

const DEFAULT_TRACE_PC_LIMIT = 20;
const MAX_TRACE_PC_LIMIT = 5000;
const TRACE_PC_ROW_HEIGHT = 20;

export default function TraceForPcPanel(props: TraceForPcPanelProps) {
  const [limit, setLimit] = createSignal(DEFAULT_TRACE_PC_LIMIT);
  createEffect(() => {
    props.idx;
    setLimit(DEFAULT_TRACE_PC_LIMIT);
  });

  const currentRecord = createMemo(() => {
    const r = props.record;
    return r && r.idx === props.idx ? r : undefined;
  });
  const source = createMemo<IpcSource | undefined>((prev) => {
    const r = currentRecord();
    if (!props.active) return undefined;
    if (!r) return undefined;
    const next = { pc: r.pc, idx: props.idx, limit: limit() };
    return prev && prev.pc === next.pc && prev.idx === next.idx && prev.limit === next.limit ? prev : next;
  });
  const [idxs, currentHistory] = createGuardedResource<IpcSource, IdxsForPcResponse>(
    source,
    (source, signal) => fetchIdxsForPc(source.pc, source.idx, source.limit, signal),
    (r, s) =>
      r.request_pc === s.pc &&
      r.request_cursor === s.idx &&
      r.request_limit === s.limit,
  );

  // before/after 各最多 5000 行，固定行高窗口渲染，避免整表挂载。
  const beforeList = createVirtualList(
    () => currentHistory()?.before.length ?? 0,
    TRACE_PC_ROW_HEIGHT,
  );
  const beforeWindowItems = createMemo(() => {
    const w = beforeList.window();
    return (currentHistory()?.before ?? []).slice(w.start, w.end);
  });
  const afterList = createVirtualList(
    () => currentHistory()?.after.length ?? 0,
    TRACE_PC_ROW_HEIGHT,
  );
  const afterWindowItems = createMemo(() => {
    const w = afterList.window();
    return (currentHistory()?.after ?? []).slice(w.start, w.end);
  });

  return (
    <section class="panel">
      <h2>Trace for PC</h2>
      <Show when={!props.recordLoading && props.recordError}>
        <p class="err">load failed: {String(props.recordError)}</p>
      </Show>
      <Show when={!idxs.loading && idxs.error}>
        <p class="err">load failed: {String(idxs.error)}</p>
      </Show>
      <Show when={props.recordLoading || idxs.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={currentHistory()}>
        {(history) => (
          <>
            <p class="dim small">
              idx {props.idx} · <code>{currentRecord()!.pc}</code> · {currentRecord()!.asm}
            </p>
            <div class="tracepc-grid">
              <div>
                <h3>before</h3>
                <div class="vscroll tracepc-vscroll" ref={beforeList.ref} onScroll={beforeList.onScroll}>
                  <table class="tracepc-table">
                    <tbody class="vbody" style={{ height: `${beforeList.window().height}px` }}>
                      <For each={beforeWindowItems()}>
                        {(idx, i) => (
                          <tr
                            class="vrow"
                            style={{ top: `${(beforeList.window().start + i()) * TRACE_PC_ROW_HEIGHT}px` }}
                            onClick={() => props.onSelect(idx)}
                          >
                            <td>{idx}</td>
                            <td>-{props.idx - idx}</td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </div>
                <p class="dim small">
                  total {history().total_before}
                  {history().before_capped ? " · partial result" : ""}
                </p>
              </div>
              <div>
                <h3>after</h3>
                <div class="vscroll tracepc-vscroll" ref={afterList.ref} onScroll={afterList.onScroll}>
                  <table class="tracepc-table">
                    <tbody class="vbody" style={{ height: `${afterList.window().height}px` }}>
                      <For each={afterWindowItems()}>
                        {(idx, i) => (
                          <tr
                            class="vrow"
                            style={{ top: `${(afterList.window().start + i()) * TRACE_PC_ROW_HEIGHT}px` }}
                            onClick={() => props.onSelect(idx)}
                          >
                            <td>{idx}</td>
                            <td>+{idx - props.idx}</td>
                          </tr>
                        )}
                      </For>
                    </tbody>
                  </table>
                </div>
                <p class="dim small">
                  total {history().total_after}
                  {history().after_capped ? " · partial result" : ""}
                </p>
              </div>
            </div>
            <Show when={history().before_capped || history().after_capped}>
              <div class="cap-notice" role="status">
                <span>
                  PC history shows at most {(history().request_limit ?? limit()).toLocaleString()} before and after rows near the cursor.
                </span>
                <Show
                  when={(history().request_limit ?? limit()) < MAX_TRACE_PC_LIMIT}
                  fallback={<span class="dim">UI/server cap is {MAX_TRACE_PC_LIMIT.toLocaleString()} rows per side.</span>}
                >
                  <button type="button" onClick={() => setLimit(MAX_TRACE_PC_LIMIT)}>
                    show {MAX_TRACE_PC_LIMIT.toLocaleString()}
                  </button>
                </Show>
              </div>
            </Show>
          </>
        )}
      </Show>
    </section>
  );
}
