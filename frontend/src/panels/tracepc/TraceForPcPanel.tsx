import { createEffect, createMemo, createResource, createSignal, For, Show } from "solid-js";

import { fetchIdxsForPc, fetchRecord } from "~/api/client";
import type { IdxsForPcResponse } from "~/api/types";
import { createGuardedResource } from "~/utils/resourceGuards";

interface TraceForPcPanelProps {
  idx: number;
  onSelect: (idx: number) => void;
  active: boolean;
}

interface IpcSource {
  pc: string;
  idx: number;
  limit: number;
}

const DEFAULT_TRACE_PC_LIMIT = 20;
const MAX_TRACE_PC_LIMIT = 5000;

export default function TraceForPcPanel(props: TraceForPcPanelProps) {
  const [limit, setLimit] = createSignal(DEFAULT_TRACE_PC_LIMIT);
  createEffect(() => {
    props.idx;
    setLimit(DEFAULT_TRACE_PC_LIMIT);
  });

  const [record] = createResource(
    () => (props.active ? props.idx : undefined),
    (idx) => fetchRecord(idx),
  );
  const currentRecord = createMemo(() => {
    const r = record();
    return r && r.idx === props.idx ? r : undefined;
  });
  const source = createMemo<IpcSource | undefined>((prev) => {
    if (!props.active) return undefined;
    const r = currentRecord();
    if (!r) return undefined;
    const next = { pc: r.pc, idx: props.idx, limit: limit() };
    return prev && prev.pc === next.pc && prev.idx === next.idx && prev.limit === next.limit ? prev : next;
  });
  const [idxs, currentHistory] = createGuardedResource<IpcSource, IdxsForPcResponse>(
    source,
    (source) => fetchIdxsForPc(source.pc, source.idx, source.limit),
    (r, s) =>
      r.request_pc === s.pc &&
      r.request_cursor === s.idx &&
      r.request_limit === s.limit,
  );

  return (
    <section class="panel">
      <h2>Trace for PC</h2>
      <Show when={!record.loading && record.error}>
        <p class="err">record load failed: {String(record.error)}</p>
      </Show>
      <Show when={!idxs.loading && idxs.error}>
        <p class="err">pc history failed: {String(idxs.error)}</p>
      </Show>
      <Show when={record.loading || idxs.loading}>
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
                <table class="tracepc-table">
                  <tbody>
                    <For each={history().before}>
                      {(idx) => (
                        <tr onClick={() => props.onSelect(idx)}>
                          <td>{idx}</td>
                          <td>-{props.idx - idx}</td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
                <p class="dim small">
                  total {history().total_before}
                  {history().before_capped ? " · partial result" : ""}
                </p>
              </div>
              <div>
                <h3>after</h3>
                <table class="tracepc-table">
                  <tbody>
                    <For each={history().after}>
                      {(idx) => (
                        <tr onClick={() => props.onSelect(idx)}>
                          <td>{idx}</td>
                          <td>+{idx - props.idx}</td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
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
