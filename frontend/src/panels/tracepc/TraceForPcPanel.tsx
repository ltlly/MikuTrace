import { createMemo, createResource, For, Show } from "solid-js";

import { fetchIdxsForPc, fetchRecord } from "~/api/client";
import type { IdxsForPcResponse } from "~/api/types";

interface TraceForPcPanelProps {
  idx: number;
  onSelect: (idx: number) => void;
  active: boolean;
}

interface IpcSource {
  pc: string;
  idx: number;
}

export default function TraceForPcPanel(props: TraceForPcPanelProps) {
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
    const next = { pc: r.pc, idx: props.idx };
    return prev && prev.pc === next.pc && prev.idx === next.idx ? prev : next;
  });
  const [idxs] = createResource<IdxsForPcResponse, IpcSource | undefined>(
    source,
    (source) => {
      if (!source) throw new Error("missing selected record");
      return fetchIdxsForPc(source.pc, source.idx, 20);
    },
  );
  const currentHistory = createMemo(() => {
    const s = source();
    const r = idxs();
    if (!s || !r) return undefined;
    return r.request_pc === s.pc &&
      r.request_cursor === s.idx &&
      r.request_limit === 20
      ? r
      : undefined;
  });

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
                  {history().before_capped ? " · capped" : ""}
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
                  {history().after_capped ? " · capped" : ""}
                </p>
              </div>
            </div>
          </>
        )}
      </Show>
    </section>
  );
}
