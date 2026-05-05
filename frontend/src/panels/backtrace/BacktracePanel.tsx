import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js";

import { fetchBacktrace } from "~/api/client";
import { createGuardedResource } from "~/utils/resourceGuards";

interface BacktracePanelProps {
  idx: number;
  onSelect: (idx: number) => void;
  active: boolean;
}

const DEFAULT_BACKTRACE_LIMIT = 256;
const MAX_BACKTRACE_LIMIT = 2048;

export default function BacktracePanel(props: BacktracePanelProps) {
  const [queryIdx, setQueryIdx] = createSignal<number | undefined>();
  const [limit, setLimit] = createSignal(DEFAULT_BACKTRACE_LIMIT);
  let queryTimer: number | undefined;

  createEffect(() => {
    props.idx;
    setLimit(DEFAULT_BACKTRACE_LIMIT);
  });

  createEffect(() => {
    if (queryTimer !== undefined) {
      window.clearTimeout(queryTimer);
      queryTimer = undefined;
    }
    if (!props.active) {
      setQueryIdx(undefined);
      return;
    }
    const idx = props.idx;
    queryTimer = window.setTimeout(() => {
      queryTimer = undefined;
      setQueryIdx(idx);
    }, 80);
  });
  onCleanup(() => {
    if (queryTimer !== undefined) window.clearTimeout(queryTimer);
  });

  const source = createMemo((prev?: { idx: number; limit: number }) => {
    const idx = queryIdx();
    if (idx === undefined) return undefined;
    const next = { idx, limit: limit() };
    return prev && prev.idx === next.idx && prev.limit === next.limit ? prev : next;
  });
  const [resp, resourceResp] = createGuardedResource(
    source,
    (s) => fetchBacktrace(s.idx, s.limit),
    (r, s) => r.idx === s.idx && r.request_limit === s.limit,
  );
  const currentResp = createMemo(() => {
    const r = resourceResp();
    return r && r.idx === props.idx ? r : undefined;
  });

  return (
    <section class="panel">
      <h2>Backtrace</h2>
      <Show when={!resp.loading && resp.error}>
        <p class="err">load failed: {String(resp.error)}</p>
      </Show>
      <Show when={resp.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={currentResp()}>
        {(r) => (
          <>
            <p class="dim small">
              idx {r().idx} · depth {r().depth}
              <Show when={r().truncated}>
                {" "}· showing last {r().returned ?? r().stack.length}
              </Show>
            </p>
            <Show when={r().truncated}>
              <div class="cap-notice" role="status">
                <span>
                  Backtrace depth is {r().depth.toLocaleString()}; showing the last {(r().request_limit ?? limit()).toLocaleString()} frames.
                </span>
                <Show
                  when={(r().request_limit ?? limit()) < MAX_BACKTRACE_LIMIT}
                  fallback={<span class="dim">UI/server cap is {MAX_BACKTRACE_LIMIT.toLocaleString()} frames.</span>}
                >
                  <button type="button" onClick={() => setLimit(MAX_BACKTRACE_LIMIT)}>
                    show {MAX_BACKTRACE_LIMIT.toLocaleString()}
                  </button>
                </Show>
              </div>
            </Show>
            <table class="bt-table">
              <thead>
                <tr>
                  <th>frame</th>
                  <th>call idx</th>
                  <th>call pc</th>
                  <th>callee</th>
                  <th>fn</th>
                </tr>
              </thead>
              <tbody>
                <For each={r().stack}>
                  {(frame, i) => (
                    <tr onClick={() => props.onSelect(frame.call_site_idx)}>
                      <td>{r().depth - r().stack.length + i()}</td>
                      <td>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            props.onSelect(frame.call_site_idx);
                          }}
                        >
                          {frame.call_site_idx}
                        </button>
                      </td>
                      <td><code>{frame.call_pc_fmt ?? frame.call_pc}</code></td>
                      <td><code>{frame.callee_pc_fmt ?? frame.callee_pc ?? ""}</code></td>
                      <td>{frame.fn ?? ""}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </>
        )}
      </Show>
    </section>
  );
}
