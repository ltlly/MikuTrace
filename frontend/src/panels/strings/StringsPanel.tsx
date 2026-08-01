import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js";

import { fetchIdxsTouchingRange, fetchStrings } from "~/api/client";
import type { StringEntry } from "~/api/types";
import { useGuarded } from "~/utils/guarded";
import { createGuardedResource } from "~/utils/resourceGuards";
import type { StringProvenanceRequest } from "./StringProvenancePanel";

interface StringsPanelProps {
  idx: number;
  onSelect: (idx: number) => void;
  onShowProvenance: (req: Omit<StringProvenanceRequest, "token">) => void;
  active: boolean;
}

interface StringsSource {
  minLen: number;
  q: string;
  limit: number;
  cursor: number;
  retry: number;
}

const STRINGS_RETRY_MS = 500;
const MAX_STRING_LIMIT = 5000;

export default function StringsPanel(props: StringsPanelProps) {
  const [minLen, setMinLen] = createSignal(4);
  const [limit, setLimit] = createSignal(500);
  const [atCursor, setAtCursor] = createSignal(false);
  const [query, setQuery] = createSignal("");
  const [jumpErr, setJumpErr] = createSignal("");
  const [retry, setRetry] = createSignal(0);
  let singleClickTimer: number | undefined;
  const jump = useGuarded();
  const source = createMemo<StringsSource | undefined>((prev) => {
    if (!props.active) return undefined;
    const next = {
      minLen: minLen(),
      q: query(),
      limit: Math.max(1, Math.min(MAX_STRING_LIMIT, limit())),
      cursor: atCursor() ? props.idx : -1,
      retry: retry(),
    };
    return prev &&
      prev.minLen === next.minLen &&
      prev.q === next.q &&
      prev.limit === next.limit &&
      prev.cursor === next.cursor &&
      prev.retry === next.retry
      ? prev
      : next;
  });
  const [resp, currentResp] = createGuardedResource<StringsSource, Awaited<ReturnType<typeof fetchStrings>>>(
    source,
    ({ minLen, q, limit, cursor }, signal) => fetchStrings(minLen, q, limit, cursor, signal),
    (r, s) =>
      r.request_min_len === s.minLen &&
      r.request_q === s.q &&
      r.request_limit === s.limit &&
      r.request_cursor === s.cursor,
  );
  const readyResp = createMemo(() => {
    const r = currentResp();
    return r?.status === "ready" ? r : undefined;
  });

  createEffect(() => {
    if (!props.active || resp.loading || currentResp()?.status !== "loading") return;
    const timer = window.setTimeout(() => setRetry((n) => n + 1), STRINGS_RETRY_MS);
    onCleanup(() => window.clearTimeout(timer));
  });

  function clearSingleClickTimer() {
    if (singleClickTimer !== undefined) {
      window.clearTimeout(singleClickTimer);
      singleClickTimer = undefined;
    }
  }

  function cancelJump() {
    jump.cancel();
  }

  onCleanup(() => {
    clearSingleClickTimer();
    cancelJump();
  });

  async function jumpString(s: StringEntry) {
    cancelJump();
    const h = jump.begin();
    const abort = h.abort;
    setJumpErr("");
    try {
      const hits = await fetchIdxsTouchingRange(s.addr, Math.max(1, s.len), 0, 80, abort.signal);
      if (!jump.isCurrent(h)) return;
      const target =
        hits.writers_after[0] ??
        hits.readers_after[0] ??
        hits.writers_before[0] ??
        hits.readers_before[0];
      if (target === undefined) {
        setJumpErr(`${s.addr} 没有关联的读写 trace`);
        return;
      }
      props.onSelect(target);
    } catch (err) {
      if (!jump.isCurrent(h)) return;
      setJumpErr(String(err));
    } finally {
      jump.release(h);
    }
  }

  function scheduleJumpString(s: StringEntry) {
    clearSingleClickTimer();
    singleClickTimer = window.setTimeout(() => {
      singleClickTimer = undefined;
      void jumpString(s);
    }, 180);
  }

  function showProvenance(s: StringEntry) {
    clearSingleClickTimer();
    cancelJump();
    setJumpErr("");
    props.onShowProvenance({
      addr: s.addr,
      len: Math.max(1, Math.min(512, s.len + 1)),
      text: s.str,
    });
  }

  return (
    <section class="panel">
      <h2>Strings</h2>
      <div class="strings-controls">
        <label>
          min len
          <input
            type="number"
            min="3"
            max="64"
            value={minLen()}
            onInput={(e) => setMinLen(Number(e.currentTarget.value) || 4)}
          />
        </label>
        <label>
          filter
          <input
            type="text"
            value={query()}
            placeholder="substring…"
            onInput={(e) => setQuery(e.currentTarget.value)}
          />
        </label>
        <label>
          limit
          <input
            type="number"
            min="1"
            max={MAX_STRING_LIMIT}
            value={limit()}
            onInput={(e) => setLimit(Number(e.currentTarget.value) || 500)}
          />
        </label>
        <label>
          <input
            type="checkbox"
            checked={atCursor()}
            onChange={(e) => setAtCursor(e.currentTarget.checked)}
          />
          {" "}at cursor
        </label>
      </div>
      <Show when={!resp.loading && resp.error}>
        <p class="err">load failed: {String(resp.error)}</p>
      </Show>
      <Show when={jumpErr()}>
        <p class="err">{jumpErr()}</p>
      </Show>
      <Show when={resp.loading || currentResp()?.status === "loading"}>
        <p class="dim">memory index loading…</p>
      </Show>
      <Show when={readyResp()}>
        {(r) => (
          <>
            <p class="dim small">
              {r().returned ?? r().strings.length}/{r().count} string{r().count === 1 ? "" : "s"}
              {r().truncated ? " · partial result" : ""}
              <Show when={r().cursor >= 0}>
                {" "}@ cursor={r().cursor}
              </Show>
            </p>
            <Show when={r().truncated}>
              <div class="cap-notice" role="status">
                <span>
                  String list stopped at {(r().request_limit ?? limit()).toLocaleString()} row cap; more matches may exist.
                </span>
                <Show
                  when={(r().request_limit ?? limit()) < MAX_STRING_LIMIT}
                  fallback={<span class="dim">UI/server cap is {MAX_STRING_LIMIT.toLocaleString()} rows; narrow the filter or enable at-cursor.</span>}
                >
                  <button type="button" onClick={() => setLimit(MAX_STRING_LIMIT)}>
                    show {MAX_STRING_LIMIT.toLocaleString()}
                  </button>
                </Show>
              </div>
            </Show>
            <ul class="strings-list">
              <For each={r().strings}>
                {(s) => (
                  <li
                    title="单击跳到第一次写入/触碰；双击查看逐字符 provenance"
                    onClick={(e) => {
                      if (e.detail === 1) scheduleJumpString(s);
                    }}
                    onDblClick={(e) => {
                      e.preventDefault();
                      showProvenance(s);
                    }}
                  >
                    <span class="dim small">{s.addr}</span>
                    <span class="dim small">{s.len}</span>
                    <span class="str">{s.str}</span>
                  </li>
                )}
              </For>
            </ul>
          </>
        )}
      </Show>
    </section>
  );
}
