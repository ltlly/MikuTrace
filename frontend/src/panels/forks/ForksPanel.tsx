import { createMemo, createSignal, For, Show } from "solid-js";

import { fetchForkEvents } from "~/api/client";
import { createGuardedResource } from "~/utils/resourceGuards";

const STATUS_OPTIONS = ["", "success", "failed_ptrace_conflict", "not_attempted"];
const DEFAULT_FORK_LIMIT = 1000;
const MAX_FORK_LIMIT = 5000;

function statusOf(event: Record<string, unknown>): string {
  const status = event.attach_status;
  return typeof status === "string" ? status : "";
}

function pidOf(event: Record<string, unknown>): string {
  const pid = event.child_pid;
  return typeof pid === "number" ? String(pid) : "";
}

interface ForksPanelProps {
  active: boolean;
}

export default function ForksPanel(props: ForksPanelProps) {
  const [status, setStatus] = createSignal("");
  const [limit, setLimit] = createSignal(DEFAULT_FORK_LIMIT);
  const source = createMemo((prev?: { status: string; limit: number }) => {
    if (!props.active) return undefined;
    const next = { status: status(), limit: limit() };
    return prev && prev.status === next.status && prev.limit === next.limit ? prev : next;
  });
  const [resp, currentResp] = createGuardedResource(
    source,
    (s) => fetchForkEvents(s.status, s.limit),
    (r, s) => r.request_status === s.status && r.request_limit === s.limit,
  );
  const failedCount = createMemo(
    () => currentResp()?.events.filter((e) => statusOf(e).startsWith("failed")).length ?? 0,
  );

  return (
    <section class="panel">
      <h2>Forks</h2>
      <div class="fork-controls">
        <label>
          status
          <select value={status()} onChange={(e) => setStatus(e.currentTarget.value)}>
            <For each={STATUS_OPTIONS}>
              {(value) => <option value={value}>{value || "all"}</option>}
            </For>
          </select>
        </label>
        <Show when={failedCount() > 0}>
          <span class="fork-warn">{failedCount()} failed</span>
        </Show>
      </div>
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
              {r().returned ?? r().events.length}/{r().count} event{r().count === 1 ? "" : "s"}
              {r().truncated ? " · partial result" : ""}
            </p>
            <Show when={r().truncated}>
              <div class="cap-notice" role="status">
                <span>
                  Fork events stopped at {(r().request_limit ?? limit()).toLocaleString()} row cap.
                </span>
                <Show
                  when={(r().request_limit ?? limit()) < MAX_FORK_LIMIT}
                  fallback={<span class="dim">UI/server cap is {MAX_FORK_LIMIT.toLocaleString()} rows; filter by status.</span>}
                >
                  <button type="button" onClick={() => setLimit(MAX_FORK_LIMIT)}>
                    show {MAX_FORK_LIMIT.toLocaleString()}
                  </button>
                </Show>
              </div>
            </Show>
            <table class="fork-table">
              <thead>
                <tr>
                  <th>pid</th>
                  <th>status</th>
                  <th>fork-like</th>
                  <th>raw</th>
                </tr>
              </thead>
              <tbody>
                <For each={r().events}>
                  {(event) => (
                    <tr class={statusOf(event).startsWith("failed") ? "failed" : ""}>
                      <td>{pidOf(event)}</td>
                      <td>{statusOf(event)}</td>
                      <td>{event.is_fork_like === true ? "yes" : event.is_fork_like === false ? "no" : ""}</td>
                      <td><code>{JSON.stringify(event)}</code></td>
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
