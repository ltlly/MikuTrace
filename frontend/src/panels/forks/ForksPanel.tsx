import { createMemo, createResource, createSignal, For, Show } from "solid-js";

import { fetchForkEvents } from "~/api/client";

const STATUS_OPTIONS = ["", "success", "failed_ptrace_conflict", "not_attempted"];

function statusOf(event: Record<string, unknown>): string {
  const status = event.attach_status;
  return typeof status === "string" ? status : "";
}

function pidOf(event: Record<string, unknown>): string {
  const pid = event.child_pid;
  return typeof pid === "number" ? String(pid) : "";
}

export default function ForksPanel() {
  const [status, setStatus] = createSignal("");
  const [resp] = createResource(status, fetchForkEvents);
  const failedCount = createMemo(
    () => resp()?.events.filter((e) => statusOf(e).startsWith("failed")).length ?? 0,
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
      <Show when={resp.error}>
        <p class="err">load failed: {String(resp.error)}</p>
      </Show>
      <Show when={resp.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={resp()}>
        {(r) => (
          <>
            <p class="dim small">{r().count} event{r().count === 1 ? "" : "s"}</p>
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
