import { For, Show } from "solid-js";

import type { UiTaskEntry } from "../utils/taskCenter";

interface TaskCenterProps {
  activeCount: number;
  tasks: UiTaskEntry[];
  onClose: () => void;
}

export default function TaskCenter(props: TaskCenterProps) {
  return (
    <div class="task-center">
      <div class="task-center-head">
        <b>Task Center</b>
        <span class="dim small">{props.activeCount} running · {props.tasks.length} recent</span>
        <button type="button" onClick={props.onClose}>close</button>
      </div>
      <For each={props.tasks.slice(0, 12)}>
        {(task) => {
          const elapsed = Math.max(0, Math.round((task.endedAt ?? performance.now()) - task.startedAt));
          return (
            <div class="task-row" classList={{ running: task.status === "running", error: task.status === "error", partial: task.status === "partial" }}>
              <span class="task-status">{task.status}</span>
              <span class="task-main">
                <b>{task.surface}</b>
                <span>{task.label}</span>
                <Show when={task.detail}>
                  <small>{task.detail}</small>
                </Show>
              </span>
              <code>{elapsed}ms</code>
            </div>
          );
        }}
      </For>
    </div>
  );
}
