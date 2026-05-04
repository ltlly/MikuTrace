import { Component, createResource, createSignal, For, Show } from "solid-js";

import { fetchCallTree } from "~/api/client";
import type { CallNode } from "~/api/types";

const DEFAULT_DEPTH = 10;
const MIN_DEPTH = 1;
const MAX_DEPTH = 50;

const CallTreeRow: Component<{ node: CallNode; defaultOpen: boolean }> = (
  props,
) => {
  const [open, setOpen] = createSignal(props.defaultOpen);
  const hasChildren = () =>
    (props.node.children?.length ?? 0) > 0 ||
    (props.node.truncated_children ?? 0) > 0;
  const label = () => props.node.fn ?? "?";
  const indent = () => `${props.node.depth * 16}px`;

  return (
    <div class="ct-row">
      <div
        class="ct-line"
        style={{ "padding-left": indent() }}
        onClick={() => setOpen((o) => !o)}
      >
        <span class="ct-toggle">
          {hasChildren() ? (open() ? "▼" : "▶") : "·"}
        </span>
        <span class="ct-fn">{label()}</span>
        <span class="ct-idx dim small">
          [{props.node.enter_idx}..{props.node.exit_idx}]
        </span>
        <Show when={(props.node.truncated_children ?? 0) > 0}>
          <span class="ct-trunc">
            +{props.node.truncated_children} truncated
          </span>
        </Show>
      </div>
      <Show when={open() && (props.node.children?.length ?? 0) > 0}>
        <For each={props.node.children}>
          {(child) => <CallTreeRow node={child} defaultOpen={false} />}
        </For>
      </Show>
    </div>
  );
};

export default function CallTreePanel() {
  const [depth, setDepth] = createSignal(DEFAULT_DEPTH);
  const [resp] = createResource(depth, fetchCallTree);

  return (
    <section class="panel">
      <h2>Call tree</h2>
      <div class="ct-controls">
        <label>
          max depth
          <input
            type="range"
            min={MIN_DEPTH}
            max={MAX_DEPTH}
            value={depth()}
            onInput={(e) => setDepth(parseInt(e.currentTarget.value, 10))}
          />
          <span class="dim small">{depth()}</span>
        </label>
      </div>
      <Show when={resp.error}>
        <p class="err">load failed: {String(resp.error)}</p>
      </Show>
      <Show when={resp.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={resp()}>
        {(r) => (
          <div class="ct-wrap">
            <CallTreeRow node={r().tree} defaultOpen={true} />
          </div>
        )}
      </Show>
    </section>
  );
}
