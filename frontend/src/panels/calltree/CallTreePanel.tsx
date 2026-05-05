import { createMemo, createResource, createSignal, For, onCleanup, Show } from "solid-js";

import { fetchCallTree } from "~/api/client";
import type { CallNode } from "~/api/types";

const DEFAULT_DEPTH = 10;
const MIN_DEPTH = 1;
const MAX_DEPTH = 50;

interface CallTreePanelProps {
  currentIdx?: number;
  onSelect?: (idx: number) => void;
  active: boolean;
}

function keyOf(node: CallNode): string {
  return `${node.depth}:${node.enter_idx}:${node.exit_idx}:${node.fn ?? "?"}`;
}

function containsIdx(node: CallNode, idx: number): boolean {
  return idx >= node.enter_idx && idx <= node.exit_idx;
}

function findPath(node: CallNode, idx: number, path: CallNode[] = []): CallNode[] | null {
  if (!containsIdx(node, idx)) return null;
  const nextPath = [...path, node];
  for (const child of node.children ?? []) {
    const found = findPath(child, idx, nextPath);
    if (found) return found;
  }
  return nextPath;
}

interface RowProps {
  node: CallNode;
  openKeys: () => Set<string>;
  setOpenKeys: (keys: Set<string>) => void;
  locatedKey: () => string;
  currentIdx?: number;
  onSelect?: (idx: number) => void;
}

function CallTreeRow(props: RowProps) {
  const hasChildren = () =>
    (props.node.children?.length ?? 0) > 0 ||
    (props.node.truncated_children ?? 0) > 0;
  const nodeKey = () => keyOf(props.node);
  const open = () => props.openKeys().has(nodeKey()) || props.node.depth === 0;
  const label = () => props.node.fn ?? "?";
  const indent = () => `${props.node.depth * 16}px`;
  const isLocated = () => props.locatedKey() === nodeKey();
  const containsCurrent = () =>
    props.currentIdx !== undefined && containsIdx(props.node, props.currentIdx);

  function toggle(e: MouseEvent) {
    e.stopPropagation();
    const next = new Set(props.openKeys());
    if (next.has(nodeKey())) next.delete(nodeKey());
    else next.add(nodeKey());
    props.setOpenKeys(next);
  }

  return (
    <div class="ct-row" data-ct-key={nodeKey()}>
      <div
        class="ct-line"
        classList={{ located: isLocated(), contains: containsCurrent() && !isLocated() }}
        style={{ "padding-left": indent() }}
        onClick={() => props.onSelect?.(props.node.enter_idx)}
      >
        <button class="ct-toggle" type="button" onClick={toggle}>
          {hasChildren() ? (open() ? "▼" : "▶") : "·"}
        </button>
        <span class="ct-fn" title={label()}>
          {label()}
        </span>
        <span class="ct-idx dim small">
          [{props.node.enter_idx}..{props.node.exit_idx}]
        </span>
        <Show when={(props.node.truncated_children ?? 0) > 0}>
          <span class="ct-trunc">+{props.node.truncated_children} truncated</span>
        </Show>
      </div>
      <Show when={open() && (props.node.children?.length ?? 0) > 0}>
        <For each={props.node.children}>
          {(child) => (
            <CallTreeRow
              node={child}
              openKeys={props.openKeys}
              setOpenKeys={props.setOpenKeys}
              locatedKey={props.locatedKey}
              currentIdx={props.currentIdx}
              onSelect={props.onSelect}
            />
          )}
        </For>
      </Show>
    </div>
  );
}

export default function CallTreePanel(props: CallTreePanelProps) {
  const [depth, setDepth] = createSignal(DEFAULT_DEPTH);
  const [resp] = createResource(
    () => (props.active ? depth() : undefined),
    (maxDepth) => fetchCallTree(maxDepth),
  );
  const currentResp = createMemo(() => {
    const r = resp();
    if (!r || !props.active) return undefined;
    return r.request_max_depth === depth() ? r : undefined;
  });
  const [openKeys, setOpenKeys] = createSignal<Set<string>>(new Set());
  const [locatedKey, setLocatedKey] = createSignal("");
  let locateSeq = 0;
  let locateRaf: number | undefined;

  function cancelLocateFrame() {
    locateSeq += 1;
    if (locateRaf !== undefined) {
      window.cancelAnimationFrame(locateRaf);
      locateRaf = undefined;
    }
  }

  onCleanup(() => cancelLocateFrame());

  function locateCurrent() {
    cancelLocateFrame();
    const tree = currentResp()?.tree;
    if (!tree || props.currentIdx === undefined) return;
    const path = findPath(tree, props.currentIdx);
    if (!path?.length) return;
    const seq = ++locateSeq;
    const next = new Set(openKeys());
    for (const node of path) next.add(keyOf(node));
    const key = keyOf(path[path.length - 1]);
    setOpenKeys(next);
    setLocatedKey(key);
    locateRaf = window.requestAnimationFrame(() => {
      locateRaf = undefined;
      if (seq !== locateSeq || locatedKey() !== key) return;
      document.querySelector(`[data-ct-key="${CSS.escape(key)}"]`)?.scrollIntoView({
        block: "center",
        inline: "nearest",
      });
    });
  }

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
        <button type="button" onClick={locateCurrent} disabled={props.currentIdx === undefined}>
          locate current fn
        </button>
      </div>
      <Show when={!resp.loading && resp.error}>
        <p class="err">load failed: {String(resp.error)}</p>
      </Show>
      <Show when={resp.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={currentResp()}>
        {(r) => (
          <div class="ct-wrap">
            <CallTreeRow
              node={r().tree}
              openKeys={openKeys}
              setOpenKeys={setOpenKeys}
              locatedKey={locatedKey}
              currentIdx={props.currentIdx}
              onSelect={props.onSelect}
            />
          </div>
        )}
      </Show>
    </section>
  );
}
