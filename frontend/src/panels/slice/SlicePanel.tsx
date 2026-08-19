import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js";

import {
  fetchBfsSlice,
  fetchForwardDepTree,
  type BfsSliceResponse,
  type DepNode,
  type ForwardDepTreeResponse,
} from "~/api/client";
import { createGuardedResource } from "~/utils/resourceGuards";
import { createVirtualList } from "~/utils/virtualList";

type SliceResponse = BfsSliceResponse | ForwardDepTreeResponse;

interface SlicePanelProps {
  idx: number;
  reg: string;
  onSelect: (idx: number) => void;
  active: boolean;
}

type Direction = "backward" | "forward";
type Mode = "union" | "intersection";

interface SliceQuery {
  direction: Direction;
  primaryIdx: number;
  secondaryIdx: number | null;
  reg: string | null;
  dataOnly: boolean;
  mode: Mode;
  limit: number;
  depth: number;
  token: number;
}

const DEFAULT_LIMIT_BACKWARD = 1_000;
const DEFAULT_LIMIT_FORWARD = 200;
const DEFAULT_DEPTH = 8;
const MAX_BACKWARD_LIMIT = 200_000;
const MAX_FORWARD_LIMIT = 2_000;
/// Records 面板 j/k 每步都会换 props.idx；防抖期内不重发 BFS 查询。
const IDX_DEBOUNCE_MS = 80;
/// 反向切片行高（slice-table 虚拟行）。
const SLICE_ROW_HEIGHT = 20;

export default function SlicePanel(props: SlicePanelProps) {
  const [direction, setDirection] = createSignal<Direction>("backward");
  const [secondaryRaw, setSecondaryRaw] = createSignal<string>("");
  const [mode, setMode] = createSignal<Mode>("union");
  const [dataOnly, setDataOnly] = createSignal(false);
  const [limitBackward, setLimitBackward] = createSignal(DEFAULT_LIMIT_BACKWARD);
  const [limitForward, setLimitForward] = createSignal(DEFAULT_LIMIT_FORWARD);
  const [depth, setDepth] = createSignal(DEFAULT_DEPTH);
  const [token, setToken] = createSignal(0);
  const [debouncedIdx, setDebouncedIdx] = createSignal<number | undefined>();
  let idxTimer: number | undefined;

  // 光标防抖：j/k 连按时 80ms 内只保留最后一个 idx，避免每次按键都
  // 触发一次最多 200k 节点的 BFS（参照 BacktracePanel 的 timer 模式）。
  createEffect(() => {
    if (idxTimer !== undefined) {
      window.clearTimeout(idxTimer);
      idxTimer = undefined;
    }
    if (!props.active) {
      setDebouncedIdx(undefined);
      return;
    }
    const idx = props.idx;
    idxTimer = window.setTimeout(() => {
      idxTimer = undefined;
      setDebouncedIdx(idx);
    }, IDX_DEBOUNCE_MS);
  });
  onCleanup(() => {
    if (idxTimer !== undefined) window.clearTimeout(idxTimer);
  });

  const secondary = createMemo<number | null>(() => {
    const raw = secondaryRaw().trim();
    if (!raw) return null;
    const n = Number.parseInt(raw, 10);
    return Number.isFinite(n) && n >= 0 ? n : null;
  });

  const query = createMemo<SliceQuery | undefined>((prev?: SliceQuery) => {
    const primaryIdx = debouncedIdx();
    if (!props.active || primaryIdx === undefined || primaryIdx < 0) return undefined;
    const next: SliceQuery = {
      direction: direction(),
      primaryIdx,
      secondaryIdx: secondary(),
      reg: props.reg || null,
      dataOnly: dataOnly(),
      mode: mode(),
      limit: direction() === "backward" ? limitBackward() : limitForward(),
      depth: depth(),
      token: token(),
    };
    return prev &&
      prev.direction === next.direction &&
      prev.primaryIdx === next.primaryIdx &&
      prev.secondaryIdx === next.secondaryIdx &&
      prev.reg === next.reg &&
      prev.dataOnly === next.dataOnly &&
      prev.mode === next.mode &&
      prev.limit === next.limit &&
      prev.depth === next.depth &&
      prev.token === next.token
      ? prev
      : next;
  });

  type GuardedShape = { kind: Direction; token: number; primaryIdx: number; data: SliceResponse };
  const [, response] = createGuardedResource<SliceQuery, GuardedShape>(
    query,
    async (q, signal) => {
      if (q.direction === "backward") {
        const idxs =
          q.secondaryIdx !== null && q.secondaryIdx !== q.primaryIdx
            ? [q.primaryIdx, q.secondaryIdx]
            : undefined;
        const data = await fetchBfsSlice({
          idx: idxs ? undefined : q.primaryIdx,
          idxs,
          dataOnly: q.dataOnly,
          limit: q.limit,
          mode: q.mode,
          signal,
        });
        return { kind: "backward", token: q.token, primaryIdx: q.primaryIdx, data };
      }
      const data = await fetchForwardDepTree({
        idx: q.primaryIdx,
        depth: q.depth,
        limit: q.limit,
        dataOnly: q.dataOnly,
        signal,
      });
      return { kind: "forward", token: q.token, primaryIdx: q.primaryIdx, data };
    },
    (value, source) =>
      value.kind === source.direction &&
      value.token === source.token &&
      value.primaryIdx === source.primaryIdx,
  );

  function bumpLimitToCap() {
    if (direction() === "backward") setLimitBackward(MAX_BACKWARD_LIMIT);
    else setLimitForward(MAX_FORWARD_LIMIT);
    setToken((t) => t + 1);
  }

  return (
    <section class="panel slice-panel">
      <h2>Slice</h2>
      <div class="slice-controls">
        <div class="slice-direction">
          <label>
            <input
              type="radio"
              name="slice-dir"
              checked={direction() === "backward"}
              onChange={() => setDirection("backward")}
            />{" "}
            backward (BFS, dep CSR)
          </label>
          <label>
            <input
              type="radio"
              name="slice-dir"
              checked={direction() === "forward"}
              onChange={() => setDirection("forward")}
            />{" "}
            forward (def→use DAG)
          </label>
        </div>
        <div class="slice-row">
          <label class="dim small">
            seed idx
            <input
              type="number"
              min="0"
              value={props.idx}
              readOnly
              title="follows the global cursor"
            />
          </label>
          <Show when={direction() === "backward"}>
            <label class="dim small">
              second seed (optional)
              <input
                type="number"
                min="0"
                placeholder="e.g. 1234"
                value={secondaryRaw()}
                onInput={(e) => setSecondaryRaw(e.currentTarget.value)}
              />
            </label>
            <label class="dim small">
              mode
              <select value={mode()} onChange={(e) => setMode(e.currentTarget.value as Mode)}>
                <option value="union">union</option>
                <option value="intersection">intersection</option>
              </select>
            </label>
          </Show>
          <Show when={direction() === "forward"}>
            <label class="dim small">
              max depth
              <input
                type="number"
                min="0"
                max="64"
                value={depth()}
                onInput={(e) => setDepth(Number(e.currentTarget.value) || DEFAULT_DEPTH)}
              />
            </label>
          </Show>
        </div>
        <div class="slice-row">
          <label class="dim small">
            limit
            <input
              type="number"
              min="1"
              value={direction() === "backward" ? limitBackward() : limitForward()}
              onInput={(e) => {
                const n = Number(e.currentTarget.value) || 100;
                if (direction() === "backward") setLimitBackward(n);
                else setLimitForward(n);
              }}
            />
          </label>
          <label class="dim small">
            <input
              type="checkbox"
              checked={dataOnly()}
              onChange={(e) => setDataOnly(e.currentTarget.checked)}
            />{" "}
            data only (drop control edges)
          </label>
          <button type="button" onClick={() => setToken((t) => t + 1)} title="refresh slice">
            run
          </button>
        </div>
        <p class="dim small">
          Backward = "this row's transitive ancestors via dep CSR" (BFS-discovery order from
          single seed, or idx-ascending after multi-seed AND/OR). Forward = "later rows that
          consumed the cursor's value" (def→use DAG, sorted by depth then idx). Filling a second
          seed and switching to <strong>intersection</strong> gives the common ancestors of two
          operations. <strong>Slice</strong> is the fast structural query — for full
          per-instruction propagation with through_mem / cross_fn use the Taint tab.
        </p>
      </div>
      <Show when={response()}>
        {(r) => (
          <Show
            when={r().kind === "backward"}
            fallback={
              <ForwardSliceView
                response={r().data as ForwardDepTreeResponse}
                onSelect={props.onSelect}
                onBumpLimit={bumpLimitToCap}
                maxLimit={MAX_FORWARD_LIMIT}
              />
            }
          >
            <BackwardSliceView
              response={r().data as BfsSliceResponse}
              onSelect={props.onSelect}
              onBumpLimit={bumpLimitToCap}
              maxLimit={MAX_BACKWARD_LIMIT}
            />
          </Show>
        )}
      </Show>
    </section>
  );
}

interface BackwardViewProps {
  response: BfsSliceResponse;
  onSelect: (idx: number) => void;
  onBumpLimit: () => void;
  maxLimit: number;
}

function BackwardSliceView(props: BackwardViewProps) {
  const r = props.response;
  const seeds = r.seeds ?? [r.seed];
  const stats = r.edge_stats;
  // slice 本体可达 200k idx；前 ROW_DETAIL_BUDGET 行带详情，其余只回 raw idx。
  // 全量渲染会生成 200k 个 <tr>，改为固定行高窗口渲染。
  const rawTail = r.rows_capped ? r.slice.slice(r.rows.length) : [];
  const totalRows = r.rows.length + rawTail.length;
  const list = createVirtualList(() => totalRows, SLICE_ROW_HEIGHT);
  const windowItems = createMemo<Array<DepNode | number>>(() => {
    const w = list.window();
    const out: Array<DepNode | number> = [];
    for (let pos = w.start; pos < w.end; pos += 1) {
      out.push(pos < r.rows.length ? r.rows[pos] : rawTail[pos - r.rows.length]);
    }
    return out;
  });
  return (
    <div class="slice-backward">
      <p class="dim small">
        {r.slice_count.toLocaleString()} rows · {seeds.length} seed
        {seeds.length === 1 ? "" : "s"} · mode {r.mode}
        {r.truncated ? ` · truncated at ${r.node_limit.toLocaleString()}` : ""}
      </p>
      <p class="dim small" title="reg=register def/use; addr=address-bus dep; mem=stored byte; control=branch">
        edges in slice — reg {stats.reg} · addr {stats.address} · mem {stats.mem} · ctrl{" "}
        {stats.control} · total {stats.total}
      </p>
      <Show when={r.truncated}>
        <div class="cap-notice" role="status">
          <span>
            Slice stopped at {r.node_limit.toLocaleString()} rows.
          </span>
          <Show
            when={r.node_limit < props.maxLimit}
            fallback={<span class="dim">UI/server cap is {props.maxLimit.toLocaleString()} rows.</span>}
          >
            <button type="button" onClick={props.onBumpLimit}>
              show {props.maxLimit.toLocaleString()}
            </button>
          </Show>
        </div>
      </Show>
      <Show when={seeds.some((s) => s.note)}>
        <ul class="slice-seed-notes">
          <For each={seeds.filter((s) => s.note)}>
            {(s) => (
              <li class="dim small">
                seed {s.kind} {s.idx ?? s.reg ?? s.addr ?? ""}: {s.note}
              </li>
            )}
          </For>
        </ul>
      </Show>
      <Show when={r.rows_capped}>
        <p class="dim small">
          row enrichment capped at {r.rows.length.toLocaleString()} of{" "}
          {r.slice.length.toLocaleString()} idx — extra rows show as raw idx only
        </p>
      </Show>
      <div class="vscroll slice-vscroll" ref={list.ref} onScroll={list.onScroll}>
        <table class="slice-table slice-vtable">
          <thead>
            <tr>
              <th>idx</th>
              <th>pc</th>
              <th>fn</th>
              <th>asm</th>
            </tr>
          </thead>
          <tbody class="vbody" style={{ height: `${list.window().height}px` }}>
            <For each={windowItems()}>
              {(item, i) => {
                const row = typeof item === "number" ? null : item;
                const idx = typeof item === "number" ? item : item.idx;
                const pos = () => list.window().start + i();
                return (
                  <tr
                    class="vrow"
                    classList={{ dim: !row }}
                    style={{ top: `${pos() * SLICE_ROW_HEIGHT}px` }}
                    onClick={() => props.onSelect(idx)}
                  >
                    <td>{idx}</td>
                    {row ? (
                      <>
                        <td>
                          <code>{row.pc}</code>
                        </td>
                        <td>{row.func ?? ""}</td>
                        <td>
                          <code>{row.asm}</code>
                        </td>
                      </>
                    ) : (
                      <td colSpan={3} class="dim slice-tail-note">
                        (no detail past row cap)
                      </td>
                    )}
                  </tr>
                );
              }}
            </For>
          </tbody>
        </table>
      </div>
      <Show when={r.slice.length === 0}>
        <p class="dim small">empty slice — try a different seed or disable data-only</p>
      </Show>
    </div>
  );
}

interface ForwardViewProps {
  response: ForwardDepTreeResponse;
  onSelect: (idx: number) => void;
  onBumpLimit: () => void;
  maxLimit: number;
}

function ForwardSliceView(props: ForwardViewProps) {
  const r = props.response;
  const g = r.graph;
  return (
    <div class="slice-forward">
      <p class="dim small">
        {g.node_count} nodes · {g.edge_count} edges
        {g.truncated ? ` · truncated at ${g.node_limit}` : ""}
        {g.hidden_edges > 0 ? ` · ${g.hidden_edges} hidden edges` : ""}
      </p>
      <Show when={g.truncated}>
        <div class="cap-notice" role="status">
          <span>Forward dep tree stopped at {g.node_limit} nodes.</span>
          <Show
            when={g.node_limit < props.maxLimit}
            fallback={<span class="dim">UI/server cap is {props.maxLimit.toLocaleString()} nodes.</span>}
          >
            <button type="button" onClick={props.onBumpLimit}>
              show {props.maxLimit.toLocaleString()}
            </button>
          </Show>
        </div>
      </Show>
      <Show when={r.seed.note}>
        <p class="dim small">seed {r.seed.note}</p>
      </Show>
      <table class="slice-table">
        <thead>
          <tr>
            <th>depth</th>
            <th>idx</th>
            <th>pc</th>
            <th>fn</th>
            <th>asm</th>
          </tr>
        </thead>
        <tbody>
          <For each={g.nodes}>
            {(node: DepNode) => (
              <tr onClick={() => props.onSelect(node.idx)}>
                <td>{node.depth}</td>
                <td>{node.idx}</td>
                <td>
                  <code>{node.pc}</code>
                </td>
                <td>{node.func ?? ""}</td>
                <td>
                  <code>{node.asm}</code>
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
      <Show when={g.nodes.length === 0}>
        <p class="dim small">no downstream uses for this seed</p>
      </Show>
    </div>
  );
}
