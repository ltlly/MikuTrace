import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js";

import { fetchBackwardTaint, fetchForwardTaint } from "~/api/client";
import type { TaintGraph, TaintRow } from "~/api/types";
import type { UiTaskReporter } from "~/utils/taskCenter";
import ProvenanceGraph, { type ProvEdge, type ProvNode } from "~/utils/provenanceGraph";

export type TaintOverlayDirection = "forward" | "backward";
type Direction = TaintOverlayDirection;
type ViewMode = "tree" | "timeline" | "table";
const TAINT_RETRY_MS = 500;
const MAX_TAINT_ROWS = 5000;

interface RunRequest {
  token: number;
  idx: number;
  reg: string;
  direction: Direction;
}

interface RunResult {
  rows: TaintRow[];
  count: number;
  stopped: boolean;
  direction: Direction;
  from: number;
  reg: string;
  limit: number;
  showDepth: boolean;
  graph?: TaintGraph;
}

export interface TaintOverlayResult {
  rows: TaintRow[];
  count: number;
  stopped: boolean;
  direction: Direction;
  from: number;
  reg: string;
  limit: number;
  graph?: TaintGraph;
}

interface TaintPanelProps {
  idx: number;
  reg: string;
  onRegChange: (reg: string) => void;
  onSelect: (idx: number) => void;
  runRequest?: RunRequest;
  active: boolean;
  onTaskUpdate?: UiTaskReporter;
  onOverlayChange?: (result: TaintOverlayResult | null) => void;
}

export default function TaintPanel(props: TaintPanelProps) {
  const [start, setStart] = createSignal(0);
  const [reg, setReg] = createSignal("x0");
  const [direction, setDirection] = createSignal<Direction>("forward");
  const [viewMode, setViewMode] = createSignal<ViewMode>("tree");
  const [maxCount, setMaxCount] = createSignal(200);
  const [throughMem, setThroughMem] = createSignal(false);
  const [dataOnly, setDataOnly] = createSignal(false);
  const [crossFnCall, setCrossFnCall] = createSignal(true);
  const [running, setRunning] = createSignal(false);
  const [result, setResult] = createSignal<RunResult | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  let runSeq = 0;
  let runAbort: AbortController | undefined;
  let retryTimer: number | undefined;
  let currentTask:
    | { id: string; surface: string; label: string; startedAt: number }
    | undefined;

  function cancelRun() {
    if (running() && currentTask) {
      props.onTaskUpdate?.({
        ...currentTask,
        status: "cancelled",
        detail: "superseded",
      });
    }
    runSeq += 1;
    if (retryTimer !== undefined) {
      window.clearTimeout(retryTimer);
      retryTimer = undefined;
    }
    runAbort?.abort();
    runAbort = undefined;
    currentTask = undefined;
    setRunning(false);
  }

  onCleanup(() => cancelRun());

  createEffect(() => {
    if (!props.active) return;
    setStart(props.idx);
    if (props.reg) setReg(props.reg);
  });

  createEffect(() => {
    if (!props.active) return;
    const req = props.runRequest;
    if (!req) return;
    setStart(req.idx);
    setReg(req.reg);
    setDirection(req.direction);
    props.onRegChange(req.reg);
    queueMicrotask(() => void run(req.direction, req.idx, req.reg));
  });

  function scheduleMemoryRetry(seq: number, dir: Direction, startArg: number, regArg: string) {
    setError("memory index loading…");
    retryTimer = window.setTimeout(() => {
      retryTimer = undefined;
      if (seq !== runSeq) return;
      void run(dir, startArg, regArg);
    }, TAINT_RETRY_MS);
  }

  function editStart(next: number) {
    cancelRun();
    setStart(next);
  }

  function editReg(next: string) {
    cancelRun();
    setReg(next);
    props.onRegChange(next);
  }

  function editDirection(next: Direction) {
    cancelRun();
    setDirection(next);
  }

  async function run(dirArg = direction(), startArg = start(), regArg = reg()) {
    cancelRun();
    const seq = ++runSeq;
    const abort = new AbortController();
    runAbort = abort;
    const limit = maxCount();
    const taskStartedAt = performance.now();
    currentTask = {
      id: "taint",
      surface: "Taint",
      label: `${dirArg} ${regArg} @${startArg}`,
      startedAt: taskStartedAt,
    };
    setRunning(true);
    setError(null);
    setResult(null);
    props.onOverlayChange?.(null);
    props.onTaskUpdate?.({
      ...currentTask,
      status: "running",
      detail: `limit ${limit}`,
    });
    try {
      const dir = dirArg;
      const flags = {
        through_mem: throughMem(),
        data_only: dataOnly(),
        cross_fn_call: crossFnCall(),
      };
      if (dir === "forward") {
        const resp = await fetchForwardTaint(startArg, regArg, limit, flags, abort.signal);
        if (seq !== runSeq || abort.signal.aborted) return;
        if (resp.status === "loading") {
          scheduleMemoryRetry(seq, dir, startArg, regArg);
          return;
        }
        const nextResult: RunResult = {
          rows: resp.hits,
          count: resp.count,
          stopped: resp.stopped_at_max,
          direction: "forward",
          from: resp.from,
          reg: resp.reg,
          limit,
          showDepth: flags.cross_fn_call,
          graph: resp.graph,
        };
        setResult(nextResult);
        props.onOverlayChange?.(nextResult);
        currentTask = undefined;
        props.onTaskUpdate?.({
          id: "taint",
          surface: "Taint",
          label: `forward ${resp.reg} @${resp.from}`,
          status: resp.stopped_at_max ? "partial" : "ready",
          startedAt: taskStartedAt,
          detail: `${resp.count} rows`,
        });
      } else {
        const resp = await fetchBackwardTaint(startArg, regArg, limit, flags, abort.signal);
        if (seq !== runSeq || abort.signal.aborted) return;
        if (resp.status === "loading") {
          scheduleMemoryRetry(seq, dir, startArg, regArg);
          return;
        }
        const nextResult: RunResult = {
          rows: resp.chain,
          count: resp.count,
          stopped: resp.stopped_at_max,
          direction: "backward",
          from: resp.from,
          reg: resp.reg,
          limit,
          showDepth: flags.cross_fn_call,
          graph: resp.graph,
        };
        setResult(nextResult);
        props.onOverlayChange?.(nextResult);
        currentTask = undefined;
        props.onTaskUpdate?.({
          id: "taint",
          surface: "Taint",
          label: `backward ${resp.reg} @${resp.from}`,
          status: resp.stopped_at_max ? "partial" : "ready",
          startedAt: taskStartedAt,
          detail: `${resp.count} rows`,
        });
      }
    } catch (e: unknown) {
      if (abort.signal.aborted) return;
      if (seq !== runSeq) return;
      setError(String(e instanceof Error ? e.message : e));
      currentTask = undefined;
      props.onTaskUpdate?.({
        id: "taint",
        surface: "Taint",
        label: `${dirArg} ${regArg} @${startArg}`,
        status: "error",
        startedAt: taskStartedAt,
        detail: String(e instanceof Error ? e.message : e),
      });
    } finally {
      if (seq === runSeq && !abort.signal.aborted) {
        if (runAbort === abort) runAbort = undefined;
        currentTask = undefined;
        setRunning(false);
      }
    }
  }

  const labelFor = (row: TaintRow): string =>
    row.why ?? row.via ?? "";

  const callDepthIndent = (row: TaintRow): string =>
    `${Math.min(10, Math.max(0, row.frame_depth ?? 0)) * 14}px`;

  const taintDepthIndent = (row: TaintRow): string =>
    `${Math.min(14, Math.max(0, row.taint_depth ?? 0)) * 18}px`;

  const edgeLabel = (row: TaintRow): string => {
    switch (row.edge_kind) {
      case "addr":
        return "addr";
      case "mem":
        return "mem value";
      case "store-src":
        return "store src";
      case "reg+mem":
        return "reg+mem";
      case "control":
        return "control";
      case "control-reg":
        return "control reg";
      case "seed":
        return "seed";
      case "reg":
        return "reg";
      default:
        return "";
    }
  };

  const nodeKind = (kind: string | undefined): ProvNode["kind"] =>
    kind === "seed" ? "seed" : "record";

  const graphNodes = createMemo<ProvNode[]>(() => {
    const r = result();
    if (!r) return [];
    if (r.graph) {
      return r.graph.nodes.map((node) => {
        const idx = node.idx;
        return {
          id: node.id,
          label: node.label,
          sub: `${node.func ?? "?"} · ${node.expression || node.via || node.asm}`,
          kind: nodeKind(node.kind),
          onClick: idx === null ? undefined : () => props.onSelect(idx),
        };
      });
    }
    return r.rows.slice(0, 160).map((row, i) => ({
      id: String(row.idx),
      label: `#${row.idx}`,
      sub: `${row.func ?? "?"} · ${labelFor(row) || row.asm}`,
      kind: i === 0 ? "seed" : "record",
      onClick: () => props.onSelect(row.idx),
    }));
  });

  const graphEdges = createMemo<ProvEdge[]>(() => {
    const graph = result()?.graph;
    if (graph) {
      return graph.edges.map((edge) => ({
        from: edge.from,
        to: edge.to,
        label: edge.label || undefined,
      }));
    }
    const shown = new Set(graphNodes().map((node) => node.id));
    const edges: ProvEdge[] = [];
    for (const row of result()?.rows ?? []) {
      if (!shown.has(String(row.idx))) continue;
      for (const parent of row.parent_idxs ?? []) {
        if (shown.has(String(parent))) {
          edges.push({ from: String(parent), to: String(row.idx), label: edgeLabel(row) || undefined });
        }
      }
    }
    return edges.slice(0, 240);
  });

  const graphSummary = createMemo(() => {
    const graph = result()?.graph;
    if (!graph) return undefined;
    const base = `${graph.node_count} items · ${graph.edge_count} links`;
    if (!graph.truncated) return base;
    return `${base} · hidden ${graph.hidden_nodes} items/${graph.hidden_edges} links`;
  });

  const graphNote = createMemo(() => {
    const graph = result()?.graph;
    if (!graph?.truncated) return undefined;
    return `showing first ${graph.nodes.length}/${graph.node_count} nodes and ${graph.edges.length}/${graph.edge_count} edges`;
  });

  const parentLabel = (row: TaintRow): string => {
    const parents = row.parent_idxs ?? [];
    if (!parents.length) return "seed";
    const edge = edgeLabel(row);
    const prefix = edge ? `${edge} from` : "from";
    return `${prefix} ${parents.map((idx) => `#${idx}`).join(",")}`;
  };

  function rerunAtUiCap(r: RunResult) {
    setMaxCount(MAX_TAINT_ROWS);
    queueMicrotask(() => void run(r.direction, r.from, r.reg));
  }

  function saveTextFile(name: string, mime: string, text: string) {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function exportRows(r: RunResult, format: "json" | "txt") {
    const stem = `taint-${r.direction}-${r.reg}-${r.from}`;
    if (format === "json") {
      saveTextFile(
        `${stem}.json`,
        "application/json",
        JSON.stringify(
          {
            direction: r.direction,
            from: r.from,
            reg: r.reg,
            count: r.count,
            stopped: r.stopped,
            limit: r.limit,
            rows: r.rows,
            graph: r.graph ?? null,
          },
          null,
          2,
        ),
      );
      return;
    }
    const header = ["idx", "pc", "func", "asm", "why_via", "edge", "parents", "taint_depth", "call_depth"];
    const lines = [
      header.join("\t"),
      ...r.rows.map((row) =>
        [
          row.idx,
          row.pc,
          row.func ?? "",
          row.asm,
          labelFor(row),
          edgeLabel(row),
          (row.parent_idxs ?? []).join(","),
          row.taint_depth ?? "",
          row.frame_depth ?? "",
        ].map((value) => String(value).replace(/\t/g, " ").replace(/\n/g, " ")).join("\t"),
      ),
    ];
    saveTextFile(`${stem}.txt`, "text/plain", `${lines.join("\n")}\n`);
  }

  return (
    <section class="panel">
      <h2>Taint</h2>
      <div class="taint-controls">
        <label>
          traceIdx
          <input
            type="number"
            min="0"
            value={start()}
            onInput={(e) => editStart(Number(e.currentTarget.value) || 0)}
          />
        </label>
        <label>
          reg
          <input
            type="text"
            value={reg()}
            onInput={(e) => editReg(e.currentTarget.value)}
          />
        </label>
        <label>
          direction
          <select
            value={direction()}
            onChange={(e) => editDirection(e.currentTarget.value as Direction)}
          >
            <option value="forward">forward</option>
            <option value="backward">backward</option>
          </select>
        </label>
        <label>
          max rows
          <input
            type="number"
            min="1"
            max={MAX_TAINT_ROWS}
            value={maxCount()}
            onInput={(e) =>
              setMaxCount(Math.max(1, Math.min(MAX_TAINT_ROWS, Number(e.currentTarget.value) || 200)))
            }
          />
        </label>
        <label>
          <input
            type="checkbox"
            checked={throughMem()}
            onChange={(e) => setThroughMem(e.currentTarget.checked)}
          />
          {" "}follow memory bytes
        </label>
        <label>
          <input
            type="checkbox"
            checked={dataOnly()}
            onChange={(e) => setDataOnly(e.currentTarget.checked)}
          />
          {" "}data only
        </label>
        <label>
          <input
            type="checkbox"
            checked={crossFnCall()}
            onChange={(e) => setCrossFnCall(e.currentTarget.checked)}
          />
          {" "}include call depth
        </label>
        <label>
          view
          <select value={viewMode()} onChange={(e) => setViewMode(e.currentTarget.value as ViewMode)}>
            <option value="tree">tree</option>
            <option value="timeline">timeline</option>
            <option value="table">table</option>
          </select>
        </label>
        <button type="button" onClick={() => void run()}>
          {running() ? "restart" : "Run"}
        </button>
      </div>
      <Show when={error()}>
        <p class="err">{error()}</p>
      </Show>
      <Show when={result()}>
        {(r) => (
          <>
            <p class="dim small">
              {r().direction} from traceIdx {r().from} reg {r().reg} · {r().count} row{r().count === 1 ? "" : "s"}
              <Show when={r().stopped}>
                {" "}· partial result
              </Show>
              {" "}
              <button type="button" class="inline-btn" onClick={() => exportRows(r(), "json")}>JSON</button>
              <button type="button" class="inline-btn" onClick={() => exportRows(r(), "txt")}>TXT</button>
            </p>
            <Show when={r().stopped}>
              <div class="cap-notice" role="status">
                <span>
                  Taint result stopped at {r().limit.toLocaleString()} row cap; the full dependency chain may continue.
                </span>
                <Show
                  when={r().limit < MAX_TAINT_ROWS}
                  fallback={<span class="dim">UI/server cap is {MAX_TAINT_ROWS.toLocaleString()} rows; narrow traceIdx/reg/options to inspect a smaller slice.</span>}
                >
                  <button type="button" onClick={() => rerunAtUiCap(r())} disabled={running()}>
                    rerun with {MAX_TAINT_ROWS.toLocaleString()}
                  </button>
                </Show>
              </div>
            </Show>
            <Show when={viewMode() !== "table"} fallback={
              <table class="taint-table">
                <thead>
                  <tr>
                    <th>idx</th>
                    <th>pc</th>
                    <th>func</th>
                    <th>asm</th>
                    <th>{r().direction === "forward" ? "why" : "via"}</th>
                    <th>edge</th>
                    <th>parents</th>
                    <th>taint depth</th>
                    {r().showDepth ? <th>call depth</th> : null}
                  </tr>
                </thead>
                <tbody>
                  <For each={r().rows}>
                    {(row) => (
                      <tr onClick={() => props.onSelect(row.idx)}>
                        <td>{row.idx}</td>
                        <td class="dim small">{row.pc}</td>
                        <td>{row.func ?? "?"}</td>
                        <td>{row.asm}</td>
                        <td>{labelFor(row)}</td>
                        <td>{edgeLabel(row)}</td>
                        <td>{parentLabel(row)}</td>
                        <td>{row.taint_depth ?? ""}</td>
                        {r().showDepth ? <td>{row.frame_depth ?? ""}</td> : null}
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            }>
              <>
                <Show when={viewMode() === "tree"}>
                  <ProvenanceGraph
                    title="Taint Provenance"
                    nodes={graphNodes()}
                    edges={graphEdges()}
                    summary={graphSummary()}
                    note={graphNote()}
                    empty="no taint dependency edges"
                  />
                </Show>
                <div class="taint-tree">
                  <For each={r().rows}>
                    {(row) => (
                      <button
                        type="button"
                        class="taint-tree-row"
                        classList={{ dependency: viewMode() === "tree" }}
                        style={{
                          "padding-left": viewMode() === "tree"
                            ? taintDepthIndent(row)
                            : callDepthIndent(row),
                        }}
                        onClick={() => props.onSelect(row.idx)}
                      >
                        <span class="taint-tree-idx">#{row.idx}</span>
                        <span class="taint-tree-fn dim small">{row.func ?? "?"}</span>
                        <code class="taint-tree-asm">{row.asm}</code>
                        <span class="taint-tree-why dim small">
                          {labelFor(row)}
                          <Show when={viewMode() === "tree"}>
                            {" · "}{parentLabel(row)}
                          </Show>
                        </span>
                      </button>
                    )}
                  </For>
                </div>
              </>
            </Show>
          </>
        )}
      </Show>
    </section>
  );
}
