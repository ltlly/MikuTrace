import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";

import { fetchBackwardTaint, fetchForwardTaint } from "~/api/client";
import type { TaintRow } from "~/api/types";

type Direction = "forward" | "backward";
type ViewMode = "timeline" | "table";
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
  showDepth: boolean;
}

interface TaintPanelProps {
  idx: number;
  reg: string;
  onRegChange: (reg: string) => void;
  onSelect: (idx: number) => void;
  runRequest?: RunRequest;
  active: boolean;
}

export default function TaintPanel(props: TaintPanelProps) {
  const [start, setStart] = createSignal(0);
  const [reg, setReg] = createSignal("x0");
  const [direction, setDirection] = createSignal<Direction>("forward");
  const [viewMode, setViewMode] = createSignal<ViewMode>("timeline");
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

  function cancelRun() {
    runSeq += 1;
    if (retryTimer !== undefined) {
      window.clearTimeout(retryTimer);
      retryTimer = undefined;
    }
    runAbort?.abort();
    runAbort = undefined;
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

  async function run(dirArg = direction(), startArg = start(), regArg = reg()) {
    cancelRun();
    const seq = ++runSeq;
    const abort = new AbortController();
    runAbort = abort;
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      const dir = dirArg;
      const flags = {
        through_mem: throughMem(),
        data_only: dataOnly(),
        cross_fn_call: crossFnCall(),
      };
      if (dir === "forward") {
        const resp = await fetchForwardTaint(startArg, regArg, maxCount(), flags, abort.signal);
        if (seq !== runSeq || abort.signal.aborted) return;
        if (resp.status === "loading") {
          scheduleMemoryRetry(seq, dir, startArg, regArg);
          return;
        }
        setResult({
          rows: resp.hits,
          count: resp.count,
          stopped: resp.stopped_at_max,
          direction: "forward",
          from: resp.from,
          reg: resp.reg,
          showDepth: flags.cross_fn_call,
        });
      } else {
        const resp = await fetchBackwardTaint(startArg, regArg, maxCount(), flags, abort.signal);
        if (seq !== runSeq || abort.signal.aborted) return;
        if (resp.status === "loading") {
          scheduleMemoryRetry(seq, dir, startArg, regArg);
          return;
        }
        setResult({
          rows: resp.chain,
          count: resp.count,
          stopped: resp.stopped_at_max,
          direction: "backward",
          from: resp.from,
          reg: resp.reg,
          showDepth: flags.cross_fn_call,
        });
      }
    } catch (e: unknown) {
      if (abort.signal.aborted) return;
      if (seq !== runSeq) return;
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      if (seq === runSeq && !abort.signal.aborted) {
        if (runAbort === abort) runAbort = undefined;
        setRunning(false);
      }
    }
  }

  const labelFor = (row: TaintRow): string =>
    row.why ?? row.via ?? "";

  const rowIndent = (row: TaintRow): string =>
    `${Math.min(10, Math.max(0, row.frame_depth ?? 0)) * 14}px`;

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
            onInput={(e) => setStart(Number(e.currentTarget.value) || 0)}
          />
        </label>
        <label>
          reg
          <input
            type="text"
            value={reg()}
            onInput={(e) => {
              setReg(e.currentTarget.value);
              props.onRegChange(e.currentTarget.value);
            }}
          />
        </label>
        <label>
          direction
          <select
            value={direction()}
            onChange={(e) =>
              setDirection(e.currentTarget.value as Direction)
            }
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
          {" "}call-depth indent
        </label>
        <label>
          view
          <select value={viewMode()} onChange={(e) => setViewMode(e.currentTarget.value as ViewMode)}>
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
                {" "}· stopped at max
              </Show>
            </p>
            <Show when={viewMode() === "timeline"} fallback={
              <table class="taint-table">
                <thead>
                  <tr>
                    <th>idx</th>
                    <th>pc</th>
                    <th>func</th>
                    <th>asm</th>
                    <th>{r().direction === "forward" ? "why" : "via"}</th>
                    {r().showDepth ? <th>depth</th> : null}
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
                        {r().showDepth ? <td>{row.frame_depth ?? ""}</td> : null}
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            }>
              <div class="taint-tree">
                <For each={r().rows}>
                  {(row) => (
                    <button
                      type="button"
                      class="taint-tree-row"
                      style={{ "padding-left": rowIndent(row) }}
                      onClick={() => props.onSelect(row.idx)}
                    >
                      <span class="taint-tree-idx">#{row.idx}</span>
                      <span class="taint-tree-fn dim small">{row.func ?? "?"}</span>
                      <code class="taint-tree-asm">{row.asm}</code>
                      <span class="taint-tree-why dim small">{labelFor(row)}</span>
                    </button>
                  )}
                </For>
              </div>
            </Show>
          </>
        )}
      </Show>
    </section>
  );
}
