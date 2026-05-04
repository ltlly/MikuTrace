import { createEffect, createSignal, For, Show } from "solid-js";

import { fetchBackwardTaint, fetchForwardTaint } from "~/api/client";
import type { TaintRow } from "~/api/types";

type Direction = "forward" | "backward";

interface RunResult {
  rows: TaintRow[];
  count: number;
  stopped: boolean;
  direction: Direction;
  showDepth: boolean;
}

interface TaintPanelProps {
  idx: number;
  reg: string;
  onRegChange: (reg: string) => void;
}

export default function TaintPanel(props: TaintPanelProps) {
  const [start, setStart] = createSignal(0);
  const [reg, setReg] = createSignal("x0");
  const [direction, setDirection] = createSignal<Direction>("forward");
  const [maxCount, setMaxCount] = createSignal(200);
  const [throughMem, setThroughMem] = createSignal(false);
  const [dataOnly, setDataOnly] = createSignal(false);
  const [crossFnCall, setCrossFnCall] = createSignal(false);
  const [running, setRunning] = createSignal(false);
  const [result, setResult] = createSignal<RunResult | null>(null);
  const [error, setError] = createSignal<string | null>(null);

  createEffect(() => {
    setStart(props.idx);
    if (props.reg) setReg(props.reg);
  });

  async function run() {
    setRunning(true);
    setError(null);
    try {
      const dir = direction();
      const flags = {
        through_mem: throughMem(),
        data_only: dataOnly(),
        cross_fn_call: crossFnCall(),
      };
      if (dir === "forward") {
        const resp = await fetchForwardTaint(start(), reg(), maxCount(), flags);
        setResult({
          rows: resp.hits,
          count: resp.count,
          stopped: resp.stopped_at_max,
          direction: "forward",
          showDepth: flags.cross_fn_call,
        });
      } else {
        const resp = await fetchBackwardTaint(start(), reg(), maxCount(), flags);
        setResult({
          rows: resp.chain,
          count: resp.count,
          stopped: resp.stopped_at_max,
          direction: "backward",
          showDepth: flags.cross_fn_call,
        });
      }
    } catch (e: unknown) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setRunning(false);
    }
  }

  const labelFor = (row: TaintRow): string =>
    row.why ?? row.via ?? "";

  return (
    <section class="panel">
      <h2>Taint</h2>
      <div class="taint-controls">
        <label>
          start
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
          max
          <input
            type="number"
            min="1"
            max="50000"
            value={maxCount()}
            onInput={(e) =>
              setMaxCount(Number(e.currentTarget.value) || 200)
            }
          />
        </label>
        <label>
          <input
            type="checkbox"
            checked={throughMem()}
            onChange={(e) => setThroughMem(e.currentTarget.checked)}
          />
          {" "}through_mem
        </label>
        <label>
          <input
            type="checkbox"
            checked={dataOnly()}
            onChange={(e) => setDataOnly(e.currentTarget.checked)}
          />
          {" "}data_only
        </label>
        <label>
          <input
            type="checkbox"
            checked={crossFnCall()}
            onChange={(e) => setCrossFnCall(e.currentTarget.checked)}
          />
          {" "}cross_fn_call
        </label>
        <button type="button" disabled={running()} onClick={run}>
          {running() ? "running…" : "Run"}
        </button>
      </div>
      <Show when={error()}>
        <p class="err">{error()}</p>
      </Show>
      <Show when={result()}>
        {(r) => (
          <>
            <p class="dim small">
              {r().direction} · {r().count} row{r().count === 1 ? "" : "s"}
              <Show when={r().stopped}>
                {" "}· stopped at max
              </Show>
            </p>
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
                    <tr>
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
          </>
        )}
      </Show>
    </section>
  );
}
