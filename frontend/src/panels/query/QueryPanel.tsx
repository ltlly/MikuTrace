import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js";

import { fetchTraceQuery } from "~/api/client";
import type { TraceQueryKind, TraceQueryResponse } from "~/api/types";
import type { UiTaskReporter } from "~/utils/taskCenter";

export interface QueryRunRequest {
  token: number;
  text: string;
}

interface QueryPanelProps {
  idx: number;
  selectedReg: string;
  onSelect: (idx: number) => void;
  active: boolean;
  runRequest?: QueryRunRequest;
  onTaskUpdate?: UiTaskReporter;
}

interface QuerySource {
  kind: TraceQueryKind;
  q: string;
  idx: number;
  reg: string;
  addr: string;
  len: number;
  limit: number;
}

const QUERY_KINDS: TraceQueryKind[] = ["records", "regs", "mem", "reads", "writes", "functions", "strings", "jni", "provenance"];
const DEFAULT_LIMIT = 200;

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function str(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function parseQueryText(text: string, currentIdx: number, selectedReg: string): QuerySource {
  const words = text.trim().split(/\s+/).filter(Boolean);
  let kind: TraceQueryKind = "records";
  let q = text.trim();
  let idx = currentIdx;
  let reg = selectedReg;
  let addr = "";
  let len = 1;
  let limit = DEFAULT_LIMIT;

  const first = words[0]?.toLowerCase();
  if (first && (QUERY_KINDS as string[]).includes(first)) {
    kind = first as TraceQueryKind;
    q = words.slice(1).join(" ");
  } else if (first === "reg") {
    kind = "regs";
    q = words.slice(1).join(" ");
  } else if (first === "memory") {
    kind = "mem";
    q = words.slice(1).join(" ");
  } else if (first === "func" || first === "fn") {
    kind = "functions";
    q = words.slice(1).join(" ");
  } else if (first === "jni-events" || first === "jni-calls") {
    kind = "jni";
    q = words.slice(1).join(" ");
  } else if (first === "prov") {
    kind = "provenance";
    q = words.slice(1).join(" ");
  }

  const rest = q.split(/\s+/).filter(Boolean);
  for (let i = 0; i < rest.length; i += 1) {
    const w = rest[i].toLowerCase();
    const next = rest[i + 1];
    if ((w === "addr" || w === "at") && next) {
      addr = next;
      i += 1;
    } else if ((w === "len" || w === "size") && next) {
      len = Number.parseInt(next, 10) || len;
      i += 1;
    } else if ((w === "limit" || w === "max") && next) {
      limit = Number.parseInt(next, 10) || limit;
      i += 1;
    } else if (w.startsWith("@")) {
      idx = Number.parseInt(w.slice(1), 10) || idx;
    }
  }

  if ((kind === "mem" || kind === "reads" || kind === "writes" || kind === "provenance") && !addr) {
    addr = rest.find((w) => /^0x[0-9a-f]+$/i.test(w)) ?? q;
  }
  if (kind === "regs") {
    reg = rest.find((w) => /^(?:x\d+|w\d+|sp|fp|lr|pc|nzcv)$/i.test(w)) ?? q.trim() ?? selectedReg;
  }
  return { kind, q, idx, reg, addr, len, limit };
}

function rowIdx(row: Record<string, unknown>): number | null {
  return num(row.idx);
}

function QueryRows(props: { resp: TraceQueryResponse; onSelect: (idx: number) => void }) {
  const keys = createMemo(() => {
    const seen = new Set<string>();
    for (const row of props.resp.rows.slice(0, 20)) {
      for (const key of Object.keys(row)) {
        if (key !== "extra") seen.add(key);
      }
      const extra = row.extra;
      if (extra && typeof extra === "object") {
        for (const key of Object.keys(extra as Record<string, unknown>)) seen.add(`extra.${key}`);
      }
    }
    return [...seen].slice(0, 8);
  });
  const valueFor = (row: Record<string, unknown>, key: string) => {
    if (!key.startsWith("extra.")) return str(row[key]);
    const extra = row.extra as Record<string, unknown> | undefined;
    return str(extra?.[key.slice("extra.".length)]);
  };
  return (
    <div class="query-results">
      <table class="query-table">
        <thead>
          <tr>
            <For each={keys()}>{(key) => <th>{key}</th>}</For>
          </tr>
        </thead>
        <tbody>
          <For each={props.resp.rows}>
            {(row) => {
              const idx = rowIdx(row);
              return (
                <tr
                  classList={{ clickable: idx !== null }}
                  onClick={() => {
                    if (idx !== null) props.onSelect(idx);
                  }}
                >
                  <For each={keys()}>{(key) => <td>{valueFor(row, key)}</td>}</For>
                </tr>
              );
            }}
          </For>
        </tbody>
      </table>
    </div>
  );
}

export default function QueryPanel(props: QueryPanelProps) {
  const [text, setText] = createSignal("records ret");
  const [kind, setKind] = createSignal<TraceQueryKind>("records");
  const [q, setQ] = createSignal("ret");
  const [addr, setAddr] = createSignal("");
  const [reg, setReg] = createSignal(props.selectedReg);
  const [len, setLen] = createSignal(1);
  const [limit, setLimit] = createSignal(DEFAULT_LIMIT);
  const [running, setRunning] = createSignal(false);
  const [resp, setResp] = createSignal<TraceQueryResponse | null>(null);
  const [error, setError] = createSignal("");
  let seq = 0;
  let abort: AbortController | undefined;
  let lastToken = -1;
  let currentTask:
    | { id: string; surface: string; label: string; startedAt: number }
    | undefined;

  function cancel() {
    if (running() && currentTask) {
      props.onTaskUpdate?.({
        ...currentTask,
        status: "cancelled",
        detail: "superseded",
      });
    }
    seq += 1;
    abort?.abort();
    abort = undefined;
    currentTask = undefined;
    setRunning(false);
  }

  onCleanup(() => cancel());

  createEffect(() => {
    if (props.selectedReg) setReg(props.selectedReg);
  });

  createEffect(() => {
    const req = props.runRequest;
    if (!props.active || !req || req.token === lastToken) return;
    lastToken = req.token;
    setText(req.text);
    const parsed = parseQueryText(req.text, props.idx, props.selectedReg);
    setKind(parsed.kind);
    setQ(parsed.q);
    setAddr(parsed.addr);
    setReg(parsed.reg);
    setLen(parsed.len);
    setLimit(parsed.limit);
    queueMicrotask(() => void run(parsed));
  });

  function sourceFromFields(): QuerySource {
    return {
      kind: kind(),
      q: q(),
      idx: props.idx,
      reg: reg(),
      addr: addr(),
      len: Math.max(1, len()),
      limit: Math.max(1, limit()),
    };
  }

  async function run(source = sourceFromFields()) {
    cancel();
    const mySeq = ++seq;
    const controller = new AbortController();
    abort = controller;
    const taskStartedAt = performance.now();
    currentTask = {
      id: "trace-query",
      surface: "Trace Query",
      label: `${source.kind} ${source.q || source.addr || source.reg}`,
      startedAt: taskStartedAt,
    };
    setRunning(true);
    setError("");
    props.onTaskUpdate?.({
      ...currentTask,
      status: "running",
      detail: `limit ${source.limit}`,
    });
    try {
      const out = await fetchTraceQuery({
        kind: source.kind,
        q: source.q,
        idx: source.idx,
        reg: source.reg,
        addr: source.addr,
        len: source.len,
        limit: source.limit,
        signal: controller.signal,
      });
      if (mySeq !== seq || controller.signal.aborted) return;
      setResp(out);
      currentTask = undefined;
      props.onTaskUpdate?.({
        id: "trace-query",
        surface: "Trace Query",
        label: `${out.kind} ${out.q || source.addr || source.reg}`,
        status: out.truncated ? "partial" : out.status === "ready" ? "ready" : "error",
        startedAt: taskStartedAt,
        detail: `${out.returned}/${out.count} rows${out.note ? ` · ${out.note}` : ""}`,
      });
    } catch (err) {
      if (controller.signal.aborted || mySeq !== seq) return;
      setError(String(err));
      currentTask = undefined;
      props.onTaskUpdate?.({
        id: "trace-query",
        surface: "Trace Query",
        label: `${source.kind} ${source.q || source.addr || source.reg}`,
        status: "error",
        startedAt: taskStartedAt,
        detail: String(err),
      });
    } finally {
      if (mySeq === seq && !controller.signal.aborted) {
        if (abort === controller) abort = undefined;
        currentTask = undefined;
        setRunning(false);
      }
    }
  }

  return (
    <section class="panel query-panel">
      <h2>Trace Query</h2>
      <div class="query-controls">
        <label>
          command
          <input
            type="text"
            value={text()}
            onInput={(e) => {
              setText(e.currentTarget.value);
              const parsed = parseQueryText(e.currentTarget.value, props.idx, props.selectedReg);
              setKind(parsed.kind);
              setQ(parsed.q);
              setAddr(parsed.addr);
              setReg(parsed.reg);
              setLen(parsed.len);
              setLimit(parsed.limit);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") void run();
            }}
          />
        </label>
        <label>
          kind
          <select value={kind()} onChange={(e) => setKind(e.currentTarget.value as TraceQueryKind)}>
            <For each={QUERY_KINDS}>{(k) => <option value={k}>{k}</option>}</For>
          </select>
        </label>
        <label>
          q
          <input type="text" value={q()} onInput={(e) => setQ(e.currentTarget.value)} />
        </label>
        <label>
          reg
          <input type="text" value={reg()} onInput={(e) => setReg(e.currentTarget.value)} />
        </label>
        <label>
          addr
          <input type="text" value={addr()} onInput={(e) => setAddr(e.currentTarget.value)} />
        </label>
        <label>
          len
          <input type="number" min="1" max="4096" value={len()} onInput={(e) => setLen(Number(e.currentTarget.value) || 1)} />
        </label>
        <label>
          limit
          <input type="number" min="1" max="5000" value={limit()} onInput={(e) => setLimit(Number(e.currentTarget.value) || DEFAULT_LIMIT)} />
        </label>
        <button type="button" onClick={() => void run()}>
          {running() ? "restart" : "run"}
        </button>
      </div>
      <Show when={error()}>
        <p class="err">{error()}</p>
      </Show>
      <Show when={running()}>
        <p class="dim small">query running…</p>
      </Show>
      <Show when={resp()}>
        {(r) => (
          <>
            <p class="dim small">
              {r().kind} · {r().returned}/{r().count} rows
              <Show when={r().truncated}> · partial</Show>
              <Show when={r().note}> · {r().note}</Show>
            </p>
            <QueryRows resp={r()} onSelect={props.onSelect} />
          </>
        )}
      </Show>
    </section>
  );
}
