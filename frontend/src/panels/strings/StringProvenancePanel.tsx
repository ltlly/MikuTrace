import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js";

import { fetchStringProvenance } from "~/api/client";
import type { StringProvByte } from "~/api/types";
import { createGuardedResource } from "~/utils/resourceGuards";
import type { UiTaskReporter } from "~/utils/taskCenter";
import ProvenanceGraph, { type ProvEdge, type ProvNode } from "~/utils/provenanceGraph";

export interface StringProvenanceRequest {
  token: number;
  addr: string;
  len: number;
  text: string;
}

interface StringProvenancePanelProps {
  request?: StringProvenanceRequest;
  onSelect: (idx: number) => void;
  active: boolean;
  onTaskUpdate?: UiTaskReporter;
}

interface Source {
  token: number;
  addr: string;
  len: number;
  retry: number;
}

const PROVENANCE_RETRY_MS = 500;
const GRAPH_BYTE_LIMIT = 32;
const GRAPH_EVENT_LIMIT = 2;

function printable(byte: number | null): string {
  if (byte === null) return ".";
  if (byte < 0x20 || byte > 0x7e) return ".";
  return String.fromCharCode(byte);
}

function hexByte(byte: number | null): string {
  if (byte === null) return "??";
  return byte.toString(16).padStart(2, "0");
}

function kindLabel(kind: string): string {
  if (kind === "w") return "write";
  if (kind === "r") return "read";
  if (kind === "x") return "external";
  return "unknown";
}

export default function StringProvenancePanel(props: StringProvenancePanelProps) {
  const [retry, setRetry] = createSignal(0);
  const source = createMemo<Source | undefined>((prev) => {
    if (!props.active || !props.request) return undefined;
    const next = {
      token: props.request.token,
      addr: props.request.addr,
      len: Math.max(1, Math.min(512, props.request.len)),
      retry: retry(),
    };
    return prev &&
      prev.token === next.token &&
      prev.addr === next.addr &&
      prev.len === next.len &&
      prev.retry === next.retry
      ? prev
      : next;
  });
  const [resp, currentResp] = createGuardedResource<Source, Awaited<ReturnType<typeof fetchStringProvenance>>>(
    source,
    (s, signal) => fetchStringProvenance(s.addr, s.len, signal),
    (r, s) => r.addr === s.addr && r.length === s.len,
  );
  const readyResp = createMemo(() => {
    const r = currentResp();
    return r?.status === "ready" ? r : undefined;
  });

  const shownBytes = createMemo(() => {
    const bytes = readyResp()?.bytes ?? [];
    const nul = bytes.findIndex((b) => b.byte === 0);
    return nul >= 0 ? bytes.slice(0, nul + 1) : bytes;
  });
  const graphNodes = createMemo<ProvNode[]>(() => {
    const nodes: ProvNode[] = [];
    for (const b of shownBytes().slice(0, GRAPH_BYTE_LIMIT)) {
      nodes.push({
        id: `byte:${b.addr}`,
        label: `byte ${printable(b.byte)}`,
        sub: `${hexByte(b.byte)} · ${kindLabel(b.kind)}`,
        kind: "string",
      });
      for (const idx of b.writers.slice(0, GRAPH_EVENT_LIMIT)) {
        nodes.push({
          id: `w:${b.addr}:${idx}`,
          label: `writer #${idx}`,
          sub: `writes ${b.addr}`,
          kind: "writer",
          onClick: () => props.onSelect(idx),
        });
      }
      for (const idx of b.readers.slice(0, GRAPH_EVENT_LIMIT)) {
        nodes.push({
          id: `r:${b.addr}:${idx}`,
          label: `reader #${idx}`,
          sub: `reads ${b.addr}`,
          kind: "reader",
          onClick: () => props.onSelect(idx),
        });
      }
    }
    return nodes;
  });
  const graphEdges = createMemo<ProvEdge[]>(() => {
    const edges: ProvEdge[] = [];
    for (const b of shownBytes().slice(0, GRAPH_BYTE_LIMIT)) {
      for (const idx of b.writers.slice(0, GRAPH_EVENT_LIMIT)) {
        edges.push({ from: `w:${b.addr}:${idx}`, to: `byte:${b.addr}`, label: "produces byte" });
      }
      for (const idx of b.readers.slice(0, GRAPH_EVENT_LIMIT)) {
        edges.push({ from: `byte:${b.addr}`, to: `r:${b.addr}:${idx}`, label: "consumed by" });
      }
    }
    return edges;
  });
  const graphSummary = createMemo(() => {
    const bytes = shownBytes().slice(0, GRAPH_BYTE_LIMIT);
    const writerCount = bytes.reduce((n, b) => n + Math.min(b.writers.length, GRAPH_EVENT_LIMIT), 0);
    const readerCount = bytes.reduce((n, b) => n + Math.min(b.readers.length, GRAPH_EVENT_LIMIT), 0);
    const suffix = shownBytes().length > GRAPH_BYTE_LIMIT ? ` · first ${GRAPH_BYTE_LIMIT} bytes shown` : "";
    return `${bytes.length} bytes · ${writerCount} shown writes · ${readerCount} shown reads${suffix}`;
  });

  createEffect(() => {
    if (!props.active || resp.loading || currentResp()?.status !== "loading") return;
    const timer = window.setTimeout(() => setRetry((n) => n + 1), PROVENANCE_RETRY_MS);
    onCleanup(() => window.clearTimeout(timer));
  });

  createEffect(() => {
    const s = source();
    if (!props.active || !s) return;
    if (resp.loading || currentResp()?.status === "loading") {
      props.onTaskUpdate?.({
        id: "string-provenance",
        surface: "String Provenance",
        label: `${s.addr} len ${s.len}`,
        status: "running",
        detail: currentResp()?.status === "loading" ? "memory index loading" : "loading",
      });
    }
  });

  createEffect(() => {
    const r = readyResp();
    if (!props.active || !r) return;
    const truncated = r.bytes.some((b) => b.writers_total > b.writers.length || b.readers_total > b.readers.length);
    props.onTaskUpdate?.({
      id: "string-provenance",
      surface: "String Provenance",
      label: `${r.addr} len ${r.length}`,
      status: truncated ? "partial" : "ready",
      detail: `${shownBytes().length} bytes`,
    });
  });

  function idxButtons(byte: StringProvByte, kind: "w" | "r") {
    const idxs = kind === "w" ? byte.writers : byte.readers;
    const total = kind === "w" ? byte.writers_total : byte.readers_total;
    return (
      <>
        <For each={idxs}>
          {(idx) => (
            <button type="button" onClick={() => props.onSelect(idx)}>
              {kind}#{idx}
            </button>
          )}
        </For>
        <Show when={total > idxs.length}>
          <span class="dim small">+{total - idxs.length}</span>
        </Show>
      </>
    );
  }

  return (
    <section class="panel string-prov-panel">
      <h2>String Provenance</h2>
      <Show when={!props.request}>
        <p class="dim">双击 Strings 中的字符串后，这里会列出每个字符对应的写入者和读取者。</p>
      </Show>
      <Show when={props.request}>
        {(req) => (
          <>
            <p class="dim small string-prov-summary">
              string @ <code>{req().addr}</code> · len {req().len} · <code class="string-prov-text">{req().text}</code>
            </p>
            <Show when={!resp.loading && resp.error}>
              <p class="err">provenance failed: {String(resp.error)}</p>
            </Show>
            <Show when={resp.loading || currentResp()?.status === "loading"}>
              <p class="dim">memory index loading…</p>
            </Show>
            <Show when={readyResp()}>
              <div class="string-prov-scroll">
                <ProvenanceGraph
                  title="String Byte Flow"
                  nodes={graphNodes()}
                  edges={graphEdges()}
                  summary={graphSummary()}
                  note="每条链路表示：writer trace 写出某个字符字节 → 该字节当前值 → reader trace 读取这个字节。完整 writer/reader 列表仍在下方表格。"
                  empty="no string provenance"
                />
                <table class="string-prov-table">
                  <thead>
                    <tr>
                      <th>addr</th>
                      <th>hex</th>
                      <th>char</th>
                      <th>state</th>
                      <th>writers</th>
                      <th>readers</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={shownBytes()}>
                      {(b) => (
                        <tr>
                          <td><code>{b.addr}</code></td>
                          <td>{hexByte(b.byte)}</td>
                          <td>{printable(b.byte)}</td>
                          <td>{kindLabel(b.kind)}</td>
                          <td class="idx-links">{idxButtons(b, "w")}</td>
                          <td class="idx-links">{idxButtons(b, "r")}</td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </div>
            </Show>
          </>
        )}
      </Show>
    </section>
  );
}
