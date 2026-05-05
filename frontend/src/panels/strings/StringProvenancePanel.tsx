import { createEffect, createMemo, createResource, createSignal, For, onCleanup, Show } from "solid-js";

import { fetchStringProvenance } from "~/api/client";
import type { StringProvByte } from "~/api/types";

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
}

interface Source {
  token: number;
  addr: string;
  len: number;
  retry: number;
}

const PROVENANCE_RETRY_MS = 500;

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
  const [resp] = createResource(source, (s) => fetchStringProvenance(s.addr, s.len));
  const currentResp = createMemo(() => {
    const r = resp();
    const s = source();
    if (!r || !s) return undefined;
    return r.addr === s.addr && r.length === s.len ? r : undefined;
  });
  const readyResp = createMemo(() => {
    const r = currentResp();
    return r?.status === "ready" ? r : undefined;
  });

  const shownBytes = createMemo(() => {
    const bytes = readyResp()?.bytes ?? [];
    const nul = bytes.findIndex((b) => b.byte === 0);
    return nul >= 0 ? bytes.slice(0, nul + 1) : bytes;
  });

  createEffect(() => {
    if (!props.active || resp.loading || currentResp()?.status !== "loading") return;
    const timer = window.setTimeout(() => setRetry((n) => n + 1), PROVENANCE_RETRY_MS);
    onCleanup(() => window.clearTimeout(timer));
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
