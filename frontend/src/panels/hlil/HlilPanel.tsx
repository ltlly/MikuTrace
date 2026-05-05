import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js";

import { fetchHlilForPc, fetchIdxsForPc } from "~/api/client";
import type { AsmToken, HlilForPcResponse, HlilLine, HlilVar } from "~/api/types";
import { tokenAddr, tokenClass, tokenReg, tokenText } from "~/utils/bnTokens";
import { createGuardedResource } from "~/utils/resourceGuards";

export interface HlilCursorHint {
  idx: number;
  pc: string;
  func: string | null;
}

export interface HlilPanelProps {
  currentIdx: number;
  currentHint?: HlilCursorHint;
  onSelect: (idx: number) => void;
  active: boolean;
}

interface HlilSource {
  pc: string;
  idx: number;
}

type HlilViewMode = "pseudo" | "hlil";

function parsePc(pc: string | undefined): number | null {
  if (!pc) return null;
  const text = pc.trim();
  if (!text) return null;
  const n = text.startsWith("0x") || text.startsWith("0X")
    ? Number.parseInt(text.slice(2), 16)
    : Number.parseInt(text, 10);
  return Number.isFinite(n) ? n : null;
}

function currentLineIndex(lines: HlilLine[], pc: string | undefined): number {
  const want = parsePc(pc);
  if (want === null) return -1;
  let best = -1;
  let bestPc = -1;
  for (let i = 0; i < lines.length; i += 1) {
    const got = parsePc(lines[i]?.pc);
    if (got === null) continue;
    if (got === want) return i;
    if (got <= want && got > bestPc) {
      best = i;
      bestPc = got;
    }
  }
  return best;
}

function varLabel(v: HlilVar): string {
  const name = v.name ?? "?";
  const ty = v.type ?? v.type_name ?? "?";
  const storage = v.storage ? ` @ ${v.storage}` : "";
  return `${name}: ${ty}${storage}`;
}

function linesForMode(r: HlilForPcResponse | undefined, mode: HlilViewMode): HlilLine[] {
  if (!r) return [];
  if (mode === "hlil") return r.hlil_lines ?? r.lines ?? [];
  return r.pseudo_lines ?? r.lines ?? [];
}

export default function HlilPanel(props: HlilPanelProps) {
  let body: HTMLDivElement | undefined;
  let jumpSeq = 0;
  let jumpAbort: AbortController | undefined;
  const [mode, setMode] = createSignal<HlilViewMode>("pseudo");

  function cancelJump() {
    jumpSeq += 1;
    jumpAbort?.abort();
    jumpAbort = undefined;
  }

  onCleanup(() => cancelJump());

  const source = createMemo<HlilSource | undefined>((prev) => {
    if (!props.active) return undefined;
    const hint = props.currentHint;
    if (!hint || hint.idx !== props.currentIdx || !hint.pc) return undefined;
    const next = { pc: hint.pc, idx: props.currentIdx };
    return prev && prev.pc === next.pc && prev.idx === next.idx ? prev : next;
  });

  const [hlil, currentHlil] = createGuardedResource<HlilSource, HlilForPcResponse>(
    source,
    (s) => fetchHlilForPc(s.pc),
    (r, s) => r.request_pc === s.pc,
  );

  const displayLines = createMemo(() => linesForMode(currentHlil(), mode()));
  const currentDisplayLine = createMemo(() => currentLineIndex(displayLines(), props.currentHint?.pc));

  async function jumpPc(pc: string | null | undefined) {
    if (!pc) return;
    cancelJump();
    const seq = ++jumpSeq;
    const abort = new AbortController();
    jumpAbort = abort;
    try {
      const r = await fetchIdxsForPc(pc, props.currentIdx, 40, abort.signal);
      if (seq !== jumpSeq || abort.signal.aborted) return;
      const candidates = [...r.before, ...r.after];
      if (!candidates.length) return;
      candidates.sort((a, b) => Math.abs(a - props.currentIdx) - Math.abs(b - props.currentIdx));
      props.onSelect(candidates[0]);
    } catch (err) {
      if (abort.signal.aborted || seq !== jumpSeq) return;
      console.warn("HLIL jump failed", err);
    } finally {
      if (jumpAbort === abort) jumpAbort = undefined;
    }
  }

  function tokenSpan(token: AsmToken) {
    const addr = tokenAddr(token);
    const reg = tokenReg(token);
    return (
      <span
        class={tokenClass(token)}
        classList={{ "op-reg": !!reg }}
        data-a={addr ?? undefined}
        title={addr ? `${addr} · double-click jump to nearest trace PC` : undefined}
        onDblClick={(e) => {
          if (!addr) return;
          e.stopPropagation();
          void jumpPc(addr);
        }}
      >
        {tokenText(token)}
      </span>
    );
  }

  function lineText(line: HlilLine) {
    const tokens = line.tokens ?? [];
    if (tokens.length) {
      return <For each={tokens}>{(token) => tokenSpan(token)}</For>;
    }
    return line.text;
  }

  createEffect(() => {
    const r = currentHlil();
    if (!props.active || !r?.ready || !r.ok) return;
    const idx = currentDisplayLine();
    if (idx < 0) return;
    queueMicrotask(() => {
      const el = body?.querySelector<HTMLElement>(`.hlil-line[data-i="${idx}"]`);
      if (!el || !body) return;
      const bodyRect = body.getBoundingClientRect();
      const lineRect = el.getBoundingClientRect();
      if (lineRect.top < bodyRect.top || lineRect.bottom > bodyRect.bottom) {
        el.scrollIntoView({ block: "center" });
      }
    });
  });

  return (
    <section class="panel hlil-panel">
      <h2>HLIL</h2>
      <div class="hlil-controls">
        <div class="hlil-view-toggle" role="tablist" aria-label="HLIL view mode">
          <button
            type="button"
            classList={{ active: mode() === "pseudo" }}
            aria-selected={mode() === "pseudo"}
            onClick={() => setMode("pseudo")}
          >
            Pseudo C
          </button>
          <button
            type="button"
            classList={{ active: mode() === "hlil" }}
            aria-selected={mode() === "hlil"}
            onClick={() => setMode("hlil")}
          >
            HLIL
          </button>
        </div>
        <span class="dim small">
          cursor #{props.currentIdx} · {props.currentHint?.pc ?? "resolving cursor"} ·{" "}
          {props.currentHint?.func ?? "unknown trace fn"}
        </span>
      </div>
      <Show when={!props.currentHint || props.currentHint.idx !== props.currentIdx}>
        <p class="dim small">resolving current trace record…</p>
      </Show>
      <Show when={hlil.loading}>
        <p class="dim small">loading HLIL for current PC…</p>
      </Show>
      <Show when={!hlil.loading && hlil.error}>
        <p class="err">hlil failed: {String(hlil.error)}</p>
      </Show>
      <Show when={currentHlil()}>
        {(r) => (
          <Show
            when={r().ready && r().ok}
            fallback={<p class="dim small">{r().error ?? r().status ?? "BN sidecar is not ready"}</p>}
          >
            <div class="hlil-head">
              <div>
                <b>{r().fn?.name ?? props.currentHint?.func ?? "unknown"}</b>{" "}
                <span class="dim">
                  [{String(r().fn?.start ?? "?")}..{String(r().fn?.end ?? "?")}) · {displayLines().length} lines
                </span>
              </div>
              <Show when={r().trace_fn && r().trace_fn?.name !== r().fn?.name ? r().trace_fn : null}>
                {(traceFn) => (
                  <div class="dim small">
                    trace sym: <code>{traceFn().name}+{traceFn().off ?? "0x0"}</code>
                  </div>
                )}
              </Show>
              <Show when={r().in_range === false}>
                <div class="dim small warn-text">PC is outside the returned BN function range.</div>
              </Show>
              <Show when={(r().vars ?? []).length > 0}>
                <details class="hlil-vars">
                  <summary>vars ({r().vars?.length ?? 0})</summary>
                  <For each={r().vars ?? []}>
                    {(v) => <div class="hlil-var">{varLabel(v)}</div>}
                  </For>
                </details>
              </Show>
            </div>
            <div
              ref={(el) => {
                body = el;
              }}
              class="hlil-body"
            >
              <For each={displayLines()}>
                {(line, i) => (
                  <div
                    class="hlil-line"
                    classList={{ cur: i() === currentDisplayLine() }}
                    data-i={i()}
                    data-pc={line.pc}
                    onClick={() => void jumpPc(line.pc)}
                    title="jump to nearest trace execution"
                  >
                    <span class="hlil-pc">{line.pc}</span>
                    <span class="hlil-code">{lineText(line)}</span>
                  </div>
                )}
              </For>
            </div>
          </Show>
        )}
      </Show>
    </section>
  );
}
