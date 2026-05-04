import { createEffect, createMemo, createResource, createSignal, For, Show } from "solid-js";

import { fetchRecords } from "~/api/client";

const PAGE = 220;
const REG_RE = /\b(?:x(?:[0-9]|1[0-9]|2[0-9]|30)|w(?:[0-9]|1[0-9]|2[0-9]|30)|sp|fp|lr)\b/gi;

interface RecordsPanelProps {
  selectedIdx: number;
  selectedReg: string;
  onSelect: (idx: number) => void;
  onSelectReg: (reg: string) => void;
}

function normalizeReg(reg: string): string {
  const r = reg.toLowerCase();
  if (r === "fp") return "x29";
  if (r === "lr") return "x30";
  if (r.startsWith("w")) return `x${r.slice(1)}`;
  return r;
}

function firstAsmReg(asm: string): string | null {
  const m = asm.match(REG_RE);
  return m?.[0] ? normalizeReg(m[0]) : null;
}

function fnLabel(row: { func: string | null; off: string | null; module: string | null }): string {
  if (row.func) return row.off ? `${row.func}+${row.off}` : row.func;
  return row.module ?? "?";
}

export default function RecordsPanel(props: RecordsPanelProps) {
  const [start, setStart] = createSignal(0);
  const source = createMemo(() => ({ start: start(), count: PAGE }));
  const [resp] = createResource(source, (s) => fetchRecords(s));

  createEffect(() => {
    const r = resp();
    if (!r) return;
    if (props.selectedIdx < r.start || props.selectedIdx >= r.end) {
      setStart(Math.max(0, props.selectedIdx - Math.floor(PAGE / 3)));
    }
  });

  function selectRow(row: { idx: number; asm: string }) {
    props.onSelect(row.idx);
    const reg = firstAsmReg(row.asm);
    if (reg) props.onSelectReg(reg);
  }

  function onScroll(e: Event) {
    const el = e.currentTarget as HTMLElement;
    const r = resp();
    if (!r) return;
    const nearBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 80;
    const nearTop = el.scrollTop <= 20;
    if (nearBottom && r.count >= PAGE) {
      setStart(r.end);
      queueMicrotask(() => {
        el.scrollTop = 24;
      });
    } else if (nearTop && r.start > 0) {
      const next = Math.max(0, r.start - PAGE);
      setStart(next);
      queueMicrotask(() => {
        el.scrollTop = Math.max(0, el.scrollHeight - el.clientHeight - 32);
      });
    }
  }

  return (
    <section class="panel records-panel">
      <h2>Records</h2>
      <Show when={resp.error}>
        <p class="err">load failed: {String(resp.error)}</p>
      </Show>
      <Show when={resp.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={resp()}>
        {(r) => (
          <>
            <div class="records-status">
              <span>
                window {r().start}–{r().end}
              </span>
              <span class="grow" />
              <span>selected idx {props.selectedIdx}</span>
              <span>reg {props.selectedReg}</span>
            </div>
            <div class="records-scroll" onScroll={onScroll}>
              <table class="records-table">
                <tbody>
                  <For each={r().records}>
                    {(row) => (
                      <tr
                        class={row.idx === props.selectedIdx ? "selected" : ""}
                        classList={{
                          "is-call": row.is_call,
                          "is-ret": row.is_ret,
                          "is-branch": row.is_branch && !row.is_call && !row.is_ret,
                        }}
                        tabIndex={0}
                        onClick={() => selectRow(row)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") selectRow(row);
                        }}
                      >
                        <td>{row.idx}</td>
                        <td>
                          <code>{row.pc}</code>
                        </td>
                        <td title={fnLabel(row)}>{fnLabel(row)}</td>
                        <td title={row.asm}>
                          <code>{row.asm}</code>
                        </td>
                        <td>
                          {row.is_call ? "call" : ""}
                          {row.is_ret ? "ret" : ""}
                          {row.is_branch && !row.is_call && !row.is_ret ? "br" : ""}
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </>
        )}
      </Show>
    </section>
  );
}
