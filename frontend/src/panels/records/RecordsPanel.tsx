import {
  createEffect,
  createMemo,
  createResource,
  createSignal,
  For,
  onCleanup,
  onMount,
  Show,
} from "solid-js";

import { fetchMeta, fetchRecords } from "~/api/client";
import type { RecordRow } from "~/api/types";

const ROW_HEIGHT = 18;
const OVERSCAN = 18;
const SAFE_SCROLL_HEIGHT = 30_000_000;
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

function rowKind(row: RecordRow): string {
  if (row.is_call) return "call";
  if (row.is_ret) return "ret";
  if (row.is_branch) return "br";
  return "";
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

export default function RecordsPanel(props: RecordsPanelProps) {
  const [scrollTop, setScrollTop] = createSignal(0);
  const [viewHeight, setViewHeight] = createSignal(0);
  const [meta] = createResource(fetchMeta);
  let viewport: HTMLDivElement | undefined;

  const totalRecords = createMemo(() => meta()?.records ?? 0);
  const fullHeight = createMemo(() => totalRecords() * ROW_HEIGHT);
  const innerHeight = createMemo(() => Math.min(SAFE_SCROLL_HEIGHT, Math.max(ROW_HEIGHT, fullHeight())));
  const compressed = createMemo(() => fullHeight() > SAFE_SCROLL_HEIGHT);
  const visibleRows = createMemo(() => Math.max(1, Math.ceil((viewHeight() || 480) / ROW_HEIGHT)));

  const range = createMemo(() => {
    const total = totalRecords();
    if (total <= 0) return { start: 0, count: 0, end: 0 };

    if (compressed()) {
      const maxScroll = Math.max(1, innerHeight() - (viewHeight() || 1));
      const maxStart = Math.max(0, total - visibleRows());
      const mapped = Math.floor((scrollTop() / maxScroll) * maxStart);
      const start = clamp(mapped - OVERSCAN, 0, maxStart);
      const end = Math.min(total, start + visibleRows() + OVERSCAN * 2);
      return { start, count: end - start, end };
    }

    const start = clamp(Math.floor(scrollTop() / ROW_HEIGHT) - OVERSCAN, 0, total);
    const end = Math.min(
      total,
      Math.ceil((scrollTop() + (viewHeight() || 480)) / ROW_HEIGHT) + OVERSCAN,
    );
    return { start, count: Math.max(0, end - start), end };
  });

  const [resp] = createResource(range, (r) => fetchRecords({ start: r.start, count: r.count }));
  let lastAutoScrollIdx = -1;

  onMount(() => {
    const syncHeight = () => setViewHeight(viewport?.clientHeight ?? 0);
    syncHeight();
    const ro = new ResizeObserver(syncHeight);
    if (viewport) ro.observe(viewport);
    onCleanup(() => ro.disconnect());
  });

  createEffect(() => {
    const selected = props.selectedIdx;
    const total = totalRecords();
    const h = viewHeight();
    if (!viewport || !total || !h) return;
    if (selected === lastAutoScrollIdx) return;
    lastAutoScrollIdx = selected;
    const idx = clamp(selected, 0, total - 1);
    const rowTop = compressed()
      ? (idx / Math.max(1, total - 1)) * Math.max(1, innerHeight() - h)
      : idx * ROW_HEIGHT;
    const rowBottom = rowTop + ROW_HEIGHT;
    if (rowTop >= scrollTop() && rowBottom <= scrollTop() + h) return;
    const next = clamp(rowTop - Math.floor(h / 3), 0, Math.max(0, innerHeight() - h));
    viewport.scrollTop = next;
    setScrollTop(next);
  });

  function rowTop(row: RecordRow): string {
    if (!compressed()) return `${row.idx * ROW_HEIGHT}px`;
    return `${scrollTop() + (row.idx - range().start) * ROW_HEIGHT}px`;
  }

  function selectRow(row: RecordRow) {
    props.onSelect(row.idx);
    const reg = firstAsmReg(row.asm);
    if (reg) props.onSelectReg(reg);
  }

  return (
    <section class="panel records-panel">
      <h2>Records</h2>
      <Show when={meta.error}>
        <p class="err">meta failed: {String(meta.error)}</p>
      </Show>
      <Show when={resp.error}>
        <p class="err">load failed: {String(resp.error)}</p>
      </Show>
      <div class="records-status">
        <span>
          window {range().start}-{range().end} / {totalRecords().toLocaleString()}
        </span>
        <span class="grow" />
        <span>selected idx {props.selectedIdx}</span>
        <span>reg {props.selectedReg}</span>
      </div>
      <div
        ref={(el) => {
          viewport = el;
        }}
        class="records-virtual"
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
      >
        <div class="records-inner" style={{ height: `${innerHeight()}px` }}>
          <Show when={meta.loading || resp.loading}>
            <p class="dim records-loading">loading…</p>
          </Show>
          <For each={resp()?.records ?? []}>
            {(row) => (
              <div
                class="records-row"
                classList={{
                  selected: row.idx === props.selectedIdx,
                  "is-call": row.is_call,
                  "is-ret": row.is_ret,
                  "is-branch": row.is_branch && !row.is_call && !row.is_ret,
                }}
                style={{ top: rowTop(row), height: `${ROW_HEIGHT}px` }}
                tabIndex={0}
                onClick={() => selectRow(row)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") selectRow(row);
                }}
              >
                <span class="dot">{rowKind(row)}</span>
                <span class="idx">{row.idx}</span>
                <span class="pc">
                  <code>{row.pc}</code>
                </span>
                <span class="func" title={fnLabel(row)}>
                  {fnLabel(row)}
                </span>
                <span class="asm" title={row.asm}>
                  <code>{row.asm}</code>
                </span>
              </div>
            )}
          </For>
        </div>
      </div>
    </section>
  );
}
