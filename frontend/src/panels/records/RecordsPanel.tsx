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

import {
  fetchBlockForPc,
  fetchIdxsForBlock,
  fetchIdxsForPc,
  fetchLastWriteOfReg,
  fetchMeta,
  fetchRecords,
  fetchRegValueAt,
} from "~/api/client";
import type { RecordRow, RecordsResponse } from "~/api/types";
import { createGuardedResource } from "~/utils/resourceGuards";

const ROW_HEIGHT = 18;
const OVERSCAN = 18;
const SAFE_SCROLL_HEIGHT = 30_000_000;
const REG_RE = /\b(?:x(?:[0-9]|1[0-9]|2[0-9]|30)|w(?:[0-9]|1[0-9]|2[0-9]|30)|sp|fp|lr)\b/gi;

interface RecordsPanelProps {
  selectedIdx: number;
  selectedReg: string;
  onSelect: (idx: number) => void;
  onSelectRow?: (row: RecordRow) => void;
  onSelectReg: (reg: string) => void;
  hiddenSos: Set<string>;
  onOpenMemory: (addr: string) => void;
  onRunTaint: (idx: number, reg: string, direction: "forward" | "backward") => void;
  // Called whenever a new window of rows is fetched. Lets App.tsx populate
  // its (idx -> {pc, func}) cache so non-row-click selections (keyboard,
  // CallTree, hash deep-link, ...) can update cursorHint without paying a
  // /api/record round-trip — the visible rows already carry the data.
  onRowsLoaded?: (rows: RecordRow[]) => void;
}

interface RegContext {
  token: number;
  x: number;
  y: number;
  idx: number;
  reg: string;
  value?: string | null;
  err?: string;
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

function asmParts(asm: string): Array<{ text: string; reg?: string }> {
  const re = /\b(?:x(?:[0-9]|1[0-9]|2[0-9]|30)|w(?:[0-9]|1[0-9]|2[0-9]|30)|sp|fp|lr)\b/gi;
  const parts: Array<{ text: string; reg?: string }> = [];
  let last = 0;
  for (const m of asm.matchAll(re)) {
    const i = m.index ?? 0;
    if (i > last) parts.push({ text: asm.slice(last, i) });
    parts.push({ text: m[0], reg: normalizeReg(m[0]) });
    last = i + m[0].length;
  }
  if (last < asm.length) parts.push({ text: asm.slice(last) });
  return parts.length ? parts : [{ text: asm }];
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

function sameRecordRow(a: RecordRow, b: RecordRow): boolean {
  return (
    a.idx === b.idx &&
    a.pc === b.pc &&
    a.rel === b.rel &&
    a.module === b.module &&
    a.func === b.func &&
    a.off === b.off &&
    a.asm === b.asm &&
    a.annotation === b.annotation &&
    a.exec_count === b.exec_count &&
    a.is_branch === b.is_branch &&
    a.is_call === b.is_call &&
    a.is_ret === b.is_ret
  );
}

export default function RecordsPanel(props: RecordsPanelProps) {
  const [scrollTop, setScrollTop] = createSignal(0);
  const [viewHeight, setViewHeight] = createSignal(0);
  const [regContext, setRegContext] = createSignal<RegContext | null>(null);
  const [optimisticIdx, setOptimisticIdx] = createSignal(props.selectedIdx);
  const [meta] = createResource(fetchMeta);
  const regValueTitleCache = new Map<string, string>();
  const rowObjectCache = new Map<number, RecordRow>();
  let viewport: HTMLDivElement | undefined;
  let regContextSeq = 0;
  let regNavSeq = 0;
  let regContextAbort: AbortController | undefined;

  function cancelRegContext() {
    regContextSeq += 1;
    regNavSeq += 1;
    regContextAbort?.abort();
    regContextAbort = undefined;
  }

  function closeRegContext() {
    cancelRegContext();
    setRegContext(null);
  }

  const totalRecords = createMemo(() => meta()?.records ?? 0);
  const fullHeight = createMemo(() => totalRecords() * ROW_HEIGHT);
  const innerHeight = createMemo(() => Math.min(SAFE_SCROLL_HEIGHT, Math.max(ROW_HEIGHT, fullHeight())));
  const compressed = createMemo(() => fullHeight() > SAFE_SCROLL_HEIGHT);
  // Rounded viewport rows avoid 1px layout jitter flipping fetch count at an
  // exact ROW_HEIGHT boundary. Overscan below still covers the partial row.
  const visibleRows = createMemo(() => Math.max(1, Math.round((viewHeight() || 480) / ROW_HEIGHT)));
  const activeIdx = createMemo(() => optimisticIdx());

  const range = createMemo<{ start: number; count: number; end: number }>(
    (prev) => {
      const total = totalRecords();
      if (total <= 0) return { start: 0, count: 0, end: 0 };

      let next: { start: number; count: number; end: number };

      if (compressed()) {
        const maxScroll = Math.max(1, innerHeight() - (viewHeight() || 1));
        const maxStart = Math.max(0, total - visibleRows());
        const mapped = Math.floor((scrollTop() / maxScroll) * maxStart);
        const start = clamp(mapped - OVERSCAN, 0, maxStart);
        const end = Math.min(total, start + visibleRows() + OVERSCAN * 2);
        next = { start, count: end - start, end };
      } else {
        // Snap scrollTop and viewHeight to ROW_HEIGHT (18px) multiples
        // before computing the window. Without this, sub-pixel browser
        // jitter (subpixel layout, fractional scrollTop on hi-DPI,
        // scrollbar gutter rounding) flips viewHeight or scrollTop by
        // 1px across an 18-multiple boundary, which changes count by 1,
        // refetches /api/records, and the <For> rebuilds every row DOM
        // node. The rebuild can land between mouseDown and mouseUp on a
        // clicked row -> browser drops the click event entirely.
        const sTopRow = Math.floor(scrollTop() / ROW_HEIGHT);
        const vRows = visibleRows();
        const start = clamp(sTopRow - OVERSCAN, 0, total);
        const end = Math.min(total, sTopRow + vRows + OVERSCAN);
        next = { start, count: Math.max(0, end - start), end };
      }

      // Stable reference when nothing actually changed -> createResource
      // does not see a new source value -> no spurious refetch.
      if (
        prev &&
        prev.start === next.start &&
        prev.count === next.count &&
        prev.end === next.end
      ) {
        return prev;
      }
      return next;
    },
  );

  const [resp, currentResp] = createGuardedResource<
    { start: number; count: number; end: number },
    RecordsResponse
  >(
    range,
    (r) => fetchRecords({ start: r.start, count: r.count }),
    (r, s) => r.request_start === s.start && r.request_count === s.count,
  );
  const displayRows = createMemo(() => {
    const rows = currentResp()?.records ?? [];
    if (!rows.length) return rows;
    const visible = new Set<number>();
    const stable = rows.map((row) => {
      visible.add(row.idx);
      const cached = rowObjectCache.get(row.idx);
      if (cached && sameRecordRow(cached, row)) return cached;
      rowObjectCache.set(row.idx, row);
      return row;
    });
    if (rowObjectCache.size > 5000) {
      for (const k of rowObjectCache.keys()) {
        if (rowObjectCache.size <= 5000) break;
        if (!visible.has(k)) rowObjectCache.delete(k);
      }
    }
    return stable;
  });
  let lastAutoScrollIdx = -1;

  createEffect(() => {
    setOptimisticIdx(props.selectedIdx);
  });

  createEffect(() => {
    const rows = displayRows();
    if (rows.length) props.onRowsLoaded?.(rows);
  });

  onMount(() => {
    const syncHeight = () => setViewHeight(viewport?.clientHeight ?? 0);
    syncHeight();
    const ro = new ResizeObserver(syncHeight);
    if (viewport) ro.observe(viewport);
    onCleanup(() => ro.disconnect());
  });

  createEffect(() => {
    if (!regContext()) return;
    const closeOnPointer = (e: PointerEvent) => {
      const target = e.target as Element | null;
      if (target?.closest(".reg-context-menu")) return;
      closeRegContext();
    };
    const closeOnKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeRegContext();
    };
    document.addEventListener("pointerdown", closeOnPointer);
    document.addEventListener("keydown", closeOnKey);
    onCleanup(() => {
      document.removeEventListener("pointerdown", closeOnPointer);
      document.removeEventListener("keydown", closeOnKey);
    });
  });
  onCleanup(() => cancelRegContext());

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
    setOptimisticIdx(row.idx);
    props.onSelect(row.idx);
    props.onSelectRow?.(row);
    const reg = firstAsmReg(row.asm);
    if (reg) props.onSelectReg(reg);
  }

  async function jumpLastWrite(idx: number, reg: string) {
    const navSeq = ++regNavSeq;
    const contextToken = regContext()?.token;
    const r = await fetchLastWriteOfReg(idx, reg);
    if (navSeq !== regNavSeq || regContext()?.token !== contextToken) return;
    if (r.idx !== null && r.idx !== undefined) props.onSelect(r.idx);
  }

  async function jumpPcValue(value: string | null | undefined, idx: number) {
    if (!value) return;
    const navSeq = ++regNavSeq;
    const contextToken = regContext()?.token;
    const r = await fetchIdxsForPc(value, idx, 40);
    if (navSeq !== regNavSeq || regContext()?.token !== contextToken) return;
    const candidates = [...r.before, ...r.after];
    if (!candidates.length) return;
    candidates.sort((a, b) => Math.abs(a - idx) - Math.abs(b - idx));
    props.onSelect(candidates[0]);
  }

  async function jumpCfgAtValue(value: string | null | undefined, idx: number) {
    if (!value) return;
    const navSeq = ++regNavSeq;
    const contextToken = regContext()?.token;
    const block = await fetchBlockForPc(value);
    if (navSeq !== regNavSeq || regContext()?.token !== contextToken) return;
    if (!block.block) {
      setRegContext((current) => (current ? { ...current, err: "PC not in any tracked block" } : current));
      return;
    }
    const idxs = await fetchIdxsForBlock(block.block, 1, idx);
    if (navSeq !== regNavSeq || regContext()?.token !== contextToken) return;
    if (idxs.idxs.length > 0) props.onSelect(idxs.idxs[0]);
    else setRegContext((current) => (current ? { ...current, err: "block not executed in trace" } : current));
  }

  async function loadRegTitle(el: HTMLElement, idx: number, reg: string) {
    const key = `${idx}:${reg}`;
    const cached = regValueTitleCache.get(key);
    if (cached) {
      el.title = cached;
      return;
    }
    try {
      const r = await fetchRegValueAt(idx, reg);
      const annotation = r.annotation ? ` ${r.annotation}` : "";
      const title = r.status === "ready" && r.value ? `${reg} = ${r.value}${annotation}` : `${reg}`;
      regValueTitleCache.set(key, title);
      el.title = title;
    } catch {
      el.title = reg;
    }
  }

  async function openRegContext(e: MouseEvent, row: RecordRow, reg: string) {
    e.preventDefault();
    e.stopPropagation();
    cancelRegContext();
    const token = ++regContextSeq;
    const abort = new AbortController();
    regContextAbort = abort;
    props.onSelect(row.idx);
    props.onSelectReg(reg);
    const base: RegContext = {
      token,
      x: Math.min(e.clientX, window.innerWidth - 300),
      y: Math.min(e.clientY, window.innerHeight - 180),
      idx: row.idx,
      reg,
    };
    setRegContext(base);
    try {
      const r = await fetchRegValueAt(row.idx, reg, abort.signal);
      setRegContext((current) =>
        current?.token === token
          ? { ...current, value: r.value, err: r.error }
          : current,
      );
    } catch (err) {
      if (abort.signal.aborted) return;
      setRegContext((current) =>
        current?.token === token ? { ...current, err: String(err) } : current,
      );
    } finally {
      if (regContextAbort === abort) regContextAbort = undefined;
    }
  }

  return (
    <section class="panel records-panel" onClick={() => closeRegContext()}>
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
        tabIndex={0}
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
      >
        <div class="records-inner" style={{ height: `${innerHeight()}px` }}>
          <Show when={meta.loading || resp.loading}>
            <p class="dim records-loading">loading…</p>
          </Show>
          <Show when={currentResp()?.truncated}>
            <div class="cap-notice records-cap-notice" role="status">
              Records window stopped at {(currentResp()?.max_count_used ?? currentResp()?.count ?? 0).toLocaleString()} rows.
            </div>
          </Show>
          <For each={displayRows()}>
            {(row) => (
              <div
                class="records-row"
                classList={{
                  selected: row.idx === activeIdx(),
                  "is-call": row.is_call,
                  "is-ret": row.is_ret,
                  "is-branch": row.is_branch && !row.is_call && !row.is_ret,
                  "so-hidden": row.module !== null && props.hiddenSos.has(row.module),
                }}
                style={{ top: rowTop(row), height: `${ROW_HEIGHT}px` }}
                tabIndex={0}
                onPointerDown={(e) => {
                  if (e.button === 0) setOptimisticIdx(row.idx);
                }}
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
                  <code>
                    <For each={asmParts(row.asm)}>
                      {(part) => (
                        <Show
                          when={part.reg}
                          fallback={<span>{part.text}</span>}
                        >
                          {(reg) => (
                            <span
                              class="op-reg"
                              classList={{ selected: reg() === normalizeReg(props.selectedReg) }}
                              title={`${reg()} · double-click last write · right-click actions`}
                              onDblClick={(e) => {
                                e.stopPropagation();
                                void jumpLastWrite(row.idx, reg());
                              }}
                              onMouseEnter={(e) => void loadRegTitle(e.currentTarget, row.idx, reg())}
                              onContextMenu={(e) => void openRegContext(e, row, reg())}
                            >
                              {part.text}
                            </span>
                          )}
                        </Show>
                      )}
                    </For>
                  </code>
                </span>
              </div>
            )}
          </For>
          <Show when={regContext()}>
            {(ctx) => (
              <div
                class="reg-context-menu"
                style={{ left: `${ctx().x}px`, top: `${ctx().y}px` }}
                onClick={(e) => e.stopPropagation()}
                onContextMenu={(e) => e.preventDefault()}
              >
                <div class="memory-context-title">
                  {ctx().reg} @ idx {ctx().idx}
                </div>
                <p class="dim small">
                  {ctx().value ? `${ctx().reg} = ${ctx().value}` : ctx().err ?? "loading..."}
                </p>
                <button type="button" onClick={() => void jumpLastWrite(ctx().idx, ctx().reg)}>
                  jump to last write
                </button>
                <Show when={ctx().value}>
                  {(value) => (
                    <>
                      <button type="button" onClick={() => props.onOpenMemory(value())}>
                        open Memory at value
                      </button>
                      <button type="button" onClick={() => void jumpCfgAtValue(value(), ctx().idx)}>
                        CFG view at value
                      </button>
                      <button type="button" onClick={() => void jumpPcValue(value(), ctx().idx)}>
                        jump to nearest PC value
                      </button>
                    </>
                  )}
                </Show>
                <button
                  type="button"
                  onClick={() => {
                    props.onSelectReg(ctx().reg);
                    closeRegContext();
                  }}
                >
                  use for taint
                </button>
                <button type="button" onClick={() => props.onRunTaint(ctx().idx, ctx().reg, "forward")}>
                  run forward taint
                </button>
                <button type="button" onClick={() => props.onRunTaint(ctx().idx, ctx().reg, "backward")}>
                  run backward taint
                </button>
              </div>
            )}
          </Show>
        </div>
      </div>
    </section>
  );
}
