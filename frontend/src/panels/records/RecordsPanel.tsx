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
  fetchAsmTokensForPcs,
  fetchCallTree,
  fetchIdxsForBlock,
  fetchIdxsForPc,
  fetchLastWriteOfReg,
  fetchMeta,
  fetchNextUseOfReg,
  fetchRecords,
  fetchRegValueAt,
} from "~/api/client";
import type { AsmToken, CallNode, CallTreeResponse, RecordRow, RecordsResponse } from "~/api/types";
import { normalizeReg, tokenAddr, tokenClass, tokenReg, tokenText } from "~/utils/bnTokens";
import { createGuardedResource } from "~/utils/resourceGuards";

const ROW_HEIGHT = 18;
const OVERSCAN = 18;
const SAFE_SCROLL_HEIGHT = 15_000_000;
const FOLDED_FETCH_BATCH_RANGES = 24;
const REG_RE = /\b(?:x(?:[0-9]|1[0-9]|2[0-9]|30)|w(?:[0-9]|1[0-9]|2[0-9]|30)|sp|fp|lr)\b/gi;
const ROW_MARKS_PREFIX = "tracemiku-row-marks:";
const ROW_MARK_COLORS = ["red", "yellow", "green", "blue", "violet"] as const;
type RowMarkColor = (typeof ROW_MARK_COLORS)[number];

export type RecordsTaintOverlayMode = "highlight" | "dim" | "only";

export interface RecordsVisibleNavigator {
  nextVisibleIdx: (idx: number, delta: number) => number;
}

export interface RecordsTaintOverlay {
  idxs: Set<number>;
  rows: RecordRow[];
  direction: "forward" | "backward";
  from: number;
  reg: string;
  count: number;
  stopped: boolean;
  mode: RecordsTaintOverlayMode;
}

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
  onVisibleNavigator?: (navigator: RecordsVisibleNavigator | null) => void;
  taintOverlay?: RecordsTaintOverlay | null;
  onTaintOverlayModeChange?: (mode: RecordsTaintOverlayMode) => void;
  onClearTaintOverlay?: () => void;
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

interface RowContext {
  x: number;
  y: number;
  idx: number;
  pc: string;
}

interface RowMark {
  color?: RowMarkColor;
  strike?: boolean;
  muted?: boolean;
  note?: string;
}

interface MinimapMark {
  idx: number;
  topPct: number;
  kind: "selected" | "taint" | "mark";
  color?: RowMarkColor;
  title: string;
}

interface FoldRange {
  key: string;
  enter: number;
  exit: number;
  fn: string;
  depth: number;
}

interface FoldFetchRange {
  start: number;
  count: number;
}

interface RowSelection {
  anchor: number;
  focus: number;
}

interface RegFlow {
  token: number;
  sourceIdx: number;
  reg: string;
  defIdx: number | null;
  useIdx: number | null;
  loading: boolean;
  defErr?: string;
  useErr?: string;
  err?: string;
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

function regFlowLabel(kind: "def" | "use" | "def-use"): string {
  if (kind === "def") return "▲";
  if (kind === "use") return "▼";
  return "↕";
}

function foldKey(node: CallNode): string {
  return `${node.depth}:${node.enter_idx}:${node.exit_idx}:${node.fn ?? "?"}`;
}

function collectFoldRanges(node: CallNode, out: FoldRange[] = []): FoldRange[] {
  if (node.depth > 0 && node.exit_idx > node.enter_idx) {
    out.push({
      key: foldKey(node),
      enter: node.enter_idx,
      exit: node.exit_idx,
      fn: node.fn ?? "?",
      depth: node.depth,
    });
  }
  for (const child of node.children ?? []) collectFoldRanges(child, out);
  return out;
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

function isRowMarkColor(value: unknown): value is RowMarkColor {
  return typeof value === "string" && (ROW_MARK_COLORS as readonly string[]).includes(value);
}

function compactRowMark(mark: RowMark): RowMark | null {
  const next: RowMark = {};
  if (isRowMarkColor(mark.color)) next.color = mark.color;
  if (mark.strike) next.strike = true;
  if (mark.muted) next.muted = true;
  const note = mark.note?.trim();
  if (note) next.note = note;
  return Object.keys(next).length ? next : null;
}

function loadRowMarks(key: string): Map<number, RowMark> {
  try {
    const raw = localStorage.getItem(key);
    const parsed = raw ? JSON.parse(raw) : {};
    const next = new Map<number, RowMark>();
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return next;
    for (const [idxRaw, value] of Object.entries(parsed)) {
      const idx = Number(idxRaw);
      if (!Number.isInteger(idx) || idx < 0 || !value || typeof value !== "object" || Array.isArray(value)) {
        continue;
      }
      const mark = compactRowMark(value as RowMark);
      if (mark) next.set(idx, mark);
    }
    return next;
  } catch {
    return new Map();
  }
}

function saveRowMarks(key: string, marks: Map<number, RowMark>) {
  const serialized: Record<string, RowMark> = {};
  for (const [idx, mark] of marks) {
    const compact = compactRowMark(mark);
    if (compact) serialized[String(idx)] = compact;
  }
  try {
    if (Object.keys(serialized).length) localStorage.setItem(key, JSON.stringify(serialized));
    else localStorage.removeItem(key);
  } catch {
    /* ignore */
  }
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
  const [rowContext, setRowContext] = createSignal<RowContext | null>(null);
  const [rowMarks, setRowMarks] = createSignal<Map<number, RowMark>>(new Map());
  const [recordsLoadingVisible, setRecordsLoadingVisible] = createSignal(false);
  const [optimisticIdx, setOptimisticIdx] = createSignal(props.selectedIdx);
  const [collapsedCalls, setCollapsedCalls] = createSignal<Set<string>>(new Set());
  const [rowSelection, setRowSelection] = createSignal<RowSelection | null>(null);
  const [regFlow, setRegFlow] = createSignal<RegFlow | null>(null);
  const [rowCacheVersion, setRowCacheVersion] = createSignal(0);
  const [foldedRowsLoading, setFoldedRowsLoading] = createSignal(false);
  const [foldTreeRequested, setFoldTreeRequested] = createSignal(false);
  const [meta] = createResource(fetchMeta);
  const [callTreeResp, currentCallTreeResp] = createGuardedResource<number, CallTreeResponse>(
    () => (foldTreeRequested() ? 50 : undefined),
    (depth) => fetchCallTree(depth),
    (resp, depth) => (resp.request_max_depth ?? 50) === depth,
  );
  const regValueTitleCache = new Map<string, string>();
  const rowObjectCache = new Map<number, RecordRow>();
  const bnTokenCache = new Map<string, AsmToken[] | null>();
  const bnTokenInflight = new Set<string>();
  const [bnTokenVersion, setBnTokenVersion] = createSignal(0);
  const [bnTokenStatus, setBnTokenStatus] = createSignal("");
  const [bnTokensDisabled, setBnTokensDisabled] = createSignal(false);
  let viewport: HTMLDivElement | undefined;
  let regContextSeq = 0;
  let regNavSeq = 0;
  let regFlowSeq = 0;
  let regContextAbort: AbortController | undefined;
  let regFlowAbort: AbortController | undefined;
  let bnTokenTimer: number | undefined;
  let bnTokenAbort: AbortController | undefined;
  let recordsLoadingTimer: number | undefined;
  const foldedFetchInflight = new Set<number>();

  function cancelRegContext() {
    regContextSeq += 1;
    regNavSeq += 1;
    regContextAbort?.abort();
    regContextAbort = undefined;
  }

  function cancelRegFlow() {
    regFlowSeq += 1;
    regFlowAbort?.abort();
    regFlowAbort = undefined;
  }

  function clearRegFlow() {
    cancelRegFlow();
    setRegFlow(null);
  }

  function closeRegContext() {
    cancelRegContext();
    setRegContext(null);
    clearRegFlow();
  }

  function closeRowContext() {
    setRowContext(null);
  }

  const totalRecords = createMemo(() => meta()?.records ?? 0);
  const rowMarksKey = createMemo(() => {
    const path = meta()?.path;
    return path ? `${ROW_MARKS_PREFIX}${path}` : null;
  });
  const taintOnlyRows = createMemo(() =>
    props.taintOverlay?.mode === "only" ? props.taintOverlay.rows : null,
  );
  const taintOnlyPositions = createMemo(() => {
    const rows = taintOnlyRows();
    if (!rows) return new Map<number, number>();
    return new Map(rows.map((row, pos) => [row.idx, pos]));
  });
  // Rounded viewport rows avoid 1px layout jitter flipping fetch count at an
  // exact ROW_HEIGHT boundary. Overscan below still covers the partial row.
  const visibleRows = createMemo(() => Math.max(1, Math.round((viewHeight() || 480) / ROW_HEIGHT)));
  const activeIdx = createMemo(() => optimisticIdx());
  const foldRanges = createMemo(() => {
    const tree = currentCallTreeResp()?.tree;
    return tree ? collectFoldRanges(tree) : [];
  });
  const foldRangeByEnter = createMemo(() => new Map(foldRanges().map((range) => [range.enter, range])));
  const collapsedFoldRanges = createMemo(() => {
    const collapsed = collapsedCalls();
    return foldRanges()
      .filter((range) => collapsed.has(range.key))
      .sort((a, b) => a.enter - b.enter || a.exit - b.exit);
  });
  const visibleFoldRanges = createMemo(() => {
    const out: FoldRange[] = [];
    const sorted = [...collapsedFoldRanges()].sort((a, b) => a.enter - b.enter || b.exit - a.exit);
    for (const range of sorted) {
      if (range.exit <= range.enter) continue;
      const last = out[out.length - 1];
      if (last && range.enter <= last.exit) {
        if (range.exit > last.exit) last.exit = range.exit;
        continue;
      }
      out.push({ ...range });
    }
    return out;
  });
  const foldedCompact = createMemo(() => visibleFoldRanges().length > 0);
  const foldedVisibleTotal = createMemo(() => {
    const hidden = visibleFoldRanges().reduce((sum, range) => sum + Math.max(0, range.exit - range.enter), 0);
    return Math.max(0, totalRecords() - hidden);
  });
  const virtualTotalRecords = createMemo(() =>
    taintOnlyRows()?.length ?? (foldedCompact() ? foldedVisibleTotal() : totalRecords()),
  );
  const fullHeight = createMemo(() => virtualTotalRecords() * ROW_HEIGHT);
  const innerHeight = createMemo(() => Math.min(SAFE_SCROLL_HEIGHT, Math.max(ROW_HEIGHT, fullHeight())));
  const compressed = createMemo(() => fullHeight() > SAFE_SCROLL_HEIGHT);

  const rawRange = createMemo<{ start: number; count: number; end: number }>(
    (prev) => {
      const total = virtualTotalRecords();
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
        // Clamp `start` so it can never run past `total - vRows`. Without
        // this, a stale scrollTop signal (e.g. right after a taint-only
        // mode switch shrinks `virtualTotalRecords`) drives start past
        // the end of the array, slice yields [], and the panel paints
        // empty rows.
        const maxStart = Math.max(0, total - vRows);
        const start = clamp(sTopRow - OVERSCAN, 0, maxStart);
        const end = Math.min(total, start + vRows + OVERSCAN * 2);
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
  const range = createMemo<{ start: number; count: number; end: number } | undefined>(() =>
    taintOnlyRows() || foldedCompact() ? undefined : rawRange(),
  );

  const [resp, currentResp] = createGuardedResource<
    { start: number; count: number; end: number },
    RecordsResponse
  >(
    range,
    (r) => fetchRecords({ start: r.start, count: r.count }),
    (r, s) => r.request_start === s.start && r.request_count === s.count,
  );
  function stabilizeRows(rows: RecordRow[]): RecordRow[] {
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
  }
  const displayRows = createMemo(() => {
    const onlyRows = taintOnlyRows();
    if (onlyRows) {
      const r = rawRange();
      return onlyRows.slice(r.start, r.end);
    }
    if (foldedCompact()) {
      rowCacheVersion();
      return foldedWindowActualIdxs().map((idx) => rowObjectCache.get(idx) ?? placeholderRow(idx));
    }
    const freshRows = currentResp()?.records;
    if (freshRows) return stabilizeRows(freshRows);
    const r = rawRange();
    if (r.count <= 0) return [];
    const cachedRows: RecordRow[] = [];
    for (let idx = r.start; idx < r.end; idx += 1) {
      const row = rowObjectCache.get(idx);
      if (row) cachedRows.push(row);
    }
    return cachedRows;
  });
  const showRecordsLoading = createMemo(() => recordsLoadingVisible());
  let lastAutoScrollIdx = -1;

  createEffect(() => {
    setOptimisticIdx(props.selectedIdx);
  });

  createEffect(() => {
    const rows = displayRows();
    const readyRows = rows.filter((row) => row.pc);
    if (readyRows.length) props.onRowsLoaded?.(readyRows);
  });

  createEffect(() => {
    const pending = ((meta.loading || resp.loading) && displayRows().length === 0) || foldedRowsLoading();
    if (pending) {
      if (recordsLoadingTimer === undefined && !recordsLoadingVisible()) {
        recordsLoadingTimer = window.setTimeout(() => {
          recordsLoadingTimer = undefined;
          setRecordsLoadingVisible(true);
        }, 120);
      }
      return;
    }
    if (recordsLoadingTimer !== undefined) {
      window.clearTimeout(recordsLoadingTimer);
      recordsLoadingTimer = undefined;
    }
    setRecordsLoadingVisible(false);
  });

  createEffect(() => {
    const key = rowMarksKey();
    setRowMarks(key ? loadRowMarks(key) : new Map());
  });

  createEffect(() => {
    if (!foldedCompact()) return;
    const missing = foldedWindowActualIdxs().filter((idx) => !rowObjectCache.has(idx) && !foldedFetchInflight.has(idx));
    if (!missing.length) return;
    void fetchFoldedRows(missing);
  });

  onMount(() => {
    const syncHeight = () => setViewHeight(viewport?.clientHeight ?? 0);
    syncHeight();
    const ro = new ResizeObserver(syncHeight);
    if (viewport) ro.observe(viewport);
    props.onVisibleNavigator?.({ nextVisibleIdx });
    onCleanup(() => {
      ro.disconnect();
      props.onVisibleNavigator?.(null);
    });
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
  createEffect(() => {
    if (!rowContext()) return;
    const closeOnPointer = (e: PointerEvent) => {
      const target = e.target as Element | null;
      if (target?.closest(".row-context-menu")) return;
      closeRowContext();
    };
    const closeOnKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeRowContext();
    };
    document.addEventListener("pointerdown", closeOnPointer);
    document.addEventListener("keydown", closeOnKey);
    onCleanup(() => {
      document.removeEventListener("pointerdown", closeOnPointer);
      document.removeEventListener("keydown", closeOnKey);
    });
  });
  createEffect(() => {
    if (!regFlow()) return;
    const clearOnKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") clearRegFlow();
    };
    document.addEventListener("keydown", clearOnKey);
    onCleanup(() => document.removeEventListener("keydown", clearOnKey));
  });
  onCleanup(() => cancelRegContext());
  onCleanup(() => cancelRegFlow());
  onCleanup(() => {
    if (bnTokenTimer !== undefined) window.clearTimeout(bnTokenTimer);
    bnTokenAbort?.abort();
    if (recordsLoadingTimer !== undefined) window.clearTimeout(recordsLoadingTimer);
  });

  function pcKey(pc: string): string {
    return pc.trim().toLowerCase();
  }

  function tokensForPc(pc: string): AsmToken[] | null {
    bnTokenVersion();
    const cached = bnTokenCache.get(pcKey(pc));
    return cached && cached.length ? cached : null;
  }

  function scheduleBnAsmFetch() {
    if (bnTokensDisabled()) return;
    if (bnTokenAbort) return;
    if (bnTokenTimer !== undefined) return;
    bnTokenTimer = window.setTimeout(() => {
      bnTokenTimer = undefined;
      void fetchBnAsmTokensForVisibleRows();
    }, 60);
  }

  async function fetchBnAsmTokensForVisibleRows() {
    if (bnTokensDisabled()) return;
    if (bnTokenAbort) return;
    const need: string[] = [];
    for (const row of displayRows()) {
      const key = pcKey(row.pc);
      if (!key || bnTokenCache.has(key) || bnTokenInflight.has(key)) continue;
      bnTokenInflight.add(key);
      need.push(row.pc);
      if (need.length >= 256) break;
    }
    if (!need.length) return;
    const abort = new AbortController();
    bnTokenAbort = abort;
    try {
      const r = await fetchAsmTokensForPcs(need, abort.signal);
      if (abort.signal.aborted) return;
      if (!r.ready) {
        setBnTokenStatus(r.status || r.error || "not ready");
        setBnTokensDisabled(true);
        return;
      }
      if (r.status !== "ok") {
        setBnTokenStatus(r.status);
        return;
      }
      const got = r.tokens ?? {};
      for (const pc of need) {
        const key = pcKey(pc);
        const tokens = got[key] ?? got[pc] ?? got[pc.toLowerCase()];
        bnTokenCache.set(key, tokens && tokens.length ? tokens : null);
      }
      while (bnTokenCache.size > 50_000) {
        const k = bnTokenCache.keys().next().value as string | undefined;
        if (!k) break;
        bnTokenCache.delete(k);
      }
      setBnTokenStatus("ok");
      setBnTokenVersion((v) => v + 1);
    } catch (err) {
      if (abort.signal.aborted) return;
      setBnTokenStatus(String(err));
    } finally {
      for (const pc of need) bnTokenInflight.delete(pcKey(pc));
      if (bnTokenAbort === abort) bnTokenAbort = undefined;
      if (!abort.signal.aborted && !bnTokensDisabled() && displayRows().some((row) => !bnTokenCache.has(pcKey(row.pc)))) {
        scheduleBnAsmFetch();
      }
    }
  }

  createEffect(() => {
    displayRows();
    scheduleBnAsmFetch();
  });

  // When the virtual coordinate system shrinks (e.g. taint overlay flipped
  // to "only" mode and total dropped from millions to hundreds), the
  // browser auto-clamps `viewport.scrollTop`. Sync the signal so
  // `rawRange` stops returning empty windows, and reset the auto-scroll
  // guard so the next selection re-centers in the new coordinate space.
  //
  // CRITICAL: this effect must only fire on coordinate-system change. If
  // it tracks `scrollTop()` reactively, every user wheel tick re-runs it,
  // which resets `lastAutoScrollIdx` and then the auto-scroll effect at
  // the bottom force-snaps the viewport back to the selected row's slot —
  // user scroll becomes impossible.
  let lastVirtualTotal = -1;
  createEffect(() => {
    const total = virtualTotalRecords();
    if (total === lastVirtualTotal) return;
    lastVirtualTotal = total;
    if (!viewport) return;
    const h = viewHeight();
    if (!h) return;
    const maxScroll = Math.max(0, innerHeight() - h);
    // Read scrollTop ONCE non-reactively — we just need its current value
    // for clamping, not a subscription.
    const current = viewport.scrollTop;
    if (current > maxScroll) {
      viewport.scrollTop = maxScroll;
      setScrollTop(maxScroll);
    }
    lastAutoScrollIdx = -1;
  });

  createEffect(() => {
    const selected = props.selectedIdx;
    const onlyPositions = taintOnlyPositions();
    const onlyRows = taintOnlyRows();
    const total = virtualTotalRecords();
    const h = viewHeight();
    if (!viewport || !total || !h) return;
    if (selected === lastAutoScrollIdx) return;
    lastAutoScrollIdx = selected;
    const idx = onlyRows
      ? onlyPositions.get(selected)
      : foldedCompact()
        ? actualIdxToFoldedPos(selected)
        : clamp(selected, 0, total - 1);
    if (idx === undefined) return;
    if (compressed()) {
      // In compressed mode, scrollTop maps linearly to rawRange.start via
      //   start = floor(scrollTop / maxScroll * maxStart)
      // and visible rows are [start, start + vRows]. The previous logic
      // treated `(idx / total) * innerHeight` as the row's pixel position
      // and bailed when that scalar was inside the viewport — but it's
      // actually the *target* scrollTop, not a y-coordinate. We compare
      // against the visible idx range instead.
      const maxScroll = Math.max(1, innerHeight() - h);
      const maxStart = Math.max(0, total - visibleRows());
      const currentStart = Math.floor((scrollTop() / maxScroll) * maxStart);
      const visibleEnd = currentStart + visibleRows();
      if (idx >= currentStart + 2 && idx <= visibleEnd - 2) return;
      const targetStart = clamp(idx - Math.floor(visibleRows() / 3), 0, maxStart);
      const next =
        maxStart > 0 ? Math.round((targetStart / maxStart) * maxScroll) : 0;
      viewport.scrollTop = next;
      setScrollTop(next);
      return;
    }
    const rowTop = idx * ROW_HEIGHT;
    const rowBottom = rowTop + ROW_HEIGHT;
    if (rowTop >= scrollTop() && rowBottom <= scrollTop() + h) return;
    const next = clamp(rowTop - Math.floor(h / 3), 0, Math.max(0, innerHeight() - h));
    viewport.scrollTop = next;
    setScrollTop(next);
  });

  function actualIdxToFoldedPos(idx: number): number {
    let hiddenBefore = 0;
    for (const range of visibleFoldRanges()) {
      if (idx <= range.enter) break;
      if (idx <= range.exit) return range.enter - hiddenBefore;
      hiddenBefore += range.exit - range.enter;
    }
    return clamp(idx - hiddenBefore, 0, Math.max(0, foldedVisibleTotal() - 1));
  }

  function foldedPosToActualIdx(pos: number): number {
    let hiddenBefore = 0;
    const p = clamp(pos, 0, Math.max(0, foldedVisibleTotal() - 1));
    for (const range of visibleFoldRanges()) {
      const visibleEnter = range.enter - hiddenBefore;
      if (p <= visibleEnter) return p + hiddenBefore;
      hiddenBefore += range.exit - range.enter;
    }
    return clamp(p + hiddenBefore, 0, Math.max(0, totalRecords() - 1));
  }

  function nextVisibleIdx(idx: number, delta: number): number {
    if (delta === 0) return clamp(idx, 0, Math.max(0, totalRecords() - 1));
    const onlyRows = taintOnlyRows();
    if (onlyRows) {
      const positions = taintOnlyPositions();
      const current = positions.get(idx) ?? 0;
      const next = clamp(current + delta, 0, Math.max(0, onlyRows.length - 1));
      return onlyRows[next]?.idx ?? clamp(idx + delta, 0, Math.max(0, totalRecords() - 1));
    }
    if (foldedCompact()) {
      const current = actualIdxToFoldedPos(idx);
      return foldedPosToActualIdx(current + delta);
    }
    return clamp(idx + delta, 0, Math.max(0, totalRecords() - 1));
  }

  function foldedWindowActualIdxs(): number[] {
    if (!foldedCompact()) return [];
    const r = rawRange();
    const out: number[] = [];
    for (let pos = r.start; pos < r.end; pos += 1) {
      out.push(foldedPosToActualIdx(pos));
    }
    return out;
  }

  function groupFetchRanges(idxs: number[]): FoldFetchRange[] {
    const sorted = [...new Set(idxs)].sort((a, b) => a - b);
    const ranges: FoldFetchRange[] = [];
    for (const idx of sorted) {
      const last = ranges[ranges.length - 1];
      if (last && idx === last.start + last.count) {
        last.count += 1;
      } else {
        ranges.push({ start: idx, count: 1 });
      }
    }
    return ranges;
  }

  async function fetchFoldedRows(idxs: number[]) {
    const ranges = groupFetchRanges(idxs);
    for (const idx of idxs) foldedFetchInflight.add(idx);
    setFoldedRowsLoading(true);
    try {
      for (let i = 0; i < ranges.length; i += FOLDED_FETCH_BATCH_RANGES) {
        await Promise.all(
          ranges.slice(i, i + FOLDED_FETCH_BATCH_RANGES).map(async (range) => {
            const r = await fetchRecords({ start: range.start, count: range.count });
            stabilizeRows(r.records);
          }),
        );
      }
      setRowCacheVersion((v) => v + 1);
    } catch (err) {
      console.warn("folded records fetch failed", err);
    } finally {
      for (const idx of idxs) foldedFetchInflight.delete(idx);
      setFoldedRowsLoading(false);
    }
  }

  function foldedRangeForRow(row: RecordRow): FoldRange | undefined {
    const range = foldRangeByEnter().get(row.idx);
    return range && collapsedCalls().has(range.key) ? range : undefined;
  }

  function foldableRangeForRow(row: RecordRow): FoldRange | undefined {
    return foldRangeByEnter().get(row.idx);
  }

  function toggleFoldRange(range: FoldRange) {
    setCollapsedCalls((current) => {
      const next = new Set(current);
      if (next.has(range.key)) next.delete(range.key);
      else next.add(range.key);
      return next;
    });
  }

  function rowTop(row: RecordRow): string {
    return `${pixelTopForIdx(row.idx)}px`;
  }

  /// Pixel y-coordinate the row at `idx` would occupy in the records-inner
  /// container. Mirrors `rowTop` but works for an arbitrary idx (used by the
  /// def/use SVG overlay, which has to render targets that may not be in
  /// `displayRows`).
  function pixelTopForIdx(idx: number): number {
    if (taintOnlyRows()) {
      return (taintOnlyPositions().get(idx) ?? 0) * ROW_HEIGHT;
    }
    if (foldedCompact()) {
      const foldedPos = actualIdxToFoldedPos(idx);
      if (!compressed()) return foldedPos * ROW_HEIGHT;
      return scrollTop() + (foldedPos - rawRange().start) * ROW_HEIGHT;
    }
    if (!compressed()) return idx * ROW_HEIGHT;
    return scrollTop() + (idx - rawRange().start) * ROW_HEIGHT;
  }

  /// Centre y of the row at `idx` (for the SVG arrow's endpoints).
  function pixelCenterForIdx(idx: number): number {
    return pixelTopForIdx(idx) + Math.floor(ROW_HEIGHT / 2);
  }

  function nextTaintMode(mode: RecordsTaintOverlayMode): RecordsTaintOverlayMode {
    if (mode === "highlight") return "dim";
    if (mode === "dim") return "only";
    return "highlight";
  }

  function taintModeLabel(mode: RecordsTaintOverlayMode): string {
    if (mode === "highlight") return "highlight";
    if (mode === "dim") return "dim non-hits";
    return "taint only";
  }

  function pctForIdx(idx: number): number {
    const total = virtualTotalRecords();
    if (total <= 1) return 0;
    if (taintOnlyRows()) {
      const pos = taintOnlyPositions().get(idx);
      return pos === undefined ? 0 : (pos / (total - 1)) * 100;
    }
    if (foldedCompact()) {
      return (actualIdxToFoldedPos(idx) / (total - 1)) * 100;
    }
    return (clamp(idx, 0, total - 1) / (total - 1)) * 100;
  }

  const minimapMarks = createMemo<MinimapMark[]>(() => {
    const total = virtualTotalRecords();
    if (total <= 0) return [];
    const out: MinimapMark[] = [
      {
        idx: activeIdx(),
        topPct: pctForIdx(activeIdx()),
        kind: "selected",
        title: `selected #${activeIdx()}`,
      },
    ];
    const overlay = props.taintOverlay;
    if (overlay) {
      const maxMarks = 1200;
      const stride = Math.max(1, Math.ceil(overlay.rows.length / maxMarks));
      for (let i = 0; i < overlay.rows.length; i += stride) {
        const idx = overlay.rows[i].idx;
        out.push({
          idx,
          topPct: pctForIdx(idx),
          kind: "taint",
          title: `taint #${idx}`,
        });
      }
    }
    for (const [idx, mark] of rowMarks()) {
      if (taintOnlyRows() && !taintOnlyPositions().has(idx)) continue;
      out.push({
        idx,
        topPct: pctForIdx(idx),
        kind: "mark",
        color: mark.color,
        title: mark.note ? `#${idx}: ${mark.note}` : `marked #${idx}`,
      });
    }
    return out;
  });

  function placeholderRow(idx: number): RecordRow {
    return {
      idx,
      pc: "",
      rel: null,
      module: null,
      func: null,
      off: null,
      asm: "",
      annotation: null,
      exec_count: null,
      is_branch: false,
      is_call: false,
      is_ret: false,
    };
  }

  function jumpMinimap(e: MouseEvent) {
    const target = e.currentTarget as HTMLElement;
    const rect = target.getBoundingClientRect();
    const ratio = clamp((e.clientY - rect.top) / Math.max(1, rect.height), 0, 1);
    const only = taintOnlyRows();
    if (only) {
      const pos = clamp(Math.round(ratio * Math.max(0, only.length - 1)), 0, Math.max(0, only.length - 1));
      const row = only[pos];
      if (row) selectRow(row);
      return;
    }
    const idx = Math.round(ratio * Math.max(0, totalRecords() - 1));
    const actualIdx = foldedCompact()
      ? foldedPosToActualIdx(Math.round(ratio * Math.max(0, virtualTotalRecords() - 1)))
      : idx;
    selectRow(rowObjectCache.get(actualIdx) ?? placeholderRow(actualIdx));
  }

  function normalizedSelection(): { start: number; end: number } | null {
    const selection = rowSelection();
    if (!selection) return null;
    return {
      start: Math.min(selection.anchor, selection.focus),
      end: Math.max(selection.anchor, selection.focus),
    };
  }

  function rowInSelection(idx: number): boolean {
    const selection = normalizedSelection();
    return !!selection && idx >= selection.start && idx <= selection.end;
  }

  function markTargetIdxs(idx: number): number[] {
    const selection = normalizedSelection();
    if (!selection || idx < selection.start || idx > selection.end) return [idx];
    const out: number[] = [];
    for (let i = selection.start; i <= selection.end; i += 1) out.push(i);
    return out;
  }

  function selectionLabel(idx: number): string {
    const selection = normalizedSelection();
    if (!selection || idx < selection.start || idx > selection.end || selection.start === selection.end) {
      return `row #${idx}`;
    }
    return `rows #${selection.start}..#${selection.end}`;
  }

  function selectRow(row: RecordRow, e?: MouseEvent) {
    const anchor = rowSelection()?.anchor ?? activeIdx();
    setOptimisticIdx(row.idx);
    if (e?.shiftKey) setRowSelection({ anchor, focus: row.idx });
    else setRowSelection({ anchor: row.idx, focus: row.idx });
    props.onSelect(row.idx);
    props.onSelectRow?.(row);
    const reg = firstAsmReg(row.asm);
    if (reg) props.onSelectReg(reg);
  }

  function regFlowKind(idx: number): "def" | "use" | "def-use" | null {
    const flow = regFlow();
    if (!flow) return null;
    const isDef = flow.defIdx === idx;
    const isUse = flow.useIdx === idx;
    if (isDef && isUse) return "def-use";
    if (isDef) return "def";
    if (isUse) return "use";
    return null;
  }

  function regFlowTitle(idx: number): string | undefined {
    const flow = regFlow();
    if (!flow) return undefined;
    const kind = regFlowKind(idx);
    if (!kind) return undefined;
    if (kind === "def") return `${flow.reg} nearest def before #${flow.sourceIdx}`;
    if (kind === "use") return `${flow.reg} nearest use after #${flow.sourceIdx}`;
    return `${flow.reg} nearest def/use around #${flow.sourceIdx}`;
  }

  function jumpRegFlowTarget(kind: "def" | "use") {
    const flow = regFlow();
    const idx = kind === "def" ? flow?.defIdx : flow?.useIdx;
    if (idx === null || idx === undefined) return;
    setOptimisticIdx(idx);
    setRowSelection({ anchor: idx, focus: idx });
    props.onSelect(idx);
    const row = rowObjectCache.get(idx);
    if (row) props.onSelectRow?.(row);
  }

  function regFlowTargetLabel(flow: RegFlow, kind: "def" | "use"): string {
    if (kind === "def") return flow.defErr ? "!" : (flow.defIdx ?? "?").toString();
    return flow.useErr ? "!" : (flow.useIdx ?? "?").toString();
  }

  function regFlowTargetTitle(flow: RegFlow, kind: "def" | "use", rowIdx: number): string {
    if (kind === "def") {
      if (flow.defErr) return `def lookup failed: ${flow.defErr}`;
      return flow.defIdx === null || flow.defIdx === undefined
        ? `no def before #${rowIdx}`
        : `jump ${flow.reg} def #${flow.defIdx}`;
    }
    if (flow.useErr) return `use lookup failed: ${flow.useErr}`;
    return flow.useIdx === null || flow.useIdx === undefined
      ? `no use after #${rowIdx}`
      : `jump ${flow.reg} use #${flow.useIdx}`;
  }

  /// Long-arrow SVG overlay drawn above `records-inner` linking the source
  /// row of the active register flow to its def (red, upward) and use
  /// (green, downward) rows. Replaces the per-row inline ▲▼ buttons. The
  /// arrow is clickable; off-screen targets clamp to the viewport edge with
  /// a "+N rows" label.
  ///
  /// IMPORTANT: this overlay must NOT capture scroll/wheel events. The
  /// parent `<svg>` and `<g>` keep `pointer-events: none`; only the
  /// `<line>` (with `pointer-events: stroke`) and the off-screen `<text>`
  /// label (with `pointer-events: visiblePainted`) accept clicks. The
  /// circle anchor and `<title>` are decorative (`pointer-events: none`).
  /// Anything else captures wheel events on a 100%-height SVG and the
  /// records virtual list stops scrolling.
  /// Arrow geometry. Returned coordinates are **viewport-relative** so the
  /// SVG container can be sized to the visible window (a few hundred px)
  /// instead of the full virtual height (which can be 30 million px on
  /// large traces and turns into a layout-instability hazard).
  const regFlowArrows = createMemo(() => {
    const f = regFlow();
    if (!f || !viewport) return null;
    const sTop = scrollTop();
    const vH = Math.max(1, viewHeight());
    void virtualTotalRecords();
    void rawRange();
    const x = 18;

    // Convert records-inner-relative y to viewport-relative y. Source row
    // and target rows can both be inside or outside the visible window.
    const toViewportY = (innerY: number) => innerY - sTop;
    const srcInner = pixelCenterForIdx(f.sourceIdx);
    const srcInWindow = srcInner >= sTop && srcInner <= sTop + vH;

    const arrows: Array<{
      kind: "def" | "use";
      color: string;
      targetIdx: number;
      srcY: number; // viewport-relative
      tgtY: number; // viewport-relative, clamped to viewport edges
      srcOff: "top" | "bottom" | null; // source off-screen direction
      tgtOff: "top" | "bottom" | null; // target off-screen direction
      label?: string;
      title: string;
    }> = [];

    for (const kind of ["def", "use"] as const) {
      const targetIdx = kind === "def" ? f.defIdx : f.useIdx;
      const err = kind === "def" ? f.defErr : f.useErr;
      if (err || targetIdx === null || targetIdx === undefined) continue;
      if (targetIdx === f.sourceIdx) continue;
      const tgtInner = pixelCenterForIdx(targetIdx);
      const tgtOff = tgtInner < sTop ? "top" : tgtInner > sTop + vH ? "bottom" : null;
      const srcOff = srcInner < sTop ? "top" : srcInner > sTop + vH ? "bottom" : null;
      const clampInner = (innerY: number) =>
        Math.max(sTop + 6, Math.min(sTop + vH - 6, innerY));
      const srcY = toViewportY(srcOff ? clampInner(srcInner) : srcInner);
      const tgtY = toViewportY(tgtOff ? clampInner(tgtInner) : tgtInner);
      const rowGap = Math.abs(targetIdx - f.sourceIdx);
      const label = tgtOff ? `+${rowGap.toLocaleString()} rows` : undefined;
      arrows.push({
        kind,
        color: kind === "def" ? "var(--err, #f78166)" : "var(--ok, #56d364)",
        targetIdx,
        srcY,
        tgtY,
        srcOff,
        tgtOff,
        label,
        title: regFlowTargetTitle(f, kind, f.sourceIdx),
      });
    }
    if (!arrows.length) return null;
    void srcInWindow;
    return { arrows, x, sTop, vH };
  });

  /// SVG sticks to the visible viewport (top = scrollTop, height = view).
  /// Arrow coordinates are viewport-relative, so scrolling re-positions
  /// the overlay correctly without painting a 30M-pixel-tall element.
  ///
  /// Path shape is `[`-bracket: short horizontal stub at source row, vertical
  /// down/up to target row's y, short horizontal stub ending in a small
  /// arrowhead pointing into the target row's content. Avoids the cramped
  /// look when target is the very next row.
  function renderRegFlowOverlay() {
    const STUB = 6; // horizontal stub length in px
    return (
      <Show when={regFlowArrows()}>
        {(data) => (
          <svg
            class="reg-flow-overlay"
            style={{
              position: "absolute",
              left: "0",
              top: `${data().sTop}px`,
              width: "100%",
              height: `${data().vH}px`,
              // CRITICAL: never capture scroll. Children opt in selectively.
              "pointer-events": "none",
              "z-index": "5",
            }}
          >
            <defs>
              <marker
                id="rf-arrow-def"
                viewBox="0 0 6 6"
                refX="5.5"
                refY="3"
                markerWidth="5"
                markerHeight="5"
                orient="auto-start-reverse"
              >
                <path d="M0,0 L6,3 L0,6 z" fill="var(--err, #f78166)" />
              </marker>
              <marker
                id="rf-arrow-use"
                viewBox="0 0 6 6"
                refX="5.5"
                refY="3"
                markerWidth="5"
                markerHeight="5"
                orient="auto-start-reverse"
              >
                <path d="M0,0 L6,3 L0,6 z" fill="var(--ok, #56d364)" />
              </marker>
            </defs>
            <For each={data().arrows}>
              {(arrow) => {
                const baseX = data().x;
                const stemX = baseX - STUB; // vertical leg sits to the left of the row content
                const tgtX = baseX; // arrowhead tip sits at the row's left edge
                // Build a single polyline for the [-shape:
                //   start at (baseX, srcY), go LEFT STUB to stemX, vertical to tgtY, RIGHT STUB to tgtX.
                const path = `M ${baseX},${arrow.srcY} L ${stemX},${arrow.srcY} L ${stemX},${arrow.tgtY} L ${tgtX},${arrow.tgtY}`;
                return (
                  <g style={{ "pointer-events": "none" }}>
                    <path
                      d={path}
                      fill="none"
                      stroke={arrow.color}
                      stroke-width="1.5"
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      marker-end={`url(#rf-arrow-${arrow.kind})`}
                      style={{ "pointer-events": "stroke", cursor: "pointer" }}
                      onClick={(e) => {
                        e.stopPropagation();
                        jumpRegFlowTarget(arrow.kind);
                      }}
                    >
                      <title>{arrow.title}</title>
                    </path>
                    <Show when={arrow.label}>
                      <text
                        x={baseX + 4}
                        y={arrow.tgtY + (arrow.tgtOff === "top" ? 10 : -3)}
                        fill={arrow.color}
                        font-size="10"
                        style={{ "pointer-events": "visiblePainted", cursor: "pointer" }}
                        onClick={(e) => {
                          e.stopPropagation();
                          jumpRegFlowTarget(arrow.kind);
                        }}
                      >
                        {arrow.label}
                        <title>{arrow.title}</title>
                      </text>
                    </Show>
                    {/* anchor dot at the source row — decorative, no events */}
                    <circle cx={baseX} cy={arrow.srcY} r="2.5" fill={arrow.color} />
                  </g>
                );
              }}
            </For>
          </svg>
        )}
      </Show>
    );
  }

  async function selectRegFlow(row: RecordRow, regRaw: string) {
    const reg = normalizeReg(regRaw);
    closeRegContext();
    closeRowContext();
    const token = ++regFlowSeq;
    const abort = new AbortController();
    regFlowAbort = abort;
    // Selecting a register on a row should NOT move the global cursor.
    // Cursor moves only on row click, double-click on the register, or
    // explicit jump from the def/use SVG arrow / right-click menu.
    props.onSelectReg(reg);
    setRegFlow({
      token,
      sourceIdx: row.idx,
      reg,
      defIdx: null,
      useIdx: null,
      loading: true,
    });

    try {
      const [def, use] = await Promise.allSettled([
        fetchLastWriteOfReg(row.idx, reg, abort.signal),
        fetchNextUseOfReg(row.idx, reg, abort.signal),
      ]);
      if (abort.signal.aborted || regFlow()?.token !== token) return;

      const defErr = def.status === "rejected" ? String(def.reason) : undefined;
      const useErr = use.status === "rejected" ? String(use.reason) : undefined;
      const err = [defErr ? `def: ${defErr}` : null, useErr ? `use: ${useErr}` : null]
        .filter(Boolean)
        .join("; ");
      setRegFlow({
        token,
        sourceIdx: row.idx,
        reg,
        defIdx: def.status === "fulfilled" ? def.value.idx : null,
        useIdx: use.status === "fulfilled" ? use.value.idx : null,
        loading: false,
        defErr,
        useErr,
        err: err || undefined,
      });
    } finally {
      if (regFlowAbort === abort) regFlowAbort = undefined;
    }
  }

  function updateRowMarks(idxs: number[], updater: (mark: RowMark, idx: number) => RowMark) {
    const key = rowMarksKey();
    setRowMarks((current) => {
      const next = new Map(current);
      for (const idx of idxs) {
        const updated = compactRowMark(updater(next.get(idx) ?? {}, idx));
        if (updated) next.set(idx, updated);
        else next.delete(idx);
      }
      if (key) saveRowMarks(key, next);
      return next;
    });
  }

  function setRowMarkColor(idx: number, color: RowMarkColor) {
    updateRowMarks(markTargetIdxs(idx), (mark) => ({ ...mark, color }));
  }

  function toggleRowMarkFlag(idx: number, key: "strike" | "muted") {
    const targets = markTargetIdxs(idx);
    const shouldEnable = targets.some((targetIdx) => !rowMarks().get(targetIdx)?.[key]);
    updateRowMarks(targets, (mark) => ({ ...mark, [key]: shouldEnable }));
  }

  function editRowNote(idx: number) {
    const current = rowMarks().get(idx)?.note ?? "";
    const next = window.prompt("row note", current);
    if (next === null) return;
    updateRowMarks(markTargetIdxs(idx), (mark) => ({ ...mark, note: next }));
  }

  function clearRowMark(idx: number) {
    updateRowMarks(markTargetIdxs(idx), () => ({}));
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

  function openRowContext(e: MouseEvent, row: RecordRow) {
    e.preventDefault();
    e.stopPropagation();
    closeRegContext();
    setOptimisticIdx(row.idx);
    props.onSelect(row.idx);
    props.onSelectRow?.(row);
    if (!rowInSelection(row.idx)) setRowSelection({ anchor: row.idx, focus: row.idx });
    setRowContext({
      x: Math.min(e.clientX, window.innerWidth - 260),
      y: Math.min(e.clientY, window.innerHeight - 220),
      idx: row.idx,
      pc: row.pc,
    });
  }

  async function openRegContext(e: MouseEvent, row: RecordRow, reg: string) {
    e.preventDefault();
    e.stopPropagation();
    closeRowContext();
    cancelRegContext();
    const token = ++regContextSeq;
    const abort = new AbortController();
    regContextAbort = abort;
    // Right-click on a register opens the menu only — the cursor stays put.
    // Choose a menu action (jump-to-last-write, taint, etc.) to actually move.
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
    <section class="panel records-panel" onClick={() => {
      closeRegContext();
      closeRowContext();
    }}>
      <h2>Records</h2>
      <Show when={meta.error}>
        <p class="err">meta failed: {String(meta.error)}</p>
      </Show>
      <Show when={resp.error}>
        <p class="err">load failed: {String(resp.error)}</p>
      </Show>
      <div class="records-status">
        <span>
          <Show
            when={taintOnlyRows()}
            fallback={<>window {rawRange().start}-{rawRange().end} / {totalRecords().toLocaleString()}</>}
          >
            {(rows) => <>taint rows {rawRange().start}-{rawRange().end} / {rows().length.toLocaleString()}</>}
          </Show>
        </span>
        <span class="grow" />
        <span>selected idx {props.selectedIdx}</span>
        <span>reg {props.selectedReg}</span>
        <Show when={regFlow()}>
          {(flow) => (
            <>
              <span class="records-reg-flow-status" title={flow().err ?? undefined}>
                flow {flow().reg} @#{flow().sourceIdx} · def {regFlowTargetLabel(flow(), "def")} · use {regFlowTargetLabel(flow(), "use")}
                <Show when={flow().loading}> · loading</Show>
              </span>
              <button
                class="status-btn"
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  clearRegFlow();
                }}
              >
                clear flow
              </button>
            </>
          )}
        </Show>
        <Show when={props.taintOverlay}>
          {(overlay) => (
            <>
              <span class="records-taint-status">
                taint {overlay().direction} {overlay().reg} @#{overlay().from} · {overlay().count} hit{overlay().count === 1 ? "" : "s"}
                <Show when={overlay().stopped}> · partial</Show>
              </span>
              <button
                class="status-btn"
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  props.onTaintOverlayModeChange?.(nextTaintMode(overlay().mode));
                }}
                title={`switch to ${taintModeLabel(nextTaintMode(overlay().mode))}`}
              >
                {taintModeLabel(overlay().mode)}
              </button>
              <button
                class="status-btn"
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  props.onClearTaintOverlay?.();
                }}
              >
                clear taint
              </button>
            </>
          )}
        </Show>
        <Show when={!callTreeResp.loading && collapsedCalls().size > 0}>
          <span class="dim">{collapsedCalls().size} folded</span>
        </Show>
        <Show when={!foldTreeRequested()}>
          <button
            class="status-btn"
            type="button"
            title="load call tree metadata for inline fold controls"
            onClick={(e) => {
              e.stopPropagation();
              setFoldTreeRequested(true);
            }}
          >
            load folds
          </button>
        </Show>
        <Show when={foldTreeRequested() && callTreeResp.loading}>
          <span class="dim">loading folds</span>
        </Show>
        <Show when={bnTokenStatus() && bnTokenStatus() !== "ok"}>
          <span title="BN asm token overlay status">bn tokens {bnTokenStatus()}</span>
        </Show>
      </div>
      <div
        ref={(el) => {
          viewport = el;
        }}
        class="records-virtual"
        tabIndex={0}
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
      >
        <div
          class="records-minimap"
          style={{ top: `${scrollTop()}px`, height: `${Math.max(1, viewHeight())}px` }}
          onClick={jumpMinimap}
          title="trace minimap"
        >
          <For each={minimapMarks()}>
            {(mark) => (
              <button
                type="button"
                class="records-minimap-mark"
                classList={{
                  selected: mark.kind === "selected",
                  taint: mark.kind === "taint",
                  marked: mark.kind === "mark",
                  "mark-red": mark.color === "red",
                  "mark-yellow": mark.color === "yellow",
                  "mark-green": mark.color === "green",
                  "mark-blue": mark.color === "blue",
                  "mark-violet": mark.color === "violet",
                }}
                style={{ top: `${mark.topPct}%` }}
                title={mark.title}
                onClick={(e) => {
                  e.stopPropagation();
                  const only = taintOnlyRows();
                  const row = only?.find((item) => item.idx === mark.idx) ?? rowObjectCache.get(mark.idx);
                  if (row) selectRow(row);
                  else props.onSelect(mark.idx);
                }}
              />
            )}
          </For>
        </div>
        <div class="records-inner" style={{ height: `${innerHeight()}px` }}>
          <Show when={showRecordsLoading()}>
            <p class="dim records-loading">loading…</p>
          </Show>
          <Show when={currentResp()?.truncated}>
            <div class="cap-notice records-cap-notice" role="status">
              Records window stopped at {(currentResp()?.max_count_used ?? currentResp()?.count ?? 0).toLocaleString()} rows.
            </div>
          </Show>
          <For each={displayRows()}>
            {(row) => {
              const mark = () => rowMarks().get(row.idx);
              const taintHit = () => props.taintOverlay?.idxs.has(row.idx) ?? false;
              const taintDimmed = () =>
                !!props.taintOverlay && props.taintOverlay.mode === "dim" && !taintHit();
              const foldedRange = () => foldedRangeForRow(row);
              const foldableRange = () => foldableRangeForRow(row);
              const flowKind = () => regFlowKind(row.idx);
              return (
                <div
                  class="records-row"
                  classList={{
                    selected: row.idx === activeIdx(),
                    "range-selected": rowInSelection(row.idx) && row.idx !== activeIdx(),
                    "is-call": row.is_call,
                    "is-ret": row.is_ret,
                    "is-branch": row.is_branch && !row.is_call && !row.is_ret,
                    "so-hidden": row.module !== null && props.hiddenSos.has(row.module),
                    "taint-hit": taintHit(),
                    "taint-dim": taintDimmed(),
                    "row-marked": !!mark(),
                    "row-strike": !!mark()?.strike,
                    "row-muted": !!mark()?.muted,
                    "has-note": !!mark()?.note,
                    "has-fold-summary": !!foldedRange(),
                    "reg-flow-source": regFlow()?.sourceIdx === row.idx,
                    "reg-flow-def": regFlow()?.defIdx === row.idx,
                    "reg-flow-use": regFlow()?.useIdx === row.idx,
                    "mark-red": mark()?.color === "red",
                    "mark-yellow": mark()?.color === "yellow",
                    "mark-green": mark()?.color === "green",
                    "mark-blue": mark()?.color === "blue",
                    "mark-violet": mark()?.color === "violet",
                  }}
                  style={{ top: rowTop(row), height: `${ROW_HEIGHT}px` }}
                  tabIndex={0}
                  onPointerDown={(e) => {
                    if (e.button === 0) setOptimisticIdx(row.idx);
                  }}
                  onClick={(e) => selectRow(row, e)}
                  onContextMenu={(e) => openRowContext(e, row)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") selectRow(row);
                    else if (e.altKey && !e.ctrlKey && !e.metaKey && /^[1-5]$/.test(e.key)) {
                      e.preventDefault();
                      const color = ROW_MARK_COLORS[Number(e.key) - 1];
                      if (color) setRowMarkColor(row.idx, color);
                    } else if (e.altKey && !e.ctrlKey && !e.metaKey && e.key.toLowerCase() === "s") {
                      e.preventDefault();
                      toggleRowMarkFlag(row.idx, "strike");
                    } else if (e.altKey && !e.ctrlKey && !e.metaKey && e.key.toLowerCase() === "d") {
                      e.preventDefault();
                      toggleRowMarkFlag(row.idx, "muted");
                    }
                  }}
                >
                <span class="dot" title={regFlowTitle(row.idx) ?? mark()?.note ?? undefined}>
                  <Show when={flowKind()} fallback={<Show when={mark()?.note} fallback={rowKind(row)}>*</Show>}>
                    {(kind) => (
                      <span class={`reg-flow-arrow ${kind()}`}>
                        {regFlowLabel(kind())}
                      </span>
                    )}
                  </Show>
                </span>
                <span class="idx">{row.idx}</span>
                <span class="pc">
                  <code>{row.pc}</code>
                </span>
                <span class="func" title={fnLabel(row)}>
                  {fnLabel(row)}
                </span>
                <span class="asm" title={mark()?.note ? `${mark()?.note}\n${row.asm}` : row.asm}>
                  <Show when={foldableRange()}>
                    {(range) => (
                      <button
                        type="button"
                        class="row-fold-btn"
                        title={`${collapsedCalls().has(range().key) ? "expand" : "collapse"} ${range().fn} [${range().enter}..${range().exit}]`}
                        onClick={(e) => {
                          e.stopPropagation();
                          toggleFoldRange(range());
                        }}
                      >
                        {collapsedCalls().has(range().key) ? "▶" : "▼"}
                      </button>
                    )}
                  </Show>
                  <code>
                    <Show
                      when={tokensForPc(row.pc)}
                      fallback={
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
                                  title={`${reg()} · click selects register and shows def/use arrow · double-click jumps to last write · right-click for actions`}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    void selectRegFlow(row, reg());
                                  }}
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
                      }
                    >
                      {(tokens) => (
                        <For each={tokens()}>
                          {(token) => {
                            const reg = tokenReg(token);
                            const addr = tokenAddr(token);
                            return (
                              <span
                                class={`${tokenClass(token)}${reg ? " op-reg" : ""}`}
                                classList={{
                                  selected: !!reg && reg === normalizeReg(props.selectedReg),
                                }}
                                data-a={addr ?? undefined}
                                data-reg={reg ?? undefined}
                                title={
                                  reg
                                    ? `${reg} · click selects register and shows def/use arrow · double-click jumps to last write · right-click for actions`
                                    : addr
                                      ? `${addr} · double-click jump to nearest trace PC`
                                      : undefined
                                }
                                onClick={(e) => {
                                  if (!reg) return;
                                  e.stopPropagation();
                                  void selectRegFlow(row, reg);
                                }}
                                onDblClick={(e) => {
                                  if (reg) {
                                    e.stopPropagation();
                                    void jumpLastWrite(row.idx, reg);
                                  } else if (addr) {
                                    e.stopPropagation();
                                    void jumpPcValue(addr, row.idx);
                                  }
                                }}
                                onMouseEnter={(e) => {
                                  if (reg) void loadRegTitle(e.currentTarget, row.idx, reg);
                                }}
                                onContextMenu={(e) => {
                                  if (reg) void openRegContext(e, row, reg);
                                }}
                              >
                                {tokenText(token)}
                              </span>
                            );
                          }}
                        </For>
                      )}
                    </Show>
                  </code>
                </span>
                <Show when={foldedRange()}>
                  {(range) => (
                    <span class="fold-summary">
                      folded {range().fn} · {Math.max(0, range().exit - range().enter).toLocaleString()} rows
                    </span>
                  )}
                </Show>
                <Show when={!foldedRange() ? mark()?.note : undefined}>
                  {(note) => (
                    <span class="row-note" title={note()}>
                      {note()}
                    </span>
                  )}
                </Show>
              </div>
              );
            }}
          </For>
          {renderRegFlowOverlay()}
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
          <Show when={rowContext()}>
            {(ctx) => {
              const mark = () => rowMarks().get(ctx().idx) ?? {};
              return (
                <div
                  class="row-context-menu"
                  style={{ left: `${ctx().x}px`, top: `${ctx().y}px` }}
                  onClick={(e) => e.stopPropagation()}
                  onContextMenu={(e) => e.preventDefault()}
                >
                  <div class="memory-context-title">
                    {selectionLabel(ctx().idx)}
                  </div>
                  <p class="dim small">{ctx().pc}</p>
                  <div class="row-mark-swatches">
                    <For each={ROW_MARK_COLORS}>
                      {(color) => (
                        <button
                          type="button"
                          class={`row-mark-swatch ${color}`}
                          classList={{ active: mark().color === color }}
                          aria-label={`mark ${color}`}
                          title={`mark ${color}`}
                          onClick={() => setRowMarkColor(ctx().idx, color)}
                        />
                      )}
                    </For>
                  </div>
                  <button type="button" onClick={() => editRowNote(ctx().idx)}>
                    {mark().note ? "edit note" : "add note"}
                  </button>
                  <button type="button" onClick={() => toggleRowMarkFlag(ctx().idx, "strike")}>
                    {mark().strike ? "remove strike" : "strike row"}
                  </button>
                  <button type="button" onClick={() => toggleRowMarkFlag(ctx().idx, "muted")}>
                    {mark().muted ? "restore row" : "dim row"}
                  </button>
                  <button type="button" onClick={() => clearRowMark(ctx().idx)}>
                    clear mark
                  </button>
                </div>
              );
            }}
          </Show>
        </div>
      </div>
    </section>
  );
}
