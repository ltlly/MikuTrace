import type { CallNode, RecordRow } from "~/api/types";
import { normalizeReg } from "~/utils/bnTokens";

export const ROW_HEIGHT = 18;
export const OVERSCAN = 18;
export const SAFE_SCROLL_HEIGHT = 15_000_000;
export const FOLDED_FETCH_BATCH_RANGES = 24;
export const ROW_MARKS_PREFIX = "tracemiku-row-marks:";
export const ROW_MARK_COLORS = ["red", "yellow", "green", "blue", "violet"] as const;

const REG_RE = /\b(?:x(?:[0-9]|1[0-9]|2[0-9]|30)|w(?:[0-9]|1[0-9]|2[0-9]|30)|sp|fp|lr)\b/gi;

export type RowMarkColor = (typeof ROW_MARK_COLORS)[number];
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

export interface RegContext {
  token: number;
  x: number;
  y: number;
  idx: number;
  reg: string;
  value?: string | null;
  err?: string;
}

export interface RowContext {
  x: number;
  y: number;
  idx: number;
  pc: string;
}

export interface RowMark {
  color?: RowMarkColor;
  strike?: boolean;
  muted?: boolean;
  note?: string;
}

export interface MinimapMark {
  idx: number;
  topPct: number;
  kind: "selected" | "taint" | "mark";
  color?: RowMarkColor;
  title: string;
}

export interface FoldRange {
  key: string;
  enter: number;
  exit: number;
  fn: string;
  depth: number;
}

export interface FoldFetchRange {
  start: number;
  count: number;
}

export interface RowSelection {
  anchor: number;
  focus: number;
}

export interface RegFlow {
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

export function firstAsmReg(asm: string): string | null {
  const match = asm.match(REG_RE);
  return match?.[0] ? normalizeReg(match[0]) : null;
}

export function asmParts(asm: string): Array<{ text: string; reg?: string }> {
  const parts: Array<{ text: string; reg?: string }> = [];
  let last = 0;
  for (const match of asm.matchAll(REG_RE)) {
    const index = match.index ?? 0;
    if (index > last) parts.push({ text: asm.slice(last, index) });
    parts.push({ text: match[0], reg: normalizeReg(match[0]) });
    last = index + match[0].length;
  }
  if (last < asm.length) parts.push({ text: asm.slice(last) });
  return parts.length ? parts : [{ text: asm }];
}

export function fnLabel(row: { func: string | null; off: string | null; module: string | null }): string {
  if (row.func) return row.off ? `${row.func}+${row.off}` : row.func;
  return row.module ?? "?";
}

export function rowKind(row: RecordRow): string {
  if (row.is_call) return "call";
  if (row.is_ret) return "ret";
  if (row.is_branch) return "br";
  return "";
}

export function regFlowLabel(kind: "def" | "use" | "def-use"): string {
  if (kind === "def") return "▲";
  if (kind === "use") return "▼";
  return "↕";
}

export function collectFoldRanges(node: CallNode, out: FoldRange[] = []): FoldRange[] {
  if (node.depth > 0 && node.exit_idx > node.enter_idx) {
    out.push({
      key: `${node.depth}:${node.enter_idx}:${node.exit_idx}:${node.fn ?? "?"}`,
      enter: node.enter_idx,
      exit: node.exit_idx,
      fn: node.fn ?? "?",
      depth: node.depth,
    });
  }
  for (const child of node.children ?? []) collectFoldRanges(child, out);
  return out;
}

export function clamp(value: number, lower: number, upper: number): number {
  return Math.min(upper, Math.max(lower, value));
}

function isRowMarkColor(value: unknown): value is RowMarkColor {
  return typeof value === "string" && (ROW_MARK_COLORS as readonly string[]).includes(value);
}

export function compactRowMark(mark: RowMark): RowMark | null {
  const compact: RowMark = {};
  if (isRowMarkColor(mark.color)) compact.color = mark.color;
  if (mark.strike) compact.strike = true;
  if (mark.muted) compact.muted = true;
  const note = mark.note?.trim();
  if (note) compact.note = note;
  return Object.keys(compact).length ? compact : null;
}

export function loadRowMarks(key: string): Map<number, RowMark> {
  try {
    const raw = localStorage.getItem(key);
    const parsed = raw ? JSON.parse(raw) : {};
    const marks = new Map<number, RowMark>();
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return marks;
    for (const [rawIndex, value] of Object.entries(parsed)) {
      const index = Number(rawIndex);
      if (!Number.isInteger(index) || index < 0 || !value || typeof value !== "object" || Array.isArray(value)) {
        continue;
      }
      const mark = compactRowMark(value as RowMark);
      if (mark) marks.set(index, mark);
    }
    return marks;
  } catch {
    return new Map();
  }
}

export function saveRowMarks(key: string, marks: Map<number, RowMark>) {
  const serialized: Record<string, RowMark> = {};
  for (const [index, mark] of marks) {
    const compact = compactRowMark(mark);
    if (compact) serialized[String(index)] = compact;
  }
  try {
    if (Object.keys(serialized).length) localStorage.setItem(key, JSON.stringify(serialized));
    else localStorage.removeItem(key);
  } catch {
    // localStorage may be unavailable in a restricted browser context.
  }
}

export function sameRecordRow(a: RecordRow, b: RecordRow): boolean {
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

export function actualIdxToFoldedPos(idx: number, ranges: FoldRange[], visibleTotal: number): number {
  let hiddenBefore = 0;
  for (const range of ranges) {
    if (idx <= range.enter) break;
    if (idx <= range.exit) return range.enter - hiddenBefore;
    hiddenBefore += range.exit - range.enter;
  }
  return clamp(idx - hiddenBefore, 0, Math.max(0, visibleTotal - 1));
}

export function foldedPosToActualIdx(
  pos: number,
  ranges: FoldRange[],
  visibleTotal: number,
  totalRecords: number,
): number {
  let hiddenBefore = 0;
  const clampedPos = clamp(pos, 0, Math.max(0, visibleTotal - 1));
  for (const range of ranges) {
    const visibleEnter = range.enter - hiddenBefore;
    if (clampedPos <= visibleEnter) return clampedPos + hiddenBefore;
    hiddenBefore += range.exit - range.enter;
  }
  return clamp(clampedPos + hiddenBefore, 0, Math.max(0, totalRecords - 1));
}

export function groupFetchRanges(idxs: number[]): FoldFetchRange[] {
  const sorted = [...new Set(idxs)].sort((a, b) => a - b);
  const ranges: FoldFetchRange[] = [];
  for (const idx of sorted) {
    const last = ranges[ranges.length - 1];
    if (last && idx === last.start + last.count) last.count += 1;
    else ranges.push({ start: idx, count: 1 });
  }
  return ranges;
}

export function nextTaintMode(mode: RecordsTaintOverlayMode): RecordsTaintOverlayMode {
  if (mode === "highlight") return "dim";
  if (mode === "dim") return "only";
  return "highlight";
}

export function taintModeLabel(mode: RecordsTaintOverlayMode): string {
  if (mode === "highlight") return "highlight";
  if (mode === "dim") return "dim non-hits";
  return "taint only";
}

export function placeholderRow(idx: number): RecordRow {
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

export function normalizedSelection(selection: RowSelection | null): { start: number; end: number } | null {
  if (!selection) return null;
  return {
    start: Math.min(selection.anchor, selection.focus),
    end: Math.max(selection.anchor, selection.focus),
  };
}

export function regFlowKind(flow: RegFlow | null, idx: number): "def" | "use" | "def-use" | null {
  if (!flow) return null;
  const isDef = flow.defIdx === idx;
  const isUse = flow.useIdx === idx;
  if (isDef && isUse) return "def-use";
  if (isDef) return "def";
  if (isUse) return "use";
  return null;
}

export function regFlowTitle(flow: RegFlow | null, idx: number): string | undefined {
  if (!flow) return undefined;
  const kind = regFlowKind(flow, idx);
  if (kind === "def") return `${flow.reg} nearest def before #${flow.sourceIdx}`;
  if (kind === "use") return `${flow.reg} nearest use after #${flow.sourceIdx}`;
  if (kind === "def-use") return `${flow.reg} nearest def/use around #${flow.sourceIdx}`;
  return undefined;
}

export function regFlowTargetLabel(flow: RegFlow, kind: "def" | "use"): string {
  if (kind === "def") return flow.defErr ? "!" : (flow.defIdx ?? "?").toString();
  return flow.useErr ? "!" : (flow.useIdx ?? "?").toString();
}

export function regFlowTargetTitle(flow: RegFlow, kind: "def" | "use", rowIdx: number): string {
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
