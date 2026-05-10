import { createEffect, createMemo, createResource, createSignal, For, onCleanup, onMount, Show, untrack } from "solid-js";
import type { JSX } from "solid-js";

import { fetchFunctions, fetchIdxsForPc, fetchMeta, fetchRecord, fetchSearch } from "./api/client";
import BacktracePanel from "./panels/backtrace/BacktracePanel";
import CallTreePanel from "./panels/calltree/CallTreePanel";
import CfgPanel, { type CfgDebugState, type CursorRecordHint } from "./panels/cfg/CfgPanel";
import DecompilerPanel from "./panels/decompiler/DecompilerPanel";
import ForksPanel from "./panels/forks/ForksPanel";
import FunctionsPanel from "./panels/functions/FunctionsPanel";
import HlilPanel from "./panels/hlil/HlilPanel";
import MemoryPanel from "./panels/memory/MemoryPanel";
import QueryPanel, { type QueryRunRequest } from "./panels/query/QueryPanel";
import RecordsPanel, { type RecordsTaintOverlay, type RecordsTaintOverlayMode, type RecordsVisibleNavigator } from "./panels/records/RecordsPanel";
import RegistersPanel from "./panels/registers/RegistersPanel";
import SettingsPanel from "./panels/settings/SettingsPanel";
import SlicePanel from "./panels/slice/SlicePanel";
import SoFilterPanel from "./panels/sofilter/SoFilterPanel";
import StringsPanel from "./panels/strings/StringsPanel";
import StringProvenancePanel, { type StringProvenanceRequest } from "./panels/strings/StringProvenancePanel";
import TaintPanel, { type TaintOverlayResult } from "./panels/taint/TaintPanel";
import TraceForPcPanel from "./panels/tracepc/TraceForPcPanel";
import XrefPanel from "./panels/xref/XrefPanel";
import type { FunctionEntry, RecordRow, TaintRow } from "./api/types";
import type { UiTaskEntry, UiTaskReporter, UiTaskUpdate } from "./utils/taskCenter";

type LeftTab =
  | "funcs"
  | "back"
  | "calltree"
  | "forks"
  | "strings"
  | "taint"
  | "slice"
  | "xref"
  | "sofilter"
  | "settings";
type RightTab = "cfg" | "regs" | "hlil" | "dec";
type BottomTab = "memory" | "navigation" | "trace-for-pc" | "string-provenance" | "query";
type HelpTopic = "overview" | "left" | "disasm" | "right" | "bottom";
type HelpState = { topic: HelpTopic; x: number; y: number };
type CmdMode = "" | "/" | ":";
type TaintRunDirection = "forward" | "backward";
type MemoryRequest = { token: number; addr: string; count?: number };
type TaintRunRequest = { token: number; idx: number; reg: string; direction: TaintRunDirection };

const HIDDEN_SOS_KEY = "tracemiku-hidden-sos";
const FUNCTION_RENAMES_PREFIX = "tracemiku-function-renames:";
const LEGACY_LAYOUT_KEY = "tracemiku-layout-v2";
const LAYOUT_KEY = "tracemiku-layout-v4";

interface LayoutState {
  leftW: number;
  rightW: number;
  bottomH: number;
  colDot: number;
  colIdx: number;
  colPc: number;
  colFunc: number;
  colAsm: number;
  syncCfg: boolean;
}

const DEFAULT_LAYOUT: LayoutState = {
  leftW: 340,
  rightW: 520,
  bottomH: 240,
  colDot: 18,
  colIdx: 60,
  colPc: 112,
  colFunc: 96,
  colAsm: 200,
  syncCfg: true,
};

function clampNumber(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

function initialLayout(): LayoutState {
  try {
    const raw = localStorage.getItem(LAYOUT_KEY);
    const isCurrentLayout = raw !== null;
    const legacyRaw = raw ?? localStorage.getItem(LEGACY_LAYOUT_KEY);
    const parsed = legacyRaw ? JSON.parse(legacyRaw) : {};
    return {
      leftW: clampNumber(Number(parsed.leftW) || DEFAULT_LAYOUT.leftW, 180, 680),
      rightW: clampNumber(Number(parsed.rightW) || DEFAULT_LAYOUT.rightW, 320, 960),
      bottomH: clampNumber(Number(parsed.bottomH) || DEFAULT_LAYOUT.bottomH, 120, 560),
      colDot: clampNumber(Number(parsed.colDot) || DEFAULT_LAYOUT.colDot, 12, 48),
      colIdx: clampNumber(Number(parsed.colIdx) || DEFAULT_LAYOUT.colIdx, 44, 140),
      colPc: clampNumber(Number(parsed.colPc) || DEFAULT_LAYOUT.colPc, 80, 260),
      colFunc: clampNumber(Number(parsed.colFunc) || DEFAULT_LAYOUT.colFunc, 80, 420),
      colAsm: clampNumber(Number(parsed.colAsm) || DEFAULT_LAYOUT.colAsm, 180, 900),
      syncCfg: isCurrentLayout && typeof parsed.syncCfg === "boolean" ? parsed.syncCfg : DEFAULT_LAYOUT.syncCfg,
    };
  } catch {
    return { ...DEFAULT_LAYOUT };
  }
}

function initialHiddenSos(): Set<string> {
  try {
    const raw = localStorage.getItem(HIDDEN_SOS_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? new Set(parsed.filter((x): x is string => typeof x === "string")) : new Set();
  } catch {
    return new Set();
  }
}

function loadFunctionRenames(key: string): Map<string, string> {
  try {
    const raw = localStorage.getItem(key);
    const parsed = raw ? JSON.parse(raw) : {};
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return new Map();
    return new Map(
      Object.entries(parsed).filter(
        (entry): entry is [string, string] =>
          typeof entry[0] === "string" && typeof entry[1] === "string" && entry[1].trim().length > 0,
      ),
    );
  } catch {
    return new Map();
  }
}

function saveFunctionRenames(key: string, renames: Map<string, string>) {
  const serialized: Record<string, string> = {};
  for (const [id, name] of renames) {
    const trimmed = name.trim();
    if (trimmed) serialized[id] = trimmed;
  }
  try {
    if (Object.keys(serialized).length) localStorage.setItem(key, JSON.stringify(serialized));
    else localStorage.removeItem(key);
  } catch {
    /* ignore */
  }
}

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || target.isContentEditable;
}

export default function App() {
  const initial = initialLayout();
  const [selectedIdx, setSelectedIdx] = createSignal(0);
  const [navHistory, setNavHistory] = createSignal<number[]>([0]);
  const [navPos, setNavPos] = createSignal(0);
  const navHistoryEntries = createMemo(() =>
    navHistory()
      .map((idx, pos) => ({ idx, pos }))
      .slice()
      .reverse(),
  );
  const [selectedReg, setSelectedReg] = createSignal("x0");
  const [selectedFn, setSelectedFn] = createSignal("");
  const [cursorHint, setCursorHint] = createSignal<CursorRecordHint | undefined>();
  // Row hint cache: every visible RecordsPanel row publishes its (idx, pc, func)
  // here. selectedIdx changes that hit the cache update cursorHint
  // synchronously (zero round-trip — fixes keyboard j/k lag and CallTree /
  // hash / Backtrace / etc. paths that previously only set selectedIdx and
  // forced CfgPanel to wait for /api/record). Cache miss falls through to
  // the cursorRecord resource below.
  const rowHintCache = new Map<number, CursorRecordHint>();
  let recordsVisibleNavigator: RecordsVisibleNavigator | null = null;
  const [rowHintCacheSize, setRowHintCacheSize] = createSignal(0);
  const [rowHintCacheVersion, setRowHintCacheVersion] = createSignal(0);
  function rememberRows(rows: RecordRow[]) {
    let changed = false;
    for (const row of rows) {
      const next = { idx: row.idx, pc: row.pc, func: row.func };
      const old = rowHintCache.get(row.idx);
      if (!old || old.pc !== next.pc || old.func !== next.func) {
        rowHintCache.set(row.idx, next);
        changed = true;
      }
    }
    while (rowHintCache.size > 5000) {
      const k = rowHintCache.keys().next().value as number | undefined;
      if (k === undefined) break;
      rowHintCache.delete(k);
      changed = true;
    }
    if (changed) {
      setRowHintCacheSize(rowHintCache.size);
      setRowHintCacheVersion((v) => v + 1);
    }
  }
  const cursorRecordSource = createMemo(() => {
    const idx = selectedIdx();
    rowHintCacheVersion();
    return rowHintCache.has(idx) ? undefined : idx;
  });
  const [cursorRecord] = createResource(cursorRecordSource, fetchRecord);
  createEffect(() => {
    const idx = selectedIdx();
    rowHintCacheVersion();
    const cached = rowHintCache.get(idx);
    if (cached) {
      const cur = cursorHint();
      if (cur?.idx !== cached.idx || cur?.pc !== cached.pc || cur?.func !== cached.func) {
        setCursorHint(cached);
      }
      return;
    }
    const r = cursorRecord();
    if (r && r.idx === idx) {
      const hint: CursorRecordHint = { idx: r.idx, pc: r.pc, func: r.func };
      rowHintCache.set(idx, hint);
      setRowHintCacheSize(rowHintCache.size);
      setRowHintCacheVersion((v) => v + 1);
      setCursorHint(hint);
    }
  });
  const [leftTab, setLeftTab] = createSignal<LeftTab>("funcs");
  const [rightTab, setRightTab] = createSignal<RightTab>("cfg");
  const [bottomTab, setBottomTab] = createSignal<BottomTab>("memory");
  const [helpState, setHelpState] = createSignal<HelpState | null>(null);
  const [hiddenSos, setHiddenSosSignal] = createSignal<Set<string>>(initialHiddenSos());
  const [cmdMode, setCmdMode] = createSignal<CmdMode>("");
  const [cmdValue, setCmdValue] = createSignal("");
  const [cmdStatus, setCmdStatus] = createSignal("j/k step · g/G edge · / search · : idx · n/N next");
  const [searchHits, setSearchHits] = createSignal<number[]>([]);
  const [searchPos, setSearchPos] = createSignal(0);
  const [searchPattern, setSearchPattern] = createSignal("");
  const [memoryRequest, setMemoryRequest] = createSignal<MemoryRequest | undefined>();
  const [taintRequest, setTaintRequest] = createSignal<TaintRunRequest | undefined>();
  const [taintOverlay, setTaintOverlay] = createSignal<RecordsTaintOverlay | null>(null);
  const [queryRequest, setQueryRequest] = createSignal<QueryRunRequest | undefined>();
  const [stringProvenanceRequest, setStringProvenanceRequest] = createSignal<StringProvenanceRequest | undefined>();
  const [leftW, setLeftW] = createSignal(initial.leftW);
  const [rightW, setRightW] = createSignal(initial.rightW);
  const [bottomH, setBottomH] = createSignal(initial.bottomH);
  const [colDot, setColDot] = createSignal(initial.colDot);
  const [colIdx, setColIdx] = createSignal(initial.colIdx);
  const [colPc, setColPc] = createSignal(initial.colPc);
  const [colFunc, setColFunc] = createSignal(initial.colFunc);
  const [colAsm, setColAsm] = createSignal(initial.colAsm);
  const [syncCfg, setSyncCfgSignal] = createSignal(initial.syncCfg);
  const [cfgDisplayFn, setCfgDisplayFn] = createSignal("");
  const [debugVisible, setDebugVisibleSignal] = createSignal(false);
  const [apiDebug, setApiDebugSignal] = createSignal(false);
  const [cfgDebugState, setCfgDebugState] = createSignal<CfgDebugState | null>(null);
  const [taskCenterOpen, setTaskCenterOpen] = createSignal(false);
  const [tasks, setTasks] = createSignal<Record<string, UiTaskEntry>>({});
  const taskEntries = createMemo(() =>
    Object.values(tasks()).sort((a, b) => b.updatedAt - a.updatedAt),
  );
  const activeTaskCount = createMemo(() =>
    taskEntries().filter((task) => task.status === "running").length,
  );
  const reportTask: UiTaskReporter = (update: UiTaskUpdate) => {
    const now = performance.now();
    setTasks((current) => {
      const prev = current[update.id];
      const startedAt = update.startedAt ?? prev?.startedAt ?? now;
      const endedAt = update.endedAt ?? (update.status === "running" ? undefined : now);
      return {
        ...current,
        [update.id]: {
          ...prev,
          ...update,
          startedAt,
          endedAt,
          updatedAt: now,
        },
      };
    });
  };
  function setApiDebug(next: boolean) {
    setApiDebugSignal(next);
    try {
      if (next) localStorage.setItem("tracemiku-api-debug", "1");
      else localStorage.removeItem("tracemiku-api-debug");
    } catch {
      /* ignore */
    }
  }
  function setDebugVisible(next: boolean) {
    setDebugVisibleSignal(next);
    try {
      if (next) localStorage.setItem("tracemiku-debug", "1");
      else localStorage.removeItem("tracemiku-debug");
    } catch {
      /* ignore */
    }
  }
  const [meta] = createResource(fetchMeta);
  const functionRenameKey = createMemo(() => {
    const path = meta()?.path;
    return path ? `${FUNCTION_RENAMES_PREFIX}${path}` : null;
  });
  const [functionRenames, setFunctionRenames] = createSignal<Map<string, string>>(new Map());
  const helpTopic = createMemo(() => helpState()?.topic ?? null);
  let cmdInput: HTMLInputElement | undefined;
  let hashJumpSeq = 0;
  let hashJumpAbort: AbortController | undefined;
  let searchSeq = 0;
  let searchAbort: AbortController | undefined;
  let gotoSeq = 0;

  createEffect(() => {
    const key = functionRenameKey();
    setFunctionRenames(key ? loadFunctionRenames(key) : new Map());
  });
  let gotoAbort: AbortController | undefined;
  let applyingNavHistory = false;

  function cancelHashJump() {
    hashJumpSeq += 1;
    hashJumpAbort?.abort();
    hashJumpAbort = undefined;
  }

  function cancelSearch() {
    searchSeq += 1;
    searchAbort?.abort();
    searchAbort = undefined;
  }

  function cancelGoto() {
    gotoSeq += 1;
    gotoAbort?.abort();
    gotoAbort = undefined;
  }

  onCleanup(() => {
    cancelHashJump();
    cancelSearch();
    cancelGoto();
  });

  function totalRecords(): number {
    return meta()?.records ?? 0;
  }

  function clampIdx(idx: number): number {
    const total = totalRecords();
    if (total <= 0) return Math.max(0, idx);
    return Math.min(total - 1, Math.max(0, idx));
  }

  function jumpToIdx(idx: number) {
    setSelectedIdx(clampIdx(idx));
  }

  function jumpVisible(delta: number) {
    const next = recordsVisibleNavigator?.nextVisibleIdx(selectedIdx(), delta) ?? selectedIdx() + delta;
    jumpToIdx(next);
  }

  createEffect(() => {
    const idx = selectedIdx();
    if (applyingNavHistory) {
      applyingNavHistory = false;
      return;
    }
    setNavHistory((history) => {
      const pos = untrack(navPos);
      if (history[pos] === idx) return history;
      const next = [...history.slice(0, pos + 1), idx].slice(-200);
      setNavPos(next.length - 1);
      return next;
    });
  });

  function jumpNavHistory(delta: 1 | -1) {
    const history = navHistory();
    const nextPos = clampNumber(navPos() + delta, 0, Math.max(0, history.length - 1));
    if (nextPos === navPos()) return;
    applyingNavHistory = true;
    setNavPos(nextPos);
    setSelectedIdx(history[nextPos]);
  }

  function clearNavHistory() {
    setNavHistory([selectedIdx()]);
    setNavPos(0);
  }

  function selectNavHistory(pos: number) {
    const history = navHistory();
    if (pos < 0 || pos >= history.length) return;
    applyingNavHistory = true;
    setNavPos(pos);
    setSelectedIdx(history[pos]);
  }

  function selectTraceRow(row: RecordRow) {
    setCursorHint({ idx: row.idx, pc: row.pc, func: row.func });
  }

  function pcFromHash(hash = window.location.hash): string | null {
    const m = hash.match(/^#insn_([0-9a-f]+)$/i);
    return m ? `0x${m[1].toLowerCase()}` : null;
  }

  async function jumpToHashPc(hash = window.location.hash) {
    const pc = pcFromHash(hash);
    if (!pc) return;
    cancelHashJump();
    const seq = ++hashJumpSeq;
    const abort = new AbortController();
    hashJumpAbort = abort;
    setCmdStatus(`resolving ${pc}...`);
    try {
      const r = await fetchIdxsForPc(pc, selectedIdx(), 80, abort.signal);
      if (seq !== hashJumpSeq || abort.signal.aborted) return;
      const candidates = [...r.before, ...r.after];
      if (!candidates.length) {
        setCmdStatus(`${pc}: not executed in trace`);
        return;
      }
      const cursor = selectedIdx();
      const nearest = candidates.sort((a, b) => Math.abs(a - cursor) - Math.abs(b - cursor))[0];
      jumpToIdx(nearest);
      setCmdStatus(`${pc}: jumped to #${nearest}`);
    } catch (err) {
      if (abort.signal.aborted) return;
      if (seq !== hashJumpSeq) return;
      setCmdStatus(`hash jump ${pc} failed: ${String(err)}`);
    } finally {
      if (hashJumpAbort === abort) hashJumpAbort = undefined;
    }
  }

  function normalizePcInput(raw: string): string | null {
    const text = raw.trim();
    const m = text.match(/^0x([0-9a-f]+)$/i);
    return m ? `0x${m[1].toLowerCase()}` : null;
  }

  async function jumpToFirstPc(pc: string, label = pc) {
    cancelGoto();
    const seq = ++gotoSeq;
    const abort = new AbortController();
    gotoAbort = abort;
    setCmdStatus(`resolving ${label}...`);
    try {
      const r = await fetchIdxsForPc(pc, 0, 1, abort.signal);
      if (seq !== gotoSeq || abort.signal.aborted) return;
      const first = r.after[0];
      if (first === undefined) {
        setCmdStatus(`${label}: not executed in trace`);
        return;
      }
      jumpToIdx(first);
      setCmdStatus(`${label}: jumped to #${first}`);
    } catch (err) {
      if (abort.signal.aborted || seq !== gotoSeq) return;
      setCmdStatus(`${label}: jump failed: ${String(err)}`);
    } finally {
      if (gotoAbort === abort) gotoAbort = undefined;
    }
  }

  function runGoto(raw: string) {
    const text = raw.trim();
    if (!text) return;
    const idxMatch = text.match(/^#?(\d+)$/);
    if (idxMatch) {
      const idx = Number.parseInt(idxMatch[1], 10);
      jumpToIdx(idx);
      setCmdStatus(`#${idx}: jumped to #${clampIdx(idx)}`);
      return;
    }
    const pc = normalizePcInput(text);
    if (pc) {
      void jumpToFirstPc(pc);
      return;
    }
    setCmdStatus(`unknown jump target: ${text}`);
  }

  async function selectFunctionByCommand(raw: string) {
    const needle = raw.trim();
    if (!needle) return;
    setCmdStatus(`resolving function ${needle}...`);
    try {
      const resp = await fetchFunctions();
      const lower = needle.toLowerCase();
      const fn = resp.functions.find((f) => f.name === needle || f.id === needle)
        ?? resp.functions.find((f) => f.name.toLowerCase().includes(lower) || f.id.toLowerCase().includes(lower));
      if (!fn) {
        setCmdStatus(`func ${needle}: not found`);
        return;
      }
      selectFunction(fn, false);
      setCmdStatus(`func ${fn.name}: selected`);
    } catch (err) {
      setCmdStatus(`func ${needle}: failed: ${String(err)}`);
    }
  }

  function runCommand(raw: string) {
    const text = raw.trim();
    if (!text) return;
    const pcCmd = text.match(/^pc\s+(0x[0-9a-f]+)$/i);
    if (pcCmd) {
      void jumpToFirstPc(pcCmd[1]);
      return;
    }
    const funcCmd = text.match(/^(?:func|fn)\s+(.+)$/i);
    if (funcCmd) {
      void selectFunctionByCommand(funcCmd[1]);
      return;
    }
    const memCmd = text.match(/^mem(?:ory)?\s+(\S+)(?:\s+(?:len|size)\s+(\d+))?$/i);
    if (memCmd) {
      const count = memCmd[2] ? Number.parseInt(memCmd[2], 10) : undefined;
      openMemoryAt(memCmd[1], count);
      setCmdStatus(`memory ${memCmd[1]}${count ? ` len ${count}` : ""}`);
      return;
    }
    const taintCmd = text.match(/^taint\s+(bwd|back|backward|fwd|forward)\s+(\S+)(?:\s+@?#?(\d+))?$/i);
    if (taintCmd) {
      const direction = taintCmd[1].toLowerCase().startsWith("b") ? "backward" : "forward";
      const idx = taintCmd[3] ? Number.parseInt(taintCmd[3], 10) : selectedIdx();
      runTaintFrom(idx, taintCmd[2], direction);
      setCmdStatus(`taint ${direction} ${taintCmd[2]} @${idx}`);
      return;
    }
    const queryCmd = text.match(/^query\s+(.+)$/i);
    if (queryCmd) {
      runQueryText(queryCmd[1]);
      return;
    }
    runGoto(text);
  }

  function selectFunction(fn: FunctionEntry, jumpEntry = false) {
    setSelectedFn(fn.id);
    setSyncCfg(false);
    setRightTab("cfg");
    if (jumpEntry && fn.entry_pc !== null) {
      void jumpToFirstPc(`0x${fn.entry_pc.toString(16)}`, functionLabel(fn));
    } else if (jumpEntry) {
      setCmdStatus(`${functionLabel(fn)}: no trace entry PC`);
    }
  }

  function functionLabel(fn: FunctionEntry): string {
    return functionRenames().get(fn.id) ?? fn.name;
  }

  function renameFunction(fn: FunctionEntry) {
    const key = functionRenameKey();
    if (!key) return;
    const current = functionRenames().get(fn.id) ?? fn.name;
    const next = window.prompt("rename function", current);
    if (next === null) return;
    const trimmed = next.trim();
    setFunctionRenames((prev) => {
      const updated = new Map(prev);
      if (!trimmed || trimmed === fn.name) updated.delete(fn.id);
      else updated.set(fn.id, trimmed);
      saveFunctionRenames(key, updated);
      return updated;
    });
  }

  function setHiddenSos(next: Set<string>) {
    setHiddenSosSignal(new Set(next));
    localStorage.setItem(HIDDEN_SOS_KEY, JSON.stringify([...next]));
  }

  function layoutSnapshot(overrides: Partial<LayoutState> = {}): LayoutState {
    return {
      leftW: leftW(),
      rightW: rightW(),
      bottomH: bottomH(),
      colDot: colDot(),
      colIdx: colIdx(),
      colPc: colPc(),
      colFunc: colFunc(),
      colAsm: colAsm(),
      syncCfg: syncCfg(),
      ...overrides,
    };
  }

  function persistLayout(overrides: Partial<LayoutState> = {}) {
    localStorage.setItem(LAYOUT_KEY, JSON.stringify(layoutSnapshot(overrides)));
  }

  function setSyncCfg(next: boolean) {
    setSyncCfgSignal(next);
    persistLayout({ syncCfg: next });
  }

  function startPanelResize(kind: "left" | "right" | "bottom", e: PointerEvent) {
    e.preventDefault();
    const startX = e.clientX;
    const startY = e.clientY;
    const startLeft = leftW();
    const startRight = rightW();
    const startBottom = bottomH();
    document.body.classList.add("is-resizing");
    document.body.style.cursor = kind === "bottom" ? "row-resize" : "col-resize";

    const onMove = (ev: PointerEvent) => {
      if (kind === "left") {
        setLeftW(clampNumber(startLeft + ev.clientX - startX, 180, 680));
      } else if (kind === "right") {
        setRightW(clampNumber(startRight - (ev.clientX - startX), 320, 960));
      } else {
        setBottomH(clampNumber(startBottom - (ev.clientY - startY), 120, 560));
      }
    };
    const onUp = () => {
      document.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerup", onUp);
      document.body.classList.remove("is-resizing");
      document.body.style.cursor = "";
      persistLayout();
    };
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
  }

  function startAsmColResize(kind: "dot" | "idx" | "pc" | "func" | "asm", e: PointerEvent) {
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    const starts = {
      dot: colDot(),
      idx: colIdx(),
      pc: colPc(),
      func: colFunc(),
      asm: colAsm(),
    };
    document.body.classList.add("is-resizing");
    document.body.style.cursor = "col-resize";
    const onMove = (ev: PointerEvent) => {
      const delta = ev.clientX - startX;
      if (kind === "dot") setColDot(clampNumber(starts.dot + delta, 12, 48));
      else if (kind === "idx") setColIdx(clampNumber(starts.idx + delta, 44, 140));
      else if (kind === "pc") setColPc(clampNumber(starts.pc + delta, 80, 260));
      else if (kind === "func") setColFunc(clampNumber(starts.func + delta, 80, 420));
      else setColAsm(clampNumber(starts.asm + delta, 180, 900));
    };
    const onUp = () => {
      document.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerup", onUp);
      document.body.classList.remove("is-resizing");
      document.body.style.cursor = "";
      persistLayout();
    };
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
  }

  const layoutStyle = createMemo<JSX.CSSProperties>(() => ({
    "--left-w": `${leftW()}px`,
    "--right-w": `${rightW()}px`,
    "--bottom-h": `${bottomH()}px`,
  }));

  const asmStyle = createMemo<JSX.CSSProperties>(() => ({
    "--col-dot": `${colDot()}px`,
    "--col-idx": `${colIdx()}px`,
    "--col-pc": `${colPc()}px`,
    "--col-func": `${colFunc()}px`,
    "--col-asm": `${colAsm()}px`,
  }));

  function openMemoryAt(addr: string, count?: number) {
    setBottomTab("memory");
    setMemoryRequest({ token: Date.now(), addr, count });
  }

  function runTaintFrom(idx: number, reg: string, direction: TaintRunDirection) {
    jumpToIdx(idx);
    setSelectedReg(reg);
    setLeftTab("taint");
    setTaintRequest({ token: Date.now(), idx, reg, direction });
  }

  function updateTaintOverlay(result: TaintOverlayResult | null) {
    if (!result) {
      setTaintOverlay(null);
      return;
    }
    const mode = untrack(taintOverlay)?.mode ?? "highlight";
    setTaintOverlay({
      idxs: new Set(result.rows.map((row) => row.idx)),
      rows: result.rows.map(recordRowFromTaintRow),
      direction: result.direction,
      from: result.from,
      reg: result.reg,
      count: result.count,
      stopped: result.stopped,
      mode,
    });
  }

  function setTaintOverlayMode(mode: RecordsTaintOverlayMode) {
    setTaintOverlay((current) => (current ? { ...current, mode } : current));
  }

  function recordRowFromTaintRow(row: TaintRow): RecordRow {
    const mnemonic = row.asm.trim().split(/\s+/, 1)[0]?.toLowerCase() ?? "";
    return {
      idx: row.idx,
      pc: row.pc,
      rel: row.rel,
      module: null,
      func: row.func,
      off: null,
      asm: row.asm,
      annotation: row.why ?? row.via ?? null,
      exec_count: null,
      is_branch: mnemonic.startsWith("b") || mnemonic === "cbz" || mnemonic === "cbnz" || mnemonic === "tbz" || mnemonic === "tbnz",
      is_call: mnemonic === "bl" || mnemonic === "blr",
      is_ret: mnemonic === "ret",
    };
  }

  function showStringProvenance(req: Omit<StringProvenanceRequest, "token">) {
    setStringProvenanceRequest({ ...req, token: Date.now() });
    setBottomTab("string-provenance");
  }

  function runQueryText(text: string) {
    setBottomTab("query");
    setQueryRequest({ token: Date.now(), text });
    setCmdStatus(`query: ${text}`);
  }

  function openCmd(mode: CmdMode) {
    setCmdMode(mode);
    setCmdValue("");
    queueMicrotask(() => cmdInput?.focus());
  }

  function closeCmd() {
    setCmdMode("");
    setCmdValue("");
    cmdInput?.blur();
  }

  async function runSearch(pattern: string) {
    const q = pattern.trim();
    if (!q) return;
    cancelSearch();
    const seq = ++searchSeq;
    const abort = new AbortController();
    searchAbort = abort;
    setCmdStatus(`searching ${q}...`);
    try {
      const cursor = selectedIdx();
      const r = await fetchSearch(q, 2000, abort.signal, cursor);
      if (seq !== searchSeq || abort.signal.aborted) return;
      const hits = r.hits.map((hit) => hit.idx).sort((a, b) => a - b);
      setSearchPattern(q);
      setSearchHits(hits);
      if (hits.length === 0) {
        setSearchPos(0);
        setCmdStatus(`${q}: 0 hits`);
        return;
      }
      let pos = hits.findIndex((idx) => idx >= cursor);
      if (pos < 0) pos = 0;
      setSearchPos(pos);
      jumpToIdx(hits[pos]);
      const partial = r.truncated
        ? ` · partial ${r.returned ?? hits.length}/${r.total_matches ?? hits.length}`
        : "";
      setCmdStatus(`${q}: ${pos + 1}/${hits.length} hits${partial}`);
    } catch (err) {
      if (abort.signal.aborted) return;
      if (seq !== searchSeq) return;
      setCmdStatus(`search failed: ${String(err)}`);
    } finally {
      if (searchAbort === abort) searchAbort = undefined;
    }
  }

  function stepSearch(dir: 1 | -1) {
    const hits = searchHits();
    if (hits.length === 0) {
      setCmdStatus("no search results, press / first");
      return;
    }
    let pos = searchPos() + dir;
    if (pos < 0) pos = hits.length - 1;
    if (pos >= hits.length) pos = 0;
    setSearchPos(pos);
    jumpToIdx(hits[pos]);
    setCmdStatus(`${searchPattern()}: ${pos + 1}/${hits.length} hits`);
  }

  function submitCmd() {
    const mode = cmdMode();
    const value = cmdValue();
    closeCmd();
    if (mode === "/") {
      void runSearch(value);
      return;
    }
    if (mode === ":") {
      runCommand(value);
    }
  }

  onMount(() => {
    try {
      if (localStorage.getItem("tracemiku-api-debug") === "1") setApiDebugSignal(true);
      if (localStorage.getItem("tracemiku-debug") === "1") setDebugVisibleSignal(true);
    } catch {
      /* ignore */
    }
    void jumpToHashPc();
    const onHashChange = () => {
      void jumpToHashPc();
    };
    window.addEventListener("hashchange", onHashChange);

    const onKey = (e: KeyboardEvent) => {
      if (helpState()) {
        if (e.key === "Escape") setHelpState(null);
        return;
      }
      if (isEditableTarget(e.target)) return;
      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault();
        jumpVisible(1);
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        jumpVisible(-1);
      } else if (e.key === "PageDown") {
        e.preventDefault();
        jumpVisible(20);
      } else if (e.key === "PageUp") {
        e.preventDefault();
        jumpVisible(-20);
      } else if (e.key === "Home") {
        e.preventDefault();
        jumpToIdx(0);
      } else if (e.key === "End" || e.key === "G") {
        e.preventDefault();
        jumpToIdx(Math.max(0, totalRecords() - 1));
      }
      else if (e.key === "/") {
        e.preventDefault();
        openCmd("/");
      } else if (e.key === "g") {
        e.preventDefault();
        openCmd(":");
      } else if (e.key === ":") {
        e.preventDefault();
        openCmd(":");
      } else if (e.key === "n") stepSearch(1);
      else if (e.key === "N") stepSearch(-1);
    };
    window.addEventListener("keydown", onKey);
    onCleanup(() => {
      window.removeEventListener("hashchange", onHashChange);
      window.removeEventListener("keydown", onKey);
    });
  });

  const leftTitle = createMemo(() => {
    const titles: Record<LeftTab, string> = {
      funcs: "Functions",
      back: "Backtrace",
      calltree: "Call Tree",
      forks: "Forks",
      strings: "Strings",
      taint: "Taint",
      slice: "Slice",
      xref: "Refs",
      sofilter: "SO Filter",
      settings: "Settings",
    };
    return titles[leftTab()];
  });
  const rightTitle = createMemo(() => {
    const titles: Record<RightTab, string> = {
      cfg: "Graph",
      regs: "Registers",
      hlil: "HLIL",
      dec: "Decompile",
    };
    return titles[rightTab()];
  });

  const vtab = (tab: LeftTab, label: string, title: string) => (
    <button
      class="vtab"
      data-vtab={tab}
      classList={{ active: leftTab() === tab }}
      title={title}
      onClick={() => setLeftTab(tab)}
    >
      {label}
    </button>
  );
  const rtab = (tab: RightTab, label: string, title: string) => (
    <button
      class="vtab"
      data-rtab={tab}
      classList={{ active: rightTab() === tab }}
      title={title}
      onClick={() => setRightTab(tab)}
    >
      {label}
    </button>
  );
  const btab = (tab: BottomTab, label: string) => (
    <button
      class="btab"
      data-btab={tab}
      classList={{ active: bottomTab() === tab }}
      onClick={() => setBottomTab(tab)}
    >
      {label}
    </button>
  );
  const helpButton = (topic: HelpTopic) => (
    <button
      class="help-btn"
      type="button"
      title="帮助"
      onClick={(e) => {
        const rect = e.currentTarget.getBoundingClientRect();
        const cardW = Math.min(560, window.innerWidth - 24);
        // Reserve enough height for the longest help body (~320 px). Flip
        // the card to the side that has more room, then clamp to keep both
        // edges inside the viewport with an 8px margin.
        const cardH = Math.min(360, window.innerHeight - 24);
        const spaceBelow = window.innerHeight - rect.bottom - 8;
        const spaceAbove = rect.top - 8;
        const placeAbove = spaceBelow < cardH && spaceAbove > spaceBelow;
        const yRaw = placeAbove ? rect.top - cardH - 8 : rect.bottom + 8;
        const x = Math.max(8, Math.min(rect.left, window.innerWidth - cardW - 8));
        const y = Math.max(8, Math.min(yRaw, window.innerHeight - cardH - 8));
        setHelpState({ topic, x, y });
      }}
    >
      ?
    </button>
  );
  const helpTitle = createMemo(() => {
    const topic = helpTopic();
    if (topic === "overview") return "traceMiku Web";
    if (topic === "disasm") return "Disassembly";
    if (topic === "right") return rightTitle();
    if (topic === "bottom") {
      if (bottomTab() === "memory") return "Memory";
      if (bottomTab() === "trace-for-pc") return "Trace for PC";
      if (bottomTab() === "string-provenance") return "String Provenance";
      if (bottomTab() === "query") return "Trace Query";
      return "Navigation";
    }
    return leftTitle();
  });
  const helpBody = createMemo(() => {
    const topic = helpTopic();
    if (topic === "overview") {
      return "主界面按调试器布局组织：左侧是函数、回溯、调用树、字符串、污点、Slice 和交叉引用；中间是动态执行过的汇编 trace；下方是内存和当前 PC 的执行历史；右侧是 CFG、寄存器和 HLIL。全局 cursor 就是当前选中的 trace idx，所有窗口都围绕它联动。点击行会设置 cursor；点击寄存器只设置 reg 不跳转；只有双击寄存器或 CFG 单击指令才会移动 cursor。";
    }
    if (topic === "disasm") {
      return "每一行是一条实际执行过的 ARM64 指令快照，不是静态反汇编列表。列含义依次是执行序号、PC、函数+偏移和汇编文本。滚动条对应整个 trace；点击行设置 cursor。寄存器交互：单击 = 选中该寄存器（Taint/Registers 同步）+ 在 dot 列上画一条长箭头连到最近的 def（红 ▲）和 use（绿 ▼），点箭头跳过去；双击寄存器 = 直接跳到 last write；右键寄存器 = 上下文菜单（取值、CFG view、taint）。地址 token 双击跳到最近 PC。Esc 清掉 def/use 箭头。";
    }
    if (topic === "right") {
      if (rightTab() === "cfg") return "CFG 显示当前函数的动态基本块图，默认跟随当前 trace 所在函数，避免直接渲染全 trace 导致 dot 超时。空白处拖动平移（拖动期间不会触发 click），按住 Ctrl 滚轮缩放；单击图中的指令或块头会跳到 trace 中离当前 cursor 最近的一次执行——同时联动 Records、Registers、Memory、HLIL、Trace for PC。";
      if (rightTab() === "regs") return "寄存器窗口显示当前 cursor 的寄存器状态，并像 pwndbg 一样自动高亮相对上一条 trace 发生变化的寄存器；note 会标出 zero、pc、sp/stack 和疑似指针。点击寄存器会把它设为 Taint/Slice 的当前寄存器（不会跳转 cursor）。";
      if (rightTab() === "hlil") return "HLIL 窗口跟随当前汇编 cursor 的 PC；配置了 Binary Ninja sidecar 时显示 Pseudo C 和 HLIL 两种结构化文本，并高亮当前 PC 对应的行。缩进来自 BN 返回的结构化 indent。点击 HLIL 行会跳到该 PC 在 trace 中离当前 cursor 最近的一次执行。";
      if (rightTab() === "dec") return "Decompile 显示 traceMiku 本地 Trace IR markdown 和 LLIL render。LLIL records 限制参与渲染的 trace 记录数；DCE 是 Dead Code Elimination，会移除计算结果没有被后续使用的临时语句，适合看更短的伪代码，但排查 lift 细节时可以关闭。这里不调用任何 LLM；模型选择和 LLM 输出暂时不在 UI 中开放。";
      return "";
    }
    if (topic === "bottom") {
      if (bottomTab() === "memory") return "Memory 是按调试器习惯排列的 hex+ASCII dump。addr 可以填十六进制地址，也可以填 x0、x1、sp 这类寄存器名；字节颜色表示读、写、外部来源或未知，当前 cursor 发生变化的字节会直接在 dump 中高亮。双击字节跳来源 idx，右键字节显示该地址前后的读写触碰分析。";
      if (bottomTab() === "trace-for-pc") return "Trace for PC 显示当前 PC 在 trace 中其它执行位置，分为 cursor 之前和之后。它用来分析循环、调度器、热点指令和同一静态指令在不同时间的状态差异。点击任意行跳转到对应 idx。CFG 单击指令会更新 cursor，本面板自动同步刷新。";
      if (bottomTab() === "string-provenance") return "String Provenance 显示 Strings 双击后选中字符串的逐字节来源。上方 String Byte Flow 的含义是 writer trace 写出某个字符字节 → 该字节当前值 → reader trace 读取该字节；为了避免图过密，只展示前 32 个字节和每字节最多 2 个写/读事件。下方表格保留完整 writer/reader 列表，点击 writer#/reader# 会跳到对应 trace。";
      if (bottomTab() === "query") return "Trace Query 是统一的结构化查询入口，可查询 records、regs、mem/reads/writes、functions、strings、JNI 和 provenance。命令栏里输入 query writes 0x... len 32、query mem addr 0x... len 32 或 query regs x9 会直接打开这里。";
      return "Navigation 记录本次页面会话里的 cursor 跳转历史，所有来自 Disassembly、CFG、CallTree、Strings、Refs 和 Trace for PC 的跳转都会进入这里。back/forward 只改变 cursor，不重新请求历史。";
    }
    if (leftTab() === "funcs") return "Functions 汇总 trace、符号和 BN sidecar 里的函数条目。选择函数会驱动 CFG 和 HLIL；记录数、block 数和入口地址用来判断热函数和分析范围。";
    if (leftTab() === "back") return "Backtrace 在当前 cursor 处重建动态调用栈。点击 frame 会跳到对应 call site，用于从深层 JNI/Native 调用回到上游上下文。";
    if (leftTab() === "calltree") return "Call Tree 显示整个 trace 的动态嵌套调用关系。定位当前函数按钮会展开并选中包含当前汇编 trace 的函数节点，适合从执行流角度找上下文。";
    if (leftTab() === "strings") return "Strings 来自 MemShadow 对内存写入的可打印字符串扫描。单击跳到第一次写入/触碰该字符串地址的 trace；双击会在底部 Provenance 展示每个字符是谁写入、谁读取。";
    if (leftTab() === "taint") return "Taint 模拟逐指令的污点传播：从当前 cursor + 寄存器开始，按 trace 顺序一步步推进，可选 through_mem（穿越内存）、cross_fn_call（穿越函数调用）、data_only（只看值流不看地址流）。返回每一行的 parent_idxs / taint_depth，可以画传播树。比 Slice 慢但语义更细——需要看「这个值经过了哪些指令、被哪条指令读/写」时用 Taint。";
    if (leftTab() === "slice") return "Slice 在持久化依赖 CSR 上做一次 BFS，比 Taint 快得多。Backward 把当前 cursor 当 sink，列出所有它直接/间接依赖的 trace 行；填第二个 idx + 切到 intersection，会得到两个 cursor 的「共同祖先」（dataflow 交点）。Forward 是反方向 def→use，列出当前行的下游使用者。data only 丢弃控制流依赖。结果按 BFS 发现顺序（单种子）或 idx 升序（多种子求交/并）排列——不是按时间或函数。Slice 不模拟传播过程也没有 through_mem/cross_fn 这些开关；要看传播细节用 Taint。";
    if (leftTab() === "xref") return "Refs 上半部分是当前 PC 在 trace 中的其它执行位置；下半部分是按解码后的汇编文本做正则搜索。它不是静态代码引用分析，ret 这类通用指令只有在提交文本搜索后才会列出匹配。";
    if (leftTab() === "settings") return "Settings 显示后端 API、MemShadow 状态、密度和调试开关。API debug log 可在需要定位前端/后端交互时打开。";
    return "SO Filter 用于多 so trace 的折叠、过滤和当前模块聚焦；核心原则是只改变显示范围，不改变 trace 数据本身。";
  });

  return (
    <>
      <header id="topbar">
        <span class="brand">
          traceMiku <span class="dim">web</span>
        </span>
        <span class="meta">Rust v2</span>
        <span class="grow" />
        <label class="toggle" title="关闭后跨函数移动 cursor 不会自动重渲染 CFG">
          <input
            type="checkbox"
            checked={syncCfg()}
            onChange={(e) => setSyncCfg(e.currentTarget.checked)}
          />
          <span>同步 CFG</span>
        </label>
        <button
          class="dbg-toggle"
          classList={{ active: debugVisible() }}
          title="切换调试浮层 (selectedIdx / cursorHint / fnName / 缓存大小 / API 日志开关)"
          onClick={() => setDebugVisible(!debugVisible())}
        >
          dbg
        </button>
        <span class="hint">↑/↓ 单步 · PgUp/PgDn 翻页 · Home/End 头尾 · / 搜索 · g 跳 #idx/0xPC</span>
        <button
          class="task-toggle"
          classList={{ active: taskCenterOpen() || activeTaskCount() > 0 }}
          title="Task Center: running/cached/partial/error analysis jobs"
          onClick={() => setTaskCenterOpen(!taskCenterOpen())}
        >
          tasks {activeTaskCount()}
        </button>
        {helpButton("overview")}
      </header>

      <main id="layout" style={layoutStyle()}>
        <div
          class="layout-splitter layout-splitter-left"
          title="拖拽调整左侧面板宽度"
          onPointerDown={(e) => startPanelResize("left", e)}
        />
        <div
          class="layout-splitter layout-splitter-right"
          title="拖拽调整右侧面板宽度"
          onPointerDown={(e) => startPanelResize("right", e)}
        />
        <aside id="left-tabs">
          {vtab("funcs", "Functions", "函数列表")}
          {vtab("back", "Backtrace", "当前 cursor 处的调用栈")}
          {vtab("calltree", "Call Tree", "整 trace 的嵌套调用树")}
          {vtab("forks", "Forks", "fork/clone 事件")}
          {vtab("strings", "Strings", "MemShadow 字符串")}
          {vtab("taint", "Taint", "逐指令污点传播（forward/backward + through_mem + cross_fn + tree/timeline）。要看「这个值经过了哪些指令」用这里；只查祖先/后继用 Slice")}
          {vtab("slice", "Slice", "依赖 CSR 上的 BFS：backward 列祖先、forward 列后继；多种子可求 intersection（共同祖先）。比 Taint 快但不模拟传播")}
          {vtab("xref", "Refs", "当前 PC 执行历史和汇编文本搜索")}
          {vtab("sofilter", "SO Filter", "multi-SO 过滤状态")}
          {vtab("settings", "Settings", "显示和 API 状态")}
        </aside>

        <section id="left-panel">
          <div class="panelhead">
            <span>{leftTitle()}</span>
            <span class="grow" />
            <span class="dim">idx {selectedIdx()}</span>
            {helpButton("left")}
          </div>
          <div id="left-panel-body">
            <div class="lp-tab" classList={{ active: leftTab() === "funcs" }}>
              <FunctionsPanel
                selectedFn={selectedFn}
                renames={functionRenames}
                onSelectFn={(fn) => selectFunction(fn, false)}
                onJumpFn={(fn) => selectFunction(fn, true)}
                onRenameFn={renameFunction}
                active={leftTab() === "funcs"}
              />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "back" }}>
              <BacktracePanel idx={selectedIdx()} onSelect={setSelectedIdx} active={leftTab() === "back"} />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "calltree" }}>
              <CallTreePanel currentIdx={selectedIdx()} onSelect={setSelectedIdx} active={leftTab() === "calltree"} />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "forks" }}>
              <ForksPanel active={leftTab() === "forks"} />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "strings" }}>
              <StringsPanel
                idx={selectedIdx()}
                onSelect={setSelectedIdx}
                onShowProvenance={showStringProvenance}
                active={leftTab() === "strings"}
              />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "taint" }}>
              <TaintPanel
                idx={selectedIdx()}
                reg={selectedReg()}
                onRegChange={setSelectedReg}
                onSelect={setSelectedIdx}
                runRequest={taintRequest()}
                active={leftTab() === "taint"}
                onTaskUpdate={reportTask}
                onOverlayChange={updateTaintOverlay}
              />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "slice" }}>
              <SlicePanel
                idx={selectedIdx()}
                reg={selectedReg()}
                onSelect={setSelectedIdx}
                active={leftTab() === "slice"}
              />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "xref" }}>
              <XrefPanel idx={selectedIdx()} onSelect={setSelectedIdx} active={leftTab() === "xref"} />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "sofilter" }}>
              <SoFilterPanel hiddenSos={hiddenSos()} onHiddenSosChange={setHiddenSos} />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "settings" }}>
              <SettingsPanel
                active={leftTab() === "settings"}
                debugVisible={debugVisible()}
                apiDebug={apiDebug()}
                onDebugVisibleChange={setDebugVisible}
                onApiDebugChange={setApiDebug}
              />
            </div>
          </div>
        </section>

        <section id="asm-col" style={asmStyle()}>
          <div class="panelhead">
            <span>
              Disassembly <span class="dim">trace stream</span>
            </span>
            <span class="grow" />
            <span class="dim">
              cursor {selectedIdx()} · reg {selectedReg()}
            </span>
            {helpButton("disasm")}
          </div>
          <div id="stream-header">
            <span class="hd ec-spacer">
              <span class="col-resize" title="调整标记列宽" onPointerDown={(e) => startAsmColResize("dot", e)} />
            </span>
            <span class="hd hd-idx">
              idx
              <span class="col-resize" title="调整 idx 列宽" onPointerDown={(e) => startAsmColResize("idx", e)} />
            </span>
            <span class="hd hd-pc">
              pc
              <span class="col-resize" title="调整 pc 列宽" onPointerDown={(e) => startAsmColResize("pc", e)} />
            </span>
            <span class="hd hd-func">
              rel
              <span class="col-resize" title="调整 rel 列宽" onPointerDown={(e) => startAsmColResize("func", e)} />
            </span>
            <span class="hd hd-asm">
              asm
              <span class="col-resize" title="调整 asm 列宽" onPointerDown={(e) => startAsmColResize("asm", e)} />
            </span>
          </div>
          <div id="stream">
            <RecordsPanel
              selectedIdx={selectedIdx()}
              selectedReg={selectedReg()}
              onSelect={setSelectedIdx}
              onSelectRow={selectTraceRow}
              onSelectReg={setSelectedReg}
              hiddenSos={hiddenSos()}
              onOpenMemory={openMemoryAt}
              onRunTaint={runTaintFrom}
              onRowsLoaded={rememberRows}
              onVisibleNavigator={(navigator) => {
                recordsVisibleNavigator = navigator;
              }}
              taintOverlay={taintOverlay()}
              onTaintOverlayModeChange={setTaintOverlayMode}
              onClearTaintOverlay={() => setTaintOverlay(null)}
            />
          </div>
          <div
            id="bottom-resize"
            title="拖拽调整底部面板高度"
            onPointerDown={(e) => startPanelResize("bottom", e)}
          />
          <div id="bottom-tabs">
            {btab("memory", "Memory")}
            {btab("navigation", "Navigation")}
            {btab("trace-for-pc", "Trace for PC")}
            {btab("string-provenance", "Provenance")}
            {btab("query", "Query")}
            <span class="grow" />
            {helpButton("bottom")}
          </div>
          <div id="bottom-content">
            <div class="bbody" classList={{ active: bottomTab() === "memory" }}>
              <MemoryPanel
                idx={selectedIdx()}
                onSelect={setSelectedIdx}
                addrRequest={memoryRequest()}
                active={bottomTab() === "memory"}
                onTaskUpdate={reportTask}
              />
            </div>
            <div class="bbody" classList={{ active: bottomTab() === "navigation" }}>
              <div class="nav-panel">
                <div class="nav-controls">
                  <button type="button" onClick={() => jumpNavHistory(-1)} disabled={navPos() <= 0}>
                    back
                  </button>
                  <button
                    type="button"
                    onClick={() => jumpNavHistory(1)}
                    disabled={navPos() >= navHistory().length - 1}
                  >
                    forward
                  </button>
                  <button type="button" onClick={clearNavHistory} disabled={navHistory().length <= 1}>
                    clear
                  </button>
                  <span class="dim small">
                    {navPos() + 1}/{navHistory().length} · cursor #{selectedIdx()}
                  </span>
                </div>
                <div class="nav-history-list">
                  <For each={navHistoryEntries()}>
                    {(entry) => (
                      <button
                        type="button"
                        classList={{ active: entry.pos === navPos() }}
                        onClick={() => selectNavHistory(entry.pos)}
                      >
                        <span>#{entry.idx}</span>
                        <span class="dim small">{entry.pos === navPos() ? "current" : entry.pos + 1}</span>
                      </button>
                    )}
                  </For>
                </div>
              </div>
            </div>
            <div class="bbody" classList={{ active: bottomTab() === "trace-for-pc" }}>
              <TraceForPcPanel
                idx={selectedIdx()}
                onSelect={setSelectedIdx}
                active={bottomTab() === "trace-for-pc"}
              />
            </div>
            <div class="bbody" classList={{ active: bottomTab() === "string-provenance" }}>
              <StringProvenancePanel
                request={stringProvenanceRequest()}
                onSelect={setSelectedIdx}
                active={bottomTab() === "string-provenance"}
                onTaskUpdate={reportTask}
              />
            </div>
            <div class="bbody" classList={{ active: bottomTab() === "query" }}>
              <QueryPanel
                idx={selectedIdx()}
                selectedReg={selectedReg()}
                onSelect={setSelectedIdx}
                active={bottomTab() === "query"}
                runRequest={queryRequest()}
                onTaskUpdate={reportTask}
              />
            </div>
          </div>
        </section>

        <section id="right-col">
          <div class="panelhead">
            <span>{rightTitle()}</span>
            <span class="grow" />
            <span class="dim">
              {rightTab() === "cfg"
                ? cfgDisplayFn() || "select function"
                : rightTab() === "hlil"
                  ? cursorHint()?.func ?? cursorHint()?.pc ?? "resolving cursor"
                  : selectedFn() || "no fn selected"}
            </span>
            {helpButton("right")}
          </div>
          <div id="right-body">
            <div class="rbody" classList={{ active: rightTab() === "cfg" }}>
              <CfgPanel
                selectedFn={selectedFn()}
                currentIdx={selectedIdx()}
                currentHint={cursorHint()}
                onSelect={setSelectedIdx}
                active={rightTab() === "cfg"}
                syncEnabled={syncCfg()}
                onDisplayFnChange={setCfgDisplayFn}
                onDebugChange={setCfgDebugState}
                onTaskUpdate={reportTask}
              />
            </div>
            <div class="rbody" classList={{ active: rightTab() === "regs" }}>
              <RegistersPanel
                idx={selectedIdx()}
                selectedReg={selectedReg()}
                onSelectReg={setSelectedReg}
                onSelect={setSelectedIdx}
                active={rightTab() === "regs"}
              />
            </div>
            <div class="rbody" classList={{ active: rightTab() === "hlil" }}>
              <HlilPanel
                currentHint={cursorHint()}
                currentIdx={selectedIdx()}
                onSelect={setSelectedIdx}
                active={rightTab() === "hlil"}
                onTaskUpdate={reportTask}
              />
            </div>
            <div class="rbody" classList={{ active: rightTab() === "dec" }}>
              <DecompilerPanel
                selectedFn={selectedFn}
                onSelectFn={setSelectedFn}
                active={rightTab() === "dec"}
              />
            </div>
          </div>
        </section>

        <aside id="right-tabs">
          {rtab("cfg", "Graph", "Trace CFG")}
          {rtab("regs", "Registers", "当前 cursor 寄存器")}
          {rtab("hlil", "HLIL", "BN HLIL")}
          {rtab("dec", "Decompile", "Trace IR / LLIL decompile")}
        </aside>

        <footer id="cmdbar">
          <span class="dim">{cmdMode() || ":"}</span>
          <input
            ref={(el) => {
              cmdInput = el;
            }}
            id="cmd-input"
            type="text"
            class="inp"
            value={cmdValue()}
            readOnly={!cmdMode()}
            placeholder={cmdMode() === "/" ? "search asm..." : cmdMode() === ":" ? "#240, 0xPC, pc 0x..., func name, mem addr len 128, taint bwd x9 @93, query ..." : "press / or g"}
            onInput={(e) => setCmdValue(e.currentTarget.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") closeCmd();
              if (e.key === "Enter") submitCmd();
            }}
          />
          <span class="cmd-status dim">{cmdStatus()}</span>
        </footer>
      </main>
      <Show when={helpState()}>
        {(state) => (
        <div class="help-popover" role="dialog" aria-modal="true" onClick={() => setHelpState(null)}>
          <div
            class="help-card"
            style={{ left: `${state().x}px`, top: `${state().y}px` }}
            onClick={(e) => e.stopPropagation()}
          >
            <button class="help-close" type="button" onClick={() => setHelpState(null)}>
              ×
            </button>
            <h3>{helpTitle()}</h3>
            <p>{helpBody()}</p>
          </div>
        </div>
        )}
      </Show>
      <Show when={taskCenterOpen() || activeTaskCount() > 0}>
        <div class="task-center">
          <div class="task-center-head">
            <b>Task Center</b>
            <span class="dim small">{activeTaskCount()} running · {taskEntries().length} recent</span>
            <button type="button" onClick={() => setTaskCenterOpen(false)}>close</button>
          </div>
          <For each={taskEntries().slice(0, 12)}>
            {(task) => {
              const elapsed = Math.max(0, Math.round(((task.endedAt ?? performance.now()) - task.startedAt)));
              return (
                <div class="task-row" classList={{ running: task.status === "running", error: task.status === "error", partial: task.status === "partial" }}>
                  <span class="task-status">{task.status}</span>
                  <span class="task-main">
                    <b>{task.surface}</b>
                    <span>{task.label}</span>
                    <Show when={task.detail}>
                      <small>{task.detail}</small>
                    </Show>
                  </span>
                  <code>{elapsed}ms</code>
                </div>
              );
            }}
          </For>
        </div>
      </Show>
      <Show when={debugVisible()}>
        <div class="debug-overlay">
          <div class="debug-row">
            <span>selectedIdx</span>
            <code>{selectedIdx()}</code>
          </div>
          <div class="debug-row">
            <span>cursorHint.idx</span>
            <code>{cursorHint()?.idx ?? "—"}</code>
          </div>
          <div class="debug-row">
            <span>cursorHint.pc</span>
            <code>{cursorHint()?.pc ?? "—"}</code>
          </div>
          <div class="debug-row">
            <span>cursorHint.func</span>
            <code>{cursorHint()?.func ?? "—"}</code>
          </div>
          <div class="debug-row">
            <span>selectedFn</span>
            <code>{selectedFn() || "—"}</code>
          </div>
          <div class="debug-row">
            <span>selectedReg</span>
            <code>{selectedReg()}</code>
          </div>
          <div class="debug-row">
            <span>tabs</span>
            <code>L:{leftTab()} R:{rightTab()} B:{bottomTab()}</code>
          </div>
          <div class="debug-row">
            <span>syncCfg</span>
            <code>{syncCfg() ? "on" : "off"}</code>
          </div>
          <div class="debug-row">
            <span>cfg.fnName</span>
            <code>{cfgDebugState()?.fnName || cfgDisplayFn() || "—"}</code>
          </div>
          <div class="debug-row">
            <span>cfg.lastGraphFn</span>
            <code>{cfgDebugState()?.lastGraphFn || "—"}</code>
          </div>
          <div class="debug-row">
            <span>cfg.loading</span>
            <code>{cfgDebugState()?.loading ? "yes" : "no"}</code>
          </div>
          <div class="debug-row">
            <span>cfg.graphSeq</span>
            <code>{cfgDebugState()?.graphSeq ?? 0}</code>
          </div>
          <div class="debug-row">
            <span>rowHintCache</span>
            <code>{rowHintCacheSize()} entries</code>
          </div>
          <label class="debug-row debug-toggle">
            <input
              type="checkbox"
              checked={apiDebug()}
              onChange={(e) => setApiDebug(e.currentTarget.checked)}
            />
            <span>log API calls (console)</span>
          </label>
          <button
            type="button"
            class="debug-close"
            onClick={() => setDebugVisible(false)}
            title="hide overlay (state persists; toggle with topbar dbg button)"
          >
            close
          </button>
        </div>
      </Show>
    </>
  );
}
