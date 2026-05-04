import { createEffect, createMemo, createResource, createSignal, For, onCleanup, onMount, Show, untrack } from "solid-js";
import type { JSX } from "solid-js";

import { fetchIdxsForPc, fetchMeta, fetchRecord, fetchSearch } from "./api/client";
import BacktracePanel from "./panels/backtrace/BacktracePanel";
import CallTreePanel from "./panels/calltree/CallTreePanel";
import CfgPanel, { type CfgDebugState, type CursorRecordHint } from "./panels/cfg/CfgPanel";
import DecompilerPanel from "./panels/decompiler/DecompilerPanel";
import ForksPanel from "./panels/forks/ForksPanel";
import FunctionsPanel from "./panels/functions/FunctionsPanel";
import HlilPanel from "./panels/hlil/HlilPanel";
import MemoryPanel from "./panels/memory/MemoryPanel";
import RecordsPanel from "./panels/records/RecordsPanel";
import RegistersPanel from "./panels/registers/RegistersPanel";
import SettingsPanel from "./panels/settings/SettingsPanel";
import SoFilterPanel from "./panels/sofilter/SoFilterPanel";
import StringsPanel from "./panels/strings/StringsPanel";
import StringProvenancePanel, { type StringProvenanceRequest } from "./panels/strings/StringProvenancePanel";
import TaintPanel from "./panels/taint/TaintPanel";
import TraceForPcPanel from "./panels/tracepc/TraceForPcPanel";
import XrefPanel from "./panels/xref/XrefPanel";
import type { RecordRow } from "./api/types";

type LeftTab =
  | "funcs"
  | "back"
  | "calltree"
  | "forks"
  | "strings"
  | "taint"
  | "xref"
  | "sofilter"
  | "settings";
type RightTab = "cfg" | "regs" | "hlil" | "dec";
type BottomTab = "memory" | "navigation" | "trace-for-pc" | "string-provenance";
type HelpTopic = "overview" | "left" | "disasm" | "right" | "bottom";
type HelpState = { topic: HelpTopic; x: number; y: number };
type CmdMode = "" | "/" | ":";
type TaintRunDirection = "forward" | "backward";
type MemoryRequest = { token: number; addr: string };
type TaintRunRequest = { token: number; idx: number; reg: string; direction: TaintRunDirection };

const HIDDEN_SOS_KEY = "tracemiku-hidden-sos";
const LAYOUT_KEY = "tracemiku-layout-v2";

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
  colAsm: 360,
  syncCfg: false,
};

function clampNumber(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

function initialLayout(): LayoutState {
  try {
    const raw = localStorage.getItem(LAYOUT_KEY);
    const parsed = raw ? JSON.parse(raw) : {};
    return {
      leftW: clampNumber(Number(parsed.leftW) || DEFAULT_LAYOUT.leftW, 180, 680),
      rightW: clampNumber(Number(parsed.rightW) || DEFAULT_LAYOUT.rightW, 320, 960),
      bottomH: clampNumber(Number(parsed.bottomH) || DEFAULT_LAYOUT.bottomH, 120, 560),
      colDot: clampNumber(Number(parsed.colDot) || DEFAULT_LAYOUT.colDot, 12, 48),
      colIdx: clampNumber(Number(parsed.colIdx) || DEFAULT_LAYOUT.colIdx, 44, 140),
      colPc: clampNumber(Number(parsed.colPc) || DEFAULT_LAYOUT.colPc, 80, 260),
      colFunc: clampNumber(Number(parsed.colFunc) || DEFAULT_LAYOUT.colFunc, 80, 420),
      colAsm: clampNumber(Number(parsed.colAsm) || DEFAULT_LAYOUT.colAsm, 180, 900),
      syncCfg: typeof parsed.syncCfg === "boolean" ? parsed.syncCfg : DEFAULT_LAYOUT.syncCfg,
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
  const [rowHintCacheSize, setRowHintCacheSize] = createSignal(0);
  function rememberRows(rows: RecordRow[]) {
    for (const row of rows) {
      rowHintCache.set(row.idx, { idx: row.idx, pc: row.pc, func: row.func });
    }
    while (rowHintCache.size > 5000) {
      const k = rowHintCache.keys().next().value as number | undefined;
      if (k === undefined) break;
      rowHintCache.delete(k);
    }
    setRowHintCacheSize(rowHintCache.size);
  }
  const cursorRecordSource = createMemo(() => {
    const idx = selectedIdx();
    return rowHintCache.has(idx) ? undefined : idx;
  });
  const [cursorRecord] = createResource(cursorRecordSource, fetchRecord);
  createEffect(() => {
    const idx = selectedIdx();
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
  const helpTopic = createMemo(() => helpState()?.topic ?? null);
  let cmdInput: HTMLInputElement | undefined;
  let hashJumpSeq = 0;
  let hashJumpAbort: AbortController | undefined;
  let searchSeq = 0;
  let searchAbort: AbortController | undefined;
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

  onCleanup(() => {
    cancelHashJump();
    cancelSearch();
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

  function openMemoryAt(addr: string) {
    setBottomTab("memory");
    setMemoryRequest({ token: Date.now(), addr });
  }

  function runTaintFrom(idx: number, reg: string, direction: TaintRunDirection) {
    jumpToIdx(idx);
    setSelectedReg(reg);
    setLeftTab("taint");
    setTaintRequest({ token: Date.now(), idx, reg, direction });
  }

  function showStringProvenance(req: Omit<StringProvenanceRequest, "token">) {
    setStringProvenanceRequest({ ...req, token: Date.now() });
    setBottomTab("string-provenance");
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
      setCmdStatus(`${q}: ${pos + 1}/${hits.length} hits`);
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
      const idx = Number.parseInt(value.trim(), 10);
      if (Number.isFinite(idx)) {
        jumpToIdx(idx);
        setCmdStatus(`idx ${clampIdx(idx)}`);
      }
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
        jumpToIdx(selectedIdx() + 1);
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault();
        jumpToIdx(selectedIdx() - 1);
      } else if (e.key === "PageDown") {
        e.preventDefault();
        jumpToIdx(selectedIdx() + 20);
      } else if (e.key === "PageUp") {
        e.preventDefault();
        jumpToIdx(selectedIdx() - 20);
      } else if (e.key === "Home" || e.key === "g") {
        e.preventDefault();
        jumpToIdx(0);
      } else if (e.key === "End" || e.key === "G") {
        e.preventDefault();
        jumpToIdx(Math.max(0, totalRecords() - 1));
      }
      else if (e.key === "/") {
        e.preventDefault();
        openCmd("/");
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
      xref: "Cross Ref",
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
        const x = Math.max(8, Math.min(rect.left, window.innerWidth - cardW - 8));
        const y =
          rect.bottom + 8 > window.innerHeight - 180
            ? Math.max(8, rect.top - 260)
            : rect.bottom + 8;
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
      return "Navigation";
    }
    return leftTitle();
  });
  const helpBody = createMemo(() => {
    const topic = helpTopic();
    if (topic === "overview") {
      return "主界面按原版 Web 的调试器布局组织：左侧是函数、回溯、调用树、字符串、污点和交叉引用；中间是动态执行过的汇编 trace；下方是内存和当前 PC 的执行历史；右侧是 CFG、寄存器和反编译。全局 cursor 就是当前选中的 trace idx，所有窗口都围绕它联动。";
    }
    if (topic === "disasm") {
      return "每一行是一条实际执行过的 ARM64 指令快照，不是静态反汇编列表。列含义依次是执行序号、PC、函数+偏移和汇编文本。滚动条对应整个 trace；点击行会设置 cursor，并把该指令里第一个寄存器自动作为污点/寄存器窗口的当前寄存器。";
    }
    if (topic === "right") {
      if (rightTab() === "cfg") return "CFG 显示当前函数的动态基本块图，默认跟随当前 trace 所在函数，避免直接渲染全 trace 导致 dot 超时。空白处拖动平移，按住 Ctrl 滚轮缩放；点击图中的指令或块头会跳到 trace 中离当前 cursor 最近的一次执行。";
      if (rightTab() === "regs") return "寄存器窗口显示当前 cursor 的寄存器状态，并像 pwndbg 一样自动高亮相对上一条 trace 发生变化的寄存器；note 会标出 zero、pc、sp/stack 和疑似指针。点击寄存器会把它设为污点追踪的当前寄存器。";
      if (rightTab() === "hlil") return "HLIL 窗口跟随 Functions 里选中的 FunctionIndex 条目；配置了 Binary Ninja sidecar 时可显示对应 BN HLIL。它用于静态结构理解，不替代中间 trace 的动态执行列表。";
      return "Decompile 窗口显示当前函数的 TraceIR、LLIL 或 LLM 反编译结果。先在 Functions/CallTree/CFG 中定位函数，再在这里查看更高层的伪代码摘要。";
    }
    if (topic === "bottom") {
      if (bottomTab() === "memory") return "Memory 是按调试器习惯排列的 hex+ASCII dump。addr 可以填十六进制地址，也可以填 x0、x1、sp 这类寄存器名；字节颜色表示读、写、外部来源或未知，当前 cursor 发生变化的字节会直接在 dump 中高亮。双击字节跳来源 idx，右键字节显示该地址前后的读写触碰分析。";
      if (bottomTab() === "trace-for-pc") return "Trace for PC 显示当前 PC 在 trace 中其它执行位置，分为 cursor 之前和之后。它用来分析循环、调度器、热点指令和同一静态指令在不同时间的状态差异。点击任意行会跳转到对应 idx。";
      if (bottomTab() === "string-provenance") return "Provenance 显示 Strings 双击后选中字符串的逐字节来源：每个字符当前值、写入 idx 列表和读取 idx 列表。点击 w#/r# 会跳到对应 trace。";
      return "Navigation 预留给原版 Web 的 cursor 历史、前进/后退和命令式跳转。当前主要跳转入口是 Disassembly、CFG、CallTree、Strings、Cross Ref 和 Trace for PC。";
    }
    if (leftTab() === "funcs") return "Functions 汇总 trace、符号和 BN sidecar 里的函数条目。选择函数会驱动 CFG、HLIL 和 Decompile；记录数、block 数和入口地址用来判断热函数和分析范围。";
    if (leftTab() === "back") return "Backtrace 在当前 cursor 处重建动态调用栈。点击 frame 会跳到对应 call site，用于从深层 JNI/Native 调用回到上游上下文。";
    if (leftTab() === "calltree") return "Call Tree 显示整个 trace 的动态嵌套调用关系。定位当前函数按钮会展开并选中包含当前汇编 trace 的函数节点，适合从执行流角度找上下文。";
    if (leftTab() === "strings") return "Strings 来自 MemShadow 对内存写入的可打印字符串扫描。单击跳到第一次写入/触碰该字符串地址的 trace；双击会在底部 Provenance 展示每个字符是谁写入、谁读取。";
    if (leftTab() === "taint") return "Taint 默认从当前 traceIdx 和当前寄存器开始；当前寄存器会随 Disassembly 里选中的指令自动更新。Forward 看后续传播，Backward 追溯值来源，选项控制是否穿过内存和是否标注函数调用深度。";
    if (leftTab() === "xref") return "Cross Ref 上半部分是当前 PC 在 trace 中的执行历史；下半部分是 ASM 文本搜索。搜索框为空时用当前指令文本做精确正则搜索，手动输入时按 mnemonic/op_str 正则搜索。";
    if (leftTab() === "settings") return "Settings 显示后端 API、密度和调试状态。后续与原版 Web 对齐的显示开关会集中放在这里。";
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
        <span class="hint">↑/↓ 单步 · PgUp/PgDn 翻页 · Home/End 头尾 · / 搜索 · :N 跳转</span>
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
          {vtab("taint", "Taint", "寄存器/内存污点追踪")}
          {vtab("xref", "Cross Ref", "当前 PC 执行历史和汇编搜索")}
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
              <FunctionsPanel selectedFn={selectedFn} onSelectFn={setSelectedFn} active={leftTab() === "funcs"} />
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
                  <For each={navHistory().map((idx, pos) => ({ idx, pos })).slice().reverse()}>
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
              />
            </div>
          </div>
        </section>

        <section id="right-col">
          <div class="panelhead">
            <span>{rightTitle()}</span>
            <span class="grow" />
            <span class="dim">
              {rightTab() === "cfg" ? cfgDisplayFn() || "select function" : selectedFn() || "no fn selected"}
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
                selectedFn={selectedFn}
                onSelectFn={setSelectedFn}
                currentIdx={selectedIdx()}
                onSelect={setSelectedIdx}
                active={rightTab() === "hlil"}
              />
            </div>
            <div class="rbody" classList={{ active: rightTab() === "dec" }}>
              <DecompilerPanel selectedFn={selectedFn} onSelectFn={setSelectedFn} active={rightTab() === "dec"} />
            </div>
          </div>
        </section>

        <aside id="right-tabs">
          {rtab("cfg", "Graph", "Trace CFG")}
          {rtab("regs", "Registers", "当前 cursor 寄存器")}
          {rtab("hlil", "HLIL", "BN HLIL")}
          {rtab("dec", "Decompile", "TraceIR / LLIL / LLM")}
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
            placeholder={cmdMode() === "/" ? "search asm..." : cmdMode() === ":" ? "jump to idx..." : "press / or :"}
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
