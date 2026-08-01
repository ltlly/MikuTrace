import { createEffect, createMemo, createResource, createSignal, For, onCleanup, onMount, Show, untrack } from "solid-js";

import {
  fetchFunctions,
  fetchIdxsForPc,
  fetchLastWriteOfReg,
  fetchMeta,
  fetchNextUseOfReg,
  fetchRecord,
  fetchSearch,
  fetchWatchpoints,
} from "./api/client";
import BacktracePanel from "./panels/backtrace/BacktracePanel";
import { useGuarded } from "./utils/guarded";
import CallTreePanel from "./panels/calltree/CallTreePanel";
import CfgPanel, { type CfgDebugState, type CursorRecordHint } from "./panels/cfg/CfgPanel";
import DecompilerPanel from "./panels/decompiler/DecompilerPanel";
import ForksPanel from "./panels/forks/ForksPanel";
import FunctionsPanel from "./panels/functions/FunctionsPanel";
import HlilPanel from "./panels/hlil/HlilPanel";
import MemoryPanel from "./panels/memory/MemoryPanel";
import PseudoCPanel from "./panels/PseudoCPanel";
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
import CryptoPanel from "./panels/crypto/CryptoPanel";
import type { FunctionEntry, RecordRow } from "./api/types";
import type { UiTaskEntry, UiTaskReporter, UiTaskUpdate } from "./utils/taskCenter";
import TaskCenter from "./app/TaskCenter";
import {
  clampNumber,
  functionRenameStorageKey,
  initialHiddenSos,
  initialLayout,
  isEditableTarget,
  loadFunctionRenames,
  persistHiddenSos,
  saveFunctionRenames,
} from "./app/persistence";
import type {
  BottomTab, CmdMode, HelpState,
  LeftTab, MemoryRequest, RightTab, TaintRunDirection, TaintRunRequest,
} from "./app/types";
import { leftTabTitle, rightTabTitle } from "./app/tabTitles";
import { recordRowFromTaintRow } from "./app/taintRows";
import { createLayoutController } from "./app/layoutController";
import DebugOverlay from "./app/DebugOverlay";
import { getHelpBody, getHelpTitle, HelpButton, HelpPopover } from "./app/HelpSystem";
import { TabButton } from "./app/AppChrome";

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
  let cursorRecordAbort: AbortController | undefined;
  const [cursorRecord] = createResource(cursorRecordSource, (idx) => {
    cursorRecordAbort?.abort();
    cursorRecordAbort = new AbortController();
    return fetchRecord(idx, cursorRecordAbort.signal);
  });
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
  const [cmdStatus, setCmdStatus] = createSignal("j/k step · [/ ] same PC · Alt+[/] reg flow · w watch");
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
  const { asmStyle, layoutStyle, setSyncCfg, startAsmColResize, startPanelResize } = createLayoutController({
    leftW, setLeftW, rightW, setRightW, bottomH, setBottomH,
    colDot, setColDot, colIdx, setColIdx, colPc, setColPc,
    colFunc, setColFunc, colAsm, setColAsm, syncCfg, setSyncCfgSignal,
  });
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
  const [functions] = createResource(fetchFunctions);
  const functionRenameKey = createMemo(() => {
    const path = meta()?.path;
    return path ? functionRenameStorageKey(path) : null;
  });

  // Auto-select function from assembly cursor
  createEffect(() => {
    const hint = cursorHint();
    const fns = functions()?.functions;
    if (!hint?.func || !fns) return;
    const curFn = selectedFn();
    const match = fns.find((f) => f.name === hint.func);
    if (match && match.id !== curFn) setSelectedFn(match.id);
  });
  const [functionRenames, setFunctionRenames] = createSignal<Map<string, string>>(new Map());
  const helpTopic = createMemo(() => helpState()?.topic ?? null);
  let cmdInput: HTMLInputElement | undefined;
  const hashJump = useGuarded();
  const search = useGuarded();
  const goto = useGuarded();
  const timeTravel = useGuarded();
  const watch = useGuarded();
  let applyingNavHistory = false;

  createEffect(() => {
    const key = functionRenameKey();
    setFunctionRenames(key ? loadFunctionRenames(key) : new Map());
  });
  onCleanup(() => {
    hashJump.cancel();
    search.cancel();
    goto.cancel();
    timeTravel.cancel();
    watch.cancel();
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
    hashJump.cancel();
    const h = hashJump.begin();
    const abort = h.abort;
    setCmdStatus(`resolving ${pc}...`);
    try {
      const r = await fetchIdxsForPc(pc, selectedIdx(), 80, abort.signal);
      if (!hashJump.isCurrent(h)) return;
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
      if (!hashJump.isCurrent(h)) return;
      setCmdStatus(`hash jump ${pc} failed: ${String(err)}`);
    } finally {
      hashJump.release(h);
    }
  }

  function normalizePcInput(raw: string): string | null {
    const text = raw.trim();
    const m = text.match(/^0x([0-9a-f]+)$/i);
    return m ? `0x${m[1].toLowerCase()}` : null;
  }

  async function jumpToFirstPc(pc: string, label = pc) {
    goto.cancel();
    const h = goto.begin();
    const abort = h.abort;
    setCmdStatus(`resolving ${label}...`);
    try {
      const r = await fetchIdxsForPc(pc, 0, 1, abort.signal);
      if (!goto.isCurrent(h)) return;
      const first = r.after[0];
      if (first === undefined) {
        setCmdStatus(`${label}: not executed in trace`);
        return;
      }
      jumpToIdx(first);
      setCmdStatus(`${label}: jumped to #${first}`);
    } catch (err) {
      if (!goto.isCurrent(h)) return;
      setCmdStatus(`${label}: jump failed: ${String(err)}`);
    } finally {
      goto.release(h);
    }
  }

  async function jumpSamePc(direction: 1 | -1) {
    const hint = cursorHint();
    const pc = hint?.pc;
    if (!pc) {
      setCmdStatus("same-pc: current PC is not ready");
      return;
    }
    timeTravel.cancel();
    const h = timeTravel.begin();
    const abort = h.abort;
    const cursor = selectedIdx();
    setCmdStatus(`${direction < 0 ? "prev" : "next"} execution ${pc}...`);
    try {
      const r = await fetchIdxsForPc(pc, direction < 0 ? cursor : cursor + 1, 1, abort.signal);
      if (!timeTravel.isCurrent(h)) return;
      const target = direction < 0 ? r.before[0] : r.after[0];
      if (target === undefined) {
        setCmdStatus(`${pc}: no ${direction < 0 ? "previous" : "next"} execution`);
        return;
      }
      jumpToIdx(target);
      setCmdStatus(`${pc}: jumped to #${target}`);
    } catch (err) {
      if (!timeTravel.isCurrent(h)) return;
      setCmdStatus(`same-pc failed: ${String(err)}`);
    } finally {
      timeTravel.release(h);
    }
  }

  async function jumpRegFlow(direction: 1 | -1) {
    const reg = selectedReg();
    if (!reg) {
      setCmdStatus("reg flow: no selected register");
      return;
    }
    timeTravel.cancel();
    const h = timeTravel.begin();
    const abort = h.abort;
    const cursor = selectedIdx();
    const label = direction < 0 ? "prev def" : "next use";
    setCmdStatus(`${label} ${reg}...`);
    try {
      const r = direction < 0
        ? await fetchLastWriteOfReg(cursor, reg, abort.signal)
        : await fetchNextUseOfReg(cursor, reg, abort.signal);
      if (!timeTravel.isCurrent(h)) return;
      if (r.idx === null || r.idx === undefined) {
        setCmdStatus(`${label} ${reg}: not found`);
        return;
      }
      jumpToIdx(r.idx);
      setCmdStatus(`${label} ${reg}: #${r.idx}${r.value ? ` value ${r.value}` : ""}`);
    } catch (err) {
      if (!timeTravel.isCurrent(h)) return;
      setCmdStatus(`${label} ${reg} failed: ${String(err)}`);
    } finally {
      timeTravel.release(h);
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

  async function runWatchCommand(raw: string) {
    const text = raw.trim();
    if (!text) {
      setCmdStatus("watch: expected reg, reg=value, or address");
      return;
    }
    const parts = text.split(/\s+/).filter(Boolean);
    const first = parts[0] ?? "";
    const regEquals = first.match(/^([A-Za-z][A-Za-z0-9]*)=(0x[0-9a-f]+|\d+)$/i);
    const addrMatch = first.match(/^0x[0-9a-f]+$/i);
    const size = parts[1] ? Number.parseInt(parts[1], 10) : undefined;
    const cursor = selectedIdx();
    const opts = regEquals
      ? { kind: "reg-equals" as const, reg: regEquals[1], value: regEquals[2], cursor, limit: 200 }
      : addrMatch
        ? { kind: "mem-touch" as const, addr: first, size: Number.isFinite(size) ? size : 1, cursor, limit: 200 }
        : { kind: "reg-change" as const, reg: first, cursor, limit: 200 };

    watch.cancel();

    const h = watch.begin();

    const abort = h.abort;
    setCmdStatus(`watch ${text}: scanning...`);
    try {
      const r = await fetchWatchpoints({ ...opts, signal: abort.signal });
      if (!watch.isCurrent(h)) return;
      const firstHit = r.hits[0];
      if (!firstHit) {
        setCmdStatus(`watch ${text}: 0 hits`);
        return;
      }
      jumpToIdx(firstHit.idx);
      if (firstHit.reg) setSelectedReg(firstHit.reg);
      const partial = r.truncated ? ` · partial ${r.returned}/${r.total_matches}` : "";
      setCmdStatus(`watch ${text}: #${firstHit.idx} (${r.total_matches} hits${partial})`);
    } catch (err) {
      if (!watch.isCurrent(h)) return;
      setCmdStatus(`watch ${text} failed: ${String(err)}`);
    } finally {
      watch.release(h);
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
    const watchCmd = text.match(/^(?:w|watch)\s+(.+)$/i);
    if (watchCmd) {
      void runWatchCommand(watchCmd[1]);
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
    persistHiddenSos(next);
  }

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

  function showStringProvenance(req: Omit<StringProvenanceRequest, "token">) {
    setStringProvenanceRequest({ ...req, token: Date.now() });
    setBottomTab("string-provenance");
  }

  function runQueryText(text: string) {
    setBottomTab("query");
    setQueryRequest({ token: Date.now(), text });
    setCmdStatus(`query: ${text}`);
  }

  function openCmd(mode: CmdMode, initial = "") {
    setCmdMode(mode);
    setCmdValue(initial);
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
    search.cancel();
    const h = search.begin();
    const abort = h.abort;
    setCmdStatus(`searching ${q}...`);
    try {
      const cursor = selectedIdx();
      const r = await fetchSearch(q, 2000, abort.signal, cursor);
      if (!search.isCurrent(h)) return;
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
      if (!search.isCurrent(h)) return;
      setCmdStatus(`search failed: ${String(err)}`);
    } finally {
      search.release(h);
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
      } else if (e.key === "[" && e.altKey) {
        e.preventDefault();
        void jumpRegFlow(-1);
      } else if (e.key === "]" && e.altKey) {
        e.preventDefault();
        void jumpRegFlow(1);
      } else if (e.key === "[") {
        e.preventDefault();
        void jumpSamePc(-1);
      } else if (e.key === "]") {
        e.preventDefault();
        void jumpSamePc(1);
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
      } else if (e.key === "w") {
        e.preventDefault();
        openCmd(":", "w ");
      } else if (e.key === "n") stepSearch(1);
      else if (e.key === "N") stepSearch(-1);
    };
    window.addEventListener("keydown", onKey);
    onCleanup(() => {
      window.removeEventListener("hashchange", onHashChange);
      window.removeEventListener("keydown", onKey);
    });
  });

  const leftTitle = createMemo(() => leftTabTitle(leftTab()));
  const rightTitle = createMemo(() => rightTabTitle(rightTab()));

  const vtab = (tab: LeftTab, label: string, title: string) => (
    <TabButton side="left" tab={tab} label={label} title={title} active={leftTab() === tab} onSelect={() => setLeftTab(tab)} />
  );
  const rtab = (tab: RightTab, label: string, title: string) => (
    <TabButton side="right" tab={tab} label={label} title={title} active={rightTab() === tab} onSelect={() => setRightTab(tab)} />
  );
  const btab = (tab: BottomTab, label: string) => (
    <TabButton side="bottom" tab={tab} label={label} active={bottomTab() === tab} onSelect={() => setBottomTab(tab)} />
  );
  const helpTitle = createMemo(() => getHelpTitle(helpTopic(), leftTab(), rightTab(), bottomTab()));
  const helpBody = createMemo(() => getHelpBody(helpTopic(), leftTab(), rightTab(), bottomTab()));
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
        <HelpButton topic="overview" onOpen={setHelpState} />
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
          {vtab("crypto", "Crypto", "密码学常数扫描 + ARM CE 检测")}
        </aside>

        <section id="left-panel">
          <div class="panelhead">
            <span>{leftTitle()}</span>
            <span class="grow" />
            <span class="dim">idx {selectedIdx()}</span>
            <HelpButton topic="left" onOpen={setHelpState} />
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
            <div class="lp-tab" classList={{ active: leftTab() === "crypto" }}>
              <CryptoPanel
                idx={selectedIdx()}
                onSelect={setSelectedIdx}
                active={leftTab() === "crypto"}
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
            <HelpButton topic="disasm" onOpen={setHelpState} />
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
            <HelpButton topic="bottom" onOpen={setHelpState} />
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
                  : rightTab() === "pseudoc"
                    ? selectedFn() || "no fn selected"
                    : selectedFn() || "no fn selected"}
            </span>
            <HelpButton topic="right" onOpen={setHelpState} />
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
            <div class="rbody" classList={{ active: rightTab() === "pseudoc" }}>
              <PseudoCPanel
                selectedFn={selectedFn}
                active={rightTab() === "pseudoc"}
                selectedIdx={selectedIdx}
                onTaskUpdate={reportTask}
              />
            </div>
            <div class="rbody" classList={{ active: rightTab() === "dec" }}>
              <DecompilerPanel
                selectedFn={selectedFn}
                onSelectFn={setSelectedFn}
                selectedIdx={selectedIdx}
                onSelectIdx={setSelectedIdx}
                active={rightTab() === "dec"}
              />
            </div>
          </div>
        </section>

        <aside id="right-tabs">
          {rtab("cfg", "Graph", "Trace CFG")}
          {rtab("regs", "Registers", "当前 cursor 寄存器")}
          {rtab("hlil", "HLIL", "BN HLIL")}
          {rtab("pseudoc", "Pseudo C", "HLIL pipeline decompile")}
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
            placeholder={cmdMode() === "/" ? "search asm..." : cmdMode() === ":" ? "#240, 0xPC, pc 0x..., func name, mem addr len 128, taint bwd x9 @93, w x0, w x0=0x123, query ..." : "press / or g"}
            onInput={(e) => setCmdValue(e.currentTarget.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") closeCmd();
              if (e.key === "Enter") submitCmd();
            }}
          />
          <span class="cmd-status dim">{cmdStatus()}</span>
        </footer>
      </main>
      <HelpPopover
        state={helpState()}
        title={helpTitle()}
        body={helpBody()}
        onClose={() => setHelpState(null)}
      />
      <Show when={taskCenterOpen() || activeTaskCount() > 0}>
        <TaskCenter
          activeCount={activeTaskCount()}
          tasks={taskEntries()}
          onClose={() => setTaskCenterOpen(false)}
        />
      </Show>
      <Show when={debugVisible()}>
        <DebugOverlay
          selectedIdx={selectedIdx()}
          cursorHint={cursorHint()}
          selectedFn={selectedFn()}
          selectedReg={selectedReg()}
          tabs={`L:${leftTab()} R:${rightTab()} B:${bottomTab()}`}
          syncCfg={syncCfg()}
          cfgDebugState={cfgDebugState()}
          cfgDisplayFn={cfgDisplayFn()}
          rowHintCacheSize={rowHintCacheSize()}
          apiDebug={apiDebug()}
          onApiDebugChange={setApiDebug}
          onClose={() => setDebugVisible(false)}
        />
      </Show>
    </>
  );
}
