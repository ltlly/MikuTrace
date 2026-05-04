import { createMemo, createSignal, Show } from "solid-js";

import BacktracePanel from "./panels/backtrace/BacktracePanel";
import CallTreePanel from "./panels/calltree/CallTreePanel";
import CfgPanel from "./panels/cfg/CfgPanel";
import DecompilerPanel from "./panels/decompiler/DecompilerPanel";
import ForksPanel from "./panels/forks/ForksPanel";
import FunctionsPanel from "./panels/functions/FunctionsPanel";
import HlilPanel from "./panels/hlil/HlilPanel";
import MemoryPanel from "./panels/memory/MemoryPanel";
import MetaPanel from "./panels/meta/MetaPanel";
import RecordsPanel from "./panels/records/RecordsPanel";
import RegistersPanel from "./panels/registers/RegistersPanel";
import SettingsPanel from "./panels/settings/SettingsPanel";
import StringsPanel from "./panels/strings/StringsPanel";
import TaintPanel from "./panels/taint/TaintPanel";
import TraceForPcPanel from "./panels/tracepc/TraceForPcPanel";
import XrefPanel from "./panels/xref/XrefPanel";

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
type BottomTab = "memory" | "navigation" | "trace-for-pc";
type HelpTopic = "overview" | "left" | "disasm" | "right" | "bottom";

export default function App() {
  const [selectedIdx, setSelectedIdx] = createSignal(0);
  const [selectedReg, setSelectedReg] = createSignal("x0");
  const [selectedFn, setSelectedFn] = createSignal("");
  const [leftTab, setLeftTab] = createSignal<LeftTab>("funcs");
  const [rightTab, setRightTab] = createSignal<RightTab>("cfg");
  const [bottomTab, setBottomTab] = createSignal<BottomTab>("memory");
  const [helpTopic, setHelpTopic] = createSignal<HelpTopic | null>(null);

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
      classList={{ active: bottomTab() === tab }}
      onClick={() => setBottomTab(tab)}
    >
      {label}
    </button>
  );
  const helpButton = (topic: HelpTopic) => (
    <button class="help-btn" type="button" title="帮助" onClick={() => setHelpTopic(topic)}>
      ?
    </button>
  );
  const helpTitle = createMemo(() => {
    const topic = helpTopic();
    if (topic === "overview") return "traceMiku Web";
    if (topic === "disasm") return "Disassembly";
    if (topic === "right") return rightTitle();
    if (topic === "bottom") return bottomTab() === "memory" ? "Memory" : bottomTab() === "trace-for-pc" ? "Trace for PC" : "Navigation";
    return leftTitle();
  });
  const helpBody = createMemo(() => {
    const topic = helpTopic();
    if (topic === "overview") {
      return "IDA/x64dbg-style workbench: left analysis tabs, center dynamic instruction trace, bottom memory/history, right CFG/register/decompile. The cursor is the selected trace idx; panels follow it.";
    }
    if (topic === "disasm") {
      return "One row is one executed instruction snapshot. Scroll to extend the trace window. Click a row to set the cursor; the first register seen in asm becomes the active register for taint/register workflows. Function column shows func+offset when symbols are known.";
    }
    if (topic === "right") {
      if (rightTab() === "cfg") return "Graph renders CFG for the selected function. Full-trace CFG is intentionally not auto-rendered on large traces because Graphviz can timeout.";
      if (rightTab() === "regs") return "Registers follow the current cursor. Changed registers are highlighted like pwndbg; notes mark zero, stack pointers, and likely pointers. Click a register to make it the active taint register.";
      if (rightTab() === "hlil") return "HLIL follows the selected FunctionIndex entry and uses the BN sidecar when configured with --so/TRACEMIKU_BN_SO.";
      return "Decompile shows TraceIR/LLIL/LLM outputs for the selected function. Select functions from the Functions panel.";
    }
    if (topic === "bottom") {
      if (bottomTab() === "memory") return "Memory is a hex+ASCII dump at an address or quick register value. Byte colors encode source/kind; changed bytes at the current cursor are highlighted inline.";
      if (bottomTab() === "trace-for-pc") return "Trace for PC lists other executions of the same PC around the cursor. Use it to inspect loops, repeated dispatchers, and hot instructions without searching manually.";
      return "Navigation is reserved for cursor history/back-forward behavior.";
    }
    if (leftTab() === "funcs") return "Functions lists trace/symbol/BN function entries. Select one to drive CFG, HLIL, and Decompile.";
    if (leftTab() === "back") return "Backtrace reconstructs the dynamic call stack at the current cursor. Click a frame to jump to its call site.";
    if (leftTab() === "calltree") return "Call Tree shows nested dynamic calls. locate current fn expands to the node containing the selected trace idx.";
    if (leftTab() === "strings") return "Strings are recovered from MemShadow writes. Use filters to find decoded buffers and interesting constants.";
    if (leftTab() === "taint") return "Taint starts from the current cursor and active register by default. Forward follows future uses; backward walks value provenance.";
    if (leftTab() === "xref") return "Cross Ref shows executions of the current PC and asm regex hits. Rows jump the trace cursor.";
    if (leftTab() === "settings") return "Settings controls density and backend/API status.";
    return "SO Filter is reserved for multi-SO folding controls.";
  });

  return (
    <>
      <header id="topbar">
        <span class="brand">
          traceMiku <span class="dim">web</span>
        </span>
        <span class="meta">Rust v2</span>
        <span class="grow" />
        <label class="toggle" title="placeholder for legacy trace/CFG sync">
          <input type="checkbox" checked readOnly />
          <span>同步 (sync trace ↔ CFG)</span>
        </label>
        <span class="hint">j/k 单步 · g/G 头尾 · / 搜索 · :N 跳转</span>
        {helpButton("overview")}
      </header>

      <main id="layout">
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
              <FunctionsPanel selectedFn={selectedFn} onSelectFn={setSelectedFn} />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "back" }}>
              <BacktracePanel idx={selectedIdx()} onSelect={setSelectedIdx} />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "calltree" }}>
              <CallTreePanel currentIdx={selectedIdx()} onSelect={setSelectedIdx} />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "forks" }}>
              <ForksPanel />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "strings" }}>
              <StringsPanel />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "taint" }}>
              <TaintPanel idx={selectedIdx()} reg={selectedReg()} onRegChange={setSelectedReg} />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "xref" }}>
              <XrefPanel idx={selectedIdx()} onSelect={setSelectedIdx} />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "sofilter" }}>
              <section class="panel">
                <h2>SO Filter</h2>
                <p class="dim">multi-SO folding controls will be rebuilt here.</p>
                <MetaPanel />
              </section>
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "settings" }}>
              <SettingsPanel />
            </div>
          </div>
        </section>

        <section id="asm-col">
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
            <span class="hd ec-spacer" />
            <span class="hd hd-idx">idx</span>
            <span class="hd hd-pc">pc</span>
            <span class="hd hd-func">rel</span>
            <span class="hd hd-asm">asm</span>
          </div>
          <div id="stream">
            <RecordsPanel
              selectedIdx={selectedIdx()}
              selectedReg={selectedReg()}
              onSelect={setSelectedIdx}
              onSelectReg={setSelectedReg}
            />
          </div>
          <div id="bottom-tabs">
            {btab("memory", "Memory")}
            {btab("navigation", "Navigation")}
            {btab("trace-for-pc", "Trace for PC")}
            <span class="grow" />
            {helpButton("bottom")}
          </div>
          <div id="bottom-content">
            <div class="bbody" classList={{ active: bottomTab() === "memory" }}>
              <MemoryPanel idx={selectedIdx()} />
            </div>
            <div class="bbody" classList={{ active: bottomTab() === "navigation" }}>
              <p class="dim">navigation history pending</p>
            </div>
            <div class="bbody" classList={{ active: bottomTab() === "trace-for-pc" }}>
              <TraceForPcPanel idx={selectedIdx()} onSelect={setSelectedIdx} />
            </div>
          </div>
        </section>

        <section id="right-col">
          <div class="panelhead">
            <span>{rightTitle()}</span>
            <span class="grow" />
            <span class="dim">{selectedFn() || "no fn selected"}</span>
            {helpButton("right")}
          </div>
          <div id="right-body">
            <div class="rbody" classList={{ active: rightTab() === "cfg" }}>
              <CfgPanel selectedFn={selectedFn()} />
            </div>
            <div class="rbody" classList={{ active: rightTab() === "regs" }}>
              <RegistersPanel idx={selectedIdx()} selectedReg={selectedReg()} onSelectReg={setSelectedReg} />
            </div>
            <div class="rbody" classList={{ active: rightTab() === "hlil" }}>
              <HlilPanel selectedFn={selectedFn} onSelectFn={setSelectedFn} />
            </div>
            <div class="rbody" classList={{ active: rightTab() === "dec" }}>
              <DecompilerPanel selectedFn={selectedFn} onSelectFn={setSelectedFn} />
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
          <span class="dim">:</span>
          <input id="cmd-input" type="text" class="inp" placeholder="command bar pending" />
        </footer>
      </main>
      <Show when={helpTopic()}>
        <div class="help-popover" role="dialog" aria-modal="true" onClick={() => setHelpTopic(null)}>
          <div class="help-card" onClick={(e) => e.stopPropagation()}>
            <button class="help-close" type="button" onClick={() => setHelpTopic(null)}>
              ×
            </button>
            <h3>{helpTitle()}</h3>
            <p>{helpBody()}</p>
          </div>
        </div>
      </Show>
    </>
  );
}
