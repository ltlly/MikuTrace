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
type HelpState = { topic: HelpTopic; x: number; y: number };

export default function App() {
  const [selectedIdx, setSelectedIdx] = createSignal(0);
  const [selectedReg, setSelectedReg] = createSignal("x0");
  const [selectedFn, setSelectedFn] = createSignal("");
  const [leftTab, setLeftTab] = createSignal<LeftTab>("funcs");
  const [rightTab, setRightTab] = createSignal<RightTab>("cfg");
  const [bottomTab, setBottomTab] = createSignal<BottomTab>("memory");
  const [helpState, setHelpState] = createSignal<HelpState | null>(null);
  const helpTopic = createMemo(() => helpState()?.topic ?? null);

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
    if (topic === "bottom") return bottomTab() === "memory" ? "Memory" : bottomTab() === "trace-for-pc" ? "Trace for PC" : "Navigation";
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
      return "Navigation 预留给原版 Web 的 cursor 历史、前进/后退和命令式跳转。当前主要跳转入口是 Disassembly、CFG、CallTree、Strings、Cross Ref 和 Trace for PC。";
    }
    if (leftTab() === "funcs") return "Functions 汇总 trace、符号和 BN sidecar 里的函数条目。选择函数会驱动 CFG、HLIL 和 Decompile；记录数、block 数和入口地址用来判断热函数和分析范围。";
    if (leftTab() === "back") return "Backtrace 在当前 cursor 处重建动态调用栈。点击 frame 会跳到对应 call site，用于从深层 JNI/Native 调用回到上游上下文。";
    if (leftTab() === "calltree") return "Call Tree 显示整个 trace 的动态嵌套调用关系。定位当前函数按钮会展开并选中包含当前汇编 trace 的函数节点，适合从执行流角度找上下文。";
    if (leftTab() === "strings") return "Strings 来自 MemShadow 对内存写入的可打印字符串扫描。filter 用于查缓冲区和常量；双击字符串会跳到第一次写入或触碰该字符串地址的 trace。";
    if (leftTab() === "taint") return "Taint 默认从当前 cursor 和当前寄存器开始；当前寄存器会随 Disassembly 里选中的指令自动更新。Forward 看后续传播，Backward 追溯值来源，选项控制是否穿过内存和函数调用。";
    if (leftTab() === "xref") return "Cross Ref 包含当前 PC 的执行历史和汇编文本搜索。它不是一排无语义按钮，而是按 idx、方向和距离展示；点击行会跳转到对应 trace。";
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
              <StringsPanel onSelect={setSelectedIdx} />
            </div>
            <div class="lp-tab" classList={{ active: leftTab() === "taint" }}>
              <TaintPanel
                idx={selectedIdx()}
                reg={selectedReg()}
                onRegChange={setSelectedReg}
                onSelect={setSelectedIdx}
              />
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
              <MemoryPanel idx={selectedIdx()} onSelect={setSelectedIdx} />
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
              <CfgPanel selectedFn={selectedFn()} currentIdx={selectedIdx()} onSelect={setSelectedIdx} />
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
    </>
  );
}
