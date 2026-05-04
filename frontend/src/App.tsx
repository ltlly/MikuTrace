import { createSignal } from "solid-js";

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

export default function App() {
  const [selectedIdx, setSelectedIdx] = createSignal(0);
  const [selectedFn, setSelectedFn] = createSignal("");

  return (
    <main class="layout">
      <header class="header">
        <h1>traceMiku v2</h1>
        <span class="dim small">analysis v2 — Rust core + Solid frontend</span>
      </header>
      <MetaPanel />
      <FunctionsPanel selectedFn={selectedFn} onSelectFn={setSelectedFn} />
      <SettingsPanel />
      <CfgPanel />
      <RegistersPanel idx={selectedIdx()} />
      <HlilPanel selectedFn={selectedFn} onSelectFn={setSelectedFn} />
      <MemoryPanel idx={selectedIdx()} />
      <TraceForPcPanel idx={selectedIdx()} onSelect={setSelectedIdx} />
      <XrefPanel idx={selectedIdx()} onSelect={setSelectedIdx} />
      <BacktracePanel idx={selectedIdx()} onSelect={setSelectedIdx} />
      <CallTreePanel />
      <ForksPanel />
      <TaintPanel />
      <DecompilerPanel selectedFn={selectedFn} onSelectFn={setSelectedFn} />
      <StringsPanel />
      <RecordsPanel selectedIdx={selectedIdx()} onSelect={setSelectedIdx} />
    </main>
  );
}
