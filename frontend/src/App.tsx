import CallTreePanel from "./panels/calltree/CallTreePanel";
import DecompilerPanel from "./panels/decompiler/DecompilerPanel";
import FunctionsPanel from "./panels/functions/FunctionsPanel";
import MetaPanel from "./panels/meta/MetaPanel";
import RecordsPanel from "./panels/records/RecordsPanel";
import StringsPanel from "./panels/strings/StringsPanel";
import TaintPanel from "./panels/taint/TaintPanel";

export default function App() {
  return (
    <main class="layout">
      <header class="header">
        <h1>traceMiku v2</h1>
        <span class="dim small">analysis v2 — Rust core + Solid frontend</span>
      </header>
      <MetaPanel />
      <FunctionsPanel />
      <CallTreePanel />
      <TaintPanel />
      <DecompilerPanel />
      <StringsPanel />
      <RecordsPanel />
    </main>
  );
}
