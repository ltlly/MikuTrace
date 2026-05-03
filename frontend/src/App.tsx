import FunctionsPanel from "./panels/functions/FunctionsPanel";
import MetaPanel from "./panels/meta/MetaPanel";
import RecordsPanel from "./panels/records/RecordsPanel";
import StringsPanel from "./panels/strings/StringsPanel";

export default function App() {
  return (
    <main class="layout">
      <header class="header">
        <h1>traceMiku v2</h1>
        <span class="dim small">analysis v2 — Rust core + Solid frontend</span>
      </header>
      <MetaPanel />
      <FunctionsPanel />
      <StringsPanel />
      <RecordsPanel />
    </main>
  );
}
