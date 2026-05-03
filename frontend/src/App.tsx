import MetaPanel from "./panels/meta/MetaPanel";

export default function App() {
  return (
    <main class="layout">
      <header class="header">
        <h1>traceMiku v2</h1>
        <span class="dim small">analysis v2 — Rust core + Solid frontend</span>
      </header>
      <MetaPanel />
    </main>
  );
}
