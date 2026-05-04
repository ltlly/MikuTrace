import { createMemo, createResource, createSignal, For, Show } from "solid-js";

import { fetchRecord, fetchSearch, fetchSearchPc } from "~/api/client";

interface XrefPanelProps {
  idx: number;
  onSelect: (idx: number) => void;
}

function refPattern(pc: string | undefined): string {
  if (!pc) return "";
  return pc.toLowerCase();
}

export default function XrefPanel(props: XrefPanelProps) {
  const [pattern, setPattern] = createSignal("");
  const [record] = createResource(() => props.idx, fetchRecord);
  const pcPattern = createMemo(() => refPattern(record()?.pc));
  const [pcRefs] = createResource(pcPattern, (pc) => (pc ? fetchSearchPc(pc, 60) : undefined));
  const asmPattern = createMemo(() => pattern().trim() || pcPattern());
  const [asmRefs] = createResource(asmPattern, (p) => (p ? fetchSearch(p, 120) : undefined));

  return (
    <section class="panel">
      <h2>Cross Ref</h2>
      <div class="xref-controls">
        <label>
          asm pattern
          <input
            type="text"
            value={pattern()}
            placeholder={pcPattern() || "0x..."}
            onInput={(e) => setPattern(e.currentTarget.value)}
          />
        </label>
        <Show when={record()}>
          {(r) => <span class="dim small">selected idx {r().idx} · pc {r().pc}</span>}
        </Show>
      </div>
      <Show when={pcRefs.error}>
        <p class="err">pc refs failed: {String(pcRefs.error)}</p>
      </Show>
      <Show when={asmRefs.error}>
        <p class="err">asm refs failed: {String(asmRefs.error)}</p>
      </Show>
      <div class="xref-grid">
        <div>
          <h3>executions at current PC</h3>
          <Show when={pcRefs.loading}>
            <p class="dim">loading…</p>
          </Show>
          <Show when={pcRefs()}>
            {(r) => (
              <>
                <p class="dim small">
                  {r().pc} · {r().count} hit{r().count === 1 ? "" : "s"}
                  {r().truncated ? " · truncated" : ""}
                </p>
                <table class="xref-table xref-exec-table">
                  <thead>
                    <tr>
                      <th>idx</th>
                      <th>where</th>
                      <th>distance</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={r().idxs}>
                      {(idx) => (
                        <tr
                          class={idx === props.idx ? "selected" : ""}
                          onClick={() => props.onSelect(idx)}
                        >
                          <td>{idx}</td>
                          <td>{idx < props.idx ? "before" : idx > props.idx ? "after" : "current"}</td>
                          <td>{idx === props.idx ? 0 : Math.abs(idx - props.idx)}</td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </>
            )}
          </Show>
        </div>
        <div>
          <h3>asm refs</h3>
          <Show when={asmRefs.loading}>
            <p class="dim">loading…</p>
          </Show>
          <Show when={asmRefs()}>
            {(r) => (
              <>
                <p class="dim small">
                  pattern {r().pattern} · {r().count} hit{r().count === 1 ? "" : "s"}
                </p>
                <table class="xref-table">
                  <thead>
                    <tr>
                      <th>idx</th>
                      <th>pc</th>
                      <th>fn</th>
                      <th>asm</th>
                    </tr>
                  </thead>
                  <tbody>
                    <For each={r().hits}>
                      {(hit) => (
                        <tr onClick={() => props.onSelect(hit.idx)}>
                          <td>{hit.idx}</td>
                          <td><code>{hit.pc}</code></td>
                          <td>{hit.func ?? ""}</td>
                          <td><code>{hit.asm}</code></td>
                        </tr>
                      )}
                    </For>
                  </tbody>
                </table>
              </>
            )}
          </Show>
        </div>
      </div>
    </section>
  );
}
