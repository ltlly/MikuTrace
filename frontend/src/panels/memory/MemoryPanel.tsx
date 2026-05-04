import { createEffect, createMemo, createResource, createSignal, For, Show } from "solid-js";

import { fetchMemDiff, fetchMemDump, fetchRecord } from "~/api/client";

interface MemoryPanelProps {
  idx: number;
}

const QUICK_REGS = ["x0", "x1", "x2", "x3", "sp"];

function hexByte(byte: number | null): string {
  if (byte === null) return "??";
  return byte.toString(16).padStart(2, "0");
}

function asciiByte(byte: number | null): string {
  if (byte === null || byte < 0x20 || byte > 0x7e) return ".";
  return String.fromCharCode(byte);
}

function diffTitle(idx: number): string {
  return idx > 0 ? `diff at idx ${idx - 1} -> ${idx}` : `diff before idx ${idx}`;
}

export default function MemoryPanel(props: MemoryPanelProps) {
  const [addr, setAddr] = createSignal("0x0");
  const [count, setCount] = createSignal(64);
  const [record] = createResource(() => props.idx, fetchRecord);
  createEffect(() => {
    const r = record();
    if (r?.regs.sp) setAddr(r.regs.sp);
  });
  const dumpSource = createMemo(() => ({
    addr: addr().trim() || "0x0",
    count: Math.max(1, Math.min(512, count())),
  }));
  const [dump] = createResource(dumpSource, (s) => fetchMemDump(s.addr, s.count));
  const diffSource = createMemo(() => ({
    idx: props.idx,
    addr: addr().trim() || "0x0",
    size: Math.max(1, Math.min(128, count())),
  }));
  const [diff] = createResource(diffSource, (s) => fetchMemDiff(s.idx, s.addr, s.size));

  return (
    <section class="panel">
      <h2>Memory</h2>
      <div class="memory-controls">
        <label>
          addr
          <input
            type="text"
            value={addr()}
            onInput={(e) => setAddr(e.currentTarget.value)}
          />
        </label>
        <label>
          count
          <input
            type="number"
            min="1"
            max="512"
            value={count()}
            onInput={(e) => setCount(Number(e.currentTarget.value) || 64)}
          />
        </label>
        <Show when={record()}>
          {(r) => (
            <div class="memory-quick">
              <For each={QUICK_REGS.filter((reg) => r().regs[reg])}>
                {(reg) => (
                  <button type="button" onClick={() => setAddr(r().regs[reg])}>
                    {reg}
                  </button>
                )}
              </For>
            </div>
          )}
        </Show>
      </div>
      <Show when={dump.error}>
        <p class="err">load failed: {String(dump.error)}</p>
      </Show>
      <Show when={diff.error}>
        <p class="err">diff failed: {String(diff.error)}</p>
      </Show>
      <Show when={dump.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={dump()}>
        {(d) => (
          <>
            <p class="dim small">{d().addr} · {d().count} bytes</p>
            <table class="memory-table">
              <thead>
                <tr>
                  <th>addr</th>
                  <th>hex</th>
                  <th>ascii</th>
                  <th>kind</th>
                  <th>src</th>
                </tr>
              </thead>
              <tbody>
                <For each={d().bytes}>
                  {(b) => (
                    <tr>
                      <td><code>{b.addr}</code></td>
                      <td><code>{hexByte(b.byte)}</code></td>
                      <td>{asciiByte(b.byte)}</td>
                      <td>{b.kind}</td>
                      <td>{b.src_idx ?? ""}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </>
        )}
      </Show>
      <Show when={diff()}>
        {(d) => (
          <div class="memory-diff">
            <h3>{diffTitle(d().idx)}</h3>
            <p class="dim small">
              {d().addr} · {d().changed_count}/{d().size} changed
            </p>
            <table class="memory-table">
              <thead>
                <tr>
                  <th>addr</th>
                  <th>before</th>
                  <th>after</th>
                  <th>changed</th>
                </tr>
              </thead>
              <tbody>
                <For each={d().bytes}>
                  {(b) => (
                    <tr class={b.changed ? "changed" : ""}>
                      <td><code>{b.addr}</code></td>
                      <td><code>{hexByte(b.before)}</code></td>
                      <td><code>{hexByte(b.after)}</code></td>
                      <td>{b.changed ? "yes" : ""}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </div>
        )}
      </Show>
    </section>
  );
}
