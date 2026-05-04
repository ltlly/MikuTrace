import { createEffect, createMemo, createResource, createSignal, For, Show } from "solid-js";

import { fetchMemDump, fetchRecord } from "~/api/client";

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
    </section>
  );
}
