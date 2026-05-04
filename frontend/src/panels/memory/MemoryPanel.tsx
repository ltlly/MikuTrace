import { createEffect, createMemo, createResource, createSignal, For, Show } from "solid-js";

import { fetchMemDiff, fetchMemDump, fetchRecord } from "~/api/client";
import type { MemDumpByte } from "~/api/types";

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

function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

function byteCellClass(kind: string): string {
  if (kind === "w") return "mem-byte write";
  if (kind === "r") return "mem-byte read";
  if (kind === "x") return "mem-byte external";
  return "mem-byte unknown";
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
  const changedAddrs = createMemo(() => {
    const set = new Set<string>();
    for (const b of diff()?.bytes ?? []) {
      if (b.changed) set.add(b.addr);
    }
    return set;
  });

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
            <table class="memory-hex-table">
              <thead>
                <tr>
                  <th>addr</th>
                  <th>00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f</th>
                  <th>ascii</th>
                </tr>
              </thead>
              <tbody>
                <For each={chunk<MemDumpByte>(d().bytes, 16)}>
                  {(line) => (
                    <tr>
                      <td>
                        <code>{line[0]?.addr}</code>
                      </td>
                      <td class="mem-hex-cells">
                        <For each={line}>
                          {(b) => (
                            <span
                              class={`${byteCellClass(b.kind)} ${
                                changedAddrs().has(b.addr) ? "changed" : ""
                              }`}
                              title={`${b.addr} ${b.kind} src=${b.src_idx ?? ""}`}
                            >
                              {hexByte(b.byte)}
                            </span>
                          )}
                        </For>
                      </td>
                      <td class="mem-ascii">
                        <For each={line}>{(b) => <span>{asciiByte(b.byte)}</span>}</For>
                      </td>
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
