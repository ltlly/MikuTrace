import { createEffect, createMemo, createResource, createSignal, For, Show } from "solid-js";

import { fetchMemDiff, fetchMemDump, fetchRecord } from "~/api/client";
import type { MemDumpByte } from "~/api/types";

interface MemoryPanelProps {
  idx: number;
  onSelect: (idx: number) => void;
}

const QUICK_REGS = ["x0", "x1", "x2", "x3", "sp"];
const REG_ADDR_RE = /^(?:x(?:[0-9]|1[0-9]|2[0-9]|30)|w(?:[0-9]|1[0-9]|2[0-9]|30)|sp|fp|lr)$/i;

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

function normalizeRegName(raw: string): string {
  const reg = raw.trim().toLowerCase();
  if (reg === "fp") return "x29";
  if (reg === "lr") return "x30";
  if (reg.startsWith("w")) return `x${reg.slice(1)}`;
  return reg;
}

export default function MemoryPanel(props: MemoryPanelProps) {
  const [addr, setAddr] = createSignal("0x0");
  const [count, setCount] = createSignal(64);
  const [record] = createResource(() => props.idx, fetchRecord);
  let autoAddr = "";
  createEffect(() => {
    const r = record();
    const sp = r?.regs.sp;
    if (!sp) return;
    const current = addr().trim();
    if (!current || current === "0x0" || current === autoAddr) {
      autoAddr = sp;
      setAddr(sp);
    }
  });
  const resolvedAddr = createMemo(() => {
    const raw = addr().trim();
    if (!raw) return "0x0";
    if (!REG_ADDR_RE.test(raw)) return raw;
    return record()?.regs[normalizeRegName(raw)] ?? "0x0";
  });
  const dumpSource = createMemo(() => ({
    addr: resolvedAddr(),
    count: Math.max(1, Math.min(512, count())),
  }));
  const [dump] = createResource(dumpSource, (s) => fetchMemDump(s.addr, s.count));
  const diffSource = createMemo(() => ({
    idx: props.idx,
    addr: resolvedAddr(),
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
            <p class="dim small">
              {d().addr} · {d().count} bytes
              <Show when={addr().trim() !== resolvedAddr()}>
                {" "}· {addr().trim()}={resolvedAddr()}
              </Show>
            </p>
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
                              onDblClick={() => {
                                if (b.src_idx !== null) props.onSelect(b.src_idx);
                              }}
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
