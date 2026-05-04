import { createEffect, createMemo, createResource, createSignal, For, onCleanup, Show } from "solid-js";

import {
  fetchIdxsTouchingRange,
  fetchMemDiff,
  fetchMemDump,
  fetchMemWritesInRange,
  fetchRecord,
} from "~/api/client";
import type { MemDumpByte, MemWritesInRangeResponse, TouchingRangeResponse } from "~/api/types";

interface MemoryPanelProps {
  idx: number;
  onSelect: (idx: number) => void;
  addrRequest?: { token: number; addr: string };
  active: boolean;
}

const QUICK_REGS = ["x0", "x1", "x2", "x3", "sp"];
const REG_ADDR_RE = /^(?:x(?:[0-9]|1[0-9]|2[0-9]|30)|w(?:[0-9]|1[0-9]|2[0-9]|30)|sp|fp|lr)$/i;

interface MemContext {
  x: number;
  y: number;
  addr: string;
  size: number;
  srcIdx: number | null;
  hits?: TouchingRangeResponse;
  writes?: MemWritesInRangeResponse;
  err?: string;
}

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
  const [count, setCount] = createSignal(128);
  const [memContext, setMemContext] = createSignal<MemContext | null>(null);
  const [selection, setSelection] = createSignal<{ anchor: string; head: string } | null>(null);
  const [dragAnchor, setDragAnchor] = createSignal<string | null>(null);
  const [record] = createResource(
    () => (props.active ? props.idx : undefined),
    (idx) => fetchRecord(idx),
  );
  let autoAddr = "";
  let lastAddrRequest = -1;
  createEffect(() => {
    if (!memContext()) return;
    const closeOnPointer = (e: PointerEvent) => {
      const target = e.target as Element | null;
      if (target?.closest(".memory-context-menu") || target?.closest(".mem-byte")) return;
      setMemContext(null);
    };
    const closeOnKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setMemContext(null);
        setSelection(null);
      }
    };
    document.addEventListener("pointerdown", closeOnPointer);
    document.addEventListener("keydown", closeOnKey);
    onCleanup(() => {
      document.removeEventListener("pointerdown", closeOnPointer);
      document.removeEventListener("keydown", closeOnKey);
    });
  });
  createEffect(() => {
    const req = props.addrRequest;
    if (!req || req.token === lastAddrRequest) return;
    lastAddrRequest = req.token;
    autoAddr = req.addr;
    setAddr(req.addr);
  });
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
  const dumpSource = createMemo(() =>
    props.active
      ? {
          addr: resolvedAddr(),
          count: Math.max(1, Math.min(512, count())),
        }
      : undefined,
  );
  const [dump] = createResource(dumpSource, (s) => fetchMemDump(s.addr, s.count));
  const diffSource = createMemo(() =>
    props.active
      ? {
          idx: props.idx,
          addr: resolvedAddr(),
          size: Math.max(1, Math.min(128, count())),
        }
      : undefined,
  );
  const [diff] = createResource(diffSource, (s) => fetchMemDiff(s.idx, s.addr, s.size));
  const changedAddrs = createMemo(() => {
    const set = new Set<string>();
    for (const b of diff()?.bytes ?? []) {
      if (b.changed) set.add(b.addr);
    }
    return set;
  });

  function addrBig(addr: string): bigint {
    try {
      return BigInt(addr);
    } catch {
      return 0n;
    }
  }

  function fmtAddr(n: bigint): string {
    return `0x${n.toString(16)}`;
  }

  function selectedBounds(fallback: string): { lo: string; hi: string; size: number; selected: boolean } {
    const sel = selection();
    if (!sel) return { lo: fallback, hi: fallback, size: 1, selected: false };
    const a = addrBig(sel.anchor);
    const h = addrBig(sel.head);
    const f = addrBig(fallback);
    const lo = a <= h ? a : h;
    const hi = a <= h ? h : a;
    if (f < lo || f > hi) return { lo: fallback, hi: fallback, size: 1, selected: false };
    return { lo: fmtAddr(lo), hi: fmtAddr(hi), size: Number(hi - lo + 1n), selected: true };
  }

  function isSelected(addr: string): boolean {
    return selectedBounds(addr).selected;
  }

  function startSelect(e: MouseEvent, addr: string) {
    if (e.button !== 0) return;
    e.preventDefault();
    setDragAnchor(addr);
    setSelection({ anchor: addr, head: addr });
  }

  function extendSelect(e: MouseEvent, addr: string) {
    const anchor = dragAnchor();
    if (!anchor || e.buttons !== 1) return;
    setSelection({ anchor, head: addr });
  }

  async function openMemContext(e: MouseEvent, b: MemDumpByte) {
    e.preventDefault();
    e.stopPropagation();
    const bounds = selectedBounds(b.addr);
    const base: MemContext = {
      x: Math.min(e.clientX, window.innerWidth - 320),
      y: Math.min(e.clientY, window.innerHeight - 260),
      addr: bounds.lo,
      size: bounds.size,
      srcIdx: bounds.size === 1 ? b.src_idx : null,
    };
    setMemContext(base);
    try {
      const [hits, writes] = await Promise.all([
        fetchIdxsTouchingRange(bounds.lo, bounds.size, props.idx, 30),
        fetchMemWritesInRange({
          idxLo: 0,
          idxHi: props.idx,
          addrLo: bounds.lo,
          addrHi: bounds.hi,
          max: 30,
        }),
      ]);
      setMemContext((current) =>
        current?.addr === bounds.lo && current.size === bounds.size
          ? { ...current, hits, writes }
          : current,
      );
    } catch (err) {
      setMemContext((current) =>
        current?.addr === bounds.lo && current.size === bounds.size
          ? { ...current, err: String(err) }
          : current,
      );
    }
  }

  return (
    <section class="panel" onClick={() => setMemContext(null)} onMouseUp={() => setDragAnchor(null)}>
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
                              } ${
                                isSelected(b.addr) ? "selected" : ""
                              }`}
                              title={`${b.addr} ${b.kind} src=${b.src_idx ?? ""}`}
                              data-addr={b.addr}
                              onMouseDown={(e) => startSelect(e, b.addr)}
                              onMouseEnter={(e) => extendSelect(e, b.addr)}
                              onMouseUp={() => setDragAnchor(null)}
                              onContextMenu={(e) => void openMemContext(e, b)}
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
            <Show when={memContext()}>
              {(ctx) => (
                <div
                  class="memory-context-menu"
                  style={{ left: `${ctx().x}px`, top: `${ctx().y}px` }}
                  onClick={(e) => e.stopPropagation()}
                  onContextMenu={(e) => e.preventDefault()}
                >
                  <div class="memory-context-title">
                    <code>{ctx().addr}</code> <span class="dim">size {ctx().size}</span>
                  </div>
                  <Show when={ctx().srcIdx !== null}>
                    <button type="button" onClick={() => props.onSelect(ctx().srcIdx!)}>
                      跳到来源 idx {ctx().srcIdx}
                    </button>
                  </Show>
                  <Show when={ctx().err}>
                    <p class="err small">{ctx().err}</p>
                  </Show>
                  <Show when={!ctx().hits && !ctx().err}>
                    <p class="dim small">加载读写分析...</p>
                  </Show>
                  <Show when={ctx().hits}>
                    {(hits) => (
                      <>
                        <div class="memory-context-grid">
                          <div>
                            <h3>writers</h3>
                            <For each={[...hits().writers_before, ...hits().writers_after]}>
                              {(idx) => (
                                <button type="button" onClick={() => props.onSelect(idx)}>
                                  write {idx}
                                </button>
                              )}
                            </For>
                            <p class="dim small">total {hits().writers_total}</p>
                          </div>
                          <div>
                            <h3>readers</h3>
                            <For each={[...hits().readers_before, ...hits().readers_after]}>
                              {(idx) => (
                                <button type="button" onClick={() => props.onSelect(idx)}>
                                  read {idx}
                                </button>
                              )}
                            </For>
                            <p class="dim small">total {hits().readers_total}</p>
                          </div>
                        </div>
                        <Show when={ctx().writes?.writes.length}>
                          <div class="memory-context-writes">
                            <h3>write details</h3>
                            <For each={ctx().writes?.writes ?? []}>
                              {(w) => (
                                <button type="button" onClick={() => props.onSelect(w.idx)}>
                                  {w.idx} {w.dst_addr} {w.src_reg ?? ""} {w.asm}
                                </button>
                              )}
                            </For>
                          </div>
                        </Show>
                      </>
                    )}
                  </Show>
                </div>
              )}
            </Show>
          </>
        )}
      </Show>
    </section>
  );
}
