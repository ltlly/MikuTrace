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

const REG_ORDER = [
  "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
  "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
  "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
  "x24", "x25", "x26", "x27", "x28", "fp", "lr", "sp", "pc",
];
const REG_ADDR_RE = /^(?:x(?:[0-9]|1[0-9]|2[0-9]|30)|w(?:[0-9]|1[0-9]|2[0-9]|30)|sp|fp|lr)$/i;

interface MemContext {
  token: number;
  x: number;
  y: number;
  addr: string;
  size: number;
  srcIdx: number | null;
  hits?: TouchingRangeResponse;
  writes?: MemWritesInRangeResponse;
  writeErr?: string;
  err?: string;
}

interface DumpSource {
  addr: string;
  count: number;
}

interface DiffSource {
  idx: number;
  addr: string;
  size: number;
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

function sortedRegNames(regs: Record<string, string>): string[] {
  const rank = new Map(REG_ORDER.map((reg, i) => [reg, i]));
  return Object.keys(regs)
    .filter((reg) => reg !== "nzcv")
    .sort((a, b) => {
      const ar = rank.get(a) ?? Number.MAX_SAFE_INTEGER;
      const br = rank.get(b) ?? Number.MAX_SAFE_INTEGER;
      if (ar !== br) return ar - br;
      return a.localeCompare(b);
    });
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
  const currentRecord = createMemo(() => {
    const r = record();
    return r && r.idx === props.idx ? r : undefined;
  });
  let autoAddr = "";
  let lastAddrRequest = -1;
  let memContextSeq = 0;
  let memContextAbort: AbortController | undefined;

  function cancelMemContext() {
    memContextSeq += 1;
    memContextAbort?.abort();
    memContextAbort = undefined;
  }

  function closeMemContext(clearSelection = false) {
    cancelMemContext();
    setMemContext(null);
    if (clearSelection) setSelection(null);
  }

  createEffect(() => {
    if (!memContext()) return;
    const closeOnPointer = (e: PointerEvent) => {
      const target = e.target as Element | null;
      if (target?.closest(".memory-context-menu") || target?.closest(".mem-byte")) return;
      closeMemContext();
    };
    const closeOnKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        closeMemContext(true);
      }
    };
    document.addEventListener("pointerdown", closeOnPointer);
    document.addEventListener("keydown", closeOnKey);
    onCleanup(() => {
      document.removeEventListener("pointerdown", closeOnPointer);
      document.removeEventListener("keydown", closeOnKey);
    });
  });
  onCleanup(() => cancelMemContext());
  createEffect(() => {
    const req = props.addrRequest;
    if (!req || req.token === lastAddrRequest) return;
    lastAddrRequest = req.token;
    autoAddr = req.addr;
    setAddr(req.addr);
  });
  createEffect(() => {
    const r = currentRecord();
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
    const regs = currentRecord()?.regs;
    if (!regs) return undefined;
    const normalized = normalizeRegName(raw);
    return regs[normalized] ?? regs[raw.toLowerCase()];
  });
  const dumpSource = createMemo<DumpSource | undefined>((prev) => {
    if (!props.active) return undefined;
    const resolved = resolvedAddr();
    if (!resolved) return undefined;
    const next = {
      addr: resolved,
      count: Math.max(1, Math.min(512, count())),
    };
    return prev && prev.addr === next.addr && prev.count === next.count ? prev : next;
  });
  const [dump] = createResource(dumpSource, (s) => fetchMemDump(s.addr, s.count));
  const diffSource = createMemo<DiffSource | undefined>((prev) => {
    if (!props.active) return undefined;
    const resolved = resolvedAddr();
    if (!resolved) return undefined;
    const next = {
      idx: props.idx,
      addr: resolved,
      size: Math.max(1, Math.min(128, count())),
    };
    return prev &&
      prev.idx === next.idx &&
      prev.addr === next.addr &&
      prev.size === next.size
      ? prev
      : next;
  });
  const [diff] = createResource(diffSource, (s) => fetchMemDiff(s.idx, s.addr, s.size));
  const currentDump = createMemo(() => {
    const s = dumpSource();
    const r = dump();
    if (!s || !r) return undefined;
    return r.request_addr === s.addr && r.request_count === s.count ? r : undefined;
  });
  const currentDiff = createMemo(() => {
    const s = diffSource();
    const r = diff();
    if (!s || !r) return undefined;
    return r.request_idx === s.idx &&
      r.request_addr === s.addr &&
      r.request_size === s.size
      ? r
      : undefined;
  });
  const changedAddrs = createMemo(() => {
    const set = new Set<string>();
    if (!diffSource()) return set;
    for (const b of currentDiff()?.bytes ?? []) {
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

  function addToAddr(addr: string, delta: number): string {
    return fmtAddr(addrBig(addr) + BigInt(delta));
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
    cancelMemContext();
    const bounds = selectedBounds(b.addr);
    const token = ++memContextSeq;
    const abort = new AbortController();
    memContextAbort = abort;
    const base: MemContext = {
      token,
      x: Math.min(e.clientX, window.innerWidth - 320),
      y: Math.min(e.clientY, window.innerHeight - 260),
      addr: bounds.lo,
      size: bounds.size,
      srcIdx: bounds.size === 1 ? b.src_idx : null,
    };
    setMemContext(base);
    try {
      const hits = await fetchIdxsTouchingRange(bounds.lo, bounds.size, props.idx, 30, abort.signal);
      let writes: MemWritesInRangeResponse | undefined;
      let writeErr: string | undefined;
      try {
        writes = await fetchMemWritesInRange({
          idxLo: 0,
          idxHi: props.idx,
          addrLo: bounds.lo,
          addrHi: addToAddr(bounds.hi, 1),
          max: 30,
          signal: abort.signal,
        });
      } catch (err) {
        if (abort.signal.aborted) return;
        writeErr = String(err);
      }
      setMemContext((current) =>
        current?.token === token
          ? { ...current, hits, writes, writeErr }
          : current,
      );
    } catch (err) {
      if (abort.signal.aborted) return;
      setMemContext((current) =>
        current?.token === token
          ? { ...current, err: String(err) }
          : current,
      );
    } finally {
      if (memContextAbort === abort) memContextAbort = undefined;
    }
  }

  return (
    <section class="panel" onClick={() => closeMemContext()} onMouseUp={() => setDragAnchor(null)}>
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
        <Show when={currentRecord()}>
          {(r) => (
            <label>
              reg
              <select
                value=""
                onChange={(e) => {
                  const reg = e.currentTarget.value;
                  if (reg) setAddr(r().regs[reg]);
                  e.currentTarget.value = "";
                }}
              >
                <option value="">select register…</option>
                <For each={sortedRegNames(r().regs)}>
                  {(reg) => <option value={reg}>{reg} = {r().regs[reg]}</option>}
                </For>
              </select>
            </label>
          )}
        </Show>
      </div>
      <Show when={!dump.loading && dump.error}>
        <p class="err">load failed: {String(dump.error)}</p>
      </Show>
      <Show when={dump.loading}>
        <p class="dim">loading…</p>
      </Show>
      <Show when={currentDump()}>
        {(d) => (
          <>
            <p class="dim small">
              {d().addr} · {d().count} bytes
              <Show when={resolvedAddr() && addr().trim() !== resolvedAddr()}>
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
                  <p class="dim small">拖选多个字节后右键，会按整段范围查询读写。</p>
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
                        <Show when={ctx().writeErr}>
                          <p class="err small">write details unavailable: {ctx().writeErr}</p>
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
