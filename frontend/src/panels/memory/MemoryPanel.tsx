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
  "nzcv",
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
  retry: number;
}

interface DiffSource {
  idx: number;
  addr: string;
  size: number;
  retry: number;
}

const MEMORY_RETRY_MS = 350;
const MEM_COLS_KEY = "tracemiku-memory-cols";

interface MemCols {
  addr: number;
  hex: number;
  ascii: number;
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

function initialMemCols(): MemCols {
  try {
    const raw = localStorage.getItem(MEM_COLS_KEY);
    if (!raw) return { addr: 116, hex: 540, ascii: 150 };
    const parsed = JSON.parse(raw) as Partial<MemCols>;
    return {
      addr: clamp(Number(parsed.addr) || 116, 76, 220),
      hex: clamp(Number(parsed.hex) || 540, 280, 1100),
      ascii: clamp(Number(parsed.ascii) || 150, 80, 360),
    };
  } catch {
    return { addr: 116, hex: 540, ascii: 150 };
  }
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
    .sort((a, b) => {
      const ar = rank.get(a) ?? Number.MAX_SAFE_INTEGER;
      const br = rank.get(b) ?? Number.MAX_SAFE_INTEGER;
      if (ar !== br) return ar - br;
      return a.localeCompare(b);
    });
}

export default function MemoryPanel(props: MemoryPanelProps) {
  const initialCols = initialMemCols();
  const [addr, setAddr] = createSignal("0x0");
  const [count, setCount] = createSignal(128);
  const [addrW, setAddrW] = createSignal(initialCols.addr);
  const [hexW, setHexW] = createSignal(initialCols.hex);
  const [asciiW, setAsciiW] = createSignal(initialCols.ascii);
  const [memContext, setMemContext] = createSignal<MemContext | null>(null);
  const [selection, setSelection] = createSignal<{ anchor: string; head: string } | null>(null);
  const [dragAnchor, setDragAnchor] = createSignal<string | null>(null);
  const [dumpRetry, setDumpRetry] = createSignal(0);
  const [diffRetry, setDiffRetry] = createSignal(0);
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

  function saveCols() {
    localStorage.setItem(
      MEM_COLS_KEY,
      JSON.stringify({ addr: addrW(), hex: hexW(), ascii: asciiW() }),
    );
  }

  function startResize(kind: keyof MemCols, e: PointerEvent) {
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    const starts = { addr: addrW(), hex: hexW(), ascii: asciiW() };
    document.body.classList.add("is-resizing");
    document.body.style.cursor = "col-resize";
    const onMove = (ev: PointerEvent) => {
      const w = starts[kind] + ev.clientX - startX;
      if (kind === "addr") setAddrW(clamp(w, 76, 220));
      else if (kind === "hex") setHexW(clamp(w, 280, 1100));
      else setAsciiW(clamp(w, 80, 360));
    };
    const onUp = () => {
      document.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerup", onUp);
      document.body.classList.remove("is-resizing");
      document.body.style.cursor = "";
      saveCols();
    };
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
  }

  createEffect(() => {
    if (!memContext()) return;
    const closeOnPointer = (e: PointerEvent) => {
      const target = e.target as Element | null;
      if (target?.closest(".memory-context-menu")) return;
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
      retry: dumpRetry(),
    };
    return prev &&
      prev.addr === next.addr &&
      prev.count === next.count &&
      prev.retry === next.retry
      ? prev
      : next;
  });
  const [dump] = createResource(dumpSource, (s) => fetchMemDump(s.addr, s.count));
  const currentDump = createMemo(() => {
    const s = dumpSource();
    const r = dump();
    if (!s || !r) return undefined;
    return r.request_addr === s.addr && r.request_count === s.count ? r : undefined;
  });
  const diffSource = createMemo<DiffSource | undefined>((prev) => {
    if (!props.active) return undefined;
    if (currentDump()?.status !== "ready") return undefined;
    const resolved = resolvedAddr();
    if (!resolved) return undefined;
    const next = {
      idx: props.idx,
      addr: resolved,
      size: Math.max(1, Math.min(128, count())),
      retry: diffRetry(),
    };
    return prev &&
      prev.idx === next.idx &&
      prev.addr === next.addr &&
      prev.size === next.size &&
      prev.retry === next.retry
      ? prev
      : next;
  });
  const [diff] = createResource(diffSource, (s) => fetchMemDiff(s.idx, s.addr, s.size));
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
  const readyDump = createMemo(() => {
    const r = currentDump();
    return r?.status === "ready" ? r : undefined;
  });
  const changedAddrs = createMemo(() => {
    const set = new Set<string>();
    if (!diffSource()) return set;
    const r = currentDiff();
    if (r?.status !== "ready") return set;
    for (const b of r.bytes) {
      if (b.changed) set.add(b.addr);
    }
    return set;
  });

  createEffect(() => {
    if (!props.active || dump.loading || currentDump()?.status !== "loading") return;
    const timer = window.setTimeout(() => setDumpRetry((n) => n + 1), MEMORY_RETRY_MS);
    onCleanup(() => window.clearTimeout(timer));
  });

  createEffect(() => {
    if (!props.active || diff.loading || currentDiff()?.status !== "loading") return;
    const timer = window.setTimeout(() => setDiffRetry((n) => n + 1), MEMORY_RETRY_MS);
    onCleanup(() => window.clearTimeout(timer));
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
      <Show when={dump.loading || currentDump()?.status === "loading"}>
        <p class="dim">memory index loading…</p>
      </Show>
      <Show when={readyDump()}>
        {(d) => (
          <>
            <p class="dim small">
              {d().addr} · {d().count} bytes
              <Show when={resolvedAddr() && addr().trim() !== resolvedAddr()}>
                {" "}· {addr().trim()}={resolvedAddr()}
              </Show>
            </p>
            <table
              class="memory-hex-table"
              style={{
                "--mem-col-addr": `${addrW()}px`,
                "--mem-col-hex": `${hexW()}px`,
                "--mem-col-ascii": `${asciiW()}px`,
              }}
            >
              <thead>
                <tr>
                  <th>
                    addr
                    <span class="col-resize" onPointerDown={(e) => startResize("addr", e)} />
                  </th>
                  <th>
                    00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                    <span class="col-resize" onPointerDown={(e) => startResize("hex", e)} />
                  </th>
                  <th>
                    ascii
                    <span class="col-resize" onPointerDown={(e) => startResize("ascii", e)} />
                  </th>
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
                            <p class="dim small">
                              {ctx().writes?.returned}/{ctx().writes?.matched} writes
                              {ctx().writes?.truncated ? " · truncated" : ""}
                            </p>
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
