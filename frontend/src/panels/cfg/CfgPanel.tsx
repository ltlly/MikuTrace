import { createEffect, createMemo, createResource, createSignal, For, onCleanup, Show } from "solid-js";

import { fetchBnCfgSvgForPc, fetchCfgSvg, fetchFunctions, fetchIdxsForPc } from "~/api/client";
import type { BnCfgSvgForPcResponse, CfgSvgResponse } from "~/api/types";

const AUTO_RENDER_MAX_BLOCKS = 120;
const AUTO_RENDER_MAX_SVG_BYTES = 900_000;
const FORCE_DOT_MAX_BLOCKS = 400;
const FORCE_DOT_MAX_EDGES = 1_000;
const CFG_FETCH_DEBOUNCE_MS = 80;

function clampTimeout(raw: number): number {
  if (!Number.isFinite(raw)) return 60;
  return Math.min(300, Math.max(5, Math.trunc(raw)));
}

function clampScale(scale: number): number {
  return Math.min(5, Math.max(0.25, scale));
}

interface CfgPanelProps {
  selectedFn: string;
  currentIdx: number;
  currentHint?: CursorRecordHint;
  onSelect: (idx: number) => void;
  active: boolean;
  syncEnabled: boolean;
  onDisplayFnChange: (fn: string) => void;
  onDebugChange?: (state: CfgDebugState) => void;
}

export interface CursorRecordHint {
  idx: number;
  pc: string;
  func: string | null;
}

export interface CfgDebugState {
  fnName: string;
  lastGraphFn: string;
  loading: boolean;
  graphSeq: number;
}

type CfgGraphResponse = CfgSvgResponse & {
  source: "trace";
  requestFn: string;
  auto: boolean;
} | (BnCfgSvgForPcResponse & {
  source: "bn-asm";
  requestFn: string;
  requestPc: string;
  auto: boolean;
});

type CfgSource = "trace" | "bn-asm";

export default function CfgPanel(props: CfgPanelProps) {
  const [fnName, setFnName] = createSignal("");
  const [cfgSource, setCfgSource] = createSignal<CfgSource>("trace");
  const [autoGraph, setAutoGraph] = createSignal(true);
  const [timeout, setDotTimeout] = createSignal(60);
  const [reload, setReload] = createSignal(0);
  const [forceGraph, setForceGraph] = createSignal(false);
  const [graph, setGraph] = createSignal<CfgGraphResponse | null>(null);
  const [graphLoading, setGraphLoading] = createSignal(false);
  const [graphError, setGraphError] = createSignal<unknown>(null);
  const [lastGraphFn, setLastGraphFn] = createSignal("");
  const [debugSeq, setDebugSeq] = createSignal(0);
  const [pan, setPan] = createSignal({ x: 0, y: 0, scale: 1 });
  const [drag, setDrag] = createSignal<null | { sx: number; sy: number; x: number; y: number }>(
    null,
  );
  const [jumpErr, setJumpErr] = createSignal("");
  let frame: HTMLDivElement | undefined;
  let suppressNextClick = false;
  let lastCenteredIdx = -1;
  let lastPanFn = "";
  let graphSeq = 0;
  let graphTimer: number | undefined;
  let graphAbort: AbortController | undefined;
  let jumpSeq = 0;
  let jumpAbort: AbortController | undefined;

  const [functions] = createResource(
    () => (props.active ? "active" : undefined),
    () => fetchFunctions(),
  );
  // Note: cursorHint is now centrally maintained by App.tsx (which also owns
  // a row-data cache and falls back to /api/record on cache miss). CfgPanel
  // just trusts the hint when its idx matches the current cursor.
  const currentRecord = createMemo<CursorRecordHint | undefined>(() => {
    const hint = props.currentHint;
    return hint && hint.idx === props.currentIdx ? hint : undefined;
  });
  const selectedFnName = createMemo(() => {
    const want = props.selectedFn;
    if (!want) return "";
    const fn = (functions()?.functions ?? []).find((f) => f.id === want);
    return fn?.source === "bn" ? "" : fn?.name ?? "";
  });
  const bnTarget = createMemo<{ key: string; pc: string; func: string | null } | undefined>((prev) => {
    const r = currentRecord();
    if (!r?.pc) return undefined;
    const key = r.func ?? r.pc;
    if (prev && prev.key === key) return prev;
    return { key, pc: r.pc, func: r.func };
  });
  const fnNames = createMemo(() => {
    const names = new Set<string>();
    for (const fn of functions()?.functions ?? []) {
      if (fn.source === "bn") continue;
      if (fn.name) names.add(fn.name);
    }
    return [...names].sort((a, b) => a.localeCompare(b));
  });
  createEffect(() => {
    if (!props.active || props.syncEnabled || cfgSource() !== "trace") return;
    const selected = selectedFnName();
    if (selected && selected !== fnName()) {
      setAutoGraph(false);
      setFnName(selected);
    }
  });

  createEffect(() => {
    if (!props.active) return;
    if (cfgSource() === "bn-asm") {
      const r = currentRecord();
      props.onDisplayFnChange(r?.func ? `BN ${r.func}` : "BN ASM CFG");
    } else {
      props.onDisplayFnChange(fnName());
    }
  });

  createEffect(() => {
    const sourceKind = cfgSource();
    const bn = bnTarget();
    if (!props.active || (sourceKind === "trace" && !fnName()) || (sourceKind === "bn-asm" && !bn?.pc)) {
      graphSeq += 1;
      if (graphTimer !== undefined) {
        window.clearTimeout(graphTimer);
        graphTimer = undefined;
      }
      graphAbort?.abort();
      graphAbort = undefined;
      frame = undefined;
      setGraph(null);
      setGraphLoading(false);
      setGraphError(null);
      return;
    }

    const requestFn = sourceKind === "trace" ? fnName() : bn?.func ?? "";
    const requestPc = bn?.pc ?? "";
    const requestTimeout = timeout();
    const requestAuto = autoGraph();
    const requestForce = forceGraph();
    reload();

    const seq = ++graphSeq;
    setDebugSeq(seq);
    if (graphTimer !== undefined) {
      window.clearTimeout(graphTimer);
      graphTimer = undefined;
    }
    graphAbort?.abort();
    frame = undefined;
    setGraph(null);
    setGraphLoading(true);
    setGraphError(null);
    graphTimer = window.setTimeout(() => {
      graphTimer = undefined;
      if (seq !== graphSeq) return;
      const abort = new AbortController();
      graphAbort = abort;
      const promise =
        sourceKind === "trace"
          ? fetchCfgSvg({ fnName: requestFn, timeout: requestTimeout, force: requestForce, signal: abort.signal })
          : fetchBnCfgSvgForPc(requestPc, "asm", requestTimeout, abort.signal);
      void promise
        .then((resp) => {
          if (seq !== graphSeq || abort.signal.aborted) return;
          if (sourceKind === "trace") {
            const traceResp = resp as CfgSvgResponse;
            setGraph({ ...traceResp, source: "trace", requestFn, auto: requestAuto });
            if (traceResp.status === "ready") setLastGraphFn(requestFn);
          } else {
            const bnResp = resp as BnCfgSvgForPcResponse;
            setGraph({
              ...bnResp,
              source: "bn-asm",
              requestFn,
              requestPc,
              auto: requestAuto,
            });
            if (bnResp.ready && bnResp.ok) setLastGraphFn(requestFn || requestPc);
          }
        })
        .catch((err) => {
          if (seq !== graphSeq || abort.signal.aborted) return;
          setGraphError(err);
        })
        .finally(() => {
          if (seq === graphSeq && !abort.signal.aborted) {
            if (graphAbort === abort) graphAbort = undefined;
            setGraphLoading(false);
          }
        });
    }, CFG_FETCH_DEBOUNCE_MS);
  });

  createEffect(() => {
    props.onDebugChange?.({
      fnName: fnName(),
      lastGraphFn: lastGraphFn(),
      loading: graphLoading(),
      graphSeq: debugSeq(),
    });
  });

  function cancelJump() {
    jumpSeq += 1;
    jumpAbort?.abort();
    jumpAbort = undefined;
  }

  onCleanup(() => {
    graphSeq += 1;
    if (graphTimer !== undefined) {
      window.clearTimeout(graphTimer);
      graphTimer = undefined;
    }
    graphAbort?.abort();
    cancelJump();
  });

  createEffect(() => {
    if (!props.active || !props.syncEnabled || cfgSource() !== "trace") return;
    const idx = props.currentIdx;
    const r = currentRecord();
    if (!r || r.idx !== idx || !r.func || r.func === fnName()) return;
    setAutoGraph(true);
    setForceGraph(false);
    setFnName(r.func);
  });

  createEffect(() => {
    const name = fnName();
    const key = cfgSource() === "trace" ? name : bnTarget()?.key ?? "";
    if (!props.active || !key || key === lastPanFn) return;
    lastPanFn = key;
    lastCenteredIdx = -1;
    setPan({ x: 0, y: 0, scale: 1 });
  });

  createEffect(() => {
    if (!props.active || !props.syncEnabled) return;
    const idx = props.currentIdx;
    const r = currentRecord();
    if (!r || r.idx !== idx) return;
    const g = graph();
    if (!g) return;
    if (g.source === "trace") {
      if (g.status !== "ready" || !shouldRenderGraph(g)) return;
      if (g.requestFn !== fnName()) return;
      if (r.func && g.fn && r.func !== g.fn) return;
    } else {
      if (!g.ok || !g.ready || !g.svg) return;
      if (g.requestPc !== r.pc && g.requestFn !== r.func) return;
    }
    const raf = window.requestAnimationFrame(() => {
      if (!props.active || !props.syncEnabled) return;
      if (idx !== props.currentIdx || graph() !== g) return;
      if (g.source === "trace" && fnName() !== g.requestFn) return;
      highlightAndCenterPc(r.pc, idx);
    });
    onCleanup(() => window.cancelAnimationFrame(raf));
  });

  function shouldRenderGraph(resp: { status: string; svg?: string; block_count?: number; auto?: boolean }): boolean {
    if (resp.status !== "ready") return false;
    if (!resp.auto) return true;
    const svgBytes = resp.svg?.length ?? 0;
    const blocks = resp.block_count ?? 0;
    return blocks <= AUTO_RENDER_MAX_BLOCKS && svgBytes <= AUTO_RENDER_MAX_SVG_BYTES;
  }

  function forceDotDisabled(resp: { block_count: number; edge_count: number }): boolean {
    return resp.block_count > FORCE_DOT_MAX_BLOCKS || resp.edge_count > FORCE_DOT_MAX_EDGES;
  }

  function selectFunction(name: string) {
    setAutoGraph(false);
    setForceGraph(false);
    setCfgSource("trace");
    setFnName(name);
  }

  function reloadGraph() {
    setAutoGraph(false);
    setForceGraph(true);
    setReload((n) => n + 1);
  }

  function findInsnAnchor(pc: string): Element | undefined {
    if (!frame) return undefined;
    const hex = pc.trim().replace(/^0x/i, "").toLowerCase();
    return [...frame.querySelectorAll("a")].find((anchor) => {
      const href = anchor.getAttribute("href") ?? anchor.getAttribute("xlink:href") ?? "";
      return href.toLowerCase() === `#insn_${hex}`;
    });
  }

  function highlightAndCenterPc(pc: string | undefined, idx: number) {
    if (!frame) return;
    frame.querySelectorAll(".cfg-current").forEach((el) => el.classList.remove("cfg-current"));
    if (!pc) return;
    const target = findInsnAnchor(pc);
    target?.classList.add("cfg-current");
    if (!target || idx === lastCenteredIdx) return;

    const frameRect = frame.getBoundingClientRect();
    const targetRect = target.getBoundingClientRect();
    if (targetRect.width <= 0 || targetRect.height <= 0) return;
    lastCenteredIdx = idx;
    setPan((current) => ({
      ...current,
      x: current.x + frameRect.left + frameRect.width / 2 - (targetRect.left + targetRect.width / 2),
      y: current.y + frameRect.top + frameRect.height / 2 - (targetRect.top + targetRect.height / 2),
    }));
  }

  async function jumpToPc(hex: string) {
    cancelJump();
    const seq = ++jumpSeq;
    const abort = new AbortController();
    jumpAbort = abort;
    setJumpErr("");
    const pc = `0x${hex.toLowerCase()}`;
    try {
      const resp = await fetchIdxsForPc(pc, props.currentIdx, 40, abort.signal);
      if (seq !== jumpSeq || abort.signal.aborted) return;
      const candidates = [...resp.before, ...resp.after];
      if (candidates.length === 0) {
        setJumpErr(`trace 中没有执行 ${pc}`);
        return;
      }
      candidates.sort((a, b) => Math.abs(a - props.currentIdx) - Math.abs(b - props.currentIdx));
      props.onSelect(candidates[0]);
    } catch (err) {
      if (abort.signal.aborted) return;
      if (seq !== jumpSeq) return;
      setJumpErr(String(err));
    } finally {
      if (jumpAbort === abort) jumpAbort = undefined;
    }
  }

  function onSvgClick(e: MouseEvent) {
    if (suppressNextClick) {
      suppressNextClick = false;
      e.preventDefault();
      return;
    }
    const target = e.target as Element | null;
    const anchor = target?.closest("a");
    const href =
      anchor?.getAttribute("href") ??
      anchor?.getAttribute("xlink:href") ??
      anchor?.getAttribute("XLink:href") ??
      "";
    const m = href.match(/#(?:insn_|hdr_b)([0-9a-f]+)/i);
    if (!m) return;
    e.preventDefault();
    void jumpToPc(m[1]);
  }

  function onWheel(e: WheelEvent) {
    if (!e.ctrlKey) return;
    e.preventDefault();
    const current = pan();
    const nextScale = clampScale(current.scale * (e.deltaY < 0 ? 1.12 : 0.89));
    setPan({ ...current, scale: nextScale });
  }

  function onPointerDown(e: PointerEvent) {
    frame?.setPointerCapture(e.pointerId);
    const current = pan();
    setDrag({ sx: e.clientX, sy: e.clientY, x: current.x, y: current.y });
  }

  function onPointerMove(e: PointerEvent) {
    const d = drag();
    if (!d) return;
    if (Math.abs(e.clientX - d.sx) + Math.abs(e.clientY - d.sy) > 4) {
      suppressNextClick = true;
    }
    setPan((current) => ({
      ...current,
      x: d.x + e.clientX - d.sx,
      y: d.y + e.clientY - d.sy,
    }));
  }

  function onPointerUp(e: PointerEvent) {
    if (suppressNextClick) {
      window.setTimeout(() => {
        suppressNextClick = false;
      }, 0);
    }
    setDrag(null);
    frame?.releasePointerCapture(e.pointerId);
  }

  function graphFrame(svg: string, overview = false) {
    return (
      <div
        ref={(el) => {
          frame = el;
        }}
        class="cfg-svg-frame"
        classList={{ dragging: !!drag(), "cfg-overview-frame": overview }}
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
      >
        <div
          class="cfg-svg-canvas"
          style={{
            transform: `translate(${pan().x}px, ${pan().y}px) scale(${pan().scale})`,
          }}
          onClick={onSvgClick}
          innerHTML={svg}
        />
      </div>
    );
  }

  return (
    <section class="panel cfg-panel">
      <h2>Graph</h2>
      <div class="cfg-controls">
        <label>
          source
          <select value={cfgSource()} onInput={(e) => setCfgSource(e.currentTarget.value as CfgSource)}>
            <option value="trace">trace CFG</option>
            <option value="bn-asm">BN ASM CFG</option>
          </select>
        </label>
        <label>
          function
          <select
            value={fnName()}
            disabled={cfgSource() !== "trace"}
            onInput={(e) => selectFunction(e.currentTarget.value)}
          >
            <option value="" disabled>select function</option>
            <For each={fnNames()}>{(name) => <option value={name}>{name}</option>}</For>
          </select>
        </label>
        <label>
          dot timeout
          <input
            type="number"
            min="5"
            max="300"
            value={timeout()}
            onInput={(e) => setDotTimeout(clampTimeout(Number(e.currentTarget.value)))}
          />
        </label>
        <button onClick={reloadGraph}>reload</button>
        <button onClick={() => setPan({ x: 0, y: 0, scale: 1 })}>fit</button>
        <span class="dim small">{props.syncEnabled ? "highlight sync" : "sync paused"}</span>
      </div>

      <Show when={functions.error}>
        <p class="err">function list failed: {String(functions.error)}</p>
      </Show>
      <Show when={cfgSource() === "trace" && !fnName() && !functions.loading}>
        <p class="dim">select a function to render trace CFG. Full-trace CFG is not rendered by default.</p>
      </Show>
      <Show when={cfgSource() === "bn-asm" && !currentRecord()}>
        <p class="dim">resolving current trace record before loading BN CFG…</p>
      </Show>
      <Show when={graphError()}>
        {(err) => <p class="err">graph load failed: {String(err())}</p>}
      </Show>
      <Show when={graphLoading()}>
        <div class="cfg-loading" role="status" aria-live="polite">
          <span class="cfg-spinner" />
          <span>rendering graph…</span>
        </div>
      </Show>
      <Show when={jumpErr()}>
        <p class="err">{jumpErr()}</p>
      </Show>

      <Show when={!graphLoading() && graph()}>
        {(resp) => {
          const r = resp();
          if (r.source === "bn-asm") {
            return (
              <>
                <Show
                  when={r.ok && r.ready && r.svg}
                  fallback={
                    <div class="cfg-large-graph">
                      <p class="dim">
                        BN ASM CFG unavailable for {r.requestPc}:{" "}
                        {String(r.error ?? r.status ?? "sidecar returned no SVG")}
                      </p>
                    </div>
                  }
                >
                  {(svg) => (
                    <>
                      <p class="dim small">
                        BN ASM CFG · {r.fn?.name ?? (r.requestFn || r.requestPc)} · drag to pan · Ctrl+wheel zoom
                      </p>
                      {graphFrame(svg())}
                    </>
                  )}
                </Show>
              </>
            );
          }
          return (
            <>
              {r.status === "ready" && shouldRenderGraph(r) && (
                <>
                  <p class="dim small">
                    {r.block_count}/{r.total_block_count} blocks · {r.fn ?? "all"} · cache{" "}
                    {r.cached ? "hit" : "miss"} · drag to pan · Ctrl+wheel zoom
                  </p>
                  {graphFrame(r.svg)}
                </>
              )}
              {r.status === "ready" && !shouldRenderGraph(r) && (
                <div class="cfg-large-graph">
                  <p class="dim">
                    {r.fn ?? fnName()} CFG is large ({r.block_count}/{r.total_block_count} blocks,{" "}
                    {Math.round((r.svg?.length ?? 0) / 1024).toLocaleString()} KiB). Auto follow skipped SVG
                    injection to keep disassembly responsive.
                  </p>
                  <button type="button" onClick={reloadGraph}>render graph</button>
                </div>
              )}
              {r.status === "large" && (
                <div class="cfg-large-graph">
                  <p class="dim">
                    {r.fn ?? fnName()} CFG is large ({r.block_count} blocks, {r.edge_count} edges,{" "}
                    ~{Math.round(r.dot_bytes / 1024).toLocaleString()} KiB dot).{" "}
                    {r.svg
                      ? `Overview shows ${r.drawn_edge_count}/${r.edge_count} representative edges; ${r.hidden_edge_count} hidden to avoid a hairball.`
                      : "Overview SVG skipped to keep the UI responsive."}
                  </p>
                  <Show when={r.svg}>
                    {(svg) => graphFrame(svg(), true)}
                  </Show>
                  <Show
                    when={!forceDotDisabled(r)}
                    fallback={<p class="dim small">dot render disabled for this CFG size.</p>}
                  >
                    <button type="button" onClick={reloadGraph}>force dot render</button>
                  </Show>
                </div>
              )}
              {r.status === "empty" && (
                <p class="dim">no traced CFG blocks for {r.fn ?? "selected function"}</p>
              )}
              {r.status === "error" && <p class="err">graphviz: {r.err}</p>}
            </>
          );
        }}
      </Show>
    </section>
  );
}
