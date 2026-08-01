import { createEffect, createMemo, createResource, createSignal, For, onCleanup, Show } from "solid-js";

import { fetchBnCfgSvgForPc, fetchCfgSvg, fetchFunctions, fetchIdxsForPc } from "~/api/client";
import type { BnCfgSvgForPcResponse, CfgSvgResponse } from "~/api/types";
import type { UiTaskReporter } from "~/utils/taskCenter";
import { useGuarded } from "~/utils/guarded";

const AUTO_RENDER_MAX_BLOCKS = 120;
const AUTO_RENDER_MAX_SVG_BYTES = 900_000;
const FORCE_DOT_MAX_BLOCKS = 400;
const FORCE_DOT_MAX_EDGES = 1_000;
const CFG_FETCH_DEBOUNCE_MS = 80;
const SVG_PANZOOM_ATTR = "data-tracemiku-panzoom";
const SVG_CSS_WIDTH_ATTR = "data-tracemiku-css-width";
const SVG_CSS_HEIGHT_ATTR = "data-tracemiku-css-height";

function clampTimeout(raw: number): number {
  if (!Number.isFinite(raw)) return 60;
  return Math.min(300, Math.max(5, Math.trunc(raw)));
}

function clampScale(scale: number): number {
  return Math.min(5, Math.max(0.25, scale));
}

function parseSvgNumber(raw: string | null): number | undefined {
  const match = raw?.trim().match(/^[-+]?(?:\d+\.?\d*|\.\d+)/);
  if (!match) return undefined;
  const n = Number(match[0]);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

function svgViewBoxSize(svg: SVGSVGElement): { width: number; height: number } | undefined {
  const raw = svg.getAttribute("viewBox");
  if (raw) {
    const parts = raw
      .trim()
      .split(/[\s,]+/)
      .map((part) => Number(part));
    if (parts.length === 4 && parts.every((part) => Number.isFinite(part))) {
      const [, , width, height] = parts;
      if (width > 0 && height > 0) return { width, height };
    }
  }

  const width = parseSvgNumber(svg.getAttribute("width"));
  const height = parseSvgNumber(svg.getAttribute("height"));
  if (width && height) return { width, height };

  const rect = svg.getBoundingClientRect();
  if (rect.width > 0 && rect.height > 0) return { width: rect.width, height: rect.height };
  return undefined;
}

function rememberSvgCssSize(svg: SVGSVGElement): { width: number; height: number } | undefined {
  const storedWidth = Number(svg.getAttribute(SVG_CSS_WIDTH_ATTR));
  const storedHeight = Number(svg.getAttribute(SVG_CSS_HEIGHT_ATTR));
  if (storedWidth > 0 && storedHeight > 0) return { width: storedWidth, height: storedHeight };

  const rect = svg.getBoundingClientRect();
  if (rect.width <= 0 || rect.height <= 0) return undefined;
  svg.setAttribute(SVG_CSS_WIDTH_ATTR, String(rect.width));
  svg.setAttribute(SVG_CSS_HEIGHT_ATTR, String(rect.height));
  return { width: rect.width, height: rect.height };
}

function ensureSvgPanZoomGroup(svg: SVGSVGElement): SVGGElement {
  rememberSvgCssSize(svg);
  const existing = svg.querySelector<SVGGElement>(`g[${SVG_PANZOOM_ATTR}]`);
  if (existing) return existing;

  const group = svg.ownerDocument.createElementNS("http://www.w3.org/2000/svg", "g");
  group.setAttribute(SVG_PANZOOM_ATTR, "1");
  const keepDirect = new Set(["defs", "desc", "metadata", "style", "title"]);
  for (const child of Array.from(svg.childNodes)) {
    if (child.nodeType === 1) {
      const tag = (child as Element).tagName.toLowerCase();
      if (keepDirect.has(tag)) continue;
    }
    group.appendChild(child);
  }
  svg.appendChild(group);
  return group;
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
  onTaskUpdate?: UiTaskReporter;
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
  const [traceLocalFollow, setTraceLocalFollow] = createSignal(false);
  const [lastGraphFn, setLastGraphFn] = createSignal("");
  const [debugSeq, setDebugSeq] = createSignal(0);
  const [pan, setPan] = createSignal({ x: 0, y: 0, scale: 1 });
  const [drag, setDrag] = createSignal<null | { sx: number; sy: number; x: number; y: number }>(
    null,
  );
  const [jumpErr, setJumpErr] = createSignal("");
  let frame: HTMLDivElement | undefined;
  let canvas: HTMLDivElement | undefined;
  let suppressNextClick = false;
  let lastCenteredIdx = -1;
  let lastPanFn = "";
  let graphSeq = 0;
  let graphTimer: number | undefined;
  let graphAbort: AbortController | undefined;
  let graphTask:
    | { id: string; surface: string; label: string; startedAt: number }
    | undefined;
  const jump = useGuarded();

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
  const fnBlockCount = createMemo(() => {
    const name = fnName();
    if (!name) return 0;
    return (functions()?.functions ?? []).find((fn) => fn.name === name)?.blocks ?? 0;
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
    if (!props.active || cfgSource() !== "trace" || fnName()) return;
    const r = currentRecord();
    if (!r?.func) return;
    setAutoGraph(true);
    setForceGraph(false);
    setFnName(r.func);
  });

  function cancelGraphTask(detail = "superseded") {
    if (graphTask && (graphLoading() || graphTimer !== undefined || graphAbort)) {
      props.onTaskUpdate?.({
        ...graphTask,
        status: "cancelled",
        detail,
      });
    }
    graphTask = undefined;
  }

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
      cancelGraphTask("inactive");
      graphAbort?.abort();
      graphAbort = undefined;
      frame = undefined;
      canvas = undefined;
      setGraph(null);
      setGraphLoading(false);
      setGraphError(null);
      return;
    }

    const requestFn = sourceKind === "trace" ? fnName() : bn?.func ?? "";
    const requestPc = bn?.pc ?? "";
    const hint = currentRecord();
    const requestLocalFocus = traceLocalFollow() || fnBlockCount() > AUTO_RENDER_MAX_BLOCKS;
    const requestTracePc =
      sourceKind === "trace" && props.syncEnabled && requestLocalFocus && hint?.func === requestFn
        ? hint.pc
        : "";
    const requestTimeout = timeout();
    const requestAuto = autoGraph();
    const requestForce = forceGraph();
    reload();

    const seq = ++graphSeq;
    const taskId = sourceKind === "trace" ? "cfg-trace" : "cfg-bn-asm";
    const taskLabel = sourceKind === "trace" ? requestFn : requestFn || requestPc;
    const taskStartedAt = performance.now();
    cancelGraphTask("superseded");
    graphTask = {
      id: taskId,
      surface: sourceKind === "trace" ? "CFG" : "BN CFG",
      label: taskLabel || "current cursor",
      startedAt: taskStartedAt,
    };
    props.onTaskUpdate?.({
      ...graphTask,
      status: "running",
      detail: requestTracePc ? `local focus ${requestTracePc}` : "loading",
    });
    setDebugSeq(seq);
    if (graphTimer !== undefined) {
      window.clearTimeout(graphTimer);
      graphTimer = undefined;
    }
    graphAbort?.abort();
    frame = undefined;
    canvas = undefined;
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
          ? fetchCfgSvg({
              fnName: requestFn,
              pc: requestTracePc,
              localDepth: 2,
              timeout: requestTimeout,
              force: requestForce,
              signal: abort.signal,
            })
          : fetchBnCfgSvgForPc(requestPc, "asm", requestTimeout, abort.signal);
      void promise
        .then((resp) => {
          if (seq !== graphSeq || abort.signal.aborted) return;
            if (sourceKind === "trace") {
              const traceResp = resp as CfgSvgResponse;
              setGraph({ ...traceResp, source: "trace", requestFn, auto: requestAuto });
              setTraceLocalFollow(traceResp.status === "large");
              graphTask = undefined;
              props.onTaskUpdate?.({
              id: taskId,
              surface: "CFG",
              label: taskLabel || "trace",
              status:
                traceResp.status === "large"
                  ? "partial"
                  : traceResp.status === "ready" && traceResp.cached
                    ? "cached"
                    : traceResp.status === "error"
                      ? "error"
                      : "ready",
              startedAt: taskStartedAt,
              detail:
                traceResp.status === "large"
                  ? `${traceResp.layout_mode ?? "large"} ${traceResp.shown_block_count ?? 0}/${traceResp.block_count} blocks`
                  : traceResp.status === "ready"
                    ? `${traceResp.block_count}/${traceResp.total_block_count} blocks`
                    : traceResp.status,
            });
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
              graphTask = undefined;
              props.onTaskUpdate?.({
              id: taskId,
              surface: "BN CFG",
              label: taskLabel || requestPc,
              status: bnResp.ok && bnResp.ready ? "ready" : "error",
              startedAt: taskStartedAt,
              detail: bnResp.cache_hit
                ? "cache hit"
                : bnResp.created_function
                  ? "created BN function"
                  : String(bnResp.status ?? ""),
            });
            if (bnResp.ready && bnResp.ok) setLastGraphFn(requestFn || requestPc);
          }
        })
        .catch((err) => {
          if (seq !== graphSeq || abort.signal.aborted) return;
          setGraphError(err);
          graphTask = undefined;
          props.onTaskUpdate?.({
            id: taskId,
            surface: sourceKind === "trace" ? "CFG" : "BN CFG",
            label: taskLabel || requestPc,
            status: "error",
            startedAt: taskStartedAt,
            detail: String(err),
          });
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
    jump.cancel();
  }

  onCleanup(() => {
    graphSeq += 1;
    if (graphTimer !== undefined) {
      window.clearTimeout(graphTimer);
      graphTimer = undefined;
    }
    cancelGraphTask("unmounted");
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

  createEffect(() => {
    graph();
    pan();
    applySvgPanZoom();
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
    const h = jump.begin();
    const abort = h.abort;
    setJumpErr("");
    const pc = `0x${hex.toLowerCase()}`;
    try {
      const resp = await fetchIdxsForPc(pc, props.currentIdx, 40, abort.signal);
      if (!jump.isCurrent(h)) return;
      const candidates = [...resp.before, ...resp.after];
      if (candidates.length === 0) {
        setJumpErr(`trace 中没有执行 ${pc}`);
        return;
      }
      candidates.sort((a, b) => Math.abs(a - props.currentIdx) - Math.abs(b - props.currentIdx));
      props.onSelect(candidates[0]);
    } catch (err) {
      if (!jump.isCurrent(h)) return;
      setJumpErr(String(err));
    } finally {
      jump.release(h);
    }
  }

  function onSvgClick(e: MouseEvent) {
    if (suppressNextClick) {
      suppressNextClick = false;
      e.preventDefault();
      return;
    }
    const href = anchorHrefForClick(e);
    if (!href) return;
    const m = href.match(/#(?:insn_|hdr_b)([0-9a-f]+)/i);
    if (!m) return;
    e.preventDefault();
    void jumpToPc(m[1]);
  }

  /// Panel-level click handler. The SVG anchors can paint inside the frame
  /// (overflow:hidden) but their bounding boxes extend above/below into
  /// areas owned by the panel header `<p class="dim small">` status text or
  /// the controls row. A user clicking a visible-looking block whose
  /// rendered text actually paints right at the frame edge can land on
  /// those header elements instead of the SVG anchor — `target.closest("a")`
  /// returns null, the canvas onClick never fires, and the jump silently
  /// fails. This handler catches that case.
  function onPanelClick(e: MouseEvent) {
    if (suppressNextClick) return; // canvas listener will handle
    const target = e.target as Element | null;
    if (!target || target.closest(".cfg-svg-canvas")) return; // canvas already handled
    if (target.closest("button, select, input, label, textarea, a")) return;
    // Only reach here when click landed on a non-interactive panel surface.
    const href = anchorHrefForClick(e);
    if (!href) return;
    const m = href.match(/#(?:insn_|hdr_b)([0-9a-f]+)/i);
    if (!m) return;
    void jumpToPc(m[1]);
  }

  /// Resolve the SVG anchor for a click event. Tries the obvious path
  /// (target.closest("a")) first. If that fails — most commonly because
  /// the user clicked the panel's header status text overlapping an
  /// `<a>` whose bounding box extends above the frame's visible area
  /// (the SVG paints inside the frame's clip but the DOM elements still
  /// have y-coords above frame.top, so a click at the panel's status
  /// `<p class="dim small">` line lands on the `<p>`, not the anchor) —
  /// fall back to a hit-test against every SVG anchor's bounding box.
  /// Pick the closest anchor whose box contains the click point. Bound
  /// the search to the SVG inside this panel.
  function anchorHrefForClick(e: MouseEvent): string | null {
    const target = e.target as Element | null;
    const direct = target?.closest("a");
    if (direct) {
      return (
        direct.getAttribute("href") ??
        direct.getAttribute("xlink:href") ??
        direct.getAttribute("XLink:href") ??
        null
      );
    }
    if (!canvas) return null;
    const cx = e.clientX;
    const cy = e.clientY;
    const anchors = canvas.querySelectorAll("a");
    for (const a of anchors) {
      const r = a.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) continue;
      if (cx >= r.left && cx <= r.right && cy >= r.top && cy <= r.bottom) {
        return (
          a.getAttribute("href") ??
          a.getAttribute("xlink:href") ??
          a.getAttribute("XLink:href") ??
          null
        );
      }
    }
    return null;
  }

  function onWheel(e: WheelEvent) {
    if (!e.ctrlKey) return;
    e.preventDefault();
    const rect = canvas?.getBoundingClientRect() ?? frame?.getBoundingClientRect();
    setPan((current) => {
      const nextScale = clampScale(current.scale * (e.deltaY < 0 ? 1.12 : 0.89));
      if (!rect || nextScale === current.scale) return current;
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      const contentX = (mx - current.x) / current.scale;
      const contentY = (my - current.y) / current.scale;
      return {
        scale: nextScale,
        x: mx - contentX * nextScale,
        y: my - contentY * nextScale,
      };
    });
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

  function applySvgPanZoom() {
    const svg = canvas?.querySelector<SVGSVGElement>("svg") ?? frame?.querySelector<SVGSVGElement>(".cfg-svg-canvas > svg");
    if (!svg) return;
    const group = ensureSvgPanZoomGroup(svg);
    const naturalViewBox = svgViewBoxSize(svg);
    const cssSize = rememberSvgCssSize(svg);
    if (!naturalViewBox || !cssSize) return;

    // Make the SVG element fit the frame and use a viewBox that matches the
    // frame's CSS pixel dimensions 1:1, so user-coord positions inside the
    // graph render at their natural pixel sizes (no squish) AND content
    // translated by the inner pan group beyond the visible region is
    // clipped by SVG natively — both visually and at the
    // getBoundingClientRect level. Without this, the parent frame's
    // `overflow: hidden` clips painting only; SVG anchors keep their
    // pre-clip DOM geometry, so a click at a panel-header pixel can land
    // on a `<p>` overlay that visually has nothing to do with the SVG
    // anchor "underneath" (whose visual is clipped away).
    if (frame) {
      const fw = Math.max(1, frame.clientWidth);
      const fh = Math.max(1, frame.clientHeight);
      const widthAttr = String(fw);
      const heightAttr = String(fh);
      const viewBoxAttr = `0 0 ${fw} ${fh}`;
      if (svg.getAttribute("width") !== widthAttr) svg.setAttribute("width", widthAttr);
      if (svg.getAttribute("height") !== heightAttr) svg.setAttribute("height", heightAttr);
      if (svg.getAttribute("viewBox") !== viewBoxAttr) svg.setAttribute("viewBox", viewBoxAttr);
      svg.setAttribute("preserveAspectRatio", "xMinYMin meet");
      svg.style.display = "block";
    }

    const current = pan();
    // Pan signal is in CSS px and the viewBox is also CSS-px-aligned, so
    // user-units-per-css = 1 in both axes regardless of the SVG's natural
    // viewBox.
    group.setAttribute(
      "transform",
      `translate(${current.x} ${current.y}) scale(${current.scale})`,
    );
  }

  function graphFrame(svg: string, overview = false) {
    return (
      <div
        ref={(el) => {
          frame = el;
          queueMicrotask(applySvgPanZoom);
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
          ref={(el) => {
            canvas = el;
            queueMicrotask(applySvgPanZoom);
          }}
          class="cfg-svg-canvas"
          onClick={onSvgClick}
          innerHTML={svg}
        />
      </div>
    );
  }

  return (
    <section class="panel cfg-panel" onClick={onPanelClick}>
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
                        <Show when={r.created_function}> · BN function created</Show>
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
                    {r.svg && r.layout_mode === "local"
                      ? `Local CFG shows ${r.shown_block_count ?? 0}/${r.block_count} blocks around ${r.focus_pc ?? r.selected_block ?? "cursor"} at depth ${r.neighborhood_depth ?? 0}; ${r.hidden_edge_count} edges hidden.`
                      : r.svg
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
