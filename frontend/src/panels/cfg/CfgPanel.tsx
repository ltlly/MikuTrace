import { createEffect, createMemo, createResource, createSignal, For, onCleanup, Show } from "solid-js";

import { fetchCfgSvg, fetchFunctions, fetchIdxsForPc, fetchRecord } from "~/api/client";

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
  onSelect: (idx: number) => void;
  active: boolean;
  syncEnabled: boolean;
}

export default function CfgPanel(props: CfgPanelProps) {
  const [fnName, setFnName] = createSignal("");
  const [timeout, setTimeout] = createSignal(60);
  const [reload, setReload] = createSignal(0);
  const [pan, setPan] = createSignal({ x: 0, y: 0, scale: 1 });
  const [drag, setDrag] = createSignal<null | { sx: number; sy: number; x: number; y: number }>(
    null,
  );
  const [jumpErr, setJumpErr] = createSignal("");
  let frame: HTMLDivElement | undefined;
  let suppressNextClick = false;
  let lastCenteredIdx = -1;
  let lastSelectedFn = "";
  let lastPanFn = "";

  const [functions] = createResource(
    () => (props.active ? "active" : undefined),
    () => fetchFunctions(),
  );
  const [record] = createResource(
    () => (props.active && props.syncEnabled ? props.currentIdx : undefined),
    (idx) => fetchRecord(idx),
  );
  const selectedFnName = createMemo(() => {
    const want = props.selectedFn;
    if (!want) return "";
    const fn = (functions()?.functions ?? []).find((f) => f.id === want);
    return fn?.source === "bn" ? "" : fn?.name ?? "";
  });
  const fnNames = createMemo(() => {
    const names = new Set<string>();
    for (const fn of functions()?.functions ?? []) {
      if (fn.source === "bn") continue;
      if (fn.name) names.add(fn.name);
    }
    return [...names].sort((a, b) => a.localeCompare(b));
  });
  const cursorFnName = createMemo(() => record()?.func ?? "");

  createEffect(() => {
    if (!props.active) return;
    const selected = selectedFnName();
    if (selected && selected !== lastSelectedFn) {
      lastSelectedFn = selected;
      setFnName(selected);
    }
  });

  createEffect(() => {
    if (!props.active) return;
    const cursorFn = cursorFnName();
    if (!props.syncEnabled || !cursorFn || cursorFn === fnName()) return;
    const timer = window.setTimeout(() => {
      if (props.active && props.syncEnabled && cursorFn === cursorFnName()) {
        setFnName(cursorFn);
      }
    }, 220);
    onCleanup(() => window.clearTimeout(timer));
  });

  createEffect(() => {
    if (!props.active) return;
    if (!fnName() && fnNames().length > 0) {
      setFnName(fnNames()[0]);
    }
  });

  const [graph] = createResource(
    () => {
      if (!props.active) return undefined;
      const name = fnName();
      return name ? { fnName: name, timeout: timeout(), reload: reload() } : undefined;
    },
    (opts) => fetchCfgSvg({ fnName: opts.fnName, timeout: opts.timeout }),
  );

  createEffect(() => {
    const name = fnName();
    if (!props.active || !name || name === lastPanFn) return;
    lastPanFn = name;
    lastCenteredIdx = -1;
    setPan({ x: 0, y: 0, scale: 1 });
  });

  createEffect(() => {
    if (!props.active || !props.syncEnabled) return;
    const idx = props.currentIdx;
    const r = record();
    if (!r || r.idx !== idx) return;
    graph();
    window.requestAnimationFrame(() => highlightAndCenterPc(r.pc, idx));
  });

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
    setJumpErr("");
    const pc = `0x${hex.toLowerCase()}`;
    try {
      const resp = await fetchIdxsForPc(pc, props.currentIdx, 40);
      const candidates = [...resp.before, ...resp.after];
      if (candidates.length === 0) {
        setJumpErr(`trace 中没有执行 ${pc}`);
        return;
      }
      candidates.sort((a, b) => Math.abs(a - props.currentIdx) - Math.abs(b - props.currentIdx));
      props.onSelect(candidates[0]);
    } catch (err) {
      setJumpErr(String(err));
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

  return (
    <section class="panel cfg-panel">
      <h2>Graph</h2>
      <div class="cfg-controls">
        <label>
          function
          <select value={fnName()} onInput={(e) => setFnName(e.currentTarget.value)}>
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
            onInput={(e) => setTimeout(clampTimeout(Number(e.currentTarget.value)))}
          />
        </label>
        <button onClick={() => setReload((n) => n + 1)}>reload</button>
        <button onClick={() => setPan({ x: 0, y: 0, scale: 1 })}>fit</button>
        <span class="dim small">{props.syncEnabled ? "sync on" : "sync paused"}</span>
      </div>

      <Show when={functions.error}>
        <p class="err">function list failed: {String(functions.error)}</p>
      </Show>
      <Show when={!fnName() && !functions.loading}>
        <p class="dim">select a function to render CFG. Full-trace CFG is not rendered by default.</p>
      </Show>
      <Show when={graph.error}>
        <p class="err">graph load failed: {String(graph.error)}</p>
      </Show>
      <Show when={graph.loading}>
        <p class="dim">rendering graph…</p>
      </Show>
      <Show when={jumpErr()}>
        <p class="err">{jumpErr()}</p>
      </Show>

      <Show when={graph()}>
        {(resp) => {
          const r = resp();
          return (
            <>
              {r.status === "ready" && (
                <>
                  <p class="dim small">
                    {r.block_count}/{r.total_block_count} blocks · {r.fn ?? "all"} · cache{" "}
                    {r.cached ? "hit" : "miss"} · drag to pan · Ctrl+wheel zoom
                  </p>
                  <div
                    ref={(el) => {
                      frame = el;
                    }}
                    class="cfg-svg-frame"
                    classList={{ dragging: !!drag() }}
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
                      innerHTML={r.svg}
                    />
                  </div>
                </>
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
