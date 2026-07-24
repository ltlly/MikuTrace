import { For, Show } from "solid-js";

import { ROW_MARK_COLORS, nextTaintMode, regFlowTargetLabel, taintModeLabel } from "./recordsModel";
import type {
  RecordsTaintOverlay,
  RecordsTaintOverlayMode,
  RegContext,
  RegFlow,
  RowContext,
  RowMark,
  RowMarkColor,
} from "./recordsModel";

export interface RegFlowArrow {
  kind: "def" | "use";
  color: string;
  targetIdx: number;
  srcY: number;
  tgtY: number;
  srcOff: "top" | "bottom" | null;
  tgtOff: "top" | "bottom" | null;
  label?: string;
  title: string;
}

export interface RegFlowOverlayData {
  arrows: RegFlowArrow[];
  x: number;
  sTop: number;
  vH: number;
}

export function RecordsStatus(props: {
  range: { start: number; end: number };
  totalRecords: number;
  taintOnlyCount: number | null;
  selectedIdx: number;
  selectedReg: string;
  regFlow: RegFlow | null;
  taintOverlay: RecordsTaintOverlay | null;
  collapsedCount: number;
  callTreeLoading: boolean;
  foldTreeRequested: boolean;
  bnTokenStatus: string;
  onClearRegFlow: () => void;
  onTaintModeChange?: (mode: RecordsTaintOverlayMode) => void;
  onClearTaint?: () => void;
  onRequestFoldTree: () => void;
}) {
  return (
    <div class="records-status">
      <span>
        <Show
          when={props.taintOnlyCount !== null}
          fallback={<>window {props.range.start}-{props.range.end} / {props.totalRecords.toLocaleString()}</>}
        >
          <>taint rows {props.range.start}-{props.range.end} / {(props.taintOnlyCount ?? 0).toLocaleString()}</>
        </Show>
      </span>
      <span class="grow" />
      <span>selected idx {props.selectedIdx}</span>
      <span>reg {props.selectedReg}</span>
      <Show when={props.regFlow}>
        {(flow) => (
          <>
            <span class="records-reg-flow-status" title={flow().err}>
              flow {flow().reg} @#{flow().sourceIdx} · def {regFlowTargetLabel(flow(), "def")} · use {regFlowTargetLabel(flow(), "use")}
              <Show when={flow().loading}> · loading</Show>
            </span>
            <button class="status-btn" type="button" onClick={(event) => {
              event.stopPropagation();
              props.onClearRegFlow();
            }}>clear flow</button>
          </>
        )}
      </Show>
      <Show when={props.taintOverlay}>
        {(overlay) => (
          <>
            <span class="records-taint-status">
              taint {overlay().direction} {overlay().reg} @#{overlay().from} · {overlay().count} hit{overlay().count === 1 ? "" : "s"}
              <Show when={overlay().stopped}> · partial</Show>
            </span>
            <button
              class="status-btn"
              type="button"
              onClick={(event) => {
                event.stopPropagation();
                props.onTaintModeChange?.(nextTaintMode(overlay().mode));
              }}
              title={`switch to ${taintModeLabel(nextTaintMode(overlay().mode))}`}
            >
              {taintModeLabel(overlay().mode)}
            </button>
            <button class="status-btn" type="button" onClick={(event) => {
              event.stopPropagation();
              props.onClearTaint?.();
            }}>clear taint</button>
          </>
        )}
      </Show>
      <Show when={!props.callTreeLoading && props.collapsedCount > 0}>
        <span class="dim">{props.collapsedCount} folded</span>
      </Show>
      <Show when={!props.foldTreeRequested}>
        <button class="status-btn" type="button" title="load call tree metadata for inline fold controls" onClick={(event) => {
          event.stopPropagation();
          props.onRequestFoldTree();
        }}>load folds</button>
      </Show>
      <Show when={props.foldTreeRequested && props.callTreeLoading}>
        <span class="dim">loading folds</span>
      </Show>
      <Show when={props.bnTokenStatus && props.bnTokenStatus !== "ok"}>
        <span title="BN asm token overlay status">bn tokens {props.bnTokenStatus}</span>
      </Show>
    </div>
  );
}

export function RecordsRegFlowOverlay(props: {
  data: RegFlowOverlayData | null;
  onJump: (kind: "def" | "use") => void;
}) {
  const stub = 6;
  return (
    <Show when={props.data}>
      {(data) => (
        <svg
          class="reg-flow-overlay"
          style={{
            position: "absolute",
            left: "0",
            top: `${data().sTop}px`,
            width: "100%",
            height: `${data().vH}px`,
            "pointer-events": "none",
            "z-index": "5",
          }}
        >
          <defs>
            <marker id="rf-arrow-def" viewBox="0 0 6 6" refX="5.5" refY="3" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M0,0 L6,3 L0,6 z" fill="var(--err, #f78166)" />
            </marker>
            <marker id="rf-arrow-use" viewBox="0 0 6 6" refX="5.5" refY="3" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M0,0 L6,3 L0,6 z" fill="var(--ok, #56d364)" />
            </marker>
          </defs>
          <For each={data().arrows}>
            {(arrow) => {
              const baseX = data().x;
              const stemX = baseX - stub;
              const path = `M ${baseX},${arrow.srcY} L ${stemX},${arrow.srcY} L ${stemX},${arrow.tgtY} L ${baseX},${arrow.tgtY}`;
              return (
                <g style={{ "pointer-events": "none" }}>
                  <path
                    d={path}
                    fill="none"
                    stroke={arrow.color}
                    stroke-width="1.5"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    marker-end={`url(#rf-arrow-${arrow.kind})`}
                    style={{ "pointer-events": "stroke", cursor: "pointer" }}
                    onClick={(event) => {
                      event.stopPropagation();
                      props.onJump(arrow.kind);
                    }}
                  >
                    <title>{arrow.title}</title>
                  </path>
                  <Show when={arrow.label}>
                    {(label) => (
                      <text
                        x={baseX + 4}
                        y={arrow.tgtY + (arrow.tgtOff === "top" ? 10 : -3)}
                        fill={arrow.color}
                        font-size="10"
                        style={{ "pointer-events": "visiblePainted", cursor: "pointer" }}
                        onClick={(event) => {
                          event.stopPropagation();
                          props.onJump(arrow.kind);
                        }}
                      >
                        {label()}
                        <title>{arrow.title}</title>
                      </text>
                    )}
                  </Show>
                  <circle cx={baseX} cy={arrow.srcY} r="2.5" fill={arrow.color} />
                </g>
              );
            }}
          </For>
        </svg>
      )}
    </Show>
  );
}

export function RecordsRegContextMenu(props: {
  context: RegContext | null;
  onJumpLastWrite: (idx: number, reg: string) => void;
  onOpenMemory: (addr: string) => void;
  onJumpCfg: (value: string, idx: number) => void;
  onJumpPc: (value: string, idx: number) => void;
  onUseForTaint: (reg: string) => void;
  onRunTaint: (idx: number, reg: string, direction: "forward" | "backward") => void;
}) {
  return (
    <Show when={props.context}>
      {(context) => (
        <div
          class="reg-context-menu"
          style={{ left: `${context().x}px`, top: `${context().y}px` }}
          onClick={(event) => event.stopPropagation()}
          onContextMenu={(event) => event.preventDefault()}
        >
          <div class="memory-context-title">{context().reg} @ idx {context().idx}</div>
          <p class="dim small">
            {context().value ? `${context().reg} = ${context().value}` : context().err ?? "loading..."}
          </p>
          <button type="button" onClick={() => props.onJumpLastWrite(context().idx, context().reg)}>
            jump to last write
          </button>
          <Show when={context().value}>
            {(value) => (
              <>
                <button type="button" onClick={() => props.onOpenMemory(value())}>open Memory at value</button>
                <button type="button" onClick={() => props.onJumpCfg(value(), context().idx)}>CFG view at value</button>
                <button type="button" onClick={() => props.onJumpPc(value(), context().idx)}>jump to nearest PC value</button>
              </>
            )}
          </Show>
          <button type="button" onClick={() => props.onUseForTaint(context().reg)}>use for taint</button>
          <button type="button" onClick={() => props.onRunTaint(context().idx, context().reg, "forward")}>run forward taint</button>
          <button type="button" onClick={() => props.onRunTaint(context().idx, context().reg, "backward")}>run backward taint</button>
        </div>
      )}
    </Show>
  );
}

export function RecordsRowContextMenu(props: {
  context: RowContext | null;
  markFor: (idx: number) => RowMark;
  selectionLabel: (idx: number) => string;
  onSetColor: (idx: number, color: RowMarkColor) => void;
  onEditNote: (idx: number) => void;
  onToggleFlag: (idx: number, key: "strike" | "muted") => void;
  onClear: (idx: number) => void;
}) {
  return (
    <Show when={props.context}>
      {(context) => {
        const mark = () => props.markFor(context().idx);
        return (
          <div
            class="row-context-menu"
            style={{ left: `${context().x}px`, top: `${context().y}px` }}
            onClick={(event) => event.stopPropagation()}
            onContextMenu={(event) => event.preventDefault()}
          >
            <div class="memory-context-title">{props.selectionLabel(context().idx)}</div>
            <p class="dim small">{context().pc}</p>
            <div class="row-mark-swatches">
              <For each={ROW_MARK_COLORS}>
                {(color) => (
                  <button
                    type="button"
                    class={`row-mark-swatch ${color}`}
                    classList={{ active: mark().color === color }}
                    aria-label={`mark ${color}`}
                    title={`mark ${color}`}
                    onClick={() => props.onSetColor(context().idx, color)}
                  />
                )}
              </For>
            </div>
            <button type="button" onClick={() => props.onEditNote(context().idx)}>{mark().note ? "edit note" : "add note"}</button>
            <button type="button" onClick={() => props.onToggleFlag(context().idx, "strike")}>{mark().strike ? "remove strike" : "strike row"}</button>
            <button type="button" onClick={() => props.onToggleFlag(context().idx, "muted")}>{mark().muted ? "restore row" : "dim row"}</button>
            <button type="button" onClick={() => props.onClear(context().idx)}>clear mark</button>
          </div>
        );
      }}
    </Show>
  );
}
