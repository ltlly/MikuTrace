import { For, Show } from "solid-js";

import type { AsmToken, RecordRow } from "~/api/types";
import { normalizeReg, tokenAddr, tokenClass, tokenReg, tokenText } from "~/utils/bnTokens";
import {
  ROW_HEIGHT,
  ROW_MARK_COLORS,
  asmParts,
  fnLabel,
  regFlowLabel,
  rowKind,
} from "./recordsModel";
import type { FoldRange, RowMark, RowMarkColor } from "./recordsModel";

type FlowKind = "def" | "use" | "def-use";

interface RecordsRowProps {
  row: RecordRow;
  mark?: RowMark;
  top: string;
  selected: boolean;
  rangeSelected: boolean;
  soHidden: boolean;
  taintHit: boolean;
  taintDimmed: boolean;
  flowKind: FlowKind | null;
  flowTitle?: string;
  flowSource: boolean;
  flowDef: boolean;
  flowUse: boolean;
  foldedRange?: FoldRange;
  foldableRange?: FoldRange;
  foldCollapsed: boolean;
  selectedReg: string;
  tokens: AsmToken[] | null;
  onPointerSelect: (idx: number) => void;
  onSelect: (row: RecordRow, event?: MouseEvent) => void;
  onOpenRowContext: (event: MouseEvent, row: RecordRow) => void;
  onSetMarkColor: (idx: number, color: RowMarkColor) => void;
  onToggleMarkFlag: (idx: number, key: "strike" | "muted") => void;
  onToggleFold: (range: FoldRange) => void;
  onSelectRegFlow: (row: RecordRow, reg: string) => void;
  onJumpLastWrite: (idx: number, reg: string) => void;
  onJumpPcValue: (value: string, idx: number) => void;
  onLoadRegTitle: (element: HTMLElement, idx: number, reg: string) => void;
  onLoadAddrTitle: (element: HTMLElement, idx: number, addr: string) => void;
  onOpenRegContext: (event: MouseEvent, row: RecordRow, reg: string) => void;
}

export default function RecordsRow(props: RecordsRowProps) {
  return (
    <div
      class="records-row"
      classList={{
        selected: props.selected,
        "range-selected": props.rangeSelected,
        "is-call": props.row.is_call,
        "is-ret": props.row.is_ret,
        "is-branch": props.row.is_branch && !props.row.is_call && !props.row.is_ret,
        "so-hidden": props.soHidden,
        "taint-hit": props.taintHit,
        "taint-dim": props.taintDimmed,
        "row-marked": !!props.mark,
        "row-strike": !!props.mark?.strike,
        "row-muted": !!props.mark?.muted,
        "has-note": !!props.mark?.note,
        "has-fold-summary": !!props.foldedRange,
        "reg-flow-source": props.flowSource,
        "reg-flow-def": props.flowDef,
        "reg-flow-use": props.flowUse,
        "mark-red": props.mark?.color === "red",
        "mark-yellow": props.mark?.color === "yellow",
        "mark-green": props.mark?.color === "green",
        "mark-blue": props.mark?.color === "blue",
        "mark-violet": props.mark?.color === "violet",
      }}
      style={{ top: props.top, height: `${ROW_HEIGHT}px` }}
      tabIndex={0}
      onPointerDown={(event) => {
        if (event.button === 0) props.onPointerSelect(props.row.idx);
      }}
      onClick={(event) => props.onSelect(props.row, event)}
      onContextMenu={(event) => props.onOpenRowContext(event, props.row)}
      onKeyDown={(event) => {
        if (event.key === "Enter") props.onSelect(props.row);
        else if (event.altKey && !event.ctrlKey && !event.metaKey && /^[1-5]$/.test(event.key)) {
          event.preventDefault();
          const color = ROW_MARK_COLORS[Number(event.key) - 1];
          if (color) props.onSetMarkColor(props.row.idx, color);
        } else if (event.altKey && !event.ctrlKey && !event.metaKey && event.key.toLowerCase() === "s") {
          event.preventDefault();
          props.onToggleMarkFlag(props.row.idx, "strike");
        } else if (event.altKey && !event.ctrlKey && !event.metaKey && event.key.toLowerCase() === "d") {
          event.preventDefault();
          props.onToggleMarkFlag(props.row.idx, "muted");
        }
      }}
    >
      <span class="dot" title={props.flowTitle ?? props.mark?.note}>
        <Show when={props.flowKind} fallback={<Show when={props.mark?.note} fallback={rowKind(props.row)}>*</Show>}>
          {(kind) => <span class={`reg-flow-arrow ${kind()}`}>{regFlowLabel(kind())}</span>}
        </Show>
      </span>
      <span class="idx">{props.row.idx}</span>
      <span class="pc"><code>{props.row.pc}</code></span>
      <span class="func" title={fnLabel(props.row)}>{fnLabel(props.row)}</span>
      <span class="asm" title={props.mark?.note ? `${props.mark.note}\n${props.row.asm}` : props.row.asm}>
        <Show when={props.foldableRange}>
          {(range) => (
            <button
              type="button"
              class="row-fold-btn"
              title={`${props.foldCollapsed ? "expand" : "collapse"} ${range().fn} [${range().enter}..${range().exit}]`}
              onClick={(event) => {
                event.stopPropagation();
                props.onToggleFold(range());
              }}
            >
              {props.foldCollapsed ? "▶" : "▼"}
            </button>
          )}
        </Show>
        <code>
          <Show
            when={props.tokens}
            fallback={
              <For each={asmParts(props.row.asm)}>
                {(part) => (
                  <Show when={part.reg} fallback={<span>{part.text}</span>}>
                    {(reg) => (
                      <span
                        class="op-reg"
                        classList={{ selected: reg() === props.selectedReg }}
                        title={`${reg()} · click selects register and shows def/use arrow · double-click jumps to last write · right-click for actions`}
                        onClick={(event) => {
                          event.stopPropagation();
                          props.onSelectRegFlow(props.row, reg());
                        }}
                        onDblClick={(event) => {
                          event.stopPropagation();
                          props.onJumpLastWrite(props.row.idx, reg());
                        }}
                        onMouseEnter={(event) => props.onLoadRegTitle(event.currentTarget, props.row.idx, reg())}
                        onContextMenu={(event) => props.onOpenRegContext(event, props.row, reg())}
                      >
                        {part.text}
                      </span>
                    )}
                  </Show>
                )}
              </For>
            }
          >
            {(tokens) => (
              <For each={tokens()}>
                {(token) => {
                  const reg = tokenReg(token);
                  const addr = tokenAddr(token);
                  return (
                    <span
                      class={`${tokenClass(token)}${reg ? " op-reg" : ""}`}
                      classList={{ selected: !!reg && reg === normalizeReg(props.selectedReg) }}
                      data-a={addr ?? undefined}
                      data-reg={reg ?? undefined}
                      title={reg
                        ? `${reg} · click selects register and shows def/use arrow · double-click jumps to last write · right-click for actions`
                        : addr ? `${addr} · double-click jump to nearest trace PC` : undefined}
                      onClick={(event) => {
                        if (!reg) return;
                        event.stopPropagation();
                        props.onSelectRegFlow(props.row, reg);
                      }}
                      onDblClick={(event) => {
                        if (reg) {
                          event.stopPropagation();
                          props.onJumpLastWrite(props.row.idx, reg);
                        } else if (addr) {
                          event.stopPropagation();
                          props.onJumpPcValue(addr, props.row.idx);
                        }
                      }}
                      onMouseEnter={(event) => {
                        if (reg) props.onLoadRegTitle(event.currentTarget, props.row.idx, reg);
                        else if (addr) props.onLoadAddrTitle(event.currentTarget, props.row.idx, addr);
                      }}
                      onContextMenu={(event) => {
                        if (reg) props.onOpenRegContext(event, props.row, reg);
                      }}
                    >
                      {tokenText(token)}
                    </span>
                  );
                }}
              </For>
            )}
          </Show>
        </code>
      </span>
      <Show when={props.foldedRange}>
        {(range) => <span class="fold-summary">folded {range().fn} · {Math.max(0, range().exit - range().enter).toLocaleString()} rows</span>}
      </Show>
      <Show when={!props.foldedRange ? props.mark?.note : undefined}>
        {(note) => <span class="row-note" title={note()}>{note()}</span>}
      </Show>
    </div>
  );
}
