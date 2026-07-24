import { createMemo, type Accessor, type JSX, type Setter } from "solid-js";

import { clampNumber, LAYOUT_KEY } from "./persistence";
import type { LayoutState } from "./types";

type PanelResizeKind = "left" | "right" | "bottom";
type ColumnResizeKind = "dot" | "idx" | "pc" | "func" | "asm";

interface LayoutControllerOptions {
  leftW: Accessor<number>;
  setLeftW: Setter<number>;
  rightW: Accessor<number>;
  setRightW: Setter<number>;
  bottomH: Accessor<number>;
  setBottomH: Setter<number>;
  colDot: Accessor<number>;
  setColDot: Setter<number>;
  colIdx: Accessor<number>;
  setColIdx: Setter<number>;
  colPc: Accessor<number>;
  setColPc: Setter<number>;
  colFunc: Accessor<number>;
  setColFunc: Setter<number>;
  colAsm: Accessor<number>;
  setColAsm: Setter<number>;
  syncCfg: Accessor<boolean>;
  setSyncCfgSignal: Setter<boolean>;
}

export function createLayoutController(options: LayoutControllerOptions) {
  function snapshot(overrides: Partial<LayoutState> = {}): LayoutState {
    return {
      leftW: options.leftW(),
      rightW: options.rightW(),
      bottomH: options.bottomH(),
      colDot: options.colDot(),
      colIdx: options.colIdx(),
      colPc: options.colPc(),
      colFunc: options.colFunc(),
      colAsm: options.colAsm(),
      syncCfg: options.syncCfg(),
      ...overrides,
    };
  }

  function persist(overrides: Partial<LayoutState> = {}) {
    localStorage.setItem(LAYOUT_KEY, JSON.stringify(snapshot(overrides)));
  }

  function setSyncCfg(next: boolean) {
    options.setSyncCfgSignal(next);
    persist({ syncCfg: next });
  }

  function listenForResize(onMove: (event: PointerEvent) => void) {
    const onUp = () => {
      document.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerup", onUp);
      document.body.classList.remove("is-resizing");
      document.body.style.cursor = "";
      persist();
    };
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
  }

  function startPanelResize(kind: PanelResizeKind, event: PointerEvent) {
    event.preventDefault();
    const startX = event.clientX;
    const startY = event.clientY;
    const startLeft = options.leftW();
    const startRight = options.rightW();
    const startBottom = options.bottomH();
    document.body.classList.add("is-resizing");
    document.body.style.cursor = kind === "bottom" ? "row-resize" : "col-resize";
    listenForResize((moveEvent) => {
      if (kind === "left") options.setLeftW(clampNumber(startLeft + moveEvent.clientX - startX, 180, 680));
      else if (kind === "right") options.setRightW(clampNumber(startRight - (moveEvent.clientX - startX), 320, 960));
      else options.setBottomH(clampNumber(startBottom - (moveEvent.clientY - startY), 120, 560));
    });
  }

  function startAsmColResize(kind: ColumnResizeKind, event: PointerEvent) {
    event.preventDefault();
    event.stopPropagation();
    const startX = event.clientX;
    const starts = {
      dot: options.colDot(),
      idx: options.colIdx(),
      pc: options.colPc(),
      func: options.colFunc(),
      asm: options.colAsm(),
    };
    document.body.classList.add("is-resizing");
    document.body.style.cursor = "col-resize";
    listenForResize((moveEvent) => {
      const delta = moveEvent.clientX - startX;
      if (kind === "dot") options.setColDot(clampNumber(starts.dot + delta, 12, 48));
      else if (kind === "idx") options.setColIdx(clampNumber(starts.idx + delta, 44, 140));
      else if (kind === "pc") options.setColPc(clampNumber(starts.pc + delta, 80, 260));
      else if (kind === "func") options.setColFunc(clampNumber(starts.func + delta, 80, 420));
      else options.setColAsm(clampNumber(starts.asm + delta, 180, 900));
    });
  }

  const layoutStyle = createMemo<JSX.CSSProperties>(() => ({
    "--left-w": `${options.leftW()}px`,
    "--right-w": `${options.rightW()}px`,
    "--bottom-h": `${options.bottomH()}px`,
  }));
  const asmStyle = createMemo<JSX.CSSProperties>(() => ({
    "--col-dot": `${options.colDot()}px`,
    "--col-idx": `${options.colIdx()}px`,
    "--col-pc": `${options.colPc()}px`,
    "--col-func": `${options.colFunc()}px`,
    "--col-asm": `${options.colAsm()}px`,
  }));

  return { asmStyle, layoutStyle, setSyncCfg, startAsmColResize, startPanelResize };
}
