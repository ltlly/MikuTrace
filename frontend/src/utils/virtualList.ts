// 大列表虚拟化共享工具：窗口计算是纯函数，scroller hook 统一
// scroll/viewport 信号与 ResizeObserver 接线。RecordsPanel 的手写
// rawRange/overscan 逻辑与各表格面板的窗口渲染都收敛到这里。
import { createMemo, createSignal, onCleanup } from "solid-js";

export interface VirtualRange {
  start: number;
  count: number;
  end: number;
}

export interface VirtualWindow extends VirtualRange {
  /** 占位层高度（total * rowHeight）。 */
  height: number;
}

/// 可视行数。viewport 未知时用 fallback 换算；round 避免 1px 抖动翻转行数。
export function visibleRowCount(
  viewportHeight: number,
  rowHeight: number,
  fallbackHeight = 480,
): number {
  return Math.max(1, Math.round((viewportHeight || fallbackHeight) / rowHeight));
}

/// 以 firstRow 为顶行计算 [start,end) 窗口，overscan 两侧各留一行缓冲。
/// start 被 clamp 到 total - visibleRows，防止陈旧 scrollTop 驱动窗口越界。
export function virtualRange(
  firstRow: number,
  visibleRows: number,
  total: number,
  overscan: number,
): VirtualRange {
  if (total <= 0) return { start: 0, count: 0, end: 0 };
  const maxStart = Math.max(0, total - visibleRows);
  const start = Math.min(Math.max(firstRow - overscan, 0), maxStart);
  const end = Math.min(total, start + visibleRows + overscan * 2);
  return { start, count: Math.max(0, end - start), end };
}

export function spacerHeight(total: number, rowHeight: number): number {
  return Math.max(0, total) * rowHeight;
}

export interface VirtualScroller {
  /** 绑到滚动容器 div 的 ref。 */
  ref: (el: HTMLDivElement) => void;
  onScroll: (e: Event & { currentTarget: HTMLDivElement }) => void;
  scrollTop: () => number;
  viewHeight: () => number;
}

/// 滚动容器接线：scrollTop 信号 + ResizeObserver 同步 clientHeight。
/// ref 在 JSX 创建期即时赋值并挂 observer（Show 分支切换后也会重新触发），
/// observer 在组件卸载时统一断开。
export function createVirtualScroller(): VirtualScroller {
  let el: HTMLDivElement | undefined;
  let ro: ResizeObserver | undefined;
  const [scrollTop, setScrollTop] = createSignal(0);
  const [viewHeight, setViewHeight] = createSignal(0);
  const ref = (node: HTMLDivElement) => {
    el = node;
    setViewHeight(node.clientHeight);
    if (!ro) ro = new ResizeObserver(() => setViewHeight(el?.clientHeight ?? 0));
    ro.disconnect();
    ro.observe(node);
  };
  onCleanup(() => {
    ro?.disconnect();
    el = undefined;
  });
  return {
    ref,
    onScroll: (e) => setScrollTop(e.currentTarget.scrollTop),
    scrollTop,
    viewHeight,
  };
}

export interface VirtualList extends VirtualScroller {
  window: () => VirtualWindow;
}

/// 表格/列表面板的常用组合：给定 total accessor 与固定行高，返回窗口。
export function createVirtualList(
  total: () => number,
  rowHeight: number,
  overscan = 12,
): VirtualList {
  const scroller = createVirtualScroller();
  const win = createMemo<VirtualWindow>(() => {
    const count = total();
    const range = virtualRange(
      Math.floor(scroller.scrollTop() / rowHeight),
      visibleRowCount(scroller.viewHeight(), rowHeight, 0),
      count,
      overscan,
    );
    return { ...range, height: spacerHeight(count, rowHeight) };
  });
  return { ...scroller, window: win };
}
