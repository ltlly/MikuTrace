# UI 问题讨论 (2026-05-01)

> 实战 Web 调试 multiso_v2 trace 时反馈的两个问题 + Pretext 调研。
> 本文只**讨论 + 结论**, 不动代码。修复留 backlog 单独 PR。

---

## 1. 虚拟滚动末尾丢失最后 ~10 条 record

### 现象

Trace 总 records=10,214,936. 用户滚动到最底, Web UI 显示最后一条是 **#10,214,924**, 实际 trace 最后一条是 **#10,214,935** (`ret`)。**丢了 11 条**。

### Root cause (`webui/app.js:223-248` `viewportIdxRange()` decoupled scroll 模式)

```js
const baseIdx = Math.floor(pct * Math.max(0, STATE.totalRecords - visible));
startIdx = Math.max(0, baseIdx - overscan);                  // ← 上方 overscan
endIdx = Math.min(STATE.totalRecords, baseIdx + visible + overscan);
const maxRowsBelowScroll = Math.floor((innerH - scrollPos) / STATE.rowHeight);
endIdx = Math.min(endIdx, startIdx + maxRowsBelowScroll);    // ← 这里 bug
```

具体推导 (滚到底):
- `scrollPos = scrollMax`, `pct = 1`
- `baseIdx = totalRecords - visible` (≈ 10214897, 设 visible=39)
- `startIdx = baseIdx - 10` = 10214887 (overscan 把 startIdx 往上推 10)
- `maxRowsBelowScroll = floor(viewH/rowHeight) = visible = 39` (滚到底时 innerH-scrollPos = viewH)
- `endIdx = min(..., startIdx + 39) = startIdx + 39` = **10214926**

→ 渲染 [10214887, 10214926), **末尾 10 条** [10214926, 10214936) **从未渲染**。

### Bug 性质

`maxRowsBelowScroll` 约束本意防止行 `top` 超出 inner 元素 (避免覆盖到 `#bottom-tabs`), 但用 `startIdx + maxRowsBelowScroll` 作上限错了 — `startIdx` 已经被 overscan 上推 10, 所以这条线把 endIdx 也跟着上推 10 → 末尾 overscan 那 10 条丢失。

decoupled 模式的 overscan-above 本身设计也有问题: row 用 `top = scrollPos + (idx - startIdx) * rowHeight` 定位, startIdx 那行 top = scrollPos (= 视口顶), 所谓"上方 overscan" 实际上 **占用了视口内的顶部空间**, 把真实可见内容下推 — 不是放在视口上方 (那里 negative top)。

### 修复思路

**Option A (最小改动)**: 用 `baseIdx` 替代 `startIdx` 做 endIdx 约束:
```js
endIdx = Math.min(endIdx, baseIdx + maxRowsBelowScroll);
```

**Option B (推荐, 真正修)**: decoupled 模式不做 overscan-above, 因为它根本无效:
```js
startIdx = Math.max(0, baseIdx);             // 不再 -overscan
endIdx = Math.min(STATE.totalRecords, baseIdx + visible + overscan);
endIdx = Math.min(endIdx, startIdx + maxRowsBelowScroll);
```

Option B 还顺便干净了 row top 计算的语义。

### 影响

只有 decoupled mode (大 trace > 1.6M 行) 受影响, 普通 mode 没这问题。修复 1 行代码 (Option B 改两行)。

---

## 2. UI 各处布局重叠 — Pretext 是否合适?

### 现象

不同分辨率 / SO 名字 / func 名字长度变化时, 多处 UI 元素**互相覆盖或显示不全**。截图证据:
- `multiso_v2` trace 每行 `func` 列 = `doCommandNative+0xN`, 适配 200px 列宽
- 但有些 SO 名字会变成 `libsgmainso-6.8.260403.so@func+offset` 超 200px
- 列内容 overflow 视觉上把后续列推走 / 字符串截断不看

### 当前布局 (`webui/styles.css:114-126`)

```css
.row-insn {
  display: grid;
  grid-template-columns: 12px 60px 100px 200px 1fr;
  /*                     ec   idx  pc   func  asm   */
  padding: 0 4px 0 8px;
  white-space: nowrap;
  gap: 6px;
}
.row-insn.fmt-fn {     /* 当 PC 列含 func 时 */
  grid-template-columns: 12px 60px 240px 1fr;
}
```

固定列宽 + `white-space: nowrap`, 内容超 200px 时**会溢出 grid cell**. 没有 `overflow: hidden` 或 `text-overflow: ellipsis` 约束, 导致内容跑到下一列范围里。

### Pretext (chenglou/pretext) 调研结论

**Pretext 实际是什么**:
- 纯 TS/JS 文本测量 + 布局库, 不是 graph 布局
- 用 canvas 字体引擎做 ground truth, 避免 DOM reflow
- 解决: 算每行多高 (给 max-width 和 line-height) / 手动行布局 / canvas-svg 排版 / 虚拟化遮挡 / 富文本 inline 流 (mentions/chips)

**适用我们的 trace 行**: ❌ **不适合**. 原因:
1. Pretext 的强项是"复杂 inline rich text" (中英混排, 字符宽度变化, BiDi). 我们 trace 行是 **monospace 等宽字体**, 字符宽度恒定 — 没有 Pretext 要解决的难题。
2. 我们的列重叠是 **CSS Grid 列宽超 vs 内容溢出**, 用 `text-overflow: ellipsis + overflow: hidden` 一行 CSS 就解决, 不需要 JS 测量库。
3. Pretext 7KB JS + 运行时开销 (Intl.Segmenter + canvas 测量), 大 trace 每行渲染 hot path 不能接受。

**适用 graphviz CFG 重叠**: ❌ 不适合. graphviz 给 SVG 是 **graph 布局** (block + edge 坐标), Pretext 不处理 graph 拓扑布局 — 那是 dagre / ELK / cytoscape / d3-graphviz 的领域。

### 我们布局重叠的真实修复路径 (CSS-only)

#### 修 trace row

```css
.row-insn .pc, .row-insn .func {
  overflow: hidden;
  text-overflow: ellipsis;
  min-width: 0;          /* 关键: 让 grid item 允许收缩 */
}
.row-insn .pc:hover, .row-insn .func:hover {
  /* 让用户 hover 看完整内容 — 已有 title 属性 (HTML tooltip) */
}
```

`min-width: 0` 是 CSS Grid 必杀 — 默认 grid item 有 `min-width: auto` 会把内容撑出 cell。设 `min-width: 0` 让它强制 ellipsis。

#### 响应式列宽

```css
@media (max-width: 1400px) { .row-insn { grid-template-columns: 12px 50px 80px 160px 1fr; } }
@media (max-width: 1100px) { .row-insn { grid-template-columns: 12px 50px 80px 1fr; }
                             .row-insn .func { display: none; } }
```

#### 修 SO badge / SO Filter list

`#lp-sofilter` 的 SO 名字 + 长 path 也同问题, 加 `text-overflow: ellipsis + min-width: 0`.

#### 修 CFG SVG 重叠

跟列宽 / 文字测量无关. graphviz `dot -Tsvg` 算坐标时:
- `nodesep`/`ranksep` 太小 → block 间距挤
- 大函数 (2k+ blocks) → graphviz heuristic 撞车
- 解: 调 dot 参数 (已用 `nodesep=0.45, ranksep=0.55`); 真要根治换 ELK / dagre 重写 layout pipeline (大改, 数天工作)

### 结论

Pretext 不适合本项目. **UI 重叠问题应该用 CSS Grid 的 `min-width: 0 + text-overflow: ellipsis`**, 工作量 ~30 分钟, 配合 hover tooltip (已有 `title` 属性) 体验完整。

CFG SVG 重叠是另一回事, graphviz 限制, 暂不动 (memory 已记 5.1 OpenAPI > 5.2 MCP > 其他, CFG layout 不在 P1 范围)。

---

## 3. 跟之前讨论关联

- 第三个话题 (libart Stalker bypass) 已搁置, 等这次 1+2 收尾再开。
- 调研了 5 种方案 (A: 移 HARD_EXCL / B: Interceptor 而非 Stalker / C: CoreSight ETM / D: addCallProbe / E: Stalker主+Interceptor sidecar) — 推荐 **E (一劳永逸架构)**, 用 `capture_rules.json` 声明式驱动 Interceptor + sidecar JSON. 详见之前 chat。

---

## 总结表

| 问题 | 现象 | 根因 | 推荐修法 | 工作量 |
|---|---|---|---|---|
| 1. 虚拟滚动丢末尾 10 条 | UI 显示 #10214924, 真 #10214935 | decoupled mode `endIdx` 被 `startIdx + visible` 错限制, 而 startIdx 已被 overscan 上推 | `app.js` 改 2 行: `startIdx = baseIdx`(不上推), 顺手干净化语义 | 15 min |
| 2. UI 列重叠 | 长 SO/func 名时 trace 行内容相互覆盖 | CSS Grid 默认 `min-width: auto`, 内容撑超 cell + 没 ellipsis | `styles.css`: 加 `min-width:0 + text-overflow:ellipsis` 到 `.pc`/`.func` + 响应式 media query | 30 min |
| (Pretext) | — | Pretext 是 inline-text 库, 不是 graph 布局; 我们等宽 mono 字体不需要 | **不引入** Pretext | — |
| 3. CFG SVG 重叠 | 大函数 dot 渲染 BB 互相挤 | graphviz dot 限制 (heuristic + nodesep/ranksep) | 暂不动. 真要根治换 ELK/dagre ≥ 2 day | backlog |

---

## 行动决定

待用户确认: 现在做 1+2 (45 min, 都是简单 CSS/JS 修复), 还是先把 libart bypass 做完 (E 架构 1.5h)?
