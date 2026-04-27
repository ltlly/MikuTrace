// traceMiku web — IDA-style SPA, graphviz dot SVG CFG with per-insn click + sync.
// 设计:
//   - 后端 dot -Tsvg 出 IDA 风的 CFG, 每条 insn 是 <a xlink:href="#insn_<pc>">
//   - 前端 innerHTML 嵌入, attach 事件 + CSS 高亮 + CSS transform 拖拽缩放
//   - sync toggle: cursor↔CFG 双向联动

const $ = (id) => document.getElementById(id);
const api = (path, params = {}) => {
  const q = new URLSearchParams(params).toString();
  return fetch(path + (q ? "?" + q : "")).then(r => r.json());
};

// 默认 settings — localStorage 覆盖
const DEFAULT_SETTINGS = {
  // limits (0 = 不限)
  taintLimit: 5000,
  searchLimit: 5000,
  idxsForPcLimit: 200,
  idxsForBlockLimit: 5000,
  stringsLimit: 5000,
  stringsMinLen: 4,
  memDumpLines: 16,        // 16 行 × 16 字节
  backtraceMaxDepth: 1000,
  dotTimeout: 60,          // graphviz dot subprocess 超时秒
  // 显示格式: 'abs' = 绝对地址 0x6d6e0e4820
  //          'fnoff' = func+offset = doCommandNative+0xb0
  //          'soFnOff' = libsgmainso@func+offset
  addrFormat: 'fnoff',
};

const STATE = {
  meta: null,
  cursor: 0,
  totalRecords: 0,
  rowHeight: 18,
  pageSize: 500,
  cache: new Map(),
  cacheKeys: [],
  inflight: new Map(),
  cfg: null,
  cfgFunc: null,
  allFuncs: [],
  activeBlockPc: null,
  activeInsnPc: null,
  prevRegs: null,
  syncEnabled: true,
  cfgPan: {x: 0, y: 0, scale: 1},
  settings: loadSettings(),
};

function loadSettings() {
  try {
    const raw = localStorage.getItem("tracemiku-settings");
    if (!raw) return {...DEFAULT_SETTINGS};
    return {...DEFAULT_SETTINGS, ...JSON.parse(raw)};
  } catch { return {...DEFAULT_SETTINGS}; }
}
function saveSettings() {
  localStorage.setItem("tracemiku-settings", JSON.stringify(STATE.settings));
}

window.TM = STATE;

// ---------------- bootstrap ----------------
async function init() {
  STATE.meta = await api("/api/meta");
  STATE.totalRecords = STATE.meta.records;
  $("meta").textContent =
    `${STATE.meta.module ? STATE.meta.module.name : "?"}` +
    `  ${STATE.totalRecords.toLocaleString()} 条`;
  $("trace-info").textContent = `${STATE.totalRecords.toLocaleString()} 条`;

  buildVirtualList();
  setupVerticalTabs();
  setupBottomTabs();
  setupKeys();
  setupCmd();
  setupCfgPanZoom();
  setupSyncToggle();
  setupCfgFuncSelect();

  setCursor(0, true);

  const r0 = await api("/api/record/0");
  pollCFG(r0?.func || null);
  // 默认 funcs tab 已 active, 立即 load 一次
  TAB_INIT.funcs = true;
  loadFuncsList();
}

// ---------------- virtual list (asm stream) ----------------
function buildVirtualList() {
  const stream = $("stream");
  stream.innerHTML = "";
  const inner = document.createElement("div");
  inner.style.position = "relative";
  // 浏览器 abs 元素 max-height ~33M px (Chrome). 大 trace 超出时用 decoupled scroll
  const SAFE_MAX_H = 30_000_000;
  const wantH = STATE.totalRecords * STATE.rowHeight;
  STATE.usingDecoupledScroll = wantH > SAFE_MAX_H;
  inner.style.height = Math.min(wantH, SAFE_MAX_H) + "px";
  // 防溢出: rows abs 位置可能略超 inner.height (decoupled 边界), 用 overflow:hidden
  // 阻止溢出渲染到下方 #bottom-tabs (用户图 #18 重叠).
  inner.style.overflow = "hidden";
  inner.id = "stream-inner";
  STATE.viewportStartIdx = 0;
  stream.appendChild(inner);

  let renderTok = 0;
  stream.addEventListener("scroll", () => {
    const tok = ++renderTok;
    requestAnimationFrame(() => { if (tok === renderTok) renderViewport(); });
  });
  // 全局事件委托 — reg hover/dblclick/right-click
  inner.addEventListener("mouseover", async ev => {
    const rg = ev.target.closest(".op-reg");
    if (!rg) return;
    if (rg.dataset.title) return;
    const reg = rg.dataset.reg;
    const idx = parseInt(rg.closest(".row-insn")?.dataset?.idx);
    if (!Number.isFinite(idx)) return;
    try {
      const r = await api("/api/reg-value-at", {idx, reg});
      if (r.status === "ready") rg.title = `${reg} = ${r.value}${r.annotation || ""}`;
      rg.dataset.title = "1";
    } catch (_) {}
  });
  inner.addEventListener("dblclick", async ev => {
    const rg = ev.target.closest(".op-reg");
    if (!rg) return;
    ev.stopPropagation();
    const reg = rg.dataset.reg;
    const idx = parseInt(rg.closest(".row-insn")?.dataset?.idx);
    const r = await api("/api/last-write-of-reg", {cursor: idx, reg});
    if (r.status === "ready" && r.idx != null) setCursor(r.idx, true);
  });
  inner.addEventListener("contextmenu", async ev => {
    const rg = ev.target.closest(".op-reg");
    if (!rg) return;
    ev.preventDefault();
    const reg = rg.dataset.reg;
    const idx = parseInt(rg.closest(".row-insn")?.dataset?.idx);
    const r = await api("/api/reg-value-at", {idx, reg});
    if (r.status !== "ready") return;
    showRegContextMenu(ev.clientX, ev.clientY, reg, r.value, r.annotation, idx);
  });
  requestAnimationFrame(renderViewport);
}

function showRegContextMenu(x, y, reg, valueHex, ann, idx) {
  const old = document.getElementById("reg-ctx"); if (old) old.remove();
  const menu = document.createElement("div");
  menu.id = "reg-ctx"; menu.className = "ctx-menu";
  menu.style.left = x + "px"; menu.style.top = y + "px";
  menu.innerHTML =
    `<div class="dim" style="padding:4px 8px">${reg} = ${valueHex}${ann ? "<br>" + escapeHtml(ann) : ""}</div>` +
    `<div class="ctx-item" data-act="lastdef">⏪ jump to last write of ${reg}</div>` +
    `<div class="ctx-item" data-act="cfg-at">📊 CFG view at ${valueHex}</div>` +
    `<div class="ctx-item" data-act="mem-at">💾 Memory view at ${valueHex}</div>` +
    `<div class="ctx-item" data-act="taint-fwd">→ forward taint ${reg}</div>` +
    `<div class="ctx-item" data-act="taint-bwd">← backward taint ${reg}</div>`;
  document.body.appendChild(menu);
  const close = () => { menu.remove(); document.removeEventListener("click", close); };
  setTimeout(() => document.addEventListener("click", close), 100);
  menu.querySelectorAll(".ctx-item").forEach(el => {
    el.addEventListener("click", async ev => {
      ev.stopPropagation();
      const act = el.dataset.act;
      close();
      if (act === "lastdef") {
        const r = await api("/api/last-write-of-reg", {cursor: idx, reg});
        if (r.idx != null) setCursor(r.idx, true);
      } else if (act === "cfg-at") {
        // reg value is an address — find its block in CFG
        const r = await api("/api/block-for-pc", {pc: valueHex});
        if (r.block) {
          // 跳到该块第一次执行的 idx
          const r2 = await api("/api/idxs-for-block", {pc: r.block, max_count: 1, near: STATE.cursor});
          if (r2.idxs && r2.idxs.length > 0) setCursor(r2.idxs[0], true);
          else alert("Block not in trace yet");
        } else alert("PC not in any tracked block");
      } else if (act === "mem-at") {
        // 切到 memory tab 并 dump 该地址
        switchBottomTab("memory");
        const inp = $("mem-addr");
        if (inp) { inp.value = valueHex; refreshMemDump(); }
      } else if (act === "taint-fwd" || act === "taint-bwd") {
        document.querySelector('[data-vtab="taint"]').click();
        await new Promise(r => setTimeout(r, 100));
        const ri = $("taint-reg");
        if (ri) ri.value = reg;
        if (act === "taint-fwd") $("taint-fwd").click();
        else $("taint-bwd").click();
      }
    });
  });
}

function viewportIdxRange() {
  const stream = $("stream");
  const inner = $("stream-inner");
  const innerH = inner.offsetHeight || parseInt(inner.style.height);
  const viewH = stream.clientHeight;
  const scrollPos = stream.scrollTop;
  const overscan = 10;
  let startIdx, endIdx;
  if (STATE.usingDecoupledScroll) {
    const visible = Math.ceil(viewH / STATE.rowHeight);
    const scrollMax = Math.max(1, innerH - viewH);
    const pct = Math.min(1, scrollPos / scrollMax);
    const baseIdx = Math.floor(pct * Math.max(0, STATE.totalRecords - visible));
    startIdx = Math.max(0, baseIdx - overscan);
    endIdx = Math.min(STATE.totalRecords, baseIdx + visible + overscan);
    // 限制 endIdx 让所有 row top + rowHeight ≤ inner.height — 否则末尾行
    // 渲染到 inner 之外, overflow 到 #bottom-tabs (用户图 #18 重叠).
    // top(i) = scrollPos + (i - startIdx) * rowHeight, 要求 ≤ innerH - rowHeight
    const maxRowsBelowScroll = Math.floor((innerH - scrollPos) / STATE.rowHeight);
    endIdx = Math.min(endIdx, startIdx + maxRowsBelowScroll);
  } else {
    startIdx = Math.max(0, Math.floor(scrollPos / STATE.rowHeight) - overscan);
    endIdx = Math.min(STATE.totalRecords,
                      Math.ceil((scrollPos + viewH) / STATE.rowHeight) + overscan);
  }
  return [startIdx, endIdx];
}

function renderViewport() {
  const stream = $("stream");
  const inner = $("stream-inner");
  const [startIdx, endIdx] = viewportIdxRange();
  // decoupled 模式: 重置每次的 viewportStartIdx, 行 top 重新计算
  STATE.viewportStartIdx = startIdx;

  // 清掉视口外的行
  inner.querySelectorAll(".row-insn").forEach(el => {
    const i = parseInt(el.dataset.idx);
    if (i < startIdx || i >= endIdx) el.remove();
  });
  // decoupled 模式下: 重置剩余行的 top (因为 scrollPos 改了)
  if (STATE.usingDecoupledScroll) {
    inner.querySelectorAll(".row-insn").forEach(el => {
      const i = parseInt(el.dataset.idx);
      el.style.top = rowTopPx(i) + "px";
    });
  }
  const present = new Set([...inner.querySelectorAll(".row-insn")]
                          .map(e => parseInt(e.dataset.idx)));

  for (let i = startIdx; i < endIdx; i++) {
    if (present.has(i)) continue;
    const winStart = Math.floor(i / STATE.pageSize) * STATE.pageSize;
    const win = STATE.cache.get(winStart);
    if (!win) continue;
    const r = win[i - winStart];
    if (!r) continue;
    inner.appendChild(buildRow(i, r));
  }

  // async 拉缺失 windows
  const need = new Set();
  for (let i = startIdx; i < endIdx; i++) {
    const winStart = Math.floor(i / STATE.pageSize) * STATE.pageSize;
    if (!STATE.cache.has(winStart) && !STATE.inflight.has(winStart))
      need.add(winStart);
  }
  for (const s of need) {
    const p = api("/api/records", {start: s, count: STATE.pageSize})
      .then(r => {
        STATE.cache.set(s, r.records);
        STATE.cacheKeys.push(s);
        if (STATE.cacheKeys.length > 100) {
          const old = STATE.cacheKeys.shift();
          STATE.cache.delete(old);
        }
        STATE.inflight.delete(s);
        // re-check viewport, 用户可能已滚走
        const [sIdx, eIdx] = viewportIdxRange();
        STATE.viewportStartIdx = sIdx;
        const cur = new Set([...inner.querySelectorAll(".row-insn")]
                            .map(e => parseInt(e.dataset.idx)));
        for (let i = Math.max(s, sIdx); i < Math.min(s + STATE.pageSize, eIdx); i++) {
          if (cur.has(i)) continue;
          const rec = r.records[i - s];
          if (!rec) continue;
          inner.appendChild(buildRow(i, rec));
        }
      })
      .catch(_ => { STATE.inflight.delete(s); });
    STATE.inflight.set(s, p);
  }
}

// PDF p.2 风格的"指令执行计数圆点": 颜色按 exec_count 分级
// 1 灰, 2-9 蓝, 10-99 绿, 100-999 黄, 1000+ 橙红
function execCountClass(c) {
  if (c == null) return "ec-unknown";
  if (c <= 1) return "ec-1";
  if (c <= 9) return "ec-low";
  if (c <= 99) return "ec-mid";
  if (c <= 999) return "ec-high";
  return "ec-vhigh";
}

// 格式化主 PC 列 (依 settings.addrFormat).
// rec: 当前 trace record 的 dict (含 pc, rel, func, off)
function formatPc(rec) {
  const fmt = STATE.settings.addrFormat;
  const so = STATE.meta?.module?.name || "";
  const fn = rec.func; const off = rec.off;
  if (fmt === "fnoff" && fn) return `${fn}+${off}`;
  if (fmt === "soFnOff" && fn) return so ? `${so}@${fn}+${off}` : `${fn}+${off}`;
  // 默认 / fallback: 绝对
  return rec.pc;
}

function buildRow(i, r) {
  const row = document.createElement("div");
  row.className = "row-insn";
  // 当 addrFormat 是 fn-based, PC 列已含 func — 加 fmt-fn class 隐藏 func 列, 避免重复
  if (STATE.settings.addrFormat === "fnoff" || STATE.settings.addrFormat === "soFnOff")
    row.classList.add("fmt-fn");
  if (r.is_call)   row.classList.add("is-call");
  if (r.is_ret)    row.classList.add("is-ret");
  if (r.is_branch && !r.is_call && !r.is_ret) row.classList.add("is-branch");
  if (i === STATE.cursor) row.classList.add("active");
  row.dataset.idx = i;
  row.dataset.pc = r.pc;
  row.style.position = "absolute";
  row.style.top = rowTopPx(i) + "px";
  row.style.left = 0; row.style.right = 0;
  row.style.height = STATE.rowHeight + "px";
  const ecCls = execCountClass(r.exec_count);
  const ecTitle = r.exec_count != null ? `executed ×${r.exec_count}` : "";
  const annHtml = r.annotation ? `<span class="ann">; ${escapeHtml(r.annotation)}</span>` : "";
  const pcFmt = formatPc(r);
  row.innerHTML =
    `<span class="ec ${ecCls}" title="${ecTitle}"></span>` +
    `<span class="idx">#${r.idx}</span>` +
    `<span class="pc" title="${r.pc}">${escapeHtml(pcFmt)}</span>` +
    `<span class="func">${r.func ? r.func + "+" + r.off : (r.rel || r.pc)}</span>` +
    `<span class="asm">${highlightRegs(r.asm)}${annHtml ? "  " + annHtml : ""}</span>`;
  row.addEventListener("click", () => setCursor(i, false));
  return row;
}

// 浏览器单 div 高度上限 ~33M px → 大 trace 用 decoupled scroll: scrollbar 位置
// 只表 percentage, 实际 row 位置由 (idx - startIdx)*rowHeight + scrollPos 算.
function rowTopPx(idx) {
  if (STATE.usingDecoupledScroll) {
    const stream = $("stream");
    return (stream.scrollTop || 0) + (idx - STATE.viewportStartIdx) * STATE.rowHeight;
  }
  return idx * STATE.rowHeight;
}

// 把 ASM 中的寄存器名 (x0..x30, w0..w30, sp, fp, lr, pc) 包成 <span class="op-reg">
const REG_RE = /\b(x([12]?\d|3[01])|w([12]?\d|3[01])|sp|fp|lr|pc|xzr|wzr)\b/gi;
function highlightRegs(asm) {
  // escape first, then replace; using a marker to avoid double-escape
  const safe = escapeHtml(asm);
  return safe.replace(REG_RE, (m) => {
    return `<span class="op-reg" data-reg="${normalizeReg(m)}">${m}</span>`;
  });
}
function normalizeReg(name) {
  const lc = name.toLowerCase();
  if (lc.startsWith("w") && lc.length > 1 && /\d/.test(lc[1])) return "x" + lc.substring(1);
  if (lc === "wzr") return "xzr";
  return lc;
}

function escapeHtml(s) {
  return s.replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
}

// Event-delegated row click → setCursor. 替代 querySelectorAll().forEach(addEventListener)
// 对每个 row 一个 listener — 5000 行 taint result 时省 5000 个 listener.
// 同 container 重复调用安全 (用 _delegatedRowClick flag 去重).
function bindRowClicks(container, selector = ".lp-row") {
  if (!container || container._delegatedRowClick === selector) return;
  container._delegatedRowClick = selector;
  container.addEventListener("click", (e) => {
    const row = e.target.closest(selector);
    if (!row) return;
    const idx = row.dataset.idx;
    if (idx != null && idx !== "") setCursor(parseInt(idx), true);
  });
}

// ---------------- cursor + sync ----------------
let _cursorDebounce = null;
function setCursor(idx, scrollIntoView = false) {
  if (idx < 0) idx = 0;
  if (idx >= STATE.totalRecords) idx = STATE.totalRecords - 1;
  STATE.cursor = idx;
  document.querySelectorAll(".row-insn.active").forEach(e => e.classList.remove("active"));
  const el = document.querySelector(`.row-insn[data-idx="${idx}"]`);
  if (el) el.classList.add("active");
  if (scrollIntoView) {
    const stream = $("stream");
    const inner = $("stream-inner");
    if (STATE.usingDecoupledScroll) {
      // 用 percentage 映射: 把 scrollTop 设到 idx 对应的 % 位置
      const innerH = inner.offsetHeight || parseInt(inner.style.height);
      const viewH = stream.clientHeight;
      const visible = Math.ceil(viewH / STATE.rowHeight);
      const scrollMax = Math.max(1, innerH - viewH);
      const pct = (idx - visible/2) / Math.max(1, STATE.totalRecords - visible);
      stream.scrollTop = Math.max(0, Math.min(scrollMax, pct * scrollMax));
    } else {
      const target = idx * STATE.rowHeight;
      if (target < stream.scrollTop || target > stream.scrollTop + stream.clientHeight - STATE.rowHeight*2) {
        stream.scrollTop = Math.max(0, target - stream.clientHeight / 2);
      }
    }
  }
  $("status").textContent = `#${idx}`;
  // 通知订阅者 (e.g. taint-from text)
  if (STATE._onCursorChange) for (const f of STATE._onCursorChange) try { f(); } catch(_){}
  if (_cursorDebounce) clearTimeout(_cursorDebounce);
  _cursorDebounce = setTimeout(async () => {
    const cur = STATE.cursor;
    if (cur !== idx) return;
    const r = await api("/api/record/" + cur);
    if (STATE.cursor !== cur) return;
    renderRegs(r);
    if (r.func && STATE.syncEnabled) maybeSwitchCfgFunc(r.func);
    if (STATE.syncEnabled) highlightCfgInsn(r.pc);
    $("status").textContent = `#${cur}  ${r.pc}  ${r.asm}`;
  }, 60);
}

function renderRegs(r) {
  const cont = $("regs-pane");
  const regs = r.regs || {};
  const prev = r.prev_regs || {};
  const ann = r.regs_annotated || {};
  // pwndbg 风: 单列宽 — name | hex | annotation. 改成 1-col flow 不再 2-col grid.
  const order = ["x0","x1","x2","x3","x4","x5","x6","x7",
                 "x8","x9","x10","x11","x12","x13","x14","x15",
                 "x16","x17","x18","x19","x20","x21","x22","x23",
                 "x24","x25","x26","x27","x28","fp","lr","sp","pc"];
  let html = '<div class="regs-list">';
  for (const nm of order) {
    if (!(nm in regs)) continue;
    const changed = prev[nm] !== undefined && prev[nm] !== regs[nm];
    const cls = changed ? "reg changed" : "reg";
    const a = ann[nm] || "";
    html += `<div class="${cls}">` +
            `<span class="rn">${nm}</span>` +
            `<span class="rv">${regs[nm]}</span>` +
            `<span class="ra">${escapeHtml(a)}</span>` +
            `</div>`;
  }
  html += "</div>";
  cont.innerHTML = html;
}

// ---------------- CFG (graphviz SVG) ----------------
async function pollCFG(fn = null) {
  $("cfg-info").textContent = fn ? `loading ${fn}…` : "loading…";
  const sel0 = $("cfg-func-select");
  if (sel0) sel0.value = fn || "";
  let tries = 0;
  while (true) {
    const params = {timeout: STATE.settings.dotTimeout || 60};
    if (fn) params.fn = fn;
    const r = await api("/api/cfg-svg", params);
    if (r.status === "ready") {
      STATE.cfgFunc = fn;
      embedCfgSvg(r);
      // 再次 sync (option 此时确保 populated)
      const sel = $("cfg-func-select");
      if (sel) sel.value = STATE.cfgFunc || "";
      const rec = await api("/api/record/" + STATE.cursor);
      if (STATE.syncEnabled) highlightCfgInsn(rec.pc);
      return;
    }
    if (r.status === "empty") {
      $("cfg-info").textContent = `(no blocks for ${fn})`;
      $("cfg-canvas").innerHTML = "";
      return;
    }
    if (r.status === "error") {
      $("cfg-info").textContent = "error: " + (r.err || "?");
      return;
    }
    tries++;
    $("cfg-info").textContent = `building… cfg=${r.cfg} pc_inst=${r.pc_inst}`;
    await new Promise(res => setTimeout(res, tries < 5 ? 500 : 2000));
  }
}

function embedCfgSvg(r) {
  const fn = STATE.cfgFunc || "all funcs";
  $("cfg-info").textContent = `${r.block_count}/${r.total_block_count} blocks · ${fn}`;
  const canvas = $("cfg-canvas");
  canvas.innerHTML = r.svg;
  const svg = canvas.querySelector("svg");
  if (!svg) return;
  // 显式设 SVG 尺寸 = viewBox 大小, 让 canvas div 有正确 layout 尺寸,
  // CSS transform: scale() 才能正常缩放
  const vb = (svg.getAttribute("viewBox") || "").split(/\s+/).map(parseFloat);
  if (vb.length === 4) {
    svg.setAttribute("width", String(vb[2]));
    svg.setAttribute("height", String(vb[3]));
  }
  svg.style.display = "block";
  // 装钩子: 每条 insn 是 <a xlink:href="#insn_<pc>">
  canvas.querySelectorAll("a").forEach(a => {
    const href = a.getAttribute("xlink:href") || a.getAttribute("href") || "";
    a.removeAttribute("href");           // 防止 default navigate
    a.removeAttribute("xlink:href");
    a.setAttribute("data-href", href);
    a.style.cursor = "pointer";
    a.addEventListener("click", (e) => {
      e.preventDefault(); e.stopPropagation();
      onCfgInsnClick(href, a);
    });
  });
  // 自适应 fit 一次
  fitCfg();
}

function fitCfg() {
  // 一般 CFG 是"窄而高" (基本块按列堆叠), 全 fit 让字小到看不清.
  // 默认: scale 按宽度 fit (≤1.0), 高度由 wrap 滚动条承载.
  // 顶端居中显示第一行.
  const wrap = $("cfg-canvas-wrap");
  const canvas = $("cfg-canvas");
  const svg = canvas.querySelector("svg");
  if (!svg) return;
  const bb = svg.getBBox();
  const W = wrap.clientWidth;
  if (bb.width > 0) {
    const sx = (W - 40) / bb.width;
    const s = Math.min(Math.max(sx, 0.3), 1.0);
    STATE.cfgPan = {x: 20, y: 20, scale: s};
  } else {
    STATE.cfgPan = {x: 0, y: 0, scale: 1};
  }
  applyCfgTransform();
}

function applyCfgTransform() {
  const c = $("cfg-canvas");
  const p = STATE.cfgPan;
  c.style.transform = `translate(${p.x}px, ${p.y}px) scale(${p.scale})`;
}

function setupCfgPanZoom() {
  const wrap = $("cfg-canvas-wrap");
  let dragging = false; let lastX = 0; let lastY = 0;
  wrap.addEventListener("mousedown", (e) => {
    if (e.target.closest("a[data-href]")) return; // click on insn — 不拖
    dragging = true; lastX = e.clientX; lastY = e.clientY;
    wrap.classList.add("dragging");
  });
  window.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    STATE.cfgPan.x += (e.clientX - lastX);
    STATE.cfgPan.y += (e.clientY - lastY);
    lastX = e.clientX; lastY = e.clientY;
    applyCfgTransform();
  });
  window.addEventListener("mouseup", () => { dragging = false; wrap.classList.remove("dragging"); });
  wrap.addEventListener("wheel", (e) => {
    e.preventDefault();
    if (e.ctrlKey || e.metaKey) {
      // ctrl + wheel = zoom (around cursor) — IDA 同款
      const rect = wrap.getBoundingClientRect();
      const mx = e.clientX - rect.left, my = e.clientY - rect.top;
      const dz = e.deltaY < 0 ? 1.1 : 0.9;
      const old = STATE.cfgPan.scale;
      const sNew = Math.max(0.05, Math.min(5, old * dz));
      STATE.cfgPan.x = mx - (mx - STATE.cfgPan.x) * (sNew / old);
      STATE.cfgPan.y = my - (my - STATE.cfgPan.y) * (sNew / old);
      STATE.cfgPan.scale = sNew;
    } else {
      // 无修饰键 wheel = 垂直滚动 (shift+wheel = 水平)
      if (e.shiftKey) STATE.cfgPan.x -= e.deltaY;
      else            STATE.cfgPan.y -= e.deltaY;
    }
    applyCfgTransform();
  }, {passive: false});
  $("btn-fit").onclick = fitCfg;
  $("btn-reload-cfg").onclick = () => pollCFG(STATE.cfgFunc);
}

function highlightCfgInsn(pcHex) {
  const canvas = $("cfg-canvas");
  if (!canvas) return;
  // remove old
  canvas.querySelectorAll("a.cursor-pc").forEach(a => a.classList.remove("cursor-pc"));
  if (!pcHex) return;
  const target = "#insn_" + pcHex.replace(/^0x/, "");
  // attribute-based selector via data-href
  const els = canvas.querySelectorAll(`a[data-href="${target}"]`);
  if (els.length === 0) return;
  els.forEach(a => a.classList.add("cursor-pc"));
  // pan to bring it into view if off-screen
  const wrap = $("cfg-canvas-wrap");
  const rect = els[0].getBoundingClientRect();
  const wrapRect = wrap.getBoundingClientRect();
  const margin = 60;
  if (rect.top < wrapRect.top + margin || rect.bottom > wrapRect.bottom - margin ||
      rect.left < wrapRect.left + margin || rect.right > wrapRect.right - margin) {
    // center
    const center_x_in_wrap = wrapRect.width / 2;
    const center_y_in_wrap = wrapRect.height / 2;
    const elem_x = rect.left - wrapRect.left + rect.width / 2;
    const elem_y = rect.top - wrapRect.top + rect.height / 2;
    STATE.cfgPan.x += (center_x_in_wrap - elem_x);
    STATE.cfgPan.y += (center_y_in_wrap - elem_y);
    applyCfgTransform();
  }
}

async function onCfgInsnClick(href, _aEl) {
  // href = "#insn_<pchex>" 或 "#hdr_b<pchex>" 或 "#ext_..."
  if (href.startsWith("#insn_")) {
    const pcHex = "0x" + href.substring(6);
    STATE.activeInsnPc = pcHex;
    showTraceForPc(pcHex);
    if (STATE.syncEnabled) {
      // 跳到离当前 cursor 最近的 trace idx
      const r = await api("/api/idxs-for-pc",
                          {pc: pcHex, cursor: STATE.cursor, limit: 1});
      const cands = [];
      if (r.before && r.before.length) cands.push(r.before[0]);
      if (r.after && r.after.length) cands.push(r.after[0]);
      if (cands.length) {
        const nearest = cands.reduce((a, b) =>
          Math.abs(a - STATE.cursor) < Math.abs(b - STATE.cursor) ? a : b);
        setCursor(nearest, true);
      }
    }
  } else if (href.startsWith("#hdr_b")) {
    const pcHex = "0x" + href.substring(6);
    STATE.activeInsnPc = pcHex;
    if (STATE.syncEnabled) {
      const r = await api("/api/idxs-for-block",
                          {pc: pcHex, max_count: 1, near: STATE.cursor});
      if (r.idxs && r.idxs.length > 0) setCursor(r.idxs[0], true);
    }
  }
}

async function showTraceForPc(pcHex) {
  switchBottomTab("trace-for-pc");
  const cont = $("b-trace-for-pc");
  cont.innerHTML = `<div class="dim">loading ${pcHex}…</div>`;
  const r = await api("/api/idxs-for-pc",
                      {pc: pcHex, cursor: STATE.cursor,
                       limit: STATE.settings.idxsForPcLimit || 30});
  const afterMore = r.after_capped ? "+" : "";
  const beforeMore = r.before_capped ? "+" : "";
  let html = `<div class="tfp-section"><h4>${pcHex}</h4>`;
  html += `<div class="dim">cursor=#${STATE.cursor} · ` +
          `${r.before.length}${beforeMore} before · ${r.after.length}${afterMore} after ` +
          `(扫到 limit 即停, 增大 limit 看更多)</div></div>`;
  html += `<div class="tfp-section"><h4>↓ AFTER cursor (${r.after.length}${afterMore})</h4>`;
  for (const i of r.after) {
    const delta = i - STATE.cursor;
    html += `<div class="tfp-row" data-idx="${i}">` +
            `<span class="delta">+${delta}</span>` +
            `<span class="pc">#${i}</span>` +
            `<span></span></div>`;
  }
  if (r.after.length === 0) html += `<div class="dim">none</div>`;
  html += `</div><div class="tfp-section"><h4>↑ BEFORE cursor (${r.before.length}${beforeMore})</h4>`;
  for (const i of r.before) {
    const delta = STATE.cursor - i;
    html += `<div class="tfp-row" data-idx="${i}">` +
            `<span class="delta">-${delta}</span>` +
            `<span class="pc">#${i}</span>` +
            `<span></span></div>`;
  }
  if (r.before.length === 0) html += `<div class="dim">none</div>`;
  html += `</div>`;
  cont.innerHTML = html;
  cont.querySelectorAll(".tfp-row").forEach(el => {
    el.addEventListener("click", () => {
      setCursor(parseInt(el.dataset.idx), true);
    });
  });
}

async function maybeSwitchCfgFunc(newFunc) {
  if (newFunc === STATE.cfgFunc) return;
  if (!newFunc) return;
  if (STATE.cfgFunc === null) return;  // user is in all-funcs mode
  await pollCFG(newFunc);
}

// ---------------- left vertical tabs ----------------
function setupVerticalTabs() {
  document.querySelectorAll("#left-tabs .vtab").forEach(t => {
    t.addEventListener("click", () => activateLeftTab(t.dataset.vtab));
  });
  document.querySelectorAll("#right-tabs .vtab").forEach(t => {
    t.addEventListener("click", () => activateRightTab(t.dataset.rtab));
  });
}
// 每个 tab 的 DOM 永久保留, 只切显示/隐藏 (不再每次切都重新 fetch+渲染).
// 第一次访问时 init, 后续切回直接 show.
const TAB_INIT = {};
function activateLeftTab(name) {
  document.querySelectorAll("#left-tabs .vtab").forEach(t =>
    t.classList.toggle("active", t.dataset.vtab === name));
  $("left-panel-title").textContent =
    {funcs: "Functions", back: "Backtrace", strings: "Strings",
     taint: "Taint", xref: "Cross Reference", settings: "Settings"}[name] || name;
  // 切换显示/隐藏对应 panel
  document.querySelectorAll("#left-panel-body > .lp-tab").forEach(b =>
    b.classList.toggle("active", b.dataset.tab === name));
  // 第一次进入才 init
  if (!TAB_INIT[name]) {
    TAB_INIT[name] = true;
    if (name === "funcs") loadFuncsList();
    else if (name === "strings") loadStrings();
    else if (name === "taint") initTaintTab();
    else if (name === "xref") initXrefTab();
    else if (name === "back") initBacktraceTab();
    else if (name === "settings") initSettingsTab();
  }
  // 切到 backtrace 时刷一下当前 cursor 的 stack
  if (name === "back") refreshBacktrace();
}

// ---------------- Backtrace ----------------
function initBacktraceTab() {
  $("lp-back").innerHTML = '<div class="dim">loading backtrace…</div>';
  STATE._onCursorChange = STATE._onCursorChange || [];
  STATE._onCursorChange.push(refreshBacktrace);
}
async function refreshBacktrace() {
  const cont = $("lp-back");
  if (!cont) return;
  // 仅当 backtrace tab 已 active 时才 update DOM (省带宽)
  if (!cont.classList.contains("active")) return;
  if (STATE._btAbort) try { STATE._btAbort.abort(); } catch(_){}
  const ctrl = new AbortController();
  STATE._btAbort = ctrl;
  try {
    const url = "/api/backtrace?idx=" + STATE.cursor;
    const resp = await fetch(url, {signal: ctrl.signal});
    const r = await resp.json();
    if (ctrl.signal.aborted) return;
    if (r.status !== "ready") {
      cont.innerHTML = `<div class="dim">building call stack… (${r.status})</div>`;
      setTimeout(() => { if (STATE._btAbort === ctrl) refreshBacktrace(); }, 1000);
      return;
    }
    let html = `<div class="dim">cursor #${STATE.cursor} · depth ${r.depth}</div>`;
    if (r.stack.length === 0) {
      html += `<div class="dim">(top of stack)</div>`;
    } else {
      for (let i = r.stack.length - 1; i >= 0; i--) {
        const f = r.stack[i];
        const fname = f.fn || "?";
        // 用 _fmt 后端格式化的相对地址 (用户图 #13 抱怨绝对地址)
        const callSite = f.call_pc_fmt || f.call_pc;
        html += `<div class="lp-row" data-idx="${f.call_site_idx}">` +
                `<span>${escapeHtml(fname)} ← ${escapeHtml(callSite)}</span>` +
                `<span class="meta">#${f.call_site_idx}</span></div>`;
      }
    }
    cont.innerHTML = html;
    bindRowClicks(cont);
  } catch (e) {
    if (e.name !== "AbortError") cont.innerHTML = `<div class="dim">err: ${e.message || e}</div>`;
  } finally {
    if (STATE._btAbort === ctrl) STATE._btAbort = null;
  }
}
function activateRightTab(name) {
  document.querySelectorAll("#right-tabs .vtab").forEach(t =>
    t.classList.toggle("active", t.dataset.rtab === name));
  document.querySelectorAll("#right-body .rbody").forEach(b =>
    b.classList.toggle("active", b.id === name + "-pane"));
  $("right-tab-title").textContent = {cfg: "Graph", regs: "Registers"}[name];
}

// ---------------- bottom tabs ----------------
function setupBottomTabs() {
  document.querySelectorAll(".btab").forEach(t => {
    t.addEventListener("click", () => switchBottomTab(t.dataset.btab));
  });
  // Memory tab: 输入地址或寄存器名 (sp/x0 etc) 显示 hex dump.
  $("b-memory").innerHTML = `
    <div style="display:flex;gap:6px;align-items:center;padding:4px 8px;border-bottom:1px solid var(--border)">
      <span class="dim">addr:</span>
      <input id="mem-addr" class="inp" value="sp" size="20"
             placeholder="0x... 或 sp/x0/...">
      <button class="btn" id="mem-go">go</button>
      <span class="dim" id="mem-info"></span>
    </div>
    <div id="mem-content" style="padding:6px 8px;font-family:monospace;font-size:11px;line-height:16px"></div>`;
  $("mem-go").addEventListener("click", refreshMemDump);
  $("mem-addr").addEventListener("keydown", e => { if (e.key === "Enter") refreshMemDump(); });
  // cursor 变化时如果 mem-addr 是寄存器, 自动 refresh
  STATE._onCursorChange = STATE._onCursorChange || [];
  STATE._onCursorChange.push(() => {
    const a = $("mem-addr")?.value;
    if (a && /^(x\d+|sp|fp|lr|pc)$/i.test(a.trim())) refreshMemDump();
  });
}

async function refreshMemDump() {
  const inp = $("mem-addr");
  if (!inp) return;
  const cont = $("mem-content");
  let raw = inp.value.trim();
  let addr = null;
  if (/^(x\d+|sp|fp|lr|pc)$/i.test(raw)) {
    // resolve 寄存器 → 当前 cursor 的值
    const r = await api("/api/record/" + STATE.cursor);
    addr = r.regs?.[raw.toLowerCase()];
    if (!addr) { cont.innerHTML = `<div class="dim">reg ${raw} unknown</div>`; return; }
  } else if (/^0x[0-9a-f]+$/i.test(raw)) {
    addr = raw;
  } else {
    cont.innerHTML = '<div class="dim">输入 0x... 或 寄存器名</div>'; return;
  }
  cont.innerHTML = '<div class="dim">loading…</div>';
  const lines = STATE.settings.memDumpLines || 16;
  const r = await api("/api/mem-dump", {addr, count: lines * 16});
  if (r.status !== "ready") {
    cont.innerHTML = `<div class="dim">building memshadow… (${r.status})</div>`;
    return;
  }
  $("mem-info").textContent = `dump from ${addr}`;
  // 16 bytes per line — ascii 列分 char 一个 span (不再字符串拼 HTML 后 escapeHtml,
  // 那会把 <span> 转成文本显示)
  let html = "";
  for (let line = 0; line < lines; line++) {
    const lineAddr = "0x" + (BigInt(addr) + BigInt(line * 16)).toString(16);
    let hex = "", ascii = "";
    for (let col = 0; col < 16; col++) {
      const idx = line * 16 + col;
      const b = r.bytes[idx];
      if (b == null || b.byte == null) {
        hex += `<span class="b-unread">??</span> `;
        ascii += `<span class="b-unread">·</span>`;
      } else {
        const cls = b.kind === "w" ? "b-write" : "b-read";
        hex += `<span class="${cls}" data-addr="${b.addr}" title="from #${b.src_idx} (${b.kind})">${b.byte.toString(16).padStart(2,'0')}</span> `;
        const ch = b.byte;
        const cc = (ch >= 0x20 && ch < 0x7f) ? String.fromCharCode(ch) : "·";
        ascii += `<span class="${cls}">${escapeHtml(cc)}</span>`;
      }
    }
    html += `<div class="mem-line">` +
            `<span class="addr">${lineAddr}</span>` +
            `<span class="hex">${hex}</span>` +
            `<span class="ascii">${ascii}</span></div>`;
  }
  cont.innerHTML = html;
  // 双击单字节 → 跳到第一次 write
  cont.querySelectorAll("[data-addr]").forEach(span => {
    span.addEventListener("dblclick", () => {
      jumpToFirstWriteOfAddr(span.dataset.addr);
    });
  });
  // 选择 + 右键: 拖动鼠标选 N 个字节, 右键 contextmenu 弹列表
  setupMemSelection(cont);
}

function setupMemSelection(cont) {
  let dragStart = null, dragEnd = null;
  const mark = () => {
    cont.querySelectorAll(".sel").forEach(e => e.classList.remove("sel"));
    if (dragStart === null || dragEnd === null) return;
    const [lo, hi] = dragStart < dragEnd ? [dragStart, dragEnd] : [dragEnd, dragStart];
    const cells = [...cont.querySelectorAll("[data-addr]")];
    for (const c of cells) {
      const a = BigInt(c.dataset.addr);
      if (a >= BigInt("0x" + lo.toString(16)) && a <= BigInt("0x" + hi.toString(16)))
        c.classList.add("sel");
    }
  };
  cont.addEventListener("mousedown", e => {
    if (e.button !== 0) return;
    const t = e.target.closest("[data-addr]");
    if (!t) { dragStart = dragEnd = null; mark(); return; }
    dragStart = parseInt(t.dataset.addr, 16);
    dragEnd = dragStart;
    mark();
    e.preventDefault();
  });
  cont.addEventListener("mousemove", e => {
    if (dragStart === null) return;
    if (e.buttons !== 1) return;
    const t = e.target.closest("[data-addr]");
    if (!t) return;
    dragEnd = parseInt(t.dataset.addr, 16);
    mark();
  });
  cont.addEventListener("contextmenu", async e => {
    e.preventDefault();
    let lo, hi;
    if (dragStart !== null && dragEnd !== null) {
      [lo, hi] = dragStart < dragEnd ? [dragStart, dragEnd] : [dragEnd, dragStart];
    } else {
      const t = e.target.closest("[data-addr]");
      if (!t) return;
      lo = hi = parseInt(t.dataset.addr, 16);
    }
    showMemContextMenu(e.clientX, e.clientY, lo, hi - lo + 1);
  });
}

async function showMemContextMenu(x, y, addr, size) {
  // 打掉旧 menu
  const old = document.getElementById("mem-ctx"); if (old) old.remove();
  const menu = document.createElement("div");
  menu.id = "mem-ctx"; menu.className = "ctx-menu";
  menu.style.left = x + "px"; menu.style.top = y + "px";
  menu.innerHTML = `<div class="dim" style="padding:4px 8px">addr=${"0x"+addr.toString(16)} size=${size}</div>` +
    `<div class="ctx-loading dim" style="padding:4px 8px">scanning…</div>`;
  document.body.appendChild(menu);
  // 关闭逻辑
  const close = () => { menu.remove(); document.removeEventListener("click", close); };
  setTimeout(() => document.addEventListener("click", close), 100);
  // fetch
  const r = await api("/api/idxs-touching-range",
    {addr: "0x" + addr.toString(16), size, cursor: STATE.cursor, limit: 30});
  if (r.status !== "ready") {
    menu.querySelector(".ctx-loading").textContent = "(building memshadow)";
    return;
  }
  let html = `<div class="dim" style="padding:4px 8px">addr=${"0x"+addr.toString(16)} size=${size} · cursor #${STATE.cursor}</div>`;
  html += `<div class="ctx-section">writers (${r.writers_total})</div>`;
  if (r.writers_before.length === 0 && r.writers_after.length === 0)
    html += `<div class="dim" style="padding:2px 12px">none</div>`;
  for (const i of [...r.writers_before, ...r.writers_after])
    html += `<div class="ctx-item" data-idx="${i}">→ #${i}</div>`;
  html += `<div class="ctx-section">readers (${r.readers_total})</div>`;
  if (r.readers_before.length === 0 && r.readers_after.length === 0)
    html += `<div class="dim" style="padding:2px 12px">none</div>`;
  for (const i of [...r.readers_before, ...r.readers_after])
    html += `<div class="ctx-item" data-idx="${i}">→ #${i}</div>`;
  menu.innerHTML = html;
  menu.querySelectorAll(".ctx-item").forEach(el => {
    el.addEventListener("click", ev => {
      ev.stopPropagation();
      setCursor(parseInt(el.dataset.idx), true);
      close();
    });
  });
}
function switchBottomTab(name) {
  document.querySelectorAll(".btab").forEach(t =>
    t.classList.toggle("active", t.dataset.btab === name));
  document.querySelectorAll(".bbody").forEach(b =>
    b.classList.toggle("active", b.id === "b-" + name));
}

// ---------------- left panel: Functions list (一次加载, 永久挂载) ----------------
async function loadFuncsList() {
  const cont = $("lp-funcs");
  cont.innerHTML = '<div class="dim">loading…</div>';
  // 等 cfg subprocess 给 funcs 列表
  while (true) {
    const cfg = await api("/api/cfg", {});
    if (cfg.status === "ready") {
      STATE.allFuncs = cfg.funcs || [];
      break;
    }
    if (cfg.status === "building") {
      cont.innerHTML = `<div class="dim">cfg building… (${cfg.cfg})</div>`;
      await new Promise(res => setTimeout(res, 1500));
      continue;
    }
    cont.innerHTML = `<div class="dim">cfg ${cfg.status}</div>`;
    return;
  }
  let html = "";
  for (const f of STATE.allFuncs) {
    const active = f.name === STATE.cfgFunc ? " active" : "";
    html += `<div class="lp-row${active}" data-fn="${escapeHtml(f.name)}">` +
            `<span>${escapeHtml(f.name)}</span>` +
            `<span class="meta">${f.blocks} bb</span></div>`;
  }
  cont.innerHTML = html || '<div class="dim">no funcs</div>';
  cont.querySelectorAll(".lp-row").forEach(r => {
    r.addEventListener("click", () => {
      pollCFG(r.dataset.fn);
      cont.querySelectorAll(".lp-row").forEach(o => o.classList.toggle("active", o === r));
    });
  });
  $("left-panel-info").textContent = `${STATE.allFuncs.length}`;
}

async function loadStrings() {
  const cont = $("lp-strings");
  cont.innerHTML = '<div class="dim">building memshadow… (一次性)</div>';
  while (true) {
    const opts = {min_len: STATE.settings.stringsMinLen,
                  limit: STATE.settings.stringsLimit};
    const r = await api("/api/strings", opts);
    if (r.status === "ready") {
      cont.innerHTML =
        '<input class="inp" id="strings-filter" placeholder="search strings…" style="width:100%;margin-bottom:4px">' +
        '<div id="strings-info" class="dim"></div>' +
        '<div id="strings-list"></div>';
      const filterInp = $("strings-filter");
      const listEl = $("strings-list");
      const infoEl = $("strings-info");
      // 把 "at-cursor" 选项加进 panel
      const cont2 = $("lp-strings");
      // 在已有结构上插一行 toggle
      if (!cont2.querySelector(".strings-cursor-toggle")) {
        const tog = document.createElement("label");
        tog.className = "strings-cursor-toggle";
        tog.innerHTML = `<input type="checkbox" id="strings-at-cursor"> 仅 cursor 时刻已构造的`;
        tog.style.fontSize = "11px"; tog.style.cursor = "pointer";
        cont2.insertBefore(tog, cont2.querySelector("#strings-info"));
      }
      const cursorTog = $("strings-at-cursor");
      let lastQ = ""; let dbTimer = null; let abortCtl = null;
      const doSearch = async (q) => {
        if (abortCtl) try { abortCtl.abort(); } catch(_){}
        abortCtl = new AbortController();
        const params = new URLSearchParams({
          min_len: STATE.settings.stringsMinLen,
          limit: STATE.settings.stringsLimit,
        });
        if (q) params.set("q", q);
        if (cursorTog.checked) params.set("cursor", STATE.cursor);
        const url = "/api/strings?" + params.toString();
        try {
          const resp = await fetch(url, {signal: abortCtl.signal});
          const j = await resp.json();
          if (j.status !== "ready") return;
          let html = "";
          for (const s of j.strings) {
            html += `<div class="lp-row" data-addr="${s.addr}">` +
                    `<span>${escapeHtml(s.str)}</span>` +
                    `<span class="meta">${s.addr}</span></div>`;
          }
          listEl.innerHTML = html || '<div class="dim">no match</div>';
          infoEl.textContent = `${j.count} string${j.count > 1 ? "s" : ""}` +
                                (cursorTog.checked ? ` · @cursor #${STATE.cursor}` : "");
          listEl.querySelectorAll(".lp-row").forEach(el => {
            el.addEventListener("click", () => {
              // 双击或单击 → 跳到第一次写入该地址的指令
              jumpToFirstWriteOfAddr(el.dataset.addr);
            });
          });
        } catch (e) {
          if (e.name !== "AbortError") infoEl.textContent = "err: " + e.message;
        }
      };
      filterInp.addEventListener("input", () => {
        if (dbTimer) clearTimeout(dbTimer);
        const q = filterInp.value;
        dbTimer = setTimeout(() => {
          if (q !== lastQ) { lastQ = q; doSearch(q); }
        }, 200);
      });
      cursorTog.addEventListener("change", () => doSearch(filterInp.value));
      doSearch("");
      // 当 cursor 变化时, 如果 at-cursor 模式, 自动重 search
      STATE._onCursorChange = STATE._onCursorChange || [];
      STATE._onCursorChange.push(() => {
        if (cursorTog.checked) {
          if (dbTimer) clearTimeout(dbTimer);
          dbTimer = setTimeout(() => doSearch(filterInp.value), 300);
        }
      });
      // 双击字符串 → 显示 provenance (谁逐字节构造的, 谁读了)
      listEl.addEventListener("dblclick", async ev => {
        const row = ev.target.closest(".lp-row");
        if (!row) return;
        await showStringProvenance(row.dataset.addr, infoEl);
      });
      return;
    }
    if (r.status === "building" || r.status === "idle") {
      await new Promise(res => setTimeout(res, 1500));
      continue;
    }
    cont.innerHTML = `<div class="dim">strings ${r.status}</div>`;
    return;
  }
}

async function showStringProvenance(addr, infoEl) {
  // 在底部 b-trace-for-pc tab 借用展示空间
  switchBottomTab("trace-for-pc");
  const cont = $("b-trace-for-pc");
  cont.innerHTML = `<div class="dim">analyzing string @ ${addr}…</div>`;
  const r = await api("/api/string-provenance", {addr, length: 64});
  if (r.status !== "ready") {
    cont.innerHTML = `<div class="dim">memshadow ${r.status}</div>`;
    return;
  }
  let html = `<div class="tfp-section"><h4>String @ ${addr} — provenance (谁构造 / 谁读取)</h4></div>`;
  // 逐字节表
  html += `<div style="font-family:monospace;font-size:11px">`;
  for (const b of r.bytes) {
    const ch = (b.byte != null && b.byte >= 0x20 && b.byte < 0x7f) ?
      String.fromCharCode(b.byte) : "·";
    const byteStr = b.byte != null ? b.byte.toString(16).padStart(2,"0") : "??";
    const writerLinks = b.writers.map(i =>
      `<a class="tfp-jump" data-idx="${i}">w#${i}</a>`).join(" ");
    const readerLinks = b.readers.map(i =>
      `<a class="tfp-jump" data-idx="${i}">r#${i}</a>`).join(" ");
    html += `<div class="tfp-row">` +
            `<span class="addr">${b.addr}</span> ` +
            `<span class="hex">${byteStr}</span> ` +
            `<span class="ascii">${escapeHtml(ch)}</span> ` +
            `<span class="dim">w(${b.writers_total}):</span> ${writerLinks} ` +
            `<span class="dim">r(${b.readers_total}):</span> ${readerLinks}` +
            `</div>`;
  }
  html += "</div>";
  cont.innerHTML = html;
  bindRowClicks(cont, ".tfp-jump");
}

async function jumpToFirstWriteOfAddr(addr) {
  // PDF p.5: 双击地址跳到定义 (第一次 write 该字节)
  const r = await api("/api/idxs-touching-addr", {addr, cursor: 0, limit: 5});
  if (r.status !== "ready") return;
  // 偏好 write (kind=w), 否则首个 read
  const all = [...r.after, ...r.before];
  const first = all.find(e => e.kind === "w") || all[0];
  if (first) setCursor(first.idx, true);
}

// taint state — 永久保留 + 支持 abort
function initTaintTab() {
  const cont = $("lp-taint");
  cont.innerHTML = `
    <div class="dim" id="taint-from">from cursor #${STATE.cursor}</div>
    <div class="row" style="margin:6px 0">
      reg <input id="taint-reg" class="inp" value="x0" size="6">
      <button class="btn" id="taint-fwd">forward →</button>
      <button class="btn" id="taint-bwd">← backward</button>
      <button class="btn" id="taint-cancel" style="display:none">cancel</button>
    </div>
    <div id="taint-out"><div class="dim">点上面 forward / backward 跑</div></div>`;
  $("taint-fwd").onclick = () => doTaint("forward");
  $("taint-bwd").onclick = () => doTaint("backward");
  $("taint-cancel").onclick = () => {
    if (STATE._taintAbort) STATE._taintAbort.abort();
  };
  // cursor 变化时刷新 "from cursor #N" + 自动 prefill 寄存器框
  // 默认填充 = 当前 insn 的 def reg (regs_def[0]); 没有 def 则保留旧值
  STATE._onCursorChange = STATE._onCursorChange || [];
  STATE._onCursorChange.push(async () => {
    const el = $("taint-from");
    if (el) el.textContent = `from cursor #${STATE.cursor}`;
    const ri = $("taint-reg");
    if (!ri || ri.matches(":focus")) return;   // 用户在编辑就别覆盖
    try {
      const r = await api("/api/record/" + STATE.cursor);
      if (r.regs_def && r.regs_def.length > 0) {
        // 取 def 中第一个非 xzr/sp/pc 的 (有意义的)
        const cand = r.regs_def.find(g => !["xzr","sp","pc","nzcv"].includes(g));
        if (cand) ri.value = cand;
      } else if (r.regs_use && r.regs_use.length > 0) {
        const cand = r.regs_use.find(g => !["xzr","sp","pc","nzcv"].includes(g));
        if (cand) ri.value = cand;
      }
    } catch (_) {}
  });
}

async function doTaint(dir) {
  // cancel any in-flight taint first
  if (STATE._taintAbort) {
    try { STATE._taintAbort.abort(); } catch (_) {}
  }
  const ctrl = new AbortController();
  STATE._taintAbort = ctrl;
  const reg = $("taint-reg").value || "x0";
  const cont = $("taint-out");
  const startCursor = STATE.cursor;
  cont.innerHTML = `<div class="dim">running ${dir} from #${startCursor} reg=${reg}…</div>`;
  $("taint-cancel").style.display = "";
  try {
    const params = new URLSearchParams({start: startCursor, reg});
    if (STATE.settings.taintLimit > 0) params.set("max_count", STATE.settings.taintLimit);
    const url = `/api/${dir}-taint?` + params.toString();
    const resp = await fetch(url, {signal: ctrl.signal});
    const r = await resp.json();
    if (ctrl.signal.aborted) return;
    if (r.status === "building" || r.status === "idle") {
      cont.innerHTML = '<div class="dim">building index…</div>';
      setTimeout(() => { if (STATE._taintAbort === ctrl) doTaint(dir); }, 1500);
      return;
    }
    const list = r.hits || r.chain || [];
    let html = `<div class="dim">${list.length} 条 (from #${startCursor})</div>`;
    for (const h of list)
      html += `<div class="lp-row" data-idx="${h.idx}">` +
              `<span>${escapeHtml(h.asm)}</span>` +
              `<span class="meta">#${h.idx}</span></div>`;
    cont.innerHTML = html;
    bindRowClicks(cont);
  } catch (e) {
    if (e.name === "AbortError") {
      cont.innerHTML = '<div class="dim">aborted</div>';
    } else {
      cont.innerHTML = `<div class="dim">error: ${e.message || e}</div>`;
    }
  } finally {
    if (STATE._taintAbort === ctrl) STATE._taintAbort = null;
    $("taint-cancel").style.display = "none";
  }
}

function initXrefTab() {
  const cont = $("lp-xref");
  cont.innerHTML = `
    <div class="dim">click 任意 trace/CFG 行触发</div>
    <div id="xref-info" style="margin:4px 0" class="dim">PC: -</div>
    <div id="xref-out"><div class="dim">尚未选择</div></div>`;
  if (STATE.activeInsnPc) loadXrefForCurrentPc();
}

async function loadXrefForCurrentPc() {
  const pc = STATE.activeInsnPc;
  if (!pc) return;
  const out = $("xref-out");
  const info = $("xref-info");
  if (!out) return;
  if (info) info.textContent = `PC: ${pc}`;
  out.innerHTML = '<div class="dim">scanning…</div>';
  // abort 旧 xref 请求
  if (STATE._xrefAbort) try { STATE._xrefAbort.abort(); } catch(_){}
  const ctrl = new AbortController();
  STATE._xrefAbort = ctrl;
  try {
    const url = "/api/idxs-for-pc?" + new URLSearchParams(
      {pc, cursor: STATE.cursor,
       limit: STATE.settings.idxsForPcLimit || 100});
    const resp = await fetch(url, {signal: ctrl.signal});
    const r = await resp.json();
    if (ctrl.signal.aborted) return;
    let html = `<div class="dim">${r.before.length} before · ${r.after.length} after (cursor #${r.cursor})</div>`;
    for (const i of r.before) html += `<div class="lp-row" data-idx="${i}"><span>#${i}</span><span class="meta">-${STATE.cursor - i}</span></div>`;
    for (const i of r.after)  html += `<div class="lp-row" data-idx="${i}"><span>#${i}</span><span class="meta">+${i - STATE.cursor}</span></div>`;
    out.innerHTML = html;
    bindRowClicks(out);
  } catch (e) {
    if (e.name !== "AbortError") out.innerHTML = `<div class="dim">err: ${e.message || e}</div>`;
  } finally {
    if (STATE._xrefAbort === ctrl) STATE._xrefAbort = null;
  }
}

// ---------------- sync toggle ----------------
function setupSyncToggle() {
  const t = $("sync-toggle");
  t.checked = STATE.syncEnabled;
  t.addEventListener("change", () => {
    STATE.syncEnabled = t.checked;
    if (t.checked) {
      // re-sync now
      api("/api/record/" + STATE.cursor).then(r => highlightCfgInsn(r.pc));
    } else {
      // clear highlights
      $("cfg-canvas").querySelectorAll("a.cursor-pc").forEach(a => a.classList.remove("cursor-pc"));
    }
  });
}

// ---------------- cfg func select ----------------
function setupCfgFuncSelect() {
  // populated by renderCFG callbacks; here just attach change handler
  const sel = $("cfg-func-select");
  sel.addEventListener("change", () => pollCFG(sel.value || null));
  // populate later when funcs known
  setInterval(() => {
    if (sel.dataset.populated === "1" && STATE.allFuncs.length === parseInt(sel.dataset.count)) return;
    if (STATE.allFuncs.length === 0) return;
    sel.innerHTML = `<option value="">— all funcs —</option>` +
      STATE.allFuncs.map(f =>
        `<option value="${escapeHtml(f.name)}">${escapeHtml(f.name)} (${f.blocks})</option>`).join("");
    sel.dataset.populated = "1";
    sel.dataset.count = String(STATE.allFuncs.length);
    sel.value = STATE.cfgFunc || "";
  }, 1000);
}

// ---------------- keyboard ----------------
function setupKeys() {
  window.addEventListener("keydown", (e) => {
    if (e.target.tagName === "INPUT") return;
    if (e.key === "j" || e.key === "ArrowDown") setCursor(STATE.cursor + 1, true);
    else if (e.key === "k" || e.key === "ArrowUp") setCursor(STATE.cursor - 1, true);
    else if (e.key === "PageDown") setCursor(STATE.cursor + 20, true);
    else if (e.key === "PageUp")   setCursor(STATE.cursor - 20, true);
    else if (e.key === "g") setCursor(0, true);
    else if (e.key === "G") setCursor(STATE.totalRecords - 1, true);
    else if (e.key === "/") { e.preventDefault(); openCmd("/", v => doSearch(v)); }
    else if (e.key === "n") { searchStep(+1); }
    else if (e.key === "N") { searchStep(-1); }
    else if (e.key === ":") { openCmd(":", v => { const n = parseInt(v); if (!Number.isNaN(n)) setCursor(n, true); }); }
  });
}

function setupCmd() {
  $("cmd-input").addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeCmd();
    if (e.key === "Enter") {
      const v = $("cmd-input").value;
      const cb = STATE._cmdCB;
      closeCmd();
      if (cb) cb(v);
    }
  });
  closeCmd();
}
function openCmd(prompt, cb) {
  STATE._cmdCB = cb;
  $("cmd-prompt").textContent = prompt;
  const inp = $("cmd-input");
  inp.value = ""; inp.focus();
}
function closeCmd() {
  STATE._cmdCB = null;
  $("cmd-prompt").textContent = "";
  $("cmd-input").value = "";
}

// ---------------- vim-style / search + n/N ----------------
async function doSearch(pattern) {
  if (!pattern) return;
  const status = $("status");
  if (status) status.textContent = `搜索 "${pattern}"...`;
  try {
    const r = await fetch(`/api/search?pattern=${encodeURIComponent(pattern)}&max_results=2000`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    STATE._searchPattern = pattern;
    STATE._searchHits = (j.hits || []).map(h => h.idx).sort((a,b)=>a-b);
    if (STATE._searchHits.length === 0) {
      if (status) status.textContent = `"${pattern}" 0 hits`;
      return;
    }
    // 跳到 cursor 之后第一个 hit
    let pos = STATE._searchHits.findIndex(i => i >= STATE.cursor);
    if (pos === -1) pos = 0;
    STATE._searchPos = pos;
    setCursor(STATE._searchHits[pos], true);
    if (status) status.textContent = `"${pattern}" ${pos+1}/${STATE._searchHits.length} hits — n/N 翻页`;
  } catch (e) {
    if (status) status.textContent = `search 失败: ${e.message}`;
  }
}
function searchStep(dir) {
  const hits = STATE._searchHits || [];
  if (hits.length === 0) {
    const status = $("status");
    if (status) status.textContent = `(无搜索结果) — 按 / 开始搜索`;
    return;
  }
  let pos = (STATE._searchPos ?? 0) + dir;
  if (pos < 0) pos = hits.length - 1;
  if (pos >= hits.length) pos = 0;
  STATE._searchPos = pos;
  setCursor(hits[pos], true);
  const status = $("status");
  if (status) status.textContent = `"${STATE._searchPattern}" ${pos+1}/${hits.length} hits — n/N 翻页`;
}

// ---------------- Settings tab ----------------
function initSettingsTab() {
  const cont = $("lp-settings");
  const s = STATE.settings;
  const fmt = (k, label, type, attrs = "") =>
    `<div class="set-row"><label>${label}</label>` +
    `<input id="set-${k}" type="${type}" value="${s[k]}" ${attrs}></div>`;
  cont.innerHTML = `
    <div class="set-section">📋 显示格式</div>
    <div class="set-row">
      <label>地址显示</label>
      <select id="set-addrFormat" class="inp">
        <option value="abs"${s.addrFormat==="abs"?" selected":""}>绝对地址 0x6d6e0e4820</option>
        <option value="fnoff"${s.addrFormat==="fnoff"?" selected":""}>func+offset (doCommandNative+0xb0)</option>
        <option value="soFnOff"${s.addrFormat==="soFnOff"?" selected":""}>so@func+offset</option>
      </select>
    </div>
    <div class="set-section">🔢 列表 limits (0 = 不限, 慎用大 trace)</div>
    ${fmt("taintLimit", "Taint hits", "number", "min=0")}
    ${fmt("searchLimit", "Search hits", "number", "min=0")}
    ${fmt("idxsForPcLimit", "Trace-for-PC each side", "number", "min=0")}
    ${fmt("idxsForBlockLimit", "Idxs for block", "number", "min=0")}
    ${fmt("stringsLimit", "Strings count", "number", "min=0")}
    ${fmt("stringsMinLen", "Strings min length", "number", "min=1")}
    ${fmt("memDumpLines", "Mem dump lines (×16 bytes)", "number", "min=1")}
    ${fmt("backtraceMaxDepth", "Backtrace max depth", "number", "min=1")}
    ${fmt("dotTimeout", "graphviz dot timeout (秒)", "number", "min=5")}
    <div class="set-row" style="margin-top:8px">
      <button class="btn" id="set-reset">重置默认</button>
      <span id="set-status" class="dim"></span>
    </div>
    <div class="dim" style="margin-top:8px;font-size:10px;line-height:14px">
      改后立即生效, 保存 localStorage.
    </div>`;
  cont.querySelectorAll("input, select").forEach(el => {
    if (!el.id.startsWith("set-")) return;
    const key = el.id.substring(4);
    if (!(key in DEFAULT_SETTINGS)) return;
    el.addEventListener("change", () => {
      const v = el.tagName === "SELECT" ? el.value : Number(el.value);
      STATE.settings[key] = v;
      saveSettings();
      $("set-status").textContent = `saved · ${key}=${v}`;
      reapplySettings();
    });
  });
  $("set-reset").addEventListener("click", () => {
    STATE.settings = {...DEFAULT_SETTINGS};
    saveSettings();
    initSettingsTab();
    reapplySettings();
  });
}

function reapplySettings() {
  // 地址格式变 → 重渲 trace 行
  document.querySelectorAll(".row-insn").forEach(el => el.remove());
  renderViewport();
}

// ---------------- go ----------------
init();
