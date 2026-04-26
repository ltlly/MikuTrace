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

const STATE = {
  meta: null,
  cursor: 0,
  totalRecords: 0,
  rowHeight: 18,
  pageSize: 500,
  cache: new Map(),         // start -> records[] window
  cacheKeys: [],            // LRU
  inflight: new Map(),      // start -> Promise (de-dupe in-flight fetch)
  cfg: null,
  cfgFunc: null,
  allFuncs: [],
  activeBlockPc: null,
  activeInsnPc: null,
  prevRegs: null,
  syncEnabled: true,
  // CFG canvas pan/zoom
  cfgPan: {x: 0, y: 0, scale: 1},
};

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
  inner.style.height = (STATE.totalRecords * STATE.rowHeight) + "px";
  inner.id = "stream-inner";
  stream.appendChild(inner);

  let renderTok = 0;
  stream.addEventListener("scroll", () => {
    const tok = ++renderTok;
    requestAnimationFrame(() => { if (tok === renderTok) renderViewport(); });
  });
  requestAnimationFrame(renderViewport);
}

function renderViewport() {
  // 不再 await: 立即渲染已 cache 行, 缺的 async 拉取, 拉到再补绘.
  const stream = $("stream");
  const inner = $("stream-inner");
  const top = stream.scrollTop;
  const bot = top + stream.clientHeight;
  const overscan = 10;
  const startIdx = Math.max(0, Math.floor(top / STATE.rowHeight) - overscan);
  const endIdx = Math.min(STATE.totalRecords,
                          Math.ceil(bot / STATE.rowHeight) + overscan);

  // 清掉视口外的行
  inner.querySelectorAll(".row-insn").forEach(el => {
    const i = parseInt(el.dataset.idx);
    if (i < startIdx || i >= endIdx) el.remove();
  });
  const present = new Set([...inner.querySelectorAll(".row-insn")]
                          .map(e => parseInt(e.dataset.idx)));

  // 已 cache 的立即画
  for (let i = startIdx; i < endIdx; i++) {
    if (present.has(i)) continue;
    const winStart = Math.floor(i / STATE.pageSize) * STATE.pageSize;
    const win = STATE.cache.get(winStart);
    if (!win) continue;
    const r = win[i - winStart];
    if (!r) continue;
    inner.appendChild(buildRow(i, r));
  }

  // 缺的 windows: 异步拉, 拉到后只画当前还在视口里的
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
        // 拉到后只补绘当前视口仍需要的行 (用户可能已滚走)
        const top = stream.scrollTop;
        const bot = top + stream.clientHeight;
        const sIdx = Math.max(0, Math.floor(top / STATE.rowHeight) - overscan);
        const eIdx = Math.min(STATE.totalRecords,
                              Math.ceil(bot / STATE.rowHeight) + overscan);
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

function buildRow(i, r) {
  const row = document.createElement("div");
  row.className = "row-insn";
  if (r.is_call)   row.classList.add("is-call");
  if (r.is_ret)    row.classList.add("is-ret");
  if (r.is_branch && !r.is_call && !r.is_ret) row.classList.add("is-branch");
  if (i === STATE.cursor) row.classList.add("active");
  row.dataset.idx = i;
  row.dataset.pc = r.pc;
  row.style.position = "absolute";
  row.style.top = (i * STATE.rowHeight) + "px";
  row.style.left = 0; row.style.right = 0;
  row.style.height = STATE.rowHeight + "px";
  const fn = r.func ? `${r.func}+${r.off}` : (r.rel || r.pc);
  const ecCls = execCountClass(r.exec_count);
  const ecTitle = r.exec_count != null ? `executed ×${r.exec_count}` : "";
  row.innerHTML =
    `<span class="ec ${ecCls}" title="${ecTitle}"></span>` +
    `<span class="idx">#${r.idx}</span>` +
    `<span class="pc">${r.pc}</span>` +
    `<span class="func">${fn}</span>` +
    `<span class="asm">${escapeHtml(r.asm)}</span>`;
  row.addEventListener("click", () => setCursor(i, false));
  return row;
}

function escapeHtml(s) {
  return s.replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
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
    const target = idx * STATE.rowHeight;
    if (target < stream.scrollTop || target > stream.scrollTop + stream.clientHeight - STATE.rowHeight*2) {
      stream.scrollTop = Math.max(0, target - stream.clientHeight / 2);
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
  // 关键: prev_regs 来自后端 (idx-1 的寄存器), NOT 上次点击的那一条.
  // 这样 4→8 跳转时, 高亮 #8 相对 #7 的变化 (这一步真的改了什么), 不是 #8 vs #4.
  const prev = r.prev_regs || {};
  const order = ["x0","x1","x2","x3","x4","x5","x6","x7",
                 "x8","x9","x10","x11","x12","x13","x14","x15",
                 "x16","x17","x18","x19","x20","x21","x22","x23",
                 "x24","x25","x26","x27","x28","fp","lr","sp","pc"];
  let html = '<div class="regs-grid">';
  for (const nm of order) {
    if (!(nm in regs)) continue;
    const changed = prev[nm] !== undefined && prev[nm] !== regs[nm];
    const cls = changed ? "reg changed" : "reg";
    html += `<div class="${cls}"><span class="rn">${nm}</span><span class="rv">${regs[nm]}</span></div>`;
  }
  html += "</div>";
  cont.innerHTML = html;
}

// ---------------- CFG (graphviz SVG) ----------------
async function pollCFG(fn = null) {
  $("cfg-info").textContent = fn ? `loading ${fn}…` : "loading…";
  let tries = 0;
  while (true) {
    const r = await api("/api/cfg-svg", fn ? {fn} : {});
    if (r.status === "ready") {
      STATE.cfgFunc = fn;
      embedCfgSvg(r);
      // 重新触发 cursor 同步 (高亮/active block)
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
                      {pc: pcHex, cursor: STATE.cursor, limit: 30});
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
    {funcs: "Functions", back: "Backtrace", strings: "Strings", taint: "Taint", xref: "Cross Reference"}[name];
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
      // 最深层在最上 (call 顺序倒序)
      for (let i = r.stack.length - 1; i >= 0; i--) {
        const f = r.stack[i];
        const fname = f.fn || "?";
        html += `<div class="lp-row" data-idx="${f.call_site_idx}">` +
                `<span>${escapeHtml(fname)} ← ${f.call_pc}</span>` +
                `<span class="meta">#${f.call_site_idx}</span></div>`;
      }
    }
    cont.innerHTML = html;
    cont.querySelectorAll(".lp-row").forEach(el =>
      el.addEventListener("click", () => setCursor(parseInt(el.dataset.idx), true)));
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
  // 初始 memory 视图给个占位
  $("b-memory").innerHTML = '<div class="dim">memory dump 在 cursor 移动时根据 SP/X0 等寄存器自动展示 (TODO: pdf parity)</div>';
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
    const r = await api("/api/strings", {min_len: 4});
    if (r.status === "ready") {
      let html = '<input class="inp" id="strings-filter" placeholder="filter…" style="width:100%;margin-bottom:4px"><div id="strings-list"></div>';
      cont.innerHTML = html;
      const filterInp = $("strings-filter");
      const listEl = $("strings-list");
      const all = r.strings || [];
      const renderStrings = (q) => {
        const ql = q.toLowerCase();
        let h = "";
        let n = 0;
        for (const s of all) {
          if (q && !s.str.toLowerCase().includes(ql) && !s.addr.includes(ql)) continue;
          h += `<div class="lp-row"><span>${escapeHtml(s.str)}</span>` +
               `<span class="meta">${s.addr}</span></div>`;
          if (++n >= 500) break;
        }
        listEl.innerHTML = h || '<div class="dim">no match</div>';
      };
      renderStrings("");
      filterInp.addEventListener("input", () => renderStrings(filterInp.value));
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

// taint state — 永久保留 + 支持 abort
function initTaintTab() {
  const cont = $("lp-taint");
  cont.innerHTML = `
    <div class="dim" id="taint-from">from cursor #${STATE.cursor}</div>
    <div class="row" style="margin:6px 0">
      reg <input id="taint-reg" class="inp" value="x0" size="4">
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
  // 当 cursor 变化时刷新 "from cursor #N" 显示 (但不自动重跑)
  STATE._onCursorChange = STATE._onCursorChange || [];
  STATE._onCursorChange.push(() => {
    const el = $("taint-from");
    if (el) el.textContent = `from cursor #${STATE.cursor}`;
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
    const url = `/api/${dir}-taint?` + new URLSearchParams({start: startCursor, reg});
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
    cont.querySelectorAll(".lp-row").forEach(el =>
      el.addEventListener("click", () => setCursor(parseInt(el.dataset.idx), true)));
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
      {pc, cursor: STATE.cursor, limit: 100});
    const resp = await fetch(url, {signal: ctrl.signal});
    const r = await resp.json();
    if (ctrl.signal.aborted) return;
    let html = `<div class="dim">${r.before.length} before · ${r.after.length} after (cursor #${r.cursor})</div>`;
    for (const i of r.before) html += `<div class="lp-row" data-idx="${i}"><span>#${i}</span><span class="meta">-${STATE.cursor - i}</span></div>`;
    for (const i of r.after)  html += `<div class="lp-row" data-idx="${i}"><span>#${i}</span><span class="meta">+${i - STATE.cursor}</span></div>`;
    out.innerHTML = html;
    out.querySelectorAll(".lp-row").forEach(el =>
      el.addEventListener("click", () => setCursor(parseInt(el.dataset.idx), true)));
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
    else if (e.key === "/") { e.preventDefault(); openCmd("/", v => { /* TODO search */ }); }
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

// ---------------- go ----------------
init();
