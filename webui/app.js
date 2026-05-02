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
  //          'fnoff' = func+offset = myFunc+0xb0
  //          'soFnOff' = libtarget@func+offset
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
  cfgSource: "trace",
  bnCfgFn: null,         // {name, start, end} of BN-CFG currently rendered (for cross-fn 自动重载)
  bnAsmTokens: new Map(),         // pc_hex -> tokens[] (or null = fetched, no data)
  bnAsmTokensInflight: new Set(), // pc_hex set inflight to /api/asm-tokens-for-pcs
  bnAsmFetchTimer: null,          // debounce handle
  bnAsmDisabled: false,           // flips true if backend reports not-ready, suppresses retries
  // SO Filter: set of SO names to hide. Persisted in localStorage.
  // soStats: {records, modules:[{name,records,percent},...]} cached after fetch.
  hiddenSOs: new Set(),
  soStats: null,
  settings: loadSettings(),
};
// load hidden SOs from localStorage
try {
  const raw = localStorage.getItem("tracemiku-hidden-sos");
  if (raw) STATE.hiddenSOs = new Set(JSON.parse(raw));
} catch (_) {}

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

  // Fetch SO stats early to decide whether this is a multi-SO trace.
  // body.multi-so toggles per-row color bars ON; single-SO traces stay clean.
  // /api/so-stats 是 numpy vectorized, 7M trace 上 ~10ms.
  api("/api/so-stats?top=200").then(stats => {
    STATE.soStats = stats;
    document.body.classList.toggle("multi-so", stats.modules.length >= 2);
  }).catch(() => {});

  setupColResize();
  buildVirtualList();
  setupVerticalTabs();
  setupBottomTabs();
  setupKeys();
  setupCmd();
  setupCfgPanZoom();
  setupSyncToggle();
  setupCfgFuncSelect();
  setupHelp();

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
    STATE.lastScrollTime = performance.now();
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
    // decoupled 模式: row top 用 scrollPos 起算, "上方 overscan" 实际占视口顶部空间
    // (无效, 反而把可见内容下推). 故只往下方 overscan, startIdx = baseIdx.
    startIdx = Math.max(0, baseIdx);
    endIdx = Math.min(STATE.totalRecords, baseIdx + visible + overscan);
    // 限制 endIdx 让所有 row top + rowHeight ≤ inner.height — 否则末尾行
    // 渲染到 inner 之外 (inner overflow:hidden 会裁掉, 但也意味着不可见).
    // 用 ceil 避免 viewH/rowHeight 不整除时末尾少 1 行 (10214936 条 trace → 末行 #10214935 被切).
    const maxRowsBelowScroll = Math.ceil((innerH - scrollPos) / STATE.rowHeight);
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

  // 已存在的行: 实数据 vs placeholder 分别记录, 让缓存到达后能升级 placeholder
  const realIdx = new Set();
  const placeholderEls = new Map();
  inner.querySelectorAll(".row-insn").forEach(el => {
    const i = parseInt(el.dataset.idx);
    if (el.classList.contains("placeholder")) placeholderEls.set(i, el);
    else realIdx.add(i);
  });

  for (let i = startIdx; i < endIdx; i++) {
    if (realIdx.has(i)) continue;
    const winStart = Math.floor(i / STATE.pageSize) * STATE.pageSize;
    const win = STATE.cache.get(winStart);
    if (win) {
      const r = win[i - winStart];
      if (r) {
        const ph = placeholderEls.get(i);
        if (ph) ph.remove();
        inner.appendChild(buildRow(i, r));
      }
    } else if (!placeholderEls.has(i)) {
      // 即便 cache miss, 立刻插 placeholder — 滚动时视觉始终非空, 不再"白屏 1-2s"
      inner.appendChild(buildPlaceholderRow(i));
    }
  }

  // 拉 missing windows: 滚动剧烈期 (<80ms 内还有 scroll) 推迟到稳定后再发,
  // 避免 fast-drag 期间发出 5-10 个会立即过期的 fetch.
  scheduleFetchMissing();
  scheduleBnAsmFetch();
}

// 占位行: 渲染 idx + "..." 让快速滚动时视觉始终非空, fetch 到达后 in-place 替换.
function buildPlaceholderRow(i) {
  const row = document.createElement("div");
  row.className = "row-insn placeholder";
  if (i === STATE.cursor) row.classList.add("active");
  row.dataset.idx = i;
  row.style.position = "absolute";
  row.style.top = rowTopPx(i) + "px";
  row.style.left = 0; row.style.right = 0;
  row.style.height = STATE.rowHeight + "px";
  row.innerHTML =
    `<span class="ec ec-unknown"></span>` +
    `<span class="idx">#${i}</span>` +
    `<span class="pc"></span>` +
    `<span class="func"></span>` +
    `<span class="asm">…</span>`;
  row.addEventListener("click", () => setCursor(i, false));
  return row;
}

function scheduleFetchMissing() {
  if (STATE.fetchDebounceTimer) return;
  const idle = performance.now() - (STATE.lastScrollTime || 0);
  // 80ms idle 才 fire; 仍在快速滚则 80-idle 后再试 (递归 schedule)
  const delay = idle < 80 ? Math.max(20, 80 - idle) : 0;
  STATE.fetchDebounceTimer = setTimeout(() => {
    STATE.fetchDebounceTimer = null;
    fireMissingWindowFetches();
  }, delay);
}

function fireMissingWindowFetches() {
  const inner = $("stream-inner");
  if (!inner) return;
  const [startIdx, endIdx] = viewportIdxRange();
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
        // re-check viewport, 用户可能已滚走 — 还在视口的 idx 才升级
        const [sIdx, eIdx] = viewportIdxRange();
        STATE.viewportStartIdx = sIdx;
        const realIdx = new Set();
        const phEls = new Map();
        inner.querySelectorAll(".row-insn").forEach(el => {
          const i = parseInt(el.dataset.idx);
          if (el.classList.contains("placeholder")) phEls.set(i, el);
          else realIdx.add(i);
        });
        for (let i = Math.max(s, sIdx); i < Math.min(s + STATE.pageSize, eIdx); i++) {
          if (realIdx.has(i)) continue;
          const rec = r.records[i - s];
          if (!rec) continue;
          const ph = phEls.get(i);
          if (ph) ph.remove();
          inner.appendChild(buildRow(i, rec));
        }
        scheduleBnAsmFetch();
      })
      .catch(_ => { STATE.inflight.delete(s); });
    STATE.inflight.set(s, p);
  }
}

// Lazy: collect 当前 viewport 里 .asm 还在 fallback 模式且未 inflight 的 PC,
// 60ms 节流 + 单批 ≤256, 一拉到结果就 in-place 替换 .asm 内容. 对没 BN 的会话
// (decomp 还在 loading 或 disabled) 静默 no-op, 不影响其它功能.
function scheduleBnAsmFetch() {
  if (STATE.bnAsmDisabled) return;
  if (STATE.bnAsmFetchTimer) return;
  STATE.bnAsmFetchTimer = setTimeout(() => {
    STATE.bnAsmFetchTimer = null;
    fetchBnAsmTokensForViewport();
  }, 60);
}

async function fetchBnAsmTokensForViewport() {
  const inner = $("stream-inner");
  if (!inner) return;
  const need = new Set();
  inner.querySelectorAll(".row-insn").forEach(row => {
    const pc = row.dataset.pc;
    if (pc && !STATE.bnAsmTokens.has(pc) && !STATE.bnAsmTokensInflight.has(pc)) {
      need.add(pc);
    }
  });
  if (need.size === 0) return;
  const pcs = [...need].slice(0, 256);
  pcs.forEach(p => STATE.bnAsmTokensInflight.add(p));
  try {
    const r = await api("/api/asm-tokens-for-pcs", {pcs: pcs.join(",")});
    if (!r || r.ready === false) {
      // backend 还没 ready, 把这批从 inflight 撤回让以后能重试; 不入 cache 防"假阳性"
      pcs.forEach(p => STATE.bnAsmTokensInflight.delete(p));
      return;
    }
    if (r.status !== "ok") return;
    const got = r.tokens || {};
    for (const p of pcs) {
      // null 标记 = 已问过, BN 不知道 (略过 future 重问)
      STATE.bnAsmTokens.set(p, got[p] || null);
    }
    // FIFO 上限: 病态 trace 里 unique PC 数可能巨大 (libsg JNI_OnLoad 实测 ~10K
    // 没问题; 上限 50K 防 worst case dict 无界).
    const CAP = 50000;
    if (STATE.bnAsmTokens.size > CAP) {
      const overflow = STATE.bnAsmTokens.size - CAP;
      const it = STATE.bnAsmTokens.keys();
      for (let i = 0; i < overflow; i++) STATE.bnAsmTokens.delete(it.next().value);
    }
    applyBnTokensToRows(pcs);
    if (need.size > pcs.length) scheduleBnAsmFetch();
  } catch (_) {
    // 网络/解析错: 撤回 inflight, 不静默 disable (用户重试)
    pcs.forEach(p => STATE.bnAsmTokensInflight.delete(p));
    return;
  } finally {
    pcs.forEach(p => STATE.bnAsmTokensInflight.delete(p));
  }
}

function applyBnTokensToRows(pcList) {
  const inner = $("stream-inner");
  if (!inner) return;
  for (const pc of pcList) {
    const tks = STATE.bnAsmTokens.get(pc);
    if (!tks || !tks.length) continue;
    const tokenHtml = renderTokens(tks);
    inner.querySelectorAll(`.row-insn[data-pc="${pc}"] .asm`).forEach(el => {
      const annEl = el.querySelector(".ann");
      // rebuild: BN tokens + 保留原 annotation 节点
      el.innerHTML = tokenHtml;
      if (annEl) {
        el.appendChild(document.createTextNode("  "));
        el.appendChild(annEl);
      }
    });
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

// SO color: deterministic hash → palette of 12 dark-bg-friendly hues.
const SO_COLORS = [
  "#79c0ff", "#56d4dd", "#ffa657", "#a5d6ff", "#d2a8ff",
  "#f2cc60", "#3fb950", "#ff7b72", "#bc8cff", "#58a6ff",
  "#ff9492", "#7ee787",
];
function soColor(name) {
  if (!name) return "#6e7681";
  let h = 0; for (let i = 0; i < name.length; i++) h = ((h << 5) - h + name.charCodeAt(i)) | 0;
  return SO_COLORS[Math.abs(h) % SO_COLORS.length];
}
// short label for SO badge: trim '.so' + version suffix → e.g. 'libfoo-1.2.3.so' → 'libfo'
function soBadge(name) {
  if (!name) return "?";
  let s = name.replace(/-[0-9.]+\.so$/, "").replace(/\.so$/, "");
  if (s.startsWith("lib")) s = s.slice(3);
  return s.length > 8 ? s.slice(0, 8) : s;
}

function buildRow(i, r) {
  const row = document.createElement("div");
  row.className = "row-insn";
  if (STATE.settings.addrFormat === "fnoff" || STATE.settings.addrFormat === "soFnOff")
    row.classList.add("fmt-fn");
  if (r.is_call)   row.classList.add("is-call");
  if (r.is_ret)    row.classList.add("is-ret");
  if (r.is_branch && !r.is_call && !r.is_ret) row.classList.add("is-branch");
  if (i === STATE.cursor) row.classList.add("active");
  row.dataset.idx = i;
  row.dataset.pc = r.pc;
  if (r.module) {
    row.dataset.module = r.module;
    // SO filter checkbox writes a class to body — `.so-hidden-<safe>` hides matching rows
    if (STATE.hiddenSOs && STATE.hiddenSOs.has(r.module))
      row.classList.add("so-hidden");
  }
  row.style.position = "absolute";
  row.style.top = rowTopPx(i) + "px";
  row.style.left = 0; row.style.right = 0;
  row.style.height = STATE.rowHeight + "px";
  const ecCls = execCountClass(r.exec_count);
  const ecTitle = r.exec_count != null ? `executed ×${r.exec_count}` : "";
  const annHtml = r.annotation ? `<span class="ann">; ${escapeHtml(r.annotation)}</span>` : "";
  const pcFmt = formatPc(r);
  const asmInner = renderAsmInner(r);
  // Module color bar (3px wide, left edge). CSS body.multi-so 控制是否显示
  // — 单 SO trace 默认隐藏 (零噪音). hover/title 显示完整 SO 名.
  const modBar = r.module
    ? `<span class="mod-bar" style="color:${soColor(r.module)}" title="${escapeHtml(r.module)}"></span>`
    : "";
  row.innerHTML =
    modBar +
    `<span class="ec ${ecCls}" title="${ecTitle}"></span>` +
    `<span class="idx">#${r.idx}</span>` +
    `<span class="pc" title="${r.pc}">${escapeHtml(pcFmt)}</span>` +
    `<span class="func">${r.func ? r.func + "+" + r.off : (r.rel || r.pc)}</span>` +
    `<span class="asm">${asmInner}${annHtml ? "  " + annHtml : ""}</span>`;
  row.addEventListener("click", () => setCursor(i, false));
  return row;
}

// 浏览器单 div 高度上限 ~33M px → 大 trace 用 decoupled scroll: scrollbar 位置
// 只表 percentage, 实际 row 位置由 (idx - startIdx)*rowHeight + scrollPos 算.
// viewH/rowHeight 不整除时, 末行底部会越过视口下沿被 #stream 裁掉 (用户:"勉强
// 能看见一点"). 按 pct 比例上移 overshoot, 让滚到底时末行底贴齐视口底, 滚到顶时
// 不偏移. 等价于原生滚动在边缘行的视觉行为.
function rowTopPx(idx) {
  if (STATE.usingDecoupledScroll) {
    const stream = $("stream");
    const inner = $("stream-inner");
    const scrollPos = stream.scrollTop || 0;
    const viewH = stream.clientHeight;
    const innerH = inner ? (inner.offsetHeight || parseInt(inner.style.height) || 0) : 0;
    const scrollMax = Math.max(1, innerH - viewH);
    const pct = Math.min(1, scrollPos / scrollMax);
    const visible = Math.ceil(viewH / STATE.rowHeight);
    const overshoot = Math.max(0, visible * STATE.rowHeight - viewH);
    return scrollPos + (idx - STATE.viewportStartIdx) * STATE.rowHeight - overshoot * pct;
  }
  return idx * STATE.rowHeight;
}

// 一行 trace asm 的内部 HTML: 优先用 BN tokens (有 .tok-* 着色),
// 否则 fallback 到 capstone 字符串 + reg-regex 着色.
function renderAsmInner(r) {
  const tks = STATE.bnAsmTokens.get(r.pc);
  if (tks && tks.length) return renderTokens(tks);
  return highlightRegs(r.asm);
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
    if (STATE.syncEnabled) {
      // BN CFG 模式: 跨 fn 自动重新加载 SVG, 同 fn 内仅 highlight (省事省 dot 渲染)
      if (STATE.cfgSource === "bn-asm") {
        const pcInt = parseInt(r.pc, 16);
        const f = STATE.bnCfgFn;
        if (!f || pcInt < f.start || pcInt >= f.end) {
          loadBnCfgForCursor();
        } else {
          highlightCfgInsn(r.pc);
        }
      } else {
        highlightCfgInsn(r.pc);
      }
    }
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
  $("btn-reload-cfg").onclick = () => loadCfgWithCurrentSource();
  // CFG source selector: trace 重建 vs BN 静态 + trace overlay
  const srcSel = $("cfg-source");
  if (srcSel) {
    srcSel.addEventListener("change", () => {
      STATE.cfgSource = srcSel.value;
      if (STATE.cfgSource !== "bn-asm") STATE.bnCfgFn = null;
      loadCfgWithCurrentSource();
    });
  }
}

// 按当前 cfg-source 选择走哪个数据源
function loadCfgWithCurrentSource() {
  const src = (STATE.cfgSource || "trace");
  if (src === "trace") return pollCFG(STATE.cfgFunc);
  if (src === "bn-asm") return loadBnCfgForCursor();
}

async function loadBnCfgForCursor() {
  $("cfg-info").textContent = "loading BN CFG…";
  try {
    const rec = await api("/api/record/" + STATE.cursor);
    const r = await api("/api/bn-cfg-svg-for-pc", { pc: rec.pc, mode: "asm" });
    if (r.status === "loading" || r.status === "disabled") {
      $("cfg-info").textContent = `decomp ${r.status}`;
      $("cfg-canvas").innerHTML = "";
      return;
    }
    if (r.status !== "ok") {
      $("cfg-info").textContent = `BN CFG: ${r.status} ${r.err || ""}`;
      $("cfg-canvas").innerHTML = `<div class="dim" style="padding:8px">${escapeHtml(r.err || r.status)}</div>`;
      // 让 cursor sync 把 "已拒绝的大 fn" 当作"已加载", 别每次 cursor 移动都重新打.
      // too-large / no-function 都返回 fn.start/end (服务端会带), 同 fn 内 cursor 移动直接静默.
      if (r.fn && r.fn.start && r.fn.end) {
        STATE.bnCfgFn = {
          name: r.fn.name,
          start: parseInt(r.fn.start, 16),
          end:   parseInt(r.fn.end, 16),
        };
      } else {
        STATE.bnCfgFn = null;
      }
      return;
    }
    // reuse embedCfgSvg but tweak info string
    embedCfgSvg(r);
    STATE.bnCfgFn = r.fn ? {
      name: r.fn.name,
      start: parseInt(r.fn.start, 16),
      end:   parseInt(r.fn.end, 16),
    } : null;
    const ovInfo = `BN ${r.fn.name} · ${r.block_count} blocks · ${r.edge_count} static edges` +
      (r.dyn_only_count ? ` · ${r.dyn_only_count} dyn-only ⚠` : "") +
      ` · total exec=${r.fn_total_exec}`;
    $("cfg-info").textContent = ovInfo;
    // 立即把 cursor PC 高亮到当前 BN CFG (loadBnCfgForCursor 自带 fit, 高亮要在 fit 之后)
    if (STATE.cursor != null) {
      try {
        const rec = await api("/api/record/" + STATE.cursor);
        highlightCfgInsn(rec.pc);
      } catch (_) {}
    }
  } catch (e) {
    $("cfg-info").textContent = "err: " + (e.message || e);
  }
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
    {funcs: "Functions", back: "Backtrace", calltree: "Call Tree",
     forks: "Forks",
     strings: "Strings",
     taint: "Taint", xref: "Cross Reference", sofilter: "SO Filter",
     settings: "Settings"}[name] || name;
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
    else if (name === "calltree") initCallTreeTab();
    else if (name === "forks") initForksTab();
    else if (name === "sofilter") initSoFilterTab();
    else if (name === "settings") initSettingsTab();
  }
  // 切到 backtrace 时刷一下当前 cursor 的 stack
  if (name === "back") refreshBacktrace();
}

// ---------------- SO Filter (multi-SO trace) ----------------
async function initSoFilterTab() {
  const cont = $("lp-sofilter");
  cont.innerHTML = '<div class="dim">loading SO stats…</div>';
  let stats;
  try {
    stats = await fetchJson("/api/so-stats?top=200&all=false");
  } catch (e) {
    cont.innerHTML = `<div class="dim">SO stats failed: ${escapeHtml(String(e))}</div>`;
    return;
  }
  STATE.soStats = stats;
  // Toggle body.multi-so so per-row color bars only appear when ≥2 SOs.
  // Single-SO traces are kept noise-free (the most common case).
  document.body.classList.toggle("multi-so", stats.modules.length >= 2);
  renderSoFilter();
}

function renderSoFilter() {
  const cont = $("lp-sofilter");
  if (!cont || !STATE.soStats) return;
  const stats = STATE.soStats;
  const lines = [];
  lines.push(`<div class="dim" style="padding:6px 8px;border-bottom:1px solid #30363d">
    ${stats.records} records · ${stats.modules.length} SOs in trace
    ${stats.unknown_records ? ` · ${stats.unknown_records} unmapped` : ""}
  </div>`);
  lines.push(`<div style="padding:6px 8px;display:flex;gap:6px;border-bottom:1px solid #30363d">
    <button class="btn" id="so-show-all" style="font-size:11px">Show all</button>
    <button class="btn" id="so-hide-rest" style="font-size:11px;margin-left:auto" title="hide everything except target SO">Hide all but #1</button>
  </div>`);
  lines.push('<div class="so-list" style="padding:4px 0">');
  for (const m of stats.modules) {
    const hidden = STATE.hiddenSOs.has(m.name);
    const col = soColor(m.name);
    const pct = m.percent.toFixed(1);
    lines.push(`<label class="so-row" style="display:flex;align-items:center;gap:6px;padding:3px 8px;cursor:pointer;${hidden ? 'opacity:.5' : ''}">
      <input type="checkbox" data-so="${escapeHtml(m.name)}" ${hidden ? '' : 'checked'}>
      <span class="mod-badge" style="color:${col};min-width:60px">${escapeHtml(soBadge(m.name))}</span>
      <span class="dim" style="font-size:10px">${pct}%</span>
      <span style="flex:1;font-family:monospace;font-size:11px;text-overflow:ellipsis;overflow:hidden;white-space:nowrap" title="${escapeHtml(m.name)}">${escapeHtml(m.name)}</span>
      <span class="dim" style="font-size:10px">${m.records}</span>
    </label>`);
  }
  lines.push('</div>');
  cont.innerHTML = lines.join("");

  cont.querySelectorAll('input[type="checkbox"]').forEach(cb => {
    cb.addEventListener("change", () => {
      const so = cb.dataset.so;
      if (cb.checked) STATE.hiddenSOs.delete(so);
      else STATE.hiddenSOs.add(so);
      persistHiddenSOs();
      // re-render trace viewport so the .so-hidden classes update
      renderViewport();
    });
  });
  $("so-show-all")?.addEventListener("click", () => {
    STATE.hiddenSOs.clear(); persistHiddenSOs(); renderSoFilter(); renderViewport();
  });
  $("so-hide-rest")?.addEventListener("click", () => {
    STATE.hiddenSOs = new Set(stats.modules.slice(1).map(x => x.name));
    persistHiddenSOs(); renderSoFilter(); renderViewport();
  });
}

function persistHiddenSOs() {
  try {
    localStorage.setItem("tracemiku-hidden-sos",
      JSON.stringify([...STATE.hiddenSOs]));
  } catch (_) {}
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
  $("right-tab-title").textContent =
    {cfg: "Graph", regs: "Registers", hlil: "HLIL (decompiled)",
     dec: "Decompile (Trace IR + LLM)"}[name] || name;
  if (name === "hlil") {
    if (!TAB_INIT.hlil) { TAB_INIT.hlil = true; initHlilTab(); }
    refreshHlil();   // immediate refresh on activate
  } else if (name === "dec") {
    if (!TAB_INIT.dec) { TAB_INIT.dec = true; initDecompileTab(); }
  }
}

// ---------------- HLIL (decompiled view) ----------------
const HLIL_STATE = {
  fnStart: null,            // 当前显示的函数 start (避免同函数重复 fetch)
  lastPc: null,             // 最近请求过的 pc
  loading: false,
  errorShown: false,
};
function initHlilTab() {
  $("hlil-pane").innerHTML =
    '<div class="dim" style="padding:8px">连接反编译后端…</div>';
  STATE._onCursorChange = STATE._onCursorChange || [];
  STATE._onCursorChange.push(refreshHlil);
}

async function refreshHlil() {
  const pane = $("hlil-pane");
  if (!pane || !pane.classList.contains("active")) return;
  const cur = STATE.cursor;
  let pc = null;
  try {
    const r = await api("/api/record/" + cur);
    pc = r.pc;
  } catch (_) { return; }
  if (!pc) return;
  if (HLIL_STATE.loading && HLIL_STATE.lastPc === pc) return;
  HLIL_STATE.lastPc = pc;
  HLIL_STATE.loading = true;
  try {
    const r = await api("/api/hlil-for-pc", { pc });
    HLIL_STATE.loading = false;
    if (!r.ready) {
      const elapsed = (r.elapsed || 0).toFixed(1);
      const msg = r.status === "loading"
        ? `反编译后端加载中… (${elapsed}s)<br><span class="dim">第一次启动 ~30-60s, 之后单函数查询 ms 级</span>`
        : r.status === "disabled"
        ? `反编译后端未启用<br><span class="dim">启动时加 <code>--so PATH</code> 参数</span>`
        : r.status === "error"
        ? `反编译后端加载失败<br><span class="dim" style="color:#c33">${escapeHtml(r.err || '')}</span>`
        : `状态: ${r.status}`;
      pane.innerHTML = `<div class="dim" style="padding:8px">${msg}</div>`;
      // 若还在 loading, 1.5s 后重试
      if (r.status === "loading") setTimeout(refreshHlil, 1500);
      return;
    }
    if (r.status === "no-function") {
      pane.innerHTML = `<div class="dim" style="padding:8px">PC ${escapeHtml(r.pc)} 不在任何已识别函数内</div>`;
      HLIL_STATE.fnStart = null;
      return;
    }
    renderHlil(r);
  } catch (e) {
    HLIL_STATE.loading = false;
    if (!HLIL_STATE.errorShown) {
      pane.innerHTML = `<div class="dim" style="padding:8px;color:#c33">err: ${escapeHtml(e.message||e)}</div>`;
      HLIL_STATE.errorShown = true;
    }
  }
}

function renderHlil(r) {
  const pane = $("hlil-pane");
  // 同函数 + 同 in_range 才复用 DOM
  const cacheKey = r.fn.start + ':' + (r.in_range ? '1' : '0');
  const sameFn = HLIL_STATE.fnStart === cacheKey;
  if (!sameFn) {
    HLIL_STATE.fnStart = cacheKey;
    let html = '';
    html += `<div class="hlil-head">`;
    // 主函数名 (BN 给的)
    html += `<div><b>${escapeHtml(r.fn.name)}</b> <span class="dim">[${escapeHtml(r.fn.start)}..${escapeHtml(r.fn.end)})  via ${escapeHtml(r.backend)}</span></div>`;
    // 不在 BN 函数范围内: 显式提示 nearest fallback (OLLVM 混淆区常见)
    if (r.in_range === false) {
      html += `<div class="dim" style="color:var(--warn)">⚠ PC ${escapeHtml(r.pc)} 不在 ${escapeHtml(r.fn.name)} 范围内 (nearest fn fallback; 可能 OLLVM 混淆 / trampoline)</div>`;
    }
    // trace 侧 sym 推断的名字 — 跟左侧 disasm 显示对照
    if (r.trace_fn && r.trace_fn.name !== r.fn.name) {
      html += `<div class="dim">↪ trace sym: <code>${escapeHtml(r.trace_fn.name)}+${escapeHtml(r.trace_fn.off)}</code> <span style="opacity:0.6">(左侧 disasm 显示的名字, 跟 BN 不同因为 trace 推断 vs 静态分析)</span></div>`;
    }
    if (r.vars && r.vars.length) {
      html += '<details class="hlil-vars"><summary>vars (' + r.vars.length + ')</summary><div>';
      for (const v of r.vars) {
        html += `<div class="hlil-var"><span class="hlil-var-name">${escapeHtml(v.name)}</span> : <span class="hlil-var-type">${escapeHtml(v.type)}</span> <span class="dim">@ ${escapeHtml(v.storage)}</span></div>`;
      }
      html += '</div></details>';
    }
    html += `</div>`;
    html += `<div class="hlil-body">`;
    for (let i = 0; i < r.lines.length; i++) {
      const l = r.lines[i];
      html += `<div class="hlil-line" data-i="${i}" data-pc="${l.pc}">`;
      html += `<span class="hlil-pc">${l.pc}</span>`;
      html += `<span class="hlil-text">${renderTokens(l.tokens, l.text)}</span>`;
      html += `</div>`;
    }
    html += `</div>`;
    pane.innerHTML = html;
    // click HLIL line → 跳到该 PC 在 trace 里的某次出现
    pane.querySelectorAll(".hlil-line").forEach(el => {
      el.addEventListener("click", (ev) => {
        // 双击 fn/data token: 跳那个 token 的目标地址 (跨函数 navigate)
        const tk = ev.target.closest(".tok-fn, .tok-data");
        if (tk && ev.detail >= 2 && tk.dataset.a) {
          jumpToPc(tk.dataset.a); ev.stopPropagation(); return;
        }
        jumpToPc(el.dataset.pc);
      });
    });
  }
  // 高亮 current line
  pane.querySelectorAll(".hlil-line.cur").forEach(e => e.classList.remove("cur"));
  if (r.current_line_idx >= 0) {
    const el = pane.querySelector(`.hlil-line[data-i="${r.current_line_idx}"]`);
    if (el) {
      el.classList.add("cur");
      // scroll into view (only when not already visible)
      const body = pane.querySelector(".hlil-body");
      if (body) {
        const rb = body.getBoundingClientRect();
        const re = el.getBoundingClientRect();
        if (re.top < rb.top || re.bottom > rb.bottom) {
          el.scrollIntoView({block: "center", behavior: "instant"});
        }
      }
    }
  }
}

async function jumpToPc(pc) {
  // 拿该 PC 的 trace idxs, 跳到离 cursor 最近的一次
  try {
    const r = await api("/api/idxs-for-pc", { pc, cursor: STATE.cursor });
    if (r.status === "ready" && (r.before.length || r.after.length)) {
      const target = r.after.length ? r.after[0] : r.before[r.before.length - 1];
      setCursor(target, true);
    }
  } catch(_) {}
}

// 把 backend 给的 tokens 渲染成 HTML, 套 .tok-{cls} class.
// fallback: 没 tokens 时 escape 原文.
// 完整匹配整行 token text 的 GPR — token-level, 不会误匹配子串.
const REG_RE_FULL = /^(x([12]?\d|3[01])|w([12]?\d|3[01])|sp|fp|lr|pc|xzr|wzr)$/i;

function renderTokens(tokens, fallbackText) {
  if (!tokens || !tokens.length) return escapeHtml(fallbackText || "");
  let s = "";
  for (const tk of tokens) {
    let cls = "tok-" + (tk.c || "other");
    let extra = tk.a ? ` data-a="${tk.a}"` : "";
    // BN reg-token + GPR 文本 → 也挂上 op-reg/data-reg, 让旧的 hover/dblclick/contextmenu
    // handler (closest(".op-reg") + dataset.reg) 在 BN-token 渲染下仍然命中.
    if (tk.c === "reg" && REG_RE_FULL.test(tk.t)) {
      cls += " op-reg";
      extra += ` data-reg="${normalizeReg(tk.t)}"`;
    }
    s += `<span class="${cls}"${extra}>${escapeHtml(tk.t)}</span>`;
  }
  return s;
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
    <div id="mem-content" style="padding:6px 8px;font-family:inherit;font-size:11px;line-height:16px"></div>`;
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
        const cls = b.kind === "x" ? "b-extern"
                  : b.kind === "w" ? "b-write" : "b-read";
        const titleKind = b.kind === "x" ? "external write" : b.kind;
        hex += `<span class="${cls}" data-addr="${b.addr}" title="from #${b.src_idx} (${titleKind})">${b.byte.toString(16).padStart(2,'0')}</span> `;
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
  html += `<div style="font-family:inherit;font-size:11px">`;
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
  // 偏好 write (kind='w' in-trace / 'x' external), 否则首个 read
  const all = [...r.after, ...r.before];
  const first = all.find(e => e.kind === "w" || e.kind === "x") || all[0];
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

// 服务器侧 clamp 上限是 50000 (TAINT_MAX_COUNT_CEILING in webui/server.py).
// 这里 50001 等价"无限": 多 1 让服务器 stopped_at_max=true 还能透传.
const TAINT_LOAD_ALL_CAP = 50001;

async function doTaint(dir, opts) {
  // cancel any in-flight taint first
  if (STATE._taintAbort) {
    try { STATE._taintAbort.abort(); } catch (_) {}
  }
  const ctrl = new AbortController();
  STATE._taintAbort = ctrl;
  const reg = $("taint-reg").value || "x0";
  const cont = $("taint-out");
  const startCursor = STATE.cursor;
  const loadAll = !!(opts && opts.loadAll);
  cont.innerHTML = `<div class="dim">running ${dir} from #${startCursor} reg=${reg}` +
                   (loadAll ? ' (load all)' : '') + '…</div>';
  $("taint-cancel").style.display = "";
  try {
    const params = new URLSearchParams({start: startCursor, reg});
    if (loadAll) {
      params.set("max_count", TAINT_LOAD_ALL_CAP);
    } else if (STATE.settings.taintLimit > 0) {
      params.set("max_count", STATE.settings.taintLimit);
    }
    const url = `/api/${dir}-taint?` + params.toString();
    const resp = await fetch(url, {signal: ctrl.signal});
    const r = await resp.json();
    if (ctrl.signal.aborted) return;
    if (r.status === "building" || r.status === "idle") {
      cont.innerHTML = '<div class="dim">building index…</div>';
      setTimeout(() => { if (STATE._taintAbort === ctrl) doTaint(dir, opts); }, 1500);
      return;
    }
    const list = r.hits || r.chain || [];
    const stopped = !!r.stopped_at_max;
    let html = `<div class="dim">${list.length} 条 (from #${startCursor})</div>`;
    if (stopped) {
      html += `<div class="dim taint-cap-banner">` +
              `⚠ 已截断: 显示 ${list.length}/?, ` +
              `<a href="#" id="taint-loadall">加载全部</a>` +
              `</div>`;
    }
    for (const h of list)
      html += `<div class="lp-row" data-idx="${h.idx}">` +
              `<span>${escapeHtml(h.asm)}</span>` +
              `<span class="meta">#${h.idx}</span></div>`;
    cont.innerHTML = html;
    bindRowClicks(cont);
    if (stopped) {
      const btn = document.getElementById("taint-loadall");
      if (btn) btn.onclick = (ev) => {
        ev.preventDefault();
        doTaint(dir, {loadAll: true});
      };
    }
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

// ── Call Tree (P0-1) ────────────────────────────────────────────────────────
function initCallTreeTab() {
  const cont = $("lp-calltree");
  cont.innerHTML = `
    <div class="lp-toolbar">
      depth <input id="ct-depth" class="inp" type="number" value="50" min="1" max="500" size="4">
      <button class="btn" id="ct-load">load</button>
    </div>
    <div id="ct-out"><div class="dim">点 load 构建调用树</div></div>`;
  $("ct-load").onclick = loadCallTree;
}

async function loadCallTree() {
  const cont = $("ct-out");
  cont.innerHTML = '<div class="dim">building tree...</div>';
  const depth = $("ct-depth").value || 50;
  try {
    const r = await fetch(`/api/call-tree?max_depth=${depth}`).then(x => x.json());
    cont.innerHTML = renderCallTreeHtml(r.tree);
    bindRowClicks(cont, ".ct-node");
  } catch (e) {
    cont.innerHTML = `<div class="dim">error: ${e.message || e}</div>`;
  }
}

function renderCallTreeHtml(node, indent = 0) {
  const fn = node.fn || "?";
  const trunc = node.truncated_children
    ? ` <span class="dim">(+${node.truncated_children} 截断)</span>` : "";
  const pad = "  ".repeat(indent);
  let html = `<div class="ct-node lp-row" data-idx="${node.enter_idx}">` +
             `<span>${pad}${escapeHtml(fn)}</span>` +
             `<span class="meta">[#${node.enter_idx}–#${node.exit_idx}]${trunc}</span>` +
             `</div>`;
  for (const c of (node.children || []))
    html += renderCallTreeHtml(c, indent + 1);
  return html;
}

// ── Forks (P1-C M6) ──────────────────────────────────────────────────────
function initForksTab() {
  const cont = $("lp-forks");
  cont.innerHTML = `
    <div class="lp-toolbar">
      <select id="fk-status-filter" class="inp">
        <option value="">all</option>
        <option value="success">success</option>
        <option value="success_partial">partial</option>
        <option value="failed_ptrace_conflict">F3 ptrace conflict</option>
        <option value="failed_spawn_gate_unavailable">F7 spawn-gate</option>
        <option value="not_attempted">not attempted</option>
        <option value="not_attempted_long_lived">not_attempted (alive)</option>
        <option value="not_attempted_short_lived">not_attempted (gone)</option>
        <option value="not_attempted_observed">not_attempted (observed)</option>
      </select>
      <button class="btn" id="fk-load">load</button>
    </div>
    <div id="fk-out"><div class="dim">点 load 拉 fork events</div></div>`;
  $("fk-load").onclick = loadForkEvents;
}

async function loadForkEvents() {
  const cont = $("fk-out");
  cont.innerHTML = '<div class="dim">loading…</div>';
  const status = $("fk-status-filter").value;
  const url = "/api/fork-events" + (status ? `?status=${status}` : "");
  try {
    const r = await fetch(url).then(x => x.json());
    if (r.count === 0) {
      cont.innerHTML = '<div class="dim">no fork events. ' +
        'agent 端用 <code>--enable-fork-hook</code> 采集.</div>';
      return;
    }
    let html = `<div class="dim">${r.count} fork events</div>`;
    for (const e of r.events) {
      const failed = (e.attach_status || "").startsWith("failed_");
      const cls = failed ? "fk-row fk-failed" : "fk-row";
      const sym = e.parent_pc_rel || e.parent_pc || "?";
      const flags = e.clone_flags ? ` flags=${e.clone_flags}` : "";
      const lc = e.lifecycle ? `, runtime=${e.lifecycle.runtime_ms}ms` : "";
      html += `<div class="${cls} lp-row" data-idx="${e.trace_idx || 0}" ` +
              `title="${escapeHtml(e.attach_status || 'unknown')}${flags}${lc}">` +
              `<span>${escapeHtml(e.syscall || '?')} → child ${e.child_pid}</span>` +
              `<span class="meta">@${sym} #${e.trace_idx || '?'}</span></div>`;
    }
    if (r.events.some(e => (e.attach_status || "").startsWith("failed_"))) {
      html += `<div class="dim taint-cap-banner">⚠ 有失败的 fork — ` +
              `推 <a href="https://github.com/ltlly/miku-shield">miku-shield</a> ` +
              `处理 fork-based anti-debug</div>`;
    }
    cont.innerHTML = html;
    bindRowClicks(cont, ".fk-row");
  } catch (e) {
    cont.innerHTML = `<div class="dim">error: ${e.message || e}</div>`;
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
        <option value="fnoff"${s.addrFormat==="fnoff"?" selected":""}>func+offset (myFunc+0xb0)</option>
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
  applyAddrFormatToHeader();
  renderViewport();
}

// fmt-fn (fnoff/soFnOff) 时 #asm-col 加 class, header 跟着隐藏 func 列.
function applyAddrFormatToHeader() {
  const col = $("asm-col");
  if (!col) return;
  const f = STATE.settings.addrFormat;
  col.classList.toggle("fmt-fn", f === "fnoff" || f === "soFnOff");
}

// 列宽拖拽: localStorage 持久化, CSS var 实时驱动 row + header.
const COL_WIDTH_KEY = "tracemiku-col-widths";
const COL_DEFAULTS = {idx: 60, pc: 100, func: 200, "pc-fnoff": 240};
const COL_MIN = {idx: 30, pc: 60, func: 60, "pc-fnoff": 100};

function loadColWidths() {
  try {
    const raw = localStorage.getItem(COL_WIDTH_KEY);
    return raw ? {...COL_DEFAULTS, ...JSON.parse(raw)} : {...COL_DEFAULTS};
  } catch { return {...COL_DEFAULTS}; }
}
function saveColWidths(w) {
  localStorage.setItem(COL_WIDTH_KEY, JSON.stringify(w));
}
function applyColWidths(w) {
  const col = $("asm-col");
  if (!col) return;
  // fmt-fn 模式 pc 列也用 pc-fnoff 宽度 (header 不会显示 func)
  // 普通模式用 pc / func 各自宽度.
  col.style.setProperty("--col-idx", w.idx + "px");
  col.style.setProperty("--col-pc", w.pc + "px");
  col.style.setProperty("--col-func", w.func + "px");
  col.style.setProperty("--col-pc-fnoff", w["pc-fnoff"] + "px");
}

function setupColResize() {
  const widths = loadColWidths();
  applyColWidths(widths);
  applyAddrFormatToHeader();

  const header = $("stream-header");
  if (!header) return;
  header.querySelectorAll(".col-resize").forEach(handle => {
    handle.addEventListener("mousedown", ev => {
      ev.preventDefault();
      const colKey = handle.dataset.col;
      // fmt-fn 模式拖 pc handle, 改的是 pc-fnoff (因为该模式 row 用 --col-pc-fnoff)
      const isFmtFn = $("asm-col").classList.contains("fmt-fn");
      const targetKey = (colKey === "pc" && isFmtFn) ? "pc-fnoff" : colKey;
      const startX = ev.clientX;
      const startW = widths[targetKey];
      const minW = COL_MIN[targetKey] || 30;
      handle.classList.add("dragging");
      document.body.style.cursor = "col-resize";
      const onMove = e => {
        const w = Math.max(minW, startW + (e.clientX - startX));
        widths[targetKey] = w;
        applyColWidths(widths);
      };
      const onUp = () => {
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        handle.classList.remove("dragging");
        document.body.style.cursor = "";
        saveColWidths(widths);
      };
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  });
}

// ---------------- help system ----------------
// 每个 panelhead 上的 ? 按钮触发. data-help 字符串决定显示哪段 doc.
// 部分 panel 是动态的 (左侧 lp-tab 切, 右侧 rtab 切, 中下 btab 切),
// 我们用 data-help="left-panel" / "right" / "bottom" 后再根据当前 active sub-tab
// 选 sub-doc.
const HELP_DOC = {
  overview: { title: "traceMiku Web — 总览", html: `
<p>左 = 函数列表/调用栈/字符串/污点等多 tab; 中 = 反汇编流 + 内存; 右 = CFG / 寄存器 / HLIL.
   光标 (cursor) 在 trace 里的当前指令 = 三个区共享的状态; 移动 cursor → 全部 follow.</p>
<h4>顶栏快捷键</h4>
<ul>
<li><kbd>j</kbd> / <kbd>k</kbd> 单步 (下/上); <kbd>↓↑</kbd> 同</li>
<li><kbd>PgDn</kbd> / <kbd>PgUp</kbd> 翻 20 条</li>
<li><kbd>g</kbd> / <kbd>G</kbd> 跳 trace 头/尾</li>
<li><kbd>:N</kbd> 跳到第 N 条 (输入数字)</li>
<li><kbd>/</kbd> 搜索反汇编 (regex)</li>
<li><kbd>Esc</kbd> 关闭弹窗 (帮助 / 命令栏)</li>
</ul>
<h4>同步开关</h4>
<p>顶栏 "同步" toggle 控制 cursor 在右侧 CFG 是否自动 highlight + scroll. 大 trace 切换函数时关闭可省 dot 重渲染.</p>
` },

  disasm: { title: "Disassembly (反汇编流)", html: `
<p>每行 = 一次 trace 记录 (一条指令的执行快照). 列从左到右:
<code>圆点 #idx 地址 func+offset asm ; 注释</code></p>
<h4>圆点 = 该 PC 的执行频次</h4>
<table>
<tr><td><span class="swatch" style="background:#444c56"></span></td><td>1 次</td></tr>
<tr><td><span class="swatch" style="background:#58a6ff"></span></td><td>2-9 次</td></tr>
<tr><td><span class="swatch" style="background:#3fb950"></span></td><td>10-99 次</td></tr>
<tr><td><span class="swatch" style="background:#f7b32b"></span></td><td>100-999 次</td></tr>
<tr><td><span class="swatch" style="background:#f85149"></span></td><td>1000+ 次 (热路径)</td></tr>
</table>
<h4>asm 颜色</h4>
<p>BN 后端 ready 后, 视口里的指令会自动升级到 BN 词法着色 (mnem / reg / num / sym / brace 各色), 跟右侧 Graph BN-CFG 一致. BN 没载入时 fallback 到 capstone 字符串 + 寄存器名 regex 着色:</p>
<ul>
<li><span style="color:#c9d1d9">浅灰粗</span> = mnem (指令助记符)</li>
<li><span style="color:#79c0ff">蓝</span> = 寄存器名</li>
<li><span style="color:#ffa657">橙</span> = 立即数 / 括号 / 数据 sym</li>
<li><span style="color:#d2a8ff">紫</span> = 函数 sym (sub_xxx / 导入)</li>
<li><span style="color:#f2cc60">黄</span> = struct 字段名</li>
<li><span style="color:#a5d6ff">浅蓝</span> = 字符串字面量</li>
<li><span style="color:#8b949e">灰斜</span> = 注释</li>
</ul>
<h4>交互</h4>
<ul>
<li>点指令行 → setCursor</li>
<li>hover 寄存器名 → 显示当前值</li>
<li>双击寄存器名 → 跳上次 def</li>
<li>右键寄存器 → 菜单 (CFG/Memory at value/taint)</li>
<li>地址显示格式 (绝对 / func+offset / so@func+offset) 在左侧 Settings 切换</li>
</ul>
` },

  right: { title: "右侧面板 (Graph / Registers / HLIL)", html: `
<p>右侧 vertical tab 切换三个子面板. 当前显示哪个就看下面对应章节.</p>

<h3>Graph (CFG)</h3>
<h4>数据源 (上方 dropdown)</h4>
<ul>
<li><b>Trace CFG</b>: 仅包含 trace 真走过的 BB. 间接跳真 target 100% 准, 但函数死代码看不到.</li>
<li><b>BN ASM</b>: 完整函数所有 BB (BN 静态分析) + trace 命中染色 + 三色 edge.</li>
</ul>
<h4>BB 边框颜色 (BN 模式)</h4>
<table>
<tr><td><span class="swatch" style="background:#30363d"></span></td><td>0 次 (静态可达, trace 未踩 — 死代码 / 未触发)</td></tr>
<tr><td><span class="swatch" style="background:#1d4060"></span></td><td>低频 (1-9)</td></tr>
<tr><td><span class="swatch" style="background:#3fb950"></span></td><td>中频 (10-99)</td></tr>
<tr><td><span class="swatch" style="background:#d8a040"></span></td><td>高频 (100-999)</td></tr>
<tr><td><span class="swatch" style="background:#f85149"></span></td><td>热路径 (1000+)</td></tr>
<tr><td><span class="swatch" style="background:#d2a8ff"></span></td><td>当前 cursor 所在 BB</td></tr>
</table>
<h4>Edge 颜色 (BN 模式)</h4>
<table>
<tr><td><span class="swatch" style="background:#3fb950"></span></td><td>true (cond taken)</td></tr>
<tr><td><span class="swatch" style="background:#f85149"></span></td><td>false (cond fall-through)</td></tr>
<tr><td><span class="swatch" style="background:#58a6ff"></span></td><td>uncond (无条件)</td></tr>
<tr><td><span class="swatch" style="background:#d2a8ff"></span></td><td>indirect (br/blr 间接跳, OLLVM dispatch)</td></tr>
<tr><td><span class="swatch" style="background:#bc8cff"></span></td><td>call / ret</td></tr>
<tr><td>实线</td><td>trace 走过 (static + dynamic 都见)</td></tr>
<tr><td>虚线</td><td>static-only (BN 知道但 trace 没走)</td></tr>
<tr><td><span style="color:#f85149">红粗实</span></td><td>dyn-only (trace 真走但 BN 没标 — OLLVM 间接跳真 target, 金矿信号)</td></tr>
</table>
<h4>交互</h4>
<ul>
<li>鼠标拖动 = pan; <kbd>Ctrl</kbd>+滚轮 = zoom; 滚轮 = 垂直滚动</li>
<li>点 BB 内任意 insn 行 → setCursor 跳 trace</li>
<li><b>fit</b> 按钮: 按宽度自适应缩放</li>
<li><b>reload</b> 按钮: 强制重新渲染 dot (改 source 后用)</li>
</ul>

<h3>Registers</h3>
<p>当前 cursor 时刻 31 个通用寄存器 + sp + pc 的值. 跟 pwndbg 配色:</p>
<ul>
<li>变化的 reg (相比 cursor-1) → <span style="color:#f85149">红色加粗</span></li>
<li>智能解引用注释 (右列):
  <ul>
    <li><code>[func+0xN]</code> 代码指针</li>
    <li><code>→ "string"</code> 字符串指针</li>
    <li><code>[SP+0xN]</code> 栈指针</li>
    <li><code>(JavaHeap)</code> / <code>(libart?)</code> 已知 region</li>
    <li>多级 deref 链 <code>→ 0x... → "..."</code></li>
  </ul>
</li>
</ul>

<h3>HLIL (反编译伪代码)</h3>
<p>由 BN/Ghidra/IDA 后端 (<code>--so PATH</code> 启动时指定) 提供. 当前 cursor 所在函数显示完整 HLIL, 行号 = 该 stmt 起始 PC.</p>
<h4>Token 着色 (BN dark theme 风)</h4>
<ul>
<li><span style="color:#ff7b72">关键字</span> (if/return/uint64_t)</li>
<li><span style="color:#79c0ff">寄存器</span> (x0/sp)</li>
<li><span style="color:#56d4dd">变量/参数</span> (var_64/arg1)</li>
<li><span style="color:#ffa657">数字/常量</span></li>
<li><span style="color:#a5d6ff">字符串</span></li>
<li><span style="color:#d2a8ff">函数符号</span> (sub_xxx/imports — 可双击)</li>
<li><span style="color:#ffa657">data 符号</span> (data_xxx — 可双击)</li>
<li><span style="color:#f2cc60">struct field</span></li>
</ul>
<h4>交互</h4>
<ul>
<li>当前 PC 对应行 → 黄色背景 + 左竖条</li>
<li>点 HLIL 任意行 → setCursor 跳到该 PC 在 trace 离 cursor 最近的执行</li>
<li>双击 fn / data token (紫/橙文字) → 跳到该地址在 trace 里的某次执行 (跨函数 navigate)</li>
<li>cursor 在同一函数内移动 → 仅更新高亮, 不重渲染 (不闪烁)</li>
</ul>
<h4>后端状态</h4>
<p>启动时 BN load SO ~30-60s; 之后单函数查询 ~5ms. 缓存到 <code>~/.cache/tracemiku/decomp/cache.db</code>, 下次复用.</p>
` },

  "left-panel": { title: "左侧面板 — 帮助按当前 tab 显示", html: `
<p>左侧 vertical tabs: Functions / Backtrace / Strings / Taint / Cross Ref / Settings.</p>

<h3>Functions</h3>
<p>trace 中走过的所有函数, 按调用次数降序. 点函数 → 跳到第一次进入它的 trace 位置 + 右侧 Graph 切到这个函数.</p>

<h3>Backtrace</h3>
<p>cursor 处的 call stack (栈底 → 栈顶). 每帧 = 一个 bl/blr 还没 ret. 点帧 → 跳到调用点 trace idx.</p>

<h3>Strings</h3>
<p>从 trace 内存写入还原出来的 ASCII 字符串. <kbd>双击</kbd> → provenance: 这串字节是谁逐字节写的, 谁读的.</p>

<h3>Taint (污点追踪)</h3>
<ul>
<li><b>From idx</b>: 起点 (默认 cursor)</li>
<li><b>Reg</b>: 起点寄存器名 (e.g. x0)</li>
<li><b>Forward</b>: 跟踪后续被该 reg 污染的指令</li>
<li><b>Backward</b>: 回溯该 reg 当前值是哪条指令 def 的, 顺着 def-chain 找根源</li>
</ul>

<h3>Cross Ref</h3>
<p>当前 cursor 处 PC 在整个 trace 中所有出现 (= PC 执行历史). 点 → 跳那一次.</p>

<h3>Settings</h3>
<p>各种显示限制 (条数 / 行数), 地址格式 (绝对 / func+offset / so@func+offset). localStorage 持久化.</p>
` },

  bottom: { title: "中下面板 (Memory / Call Tree / Navigation / Trace for PC)", html: `
<h3>Memory</h3>
<p>输入 <code>0x...</code> 或寄存器名 (sp/x0/...) → hex+ASCII dump. 默认 16 行 × 16 字节 (Settings 可调).</p>
<h4>字节颜色</h4>
<ul>
<li><span style="color:#6e7681">暗灰</span> = 该字节 trace 没读过也没写过</li>
<li>白 = 读过 (从 register 装载)</li>
<li><span style="color:#3fb950">绿</span> = 写过 (从 register 存储)</li>
</ul>
<h4>交互</h4>
<ul>
<li>双击 <span style="color:#3fb950">绿</span> 字节 → 跳到第一次 write 该字节的 trace idx</li>
<li>拖选字节范围, 右键 → 菜单 (readers / writers / 跳第一个 R-or-W)</li>
</ul>

<h3>Call Tree</h3>
<p>函数调用树 (整 trace). 还在开发.</p>

<h3>Navigation</h3>
<p>cursor 历史栈 (类似浏览器前进后退). 还在开发.</p>

<h3>Trace for PC</h3>
<p>显示某 PC 在 trace 里所有出现的 idx, 按 cursor 分前后. 通过点击 CFG 的 ASM 行或 trace 指令触发.</p>
` },
};

let HELP_OPEN_FOR = null;   // 当前打开 help 的 panel id

function setupHelp() {
  // 全局 click delegation: 触发器 (.help-btn) 弹出, popover 外部点击关闭
  document.addEventListener("click", (ev) => {
    const btn = ev.target.closest(".help-btn");
    if (btn) {
      ev.stopPropagation();
      let id = btn.dataset.help;
      // 左侧 left-panel: 当前 active lp-tab 决定子内容. 暂用 left-panel 总说明.
      // (后续如需精细化可加 tab-specific doc 但当前一份 doc 已经覆盖所有 lp tabs)
      const doc = HELP_DOC[id];
      if (!doc) return;
      showHelp(doc, btn);
      return;
    }
    // 点 popover 内部不关闭 (除了 close-x 已在内部处理)
    const pop = $("help-popover");
    if (pop && !pop.classList.contains("hidden") && !pop.contains(ev.target)) {
      hideHelp();
    }
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") hideHelp();
  });
}

function showHelp(doc, anchorEl) {
  const pop = $("help-popover");
  const cnt = $("help-popover-content");
  cnt.innerHTML = `<span class="close-x" id="help-close">×</span>`
                + `<h3>${escapeHtml(doc.title)}</h3>`
                + doc.html;
  pop.classList.remove("hidden");
  // 定位: 锚点下方; 若超出右侧则左移; 若超出底部则上翻
  const r = anchorEl.getBoundingClientRect();
  pop.style.left = "0px";   // tmp 让 measure 干净
  pop.style.top = "0px";
  pop.style.visibility = "hidden";
  const pr = pop.getBoundingClientRect();
  let left = r.right - pr.width;          // 默认左对齐到 ? 按钮的右侧 (popover 长在 ? 左下方)
  if (left < 8) left = 8;
  let top = r.bottom + 6;
  if (top + pr.height > window.innerHeight - 8) {
    top = Math.max(8, r.top - pr.height - 6);
  }
  pop.style.left = left + "px";
  pop.style.top  = top + "px";
  pop.style.visibility = "visible";
  HELP_OPEN_FOR = doc.title;
  $("help-close").addEventListener("click", (ev) => {
    ev.stopPropagation(); hideHelp();
  });
}
function hideHelp() {
  const pop = $("help-popover");
  if (pop && !pop.classList.contains("hidden")) {
    pop.classList.add("hidden");
    HELP_OPEN_FOR = null;
  }
}

// ---------------- DEC4 — Trace Decompiler tab (右侧, 跟 HLIL 同级) ----------------
//
// Token 经济:
//  - dec_summary 缓存 (per hooks/memshadow). server 已 cache 不重算.
//  - LLM 输出 cache (client-side, by fn_id+model+lang+useMem). 重复点不重发.
//  - prompt token 估值显示 (在 fn 列表 + 反编译按钮提示).
//
// 当前能选的 fn 是 calltree 切的 top-K (默认 K=10 → F0-F9). 改 split_top_k
// 让 fn 列表加长 (用户反馈太少). 通过 ?split_top_k=N URL 参数支持.

let DEC_SELECTED_FN = null;
const DEC_CACHE = {};   // key = fn_id|model|lang|useMem|tier → result

async function initDecompileTab() {
  // 拉 model key status
  try {
    const r = await fetch("/api/dec/models").then(r => r.json());
    const k = r.api_keys_configured || {};
    const status = Object.entries(k).map(([n, v]) =>
      `${n}: ${v ? "✓" : "✗"}`).join(" · ");
    $("dec-key-status").textContent = "API keys: " + status;
  } catch (e) {
    $("dec-key-status").textContent = "load model status fail: " + e;
  }
  $("dec-refresh").addEventListener("click", loadDecSummary);
  $("dec-llm-call").addEventListener("click", runDecLlmCall);
  $("dec-llil").addEventListener("click", runDecLlilRender);
  $("dec-vm-mem").addEventListener("change", loadDecSummary);
  $("dec-tier").addEventListener("change", () => {
    if (DEC_SELECTED_FN) selectDecFn(DEC_SELECTED_FN);
  });
  loadDecSummary();
}

function _decUrl(useMem) {
  // split_top_k / split_min_records 从 UI input 取 (默认 40/10).
  // CLI 默认 10/50 更保守, UI 给更多 fn.
  const params = new URLSearchParams();
  if (useMem) params.set("with_memshadow", "1");
  const k = ($("dec-split-k") && $("dec-split-k").value) || "40";
  const m = ($("dec-split-min") && $("dec-split-min").value) || "10";
  params.set("split_top_k", k);
  params.set("split_min_records", m);
  return params.toString() ? "?" + params.toString() : "";
}

async function loadDecSummary() {
  const list = $("dec-fn-list");
  list.innerHTML = '<div class="dim">building IR (1-3s)…</div>';
  const useMem = $("dec-vm-mem").checked;
  const url = "/api/dec/summary" + _decUrl(useMem);
  let s;
  try {
    s = await fetch(url).then(r => r.json());
  } catch (e) {
    list.innerHTML = '<div class="dim">load failed: ' + e + '</div>';
    return;
  }
  // VM candidates summary
  let vm = "";
  if (s.vm_candidates && s.vm_candidates.length) {
    const v = s.vm_candidates[0];
    vm = `<div class="dec-vm-summary">VM: dispatcher 0x${v.dispatcher_pc.toString(16)}` +
         ` (conf ${v.confidence.toFixed(2)})` +
         (v.reader_inst ? ` · reader: <code>${escapeHtml(v.reader_inst)}</code>` : "") +
         (v.bytecode_addr ? ` · bytecode @0x${v.bytecode_addr.toString(16)}` +
           ` (${v.hex_dump_lines} hex lines)` : "") +
         "</div>";
  }
  // fn list — 显示估值 token 让 user 提前感知 cost
  const items = (s.fns || []).map(f => {
    // 估值: blocks * 600 chars / 4 (粗估), summary 级 100
    const estChars = f.blocks * 600 + 200;
    const estTokens = Math.round(estChars / 4);
    return `<div class="dec-fn-item" data-fn="${f.id}" title="entry idx=${f.entry_idx}, exit=${f.exit_idx}, ~${estTokens} prompt tokens">
       <span class="dec-fn-id">${f.id}</span>
       <span class="dec-fn-name">${escapeHtml(f.name)}</span>
       <span class="dec-fn-stats dim">blk=${f.blocks} loop=${f.loops} call=${f.calls}` +
       (f.type_anchors ? ` anc=${f.type_anchors}` : "") +
       ` ~${estTokens}tok</span>
     </div>`;
  }).join("");
  list.innerHTML =
    `<div class="dim small">trace ${s.records} rec / module ${s.module_name || "?"} / ${s.fns.length} fns</div>` +
    vm + items;
  list.querySelectorAll(".dec-fn-item").forEach(el => {
    el.addEventListener("click", () => selectDecFn(el.dataset.fn));
  });
  if (s.fns && s.fns.length) selectDecFn(s.fns[0].id);
}

async function selectDecFn(fnId) {
  DEC_SELECTED_FN = fnId;
  const list = $("dec-fn-list");
  list.querySelectorAll(".dec-fn-item").forEach(el =>
    el.classList.toggle("dec-fn-selected", el.dataset.fn === fnId));
  const out = $("dec-output");
  out.innerHTML = '<div class="dim">loading IR…</div>';
  const useMem = $("dec-vm-mem").checked;
  const tier = $("dec-tier").value || "hot";
  const k = ($("dec-split-k") && $("dec-split-k").value) || "40";
  const m = ($("dec-split-min") && $("dec-split-min").value) || "10";
  let qs = `?tier=${tier}` + (useMem ? "&with_memshadow=1" : "") +
           `&split_top_k=${k}&split_min_records=${m}`;
  const url = `/api/dec/fn/${encodeURIComponent(fnId)}${qs}`;
  try {
    const r = await fetch(url).then(r => r.json());
    const md = r.markdown || "";
    const estTokens = Math.round(md.length / 4);
    $("dec-cost-hint").textContent =
      `当前 fn IR ≈ ${md.length.toLocaleString()} chars / ~${estTokens.toLocaleString()} tokens. ` +
      `点 反编译 调 LLM (中文模式 + cache, 重点不重发)`;
    out.innerHTML = `<div class="dec-fn-md"><pre>${escapeHtml(md)}</pre></div>`;
  } catch (e) {
    out.innerHTML = '<div class="dim">load failed: ' + e + '</div>';
  }
}

async function runDecLlmCall() {
  if (!DEC_SELECTED_FN) {
    alert("先选一个 fn");
    return;
  }
  const model = $("dec-model").value;
  const useMem = $("dec-vm-mem").checked;
  const lang = $("dec-zh").checked ? "zh" : "en";
  const tier = $("dec-tier").value || "hot";
  const cacheKey = `${DEC_SELECTED_FN}|${model}|${lang}|${useMem}|${tier}`;
  const out = $("dec-output");
  // client cache 命中 → 不重发, 省 token
  if (DEC_CACHE[cacheKey]) {
    const r = DEC_CACHE[cacheKey];
    out.innerHTML = _renderDecResult(r, true);
    return;
  }
  out.innerHTML = `<div class="dim">calling LLM (${model}, ${lang}) — 30-90s, 请稍等…</div>`;
  const t0 = Date.now();
  try {
    const r = await fetch("/api/dec/llm-call", {
      method: "POST",
      headers: {"content-type": "application/json"},
      body: JSON.stringify({
        fn_id: DEC_SELECTED_FN,
        model: model,
        with_memshadow: useMem,
        lang: lang,
        tier: tier,
        split_top_k: parseInt(($("dec-split-k") && $("dec-split-k").value) || "40", 10),
        split_min_records: parseInt(($("dec-split-min") && $("dec-split-min").value) || "10", 10),
      }),
    }).then(r => r.json());
    r._client_ms = Date.now() - t0;
    if (!r.ok) {
      out.innerHTML = `<div class="dec-error">LLM error: ${escapeHtml(r.error || "")}</div>`;
      return;
    }
    DEC_CACHE[cacheKey] = r;
    out.innerHTML = _renderDecResult(r, false);
  } catch (e) {
    out.innerHTML = '<div class="dec-error">request failed: ' + escapeHtml(String(e)) + '</div>';
  }
}

function _renderDecResult(r, fromCache) {
  const tag = fromCache ? " · <b style='color:#888'>(cache 命中, 0 token)</b>" : "";
  const meta = `<div class="dim small">${r.model} · ${r.in_tokens}→${r.out_tokens} tok` +
               ` · server ${r.latency_ms}ms${tag}</div>`;
  return meta + `<div class="dec-llm-out"><pre>${escapeHtml(r.c_code || "")}</pre></div>`;
}

async function runDecLlilRender() {
  if (!DEC_SELECTED_FN) { alert("先选一个 fn"); return; }
  const useMem = $("dec-vm-mem").checked;
  const k = ($("dec-split-k") && $("dec-split-k").value) || "40";
  const m = ($("dec-split-min") && $("dec-split-min").value) || "10";
  const out = $("dec-output");
  out.innerHTML = `<div class="dim">running LLIL 8-pass pipeline (lift→SSA→constfold→dce→typelat→struct→restructure→render)...</div>`;
  const t0 = Date.now();
  try {
    const r = await fetch("/api/llil/render", {
      method: "POST",
      headers: {"content-type": "application/json"},
      body: JSON.stringify({
        fn_id: DEC_SELECTED_FN,
        with_memshadow: useMem,
        split_top_k: parseInt(k, 10),
        split_min_records: parseInt(m, 10),
      }),
    }).then(r => r.json());
    const dt = Date.now() - t0;
    if (!r.ok) {
      out.innerHTML = `<div class="dec-error">LLIL pipeline error: ${escapeHtml(r.error || "")}<br><pre>${escapeHtml(r.traceback || "")}</pre></div>`;
      return;
    }
    const cacheTag = r.cache_hit ? " <b>(cache 命中)</b>" : "";
    const s = r.stats || {};
    const uidf = s.uidf_observed
      ? ` · UIDF=${s.uidf_const}/${s.uidf_observed} const`
      : "";
    const meta = `<div class="dim small">LLIL 8-pass · fn=${r.fn_id} ${r.name || ""} · `
               + `blocks=${s.blocks} · lift=${s.lift_total} (${(s.lift_coverage*100).toFixed(1)}%覆盖) · `
               + `constfold=${s.constfold_count} · dce=${s.dce_removed} · `
               + `structs=${s.struct_shapes}${uidf} · ${dt}ms${cacheTag}</div>`;
    out.innerHTML = meta + `<div class="dec-llm-out"><pre>${escapeHtml(r.c_code || "")}</pre></div>`;
  } catch (e) {
    out.innerHTML = '<div class="dec-error">request failed: ' + escapeHtml(String(e)) + '</div>';
  }
}

// ---------------- go ----------------
init();
