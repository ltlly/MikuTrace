// traceMiku web — IDA-style split SPA
// 单进程: FastAPI 后端 + 这一份 vanilla JS 前端. 无构建工具.

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
  pageSize: 100,
  cache: new Map(),         // start -> records[] window
  cacheKeys: [],            // LRU
  cy: null,
  cfg: null,                // {blocks, edges, blockById}
  activeBlockPc: null,
  prevRegs: null,
};

// ---------------- bootstrap ----------------
async function init() {
  STATE.meta = await api("/api/meta");
  STATE.totalRecords = STATE.meta.records;
  $("meta").textContent =
    `${STATE.meta.module ? STATE.meta.module.name : "?"}` +
    `  ${STATE.totalRecords.toLocaleString()} 条`;
  $("trace-info").textContent = `${STATE.totalRecords.toLocaleString()} 条`;
  buildVirtualList();
  setupTabs();
  setupKeys();
  setupCmd();
  // 立即渲染 trace + regs, 不等 CFG.
  setCursor(0, /*scrollIntoView=*/true);
  // 默认只加载入口函数的 CFG (1913 -> ~50 块, 避免 cytoscape 主线程 freeze).
  // 用户可以点 "show all" 切到全图. cursor 走出函数边界时自动跟随新函数.
  const r0 = await api("/api/record/0");
  pollCFG(r0?.func || null);
}

// 默认 CFG 只渲染当前光标所在函数 (~50 个块, 不是 1913).
// 大 CFG 全图渲染 cytoscape 主线程 freeze 数秒. 单函数视图秒响应.
STATE.cfgFunc = null;        // 当前正在渲染的函数名 (null = 全图)
STATE.allFuncs = [];

async function pollCFG(func = null) {
  $("cfg-info").textContent = func ? `loading ${func}…` : "loading…";
  let tries = 0;
  while (true) {
    const r = await api("/api/cfg", func ? {fn: func} : {});
    if (r.status === "ready") {
      STATE.cfgFunc = func;
      STATE.allFuncs = r.funcs || [];
      renderCFG(r);
      setCursor(STATE.cursor, false);
      return;
    }
    tries++;
    const elap = (r.elapsed && r.elapsed.cfg) ? r.elapsed.cfg.toFixed(1) : "?";
    $("cfg-info").textContent = `building… cfg=${r.cfg} pc_inst=${r.pc_inst} (${elap}s)`;
    if (r.errors && Object.keys(r.errors).length) {
      $("cfg-info").textContent = "error: " + JSON.stringify(r.errors);
      return;
    }
    await new Promise(res => setTimeout(res, tries < 5 ? 500 : 2000));
  }
}

// ---------------- virtualized trace list ----------------
function buildVirtualList() {
  const stream = $("stream");
  // single tall spacer giving correct scroll height
  stream.innerHTML = "";
  const totalH = STATE.totalRecords * STATE.rowHeight;
  const inner = document.createElement("div");
  inner.style.position = "relative";
  inner.style.height = totalH + "px";
  inner.id = "stream-inner";
  stream.appendChild(inner);

  let renderTok = 0;
  stream.addEventListener("scroll", () => {
    const tok = ++renderTok;
    requestAnimationFrame(() => { if (tok === renderTok) renderViewport(); });
  });
  // first paint
  requestAnimationFrame(renderViewport);
}

async function renderViewport() {
  const stream = $("stream");
  const inner = $("stream-inner");
  const top = stream.scrollTop;
  const bot = top + stream.clientHeight;
  const startIdx = Math.max(0, Math.floor(top / STATE.rowHeight) - 5);
  const endIdx = Math.min(STATE.totalRecords, Math.ceil(bot / STATE.rowHeight) + 5);

  // fetch missing windows of pageSize
  const need = [];
  for (let i = startIdx; i < endIdx; i += STATE.pageSize) {
    const winStart = Math.floor(i / STATE.pageSize) * STATE.pageSize;
    if (!STATE.cache.has(winStart)) need.push(winStart);
  }
  if (need.length > 0) {
    await Promise.all(need.map(s =>
      api("/api/records", { start: s, count: STATE.pageSize }).then(r => {
        STATE.cache.set(s, r.records);
        STATE.cacheKeys.push(s);
        if (STATE.cacheKeys.length > 200) {
          const old = STATE.cacheKeys.shift();
          STATE.cache.delete(old);
        }
      })
    ));
  }

  // remove rows out of viewport
  inner.querySelectorAll(".row-insn").forEach(el => {
    const i = parseInt(el.dataset.idx);
    if (i < startIdx || i >= endIdx) el.remove();
  });

  // render new rows
  const present = new Set([...inner.querySelectorAll(".row-insn")].map(e => parseInt(e.dataset.idx)));
  for (let i = startIdx; i < endIdx; i++) {
    if (present.has(i)) continue;
    const winStart = Math.floor(i / STATE.pageSize) * STATE.pageSize;
    const win = STATE.cache.get(winStart);
    if (!win) continue;
    const r = win[i - winStart];
    if (!r) continue;
    const row = document.createElement("div");
    row.className = "row-insn";
    if (r.is_call)   row.classList.add("is-call");
    if (r.is_ret)    row.classList.add("is-ret");
    if (r.is_branch && !r.is_call && !r.is_ret) row.classList.add("is-branch");
    if (i === STATE.cursor) row.classList.add("active");
    row.dataset.idx = i;
    row.style.position = "absolute";
    row.style.top = (i * STATE.rowHeight) + "px";
    row.style.left = 0;
    row.style.right = 0;
    row.style.height = STATE.rowHeight + "px";
    const fn = r.func ? `${r.func}+${r.off}` : (r.rel || r.pc);
    row.innerHTML =
      `<span class="idx">#${r.idx}</span>` +
      `<span class="pc">${r.pc}</span>` +
      `<span class="func">${fn}</span>` +
      `<span class="asm">${escapeHtml(r.asm)}</span>`;
    row.addEventListener("click", () => setCursor(i, /*scroll*/false));
    inner.appendChild(row);
  }
}

function escapeHtml(s) {
  return s.replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
}

// ---------------- cursor + sync ----------------
// 关键: 滚动/连续按键时, 仅更新轻量 UI (active row, status), 把重活
// (regs fetch + CFG highlight) debounce 到停 80ms 后再做. 1913-node
// 的 cy.animate/center 每次都重渲, 不 debounce 滚 j/k 即冻屏.
let _cursorDebounce = null;
function setCursor(idx, scrollIntoView = false) {
  if (idx < 0) idx = 0;
  if (idx >= STATE.totalRecords) idx = STATE.totalRecords - 1;
  STATE.cursor = idx;
  // 立即: active row + scroll
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
  $("status").textContent = `#${idx}  …`;
  // 重活 debounce
  if (_cursorDebounce) clearTimeout(_cursorDebounce);
  _cursorDebounce = setTimeout(async () => {
    const cur = STATE.cursor;
    if (cur !== idx) return;     // 用户又跳走了, 跳过
    const r = await api("/api/record/" + cur);
    if (STATE.cursor !== cur) return;  // 第二道保险
    renderRegs(r);
    // 跨函数自动切 CFG 视图 (单函数模式下)
    if (r.func) maybeSwitchCfgFunc(r.func);
    highlightBlock(r.block_pc);
    $("status").textContent = `#${cur}  ${r.pc}  ${r.asm}`;
  }, 80);
}

function renderRegs(r) {
  const cont = $("tab-regs");
  const regs = r.regs || {};
  const grid = document.createElement("div"); grid.className = "regs-grid";
  const order = ["x0","x1","x2","x3","x4","x5","x6","x7",
                 "x8","x9","x10","x11","x12","x13","x14","x15",
                 "x16","x17","x18","x19","x20","x21","x22","x23",
                 "x24","x25","x26","x27","x28","fp","lr","sp","pc"];
  for (const nm of order) {
    if (!(nm in regs)) continue;
    const cell = document.createElement("div"); cell.className = "reg";
    if (STATE.prevRegs && STATE.prevRegs[nm] !== regs[nm]) cell.classList.add("changed");
    cell.innerHTML = `<span class="rn">${nm}</span><span class="rv">${regs[nm]}</span>`;
    grid.appendChild(cell);
  }
  cont.innerHTML = ""; cont.appendChild(grid);
  STATE.prevRegs = regs;
}

// ---------------- CFG ----------------
function renderCFG(payload) {
  STATE.cfg = payload;
  const total = payload.total_block_count || payload.block_count;
  const filt = STATE.cfgFunc ? ` · ${STATE.cfgFunc}` : ` · all funcs`;
  $("cfg-info").textContent = `${payload.block_count}/${total} blocks · ${payload.edge_count} edges${filt}`;
  // populate function select
  const sel = $("cfg-func-select");
  if (sel && (!sel._populated || STATE.allFuncs.length !== sel._lastFuncCount)) {
    sel.innerHTML = `<option value="">— all funcs (${total} blocks, slow) —</option>` +
      STATE.allFuncs.map(f => `<option value="${escapeHtml(f.name)}">${escapeHtml(f.name)} (${f.blocks})</option>`).join("");
    sel._populated = true;
    sel._lastFuncCount = STATE.allFuncs.length;
  }
  if (sel) sel.value = STATE.cfgFunc || "";

  const elements = [];
  for (const b of STATE.cfg.blocks) {
    elements.push({ data: { id: b.id, label: `${b.rel || b.start}\n${b.label}\n×${b.executions}`,
                            executions: b.executions, start: b.start } });
  }
  for (const e of STATE.cfg.edges) {
    elements.push({ data: { id: e.id, source: e.src, target: e.dst, kind: e.kind, count: e.count } });
  }
  if (STATE.cy) STATE.cy.destroy();
  STATE.cy = cytoscape({
    container: $("cy"),
    elements,
    layout: { name: "dagre", rankDir: "TB", nodeSep: 22, rankSep: 36 },
    style: [
      { selector: "node", style: {
          "background-color": "#1f2630",
          "border-color": "#30363d",
          "border-width": 1,
          "color": "#d0d7de",
          "shape": "round-rectangle",
          "label": "data(label)",
          "text-wrap": "wrap",
          "text-valign": "center", "text-halign": "center",
          "text-max-width": 280,
          "font-family": "monospace",
          "font-size": 10,
          "padding": 6,
          "width": "label", "height": "label",
        }
      },
      { selector: "node.active", style: {
          "background-color": "#2d4060",
          "border-color": "#58a6ff", "border-width": 2,
          "color": "#ffffff",
        }
      },
      { selector: "node.hot", style: {
          "border-color": "#f78166",
        }
      },
      { selector: "edge", style: {
          "width": 1, "line-color": "#444c56",
          "target-arrow-color": "#444c56",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          "label": "data(count)",
          "color": "#6e7681",
          "font-size": 8,
          "text-background-color": "#0e1117",
          "text-background-opacity": 1,
          "text-background-padding": 2,
        }
      },
      { selector: "edge[kind = 'taken']", style: { "line-color": "#3fb950", "target-arrow-color": "#3fb950" } },
      { selector: "edge[kind = 'fall']",  style: { "line-color": "#444c56" } },
    ],
  });
  // mark hot blocks (top 10% executions)
  const all = STATE.cfg.blocks.map(b => b.executions).sort((a,b)=>b-a);
  const cutoff = all[Math.floor(all.length*0.1)] || 0;
  STATE.cy.nodes().forEach(n => {
    if ((n.data("executions") || 0) >= cutoff && cutoff > 1)
      n.addClass("hot");
  });
  STATE.cy.on("tap", "node", async (evt) => {
    const blockPc = evt.target.data("start");
    const r = await api("/api/idxs-for-block",
                        { pc: blockPc, max_count: 1, near: STATE.cursor });
    if (r.idxs && r.idxs.length > 0) setCursor(r.idxs[0], true);
    showBlockDetail(blockPc);
  });
  $("btn-fit").onclick = () => STATE.cy.fit();
  $("btn-reload-cfg").onclick = () => pollCFG(STATE.cfgFunc);
  const fnSel = $("cfg-func-select");
  if (fnSel && !fnSel._wired) {
    fnSel.addEventListener("change", () => { pollCFG(fnSel.value || null); });
    fnSel._wired = true;
  }
  // 单函数视图 → fit; 全图 → center on active
  if (STATE.cfg.block_count <= 200) {
    STATE.cy.fit();
  } else {
    STATE.cy.zoom(1.0);
    const active = STATE.activeBlockPc && STATE.cy.getElementById(STATE.activeBlockPc);
    if (active && active.length) STATE.cy.center(active);
    else STATE.cy.center();
  }
}

// 当 cursor 跨函数边界时, 自动切到新函数的 CFG 视图. 无开销 — 只
// 当 func 变化才重新 fetch + render.
async function maybeSwitchCfgFunc(newFunc) {
  if (newFunc === STATE.cfgFunc) return;
  if (!newFunc) return;
  // 仅当当前在单函数模式时自动切; 全图模式不变
  if (STATE.cfgFunc === null && STATE.allFuncs.length === 0) return;
  // 用户在全图模式 → 别强迫切单函数
  if (STATE.cfgFunc === null) return;
  await pollCFG(newFunc);
}

function highlightBlock(pcHex) {
  if (!STATE.cy) return;
  // 同一个 block 不重做 pan/redraw — 比 1913-node 全量 redraw 省很多
  if (pcHex === STATE.activeBlockPc) return;
  STATE.cy.nodes().removeClass("active");
  if (!pcHex) { STATE.activeBlockPc = null; return; }
  const n = STATE.cy.getElementById(pcHex);
  if (n && n.length) {
    n.addClass("active");
    STATE.activeBlockPc = pcHex;
    // 直接 center, 不 animate. 1913 节点逐帧 redraw 会冻屏.
    STATE.cy.center(n);
  }
}

async function showBlockDetail(pc) {
  const b = await api("/api/block", { pc });
  const cont = $("tab-block");
  let html = `<div><b>Block ${b.start} → ${b.end}</b> · `;
  if (b.func) html += `${b.func}+${b.off} · `;
  html += `executions: ${b.executions}</div><br>`;
  for (const ins of b.insns) {
    html += `<div class="hit-row">` +
            `<span class="idx">${ins.rel || ""}</span>` +
            `<span class="pc">${ins.pc}</span>` +
            `<span></span><span class="asm">${escapeHtml(ins.asm)}</span><span></span></div>`;
  }
  html += `<br><div>exits:</div>`;
  for (const e of b.exits) html += `<div>→ ${e.to} (${e.kind})</div>`;
  cont.innerHTML = html;
  switchTab("block");
}

// ---------------- tabs ----------------
function setupTabs() {
  document.querySelectorAll(".tab").forEach(t => {
    t.addEventListener("click", () => switchTab(t.dataset.tab));
  });
  // taint
  $("ft-btn").onclick = () => doTaint("forward");
  $("bt-btn").onclick = () => doTaint("backward");
  $("search-btn").onclick = doSearch;
  $("search-q").addEventListener("keydown", e => { if (e.key === "Enter") doSearch(); });
}
function switchTab(name) {
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".tabbody").forEach(b => b.classList.toggle("hidden", b.id !== "tab-" + name));
  if (name === "strings") loadStrings();
}

let _stringsLoaded = false;
async function loadStrings() {
  if (_stringsLoaded) return;
  _stringsLoaded = true;
  $("strings-out").textContent = "loading…";
  const r = await api("/api/strings", { min_len: 4 });
  let html = "";
  for (const s of r.strings.slice(0, 500))
    html += `<div>${s.addr} (${s.len}) ${escapeHtml(JSON.stringify(s.str))}</div>`;
  $("strings-out").innerHTML = html || "<div class=dim>no strings</div>";
}

async function doTaint(dir) {
  const reg = $("taint-reg").value || "x0";
  const r = await api(`/api/${dir}-taint`, { start: STATE.cursor, reg });
  const out = $("taint-out");
  const list = r.hits || r.chain || [];
  let html = `<div class=dim>${list.length} 条 · from #${r.from} reg=${r.reg}</div>`;
  for (const h of list)
    html += `<div class="hit-row" data-idx="${h.idx}">` +
            `<span class="idx">#${h.idx}</span>` +
            `<span class="pc">${h.pc}</span>` +
            `<span class="func">${h.func || ""}</span>` +
            `<span class="asm">${escapeHtml(h.asm)}</span>` +
            `<span class="why">${escapeHtml(h.why || h.via || "")}</span></div>`;
  out.innerHTML = html;
  out.querySelectorAll(".hit-row").forEach(el => {
    el.addEventListener("click", () => setCursor(parseInt(el.dataset.idx), true));
  });
}

async function doSearch() {
  const q = $("search-q").value.trim();
  if (!q) return;
  const r = await api("/api/search", { pattern: q });
  const out = $("search-out");
  let html = `<div class=dim>${r.count} 条 · pattern=${escapeHtml(r.pattern)}</div>`;
  for (const h of r.hits)
    html += `<div class="hit-row" data-idx="${h.idx}">` +
            `<span class="idx">#${h.idx}</span>` +
            `<span class="pc">${h.pc}</span>` +
            `<span class="func">${h.func || ""}</span>` +
            `<span class="asm">${escapeHtml(h.asm)}</span><span></span></div>`;
  out.innerHTML = html;
  out.querySelectorAll(".hit-row").forEach(el => {
    el.addEventListener("click", () => setCursor(parseInt(el.dataset.idx), true));
  });
}

// ---------------- keyboard ----------------
function setupKeys() {
  window.addEventListener("keydown", (e) => {
    if (e.target.tagName === "INPUT") return;
    if (e.key === "j" || e.key === "ArrowDown") setCursor(STATE.cursor + 1, true);
    else if (e.key === "k" || e.key === "ArrowUp") setCursor(STATE.cursor - 1, true);
    else if (e.key === "PageDown") setCursor(STATE.cursor + 20, true);
    else if (e.key === "PageUp")   setCursor(STATE.cursor - 20, true);
    else if (e.key === "g") { /* lower g: top */ setCursor(0, true); }
    else if (e.key === "G") { setCursor(STATE.totalRecords - 1, true); }
    else if (e.key === "/") { e.preventDefault(); openCmd("/", v => { $("search-q").value = v; switchTab("search"); doSearch(); }); }
    else if (e.key === "f") { openCmd("ftaint reg=", v => { $("taint-reg").value = v.trim() || "x0"; switchTab("taint"); doTaint("forward"); }); }
    else if (e.key === "b") { openCmd("btaint reg=", v => { $("taint-reg").value = v.trim() || "x0"; switchTab("taint"); doTaint("backward"); }); }
    else if (e.key === ":") { openCmd(":", v => { const n = parseInt(v); if (!Number.isNaN(n)) setCursor(n, true); }); }
  });
}

// ---------------- minimal cmdbar ----------------
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
  inp.value = ""; inp.placeholder = ""; inp.style.display = "";
  inp.focus();
}
function closeCmd() {
  STATE._cmdCB = null;
  $("cmd-prompt").textContent = "";
  $("cmd-input").value = "";
}

// 让 cytoscape 跟随窗口大小变化
window.addEventListener("resize", () => {
  if (STATE.cy) { STATE.cy.resize(); STATE.cy.fit(); }
});

// 暴露给 dev/inspector 用 (不影响生产, 只是方便 debug)
window.TM = STATE;

// ---------------- go ----------------
init();
