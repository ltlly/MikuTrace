# PDF Viewer 功能对照

来源: [原创] 使用时间无关调试技术 (Timeless Debugging) 高效分析混淆代码  
作者: krash (看雪 thread-273055), 2022-05-29  
PDF: `example/[原创]使用时间无关调试技术(Timeless Debugging)高效分析混淆代码-Android安全-看雪安全社区｜专业技术交流与安全研究论坛.pdf`

PDF 共 25 页. 第 1-10 页是工具功能展示, 第 11-20 页是用工具实战分析 ollvm11 sample. 评论区 (第 21-25 页) 透露了一些设计细节.
作者将工具分两部分: trace 记录器 + trace 分析器 (此 doc 只对照"分析器", 即 viewer).

> **2026-05-01 更新**: TUI (`viewer/app.py`) 已**冻结**, 不再维护。Web SPA
> (`webui/`) 是当前主 UI; CLI (`python -m viewer ...`) + Python SDK
> (`from viewer import ...`) + REST API 是 LLM 友好接口三件套。本文档保留
> TUI 行号引用作为历史 — 具体当前实现请看 `viewer/__main__.py` 和
> `webui/server.py`。

> **核心设计哲学** (PDF p10, 第 21 楼回复):
> 1. 离线分析, 不依赖反混淆;
> 2. 自重建 CFG 对抗间接跳转混淆;
> 3. CFG 边"从块上方进入, 下方离开, 不穿过块, 不重合";
> 4. "亿级 trace 设计" (作者实测 9000w 条, 1.12GB).

---

## 已实现 ✓

### 主布局 + 三大基本面板
- **指令流视图 (左中央)** — 每行 `#编号  函数+offset  +rel  mnemonic ops`, cursor `▶` 标记 + 滚动跟随  
  实现: `viewer/app.py:49-145` (TUI `InsnStream`); `webui/app.js:95-158` (Web 虚拟列表, 200w 条丝滑)
- **寄存器视图 (右上)** — 全 33 寄存器 (x0..x28, fp, lr, sp, pc), 变化高亮 (★ 红色), pwndbg 风格智能解引用  
  实现: `viewer/app.py:150-192` (`RegPanel`); `viewer/display.py` (classify); `webui/app.js:200-217` (`renderRegs` + `.changed` class)
- **内存视图 (右中)** — hex+ascii dump, `??` 显示未访问字节, 按 `m` 可改地址  
  实现: `viewer/app.py:197-234` (`MemPanel`); `viewer/memshadow.py` (`MemShadow.hex_dump` 红色 dim `??`)
- **交叉引用视图 (右下 tab)** — `←` UD 链 + `→` DU 链 + 内存 op 显示读/写地址 size  
  实现: `viewer/app.py:239-273` (`XRefTab`); `viewer/index.py` (`Index.def_chain` / `use_chain`)
- **字符串视图 (右下 tab)** — 从 mem shadow 提取 ASCII run, 显示 addr + 内容  
  实现: `viewer/app.py:300-315` (`StringsTab`); `viewer/memshadow.py:129-156` (`find_strings`)
- **CFG 视图 (右下 tab + 全屏 Screen)** — 基本块列表/图形/文本三视图模式, 当前光标块自动同步选中  
  实现: `viewer/app.py:365-547` (`CFGTab`), `:553-684` (`CFGFullScreen`); `viewer/cfg_graph.py` (ASCII art)
- **块导航图 (右下 tab)** — 小方块矩阵, 颜色随执行频率, 当前块高亮  
  实现: `viewer/app.py:318-362` (`BlockMapTab`)

### 指令级元素
- **每条指令编号 (idx)** — `#1234567` 全局唯一  
  实现: `InsnStream.render` `app.py:117`; web `row.dataset.idx`
- **PC 相对偏移 (`+0x1234`)** — 模块内自动转 offset, 模块外显示绝对地址  
  实现: `viewer/app.py:40-44` (`fmt_addr`)
- **函数名 + 偏移注释** — `JNI_OnLoad+0x40` 等; 已知 libsgmainso 偏移内置  
  实现: `viewer/symbols.py:75-83` (`KNOWN_LIBSGMAINSO`)
- **分支高亮 (PDF 红箭头风格的色彩区分)** — branch 紫色, ret 红色, 模块外 dim  
  实现: `viewer/app.py:120-122`; web `row-insn.is-call/.is-ret/.is-branch`

### 交互 (键盘 + 鼠标)
- **方向键单步, PgUp/PgDn 翻页** — `viewer/app.py:55-62` BINDINGS
- **g 跳转 (按 idx / PC / @PC 列出全部)** — `viewer/app.py:937-963` `_do_goto`
- **/ 反汇编正则搜索 (中文化提示)** — `viewer/app.py:965-972`
- **d/u 跳到定义/使用** — `viewer/app.py:905-913`
- **f/b 正向/反向污点 (寄存器 prefill)** — `viewer/app.py:822-829, 986-1002`
- **m 设定内存地址 (寄存器名 / 16进制)** — `viewer/app.py:831-834, 974-984`
- **s 提取字符串** — `viewer/app.py:841-845`
- **C / B 构建 CFG / 块图; F 全屏 CFG** — `viewer/app.py:847-877`
- **Ctrl-S 导出 CFG dot, Ctrl-O 浏览器看 SVG** — `viewer/app.py:879-903`
- **鼠标点击指令 → 跳到该 idx** — `InsnStream.on_click` `app.py:126-134`; web `row.click → setCursor` `app.js:155`
- **鼠标滚轮单步** — `app.py:136-140`
- **CFG 块鼠标点击 → 跳到 trace 中该块** — web `app.js:299-305`

### 分析能力
- **重建 CFG (从 trace 恢复, 抗间接跳转混淆)** — `viewer/cfg.py:40-113` `build_cfg`
- **正向污点追踪 (寄存器 + 内存)** — `viewer/taint.py:32-69` `forward_taint`
- **反向污点追踪 (递归回溯到内存源)** — `viewer/taint.py:72-128` `backward_taint`
- **内存 shadow + ?? 标记** — `viewer/memshadow.py:55-127`
- **字符串自动提取 (ASCII run, min_len 可调)** — `viewer/memshadow.py:129-156`
- **PC 执行历史 (该 PC 在 trace 中所有 idx)** — Web `/api/idxs-for-pc` (`server.py:492-514`); 但 TUI 端只有 `goto @0xPC` 列表 (`app.py:942-952`)
- **基本块执行计数 + 出边显示** — `viewer/cfg.py` `Block.executions / exits`
- **CFG 热点块排序 + Top N 列表** — `viewer/app.py:394-396, 491-501`

### Web SPA (一些超出 PDF 的现代化)
- **多函数 CFG 切换 (按 fn 渲染单函数 ~50 块, 否则 cytoscape 卡顿)** — `webui/app.js:51-72, 326-334`
- **graphviz dot HTML 标签 + IDA 风格 SVG** — `webui/server.py:347-490` (条件分支绿/红, ret/call 紫, uncond 蓝)
- **跨函数自动切 CFG 视图** — `webui/app.js:326-334`
- **后台异步建 CFG/index/mem-shadow** — `webui/server.py:81-167` (子进程独立 GIL)

### CLI
- **`tracemiku query`: AI 友好 JSON 接口** — records / forward-taint / backward-taint / strings / cfg / search / func-summary  
  实现: `tracemiku:707-842`
- **`tracemiku list/info`: 多 call 元信息汇总** — `tracemiku:474-704`
- **`tracemiku web`: 启动 SPA** — `tracemiku:467-471`

---

## 部分实现 ⚠

- **指令计数器圆点 (per-instruction execution-count dot)**  
  PDF 第 2 页 (img-001 / pg2-002-001): 每条指令最左有一个小彩色圆点, 颜色随执行次数 (越花色 = 重复执行越多). 这是非常显眼的视觉特征.  
  当前: 行级别 only; 没有 per-PC 计数列. 可以从 `block_idxs` 反推单 PC 执行次数, 但没渲染.  
  缺: 渲染圆点 / 数字 (例如 `· × 1`, `▒ × 5`, `█ × 100+` 同 BlockMapTab 风格).
- **指令逐条注释列 (PDF 中的右侧注释如 `__vfprintf + fc libc`)**  
  PDF 第 2 页可见每条指令旁注释: `__vfprintf + 1f0 libc`, `// 这是相关推选` 等. 类似 IDA 边注.  
  当前: 只有函数+offset 在前缀, 没有结尾的语义注释 (如 `bl __vfprintf` → 自动加 `; libc::vfprintf`).  
  缺: call target 解析为外部 import; 内存 op 自动加 `; arg = "9b..."` 字符串.
- **CFG 图形 (Decompiler Layout)**  
  PDF 第 9-10 页: 作者参考 Ghidra Decompiler Layout, 强连通分量绘一起 / 返回块固定底部 / 循环不同色 / 缩进等级 / 边不穿块.  
  当前: graphviz dot Sugiyama 默认布局 + viewer/cfg_graph.py 简单 ASCII 树. 没实现自定义结构化算法 (强连通分量分组, 循环识别, 缩进着色).  
  缺: 真正的 Decompiler Layout 引擎; 强连通分量检测; 循环嵌套着色.
- **CFG 循环交互 (Alt+Click 选中所属循环)**  
  PDF 第 14 页: "使用 alt+单击 尝试选择 750bd55400 所在基本块所属循环".  
  当前: web `app.js:299` 只支持简单 tap → 跳块; 没有 alt+click 选中整个 SCC.  
  缺: 循环检测 + alt-click 高亮整个循环 + 显示循环出口 (PDF: "发现循环只有一个出口").
- **块导航图 (BlockMap)**  
  PDF 第 10 页 (img-021): 真正的 "块密度图", 每块 1 像素方格, 不同循环不同色, 当前块绿色, 返回块红色.  
  当前: TUI `BlockMapTab` 用 `· ▒ ▓ █` 字符按执行次数着色, 但**没有按循环分色**, 没有缩进等级显示.  
  缺: 循环检测 → 不同色; 嵌套缩进; Web 版完全没实现 (Web 只在 left-tabs 草图占位).
- **字符串视图的搜索 / 上下导航**  
  PDF 第 6 页 (img-011): "Search Strings" + Forward / Backward 按钮.  
  当前: TUI 一次显示前 500 条, 没有搜索框; Web 无搜索框 + 无内容 (一次性 dump).  
  缺: 字符串搜索框 + 双击跳到该地址在 mem 视图 / 跳到引用它的指令.
- **多线程 / 嵌套 trace 浏览**  
  PDF 第 23 页回复: "支持同时 trace 多个线程和嵌套 trace".  
  当前: 后端 `tracemiku` 已经支持 per-call 多文件 (`calls/_pending_call_*`), 但 viewer 一次只能开一个 .bin. 没有跨 call 切换 UI.  
  缺: TUI/Web 顶部切换 call 的 dropdown; 跨 call 关联 (caller→callee 跳转).
- **调用栈视图 (Backtrace)**  
  PDF 第 7 页 + 12 页 (img-009 截图带 Backtrace 字样): 显示当前 idx 的完整 frame 链, 点 frame 跳到调用方.  
  当前: web/index.html 第 25 行 `data-vtab="back" title="BackTrace"` 占位; 没有真正实现.  
  缺: 通过 sp / lr 重建 frame 链 (依赖 bl/blr/ret 配对); 跳到调用方功能.
- **Call Tree / Navigation 历史**  
  Web `index.html:51-58` 占位 `b-calltree` / `b-navigation` 显示 "pending".  
  缺: 全部实现.

---

## 未实现 ☐

### 高优先级 (PDF 直接展示, 反调试核心价值)
- **指令执行计数圆点 / 颜色** — 优先级: high — 思路: 对每个唯一 PC 在 trace 中的命中数预聚合 (复用 `pc_to_idxs`), `InsnStream.render` 行首加 `· ▒ ▓ █` 字符 + 颜色; 同时为 web 行加 `data-count=N` + CSS 着色.
- **PDF 第 12 页"格式化打印参数自动解" (call 时自动 attach 字符串 arg)** — 优先级: high — 思路: 检测 `bl <known_libc>` (sprintf, vfprintf, memcpy...) → 解析 ABI → 通过 mem shadow 解 x0..x7 args; 在指令流右侧追加 `; sprintf(buf, "%02x", 0x9b)`.
- **CFG 强连通分量分组 + 循环检测** — 优先级: high — 思路: Tarjan SCC on `cfg.edges`; 标记 loop headers; 块导航图 + CFG 全屏视图按 SCC id 上色; 提供 "select-loop" 命令 (alt+click 等价).
- **CFG Decompiler Layout (Ghidra 风格)** — 优先级: high — 思路: 实现 simple structuring algorithm: (1) 找回边构造 loop 区域; (2) 双路 cond 看作 if-else; (3) 多路看作 switch; (4) 拓扑排序后强制 ret 块到最底层. 输出每块 (depth, x_coord) 给 web 前端 SVG / dot 用.
- **Backtrace 面板 (调用栈)** — 优先级: high — 思路: 一次扫 trace, 维护 stack: 遇 bl/blr push, 遇 ret pop; 每条 record 关联当前 frame list; UI 列出 + 点击跳到调用方 (== bl 那条 idx).
- **指令右侧自动注释 (库函数, 字符串 arg, mem 内容)** — 优先级: high — 思路: ① call → 外部模块名 + 函数名 + 已知签名; ② mem op → 自动 `mem.byte_at()` 解读为 ASCII / 整数; ③ 跨语言: tag 系统 (用户也能添加 user comment).

### 中优先级 (PDF 提及但用户不一定立刻需要)
- **内存视图双击跳转到定义** — 优先级: mid — 思路: TUI `MemPanel` + Web 内存 hex grid 上点击 / 双击; 通过 `MemShadow.byte_at(addr, t)` 拿到 source_idx, `goto_idx(source_idx)`.
- **字符串视图: 搜索框 + 双击跳转 + 引用反查** — 优先级: mid — 思路: 字符串 -> 地址 -> 找 mem ops 触及该地址的所有 idx, 弹出 trace 列表.
- **指令历史 (per-PC) 面板独立化** — 优先级: mid — 思路: web 已有 `b-trace-for-pc` tab + `/api/idxs-for-pc`, 但没绑事件; TUI 只有 `goto @PC` 命令. 加专门 tab + 双击 PC 行/CFG 块即填充.
- **导航历史 (Back/Forward 跳转栈)** — 优先级: mid — 思路: 用户 d/u/f/b 跳一次都进 stack, Alt-Left/Right 回退/前进; web `b-navigation` 已占位.
- **Call Tree 树视图** — 优先级: mid — 思路: 复用 backtrace 数据, 渲染 `▾ JNI_OnLoad ──> ▾ doCommand ──> sub_xxx`, 点节点跳到该 call site idx.
- **CFG 边分类着色** (taken=绿, fallthrough=红, uncond=蓝, ret=紫, call=紫虚线) — 优先级: mid — 思路: web `cfg_svg` API 已经实现, 但 cytoscape 端 (`app.js:288-289`) 只区分 `taken/fall`. 同步两边的 kind 推断.
- **支持多 call 切换 / 跨 call 跳转** — 优先级: mid — 思路: server 接受 run 目录, 允许 GET `/api/calls` 列出, 切换 `t = load(call_dir)`; cross-call 跳转通过 caller/callee 关联.

### 低优先级 (作者提及但是次要)
- **VM-noise 自动过滤 (PDF 第 7 页)** — 优先级: low — 思路: 检测高频循环块 (执行 >> avg), 给"折叠"选项, 污点结果中也提供 "skip VM" 复选框. 实际上当前 forward_taint 自动跳过未污染指令, 已经达到类似效果; 进一步 VM-detect 可以延后.
- **CFG 边形状美化 (从块上方进入下方离开, 不穿块不重合)** — 优先级: low — 思路: graphviz `splines=ortho` 已开 (`server.py:389`), 进一步要自定义 routing 算法成本高, 收益低.
- **trace 元信息工具栏 (call#, tid, cmd, ret, ms)** — 优先级: low — 思路: TUI 已有 title 行 + status bar; web `meta` span. 都有但信息少, 可加 more.
- **导出 PNG / SVG 截图** — 优先级: low — 思路: web 端 `cytoscape.png()` 一行调用; TUI 端复用现有 `Ctrl-S` dot 导出.
- **批注/标签持久化 (user comment on insn)** — 优先级: low — 思路: 落地一个 sidecar `comments.json` 在 trace 目录, viewer 加载时合并显示.
- **更精细的内存值跟踪 (区分 r/w 不同时刻的值)** — 优先级: low — `MemShadow` 已记 (idx, byte, kind), 渲染时按 kind 着色 (绿=read, 黄=write).

---

## TODO 排序 (优先级)

1. **指令计数器圆点 + per-PC 颜色** — PDF 第一眼就能看到的视觉特征, 必须有.
2. **Backtrace 面板 + Call Tree** — Web 已经占位, 用户期待度高; 通过 bl/ret 配对一遍 trace 即可建栈.
3. **指令注释列 (call target / mem ASCII)** — PDF 截图密集出现, 极大提升可读性.
4. **CFG SCC + 循环检测 + Alt-click 选中循环** — PDF 重点宣传 (图布局); 也是块导航图正确着色的前提.
5. **CFG Decompiler Layout (替代 graphviz Sugiyama)** — 最长尾的工作, 但是是 PDF "独一无二的功能"; 至少先做局部改进 (强制 ret 块到底层 / 循环成员同 rank).
6. **块导航图按循环分色 + 嵌套缩进** — 紧跟 #4, 有 SCC 后立刻能做.
7. **PC 执行历史面板 (web `b-trace-for-pc` 兑现 + 双击 CFG 块自动填充)**.
8. **字符串视图搜索框 + 双击跳转**.
9. **内存视图双击跳到定义 (PDF 第 5 页明确演示)**.
10. **多 call 切换 UI (支持 `tracemiku` per-call run 目录)**.
11. **导航历史 (Back/Forward) + 用户批注**.
12. **VM-noise 折叠 / 边路由美化 / PNG 截图等长尾**.

---

## 附录: PDF 中明确出现的功能短语 (用于以后核对)

| 中文短语 (PDF 原文) | 页 | 当前状态 |
|---|---|---|
| 指令流视图 | 2 | ✓ |
| 寄存器视图 | 3 | ✓ |
| 内存视图 (`??` 未访问字节) | 4-5 | ✓ |
| 在内存中双击跳转到定义 | 5 | ☐ |
| 交叉引用视图 (`<-` UD / `->` DU) | 5 | ✓ |
| "00010679 w 4 0000007ff3e99d98" 内存写入者编号 | 5 | ✓ (XRefTab) |
| 字符串参考 ("杀手级功能") | 6 | ⚠ (无搜索) |
| 正向污点追踪 / 反向污点追踪 | 6-7 | ✓ |
| 调用栈 (跳转到上层调用者考察参数) | 7 | ☐ |
| 控制流图 (从 trace 重建抗间接跳转) | 8 | ✓ |
| Decompiler Layout (Ghidra 风格) | 8-9 | ☐ |
| 强连通分量绘一起 | 8 | ☐ |
| 函数返回块固定底层 | 8 | ☐ |
| 边尽可能向下跳转 | 8 | ⚠ (graphviz default) |
| 块导航图 (小创新, 独一无二) | 10 | ⚠ (无循环分色) |
| 可视化调试进度 | 10 | ✓ (BlockMap) |
| 识别循环头 (黄色) | 10 | ☐ |
| 不同循环不同颜色 | 10 | ☐ |
| 评估函数规模 / 复杂度 | 10 | ⚠ (热度色) |
| 字符串视图搜索 (img-011 Search 按钮) | 6 | ☐ |
| 内存搜索 ("使用第一字节 9b 进行搜索") | 11 | ✓ (反汇编搜索, 不是字节搜索) |
| 选中字节进行逆向污点追踪 (img-013) | 11-12 | ⚠ (TUI 只有 reg 不能 mem) |
| 指令执行历史 (PC 执行 5 次) | 16 | ⚠ (web API 有, UI 没) |
| Alt+单击 选中所属基本块所属循环 | 14 | ☐ |
| 循环退出条件考察 | 14 | ☐ |
| 标准 sha256 transform 函数级对比 | 16 | ☐ (未来工具增强) |
