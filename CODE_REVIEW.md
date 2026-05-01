# traceMiku 代码审查报告

> 2026-05-01, 基于 main 分支 commit 4317de7
> Reviewer 复核于 2026-05-01: 每条都核对了实际代码,标注 ✅/⚠️/❌ + 修订意见。
> **2026-05-01 二轮复核**: 用户决定 **TUI (`viewer/app.py`) 不再维护**, Web 是 UI 唯一目标, 同时要暴露 **AI 友好接口** (MCP / REST + JSON schema) 让 LLM 直接探索 trace。本文档已据此重排优先级。

**项目方向调整 (新)**:
1. **TUI 冻结**: `viewer/app.py` (1013 行 textual 应用) 和它依赖的 TUI-only 代码路径 **不再加新功能, 只对触及到的部分按需重构**。涉及 TUI 的优化建议一律降为最低优先级或撤回。
2. **Web 是唯一 UI**: `webui/server.py` + `webui/app.js` 是主要工作目标, 所有 UX 改进先在 Web 上实现。
3. **AI 友好接口** (新增第五节): 文档化的 REST + 稳定 JSON schema + MCP server, 让 Claude/LLM 把 trace 当成可探索的对象。这是工具产品化的关键步骤 (memory `feedback_focus_on_tool` — traceMiku 是产品)。

**复核摘要 (按新方向调整)**:
- ✅ 直接采纳: #4, #5, #6, #8, #10, #19 (6 条 — 真实问题, 修复明确)
- ⚠️ 部分采纳/需调整: #1, #3, #7, #9, #12, #14, #15, #17, #18, #20, #23
- ❌ 否决: #13 (会引入 bug), #21 (流式 trace 复杂度过高)
- 🚫 撤回 (因 TUI 冻结): #2 (TUI/Web 去重不再有意义), #11 (TUI dispatch 不再优化)
- 🆕 新功能: #16 (diff) backlog; #22 (CLI) / #24 (Python SDK) 并入新第五节"AI 友好接口"

**新的 quick win 顺序** (在文末完整表格):
1. ~~`collect_modules_from_trace` 真正实现 (#6)~~ ✅ DONE (`bd8cc4e` + `1a1819a`)
2. ~~`_addr_of` 抽到 `viewer/trace.py` (#4)~~ ✅ DONE (`bd8cc4e`)
3. ~~bare `except:` → `except Exception:` (#10)~~ ✅ DONE (`bd8cc4e`)
4. ~~`Record.reg()` 用 dict (#8)~~ ✅ DONE (`bd8cc4e`)
5. ~~`json.load(open())` → `Path.read_text()` (#9)~~ ✅ DONE (`bd8cc4e`)
6. `KNOWN_LIBSGMAINSO` 参数化 (#5) — 1 小时
7. **API JSON schema 文档化** (新, 第五节) — 半天, 是 AI 友好接口的前置

---

## 一、架构级重构建议

### 1. `server.py` 1588 行大文件拆分

`webui/server.py` 把 5 个不同职责混在一个文件里:

| 职责 | 行数范围 | 建议模块名 |
|------|----------|-----------|
| CFG 渲染 (dot/SVG/BN overlay) | 26-175 | `webui/cfg_render.py` |
| 子进程 CFG 构建 | 178-216 | `webui/bg_build.py` |
| BG 状态机 + 后台线程管理 | 272-362 | `webui/bg.py` |
| 20+ API endpoints | 369-1555 | `webui/api.py` (或按域拆: `api_trace.py`, `api_cfg.py`, `api_decomp.py`) |
| serve() 入口 | 1565-1588 | `webui/server.py` (仅入口) |

`_CFG_SVG_CACHE`, `_CFG_OVERLAY_CACHE` 这些手动管理的缓存 + FIFO eviction, 应该封装成一个 `LRUCache` 类, 被各处复用。

> **Reviewer ⚠️ 部分合理, 但被低估了改动量**
> - "5 个职责" 描述准确, 但 `make_app(trace_path)` 是个 1300 行闭包: `t / sym / BG / cache / DECOMP / _MODULES_CACHE` 都是闭包变量,不是 module 级。拆出去要把它们重构成 `class TraceServer` 或显式传参。**估时 1-2 天, 不是 quick win**。
> - 实际可低成本拆出去的是**纯函数**: `_html_esc / _classify_mnem / _MNEM_COLORS / _TOK_COLOR / _render_tokens_html / _format_insn_row / _build_block_label / _bn_bb_border_color / _split_mnem_ops_from_tokens / _render_dot_to_svg` (lines 28-175) — 这些没用闭包变量, 直接搬到 `webui/cfg_render.py` 即可,**真的是 quick win**。
> - `_subprocess_build_cfg_and_pcinst` (line 178) 是 module 级 (因为 multiprocessing 要 pickle), 已经独立。
> - LRUCache 封装: 当前两处缓存语义不一样 (`_CFG_SVG_CACHE` 按 `(fn, theme)` key, FIFO; `_CFG_OVERLAY_CACHE` 按 `fn_start` key, 也是 FIFO + size cap)。封装成 `LRUCache` 收益小。**优先级低**。
> - **建议**: 只做"纯函数搬迁"这一步, 不动 endpoints。等到 endpoint 数量再涨 30% 时再说 `webui/api/*.py`。

### 2. ~~TUI (`app.py`) 和 Web (`server.py`) 之间大量重复~~

> **🚫 撤回 (TUI 冻结后此条不再有意义)**
>
> TUI (`viewer/app.py`) 不维护后, 不存在"两端重复"问题 — 只剩一端 (Web)。**仍然要做**的只有一项: 抽 `viewer/formatter.py:record_to_dict(t, sym, idx) -> dict` 给 Web 的 `records()` / `one_record()` / 未来 MCP server 共用 (见第五节)。
>
> TUI 端的 `CFGTab.update_cursor_pc` / `cfg.py:write_dot()` 等细节 **不再优化**; `cfg.py:write_dot()` 还在被 TUI 的 Ctrl-S 用, 维持原状即可。如果将来彻底删掉 `viewer/app.py`, 顺手删掉 `cfg.py:write_dot` 和 `cfg.py:textual_summary`。
>
> 真正还要做的就只是 formatter 抽离 — 列在第五节作为"统一 record JSON 输出"的一部分。

### 3. `BG` dict 应该是一个类

当前写法:

```python
# 6 个 key x 5 个 field = 30 个 dict 路径, 没有类型检查
BG["cfg"]["status"] == "ready"
BG["cfg"]["data"]
```

建议:

```python
@dataclass
class BgTask:
    status: Literal["idle","building","ready","error"] = "idle"
    data: Any = None
    err: Optional[str] = None
    started_at: float = 0.0
    ready_at: float = 0.0

class BgManager:
    cfg: BgTask
    pc_inst: BgTask
    ...
```

> **Reviewer ⚠️ 合理, 优先级低**
> - 现状已经有 `_bg_run(key, fn)` / `_bg_get(key, fn)` 抽象 (server.py:289-311), 比"30 个 dict 路径"难看程度的描述要好。
> - 改成 dataclass 主要收益是 IDE 补全 + mypy 类型检查, 实际 bug 风险很低。
> - 改动会触及 6 个 BG key 的全部 reader (server.py 里 ~30 处 `BG[k]["status"]` / `BG[k]["data"]`), diff 大但机械。
> - **建议**: 留到下次大改 server.py 时一起做; 单独立个 PR 不值。

---

## 二、代码质量问题

### 4. `_addr_of()` 在 3 个文件中重复 ✅ DONE (`bd8cc4e`)

`taint.py:21`, `memshadow.py:25`, `display.py` 里都有几乎一样的 `_addr_of` 实现:

```python
def _addr_of(rec, mem_op_tuple):
    base, idx_reg, disp, sz, is_w = mem_op_tuple
    bv = rec.reg(base) if base in ALL_REGS else 0
    iv = rec.reg(idx_reg) if (idx_reg and idx_reg in ALL_REGS) else 0
    return (bv + iv + disp) & 0xffffffffffffffff
```

应该放在 `viewer/trace.py` 或新建 `viewer/insn_util.py`。

> **Reviewer ✅ 完全合理 (TUI 冻结后, 只剩 2.5 处重复)**
> - 核对: `taint.py:21` 和 `memshadow.py:25` 的实现逐字相同; `viewer/index.py:46-47` 内联了相同逻辑。
> - **更正原描述**: `display.py` **没有** `_addr_of` (grep 过), 实际重复是 `taint.py + memshadow.py + index.py` 三处。
> - **建议放置位置**: `viewer/trace.py` 末尾, 因为 `_addr_of` 概念上和 `Record.reg()` 一组 ("从 record 解出某个 mem op 的地址"), 不必新建文件。
> - 顺便: 三处 `& 0xffffffffffffffff` 也可以用 `np.uint64` 视图避免, 不过这是后话。

### 5. `KNOWN_LIBSGMAINSO` 硬编码在 `symbols.py:77`

```python
KNOWN_LIBSGMAINSO = {
    0x570b8: "JNI_OnLoad",
    0x5758c: "JNI_OnUnload",
    0x57770: "doCommandNative",
    0x1ab90c: "one_jni_onload",
    0x1aba64: "one_jni_onunload",
}
```

这是只针对特定 SO 版本的常量, 不应内嵌在核心模块里。建议:
- 外部化到 `symbols/known_offsets.json`
- 或让 `build_from_trace` 接受一个 `known_offsets: dict` 参数

> **Reviewer ✅ 合理**
> - 一致性: 这条违背了 memory 里记的 `feedback_focus_on_tool` ("traceMiku 是产品, libsgmainso 是 example") — viewer 是产品代码, 不该 hardcode example 的偏移。
> - **更优方案**: 让 `build_from_trace` 接 `known_offsets: dict[int,str] | None = None`, 调用方 (CLI / web entry) 从 `meta.json` 里读 `known_offsets` 字段或读外部 JSON。这样 default = `None` 时就纯走启发式 (bl 目标 + 第一个 PC), 跟具体 SO 完全解耦。
> - `KNOWN_LIBSGMAINSO` 的 sample 内容可以挪到 `examples/libsgmainso/known_offsets.json` 顺便给后人看。
> - 同时检查 `symbols.py:103-120` 的 "drop entries inside known" 逻辑 — 它依赖 `KNOWN_LIBSGMAINSO`, 改造后这部分要参数化。

### 6. `collect_modules_from_trace` 几乎是空壳 ✅ DONE (`bd8cc4e` + `1a1819a`)

`display.py:175`:

```python
def collect_modules_from_trace(trace: Trace, mem: MemShadow) -> list[tuple[int, int, str]]:
    out = []
    if trace.meta.module:
        m = trace.meta.module
        out.append((m.base, m.end, m.name))
    # Heuristic: scan unique pcs for "modules" (large clusters of addresses)
    return out  # <-- 注释说要做 heuristic, 但实际没实现
```

对 pwndbg 风格的寄存器解引用来说, 这是关键缺失 -- 现在只能识别 1 个 SO 的地址范围。

> **Reviewer ✅ 完全合理, 这是 #1 优先级实现项 (用户能直接感受)**
> - 现状: `display.py:175-183` 只返回 meta.module 一项, "Heuristic" 注释纯空话。
> - 后果是 `_classify_reg_value` (server.py:435) 对 `[libart.so+...]` / `[libc.so+...]` 一类指针只能 fallback 到 `_heuristic_region` 的粗暴 hash (`(value >> 56) == 0xb4` → "JavaHeap"), 大部分非主 SO 的 code-pointer 显示成裸 hex。
> - **实现思路** (复核更新: 比预期简单得多):
>   - **tracer 已经调了 `Process.enumerateModules()`** — `agent_cmodule_v5.js:210` 和 `agent_generic.js:55` 都有, 但只 `send({type:"module", ...})` 了匹配 `soPattern` 的那一个 (v5:247, generic:330)。**改法: 在 `send` 前加循环遍历所有 modules 发送**, ~5 行 JS。
>   - **viewer 端**: `meta.json` 收到 `modules: [{name, base, size}, ...]` 数组后, `collect_modules_from_trace` 直接从 `trace.meta.modules` 构建 range list, ~10 行 Python。
>   - **不需要 PC 簇启发式** (来源 1 可砍掉), tracer 直接给的 module list 更可靠。
>   - **不需要 `/proc/pid/maps`** (来源 2 也可简化), `enumerateModules()` 已经返回 `{name, base, size}` — 等价信息。
>   - **meta.json schema** 加一个 `modules: [{name: str, base: int, size: int}]` 字段, 向后兼容 (旧 trace 没有此字段时 fallback 到 meta.module)。
> - **改动量**: tracer JS ~5 行 + viewer display.py ~10 行 + meta schema 1 字段。

### 7. 手写二分搜索应该用 `bisect`

`SymbolMap.lookup()` 和 `Index.def_chain()` 都手写了二分搜索:

```python
# 当前 (手写, trace.py / symbols.py 多处):
lo, hi = 0, len(self.functions)
while lo < hi:
    mid = (lo + hi) // 2
    if self.functions[mid][0] <= pc: lo = mid + 1
    else: hi = mid

# 建议:
import bisect
lo = bisect.bisect_right(self._starts, pc) - 1
```

标准库更简洁且经过 C 优化。

> **Reviewer ⚠️ 合理但收益微小**
> - 性能: `bisect` 是 C, 手写 Python 二分确实慢 5-10x; 但 `SymbolMap.lookup` 单次 O(log N), N≈1000 函数 → 10 次比较, 50 µs vs 5 µs, 用户感觉不到。
> - **更值的优化**: `SymbolMap` 维护 `self._starts: list[int]` 和 `self._names: list[str]` 两个并行 list (一个 O(log N) cache locality), 比当前的 `list[tuple[int,str]]` (Python tuple 包装慢) 略快。但同样不是瓶颈。
> - **真要做就一起做**: `Index.def_chain`/`Index.use_chain` (index.py:62-109) 也手写了二分, 一并替换可以减 ~30 行代码。可读性比性能收益大。
> - **建议**: 顺手做 (一次性改完所有手写二分,省得以后看到又想改), 但不单立 PR。

### 8. `Record.reg()` 用 `list.index()` 线性查找 ✅ DONE (`bd8cc4e`)

`trace.py:38`:

```python
def reg(self, name: str) -> int:
    ...
    i = REG_NAMES.index(name)  # O(N), 每次调用
    return self.regs[i]
```

`REG_NAMES` 有 31 个元素, 每次 `reg()` 调用都是 O(N) 线性扫描。应该预编译 dict:

```python
_REG_INDEX = {name: i for i, name in enumerate(REG_NAMES)}

# Record.reg() 里:
return self.regs[_REG_INDEX[name]]  # O(1)
```

> **Reviewer ✅ 合理, 是 quick win**
> - `Record.reg()` 在 `_addr_of` / index build / display.classify / mem shadow build 里高频调用; 单次 list.index 是 O(31) ≈ 比 dict O(1) 慢 5-10x。
> - 在 6.8M trace 上 mem shadow build 调 `_addr_of` 数百万次 → 节几秒不夸张。
> - **改动是 5 行代码, 0 风险, 立刻做**。
> - 同时把 `if name == "pc"/"sp"/"nzcv"` 三个 special case 也并入 dict (`{**REG_NAMES_idx, "sp": -3, "pc": -2, "nzcv": -1}` 加分支), 或者反过来 — 给 special case 一个 dict-of-callable, 整体更对称。但简单加 dict 已经够了。

### 9. `json.load(open(mp))` 多处文件句柄泄漏 ✅ DONE (`bd8cc4e`)

`trace.py:119,130,137` 等多处:

```python
_populate_meta(meta, json.load(open(mp)))  # 文件句柄靠 GC 关闭
```

在长时间运行的 server 中尤其不好。应该改为:

```python
with open(mp) as f:
    _populate_meta(meta, json.load(f))
```

> **Reviewer ✅ 合理**
> - 实际泄漏程度: CPython 引用计数会在 `json.load(open(mp))` 这条语句结束后立即关闭 fd (refcount=0), 真正"泄漏"几乎不发生。但 PyPy 不保证, 且这是公认的反模式。
> - 5 处都很短, **修起来就是机械的字符串替换**, 0 风险, 立刻改。
> - 同时检查 `symbols.py:146` 也有 `json.load(open(json_path))` — 一并修。
> - **建议**: 换种写法更紧凑 — `import json; json.loads(pathlib.Path(mp).read_text())`, 文件句柄根本不进 Python (read_text 内部 with), 还少一行 indent。

### 10. 大量 bare `except:` ✅ DONE (`bd8cc4e`)

`trace.py:74`, `server.py:216,325` 等:

```python
try: self._mm.close()
except: pass  # 吞掉所有异常, 包括 KeyboardInterrupt
```

至少应该用 `except Exception:`。

> **Reviewer ✅ 合理, 立刻做**
> - 已确认位置: `trace.py:74,76,123,156` + `server.py:216,326,330` 共 7 处 bare except。
> - 后果实例: ctrl-C 试退 server 时, `proc.terminate()` 那个 except 会吞掉 `KeyboardInterrupt`, 导致按一次 ctrl-C 没反应、按多次才退 — 用户层面就是体感问题。
> - **机械替换**, 0 风险。同时 grep `except:\s*pass` 全仓, 别漏。

### 11. ~~TUI 命令分发是 if/elif 链~~

> **🚫 撤回 (TUI 冻结)**
> TUI 不维护, 此项作废。原审查里的否决理由仍然成立 (5 个分支不值得 dispatch dict), 但现在更直接 — 这块代码不再触碰。

### 12. `MemShadow.build()` 内存效率

`memshadow.py:64` -- `self.bytes: dict[int, list]` 为每个被访问的字节地址维护一个 list。如果 trace 大量访问同一 buffer (比如解密循环), 这个 dict 可能膨胀到数 GB。numpy 视图 (w_idx/w_addr/r_idx/r_addr) 是后加的优化, 但原始 dict 仍然存在。

建议: build 时只维护 numpy arrays, `byte_at()` 查询用 numpy searchsorted, 彻底淘汰 per-byte dict。

> **Reviewer ⚠️ 描述对方向, 但建议有坑**
> - 现状确认: `self.bytes` (memshadow.py:59) 是 `dict[byte_addr] -> list[(idx, byte, kind)]`, 每个 list 元素是 Python tuple。一个 64-bit 写产生 8 个 entry; 6.8M trace 数百万 mem op → 数千万 entry → **GB 级内存是真的**。
> - **但"彻底淘汰 dict"行不通**: `byte_at(addr, t)` 是按 byte 查的; numpy 方案要 (a) 一个全局 sorted-by-(addr, idx) 的二维 array, (b) `searchsorted` 找 (addr, t)。这是可行的, 但要注意 byte-granularity 的展开 — 一个 8 字节 store 必须展开成 8 个 entry, 否则跨 store overlap 时返回错的字节。
> - **更好的优化方向 (按收益排序)**:
>   1. **不 splat to bytes**, 改成存 word-level events: `(idx, addr, size, value, kind)` 的 numpy 结构化数组; `byte_at(addr, t)` 查 `addr <= word_addr+word_size` 且 `word_addr <= addr` 的最近 event, 在线解 byte。**省 8x 内存**。
>   2. `find_strings` (memshadow.py:149-183) 每次扫 `sorted(self.bytes.keys())` 是 O(N log N), 已经 cache 了, OK。但配合上面 (1) 后要重写。
>   3. `hex_dump` 调 `byte_at` 一次循环 256 次, 配合 numpy mask 可以 vectorize, **省 100x 时间**。
> - **建议**: 这条留到内存确实超 4GB 时再做, 改造工作量 1-2 天。当前只在 6.8M trace 上没炸 → 可以先观察。

---

## 三、性能优化空间

### 13. `decode()` 的 lru_cache key 可以优化

`disasm.py:60` -- `(pc, inst)` 两个 int 做 key。由于 ARM64 指令 4 字节, 同一指令在不同 PC 的语义相同 (除了 PC-relative 寻址)。如果 trace 中同一指令出现在多个 PC, cache 命中率低。可以考虑只用 `inst` 做 key, PC 作为附加信息。

> **Reviewer ❌ 否决, 这条会引入 bug**
> - **作者自己已经写了警告**: "除了 PC-relative 寻址" — 但这个例外不是少数, ARM64 里 `adr / adrp / b / bl / b.cond / cbz/cbnz / tbz/tbnz / ldr <reg>, =literal` 全都依赖 PC, 解码出的 `branch_target` (disasm.py:120) 就是 PC + imm。
> - 而且 `Decoded.pc` 是 dataclass 字段 (disasm.py:36), 用 `(inst,)` 做 key 时 cache 第一次进来什么 PC, 后面所有同 inst 都返回那个 PC 的 Decoded, **branch_target 全错**, 整个 CFG / call graph / 函数命名都崩。
> - 实际 cache 命中率: 同一函数内同一指令 (重复执行 loop 里的 cmp/branch) PC 是固定的, `(pc,inst)` cache 命中 100%; 跨函数同一 inst 才会 miss, 但本来就是不同 PC, 不应该共享 Decoded (见上)。
> - **现状的 cache 是对的, 不要改**。

### 14. `cfg.py:build_cfg` 两次遍历 trace

`cfg.py:110` -- Pass 1 找 block boundaries, Pass 2 填充 blocks + edges。可以合并为单次遍历, 用 "first-seen PC -> new block start" 逻辑。

> **Reviewer ⚠️ 不建议改**
> - 两遍遍历的代价: 当前 Pass 1 只做 `t.pc(i) / t.inst(i) / decode(...)` (decode lru_cache 第一次填), Pass 2 又做一遍 — 但 decode 已 cache, Pass 2 的 decode 全是 cache hit。**实测两遍跟一遍差不了 20%**。
> - 合并逻辑是真的难: 两遍有"先发现所有边界, 再以边界为 boundary 填块"的清晰契约。合一遍要在中途动态 split 已存在的块 (后来发现某 PC 也是 boundary), 代码量翻倍, bug 风险大。
> - 子进程已独立 GIL (server.py:178), 用户感知是异步的; 主进程 API 没被它阻塞 — **当前架构已经把"build CFG 慢"这个问题挡掉了**。
> - **建议**: 不改 (满足 "Three similar lines is better than a premature abstraction" 的反向: 不要为微优化引入复杂度)。

### 15. `server.py:records()` 对每个 record 做 `decode()` + `sym.lookup()`

`server.py:385-429` -- 对 100 条记录的 viewport, 每条做两次查找。`decode` 有 cache, 但 `sym.lookup()` 每次触发 `_ensure_sorted()`。可以用 numpy vectorize 或 batch lookup。

> **Reviewer ⚠️ 描述里有事实错误, 但抽 formatter 仍合理**
> - **`_ensure_sorted` 每次都触发的说法是错的**: `symbols.py:30-33` 里 `if not self._sorted` 守卫, 第二次起直接跳过。后续 `sym.lookup` 是纯 O(log N) 二分。
> - 100 条 viewport 的实际成本: 100 * (decode cache hit) + 200 * (lookup 二分, 1000 函数 → 10 比较) ≈ < 5ms, **不是瓶颈**。
> - **真要做的 batch 思路**: 有用, 但收益小。numpy vectorize 不易 (lookup 返回 (str, int) 不是 numeric); 改成 `[bisect_right(starts, pc)-1 for pc in pcs]` 倒能省 Python 调用开销, 但 100 次循环本来就是 50 µs。
> - **真正的瓶颈在 `_classify_reg_value`** (server.py:435) — `/api/record/{idx}` 一次给 31 个 reg 各跑一次 classify, 每次内部 `deref_u64` 调 `mem.byte_at` 8 次 → 248 次 dict lookup + Python loop。这是 `one_record` 慢的真凶, 不是 `records()`。
> - **修订建议**: 抽 `viewer/formatter.py:record_to_dict` (合 #2 一起做), 同时给 `_classify_reg_value` 加 LRU cache (`(value, t_cursor//1000, sp//1024) → str`, t/sp 量化保 cache 命中率, 大部分 reg value 在相邻 record 不变)。

---

## 四、新功能建议

### 16. Trace Diff: 对比两个 trace

RE 场景下非常有用 -- 比较 "正常路径" vs "异常路径" 的寄存器差异和 CFG 覆盖差异。

实现思路:
- 加载两个 Trace 对象, 按 PC 对齐
- 输出 diff: 寄存器值差异, CFG 覆盖差异, 内存访问差异
- 前端 split-view 左右对比

> **Reviewer 🆕 价值高, 但需求要 brainstorm**
> - "按 PC 对齐"是个错觉: 真实场景下两个 trace 的 PC 序列长度不同 (cmd 70102 走 if, cmd 70103 走 else), 简单 zip 没意义。需要做 LCS / Myers diff。
> - 更实用的 v0: **CFG 块覆盖差异** 最简单 (block_starts 集合差) + **唯一访问的 PC 集合 diff** + **每个共享 PC 上 reg snapshot 的差异分布** (e.g. "x0 在 trace A 是 70102, B 是 0, 一致出现差异"). 这三个查询 30 行代码就能起一个原型。
> - **建议**: 留 backlog, 等遇到第二个 SO/cmd 对比的实际场景再做; 现在做就是过度设计 (memory `feedback_focus_on_tool` 提示工具优先)。

### 17. Per-function Trace Filter

当前所有 API 都作用于全 trace。增加 `?fn=doCommandNative` 参数, 让 trace 流只展示特定函数内的记录, 减少前端渲染压力。

> **Reviewer ⚠️ 已经有部分实现**
> - `/api/cfg?fn=...` 已经支持 fn 过滤 (server.py:538-603)。
> - 缺的是 `/api/records?fn=...` 这条 — 也确实有用, 比如分析 `JNI_OnLoad` 调用 chain 时只看本 fn 内的 record。
> - **实现简单**: 利用已有的 `BG["pc_to_block"]` + 找到 fn 的所有 block_start → 用 `BG["block_idxs"]` 拿 idx list → numpy `np.isin(viewport_idxs, fn_idxs)` 过滤。
> - **建议**: 中等优先级, 等 #6 (modules) 之后做。

### 18. Trace Export

- **SQLite**: 方便 SQL 查询 ("哪些 PC 访问了地址 X?", "x0 在哪些时刻等于 0x70102?")
- **Perfetto trace format**: 在 ui.perfetto.dev 里可视化时间线
- **JSON**: 给其他工具消费

> **Reviewer ⚠️ 三个里只有 SQLite 真正有用**
> - **SQLite ✅**: 6.8M record 写 SQLite ~ 几百 MB, 用户能用 `sqlite3` 命令行直接 grep 任意条件, 价值高。schema 推荐: `records(idx INTEGER PK, pc INTEGER, inst INTEGER, x0..x30 INTEGER, sp INTEGER)` + `CREATE INDEX ON pc`. 实现 50 行。
> - **Perfetto ⚠️**: Perfetto 是时间线 (一个事件一个 slice), 给 trace record 上时间戳很尴尬 (record 之间没真实时间, 只有"第 i 条")。用 idx 做时间戳的话, ui.perfetto.dev 显示不出 ARM64 语义优势。**不建议**, 除非 tracer 真的能采时间戳。
> - **JSON ❌**: SQLite 已经能 export 出 JSON; 不需要单独的 JSON exporter。
> - **建议**: 只做 SQLite。

### 19. `field_at()` 实现 (BN backend)

`binja.py:317` 的 `field_at()` 还是 stub:

```python
def field_at(self, pc: int, reg: str, offset: int) -> Optional[FieldHint]:
    # Stub for M0 -- needs HLIL operand walking. Implement in M2.
    return None
```

实现了这个, 就能在 trace 里看到:

```
ldr x9, [x8, 0x80]  ->  [pthread_mutex_t.__lock]
```

这样的结构体字段语义, 对逆向帮助巨大。

> **Reviewer ✅ 完全合理, 这是项目最大的逆向价值点之一**
> - 现状: `binja.py:317` 确实是 stub `return None`。
> - 实现路径: BN HLIL 已经有 type info → `bv.get_function_at(pc).hlil` → 找当前指令对应的 HLIL instruction → 看是否是 `HLIL_DEREF_FIELD` / `HLIL_STRUCT_FIELD` → 拿 type + offset → 返回 `FieldHint(type_name="pthread_mutex_t", field_name="__lock")`。
> - 难点: PC → HLIL instruction 的映射不是 1:1 (一条 ARM64 ldr 可能对应多条 HLIL); 用 `func.hlil.get_instruction_starts_at_address(pc)` 拿候选, 取 offset 匹配的那条。
> - **建议**: M2 milestone, 优先级仅次于 #6 (modules)。这两个一起做能让 web UI 的 hex dump 从 "raw bytes" 升级到 "annotated struct dump", 体验差异巨大。

### 20. Breakpoint/Watchpoint 条件过滤

在 Web UI 里支持 "当 x0 == 0x70102 时高亮" 这样的条件断点。底层用 numpy mask 实现, 前端加 filter bar。

> **Reviewer ⚠️ 价值高但 UX 设计是关键**
> - 底层用 numpy 是对的 — `t._mm` 已经是 mmap, 寄存器值在固定 offset, 可以直接 `np.frombuffer(...).reshape(-1, 34)` 拿全部 reg 矩阵 → `(matrix[:, 1] == 0x70102)` 一行解决。
> - **UX 难点**: 表达式语言 ("x0 == 0x70102 && pc in [0x..., 0x...]") 解析,前端语法是关键。最简版 v0: 单个 reg + 单个值 + 单个 op (==/!=/&), 30 行 frontend + 20 行 backend。
> - **建议**: 中等优先级, 配合 #17 一起做 (二者都是 "filter trace records" 的不同维度)。

### 21. Real-time Trace Streaming

当前是先 collect trace, 再加载分析。如果能支持 WebSocket streaming (Frida agent -> server -> browser), 可以实现实时 trace 观察。

> **Reviewer 🆕 不建议做**
> - 成本: tracer 端从 file output 改成 socket output, agent.js 大改; viewer 端要支持 "活 trace" — `Trace` 类的 mmap 假设 `n` 不变, 流式 trace `n` 是动态的, 要重写 cursor / index / CFG build 逻辑全部。
> - 逆向场景: 实际 RE 工作流是 "跑一次, 然后慢慢看", 不是"边跑边看"。实时性收益小。
> - **观点**: 留 backlog。除非 tracer 那边因为内存 cap (memory `feedback_dont_crash_device`) 被迫做流式, 才顺水推舟一起做。

### 22. CLI 工具链化

当前 CLI 入口只有 `python -m viewer`。建议增加:

```
tracemiku export --format sqlite trace_dir/
tracemiku search "mov x0" trace_dir/
tracemiku stats trace_dir/
tracemiku diff trace_a/ trace_b/
```

> **Reviewer ⚠️ 并入第五节 (AI 友好接口)**
>
> CLI 子命令本身价值小 (Web 已有搜索, search 重做无意义); 但配合"AI 友好"重新看, **`stats` 和 `export` 子命令是 LLM 通过 shell 探索 trace 的入口** — 让 Claude 一句 `python -m viewer stats path/` 就能拿到 trace 元信息, 比走 HTTP 简单。
>
> 见第五节, 这一项作为 "thin CLI for LLM shell access" 重新规划。

### 23. Pinned Bookmarks / Annotations

允许用户在 trace 的特定 idx 上打标签 ("这里 x0 是 JNIEnv*", "这个分支是关键判断"), 持久化到 meta.json。多人协作分析同一 trace 时尤其有用。

> **Reviewer ⚠️ 持久化位置应该改**
> - meta.json 是 tracer 写的, viewer 不应往里 mutate (会破坏 tracer/viewer 的边界)。
> - **应该**: 单独 `annotations.json` 文件, 跟 trace.bin 同目录, 由 viewer 读写。schema 简单 — `[{idx: int, type: "note"|"bookmark", text: str, ts: float}]`。
> - 实际逆向场景里确实有用 — 跨 session 保留笔记。Web UI 加个右键 "add note" + 侧边栏 list 就够。
> - **建议**: 中等优先级, 实现 ~80 行, 任何时候有空都能做。

### 24. Python SDK / REPL

提供 `from tracemiku import Trace; t = load("path")` 的 Python API, 让用户可以在 Jupyter/IPython 里交互式分析 trace 数据, 不需要启动 server。

> **Reviewer ⚠️ 并入第五节 (AI 友好接口)**
>
> 现状已经能用 (`from viewer.trace import load`); 真缺的是 **稳定 API + 文档**, 这正是 "AI 友好" 的题中之义 — LLM 用 BashTool 在 IPython 里探索 trace 就是 SDK 用法。
>
> 见第五节, 把这条放到 "Python API 稳定化 + cookbook 文档" 里实施。

---

---

## 五、AI 友好接口设计 🆕

> **目标**: 让 Claude / LLM 把 trace 当成可探索对象, 不必手动看 Web UI。
> 三层接口同时建, 各层独立有用、组合更强:
>   1. **REST API + 稳定 JSON schema** (Web 既存, 缺文档)
>   2. **MCP server** (`tracemiku-mcp`) — LLM 在自己 session 里直接调
>   3. **Thin CLI + Python SDK** — LLM 通过 BashTool 用 shell 用法探索

### 5.1 REST API JSON schema 文档化

**现状**: `webui/server.py` 已有 ~20 个 endpoint (`/api/meta`, `/api/records`, `/api/record/{idx}`, `/api/cfg`, `/api/block`, `/api/loops`, `/api/cfg-svg`, `/api/bn-cfg-svg-for-pc`, `/api/hlil-for-pc`, ...), 但:
- 返回结构散在代码里, 没有 spec 文档
- 字段命名不一致 (有些 `pc` 是 hex string `"0x..."`, 有些是 int; `func` 在没找到时返回 `None`, 别处可能返回 `"?"`)
- 没有版本号 / 没有错误格式 schema

**建议**:
- **使用 FastAPI 的 OpenAPI 自动文档** — 它已经在 `app = FastAPI(...)` 这里内建了, 访问 `/docs` 就有 Swagger UI, 关键是把 endpoint 的 response 改成 Pydantic model:

```python
class RecordRow(BaseModel):
    idx: int
    pc: str        # always hex "0x..."
    rel: str | None
    func: str | None
    off: str | None
    asm: str
    annotation: str | None
    exec_count: int | None
    is_branch: bool
    is_call: bool
    is_ret: bool

@app.get("/api/records", response_model=RecordsResponse)
def records(...): ...
```
  这样 `/openapi.json` 就有完整 schema, LLM 一拉就懂。

- **统一字段约定** (一次性梳理):
  - PC / 地址 / module base 永远输出 hex string (`"0x57770"`); 永不输出裸 int (避免 JSON 大整数精度问题)
  - 不存在/未知 一律 `None` (不要 `"?"` 不要 `""`)
  - 错误统一 `{"error": str, "code": str}` 不是各 endpoint 自定义

- **加 `/api/schema`** — 返回所有字段的语义说明, LLM 可以一次拉完。

**优先级**: P0 (没有它后面 MCP server 没法做)

### 5.2 `tracemiku-mcp`: 让 Claude 直接探索 trace 的 MCP server

**现状**: 用户已经在用 `mcp__binary_ninja_headless_mcp__*` (Binary Ninja MCP) 和 `mcp__ida__*` (IDA MCP), 这两个 MCP 让 LLM 能直接对二进制做 RE 工作。trace 是另一个值得 MCP 化的对象。

**最小工具集** (v0, 8-10 个工具就够 LLM 做有意义的探索):

| MCP tool | 输入 | 输出 | 用途 |
|----------|------|------|------|
| `tracemiku_open` | `trace_path` | `{trace_id, records, module}` | 加载 trace, 返回 handle |
| `tracemiku_stats` | `trace_id` | `{records, unique_pcs, block_count, hot_fns:[...]}` | LLM 第一眼了解 trace 规模 |
| `tracemiku_records` | `trace_id, start, count, regs?` | `[RecordRow, ...]` | 拉 viewport |
| `tracemiku_record` | `trace_id, idx` | `RecordDetail` (含 reg + classify) | 单条详情 |
| `tracemiku_search_pc` | `trace_id, pc` | `[idx, ...]` | 找特定 PC 的所有执行点 |
| `tracemiku_search_reg` | `trace_id, reg, value, op` | `[idx, ...]` | "x0 == 0x70102 在哪些 idx?" |
| `tracemiku_taint_forward` | `trace_id, idx, reg, max_count` | `[(idx, why), ...]` | 正向污点 |
| `tracemiku_taint_backward` | `trace_id, idx, reg, max_count` | `[(idx, via), ...]` | 反向污点 (def chain) |
| `tracemiku_cfg_summary` | `trace_id, fn?` | `{blocks, edges, hot_blocks:[...]}` | CFG 概览 (不输出 SVG, LLM 看不了图) |
| `tracemiku_block` | `trace_id, pc` | `BlockDetail` (含 insns, exits) | 单块详情 |
| `tracemiku_decompile` | `trace_id, pc` | `{hlil_lines:[...], tokens:[...]}` | BN HLIL (复用 server.py 已有的 backend) |

**关键设计**:
- 输出**全部 JSON**, 不输出 SVG / HTML / 图像 (LLM 看不了图, 浪费 token)
- `cfg_summary` 输出**结构化的 hot_blocks 列表**, LLM 可以选 block 接着 query, 就像它在 BN MCP 里调 `function_basic_blocks` 然后 `binary_get_function_il_at`。
- 每条命令都要有清晰 `description` (写在 MCP server 注册时), 让 LLM 自己挑工具。
- 实现框架: 复用 Anthropic 的 MCP Python SDK, 上面 10 个工具是对 `viewer/*.py` 的 thin wrapper, **代码量预估 300-500 行** (一天工作量)。

**优先级**: P1 (在 5.1 之后做; 5.1 的 schema 直接复用)

### 5.3 Thin CLI + 稳定 Python SDK

**目的**: LLM 通过 BashTool 也能探索 trace, 不强制 MCP。

**新增 subcommand** (改 `viewer/__main__.py`, argparse subparsers):

```bash
python -m viewer stats path/to/trace/    # JSON 输出 trace 元信息
python -m viewer records path/ --start 100 --count 50 --json
python -m viewer search-pc path/ 0x57770   # 找 PC 的所有 idx
python -m viewer taint-fwd path/ --idx 100 --reg x0
python -m viewer export path/ --format sqlite -o out.db
```

**约定**:
- 默认 `--json` 输出 (LLM 友好), 加 `--text` 才输出人类格式
- 每个子命令的 `--help` 写得像 MCP tool description (一句话说能干嘛 + input/output 例子)

**Python SDK 稳定化**: 整理 `viewer/__init__.py` 显式 export:

```python
# viewer/__init__.py
from .trace import Trace, load, Record, TraceMeta
from .symbols import SymbolMap, build_from_trace
from .index import Index
from .memshadow import MemShadow
from .cfg import build_cfg, CFG, Block
from .taint import forward_taint, backward_taint
from .disasm import decode, Decoded
__version__ = "0.2.0"
__all__ = [...]
```

加个 `examples/llm_cookbook.py` (不是 jupyter, 是给 LLM 看的 .py):
```python
# 5 个例子: load / stats / find PC / taint / export
# 每个例子加注释, 让 LLM 一眼看懂怎么用
```

**优先级**: P1 (和 MCP server 并列, 算同一个产品化批次)

### 5.4 LLM 需要但当前没有的能力 (新功能)

复盘"LLM 想问什么但 viewer 答不了":
1. **trace 时间轴上的 reg 值变化** — 给个 reg 名 + 时间窗, 返回 `[(idx, value), ...]`, LLM 用来看"x0 在 doCommandNative 里取过什么值"
2. **memory diff**: "这条记录前后 mem[0x...] 变成了什么" — `memshadow` 已有 `byte_at`, 包一层 `mem_diff(idx, addr, size) -> {before, after}`
3. **call graph slice**: "从 doCommandNative 调了哪些函数, 各调几次" — `index` 的 reg/mem 索引能提取
4. **"summarize this function"**: 给 fn pc, 返回 (block 数, hot path, 入口出口 register pattern, 调用了哪些外部函数) — 给 LLM 一个 starting point, 不必它自己 query 50 次

这些是 5.2 的 v1 (v0 之后再加的工具)。

---

## 六、Quick Wins (低风险高收益)

> 已按"TUI 冻结 + AI 友好接口"两个新方向重排。原表中针对 TUI 的项已撤回。

| # | 改动 | 文件 | 影响 | Reviewer |
|---|------|------|------|----------|
| 1 | `Record.reg()` 用 dict 替代 `list.index()` | `viewer/trace.py:33-38` | 所有热路径 O(1), `_addr_of` 内会大量调用 | ✅ **DONE** (`bd8cc4e`) |
| 2 | `_addr_of` 抽到 `viewer/trace.py` 末尾 | `taint.py:21` / `memshadow.py:25` / `index.py:46` | 消除 3 处重复 (display.py 没有) | ✅ **DONE** (`bd8cc4e`) |
| 3 | `json.load(open())` → `Path.read_text()` | `viewer/trace.py` (5 处) / `viewer/symbols.py:146` | 修 fd 泄漏 + 写法更紧凑 | ✅ **DONE** (`bd8cc4e`) |
| 4 | bare `except:` → `except Exception:` | `trace.py:74,76,123,156` + `server.py:216,326,330` | 避免吞 KeyboardInterrupt | ✅ **DONE** (`bd8cc4e`) |
| 5 | `collect_modules_from_trace` 真正实现 | `viewer/display.py` + `viewer/trace.py` + `tracer/agent_*.js` + `tracemiku` | **多 SO 指针 classify, 端到端已打通** | ✅ **DONE** (`bd8cc4e` + `1a1819a`) |
| 6 | `KNOWN_LIBSGMAINSO` 参数化 | `viewer/symbols.py:76-82` | 解耦 example 与 viewer 核心 | ✅ P1 (1h) |
| 7 | server.py 纯函数 (lines 28-175) 搬到 `webui/cfg_render.py` | `webui/server.py` → `webui/cfg_render.py` | server.py 减 150 行, 不动闭包 | ✅ P1 (1h) |
| 8 | **API 改用 Pydantic response_model**, 暴露 `/openapi.json` | `webui/server.py` 全部 endpoint | **AI 友好接口前置, 让 schema 可发现** | ✅ **P1 (半天)** |
| 9 | 手写二分 → `bisect` | `symbols.py` / `index.py:62-109` | 更简洁 + 微性能提升 | ⚠️ 顺手做 |
| 10 | BG dict → dataclass | `server.py:273-286` | 类型安全 + IDE 补全 | ⚠️ 留到大改 |
| ~~11~~ | ~~`_classify_mnem` 提取常量~~ | — | 已经是 dict 字面量, 没重复 | ❌ 撤 |
| ~~12~~ | ~~删除 `cfg.py:write_dot()`~~ | — | TUI Ctrl-S 还在用, 不是死代码 | ❌ 撤 |

---

## 七、总结 (按新方向重写)

**项目方向 (2026-05-01 决定)**:
- TUI (`viewer/app.py`) **冻结**, 不维护
- Web (`webui/`) 是唯一 UI
- 暴露 **AI 友好接口** (REST + OpenAPI schema, MCP server, thin CLI / Python SDK), 让 LLM 把 trace 当可探索对象 — 详见第五节

**架构决策仍然成立**: mmap trace + lazy index + numpy vectorize + 子进程 CFG build, 这些底层不需要动。

**真正值得立刻做的 quick wins** (按 "AI 友好接口" 调整后):

| 优先级 | 改动 | 估时 | 说明 |
|--------|------|------|------|
| **P0** | `collect_modules_from_trace` 实现 (#6) | ~1h | ✅ DONE (`bd8cc4e` + `1a1819a`), 端到端已打通 |
| **P0** | `_addr_of` 抽到 `viewer/trace.py` (#4, 含 `index.py:46`) | 30min | ✅ DONE (`bd8cc4e`) |
| **P0** | bare `except:` 全仓修 (#10) | 15min | ✅ DONE (`bd8cc4e`) |
| **P0** | `Record.reg()` 用 dict (#8) | 15min | ✅ DONE (`bd8cc4e`) |
| **P0** | `json.load(open())` 一律 `Path.read_text()` (#9) | 15min | ✅ DONE (`bd8cc4e`) |
| **P1** | `KNOWN_LIBSGMAINSO` 参数化 (#5) | 1h | 解耦 example |
| **P1** | server.py 纯函数搬到 `webui/cfg_render.py` (#1 修订版) | 1h | 减 150 行 |
| **P1** | **API 改用 Pydantic + OpenAPI schema** (新, 5.1) | **半天** | **AI 友好接口前置** |
| **P1** | BN backend `field_at` 实现 (#19) | 1-2 day | M2 milestone |
| **P1** | SQLite export (#18, 通过 `python -m viewer export`) | 半天 | 配合 5.3 LLM CLI |
| **P2** | `tracemiku-mcp` MCP server (新, 5.2) | 1-2 day | LLM 直接探索 trace |
| **P2** | thin CLI subcommands + Python SDK 文档 (新, 5.3) | 半天 | LLM via BashTool |
| **P3** | LLM-friendly 高级查询 (新, 5.4) | 各 0.5-1 day | reg-timeline / mem-diff / fn-summary |
| **P3** | 其余 (BG dataclass, bisect, MemShadow numpy 改造, trace diff) | 按需 | 等遇到具体痛点 |

**关键纠正** (3 处原文档事实错误):
1. **#13 (decode lru_cache 改 inst-only)** — ❌ 绝对不要做, 会让 PC-relative 指令解码全错。
2. **#15 (records 慢因 `_ensure_sorted`)** — ❌ 错, `_sorted` flag 守卫了; 真瓶颈是 `_classify_reg_value`。
3. **#4 (display.py 有 `_addr_of`)** — 实际没有, 重复在 `taint.py + memshadow.py + index.py:46-47`。

**TUI 相关条目处理**: #2 (TUI/Web 去重)、#11 (TUI dispatch) 已撤回。`cfg.py:write_dot` / `cfg.py:textual_summary` / `viewer/app.py` 整个文件 — 不再加新功能, 出 bug 不修, 等正式弃用时一起删。

**两个真正的"工具级进化点"**:
- **#6 `collect_modules_from_trace`** — ✅ DONE (`bd8cc4e` + `1a1819a`). viewer 从 "只懂 libsgmainso 一个 SO" 升级到 "懂多个 module"; agent 发 modules → host 写 meta.json → viewer 读取, 端到端已打通。
- **5.1 OpenAPI schema** — 下一步优先做; 是 5.2 (MCP server) 的前置。

**下一步建议**:
1. ~~先做 P0 五项打底~~ ✅ 已完成 (`bd8cc4e` + `1a1819a`)。
2. 单独 PR 做 5.1 (Pydantic + OpenAPI) — 这一步会让所有 endpoint 的字段约定固化下来, 后面动它们就难了, 所以越早越好。
3. 之后 5.2 (MCP server) 是 `tools/tracemiku-mcp/` 子目录的事; 用 Anthropic MCP Python SDK, 工具调用全部 wrap 已有 `viewer/*.py` 函数, 增量小。
4. P1 内的 #19 (`field_at`) 单独排期, 它和 5.x 是独立 track。

---

## 八、三轮复核 (2026-05-01, 基于 commit `cc48513` HEAD)

`1a1819a` 把多模块端到端打通 (host driver + viewer reader 两 patch 字节级与建议一致), `cc48513` 同步了文档。33 unit tests 全过, Case C 实证 multi-module load 正常。

但抓到 3 个新的小 todo:

### 8.1 缺 multi-module pipeline 的 regression test 🆕

`tests/` 全仓 grep 不到 `modules` — 现在改一行 `_populate_meta` / load() 的 fallback 路径就容易再次回归。

**建议**: 加 `tests/test_meta_modules.py`, 跑 3 个 case (用 mock meta.json + 1 byte trace.bin):
- per-call dir (`d/calls/call_NNN/`) + run-level meta 含 `modules` → `meta.modules` 应 == 3
- legacy `trace_*.bin` 布局 + run-level meta 含 `modules` → 同上
- 仅有 `meta.module` 单数 (legacy trace, 无 modules 字段) → fallback 后 `meta.modules == [meta.module]`

复用三轮复核里实证用的 mock 代码即可, 30 分钟落地。

### 8.2 `/api/meta` endpoint 不暴露 `modules` 字段 🆕

`webui/server.py:371-382`:
```python
return {
    "path": ...,
    "module": {"name": m.name, "base": hex(m.base), ...} if m else None,
    # 缺: "modules": [{"name", "base", "size", "end"}, ...]
}
```

**后果**: Web 前端 / 未来的 MCP client 拿不到多 SO 列表。`_classify_reg_value` 内部用了 `collect_modules_from_trace` 是间接路径 (够它自己 classify), 但外部 consumer 看不到。

**修复 (1 行)**:
```python
"modules": [{"name": x.name, "base": hex(x.base), "size": x.size, "end": hex(x.end)}
            for x in t.meta.modules],
```

属于 **5.1 (API schema 文档化) 的范畴**, 顺手在做 Pydantic 化时一起加。

### 8.3 `viewer/trace.py` 三处 `meta.module → meta.modules` fallback 重复

`1a1819a` 在两处 run-level merge 末尾加了:
```python
if meta.module and not meta.modules:
    meta.modules.append(meta.module)
```
(`trace.py:160` 和 `trace.py:194`)

而 `bd8cc4e` 在 `_populate_meta` 末尾也加了同样的 (line 209-210)。**三处语义完全相同, 重复**。

**修复 (低优先级, 但会让代码干净)**:
- 删掉 `trace.py:160` 和 `trace.py:194` 的两处
- 在 `load()` 函数 return 之前 (即两个 `return Trace(bin_path, meta)` 之前) 各加一行调用一个新的 helper `_finalize_modules_fallback(meta)`
- 或者更简单: 直接保留 `_populate_meta` 那处, 因为 per-call meta 必然走 `_populate_meta`; 而 run-level merge 之后立即 return, 在 return 之前再补一次兜底也不亏 — 现状其实是 "防御性多次重置", 删了也对。

**推荐: 直接删 `trace.py:160` 和 `trace.py:194` 两处**, 因为 `_populate_meta` 已经处理了从 per-call meta 进来的情形; 而 run-level meta 即使写了 `module` 单数, 也走的是 fallback (`_populate_meta` 在 per-call meta 里处理), 不需要在 run-level merge 后再补一次。**待小心验证**, 不是 quick win — 列在 P3。

### 8.4 第 1 步审计的"未做"清单 (按下一步推荐顺序)

| 优先级 | TODO | 估时 | 依赖 |
|--------|------|------|------|
| **P1.A** ⭐ | **5.1 API Pydantic + OpenAPI schema** (含 8.2 暴露 modules) | 半天 | ✅ DONE (`7453d7c`) |
| P1.B | regression test for multi-module pipeline (8.1) | 30min | ✅ DONE (`1341e6f`) |
| P1.C | server.py 纯函数 (lines 28-175) → `webui/cfg_render.py` | 1h | ✅ DONE (`9f1e3f0`) |
| P1.D | `KNOWN_LIBSGMAINSO` 参数化 (#5, `build_from_trace` 接 `known_offsets`) | 1h | ✅ DONE (`1341e6f`) |
| P1.E | BN backend `field_at` 实现 (#19) | 1-2 day | ✅ DONE (`74f6ea5`) |
| P1.F | SQLite export (`python -m viewer export`) (#18) | 半天 | ✅ DONE (`f574873`) |
| P2.A | 5.2 `tracemiku-mcp` MCP server | 1-2 day | **5.1 必须先做** |
| P2.B | 5.3 thin CLI subcommands + Python SDK 文档 | 半天 | 可与 5.2 并行 |
| P3 | 8.3 trace.py fallback 三处去重 | 15min | 防御性, 顺手做 |
| P3 | 5.4 LLM 友好高级查询 / BG dataclass / bisect / MemShadow numpy / trace diff | 按需 | — |

### 8.5 推荐下一步

如果只挑一个 PR, **做 P1.A (5.1 API schema 文档化)** — 它:
- 强制让 `/api/meta` 字段补全 (顺手解决 8.2)
- 是 5.2 (MCP server) 的硬前置, 拖久了字段名再改就是 breaking change (现在还没下游消费者, 改起来便宜)
- 半天工作量, 单 PR 收尾干净
- 顺便定义 modules / record / cfg 等 response Pydantic model, 后面 MCP wrapper 可以直接复用

如果想先把"已修好的链路"100% 收尾, **优先做 P1.B (regression test, 30min)** — 防止 multi-module 再回归。这是 memory `feedback_e2e_pipeline_audit` 写下的教训的直接延伸: 改 agent→host→viewer 链路得有测试看着, 不能只靠 mock 一次。
