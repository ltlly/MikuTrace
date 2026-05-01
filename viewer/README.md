# viewer/ — core 库 + CLI 子命令 + Python SDK

`viewer/` 是 traceMiku 的离线分析 core. 它给三种消费者用同一份底层:

- **Web** (`webui/`) — `webui/server.py` 直接 import `viewer.*`
- **CLI** (`viewer/__main__.py`) — `python -m viewer <subcommand>`, JSON 输出
- **Python SDK** (`viewer/__init__.py`) — `from viewer import load, ...`

> `viewer/app.py` 的 textual TUI **已冻结**, 仅保留兼容入口 `python -m viewer <dir>`,
> 不再加新功能。新功能一律先在 Web 上做。

---

## Python SDK

公共 API 在 `viewer/__init__.py` 显式 export:

```python
from viewer import (
    # core trace
    Trace, Record, Module, TraceMeta,
    load, addr_of,
    REG_NAMES, ALL_REGS, REC_SIZE,
    # disasm
    decode, Decoded, fmt_insn,
    # symbol map
    SymbolMap, build_from_trace, load_ida_symbols, auto_known_offsets,
    # CFG
    build_cfg, CFG, Block, find_sccs, loop_sccs,
    # cross-ref index
    Index,
    # memory shadow
    MemShadow,
    # taint
    forward_taint, backward_taint,
    # decompiler backend
    make_backend,
)
```

### 最小例子

```python
from viewer import load, build_from_trace, Index, decode

t = load("traces/run1/calls/call_002_*/")
print(len(t), "records")
print(t.meta.module.name)              # libsgmainso-6.8.260403.so

sym = build_from_trace(t)              # PC → function name
                                        # auto-loads examples/<so>/known_offsets.json
idx = Index(t); idx.build()            # def/use chains

# 看第 100 条记录
r = t.record(100)
d = decode(r.pc, r.inst)
print(f"#{r.idx}  {hex(r.pc)}  {d.mnemonic} {d.op_str}  x0={hex(r.reg('x0'))}")
```

### 完整 cookbook

`examples/llm_cookbook.py` 有 10 个 self-contained 例子:

| Example | 说明 |
|---|---|
| `load_trace` | Load + 元信息 |
| `count_blocks` | Build CFG, 列 hottest blocks |
| `find_pc` | numpy vec 找一个 PC 的所有 idx |
| `taint_x0` | Forward-taint x0 |
| `backward_taint_chain` | Backward def-chain 看 reg 来源 |
| `find_strings_in_mem` | MemShadow 里所有 ≥N 字节 ASCII 串 |
| `mem_dump_at_addr` | hex dump |
| `classify_branch` | 统计 branch/call/ret/other 比例 |
| `hot_pcs` | top-N 最热 PC + 反汇编 |
| `full_trace_summary` | 一次性 summary, LLM agent 友好 |

```bash
python examples/llm_cookbook.py all              # 跑所有
python examples/llm_cookbook.py taint_x0         # 跑单个
```

---

## CLI 子命令 (LLM/scripting)

`viewer/__main__.py` 暴露 12 个子命令, 默认 JSON 输出:

```bash
# 元信息 / 导出
python -m viewer stats <trace>
python -m viewer export <trace> --format sqlite [-o out.db]

# 索引 / 搜索
python -m viewer search-pc <trace> 0x... [--limit N]
python -m viewer idxs-for-pc <trace> 0x... [--cursor N --limit M]
python -m viewer search-asm <trace> 'regex' [--max N]

# 污点 / 内存
python -m viewer taint-fwd <trace> --start N --reg x0 [--max N]
python -m viewer taint-bwd <trace> --start N --reg x0 [--max N]
python -m viewer mem-dump <trace> --addr 0x... [--count N --cursor N]

# 高级查询
python -m viewer reg-timeline <trace> --reg x0 --start 0 --end 1000
python -m viewer mem-diff <trace> --idx 100 --addr 0x... --size 32
python -m viewer fn-summary <trace> --fn doCommandNative

# BN HLIL 字段语义 (需 BN backend)
python -m viewer field-at <trace> --pc 0x... --reg x8 --offset 0x80 \
       --so /path/to/lib.so

# 启动 deprecated TUI (兼容裸路径)
python -m viewer <trace_dir>
```

每个命令的 `--help` 写得清晰 (LLM 能直接挑工具)。地址参数都接受 hex
(`0x...`) 或十进制。

### 示例: 看 doCommandNative 在 trace 里被执行了几次, 第一次入口什么 PC

```bash
TRACE=traces/run1/calls/call_002_*/
python -m viewer fn-summary "$TRACE" --fn doCommandNative
# {"status":"ready","fn":"doCommandNative","pc":"0x6d12397770",
#  "block_count":70,"total_executions":164,
#  "entry_idxs":[0],"entry_idxs_total":1, ...}
```

### 示例: 跟踪 cmd id 70102 在哪些 reg 上被搬动

```bash
python -m viewer reg-timeline "$TRACE" --reg x2 --start 0 --end 100
python -m viewer taint-fwd "$TRACE" --start 0 --reg x2 --max 200
```

---

## 文件清单

```
viewer/
├── __init__.py        # 公共 API exports (29 names)
├── __main__.py        # 12 个 CLI 子命令 + dispatcher
├── trace.py           # mmap binary trace 解析 + Record + addr_of
├── disasm.py          # capstone 包装 + def/use 提取 (lru_cache 200K)
├── symbols.py         # SymbolMap + auto_known_offsets discovery
├── cfg.py             # build_cfg + Tarjan SCC + write_dot (TUI 用)
├── index.py           # def/use chain + mem_addr_to_writes
├── memshadow.py       # 稀疏内存 shadow + find_strings + hex_dump
├── taint.py           # 正向/反向污点 (heap-based, O(|hits|·log N))
├── display.py         # pwndbg 风 classify + multi-module collector
├── decompiler/        # BN/Ghidra/IDA backend 抽象 + binja 实现
│   ├── backend.py     # FieldHint / Function / Variable 等 dataclasses
│   └── backends/
│       ├── binja.py   # BN 实现 (含 field_at HLIL walker)
│       ├── ghidra.py  # stub
│       ├── ida.py     # stub
│       └── none.py    # null backend
└── app.py             # TUI (deprecated, 不维护)
```

## 关键 API

### `load(trace_dir_or_file) -> Trace`

读 trace.bin + meta.json (per-call / run-level 都支持)。返回 `Trace` 含
`record(i)`, `pc(i)`, `inst(i)`, `pc_array()` (numpy 零拷贝视图)。

### `build_from_trace(trace, base=0, known_offsets=None) -> SymbolMap`

从 trace 推断函数列表 (bl 目标 + 第一个 PC)。`known_offsets=None` 时自动
discover (按顺序: trace.meta.raw["known_offsets"] / `<trace_dir>/known_offsets.json` /
`<run_dir>/known_offsets.json` / `examples/<so_basename>/known_offsets.json`)。

### `Index(trace).build()`

扫一次 trace, 建 `reg_defs / reg_uses / mem_writes / mem_reads /
mem_addr_to_writes`。供 `forward_taint` / `backward_taint` 加速 (旧 O(N²) →
新 O(|hits|·log N))。67k record 上 1-2 秒。

### `MemShadow(trace).build()`

按 trace 时序扫所有 store/load, 重建字节级内存 shadow。`byte_at(addr, t)`
返回 (byte_value, kind, source_idx), kind ∈ `r`/`w`/`??`。

### `forward_taint(trace, start_idx, taint_reg, max_count, index)`

heap-based 正向污点。返回 `[(insn_idx, why), ...]`。

### `build_cfg(trace, only_module=True) -> CFG`

从 trace 重建 BB-CFG。`CFG.blocks` 是 `dict[start_pc, Block]`,
`CFG.edges` 是 `dict[(src, dst), {kind, count}]`。

### `decode(pc, inst) -> Decoded`

capstone 包装, lru_cache。返回 `mnemonic`, `op_str`, `regs_def/use`,
`mem_op` (含 base/index/disp/size/is_write), `is_branch/call/ret`,
`branch_target`, `indirect_branch_reg`。

### `make_backend(name)` (lazy)

`name` ∈ `'binja' | 'ghidra' | 'ida' | 'r2' | None` (auto)。返回
decompiler backend (含 `function_at`, `hlil_for`, `cfg_for`, `field_at`,
`asm_tokens_at` 等)。lazy import 避免主路径拉 BN。

---

## 跟 webui 的关系

`webui/server.py:make_app(trace_path)` 内部 import `viewer` 然后包成 REST
endpoints。`webui/schemas.py` 定义 strict Pydantic schemas, OpenAPI 自动
生成。改 viewer core 时跑 `pytest tests/test_webui.py` 验证 web 那端。

`webui/cfg_render.py` 是从 server.py 抽出来的纯函数 (graphviz dot 拼接 +
HTML token 着色), 跟 viewer/ 无关。

## 测试

```bash
pytest tests/ --ignore=tests/test_percall.py --ignore=tests/test_pull_fixes.py \
              --ignore=tests/test_webui_full.py --ignore=tests/test_real_trace.py
# 41 passed
```

(那 4 个 ignore 是要起 subprocess / 真 trace 的, 在 sandbox 跑不动。)

## 旧 TUI 用法 (deprecated)

```bash
python -m viewer traces/run1/calls/call_002_*/
# 或
./tracemiku view traces/run1/calls/call_002_*/
```

快捷键: ↑↓/k/j 单步, PgUp/PgDn 翻页, `g` 跳转, `/` 搜索, `d`/`u`
def/use, `f`/`b` 污点, `m` 内存, `s` 字符串, `C` CFG, `B` BlockMap,
`Ctrl-S` 导出 dot, `q` 退出。

新功能不会加进 TUI; 在 Web (`./tracemiku web <trace>`) 上做。
