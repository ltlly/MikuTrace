# traceMiku 测试覆盖盘点

> Last reviewed: 2026-05-02 (post xsign-RE 工具改进). **342 个测试 / 31 个测试文件**
> 覆盖了核心数据通路. 新增:
> - `test_ext_write_pipeline.py` (deep-trace 边界 ptr-diff + external_writes.bin)
> - `test_jni_string_wiring.py` (JSON-driven JNI hooks 配置/agent/host wiring)
> - `test_mem_writes_in_range.py` (mem-writes-in-range / mem-flow / crypto-scan /
>   taint-bwd --through-mem / MemShadow sidecar 持久化)
>
> 这份文档把 **每个小功能** 列一遍, 标出 ✅ 有测试 / ⚠️ 部分覆盖 / ❌ 无测试, 并对
> 每条 ❌ 给出测试该写什么 (testable invariants).

跑法:
```bash
/usr/bin/python3 -m pytest tests/ -v        # 全跑 (~50s, 跳过 real_trace)
/usr/bin/python3 -m pytest tests/ -m "not slow"  # 快速 (排除真实 trace)
```

---

## 1. `viewer/trace.py` — Record / Trace / Module / load

| 功能 | 测试 | 状态 |
|---|---|---|
| `REC_SIZE=272` 二进制布局正确解 | test_disasm.py 间接 (synth 写盘 → Trace 读) | ✅ |
| `Trace.record(i)` 寄存器顺序: x0..x28, fp, lr, sp | test_disasm.py / test_index.py | ✅ |
| `Trace.pc_array()` zero-copy stride view | test_data_chase.py 通过 idxs-for-pc | ⚠️ 没直接 |
| `Record.reg("x29")` 不报错 (内部存为 fp) | — | ❌ **加测 alias** |
| `addr_of(rec, mem_op_tuple)` base/index/disp 计算 | test_field_at.py 间接 | ⚠️ |
| `load(dir)` per-call dir 布局 | test_meta_modules.py | ✅ |
| `load(file)` legacy bin 单文件 | test_meta_modules.py | ✅ |
| `_populate_meta` modules 列表合并 (run + per-call override) | test_meta_modules.py | ✅ |
| trace 0 长度 / 单条 trace 边界 | test_webui_full::test_record_edge_cases | ⚠️ 仅 webui 视角 |

**Gap**: `Record.reg(alias)` 行为, `addr_of` 各种 mem_op 形式 (无 base, 仅 disp, 带 idx_reg).

---

## 2. `viewer/disasm.py` — capstone wrapper + classification

| 功能 | 测试 | 状态 |
|---|---|---|
| `decode(pc, inst)` mnemonic + op_str | test_disasm | ✅ |
| `regs_use / regs_def` for mov/add/cmp | test_disasm | ✅ |
| `is_branch / is_call / is_ret` for b/bl/ret/blr/cbz/tbz/b.eq | test_disasm::test_branch_classification | ✅ |
| capstone-bug fix: `cmp/tst/cmn` 不写 operand 只写 nzcv | test_disasm::test_cmp_x0_x1 | ✅ |
| `mem_op` 含 base/idx/disp/sz/is_w | test_disasm::test_load_store_mem_op | ✅ |
| `branch_target` for b/bl 立即数 | — | ❌ |
| `indirect_branch_reg` for br/blr xN | test_disasm::test_indirect_branch | ✅ |
| size 推断: `ldrb` (1) / `ldrh` (2) / `ldr w0` (4) / `ldr x0` (8) | — | ❌ |
| 未识别 inst 落 `<bad>` | — | ❌ |
| `decode` lru_cache hit | — | ❌ (perf) |

**Gap**: `branch_target` 立即数, size 后缀映射 (一旦 capstone 升级或 mnemonic 字符变化容易回归), `<bad>` 兜底.

---

## 3. `viewer/cfg.py` — build_cfg / SCC / aux

| 功能 | 测试 | 状态 |
|---|---|---|
| 直线代码 → 1 块 | test_cfg::test_cfg_linear | ✅ |
| 含分支 → 多块 | test_cfg::test_cfg_with_branch | ✅ |
| 循环 → 至少 2 块 | test_cfg::test_cfg_loop | ✅ |
| `executions` 计数正确 | test_cfg::test_cfg_executions_count | ✅ |
| **Bug #1**: `_filled` 在 cur 退场前必设 | test_cfg_bugs::test_block_insns_no_dup_after_fallthrough_to_known_start | ✅ NEW |
| **Bug #2**: entry_pc 必在 module 内 | test_cfg_bugs::test_entry_pc_in_module_when_trace_starts_external | ✅ NEW |
| **Bug #3**: call_stack 跨外部 SO 平衡 | test_cfg_bugs::test_call_stack_balanced_across_external_call | ✅ NEW |
| 真实 trace 0 重复 insns | test_cfg_bugs::test_real_trace_no_dup_insns | ✅ NEW |
| `find_sccs` Tarjan 正确性 | test_webui_full::test_scc_finds_loops | ⚠️ 仅经 API |
| 自环 SCC | test_webui_full::test_scc_self_loop | ⚠️ 仅经 API |
| `loop_sccs` size>=2 / 自环过滤 | — | ❌ **加直接测试** |
| `build_aux_indices` 输出与旧 Python loop 等价 | — | ❌ **加测** (NEW 代码) |
| `build_aux_indices` block_idxs trace 序保留 | — | ❌ |
| `write_dot` 不报错 + 含所有节点 | — | ❌ |
| `textual_summary` Top-N | — | ❌ |
| `only_module=False` 全局 CFG | — | ❌ |

**Gap**: `loop_sccs` 单元 (合成), `build_aux_indices` regression (新代码,容易回归), `write_dot` smoke.

---

## 4. `viewer/cfg_graph.py` — ASCII art CFG (TUI)

| 功能 | 测试 | 状态 |
|---|---|---|
| 任何 | — | ❌ TUI 已冻结, 不强求 |

跳过 — 用户 memory 里说"TUI 冻结" .

---

## 5. `viewer/index.py` — Index (def-use chains)

| 功能 | 测试 | 状态 |
|---|---|---|
| reg_defs / reg_uses bisect | test_index | ✅ |
| def_chain 沿 use 反向 | test_index::test_def_chain | ✅ |
| use_chain 沿 def 正向 | test_index::test_use_chain | ✅ |
| mem_writes / mem_reads 数组 | test_index::test_mem_writes_reads | ✅ |
| Index.build idempotent | — | ❌ (低优) |

OK.

---

## 6. `viewer/memshadow.py` — MemShadow

| 功能 | 测试 | 状态 |
|---|---|---|
| 写可见 (cursor 后) | test_memshadow::test_mem_write_visible | ✅ |
| 读捕捉 value | test_memshadow::test_mem_read_captures_value | ✅ |
| hex_dump unknown bytes | test_memshadow::test_hex_dump_unknown_bytes | ✅ |
| find_strings 合成 | test_memshadow::test_find_strings_synthetic | ✅ |
| `_value_of_write/_read` 各种 size (1/2/4/8) | — | ❌ |
| stp/ldp pair 正确算 size | — | ❌ |

**Gap**: pair load/store (stp/ldp) 是 16 字节, size 推断容易出错.

---

## 7. `viewer/taint.py` — forward / backward taint

| 功能 | 测试 | 状态 |
|---|---|---|
| forward 基础链 | test_taint::test_forward_taint_basic_chain | ✅ |
| forward 经寄存器传播 | test_taint::test_forward_taint_via_register_propagation | ✅ |
| backward 链 | test_taint::test_backward_taint_chain | ✅ |
| backward 跨 cmp | test_taint::test_backward_taint_through_cmp | ✅ |
| dedup | test_taint::test_taint_dedup | ✅ |
| 真实 trace x2 → smull | test_real_trace::test_forward_taint_x2_finds_smull | ✅ (skipif) |
| limit 截断 | — | ❌ |
| exclude_regs 配置 | — | ❌ |

OK (核心覆盖).

---

## 8. `viewer/symbols.py` — SymbolMap / ModuleResolver

| 功能 | 测试 | 状态 |
|---|---|---|
| `ModuleResolver.resolve(pc)` | test_data_chase::test_module_resolver_basic | ✅ |
| `ModuleResolver` numpy vectorize | test_data_chase::test_module_resolver_vectorize | ✅ |
| `SymbolMap.lookup(pc)` 函数+offset | test_real_trace::test_symbols_resolve_doCommand | ⚠️ skipif |
| `auto_known_offsets` 解 trace meta | — | ❌ |
| `load_ida_symbols` JSON 解析 | — | ❌ |
| `build_from_trace` JNI method 名提取 | — | ❌ |

**Gap**: SymbolMap 直接单元 (synth meta + lookup) — 关键, 因为 lookup 改名会破其它一切.

---

## 9. `viewer/display.py` — value classify / deref

| 功能 | 测试 | 状态 |
|---|---|---|
| `is_in_known_module(modules, v)` | — | ❌ |
| `looks_like_ascii(b)` | — | ❌ |
| `maybe_string_at(mem, addr)` | — | ❌ |
| `deref_u64(mem, addr)` | — | ❌ |
| `_heuristic_region(value)` heap/stack/code 区分 | — | ❌ |
| `classify(value, ...)` 综合 | — | ❌ |
| `format_reg_line` 颜色化 | — | ❌ |
| `collect_modules_from_trace` | — | ❌ |

**Gap**: 整个文件无单元. 这些函数被 webui /api/record 大量用, 行为变化无人觉察.

---

## 10. `webui/cfg_render.py` — pure render helpers

| 功能 | 测试 | 状态 |
|---|---|---|
| `html_esc` & < > " 转义 | — | ❌ |
| `classify_mnem('ret'/'bl'/'b.eq'/'sub')` → ret/call/branch/'' | — | ❌ |
| `MNEM_COLORS` 4 个 key 都存在 | — | ❌ |
| `build_block_label(rows, color)` 包含 BORDER/CELLPADDING | — | ❌ |
| `render_tokens_html(tokens)` skip meta + empty | — | ❌ |
| `format_insn_row(rel, mnem, ops, pc, title)` HREF/TITLE | — | ❌ |
| `BN_EDGE_KIND_COLOR` 10 种 kind | — | ❌ |
| `bn_bb_border_color(0/1/100/10000)` 梯度 | — | ❌ |
| `split_mnem_ops_from_tokens` BN tokens fallback 字符串 | — | ❌ |
| `render_dot_to_svg` graphviz 不存在时 err | — | ❌ |

**Gap**: 整个文件无单元. 都是 pure functions, 容易测.

---

## 11. `webui/server.py` — FastAPI endpoints (39 个)

### Core data
| Endpoint | 测试 | 状态 |
|---|---|---|
| GET `/api/meta` | test_webui::test_meta + test_webui_full::test_records_meta | ✅ |
| GET `/api/records` | test_webui::test_records_window + test_webui_full::test_records_window_boundaries | ✅ |
| GET `/api/record/{idx}` | test_webui::test_record_one + test_webui_full::test_record_n_consistency / test_record_edge_cases | ✅ |
| GET `/api/so-stats` | test_data_chase::test_so_stats_endpoint | ✅ |

### CFG
| Endpoint | 测试 | 状态 |
|---|---|---|
| GET `/api/cfg` | test_webui::test_cfg + test_webui_full::test_cfg_dedupe | ✅ |
| GET `/api/cfg-svg` | test_webui_full::test_cfg_svg_status_progression | ⚠️ 仅状态机 |
| GET `/api/cfg?fn=foo` filter | — | ❌ |
| GET `/api/block-for-pc` | test_webui::test_block_for_pc | ✅ |
| GET `/api/block` | — | ❌ |
| GET `/api/loops` | test_webui_full::test_api_loops_endpoint | ✅ |
| GET `/api/idxs-for-pc` | test_webui_full::test_idxs_for_pc_correctness | ✅ |
| GET `/api/idxs-for-block` | test_webui_full::test_idxs_for_block_basic | ✅ |
| GET `/api/backtrace` | test_webui_full::test_backtrace_endpoint | ✅ |

### Search / inspect
| Endpoint | 测试 | 状态 |
|---|---|---|
| GET `/api/search` | test_webui::test_search | ✅ |
| GET `/api/strings` | test_webui_full::test_strings_search_filter / test_strings_at_cursor_filter | ✅ |
| GET `/api/string-provenance` | test_webui_full::test_string_provenance_endpoint | ✅ |

### Memory & registers
| Endpoint | 测试 | 状态 |
|---|---|---|
| GET `/api/mem-dump` | test_webui_full::test_mem_dump_endpoint | ✅ |
| GET `/api/last-write-of-reg` | test_webui_full::test_last_write_of_reg | ✅ |
| GET `/api/reg-value-at` | test_webui_full::test_reg_value_at | ⚠️ 不含 alias x29/x30 |
| GET `/api/last-write-of-addr` | test_data_chase::test_last_write_of_addr_endpoint | ✅ |
| GET `/api/idxs-touching-range` | test_webui_full::test_idxs_touching_range_endpoint | ✅ |
| GET `/api/idxs-touching-addr` | test_webui_full::test_idxs_touching_addr_endpoint | ✅ |

### Taint & data-chase
| Endpoint | 测试 | 状态 |
|---|---|---|
| GET `/api/forward-taint` | — | ❌ (核心模块有, 端点没单测) |
| GET `/api/backward-taint` | — | ❌ |
| GET `/api/data-chase` | test_data_chase::test_data_chase_endpoint | ✅ |
| GET `/api/find-mem-pattern` | test_data_chase::test_find_mem_pattern_endpoint | ✅ |

### LLM-friendly higher-level
| Endpoint | 测试 | 状态 |
|---|---|---|
| GET `/api/reg-timeline` | — | ❌ |
| GET `/api/mem-diff` | — | ❌ |
| GET `/api/fn-summary` | — | ❌ |
| GET `/api/field-at` | test_field_at::test_field_at_no_decomp / test_field_at_invalid_pc | ✅ |
| GET `/api/jni-calls` | test_data_chase::test_jni_calls_endpoint | ✅ |
| GET `/api/jobj-history` | test_data_chase::test_jobj_history_endpoint / invalid | ✅ |
| GET `/api/jni-strings` | test_data_chase::test_jni_strings_endpoint | ✅ |

### Status / decompiler
| Endpoint | 测试 | 状态 |
|---|---|---|
| GET `/api/bg-status` | test_webui_full::test_cfg_async_first_call (间接) | ⚠️ |
| GET `/api/decomp-status` | — | ❌ |
| GET `/api/asm-tokens-for-pcs` | — | ❌ |
| GET `/api/hlil-for-pc` | — | ❌ (需要 BN, 不强求) |
| GET `/api/bn-cfg-svg-for-pc` | — | ❌ (需要 BN) |
| GET `/api/bn-cfg-for-pc` | — | ❌ (需要 BN) |

### Static
| Endpoint | 测试 | 状态 |
|---|---|---|
| GET `/` index.html | test_webui::test_index_html_served | ✅ |

### Recently fixed
| 修过的行为 | 测试 | 状态 |
|---|---|---|
| `_norm_reg(x29)` → fp | — | ❌ **加测** (Bug #31 fix) |
| `_norm_reg(x30)` → lr | — | ❌ **加测** |
| `_norm_reg(xzr)` → ZERO sentinel | — | ❌ **加测** |
| `/api/reg-value-at?reg=x30` 不再 ResponseValidationError | — | ❌ **加测** |
| `/api/reg-value-at?reg=x29` 返回正确值 | — | ❌ **加测** |

---

## 12. `webui/schemas.py` — Pydantic models

不直接测试; 端点测试覆盖 (FastAPI response_model 验证). OK.

---

## 13. `tracer/agent_*.js` — Frida agent

| 功能 | 测试 | 状态 |
|---|---|---|
| Stalker exclude libart/system_server | — | ❌ (运行时, 难自动测) |
| `resolveExportName` non-null | test_pull_fixes::test_agent_v5_resolves_export_name_not_null_pointer | ✅ |
| `resolveOffset` 不盲加 0 | test_pull_fixes::test_agent_v5_does_not_blindly_add_null_offset | ✅ |
| `tracer/pull_fixes` su fallback | test_pull_fixes (5 个) | ✅ |
| **新增**: JNI string hook (Task #30) | — | ❌ pending Task #30 完成 |

---

## 14. CLI (`tracemiku` 顶层 + `viewer/__main__.py` 子命令)

| Command | 测试 | 状态 |
|---|---|---|
| `tracemiku list` | test_percall::test_list_run_shows_calls_desc | ✅ |
| `tracemiku info <call>` | test_percall::test_info_call_dir_complete / truncated | ✅ |
| `tracemiku info <run>` | test_percall::test_info_run_aggregates | ✅ |
| `tracemiku trace` | — | ❌ (需 device, 不强求) |
| `tracemiku finalize` | — | ❌ |
| `tracemiku view` (TUI) | — | ❌ (TUI 冻结) |
| `tracemiku web` | — | ❌ (整体由 webui tests 覆盖) |
| `tracemiku query` | — | ⚠️ (个别 viewer cmd_* 间接) |
| `viewer cmd_stats` | — | ❌ |
| `viewer cmd_export` | — | ❌ |
| `viewer cmd_search_pc / search_asm / idxs_for_pc` | test_data_chase 间接 | ⚠️ |
| `viewer cmd_taint_fwd / taint_bwd` | test_taint 直接, CLI 调用面没测 | ⚠️ |
| `viewer cmd_data_chase` | test_data_chase | ✅ |
| `viewer cmd_records / cmd_so_stats` | test_data_chase 间接 | ⚠️ |
| `viewer cmd_jni_calls / jobj_history / jni_strings` | test_data_chase | ✅ |
| `viewer cmd_mem_dump / reg_timeline / mem_diff / fn_summary / field_at` | — | ❌ |

**Gap**: 多数 CLI 子命令没测 argparse + JSON 输出格式. JSON 格式变化无人觉察.

---

## 15. Frontend (`webui/app.js`, `index.html`, `styles.css`)

| 功能 | 测试 | 状态 |
|---|---|---|
| 任何 | — | ❌ 无 JS test runner |

**Gap (整个 frontend)**: 列宽拖拽 / 滚动占位 / decoupled scroll / cursor sync / cmd 解析 / settings 持久化 / SO filter / BN tokens — 全部无自动化测试.

写法: 现在没装 jsdom/playwright/jest. 短期先用 `node --check` 当 syntax check (CI 加一行就行); 长期值得跑 Playwright 一组冒烟. 优先级中.

---

## 16. tools/* — eBPF, miku-shield (用户的另一个项目)

跳过 — 是 fork, 上游维护.

---

# Test Gap 优先级 (按"最容易回归 × 影响最大")

## P0 (最近改的, 必须有 pin 测试)
1. **`webui::_norm_reg` 别名** — alias 表是新代码, 单点失败拖整个 op-reg 交互 (Bug #31)
2. **`viewer/cfg::build_aux_indices` 等价性** — 新向量化代码, 万一 numpy boundary 有 off-by-one 就误差很大
3. **`/api/reg-value-at?reg=x29|x30|xzr`** — 端到端 pin alias 行为

## P1 (pure functions, 容易测, 改了无人知道)
4. `viewer/cfg::loop_sccs` 自环 + size>=2 直接单元
5. `webui/cfg_render::*` 全部 pure helpers
6. `viewer/symbols::SymbolMap.lookup / build_from_trace` 直接单元

## P2 (覆盖率薄弱处)
7. `viewer/display::*` 整文件无单元
8. `viewer/disasm::decode` size 后缀 + branch_target 立即数
9. `webui::/api/forward-taint / backward-taint` 端点未测

## P3 (低优 / 难自动化)
10. CLI argparse + JSON 输出格式 stability
11. Frontend Playwright smoke
12. Tracer JNI hook (依赖 device)

---

# 本次提交的测试增量

P0 全部加测 → `tests/test_recent_fixes.py` (新建, 见下次 commit).
P1 #4, #5 加测 → `tests/test_cfg_render.py`, `tests/test_loop_sccs.py`.
P1 #6 加测 → `tests/test_symbols.py`.

剩余 P1/P2/P3 列在 backlog, 用户 prioritize 后再写.
