# traceMiku Backlog / TODO

> 唯一 backlog 入口. README / tracer-README / CODE_REVIEW 等文档不再各自维护待办,
> 新增条目一律加到这里. 已完成的从这里删, 不留 strikethrough.
>
> 项目哲学 (从批注收敛): **全量信息 > 性能**, **真实业务场景 > 社区曝光**.
> 1GB trace 可忍受, 不做 selective insn; 不为 SEO 做 drcov; 不做 CTF 伪需求.

---

# 进度概览

## 🚧 进行中 (2026-05-03 — Analysis v2 — Rust core + TS frontend)

- 设计 spec: `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`
- 实施 plan (M0+M1): `docs/superpowers/plans/2026-05-03-analysis-v2-m0-m1.md`
- M0 perf baseline: `docs/superpowers/specs/2026-05-03-m0-perf-baseline.md` ✅
- M0 LLIL diff spec: `docs/superpowers/specs/2026-05-03-llil-diff-spec.md` ✅
- M0 /api/meta wire contract: `docs/superpowers/specs/2026-05-03-meta-endpoint-contract.md` ✅
- M1 Rust workspace 3 crates: ✅
- M1 tracemiku-core::trace::TraceMeta: ✅
- M1 tracemiku-server::routes::meta /api/meta endpoint: ✅
- M1 tracemiku-cli stats subcommand (placeholder): ✅
- M1 frontend Vite + Solid + TS skeleton + MetaPanel: ✅
- M1 e2e smoke (cargo run + npm run dev + browser /api/meta): ✅
- M2-α `tracemiku-core::trace::{Record, Trace}` + mmap parser: ✅ 2026-05-03
- M2-α `tracemiku-cli stats` parity vs `python -m viewer stats`: ✅ (scripts/m2_alpha_parity.py)
- M2-β `tracemiku-core::disasm` (capstone wrapper + thread-local FIFO cache 200k): ✅ 2026-05-04
- M2-β `/api/records` + `/api/record/{idx}` (subset wire shape; symbol-fields null): ✅ 2026-05-04
- M2-β frontend `RecordsPanel` (paginated 50-record windows): ✅ 2026-05-04
- M2-γ `tracemiku-core::disasm.regs_def/regs_use` (capstone detail + cmp fix): ✅ 2026-05-04
- M2-γ `tracemiku-core::index::Index` (reg_defs/reg_uses sequential build): ✅ 2026-05-04
- M2-γ `tracemiku-core::symbols::{SymbolMap, ModuleResolver, build_from_trace}`: ✅ 2026-05-04
- M2-γ `/api/idxs-for-pc` + populated `/api/records.func/off/module`: ✅ 2026-05-04 (real-trace func/off depends on M2-δ auto_known_offsets)
- M2-δ `tracemiku-core::cfg` (build_cfg + Block + Tarjan SCC via petgraph): ✅ 2026-05-04
- M2-δ `tracemiku-core::symbols::auto_known_offsets` (bl-target heuristic): ✅ 2026-05-04
- M2-δ `/api/cfg` + `/api/idxs-for-block`: ✅ 2026-05-04
- M2-ε `tracemiku-core::function_index` + `/api/functions`: ✅ 2026-05-04
- M2-ε `/api/last-write-of-reg`: ✅ 2026-05-04
- M2-ε examples/<so>/known_offsets.json overlay: ✅ 2026-05-04
- M2-ε frontend Functions panel (source-tagged list): ✅ 2026-05-04
- M2-ζ disasm mem_op extraction + Index mem ops: ✅ 2026-05-04
- M2-ζ tracemiku-core::memshadow port: ✅ 2026-05-04 (eager build; sidecar deferred)
- M2-ζ /api/strings + /api/mem-dump + StringsPanel: ✅ 2026-05-04
- M2-ζ scripts/m2_zeta_parity.py: ✅ 2026-05-04
- M3-α `tracemiku-core::calltree` port + `/api/call-tree` + CallTreePanel + parity script: ✅ 2026-05-04
- M3-α auto_known_offsets naming fix (`f_<0xhex>` → `sub_<hex>`, Python parity, caught by parity gate): ✅ 2026-05-04
- M3-β `tracemiku-core::taint` (forward/backward index-accelerated, BFS via VecDeque, frame_depth_map): ✅ 2026-05-04
- M3-β /api/forward-taint + /api/backward-taint + TaintPanel: ✅ 2026-05-04
- M3-β scripts/m3_beta_parity.py: ✅ 2026-05-04 (both endpoints HARD-gated; forward 0.90 / backward 0.81)
- M3-disasm-followup ARM64 pre/post-indexed writeback in decoder.rs: ✅ 2026-05-04 (closed M3-γ backward parity gap)
- M3-δ tracemiku-core::decompiler::{ir,backend,builder}: ✅ 2026-05-04 (skeleton — root F0 only; advanced features in M3-ε)
- M3-δ /api/dec/summary + DecompilerPanel + scripts/m3_delta_parity.py: ✅ 2026-05-04 (parity soft-gated 0.01 jaccard pending M3-ε symbol fallback)
- M3-ε split_top_k_callees in build_trace_ir (metadata only, no BlockIR yet): ✅ 2026-05-04
- M3-ε /api/dec/summary symbol-source fallback + parity HARD-gate (0.99 jaccard on real trace): ✅ 2026-05-04
- M3-ζ BlockIR construction skeleton (id/pc/end_pc/insns/exec_count for F0 + split FuncIRs; stable B0..Bn ids; build_trace_ir gains &CFG): ✅ 2026-05-04
- M3-η BlockIR.asm rendering + samples extraction (per-PC first-idx map; x0..x3 + sp at first occurrence): ✅ 2026-05-04
- M3-η BlockIR.tier classification (hot top-150 by exec_count, warm, cold): ✅ 2026-05-04
- M3-θ /api/dec/fn/{id} + render_func_md skeleton (header + metadata + per-block asm/samples; trace:* + bare F0): ✅ 2026-05-04
- M3-ι BlockIR.exits + cfg EdgeMeta (kind/count) + render_summary_md fidelity: ✅ 2026-05-04
- M3-ι2a type_anchor.py port + auto-discovery + render section: ✅ 2026-05-04
- M3-ι2b ollvmdet.py + vm_candidate.py port + summary VM-candidates body fidelity: ✅ 2026-05-04
- M3-ι2c `/api/dec/fn/{id}` sym:* / cfg:* source support + scripts/m3_iota_parity.py real-trace HARD gate: ✅ 2026-05-04 (summary fns 0.978 / summary_md 0.943 / F0 md 0.969 / VM candidate exact)
- M3-ι2d `/api/dec/llm-call` + `/api/dec/models` Rust port: ✅ 2026-05-04 (prompt bundle + claude/deepseek/qwen/mimo reqwest adapters + success cache; mock-provider tests, no real API calls)
- M3-γ backward MEM-chasing + d0.regs_def initial seed: ✅ 2026-05-04 (algorithm correct; parity tightening pending disasm follow-up)
- M3-γ through_mem byte-overlap (forward + backward) + MemShadow.latest_write_idx_strict_before: ✅ 2026-05-04
- M3-γ data_only flag + DEFAULT_FRAME_REGS: ✅ 2026-05-04
- M3-γ cross_fn_call wire (frame_depth row field): ✅ 2026-05-04
- M3-γ frontend TaintPanel toggles + depth column: ✅ 2026-05-04

- M3-α: calltree + /api/call-tree + CallTreePanel + parity ✅ 2026-05-04
- M3-β: basic taint forward/backward + frame_depth + 2 endpoints + TaintPanel + parity ✅ 2026-05-04 (forward green; backward soft-gated)
- M3-γ: advanced taint (MEM-chasing + through_mem + data_only + cross_fn_call) + frontend toggles ✅ 2026-05-04
- M3-δ: decompiler skeleton — ir + backend stub + builder skeleton + /api/dec/summary + DecompilerPanel + parity (soft) ✅ 2026-05-04
- M3-ε: split_top_k_callees + /api/dec/summary symbol-source fallback + parity hard-gate ✅ 2026-05-04
- M3-ζ: BlockIR construction skeleton (id/pc/end_pc/insns/exec_count) ✅ 2026-05-04
- M3-η: BlockIR asm + samples + tier ✅ 2026-05-04
- M3-θ: /api/dec/fn/{id} + render_func_md skeleton ✅ 2026-05-04
- M3-ι: BlockIR.exits + render_summary_md ✅ 2026-05-04
- M3-ι2a: type_anchor.py port + tools/hooks/ auto-discovery + render type-anchors section ✅ 2026-05-04
- M3-ι2b: ollvmdet + vm_candidate port + summary VM-candidates hex-dump body ✅ 2026-05-04
- M3-ι2c: /api/dec/fn/{id} sym:* / cfg:* source support + real-trace parity script m3_iota_parity.py covering type_anchor + vm_candidate + summary ✅ 2026-05-04
- M3-ι2d: /api/dec/llm-call (LLM client port: claude / deepseek / qwen / mimo via reqwest + serde JSON) ✅ 2026-05-04. `bn:*` dec_fn remains gated on Rust BN sidecar/backend (M6).
- M3-κ: Graph panel SVG (`/api/cfg-svg` via Graphviz dot + Solid Graph panel) ✅ 2026-05-04
- M3-λ: memshadow v3 binary sidecar (`trace.bin.memshadow.v3.bin`) ✅ 2026-05-04
- M3-μ: Python viewer cutover prep — Rust CLI route wrappers + list/info parity; legacy delete deferred to M7 sign-off ✅ 2026-05-04
- M3-ν: inspect endpoints `/api/search`, `/api/so-stats`, `/api/reg-value-at`, `/api/reg-at-idx` ✅ 2026-05-04
- M3-ξ: CLI wrappers for `idxs-for-pc`, `search`/`search-asm`, `so-stats`, `reg-value-at`/`reg-at-idx` ✅ 2026-05-04
- M3-ο: Rust `TraceMeta.fork_events` + `/api/fork-events` + CLI wrapper ✅ 2026-05-04
- M3-π: MemShadow/Index memory query endpoints + CLI wrappers (`last-write-of-addr`, `idxs-touching-*`, `find-mem-pattern`) ✅ 2026-05-04
- M3-ρ: navigation endpoints `/api/block-for-pc`, `/api/block`, `/api/loops`, `/api/backtrace` ✅ 2026-05-04
- M3-σ: `/api/call-chain` + CLI wrapper ✅ 2026-05-04
- M3-τ: `/api/data-chase` + CLI wrapper ✅ 2026-05-04
- M3-υ: `/api/reg-timeline` + `/api/mem-diff` and CLI wrappers ✅ 2026-05-04
- M3-φ: `/api/mem-flow` + CLI wrapper ✅ 2026-05-04
- M3-χ: `/api/search-pc` + CLI wrapper ✅ 2026-05-04
- M3-ψ: `/api/ollvm-detect-vm` + CLI wrapper ✅ 2026-05-04
- M3-ω: `/api/fn-summary` + CLI wrapper ✅ 2026-05-04
- M3-crypto: `/api/crypto-scan` + CLI wrapper ✅ 2026-05-04
- M3-string-provenance: `/api/string-provenance` ✅ 2026-05-04
- M3-hash-finalize: `/api/hash-finalize-detect` + CLI wrapper ✅ 2026-05-04
- M3-auto-phase: `/api/auto-phase-detect` + CLI wrapper ✅ 2026-05-04
- M3-jni-events: `/api/jni-events` ✅ 2026-05-04
- M3-jni-calls: `/api/jni-calls` + CLI wrapper ✅ 2026-05-04
- M4-α: shared selected-record cursor + Registers / Memory hex dump / Trace-for-PC panels ✅ 2026-05-04
- M4 (next): TS frontend core polish / remaining panels (Backtrace, Forks, Xref, Settings, Memory diff, richer Decompile UX)
- M3-M7: 见 spec §9 milestones

**M3-γ scope (history):**
1. ✅ Rust `backward_taint`: MEM-chasing + d0.regs_def initial seed shipped (commit `e031c2c`).
1a. ✅ **Closed** — Rust disasm writeback handling: `decoder.rs::build_reg_accesses` now adds the base reg to `regs_def` when `Arm64Detail::writeback() == true`. Capstone-rs 0.13 doesn't have a top-level `cs.regs_access()` analogue to Python's, but exposes the same info via the per-instruction `writeback()` flag + manual operand walk. Backward parity moved from 0.31 → 0.81 jaccard; gate hard-tightened.
2. Rust `forward_taint` + `backward_taint`: add `through_mem: bool` flag (when true, byte-overlap via MemShadow; when false, exact-addr fast path).
3. Rust `forward_taint` + `backward_taint`: add `data_only: bool` flag (filter addressing-reg propagation; DEFAULT_FRAME_REGS exclusion when data_only=True).
4. Wire `cross_fn_call: bool` flag through endpoints; route handler annotates each row with `frame_depth: Option<u32>` from `state.frame_depths`.
5. Frontend: add 3 toggle checkboxes to TaintPanel (through_mem, data_only, cross_fn_call) + frame_depth column.
6. Re-run `scripts/m3_beta_parity.py` to confirm backward jaccard ≥ 0.6 (forward should remain ≥ 0.6 too).

## ⚠ 部分完成 (2026-05-03 — FunctionIndex / Web Refactor)

**已落地**: `viewer.function_index` 模块, `/api/functions` 端点, `trace:F0` / `sym:<name>`
稳定 id, 老 `F0` / `cfg:<name>` 兼容, Decompile 不再卡 BG CFG (sync fallback 测试钉住),
前端 Functions 面板改吃 `/api/functions`. **807 passed / 10 skipped / 0 failed**.

**未达成**(独立审查发现, 见下面 P0-Next-FollowUp):

1. `bn:<addr>` 仅模型层支持, **`/api/functions` 不枚举 BN 函数**
   (`_build_function_index` 不传 `bn_funcs`, `counts.bn` 永远 0).
2. 前端 HLIL tab 仍按 cursor PC 查 `/api/hlil-for-pc`, **没消费 `/api/hlil-for-fn`**.
   FunctionIndex 不是 HLIL 的 canonical source.
3. LLIL `scope=body` 只对 `trace:F0` 生效 (root trace view), UI 文案没说清楚.

**已修(本节追加)**:

- `_resolve_dec_fn` 改返回 `(fn, canonical_id)`, 调 `top.fn()` / `build_fn_decompile_prompt()`
  用 canonical id; 之前默认选 `trace:F0` 点 LLM raw 必挂 (HTTP 400, KeyError).
- 前端 LLM raw cache key 加 `split_top_k` / `split_min_records` (改参数后不复用旧 cache).

| # | 项 | commit |
|---|---|---|
| T0 | refactor(web) handoff baseline — BN HLIL cap + LLIL scope + dec sym-fn fallback | 649a67b |
| T0+ | fix(web) baseline review — non-mutating llm-call + source-tag align + cfg sync | fba791d |
| T1 | test(fixture) trace_root_two_callees — root calls f_alpha + f_beta | 8a8cae6 |
| T2 | test(web) pin equivalence snapshots before refactor | 3472c11 |
| T3 | feat(viewer) FunctionIndex — unified fn model for web/cli/sdk | b28eb1c |
| T3+ | fix(viewer) FunctionIndex polish — strict parse_id, drop private call | 5b7ce93 |
| T4 | feat(web) GET /api/functions — unified FunctionIndex endpoint | ca7f66c |
| T5 | feat(web) dec endpoints migrate to prefixed fn ids | f09c265 |
| T6 | feat(web ui) Functions panel + Decompile consume /api/functions | 3708e06 |
| T7 | test(web) pin dec/fn sync-CFG fallback — sym:* must not block on BG | 456aaa0 |
| T8 | feat(web) /api/hlil-for-fn — FunctionIndex-keyed HLIL lookup (端点已开, 前端未接) | 62af3ec |

(再加 T9 / 修复 commit 见 git log)

---

# P0-Next-FollowUp — FunctionIndex 真正全量统一

> 上一轮宣称"完成", 实际只覆盖 trace:* + sym:*. 这三项做完才算真正符合
> 设计文档 ("/api/functions canonical source across Functions / CFG / HLIL / Decompile").

- **F1**: `_build_function_index` 在 `DECOMP["status"] == "ready"` 时从 BN backend
  枚举 functions 传入 `bn_funcs`. `_resolve_dec_fn` 加 `src == "bn"` 分支
  (resolve 到 BN-backed FuncIR 或 fallback 到 HLIL). 加 `test_api_functions_includes_bn`
  (BN-gated). 接入后 `counts.bn > 0` for `--so` 启动的 trace.
- **F2**: 前端 HLIL tab 加 "follow function selection" 模式: 当 Functions 面板/Decompile
  选中 fn 时自动调 `/api/hlil-for-fn` 而不是按 cursor PC. 至少 Functions 面板
  双击/右键给 "在 HLIL 里看" 选项.
- **F3**: LLIL `scope=body` 通用化到任意 fn (用 calltree per-frame range),
  stats 加 `body_only_applied: bool` 让前端区分 "无 callee 排除" vs
  "filter 不适用此 fn". 或保持现状但 UI 文案改成 "Body only (root only)".

合入门槛: F1 + F2 + F3 任一项实现就更新本节, 或写明 deferred reason.

| # | 项 | commit |
|---|---|---|
| T0 | refactor(web) handoff baseline — BN HLIL cap + LLIL scope + dec sym-fn fallback | 649a67b |
| T0+ | fix(web) baseline review — non-mutating llm-call + source-tag align + cfg sync | fba791d |
| T1 | test(fixture) trace_root_two_callees — root calls f_alpha + f_beta | 8a8cae6 |
| T2 | test(web) pin equivalence snapshots before refactor | 3472c11 |
| T3 | feat(viewer) FunctionIndex — unified fn model for web/cli/sdk | b28eb1c |
| T3+ | fix(viewer) FunctionIndex polish — strict parse_id, drop private call | 5b7ce93 |
| T4 | feat(web) GET /api/functions — unified FunctionIndex endpoint | ca7f66c |
| T5 | feat(web) dec endpoints migrate to prefixed fn ids | f09c265 |
| T6 | feat(web ui) Functions panel + Decompile consume /api/functions | 3708e06 |
| T7 | test(web) pin dec/fn sync-CFG fallback — sym:* must not block on BG | 456aaa0 |
| T8 | feat(web) /api/hlil-for-fn — FunctionIndex-keyed HLIL lookup | 62af3ec |

新增模块: `viewer/function_index.py` (FunctionEntry / FunctionIndex / parse_id).
新增 endpoint: `GET /api/functions`, `GET /api/hlil-for-fn`.
SDK exports: `from viewer import FunctionIndex, FunctionEntry, parse_id, make_*_id`.

## ✅ 已完成 (2026-05-02 single session)

### P0 (6/6) — 全部 ship + tests pass

| # | 项 | commit |
|---|---|---|
| P0-5 | taint cap=5000 + stopped_at_max + 加载全部按钮 + DoS clamp | 644b316 |
| P0-3 | Web 同步 11 个 CLI endpoint (4 batches A-D) | b9cd80c · 2788a47 · f29afdf · 6b04e3c |
| P0-2 | viewer 集成 jni_hooks.jsonl (Trace.jni_events lazy + display annot) | 6ff4860 |
| P0-4 | hex dump 紫色区分 external write (kind='x') | 174d063 |
| P0-6 | trace 失败诊断 + miku-shield URL hint | ba14908 |
| P0-1 | Call Tree tab (bl/ret pair walking) | 23c0829 |

### P1 (4/4) — 全部完成

| # | 项 | commit | 备注 |
|---|---|---|---|
| P1-A | taint --cross-fn-call (frame_depth 标注) | 416c4fa | viewer-only, 全量 propagation 待真机 |
| P1-B | hash-finalize-detect (闭环 crypto-scan) | fbf735d | u32x5 / byte_seq, window-based |
| P1-D | ollvm-detect-vm heuristic | 4328364 | confidence-scored, 仅 detect 不 decode |
| P1-C M1 | agent fork hook (libc fork/clone/__bionic_clone) | 3406512 | **真机 PASS**, vfork 因 Bionic 调用约定不抓 |
| P1-C M2 | race-attach child + child sessions teardown | 16a8500 | 实测 spawn_gating 不抓 fork; race-attach 在 ptrace 服务上 F3 timeout (架构限制) |
| P1-C M3 | proc poll lifecycle fallback (`/proc/<pid>/stat`) | 8afc2d9 | Tier 3 数据: runtime_ms, last_state, comm |
| P1-C M5 | CLI fork summary at trace end | 8afc2d9 | Total / Fully traced / Partial / Failed; ≥2 fail 推 miku-shield |
| P1-C M6 | Web SPA Forks tab UI | 8afc2d9 | 状态过滤下拉, 失败 fork 红色 + miku-shield banner |
| P1-C M7 | viewer fork-events read (CLI + /api + Trace.meta) | 5976c51 | 接收 agent 落盘 fork_events |
| P1-C M8 | e2e real-device smoke | 2e10dd4 | **真机 PASS** — 验证 F3 ptrace conflict 是真实约束, 文档化 |

### 反 OLLVM 实战补强 — CLI 工具批 (基础已落地)

- `mem-writes-in-range`: numpy mask, 200 hits ~30ms
- `mem-flow`: per-byte event timeline (含 readers_only / writers_only)
- `crypto-scan`: 22 标准原语 (SHA1/SHA256/MD5/AES SBOX+invSBOX+Rcon/TEA/
  ChaCha20/HMAC ipad/opad/SM3/SM4/Blake2/CRC32, LE 字节序内置)
- `taint-bwd/fwd --through-mem`: byte 级 mem overlap
- `find-mem-pattern --idx-lo/hi`: first_idx 范围过滤
- `reg-at-idx`, `call-chain`, `hash-input-search`, `auto-phase-detect`,
  `diff-traces`, `hash-finalize-detect`, `ollvm-detect-vm`, `fork-events`
- `MemShadow` sidecar 持久化 (`.memshadow.v2.npz`): cold 37s → warm 6s

### 解耦项目特定目标

- agent_cmodule_v5/v3.js 删 hardcoded `soPattern: "libsgmainso"` / `fnOffset`
- `SGMAIN_TGKILL_SVC_OFFSETS` → JSON spec (`tools/hooks/<so>_suicide.json`)
- `_hideMaps_filterLine` 用 STATE.soPattern 动态匹配
- 8 处 docstring + webui dropdown 抽象化

**累计**: 23 commits, 444 unit tests + 3 real-device smoke + 1 真机 anti-debug 复盘.

## 真机 e2e 实测发现 (2026-05-02)

完整 e2e (Taobao com.taobao.taobao + cmd 70102 doCommandNative) → 详见
[docs/anti-debug-libart.md](docs/anti-debug-libart.md).

**关键发现**: `--trace-deep` 触发 anti-debug self-kill. Stalker per-symbol exclude
libart 时, 在 excluded symbol BOUNDARY 装 inline-hook 改 libart `.text`. libsgmainso
anti-debug worker thread 周期性比对 libart bytes vs disk image, 检测到 → tgkill.

实验对照:
- minimal (无 deep/hide/patch): 15.4M records ✓
- 仅 `--patch-suicide`: 7.7M+ ✓
- 仅 `--hide-rwx-maps`: 9.7M ✓
- **仅 `--trace-deep`: 60k → SI_USER ✗**
- bare Frida attach (无 Stalker): 25s 0 kill events ✓

主线程零 libart `.text` 读 — 检测在 worker thread, 我们没 trace 到 exact PC.

**修复 (commit 6616d97)**: P0-6 诊断扩展 — SI_USER + 深栈 + `--trace-deep` 自动
建议关 `--trace-deep`. 真机 verify 自动给出建议:
```
=== Trace 死前诊断 (P0-6) ===
诊断: SI_USER + 深栈 — anti-debug 检测到 Frida 痕迹后 self-kill ...
强烈建议: 关 --trace-deep 重跑. ...
```

**未来增强 (新 backlog)**:
- `--block-self-kill` agent flag: hook libc tgkill/kill/pthread_kill/raise,
  signal=11/6 时返回 0 不发. 拦所有 signal-based anti-debug 自杀, 不依赖
  patch-suicide spec 完整性. ~1d 工作量.
- 逆向 anti-debug worker thread 找 exact 检测 PC: 需 --follow-workers 完整
  抓所有 libsgmainso 线程, 然后看哪条调用链通向 sub_45bbe0(arg, ...) 且 x6=131.
  每版本要重逆, ROI 较低.

---

## P1-C 真机验证发现 (重要架构事实)

实测两个 Frida 限制确认了 traceMiku 在 fork-tracing 上的能力边界:

1. **`enable_spawn_gating()` 不抓 fork()** — 只对 `device.spawn()` 后裔生效.
   `manual_child_gating_smoke.py` 真机 verify (2026-05). attach 到运行中
   进程后 fork 不发 `child-added` 事件.

2. **race-attach 在 ptrace-based Frida server 上 F3** — child 继承 parent 的
   ptrace 关系, 后续 `device.attach(child_pid)` 永久 block.
   `manual_m8_e2e_smoke.py` 真机 verify: 3/3 fork children timeout.

**结论**: traceMiku P1-C 在 ptrace-based Frida 配置 (含 miku-srv) 下:
- ✅ M1 fork-event Tier 1 (parent_pc, child_pid, syscall) 永远抓得到
- ✅ M3 proc poll lifecycle (Tier 3, runtime_ms 等) 永远抓得到
- ⚠ M2 race-attach 仅在 child 生命周期与 Frida 内部 ptrace 不冲突时偶尔成功 (实际几乎从不)
- ➜ **fork-based anti-debug 真正解决方案: miku-shield (eBPF kernel breakpoint, 无 ptrace)**

**已知 gap**:
- vfork() 在 Bionic 上 hook 不到 (特殊调用约定 bypass Interceptor.onLeave). 已 deprecated.
- F5 (parent 因 child 减速崩) 在 race-attach F3 主导下不太可能复现 (race-attach 直接超时, 不影响 parent timing).

---

# P1-C 设计 spec (历史归档, M1-M8 已 ship)

> 历史设计归档, 不作为当前 CLI 行为的权威说明. 当前 CLI 以
> `./tracemiku trace --help` 为准: `--child-trace-mode` 默认 `off`,
> `full/safe` 需要显式打开; fork lifecycle 轮询默认开, 用
> `--no-fork-poll-child` 关闭.

## 决定 (已全部锁定)

| 决定 | 选择 |
|---|---|
| child 进入方式 | **spawn-gated**: child SIGSTOP, agent 注入后 resume |
| trace 输出组织 | **parent_pid/child_pid 两份独立 trace dir**, viewer 可同时 load |
| JNI hooks 在 child 是否重装 | **是, 都装** (反调试 fork 也是功能实现一部分) |
| F5 处理 | 历史设计: **`--child-trace-mode=full\|safe`**. 当前 CLI 默认 `off`; `full/safe` 显式 opt-in. `safe` 语义保留为后续收敛项. |
| `clone(2)` flags 区分 | **fork-like (`CLONE_THREAD==0`) 走 P1-C; thread-like 仍走 `pthread_create` follow** |

## 7 种失败模式 (F1-F7)

| ID | 场景 | 拿到 | 缺失 | 用户提示 |
|---|---|---|---|---|
| F1 | 全程成功 | 一切 | — | 正常 |
| F2 | child 跑得比 agent init 还快 | parent PC, child PID, runtime, exit | 指令 trace | "child 提前退出" |
| F3 | child 自己 ptrace 父了 | parent PC, child PID, attach error | 指令 + exit | "推 miku-shield" |
| F4 | raw `clone(SIGCHLD)` Frida 没拦 | parent PC (额外 hook), child PID | 全部 child trace | "试 --extra-fork-syscalls" |
| F5 | parent 因 child 减速崩 | parent 崩前 idx | 完整业务 | "改 `--child-trace-mode=safe`" |
| F6 | child SIGKILL 提前死 | parent PC, child PID, exit signal | 部分 trace | "child 被强杀" |
| F7 | spawn-gating 不 work | parent PC, child PID 不知 | 全部 child | "检查 Frida / 升 Android" |

## Tier 1 最低保证 (M1 已实现)

```json
{
  "type": "fork-event",
  "trace_idx": 1234567,
  "parent_pc": "0x7608ed1234",
  "parent_pc_rel": "0x6b234",
  "parent_in_target": true,
  "parent_module": "libtarget.so",
  "syscall": "clone",
  "clone_flags": "0x1200011",
  "is_fork_like": true,
  "child_pid": 12345,
  "ts": 1730000000123,
  "attach_status": "not_attempted"
}
```

`attach_status`: `not_attempted` (M1, 当前) → `success` / `success_partial` /
`failed_ptrace_conflict` / `failed_spawn_gate_unavailable` / `failed_unknown` (M2/M3 后).

## 用户可见输出 (M5/M6 待实现)

### CLI 实时 (每 fork 一段) — M5

```
[trace] [FORK] parent_idx=1234567 +0x6b234 (sub_1a200) → child pid=12345
        ✓ attached, agent injected (clone flags=0x1200011, fork-like)
        ⚠ child exited too fast (45ms < agent_init=120ms), no instructions
        notes: 可能 anti-debug short-lived check, 推 miku-shield
```

### Trace 完成后 fork summary — M5

```
=== Fork Summary ===
Total fork-like:   7
  ✓ Fully traced:  3
  ⚠ Partial:       1   (child of call_003, 87 insns)
  ✗ Attach failed: 2   (F3 ptrace conflict / F7 spawn-gate unavailable)
  ⚠ Parent crashed:1   (F5 — child of call_005 → timing detection)
提示: 多个 child 抓不全, 可能这个 SO 用 fork-based anti-debug.
      推 miku-shield: github.com/ltlly/miku-shield
```

### Web SPA "Forks" tab — M6

- 主 timeline 上每个 fork 点画 ⏎ 标记, 点击展开
- 表格: parent_idx · parent_func+offset · child_pid · status · runtime · instructions · [跳 child trace]
- 失败 fork 红色, hover 显示具体 failure mode + 建议

### CLI / `/api/fork-events` — M7 已 ship

```bash
viewer fork-events traces/run1
viewer fork-events traces/run1 --status failed_ptrace_conflict
GET /api/fork-events?status=failed_ptrace_conflict
```

## --child-trace-mode 选项 (当前 CLI 摘要)

```
tracemiku trace ...                             # 默认: --child-trace-mode=off, 仅 Tier 1 fork-event + lifecycle poll
tracemiku trace ... --child-trace-mode=full     # fork-event 一到立即 race-attach child + 注入 same agent
tracemiku trace ... --child-trace-mode=safe     # 当前实现按 full 路径走; safe 限制语义待后续实现
tracemiku trace ... --no-fork-poll-child        # 关闭 child lifecycle 后台轮询
```

## 参考

- Frida 17 `Process.spawn(child)` API + `enableChildGating`
- Linux kernel `clone(2)` flags (CLONE_THREAD/CLONE_VM/CLONE_FILES/SIGCHLD)
- Android Bionic `__bionic_clone` wrapper
- HardTaint 跨进程 taint 处理章节

---

# P2 — 战略 / 待讨论

## P2-A: NEON / FP register record format v2 (future / 未实现)

**确认要做, 但当前 CLI 尚无 `--include-neon`** (用户接受 "不在乎向后兼容, 全量采集"):
- future `--include-neon` 选项, 开启后 record v2 加 32 个 V0..V31 (16B each)
- record 大小 272 → 784 字节, trace.bin 16GB → 47GB on 67M rec
- `meta.json` 加 `record_version: 2`, viewer 自适应 stride
- **自动检测**: trace 完毕 disasm 扫到 v?/s?/d?/q? operand → 当前先日志提示
  "目标含 NEON/FP, 当前未采集 SIMD 寄存器; 等 future --include-neon 支持后重采"

实现: agent CModule 加 NEON regfile 读取 (ARM64 fpsimd state) + record v2 写入;
viewer trace.py / disasm.py / index.py / display.py 全链路 stride 改;
host CLI 自动检测扫描后发警告.

## P2-B: Native `libgumTraceMiku.so` (调研先于实现)

**用户问题**: "好奇他对 fork 多线程怎么处理"

调研 task (1 周):
- 看 [revercc/gumTVM](https://github.com/revercc/gumTVM) 怎么处理 fork
- 多线程 Stalker.follow native 层协调 (per-thread ring 还是共享 ring?)
- 砍 frida-server 后注入机制 (ptrace? PT_INTERP hijack?)
- 输出: 调研报告决定是否开 native tracer

ROI 中等. 主要为长期独立化准备. 阻塞: miku-shield 方向决定后启动.

## P2-C: anti-debug L3 fork+ptrace+SIGSEGV 突破 (3-5d)

**判定**: miku-shield 出后这层自动失效, traceMiku **不再做**.
miku-shield 短期不可用 → fallback: P0-6 提示 + 用户自写 Frida bypass.

## P2-DEC: trace decompiler — LLM-friendly skeleton IR (路线 B, ~2 周)

**研究**: [`docs/trace-decompiler-research.md`](docs/trace-decompiler-research.md)
**设计**: [`docs/trace-decompiler-design.md`](docs/trace-decompiler-design.md)
  含 **§7.0 普适性原则** — 所有 PR 必须自查通过 (无硬编码变种).
**实测**: [`docs/poc-mimo-libsgmainso-2026-05.md`](docs/poc-mimo-libsgmainso-2026-05.md)

**定位**: 机器把 trace 折叠/类型推导/反 OLLVM, 输出紧凑结构化 IR;
反编译这一步交给 Claude/DeepSeek-R1/Qwen/mimo. 不写 19-stage codegen.

**ship 进度** (feat/trace-decompiler 分支):

| # | Stage | 状态 | 普适? | commit |
|---|---|---|---|---|
| DEC1 | 骨架 + IR + `tracemiku dec` CLI | ✅ | ✓ | 7749dd2 |
| DEC2 | Claude/DeepSeek/Qwen adapter + prompts | ✅ | ✓ | 1ee49a1 |
| DEC2+ | OpenCode/mimo backend + 端到端 PoC | ✅ | ✓ | 1032641 |
| DEC3-A | hot/warm/cold tier 渲染 (真机 -73%) | ✅ | ✓ | da22070 |
| DEC3-B0 | calltree 切子 FuncIR (1 fn → 10 fn) | ✅ | ✓ | baf4300 |
| DEC3-B | 类型锚点 (JSON-spec driven) | ✅ | ✓ | 92af597 |
| DEC3-D | VM 候选区段提取 (复用 ollvmdet, 不 disasm) | ✅ | ✓ | 2d171be |
| DEC3-C | 循环 induction var (numpy regression) | ✅ | ✓ | 345ae6a |
| DEC4 | 多模型 benchmark (`tracemiku dec-bench`) | ✅ | ✓ | 7a10f2c |
| DEC5 | README + TODO 同步 | ✅ | n/a | (本 commit) |

**累计**: 16 commits / ~6000 LOC / 525 tests pass. 真机 libsgmainso e2e:
- F1 sub_54820 → mimo 给出 3 层嵌套查找 + XOR 计算的具体 C + ABI
- F0 doCommandNative 含 VM hex evidence → mimo 给出完整 VM dispatcher
  (`uint16_t opcode = *(vm_pc+0x10); vm_pc += 0x10; handler_table[opcode]()`)
- 类型锚点 (cmd_init / lock_acquire / Mutex* / SgmainCtx*) 完整注入

**普适性合规要点** (设计 §7.0 强约束, PR review 必查):
- 不写死 SO 名 / opcode 编码 / fn 偏移 / 寄存器名
- "硬"知识全部从 JSON spec 读 (`tools/hooks/*.json` 用户驱动)
- 检测 ≠ 决定; 输出 confidence + reasons, 让 LLM 决
- ollvmdet.py 是先例正例 ("NEVER decode VM bytecode")

## P2-LLIL: 自研 BN-style 反编译器 (LLIL → SsaBlock → C-pseudo)

**定位**: P2-DEC 的"机器折叠 → LLM 反编译"是 IR 路线; P2-LLIL 是**直接写
反编译器**路线 — BN/IDA 风格 LLIL 表达式树 + block-local SSA + UIDF (trace
真值注入) + 多 pass 优化, 输出 C-like pseudocode 不靠 LLM. 长远目标:
**直接拿这套工具 100% 复刻 x-sign 算法**.

**入口**: `viewer/decompiler/llil/`, webui `/api/decompile?fn=…&pass=llil`
渲染到 SPA. 测试: `tests/test_llil_*.py` (跑 `uv run pytest tests/test_llil_*.py -q` 看数).

**Pipeline (8 主 pass + 多 extras)**:

```
lift_arm64 (capstone) → ssa_block → constfold → dce → flag_elim
  → typelat → struct_lat → var_unify → restructure → render_hlil
extras: uidf (trace 真值), memshadow LOAD-fold, string deref
```

**Stage 完成情况**:

| # | Stage | 测试 | 备注 |
|---|---|---|---|
| L0 | LlilExpr 表达式树 (BN 风格 op/size/operands/extra) | ✅ | 50+ op |
| L1 | lift_arm64 (capstone, ~80 op) | ✅ | madd/msub/smull/umull/sxt*/uxt*/sdiv/udiv/ubfx/sbfx/mrs/adr/adrp/ROR/ROL/indexed-addressing/w-form 归一 |
| L2 | block-local SSA (cur_versions / tag) | ✅ | 含 AAPCS64 call kill (caller-saved + nzcv) |
| L3 | constfold + dce | ✅ | env-driven, uidf 可注入 const |
| L4 | flag_elim (cmp+b.cond → IF(CMP_X)) | ✅ | |
| L5 | typelat (基础类型推 + ptr) | ✅ | |
| L6 | struct_lat (struct field 推断) | ✅ | |
| L6.5 | var_unify (BN x_NN/arg_N/cs_xN 命名) | ✅ | |
| L7 | restructure (CFG → if/while/for) | ✅ | indirect jump 走 cfg.succs |
| L8 | render_hlil (C-pseudo 输出) | ✅ | prologue/epilogue 折叠, local var 命名, ×N exec_count, call args, ret return-value, string 解密, ROR/ROL 函数式 |
| L1.5 | UIDF (trace 真值 → ObservedValues) | ✅ | SET_REG + CALL ret_x0 |

**累计**: LLIL pipeline + webui 集成完整 — 跑 `uv run pytest -q` 看实时通过数.

**最近一轮 (2026-05-03 session, 8 commits)**:

| # | commit | 内容 |
|---|---|---|
| 1 | b15f695 | render: memshadow string deref (OLLVM 加密 string 在 trace 中实际解密后 fold) |
| 2 | 0e9f451 | lift fix: `_first_reg_token` 归一 wN/wzr → xN/xzr (cbz/tbz SSA 正确) |
| 3 | 66dc32c | SSA: LLIL_CALL kill caller-saved (x0..x18, lr, nzcv per AAPCS64) |
| 4 | 9c3ce78 | render fix: cur_versions 同步 SSA call-kill, post-call read 拿 return version |
| 5 | fe566c5 | render: ret 显示 `return x0_vN` (AAPCS64 return value) |
| 6 | d1fd621 | LLIL: 加 ROR/ROL — crypto round op (lift + render `_ror(x,n)`/`_rol(x,n)`) |
| 7 | 8b3b712 | lift: indexed addressing `[base, idx, lsl #shift]` |
| 8 | c6cf114 | UIDF + render: call return-value 注释 (trace ret_x0 → `// → x0=0xff`) |

**P2-LLIL 下一步候选** (按优先级):
- 跨 block SSA full loop-phi refinement: worklist 不动点. 当前 `ssa_blocks_cfg` 已有 synthetic phi entry version + backedge incoming metadata refinement (含 backedge-only defs), 但循环内 use/exit version 尚未迭代到不动点.
- float / SIMD lift (NEON 寄存器目前没记, 见已知限制)
- 真机 BN HLIL 对比扫描 — 选 top-N `sub_*` 跑 viewer + BN 输出 diff
- LLIL-level taint propagation (复用 SSA def-use)
- 链 P2-DEC: LLIL 输出作为 LLM prompt 的 IR 层 (vs raw skeleton)

---

# ❄ 暂不做 (deferred, 不是 cancel)

| 项 | 原因 |
|---|---|
| **page-dirty 模式 (#52)** | 实际命中率 < 5%, 等出现具体 case 再做 |
| **server.py 1588 行拆分** | 1300 行闭包要重构成 class, 高风险低收益 |
| **MemShadow word-level numpy 结构化数组** | 当前 dict 在 6.8M trace 上 GB 级可扛, 等 4GB 超限再做 |
| **CFG 布局换 ghidra Decompiler Layout** | graphviz `dot` 凑合用 |
| **`Index.def_chain` / `use_chain` 改 stdlib `bisect`** | 微优化 5-10x 不影响用户 |
| **L5 glib `gmain` / `gdbus` 线程名** | miku-shield 出后自动失效 |
| **taint 跨函数全量 propagation** | P1-A 已加 frame_depth 标注; 全量 propagation 待真机验证后再扩展 |

---

# 🚫 别做 (用户明确否决)

| 项 | 原因 |
|---|---|
| drcov / EZCOV 输出 | 业务用不到, 不为 SEO 做事 |
| HardTaint pointer-only selective | 1GB 内可忍, 要全量信息 |
| WebSocket streaming | 采集崩了一半数据没了, 边采边看不符合场景 |
| Pwntools/pwndbg 兼容 | 安卓 App pwndbg 是伪需求 |
| VarBERT 集成 | 未来可能基于 trace 自写反编译器 |
| D-810-ng OLLVM VM decode | 不做集成 |
| dAngr symbolic execution | 加固 SO 几乎全 timeout, 投入产出不划算 |
| ollvm-vm-trace | VM IP 不一定在寄存器 (内存/栈/全局/交替/内联) |
| Frida 17 unrooted Android | LSP 和 repack 检测比 root 更严, 没 ETM 硬件 |
| ARM CoreSight ETM | 没硬件 |
| 自己写 OLLVM VM 反编译器 | 过度工程 |
| 重 link frida-agent.so 重命名 internal symbol | miku-shield 路线替代 |
| 完整重做 frida-server | stealth rename 已是恰当成本 |
| 分布式多机抓 trace | 单机 + multi-process (P1-C) 已足够 |
| TUI 任何新功能 | TUI 冻结决定不变 |

---

# 已知限制 (设计如此, 不修)

- **NEON/FP 寄存器没记** → 见 P2-A record v2 (确认要做).
- **vfork() 在 Bionic 上 hook 不到** (P1-C M1) — 已 deprecated, 实际反调试场景不影响.
- **字符串只能从 MemShadow 抠** — trace 没读到的字节没法识别字符串.
- **TUI (`viewer/app.py`) 冻结** — Web 是唯一 UI.

---

# miku-shield 边界 (独立项目, 不在 traceMiku 名下)

`miku-shield` (~/Code/miku-shield, github.com/ltlly/miku-shield) 是 traceMiku 的姐妹
项目, 不在本 TODO 维护. **唯一耦合点**:

- **P0-6 trace 报错提示**: 检测到 anti-debug 指纹时引用 miku-shield URL.
- README 加段 "L3+ 反调试推荐 miku-shield".

不做:
- ❌ tracemiku 自动 spawn miku-shield daemon
- ❌ 统一 CLI `miku trace` / `miku shield` (用户群不同)

---

# 待探讨

- miku-shield 与 traceMiku 协作的更多场景? (除 P0-6 错误诊断外)
- 自研反编译器路线 (vs 接 VarBERT) 的长期规划?
- P1-A 跨函数 taint 的 callee 选择策略 (走 trace 实际进入的还是 sym 静态调用图)?

---

# 关键参考资源

## 同类项目对照

- **Frinet** (Synacktiv SSTIC 2024) — https://github.com/synacktiv/frinet
- **Lighthouse** — https://github.com/gaasedelen/lighthouse
- **eDBG** (ShinoLeah) — https://github.com/ShinoLeah/eDBG (eBPF kernel breakpoint)

## 论文 / 研究

- **HardTaint** (OOPSLA 2024) — https://arxiv.org/abs/2402.17241
- **Purifire / "To Unpack or Not to Unpack"** (arXiv 2509.16340)
- **XTrace** (字节跳动 arXiv 2512.21555, 2025-12)

## 实操文档

- **DetectFrida** (darvincisec) — https://github.com/darvincisec/DetectFrida
- **NVISO: Patching ARM64 .init_array** —
  https://blog.nviso.eu/2025/10/14/patching-android-arm64-library-initializers-for-easy-frida-instrumentation-and-debugging/
- **PolyTracker TDAG** — https://github.com/trailofbits/polytracker
