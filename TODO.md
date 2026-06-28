# TODO — traceMiku

> The single source-of-truth backlog for the whole toolchain (tracer, Rust
> core/server/CLI, frontend, vendored runtime) — not just the decompiler.
>
> Last updated: 2026-06-02 (Wave 1+2 workflow: all 26 decompiler audit tasks implemented, see below)

## AI runtime-truth CLI — tool-neutral (SO,offset) interop (2026-06-27)

> Strategy: `docs/competitive/ai-cli-strategy-2026-06-27.md`. traceMiku owns the
> runtime-truth axis static tools (IDA/BN/Ghidra, CLI or UI) structurally can't,
> joined to any disassembler only via the shared `(SO, static-offset)` coordinate.
> All four P0 commands: tool-neutral, in-process oneshot, CLI+server+wrapper
>三层贯通, adversarially validated on a real liblynxsecurity trace.

- [x] **P0 — 地址互操作地基**: `GET /api/resolve` + `query resolve`. 双向
  `(SO,offset)<->PC`, 工具中立名匹配(全路径/basename/前缀/子串), 回带运行时事实
  (exec_count/first-last_idx/in_module/executed), ambiguous/out_of_range/miss 区分。
  core `ModuleResolver::resolve_offset_candidates`. 偏移/地址默认 HEX (`d`-前缀十进制)。
- [x] **P0 — 间接跳转/调用解析**: `GET /api/indirect-targets` + `query indirect-targets`.
  br/blr 真实跳转目标分布+命中次数, 源/目标都回带坐标, `--min-count` 过滤, 列全部模式。
  复用 `cfg::resolve_indirect_branch_targets`。
- [x] **P0 — 运行时解密内存/代码导出**: `GET /api/mem-export` + `query mem-export`.
  按 `(SO,offset,len)` 导出 MemShadow w/x/i 真值, hex blob + provenance runs + 直方图
  + completeness, `??` 绝不冒充真零, `--out` 写原始字节供 loadfile。
- [x] **P0 — 运行时值点查**: `GET /api/reg-at` + `query reg-at`. `(SO,offset)|PC` 处寄存器
  全执行值 + 跨执行去重值分布(带计数+provenance)。

- [x] **P1 — 反向数据流/lineage 偏移键化**: `taint-bwd`/`bfs-slice` 加
  `--so/--off/--occurrence` (CLI `resolve_offset_to_idx` 复用 resolve+idxs-for-pc
  同一 app)。`forward-dep-tree`/`byte-lineage` 可后续同法键化。
- [x] **P1 — 路径覆盖**: `GET /api/coverage` + `query coverage`。函数执行块 +
  分支方向塌缩 (条件分支实际走向/命中次数, one_sided 标注静态歧义塌缩)。
- [ ] **P1 — 内存完整性 Phase 2 (syscall/JNI 回读)**: 给 mem-export/reg-at 补内核写的
  buffer (read/recv/stat/getrandom)。**触 device agent, 风险高, 最后做**。设计见
  `docs/competitive/runtime-truth-big-features-2026-06-27.md` 大件 C。

## 运行时真相大件 (设计已定, 见 runtime-truth-big-features-2026-06-27.md)

- [ ] **大件 A — trace-anchored 重放生成器** (`replay-export`): 用 trace 当 oracle 的
  确定性重放+校验+填洞。A1 校验式重放(纯host, 顺带 lifter 回归测试)优先。
- [ ] **大件 B — provenance 注解的 AI 友好反编译**: IL token 流每个值带来源标注
  (mem/reg/syscall/import/??)。B1 token provenance 优先。
- [ ] **大件 C — syscall/JNI Phase 2** (= 上面 P1 末项)。

## 运行时真相 CLI — 收尾 / 前端接线 (本轮未做, 2026-06-27 勘察)

> 5 个新 route (resolve/indirect-targets/mem-export/reg-at/coverage) 已三层贯通
> 到 CLI+server+wrapper, 但**前端零接线**。战略上这些主要是 AI/CLI 面 (人走
> IDA/BN/Ghidra), 所以前端接线**价值存疑**, 只挑人在 Web 看 CFG 时的刚需做。

- [ ] **coverage 叠加到 CFG 视图**: 把 `/api/coverage` 的分支方向塌缩 (one_sided /
  taken vs fall 命中数) 画到 Web CFG 边上。价值: 人看 CFG 时最直观的运行时事实。
- [ ] **indirect-targets 画成 CFG 边**: `br x8` 的真实目标分布画成边 + 命中数标签。
  注意已有 `EdgeKind::IndirectDispatch` + cfg-svg 的 large-overview 通路, 复用。
- [ ] (可选, 低价值) `resolve`/`reg-at`/`mem-export` 接 client.ts — 更像 CLI/AI 工具,
  接进 UI 收益低, 仅在确有交互需求时做。
- [ ] **CLAUDE.md AI 指南已补** (本轮): runtime-truth 命令块 + Code Map 已更新;
  若后续加命令记得同步该块 + `/openapi.json` route coverage 测试。

## P0 — Core Correctness

- [x] ARM64 lifter: 99.93-100% LLIL coverage, 0 bare Intrinsic
- [x] Call target name resolution: `0xHEX()` → `sub_xxx()`
- [x] Flag elimination: cmp+b.cond → direct comparison
- [x] **Call parameters**: trace x0-x7 values extracted and displayed at call sites
- [x] **Indirect call resolution**: blr x8 → resolve actual target from trace data
- [x] **Function boundaries**: ret/blr boundary detection, sub_8a7b8: 438→75 lines

## P1 — Decompile UI (对标 IDA/BN/Ghidra)

- [x] **Cursor sync (click→jump)**: click decompile line → jump assembly cursor to matching PC
- [x] **Line click → jump**: extract PC from line, resolve via /api/idxs-for-pc, jump
- [x] **Variable hover**: mouseover variable → show value(s) from trace records
- [x] **Variable rename**: double-click var → rename, propagate across function
- [x] **Variable type**: right-click → set type (int32_t/uint64_t/char*/struct*)
- [x] **Fold/unfold blocks**: collapse {} code blocks, collapse stack frame
- [x] **Highlight current line**: cursor moves → highlight matching decompile line

## P2 — Analysis

- [x] Xrefs from decompile: right-click → show all references to variable
- [x] Decompile diff: compare two trace snapshots
- [x] Global variable resolution from ELF symbols
- [x] Stack variable auto-naming
- [x] Type recovery through call boundaries

## Memory completeness — layered ground-truth oracle

> Design: `docs/memory-completeness-design.md`. MemShadow is now a layered byte
> oracle: every `byte_at` returns `(value, kind, src)` where kind ∈
> {w=store, r=load, x=external/syscall, i=initial-snapshot, ??=unknown}.

- [x] **Phase 1 — initial memory snapshot (`--snapshot-mem`)**: agent captures
  real device memory at t=0 (`tracer/src/sidecar/mem_snapshot.ts`), host pulls
  `memory_snapshot.bin`, MemShadow loads it as the `i` fallback layer
  (`memshadow.rs::MemSnapshot`). Verified on libsgmainso x-sign: a
  snapshot-covered address that the trace never wrote now returns
  completeness=1.0 with kind `i` (was `??`). Recovers pre-trace data: decrypted
  VM bytecode tables, `.rodata` constants, embedded keys.
- [ ] **Phase 2 — syscall output-buffer readback**: extend `semantic.ts` hooks
  with an out-buffer ABI table (read/recvfrom/stat/gettimeofday/getrandom/...),
  read the buffer on onLeave, emit as `ext-write` (kind `x`). Precise, universal
  fix for kernel-written buffers. Reuses `external_writes.bin` channel.
- [ ] **Phase 3 — live mem-operand capture (`--capture-mem-operands`)**:
  GumTrace-style — Capstone-decode operands in the callout and `readByteArray`
  real bytes. Opt-in (slower than register-only snapshot). Deferred.
- [ ] **Tenet export**: emit `reg=val,mr=addr:bytes,mw=...` per line so traces
  load in IDA's Tenet plugin for time-travel debugging. Interop, not rebuild.

## P3 — Polish

- [x] Decompile-to-C export
- [x] Search within decompile
- [x] Decompile history (back/forward)

## Done (Recent)

- [x] Ghidra-style Pass framework: 55/62 Actions, 6-phase pipeline
- [x] Decompile panel: LLIL/MLIL/HLIL sub-tabs, lazy text loading
- [x] 7 ARM64 test binaries, 56+ functions, 563+ tests
- [x] BN vs traceMiku systematic comparison
- [x] Android .so compiled + pushed to device

## Bugs — Interaction & Correctness

- [x] **First function after WebUI start shows "no HLIL"**: fixed by adding `include_text` to PipelineSource, ensuring showText changes trigger re-fetch.
- [x] **IDA/BN interaction parity**: type dialog now accepts C expressions (IDA Y key), rename validates (IDA N key), hover shows values.
- [x] **`&gt;` / `&lt;` HTML entities**: fixed by running syntax highlighting on raw text before HTML escaping, preventing entity splitting.
- [x] **Double-click rename validation**: rejects empty, numeric-only, C keywords, and duplicate names.
- [x] **Right-click set type → input dialog**: replaced fixed menu with C type expression input field (accepts pointers, structs, typedefs).
- [x] **Auto-select function from assembly cursor**: App.tsx now watches cursorHint and auto-selects containing function.
- [x] **Goto/Label emitted in IL**: added label insertion pass that collects Goto/If targets and emits Label expressions.
- [x] **Tasks window**: emits "cancelled" status on panel close/inactive, allowing task center to dismiss.
- [x] **Assembly scroll snap on click**: uses live DOM scrollTop instead of potentially-stale signal for visibility check.
- [x] **IL pipeline passes now running**: constfold, DCE, Ghidra-style universal pipeline (simplify, const-prop, type-prop, struct recovery) called in decompile_trace().
- [x] **Assembly hover values**: added `loadAddrTitle` for address token hover, register hover already existed.

## Done — Infrastructure & Reliability (2026-05)

- [x] **maxRecords CModule enforcement**: agent CModule `on_insn` checks hard cap, ring heartbeat auto-finalizes with `truncated: true`
- [x] **`--remote` default USB-first**: `--remote` default changed from `"127.0.0.1:6699"` to `None`; USB is now default connection
- [x] **`tracemiku probe`**: lightweight Interceptor export counting mode (no Stalker, no trace.bin); reports call frequency and avg latency
- [x] **`make test-device`**: device integration test — cross-compile ARM64 C target, push, trace, verify output alignment/records

## Done — Crypto Scan Stack (2026-05)

- [x] **`crypto_scan` core**: constant-fingerprint scanner (MD5/SHA round constants, AES/SM3/SM4 tables, CRC32C, FNV, Murmur3, xxHash, Poly1305, ChaCha20, RC4 identity table) + ARM Crypto Extensions instruction detection
- [x] **`/api/crypto-scan`**: instruction-level constant hits with verdict classification
- [x] **`/api/crypto-analysis`**: combined MemShadow byte-pattern + constant + ARM CE hardware-instruction scan
- [x] **`tracemiku crypto <call_dir>` CLI**: wraps `/api/crypto-analysis` (Rust CLI `crypto` subcommand, JSON output)
- [x] **CryptoPanel** (`frontend/src/panels/crypto/CryptoPanel.tsx`): Memory / Instructions / Hardware sub-tabs in the left panel

## Done — Spawn Hook & Anti-Detection (2026-05)

- [x] **Spawn-mode JNI_OnLoad timing race break**: spawn-gating + spawn hook pipeline to instrument before `JNI_OnLoad` runs
- [x] **Signature SO full scan**: signature-analysis sweep across signing/anti-debug SOs (target-agnostic, spec-driven)
- [x] **Anti-detect plugin framework**: `--anti-detect <id>` registry; `hide_rwx_maps`, `patch_suicide` plugins (`tracer/src/anti_detect/`)
- [x] **Anti-detection catalog**: `docs/anti-detection-catalog.md` — L1–L10 detection taxonomy and traceMiku coverage status

## Done — Vendored Frida Runtime (2026-05)

- [x] **frida-server 17.9.11 from source**: `vendor/frida-patched/miku-trace-server-17.9.11` (53 MB arm64), Stalker literal-pool overflow fix (PR #1113), codeslab fallback, Florida anti-detect patches, `frida`→`miku` rename
- [x] **`frida_agent_main` symbol kept**: reverted Florida 0003 (renaming broke Vala-generated symbol/export-file linkage)
- [x] **`install-stealth.sh`**: push + launch helper; non-default port + app cache dir trace output

## Bugs / Open

- [ ] Audit Rust server layer for band-aid architecture in `rust/crates/tracemiku-server/src` (text post-processing after semantic rendering, sentinel values, route-level repair logic, flattened response shapes).
- Known structural improvements completed in Wave 1+2 workflow (2026-06-02).
  See `docs/decompiler-audit-2026-06-01.md` for the full benchmark — all 26
  items from the audit are now implemented. Remaining: variable merging (needs
  cross-block SSA migration), and iterative refinement of new passes.

### Critical — blocking decompiler quality

- [x] **Concretize observed values into IL constants (Phase 1b)**: `inject_observed_constants()` wired into `il_pipeline.rs`; observed_const_count in PipelineResult. Wave 1.
- [x] **Path specialization → CFG (Phase 2 complete)**: `executed_edge_filter()` in `hlil/pass_restructure.rs` filters CFG edges by trace execution; OLLVM dispatcher blocks collapse to direct jumps. Wave 2.
- [x] **HLIL For/Switch/Break/Continue unwired**: wired in `hlil/pass_restructure.rs` (For/Switch detection, Break/Continue insertion, 5-hop convergence) + `hlil/render.rs`. Wave 1.
- [x] **Cross-block SSA**: MULTIEQUAL/Phi opcode in `llil/expr.rs`; Bilardi-Pingali Phi placement using CHK dominator from `cfg.rs`; dominator-tree variable renaming in `llil/ssa.rs`. Wave 2.

### High — major quality/accuracy improvements

- [x] **Type system expansion**: 15+ TypeKind (Int8-Uint64, Float32/64, Struct/Array/Union/FuncPtr/Void); signedness; 15 TypeOp rules for high-frequency ARM64 ops; meet/join lattice. Wave 2.
- [x] **Simplify rules**: 10 rules added (ConstBinop, BitwiseIdentity, ExtensionChain, ShiftIdentity, SignBit, DoubleCompare, BoolFlip, CopyPropLocal, ShiftFold, AddrArith) with per-opcode indexed tables. Wave 1.
- [ ] **Variable merging**: Varnode→HighVariable→VariableGroup chain. Depends on cross-block SSA migration (SSA done, renaming needed). Deferred.
- [x] **MemShadow → decompiler**: `il_pipeline.rs` passes MemShadow to struct recovery; `pass_struct_recovery.rs` now supports scaled index, negative offsets, observed-address clustering via `suggest_type_from_bytes()`. Wave 1.
- [x] **Dominator O(n²) → Cooper-Harvey-Kennedy**: shared O(n) engine in `cfg.rs` (`compute_idom_cooper`, `compute_dominator_tree`, `compute_dominance_frontiers`); callers migrated. Wave 1+2.
- [x] **Parameter identification**: `identify_parameters()` scores x0-x7 via pointer/usage/callee-pass heuristics; classifies Pointer/SmallInt/Handle/StringPtr; rendered as HLIL comment. Wave 1.

### Medium — significant polish

- [x] **Jump table recovery**: `resolve_jump_table_targets()` consumes trace records for indirect br targets; annotates switch cases. Wave 1.
- [x] **Token-based C rendering**: `CToken`/`CTokenKind` in `hlil/expr.rs`; `render_hlil_tokens() -> Vec<CToken>` in `hlil/render.rs` with pc/op_index metadata. Wave 1.
- [x] **Semantic test verification**: `tests/semantic_decompile_tests.rs` with assert_contains/assert_control_flow/assert_eliminated_goto framework; 15+ semantic assertions. Wave 2.
- [x] **Multi-precision arithmetic merging**: `pass_multiprecision.rs` detects SplitVarnode/AddForm/SubForm/CarryFlag patterns; registered Phase 3. Wave 2.
- [x] **P-code injection / CALLOTHER extension points**: `callother_registry.rs` with syscall/JNI tables; `HlilOp::CallOther` variant; ARM64 SVC detection. Wave 1.
- [x] **Indirect br target resolution → CFG**: `resolve_indirect_branch_targets()` in `cfg.rs`; EdgeKind::IndirectDispatch; dashed edges in CFG render. Wave 2.
- [x] **Branch bias / loop counts in IL**: hot_path in EdgeMeta; loop iteration counts on While/DoWhile/For; branch taken/not-taken comments in HLIL render. Wave 1.
- [x] **Multi-call value differencing**: `classify_value_stability()` as Constant/InputDependent/CallDependent/Unobserved; prevents over-specialized folding. Wave 2.
- [x] **Union resolution (ScoreUnionFields)**: `pass_union_resolution.rs` detects same-base/different-type access; scoring heuristic; Phase 5 pass. Wave 2.
- [x] **BitField transformations**: `pass_bitfield.rs` detects UBFX/SBFX/BFI patterns in LLIL; registered Phase 3. Wave 1.

### Low — future enhancement

- [x] User-defined type database: `type_database.rs` with TypeDatabase/CType/StructDef/EnumDef; serde persistence; C type expression parser. Wave 2.
- [x] Call signature inference: `infer_call_signatures()` aggregates call site arg types; return type from x0 usage; signature string generation. Wave 2.
- [x] TraceIR loop bodies populated: back-edge detection, induction variable identification, loop bound inference; LoopIR fields filled. Wave 2.
- [x] LLM fewshot exemplar in TraceIR prompt: curated djb2_hash exemplar in `prompt.rs`. Wave 2.
- [x] Decompile eval tool semantic accuracy metric: `--semantic` flag; control-flow/variable/statement/keyword metrics; per-function + aggregate scores. Wave 2.
- [x] Frontend keyboard navigation parity: line cursor in pseudocode (arrow keys); Enter→jump assembly; Tab→cycle signature/body; persistent rename/type propagation. Wave 2.

## P4 — Agent DX & Device Ergonomics

- [x] `tracemiku doctor` pre-flight check command
- [x] Pre-flight checks integrated into `cmd_trace()`
- [x] `--pkg` failure shows frida-ps process matches
- [x] CLI `cargo run --quiet` to suppress compilation noise
- [x] `query search` accepts both positional and `--pattern` arg
- [x] MemShadow completeness metadata in /api/mem-dump
- [x] Server ready JSON signal on stdout
- [x] Non-TTY compact JSON output (is-terminal)
- [x] Batch `--indices` for Records command
- [x] `tracemiku crypto` empty result diagnostic message
- [x] CLAUDE.md "AI Agent Quick Start" section
- [ ] Shell completion generation (clap_complete) — future

## Bugs — Fixed (Previous)

- [x] **Assembly scroll freeze**: SAFE_SCROLL_HEIGHT 30M→15M
- [x] **Single-click variable highlighting**: highlights all same-name variables in function; toggle on re-click
- [x] **Goto label double-click navigation**: double-click label ref → scroll to label definition
- [x] **HLIL structural control flow**: CFG-based restructuring pass converts flat goto into if/else, while, do-while. HLIL/MLIL/LLIL now structurally different.
