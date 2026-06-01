# TODO — traceMiku

> The single source-of-truth backlog for the whole toolchain (tracer, Rust
> core/server/CLI, frontend, vendored runtime) — not just the decompiler.
>
> Last updated: 2026-06-01 (decompiler audit vs Ghidra benchmark, see
> `docs/decompiler-audit-2026-06-01.md` for full report).

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

- No known correctness bugs in the shipped decompile/trace UI paths.
  Current focus is closing the trace-aware decompiler gap and structural
  improvements identified in the 2026-06-01 Ghidra benchmark audit — see
  `docs/decompiler-audit-2026-06-01.md` for the full ranked report.

### Critical — blocking decompiler quality

- [ ] **Concretize observed values into IL constants (Phase 1b)**: `collect_observed_values` + `is_const()` exist but constfold path in `il_pipeline.rs` still uses static data only. Wire observed constants into IL — the #1 readability win for a trace decompiler.
- [ ] **Path specialization → CFG (Phase 2 incomplete)**: `branch_taken` populated, `specialize_trace_control_flow` runs, but HLIL restructurer `build_cfg` never filters by execution. OLLVM dispatchers remain unstructured gotos.
- [ ] **HLIL For/Switch/Break/Continue unwired**: constructors exist in `expr.rs` but `pass_restructure.rs` never emits them (only While/DoWhile). One-hop convergence (`check_convergence:814`) degrades multi-block if/else to goto tails.
- [ ] **Cross-block SSA**: `ssa_block` is single-block only — no MULTIEQUAL (Phi) opcodes, no dominance frontiers. Every block boundary breaks SSA; all downstream analysis loses precision at jump targets. Requires Cooper-Harvey-Kennedy O(n) dominator + Bilardi-Pingali Phi placement.

### High — major quality/accuracy improvements

- [ ] **Type system expansion**: 6 TypeKind (Any/Int/Ptr/Handle/Bool/Conflict) vs Ghidra's 18 meta + 24 sub. No signedness, float, struct/array/union. Expand TypeKind + add TypeOp per-opcode rules (start with 15 highest-frequency).
- [ ] **Simplify rules**: 4 rules (IdentityOp/SubToAdd/DoubleNeg/ComparisonFold) vs Ghidra's 120+. Add per-opcode indexed rule tables; 10 highest-frequency rules as first milestone (ConstBinop, BitwiseIdentity, ExtensionChain, ShiftIdentity, SignBit).
- [ ] **Variable merging**: Varnode→HighVariable→VariableGroup chain absent. SSA version numbers shown as distinct variables. Implement after cross-block SSA.
- [ ] **MemShadow → decompiler**: MemShadow cached on shared state but decompiler never reads it. Struct recovery matches only base+non-negative-const — no scaled index, negative offsets, or observed-address clustering.
- [ ] **Dominator O(n²) → Cooper-Harvey-Kennedy**: both llil.rs and hlil/pass_restructure.rs use BTreeSet with duplicates. Implement shared O(n) engine in `cfg.rs`.
- [ ] **Parameter identification**: function parameters not discovered/classified/ranked. Ghidra's ParamMeasure ranking has no equivalent. Trace values give us an advantage here (x0-x7 at call sites are directly observed).

### Medium — significant polish

- [ ] **Jump table recovery**: PathMeld + EmulateFunction has no equivalent. Trace records every taken branch target but switch detection doesn't consume them.
- [ ] **Token-based C rendering**: all 3 renderers produce plain text. Define CToken {text, kind, pc, op_index} and refactor renderers to emit `Vec<CToken>`. Enables single-click highlight, right-click set-type, persistent rename propagation without regex hacks.
- [ ] **Semantic test verification**: tests check structure (count, not-empty) but not semantic correctness. Add stringmatch-style assertions (like Ghidra's 140+ tests).
- [ ] **Multi-precision arithmetic merging**: 64-bit/128-bit multi-precision merging (SplitVarnode, AddForm, SubForm, etc.) absent.
- [ ] **P-code injection / CALLOTHER extension points**: no mechanism for modeling syscalls, JNI calls, or platform-specific instructions.
- [ ] **Indirect br target resolution → CFG**: blr targets are annotated in text but br xN dispatch (OLLVM/VM) gets no target resolution into IL/CFG.
- [ ] **Branch bias / loop counts in IL**: EdgeMeta.count exists but not rendered or used for hot/cold path annotation.
- [ ] **Multi-call value differencing**: cannot classify values as Constant vs InputDependent across calls. Needed for parameter recovery and preventing over-specialized folding.
- [ ] **Union resolution (ScoreUnionFields)**: memory accessed as different types at different offsets not identified as union candidates.
- [ ] **BitField transformations**: INSERT/ZPULL/SPULL for sub-byte register access patterns absent.

### Low — future enhancement

- [ ] User-defined type database (persist C typedefs/structs from frontend to backend)
- [ ] Call signature inference from call site argument types
- [ ] TraceIR loop bodies populated in render (LoopIR/InductionVarIR structs exist but builder never fills them)
- [ ] LLM fewshot exemplar in TraceIR prompt
- [ ] Decompile eval tool semantic accuracy metric (not just coverage/timing)
- [ ] Frontend keyboard navigation parity with IDA/Ghidra (line cursor in pseudocode, persistent rename/set-type propagation)

## Bugs — Fixed (Previous)

- [x] **Assembly scroll freeze**: SAFE_SCROLL_HEIGHT 30M→15M
- [x] **Single-click variable highlighting**: highlights all same-name variables in function; toggle on re-click
- [x] **Goto label double-click navigation**: double-click label ref → scroll to label definition
- [x] **HLIL structural control flow**: CFG-based restructuring pass converts flat goto into if/else, while, do-while. HLIL/MLIL/LLIL now structurally different.
