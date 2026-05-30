# TODO — traceMiku

> The single source-of-truth backlog for the whole toolchain (tracer, Rust
> core/server/CLI, frontend, vendored runtime) — not just the decompiler.
>
> Last updated: 2026-05-30 (after the frida 17.9.11 vendor + crypto stack +
> spawn-hook landings; this file had been ~16 days and one milestone stale).

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

- No known correctness bugs in the shipped decompile/trace UI paths (see fixed
  lists below). Current focus is **latency/responsiveness hardening** and
  closing the trace-aware decompiler gap, not new feature breadth — see
  `docs/improvement-audit-2026-05-30.md` for the ranked roadmap.

### Known gaps (from the 2026-05-30 audit, not yet shipped)

- [ ] **Trace-aware decompiler is functionally static**: `il_pipeline` receives an empty `TraceContext` slice; observed register/memory/branch values are discarded before lifting (audit §2 Phase 0)
- [ ] **No value concretization / never-taken branch pruning** in the IL (audit §2 Phase 1–2; OLLVM/VM de-flattening lever)
- [ ] **HLIL structurer incomplete**: emits only `While`/`DoWhile`; `For`/`Switch`/`Break`/`Continue` variants exist but are never emitted (audit §5)
- [ ] **No HTTP compression** on the axum server (CFG SVG / IL text / static assets all highly compressible) (audit §3)
- [ ] **Anti-detection coverage gaps**: L3 fork+ptrace daemon (needs eBPF), L5 `frida_agent_main`/gadget symbol scan (needs agent.so relink), L10 incomplete suicide patch (`docs/anti-detection-catalog.md`)
- [ ] **Single-thread Stalker follow only**: worker/JNI threads invisible; needs per-thread rings + `pthread_create` hook (audit §4)
- [ ] **Record-format version field**: `REC_SIZE=272` hardcoded with no `format_version` in `meta.json`; prerequisite for any richer capture (audit §4)

## Bugs — Fixed (Previous)

- [x] **Assembly scroll freeze**: SAFE_SCROLL_HEIGHT 30M→15M
- [x] **Single-click variable highlighting**: highlights all same-name variables in function; toggle on re-click
- [x] **Goto label double-click navigation**: double-click label ref → scroll to label definition
- [x] **HLIL structural control flow**: CFG-based restructuring pass converts flat goto into if/else, while, do-while. HLIL/MLIL/LLIL now structurally different.
