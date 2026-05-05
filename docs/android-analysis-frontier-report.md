# Android Analysis Frontier Report

> Written 2026-05-05 after web research and current `main` code audit.
> Scope: practical Android native/JNI analysis pain points, traceMiku feature
> direction, UI interaction priorities, and triage of the reported main-branch
> bug list.

## Executive Summary

traceMiku is now past the "can capture and can render a trace" stage. The next
high-leverage work is not adding more independent tabs; it is turning existing
trace, CFG, taint, MemShadow, BN, JNI, and decompiler surfaces into one
cross-layer evidence system.

Priority directions:

1. Capture campaign manager: reproducible device/app/Frida/trace sessions.
2. Cross-layer timeline: Java/JNI/native/thread/file/network/dynamic-load events
   aligned with trace index and timestamp.
3. Trace query engine: SQL-like or structured queries over records, registers,
   memory events, functions, strings, JNI events, and provenance.
4. Task center: every heavy CFG/BN/taint/string/memory job has running/cached/
   cancelled/partial state.
5. Provenance graph: default representation for taint, memory range, string,
   JNI argument, and output headers.

## Sources Consulted

- OWASP MASTG dynamic analysis and Android anti-reversing guidance:
  https://mas.owasp.org/
- Android Play Integrity API overview:
  https://developer.android.google.cn/google/play/integrity/overview
- Android NDK Memory Tagging Extension documentation:
  https://developer.android.google.cn/ndk/guides/arm-mte
- Android ABI / BTI notes:
  https://developer.android.com/ndk/guides/abis
- Perfetto tracing and TraceProcessor SQL:
  https://perfetto.dev/docs/
- Android simpleperf native profiling:
  https://developer.android.com/ndk/guides/simpleperf
- Binary Ninja debugger / TTD notes:
  https://docs.binary.ninja/
- Recent Android dynamic-loading / packer literature, including DLCDroid and
  Purifire-style app unpacking/analysis work.

## Practical Pain Points In 2026 Android Analysis

### Cross-layer gaps

Real-world targets rarely keep the interesting logic in one layer. A trace can
start at a Java method, cross JNI, dispatch into native, enqueue worker-thread
jobs, dynamically load SO/Dex payloads, and then emit a network request. A pure
instruction trace answers "what happened on this followed thread", but not
"which Java call, worker thread, file, socket, or dynamically loaded module made
this value meaningful".

Needed capabilities:

- Java/JNI/native event alignment by time, tid, and trace index.
- Worker-thread follow evidence: when the main trace signals or wakes another
  thread, show whether that thread was traced.
- Dynamic load markers for `dlopen`, `android_dlopen_ext`, DexClassLoader, and
  InMemoryDexClassLoader.
- Maps snapshot diff and auto dump for new executable regions.

### Anti-analysis is now a workflow problem

Root, Frida, debugger, emulator, and integrity checks are no longer isolated
branches. Modern apps often combine client-side RASP checks with server-side
Play Integrity decisions. The UI should distinguish local bypass points from
server-verdict dependencies.

Needed capabilities:

- Integrity API observation: nonce, call stack, return path, network binding.
- RASP event lane: suspicious checks, thread scans, maps scans, ptrace,
  `/proc` reads, seccomp, and anti-Frida string scans.
- Capture mode comparison: rooted Frida server, embedded Gadget, spawn/attach,
  cold launch, worker follow, and no-root workflows.

### Obfuscation collapses PC semantics

OLLVM/VM style code often routes many semantic byte writes through one physical
PC. In those cases PC-based search and xref are weak; trace index, target
address, memory value, and provenance are the real keys.

Needed capabilities:

- Provenance graph as the first-class view, not a secondary table.
- Memory-range selection feeding writers/readers, data chase, backward taint,
  and string provenance.
- VM-oriented grouping by data address, byte stream, handler dispatch, and hot
  loops rather than by raw PC alone.

### Hardware and platform hardening changes failure modes

MTE, BTI, PAC-like codegen patterns, and modern Android linker behavior turn
hook failures and crashes into normal diagnostic events. A failed trace should
show why it failed, not just that the app died.

Needed capabilities:

- Crash diagnostics: signal, `si_code`, PC, module, likely MTE/BTI/PAC/hook
  class, and last trace event.
- Hook strategy hints: inline hook unsafe, Stalker-only path, Gadget path,
  exclude hostile functions, or worker-thread follow needed.

## UI Interaction Priorities

### 1. Timeline-first navigation

Keep records as the primary detailed list, but add global lanes:

- thread and function spans;
- JNI and Java events;
- dynamic load / maps diff events;
- file/network/syscall events;
- memory hot ranges and strings;
- Perfetto/simpleperf slices when imported.

Clicking any lane event should move the trace cursor and synchronize CFG,
registers, memory, taint, string provenance, and decompiler panels.

### 2. Command palette as the unified control plane

Extend the existing `g` jump into a command palette:

```text
#443
pc 0x75f63067ec
func sub_169a10
mem 0x740fd72f80 len 128
taint bwd x9 @93
string "M1gA9..."
query writes addr 0x... len 32
```

This is more scalable than adding a separate form per tab.

### 3. Task center for heavy work

CFG rendering, BN HLIL/CFG, taint, string provenance, memory range queries,
decompile, and trace SQL should share one job surface:

- running / queued / cached / cancelled;
- elapsed time;
- input parameters;
- result cap and partial state;
- cancel and rerun controls.

The user should never wonder whether the UI is frozen or a background query is
still active.

### 4. Explicit completeness badges

Every analysis result should expose one of:

- complete;
- partial / capped;
- stale response discarded;
- from cache;
- missing worker thread;
- BN-created function;
- static-only / trace-only;
- no memory shadow yet.

Partial data is a correctness issue, not only a UI detail.

### 5. Local CFG by default

Large full-function CFGs should not be the interactive default. The better
default is a local view around the selected block:

- selected block;
- incoming and outgoing neighbors;
- hot edges;
- loop/SCC context;
- call edges;
- one-click expand.

Full Graphviz output should remain bounded and export-oriented.

### 6. Notebook / evidence workspace

Add durable analysis state:

- bookmarks on trace index, PC, memory range, string, and function;
- analyst notes;
- saved queries;
- pinned provenance chains;
- exportable report snippets with JSON evidence.

## Reported Main-branch Bug Triage

Verdict meanings:

- Confirmed: code inspection shows the reported behavior is real.
- Partially confirmed: the core issue is real, but the consequence or suggested
  fix needs adjustment.
- Risk / minor: plausible edge case or wasted work, but not proven to break a
  current user path.
- Not current bug: current code already handles the reported part or no active
  callsite was found.

| # | Verdict | Severity | Analysis |
|---|---|---|---|
| 1 | Partially confirmed | High | `is_store_style()` omits `stnp`, while `mem_op::STORE_BASES` includes it and pair-splits `stnp`. So register def/use and taint provenance are wrong for at least the first stored register. However MemShadow and `index.mem_writes` are not fully missing for `stnp`, because `mem_op` marks it as a write and carries `src_reg` for both halves. The stated "MemShadow does not write corresponding bytes" is too broad. `stxp/stlxp` need separate handling: their first operand is the exclusive status destination, while following regs are store sources, so blindly adding them to store-style would be wrong. |
| 2 | Confirmed | High | `normalize_disasm_reg("W30") == "x30"` is pinned by test, while canonical trace names use `lr`; same for `w29` vs `fp`. Index and taint use normalized strings, so `fp`/`lr` seeds can miss w-form definitions recorded as `x29`/`x30`. `Record::reg_by_name` is tolerant for values, but it does not fix index-key mismatch. |
| 3 | Confirmed | High | `AppState` calls `BnSidecarManager::from_env_with_base((primary_base != 0).then_some(primary_base))`, so `TRACEMIKU_BN_BASE` is ignored on the production path. This also prevents env override when `primary_base` is non-zero. |
| 4 | Confirmed | Medium | `/api/cfg`, `/api/functions`, `/api/data-chase`, and `/api/block` lack a consistent cap/truncation contract. `data_chase` caps internally but does not return `stopped_at_max` / `max_steps_used`. `cfg` and `functions` can return unbounded JSON. |
| 5 | Confirmed | Medium | `records_handler` decodes up to 1000 records on the async handler path. `navigation::block_handler`, `loops_handler`, and `call_chain_handler` also do CPU/scan work without per-handler `spawn_blocking`. The current heavy-route test is file-level and can pass because another handler in `navigation.rs` uses `spawn_blocking`. |
| 6 | Confirmed | Medium | `trace_fn_start()` derives function start from `SymbolMap::lookup(pc)`, and `SymbolMap` returns the nearest previous symbol without size/bound checking. Gap PCs can therefore pass an unrelated earlier function start to BN function creation. |
| 7 | Partially confirmed | Medium | Server route `/api/bn-cfg-svg-for-pc` already forwards `created_function` from the sidecar. The frontend CFG BN ASM header does not display it, so the UI contract gap is real, but the server side is not missing in current code. |
| 8 | Confirmed | Medium | `selectFunction(fn, true)` silently does nothing beyond CFG selection when `entry_pc === null`. There is no status message explaining that no trace entry PC exists. |
| 9 | Confirmed | Medium | The nav history list creates fresh `{idx,pos}` objects inside `<For>` on every render. Solid `<For>` is referential, so fast cursor changes can rebuild the list unnecessarily and risk focus/jitter. |
| 10 | Confirmed | Low | `scheduleMemoryRetry()` can apply an old run after the user edits start/reg controls without explicitly pressing Run, because editing those signals does not cancel the scheduled retry. The result carries old `from/reg`, but it can still overwrite the visible result area after inputs changed. |
| 11 | Risk / minor | Low | `_to_bn_addr()` passes through `pc < runtime_base` and maps far-above-runtime PCs outside the image. Function creation later checks image bounds, so this is mostly wasted work and confusing errors rather than a confirmed wrong-function creation path. |
| 12 | Risk / minor | Low | `_line_to_wire()` can fall back to `pc: 0x0` when BN line address and fallback address are absent. This can waste token/click lookups and confuse current-line matching on synthesized lines, although it depends on BN line shape. |
| 13 | Risk / minor | Low | `parse_id("bn:...")` validates but returns the original payload, so `bn:0xABC` and `bn:0XABC` remain distinct strings outside `by_id()`. No active breaking callsite was found; canonicalizing remains prudent. |

## Bug-fix Priority Recommendation

P0 bug-fix batch:

1. Fix ARM64 register normalization for `w29/w30` and add tests for taint/index
   matching `fp/lr`.
2. Fix `stnp` def/use classification; add separate explicit tests for `stnp`,
   `stxp`, and `stlxp` instead of applying one generic store-style rule.
3. Make `TRACEMIKU_BN_BASE` effective and allow env override.
4. Add per-handler runtime-blocking tests, not only per-file tests.

P1 hardening batch:

1. Add cap/truncation fields to unbounded API responses.
2. Move records/block/loops/call-chain heavy work off the async runtime.
3. Bound-check BN function-start hints using `FunctionIndex` or symbol ranges.
4. Display BN `created_function` in CFG and explain no-entry function jumps.
5. Stabilize nav history identity and cancel stale taint retries on input edits.

## Strategic Product Direction

The strongest product path is:

```text
capture campaign
  -> cross-layer timeline
  -> trace query engine
  -> provenance graph
  -> notebook/report export
```

This makes traceMiku a practical Android analysis workstation rather than a
collection of independent trace tabs.
