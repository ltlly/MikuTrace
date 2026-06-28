# Memory Completeness Design — layered ground-truth oracle

Status: Phase 1 (initial snapshot) implemented 2026-06-27. Phase 2 (syscall
readback) designed here, partially implemented. Phase 3 (live mem-operand
capture) designed, deferred.

## Problem

traceMiku records a full register snapshot per instruction (272-byte records:
pc + x0..x28 + fp/lr/sp + pstate + insn) but **records no memory data**.
`MemShadow` reconstructs memory by *inference*:

- store insn → bytes come from the source register's pre-state
- load insn  → bytes come from the destination register's post-state (next record)

This inference is fast (the hot callout only copies registers) but has hard
blind spots — memory modified where we cannot observe the modifying store:

1. **Pre-trace state** — anything initialized before the trace window opened.
   The libsgmainso x-sign VM bytecode table (~10KB at `x21`) is decrypted at
   `JNI_OnLoad`, long before the sign call we hook. `.rodata` constants too.
   MemShadow only sees the *read* of these, never a matching write →
   `observed_read_without_matching_traced_write` frontier.
2. **Kernel writes** — a syscall (`read`, `stat`, `recvfrom`, ...) writes the
   user output buffer in kernel mode. There is no user-mode store instruction,
   so inference cannot see it. (The x-sign `stat().st_mtim` gap.)
3. **Excluded-region writes** — code we Stalker-exclude (linker, ART apex, any
   self-modifying module) can write memory we never trace.
4. **Other threads / DMA / shared memory** — writes by threads we don't follow.

This is **not a traceMiku bug**. It is the universal limit of user-mode DBI.
Tenet's own FAQ states it directly: *"usermode DBI generally do not get a
memory callback for external writes to process memory ... it is the kernel that
writes memory into your designated usermode buffer ... tricky to solve without
modeling syscalls."* Microsoft TTD has the same limitation. The industry answer
is: **a known initial state + syscall modeling.**

## The unified model: a layered byte oracle with provenance

Every memory byte query — `MemShadow::byte_at(addr, t)` — returns
`(value, kind, source_idx)` or `(None, "??", None)`. `kind` is the **provenance**
of the value, and the layers have a strict priority by trace-time `idx`:

| kind | source | fidelity | idx |
|------|--------|----------|-----|
| `w`  | traced store | exact | the storing record |
| `r`  | traced load (observed in next record's reg) | exact | the loading record |
| `x`  | external write — syscall output-buffer readback OR boundary-diff | exact-ish | the call's record |
| `i`  | **initial snapshot** — real device memory captured at trace start | t=0 baseline | 0 |
| `??` | never observed | unknown — honest "we don't know" | — |

The invariant: **a query never lies.** It returns a real observed/captured
value with its provenance, or it says `??`. A consumer (mem-dump completeness,
byte-lineage, vm-backchain) can trust `w`/`x`/`i` as ground truth and treat `??`
as a genuine frontier rather than guessing.

Resolution order in `byte_at(addr, t)`:
1. Latest event in the per-byte event list with `idx <= t` (covers `w`/`r`/`x`).
2. If none: fall back to the **initial snapshot** (`i`, idx 0) — correct for any
   `t` before the first traced write, which is exactly when the map has no event.
3. If still none: `??`.

This is elegant because the snapshot is just *another layer behind the same
oracle* — no consumer changes, and idx-ordering makes a later traced store
naturally override the snapshot baseline.

### Why the snapshot is a separate compact store, not splatted into the map

A snapshot can be hundreds of MB. Splatting every byte into
`BTreeMap<u64, Vec<ByteEvent>>` would create one map entry per byte → memory
blow-up. Instead the snapshot is kept as **sorted region blobs**
(`Vec<SnapRegion { base, data }>`) and binary-searched only on a map miss. It
stays sparse and cheap, and it is loaded independently of the v5 sidecar so the
sidecar format is unchanged.

### Honest staleness note

The snapshot is the t=0 state. For **read-only / init-once** data (the decrypted
bytecode table, `.rodata` constants, embedded keys) it is exactly correct — that
is the whole win. For **mutable** memory it is only the *initial* value; once a
traced store happens, the `w` layer (higher idx) correctly takes over. The only
unsound case is memory mutated by an *untraced* writer *between* t=0 and the
query — inherently unobservable; we mark such bytes by their best available
layer and never fabricate.

## Phase 1 — initial snapshot (IMPLEMENTED)

**Agent** (`tracer/src/sidecar/mem_snapshot.ts`): on target-function entry,
after excludes/ranges are set, enumerate the regions of interest and dump them
to a device file `snapshot_call<idx>.bin`. Default capture set:

- the target SO's mapped segments (all perms) — gets `.rodata` constants
- readable anonymous / heap `rw-`/`r--` regions — gets decrypted runtime tables
  (e.g. the VM bytecode blob at `0x7400…`)

Capped by `snapshotMaxBytes` (default 512 MB) to protect the device. Skips
unreadable pages gracefully.

**Format** `snapshot_call<idx>.bin`:
```
magic   "TMSNAP\0\0"   (8 bytes)
version u32            (= 1)
count   u32            (region count)
[per region]
  base    u64
  size    u64          (= data length, bytes)
  perms   u32          (bit0=r bit1=w bit2=x)
  flags   u32          (reserved, 0)
  data    [size bytes]
```

**Host** (`tracemiku`): pull `snapshot_call<idx>.bin` at teardown beside
`trace.bin`, save as `memory_snapshot.bin` in the per-call dir.

**Rust** (`tracemiku-core::memshadow`): `MemSnapshot` loads
`memory_snapshot.bin`, `MemShadow.snapshot: Option<MemSnapshot>` is attached in
`load_or_build`, and `byte_at` falls back to it with kind `i`.

**CLI flag**: `--snapshot-mem` (+ `--snapshot-max-mb N`).

## Phase 2 — syscall output-buffer readback (DESIGNED)

> **2026-06-27 status**: the HOST side is complete and tested — `external_writes.bin`
> (17B records: `idx:u64, addr:u64, byte:u8`) already merges into MemShadow as
> the `x` layer (`memshadow.rs::merge_external_writes`, test
> `memshadow_loads_external_writes_as_x_events`). So Phase 2's only remaining
> work is the DEVICE-side `onLeave` capture below — it appends to that existing
> format and host/core/`mem-export`/`reg-at` benefit with zero changes. Turnkey
> wiring + safety/validation plan: `docs/competitive/runtime-truth-big-features-2026-06-27.md` 大件 C.

The precise, universal answer to blind spot #2. The existing semantic-event
hooks (`tracer/src/sidecar/semantic.ts`) already Interceptor-attach libc/syscall
wrappers and snapshot string args. Extend them with an **output-buffer table**:
for each syscall/libc fn, which arg is the out buffer and where its written
length comes from (a fixed arg, or the return value). On `onLeave`, read that
buffer and emit `ext-write` events (kind `x`) — exactly the existing
`external_writes.bin` channel, just driven by a syscall ABI table instead of
only the 6 stat functions.

Output-buffer table (initial):

| fn | out buf arg | length source |
|----|-------------|---------------|
| `read`/`pread64` | arg1 | return value (bytes read) |
| `recvfrom`/`recv` | arg1 | return value |
| `stat`/`fstat`/`lstat`/`*at` | the `struct stat*` arg | `sizeof(struct stat)` = 128 |
| `gettimeofday` | arg0 | 16 |
| `clock_gettime` | arg1 | 16 |
| `__system_property_get` | arg1 | return value |
| `getrandom` | arg0 | return value |

This is exact because the kernel ABI is a contract. Excluded-region writes
(blind spot #3) have no contract and stay on the heuristic boundary-diff path.

## Phase 3 — live memory-operand capture (DESIGNED, DEFERRED)

GumTrace-style: in the hot callout, Capstone-decode the operands and
`readByteArray` the real memory at the access site, recording true bytes rather
than inferring.消除 inference 依赖, partially immune to all blind spots for any
byte the traced code actually touches. Cost: the callout does memory reads →
slower than the current pure-register snapshot. Make it opt-in
(`--capture-mem-operands`) so the default fast path is preserved.

## Tenet export (FUTURE)

The layered oracle maps cleanly onto the Tenet trace format
(`reg=val,...,mr=addr:bytes,mw=addr:bytes` per line; see
github.com/gaasedelen/tenet tracers/README.md). Exporting Tenet logs would let
traceMiku traces load in IDA's Tenet plugin for time-travel debugging. Tracked
separately.

## Validation

`--snapshot-mem` on the libsgmainso x-sign trace must turn the VM
bytecode-table reads from `observed_read_without_matching_traced_write` (kind
`??`) into kind `i` with real bytes, and `mem-dump --completeness` over that
region must rise toward 1.0.
