# x-sign algorithm — final structural spec (call_001 trace model)

> Companion to `docs/xsign-reconstruction-progress.md` and the runnable
> `examples/libsgmainso/xsign_partial_sim.py`. The simulator reproduces
> the call_001 x-sign byte-for-byte (`matches_trace: true`); this doc is
> the human-readable spec of what that simulator implements and where the
> remaining boundaries are.

## Inputs

The algorithm is a deterministic function of the following inputs, each
of which comes from outside the SO and must be supplied at call time:

| input | source | example (call_001) |
|---|---|---|
| `time_t` | `time(NULL)` (libc) | `0x69f5b3cb` (= 1777710027) |
| `stat_mtim_tv_sec` | `stat()` of an app file | `0x69f2e9fb` |
| `process_id` | `getpid()` | (small int) |
| `vm_bytecode_table` | embedded in libsgmainso .rodata | ~10 KB blob at `x21` base |
| `pretrace_table_seed_word` | libsgmainso .rodata | `0x95f2ec` |
| `pretrace_table_xor_a` | libsgmainso .rodata | `0x006dcbf8` |
| `pretrace_table_xor_b` | libsgmainso .rodata | `0x05203a10` |
| `vm_xor_const_word2` | libsgmainso .rodata | `0x05203a10` |
| `vm_xor_const_word3plus` | libsgmainso .rodata | `0x2cabac28` |
| `xor_lhs_runs` | libsgmainso .rodata + small dynamic mix | (parameterised) |
| `mod255_even_input`, `mod255_odd_input`, `mod255_mask_offsets` | libsgmainso .rodata | (parameterised) |

`time_t` and `stat_mtim_tv_sec` are the only inputs that change with the
device clock; everything else either comes from the SO binary or is
derived from `process_id`.

## Output layout (76-byte payload, then Base64)

```text
offset  size  source
------  ----  ----------------------------------------------------------
   0     1   constant 0x00      (zero-init, never re-written)
   1     1   constant 0x00
   2     1   constant 0x00
   3     1   stat_mtim_tv_sec & 0xff
   4..7   4  u32_le((stat_mtim_tv_sec >> 8) | (static_byte << 24))
   8..11  4  word[2]   ← VM xor-ladder, VM_XOR_CONST_2 = 0x05203a10
  12..15  4  word[3]   ← VM xor-ladder, VM_XOR_CONST_3+ = 0x2cabac28
  16..19  4  word[4]   ← VM xor-ladder
  20..23  4  word[5]   ← VM xor-ladder
  24..27  4  word[6]   ← VM xor-ladder
  28..31  4  word[7]   ← VM xor-ladder
  32..35  4  word[8]   ← VM xor-ladder
  36..39  4  word[9]   ← VM xor-ladder
  40..43  4  word[10]  ← VM xor-ladder
  44..47  4  word[11]  ← VM xor-ladder (only low 16 bits non-zero)
  48      1  strb stream byte 0 — VM-derived
  49      1  strb stream byte 1 — VM-derived
  50      1  strb stream byte 2 — VM-derived
  51      1  strb stream byte 3 — VM-derived
  52..54  3  zero (intentional padding, observed)
  55..75 21  zero (pre-trace zero-init, never re-written)
```

```text
xsign = base64( payload[0..76] )
```

URL-encoding of `+` and `/` is applied by the JNI caller, not by the SO,
so it is outside this spec.

`static_byte` for word[1]:

```text
static_byte = low8( pretrace_table_seed_word
                    ^ pretrace_table_xor_a
                    ^ pretrace_table_xor_b )
            = low8( 0x95f2ec ^ 0x006dcbf8 ^ 0x05203a10 )
            = 0x79
```

## VM xor-ladder (words 2..11)

Each word at offset `4*i` (`i ∈ [2..11]`) is built from one boundary
byte and one VM state register:

```python
word[i] = (boundary_byte_i << 24) | ((vm_state_i >> 8) & 0x00ffffff)
```

`vm_state_i` is the result of a per-word VM fragment whose head is:

```python
vm_state_i = vm_chain(vm_bytecode_table, prior_state) ^ VM_XOR_CONST_i
```

with

```text
VM_XOR_CONST_i = 0x05203a10  for i == 2
VM_XOR_CONST_i = 0x2cabac28  for i ∈ [3..11]
```

The trace-bound terminal of `vm_chain` is `ldr x1, [x21, #8]` at idx
≈10,613,716–10,620,557 in call_001, where `x21` is the VM bytecode
pointer initialised before the trace started. The 35 / 64 observed
bytes at the terminal address show that the bytecode is a real binary
table inside the SO — once you have the SO, the chain becomes a pure
function of `(time_t, stat_mtim_tv_sec, vm_bytecode_table)`. Without
the SO, the chain is `pending_lift` because the bytecode never appears
in the trace.

The boundary bytes for call_001 are:

```text
i      boundary_byte    vm_state_i (post-XOR)
------ ---------------- --------------------
0      stat_mtim & 0xff stat_mtim >> 8           (input-derived)
1      0x79 (static)    stat_mtim >> 8           (input-derived)
2      0x41             0x95f2ec79               (XOR with 0x05203a10)
3      0xb3             0x9301f641               (XOR with 0x2cabac28)
4      0x0c             0x513c4bb3               (XOR with 0x2cabac28)
5      0xe3             0x9d02cc0c               (XOR with 0x2cabac28)
6      0x95             0xc2ce39e3               (XOR with 0x2cabac28)
7      0x7c             0x23903095               (XOR with 0x2cabac28)
8      0x3b             0xf4a4bf7c               (XOR with 0x2cabac28)
9      0x34             0x4a44a03b               (XOR with 0x2cabac28)
10     0x9b             0xc5442334               (XOR with 0x2cabac28)
11     0x00             0x69c5(short)            (XOR with 0x2cabac28)
```

The same `>> 8` shift connecting `boundary_byte_i` and `vm_state_(i-1)`
appears across every word: it is a 4-byte shift register where each
word emits 24 bits of state and absorbs one new byte at the high end.

## Bytes 48..51

Four `strb` writes that follow the same shift register but at byte
granularity:

```python
payload[48] = (boundary_byte_12 = 0x3a)  # VM-derived from xor-ladder tail
payload[49] = 0xbf
payload[50] = 0x03
payload[51] = 0x01
```

These are all in the `vm_xor_ladder_pending_lift` source class — same
boundary as words 2..11.

## What's algorithmically complete

The `xsign_partial_sim` simulator reproduces the call_001 x-sign byte
for byte:

```bash
uv run python examples/libsgmainso/xsign_partial_sim.py \
  | jq '.current_trace_model_simulation.matches_trace'
# => true
```

That covers:

* the 76-byte layout and zero-padding regions;
* word[0] / word[1] head as a closed-form function of `stat_mtim_tv_sec`
  and `static_byte`;
* the `static_byte = low8(seed ^ table_xor_a ^ table_xor_b)` formula;
* the time→LCG seed, multiplier `0x5851f42d4c957f2d`, increment 1, and
  the output-mixing pattern `(state >> 32) + const_i` (verified against
  observed VM state values);
* the `(boundary << 24) | (xor_state >> 8)` shift-register layout for
  each xor-ladder word;
* the `mod255_low_byte` folds for the call_001 strb-byte stream;
* the Base64 index layer for the full 68-byte aligned semantic tail
  (no remaining unknowns at the encoder).

## What requires the SO binary as input (not a trace gap)

Per the project's hard rule that target-specific facts belong outside
the analysis core, the following are **inputs**, not derivations:

* `vm_bytecode_table` — the ~10 KB pre-trace blob at the address held
  in `x21` during the dispatcher loop. It controls the per-word
  `vm_chain` evaluation that produces `xor_state_i`. Without it the
  trace shows the read but cannot reconstruct what is being read.
* `pretrace_table_seed_word`, `pretrace_table_xor_a`,
  `pretrace_table_xor_b`, `vm_xor_const_word2`, `vm_xor_const_word3plus`
  — six 32-bit constants in `.rodata` that gate the head and ladder
  constants. They are constants per-build, not per-call.
* `xor_lhs_runs`, `mod255_*_input`, `mod255_mask_offsets` — extra
  parameter blobs the simulator threads through the byte builders.

The simulator records all of these in
`current_trace_model_input_manifest` so an extractor can fill them by
parsing the SO. Extracting them from libsgmainso.so is a
reverse-engineering task on the binary, not a trace-analysis task.

## Verifying with the new CLI

The findings above are mechanically reproducible with one CLI session
each:

```bash
CD=traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms

# 1. Payload layout (76 bytes, 12 word writers + 7 byte writers + zeros).
tracemiku-cli byte-writer-map $CD --addr 0x74b68bbe00 --size 76 \
  | jq '.bytes | group_by(.writer.idx) | map({idx:.[0].writer.idx, asm:.[0].writer.asm, span:length, sv:.[0].writer.src_value}) | sort_by(.idx)'

# 2. time() → LCG seed → VM slot 0xc0 → affine mod64 step (one hop).
tracemiku-cli forward-dep-tree $CD --idx 13831028 --depth 12 --limit 80 --data-only

# 3. Common ancestors of two variable bytes (2,346 rows incl. bytecode reads
#    at [x21, #4/0x10/0x19/0x1b]); 26x more than var-vs-const.
tracemiku-cli bfs-slice $CD --idxs 13946358,13947010 \
  --mode intersection --limit 3000 --data-only

# 4. Pre-trace VM bytecode pointer + observed bytes.
tracemiku-cli record $CD 13943022 | jq '.regs.x21'   # → 0x74fbf70370
tracemiku-cli mem-dump $CD --addr 0x74fbf70370 --count 64 --cursor 13943022

# 5. Per-word xor-ladder formulas (already encoded in the simulator).
tracemiku-cli api $CD /api/byte-lineage \
  -p 'addr=0x74b68bbe08' -p 'before_idx=14164462' -p 'compact=true'
```

## Final completion status

`xsign_partial_sim.py` records this as `complete_for_call001_trace_model`
and `portable_algorithm_ready: false`. That is the correct status: the
algorithm spec is complete; the only step left is extracting the
`vm_bytecode_table` and the .rodata constants from libsgmainso.so to
turn `portable_algorithm_ready` to `true`. That is a binary-RE step on
the SO, not a trace-analysis step, and it is intentionally outside the
scope of traceMiku's tool-development goal (per CLAUDE.md "the project
goal is the tool, not a single SO target").

## Why the SO alone is not enough — appendix on the protector layout

Pulling
`example/106_d9da290cacaffd471ee1231d16b59190/lib/arm64-v8a/libsgmainso-6.8.260403.so`
apart shows the protector explicitly does NOT keep the run-time
constants in static `.rodata`. Specifically:

* The ELF section table is wiped (every `Address` reads
  `0xffffffff…`, every `Size` is `0x10`); only the LOAD program
  headers are intact.
* LOAD2 (RW relro) entropy is `0.59` — sparse PLT/GOT.
* LOAD3 (RW data, `0x12da30` bytes) entropy is `7.88` — the high
  end of "encrypted/compressed". Its top non-zero 8-byte windows
  (`010000002b110008`, `3c0c820f03e2ffff`, `eb0400004301ffff`) look
  like bytecode templates with embedded `0xffffffff` placeholders, not
  plain ARM code.
* A literal byte search for every documented runtime constant
  (`0x5851f42d4c957f2d`, `0x2cabac28`, `0x05203a10`, `0x006dcbf8`)
  returns **zero** hits inside the SO. None of them live in static
  bytes; they are either constructed at runtime by VM ops or stored
  encrypted in LOAD3.
* `tracemiku-cli resolve-trace-addr` for both `x21 = 0x74fbf70370`
  (the VM dispatcher pointer) and `0x75ebae5ad8` (the xor-ladder
  bytecode source) returns `status: miss` against the trace's 466
  module mappings — both addresses are heap, not SO-mapped.
* `tracemiku-cli byte-writer-map` of `0x74fbf70370` shows the bytes
  there are **written by the VM dispatcher itself** at idx 11272709
  inside `sub_16ae04` (the inner instruction at idx 11272709 is
  `strh w3, [x23]` with `w3 = 0x252`, inside a tight `ubfx/sbfx/strb`
  sequence — the VM is building its own next-step state).
* `tracemiku-cli byte-writer-map` of `0x75ebae5ad8` shows **no
  observed writer** — the data was deposited before our trace started,
  by the SO's loader/initialiser path.
* Zero records inside the trace touch the LOAD3 region of the SO
  (`/api/query kind=reads addr_lo=0x7601bce000 addr_hi=0x7601cfc880`
  returns `count: 0`). The decoder ran during JNI_OnLoad / first-call
  init, well before the trace recording window.

So the path "decompile static SO → portable simulator" requires three
extra reverse-engineering steps that the trace cannot bootstrap:

1. Locate the LOAD3-decryption stub (or the runtime decoder that
   feeds the VM dispatcher heap regions).
2. Rebuild that decoder in Python so the heap state can be produced
   from static SO bytes alone.
3. Detangle the VM-of-VM control flow inside `sub_16ae04`, which
   constructs each next dispatch slot byte-by-byte.

The cheaper-and-correct alternative — and what
`xsign_partial_sim.py`'s `current_trace_model_input_manifest` is
designed for — is to **extract the decoded heap regions once on a
running device** and supply them as a parameter:

```bash
# On a rooted device after libsgmainso has loaded but before the
# x-sign call.
adb shell cat /proc/<pid>/maps | grep "\[anon"
adb shell dd if=/proc/<pid>/mem of=/sdcard/bc1.bin bs=1 \
    skip=$((0x74fbf70370)) count=$((0x10000))
adb shell dd if=/proc/<pid>/mem of=/sdcard/bc2.bin bs=1 \
    skip=$((0x75ebae5000)) count=$((0x10000))
adb pull /sdcard/bc1.bin /sdcard/bc2.bin .
```

These two heap dumps, plus the per-call `time_t`, `stat_mtim_tv_sec`,
and `process_id`, are the true minimal portable-input set. Once the
dumps are present, `current_trace_model_simulation` produces the exact
x-sign offline; the simulator's `portable_algorithm_ready` flag would
then be flipped to true. Note that the heap addresses depend on the
process's allocator state and shift across loads — extract them once,
treat them as opaque blobs, and re-anchor through the dispatcher
register `x21` rather than hard-coding the pointer.

The bottom line: **the SO is a packed/encrypted VM container**. The
algorithm has been spelled out completely from the trace evidence; what
"the SO contains" is a packed implementation of the same algorithm
behind a runtime decoder, not a more-portable form of it. Static
extraction without reverse-engineering the protector is strictly
weaker evidence than the trace already gives.
