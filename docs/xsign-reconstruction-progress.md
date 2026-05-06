# x-sign reconstruction progress

This note records concrete trace findings for the current x-sign reconstruction
work. It is target-specific evidence, not a core traceMiku assumption.

## Current sample set

Command:

```bash
rust/target/debug/tracemiku-cli scan-jni-output-strings traces \
  --key x-sign \
  --decode-url \
  --decode-base64 \
  --decode-base64-full \
  --diff-base64 \
  --prior-inputs 80 \
  --limit 20
```

Observed across six local samples:

- raw x-sign length after URL decode: 102 bytes.
- base64-decoded payload length: 76 bytes.
- common decoded prefix: `6b360108cd34ef1000`.
- `base64_diff.stable_ranges` reports this as a half-open byte range
  `[0,9)`.
- `base64_diff.first_variable.output_map_args` points to Base64 group `3`, the
  first group after the fixed header.
- corresponding raw base64 prefix: `azYBCM007x`.
- Searching the trace for the decoded payload prefix did not find a contiguous
  raw payload buffer in `call_001`; current evidence points to incremental
  Base64/string assembly rather than a single observed pre-encode buffer.

Example decoded payload prefix/suffix:

```text
6b360108cd34ef1000a626105d528b91...
...8554125a7faa708626158de616062616
```

The fixed prefix strongly suggests the final x-sign string is standard Base64
over a 76-byte binary payload, with a fixed 9-byte binary header.

## Output buffer chain

For `traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms`:

```bash
rust/target/debug/tracemiku-cli output-backtrace <call_dir> \
  --key x-sign \
  --max-mem-hits 10 \
  --writes-per-hit 0 \
  --skip-taint
```

Full raw string hits:

```text
0x74b68bcc1c first_idx=14755491
0x756649a2d0 first_idx=14761618
0x756649f510 first_idx=14818316
0x756649fb35 first_idx=14803456
```

Short fixed-prefix hit:

```bash
rust/target/debug/tracemiku-cli api <call_dir> /api/find-mem-pattern \
  -p bytes_hex=617a5942434d30303778 \
  -p max=20
```

Includes `0x74b68bbbff`, which contains only the fixed `azYBCM007x` prefix.

## VM chain examples

Final copy layer for first four output bytes:

```bash
rust/target/debug/tracemiku-cli vm-backchain <call_dir> \
  --idx 14755538 \
  --reg w1 \
  --steps 5 \
  --lookback 200000
```

Observed chain:

```text
14755538 str w1, [x19, x6]            value 0x42597a61 ("azYB")
  <- slot 29 write
14755494 str x16, [x25, x1]           value 0x42597a61
  <- ldr w16, [0x74b68bcc1c]
14748081 strb w19, [x8, x14]          value 0x42 ("B")
  <- slot 2 write
14748039 str x1, [x25, x5]            value 0x42
  <- ldrb w1, [0x74b68bbc02]
```

This proves the final JNI-visible string is copied from earlier VM-managed
string buffers, not generated directly at the last `NewStringUTF` callsite.

## Base64 alphabet

The VM table lookup uses a standard Base64 alphabet at `0x74fbf29990`.

Example:

```bash
rust/target/debug/tracemiku-cli vm-slice <call_dir> \
  --start 14730878 \
  --count 14 \
  --only-vm
```

Relevant rows:

```text
14730882 ldr x4, [x25, x19, lsl #3]   x4 = 0x74fbf29990
14730884 ldr x20, [x25, x17, lsl #3]  x20 = 0
14730885 ldrb w3, [x4, x20]           w3 = 0x41 ("A")
14730888 str x3, [x25, x1]            stores "A" back to VM slot 17
```

Dumping `0x74fbf29990` shows the accessed bytes line up with:

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

Unknown bytes in `mem-dump` output mean "not observed in MemShadow", not
different alphabet bytes.

## Current CLI workflow

Attach chain evidence directly to the output report:

```bash
rust/target/debug/tracemiku-cli output-backtrace <call_dir> \
  --key x-sign \
  --skip-taint \
  --max-mem-hits 2 \
  --writes-per-hit 8 \
  --vm-chain-steps 3 \
  --vm-chain-runs 6
```

When a chain stops at an ALU row or table lookup, inspect
`backstep.frontier[]`. For a table lookup such as:

```text
ldrb w3, [x4, x20]
```

the interesting branch is usually the index register (`x20`), not the alphabet
base (`x4`):

```bash
rust/target/debug/tracemiku-cli vm-backstep <call_dir> \
  --idx 14730885 \
  --reg x20 \
  --lookback 300000
```

As of 2026-05-06, `vm-backchain --follow-frontier` automates this common manual
branch. A trace-backed smoke run from a later output store:

```bash
rust/target/debug/tracemiku-cli vm-backchain <call_dir> \
  --idx 14748757 \
  --reg w1 \
  --steps 16 \
  --lookback 500000 \
  --follow-frontier
```

showed the expected result-to-input walk:

```text
str w1, [x19, x6]                    writes "piYQ" group
<- VM slot 2 value 0x59697041         earlier "ApiY" word
<- output scratch byte 0x59           byte 'Y'
<- Base64 table lookup                alphabet byte has no writer
<- frontier x20 = 0x18                table index for 'Y'
<- VM slot / memory byte 0x61         underlying byte feeding that index
```

While validating this chain, a core address-indexing bug was found and fixed:
Rust `MemOp::addr_of` originally ignored scaled register-index addressing such
as `[x25, x15, lsl #3]`. That made VM slot writes land at the wrong indexed
address for MemShadow, `mem-writes-in-range`, and backward chain hops. After the
fix, the same trace confirms:

```text
idx 14731216  str x19, [x25, x15, lsl #3]
slot addr     0x7744599528
src x19       0x18
```

so the Base64 table index for `Y` is now explained by the actual `lsr`
calculation:

```text
idx 14731214  lsr x19, x2, x11   ; x2=0x61, x11=2, x19=0x18
```

The next reconstruction step is to interpret these VM opcode windows as
Base64-index operations and then continue from the bytes being shifted/masked
back to the payload source.

For the output group `piYQ`, the corrected chain identifies a reusable VM
word-assembly template:

```text
slot2 = 0x59697041                 ; "ApiY" intermediate
slot2 = slot2 >> 8                 ; 0x596970  ("piY")
slot4 = slot3 << 24                ; 0x51000000 ("Q" in high byte)
slot2 = slot4 | slot2              ; 0x51596970, little-endian bytes "piYQ"
store w1 -> output buffer
```

This confirms the late VM stage is assembling Base64 character words in
little-endian order. The raw 76-byte payload still has not appeared as a
contiguous buffer; the likely route is to lift these VM templates back to the
table-index calculations that produce each Base64 character.

`vm-backtree` is now the preferred inspection command for this stage because it
does not collapse ALU merges to one heuristic branch. For `idx 14748746 --reg
x4`, it returns both:

```text
x14 = 0x51000000 <- lsl w16, w1, #0x18
x17 = 0x596970   <- lsr w12, w7, #0x8
```

and then continues the data branches back to earlier intermediate words such as
`0x4b565851` and `0x59697041`, while keeping shift amounts as separate
frontier leaves.

`output-map` now packages this per Base64 group. Example:

```bash
rust/target/debug/tracemiku-cli output-map <call_dir> \
  --key x-sign \
  --hit-order earliest \
  --group-start 3 \
  --groups 1 \
  --tree-depth 8 \
  --tree-max-nodes 220 \
  --tree-frontier-with-next \
  --lookback 500000
```

For group 3 it reports:

```text
chars       piYQ
decoded     a62610
writer      str w16, [x2, x5]
tree root   0x51596970 -> orr x4, x14, x17
branches    x14=0x51000000, x17=0x596970
```

`vm-backtree` also reports `upstream.byte_nexts` for word loads. On the
`piYQ` group, the load that produces `0x4b565851` now expands to the four
byte writers for `Q/X/V/K`, and the load that produces `0x59697041` expands to
`A/p/i/Y`. This is the level needed to keep walking from generated Base64 text
back toward payload bit indexes.

The same information is summarized under `highlights.word_loads`; table lookup
rows are summarized under `highlights.table_lookups` with the recovered
alphabet index when the index register is visible.

`output-map` also records the Base64 math for every group under
`base64.indices` and `base64.decoded_bytes`, so the index traces can be mapped
directly back to payload bytes. With a tree attached, `base64_lookup_matches`
maps the current group characters to concrete alphabet lookup trace idxs; for
`piYQ` this resolves `p/i/Y/Q` to idxs
`14731087/14731131/14731228/14731327`.
Use `--index-tree-depth` to attach bounded provenance trees for those index
registers without running four separate commands.

Important caveat from the first index-tree pass: these lookup idxs are already
past the alphabet table, but still inside a Base64 scratch/window layer. For
example, the `p` lookup (`index 0x29`) is built as:

```text
0x28 = 0x0a << 2
0x01 = 0x62 >> 6
0x29 = 0x28 | 0x01
```

This is a valid Base64 6-bit construction, but the input bytes shown here are
scratch/window bytes. They must still be traced further before treating them as
business payload fields. The VM writes overlapping 4-character windows, so a
character reused in final group `piYQ` may have been generated in a neighboring
window such as `ApiY`.

`index_tree.highlights.alu_formulas` now exposes these relationships directly.
`base64_lookup_matches[].matches[].index_summary.interesting_formulas` filters
that list to small-value formulas so it can be used as a compact prompt input.
For group 3, current examples include:

```text
p  0x29 = 0x28 | 0x1
p  0x1  = 0x62 >> 0x6
i  0x22 = 0x62 & 0x3f
Y  0x18 = 0x61 >> 0x2
Q  0x10 = 0x610 & 0x30
```

`vm-ops` now collapses the interpreter rows by `x21`/`vm_ip`, which makes the
same path readable as VM operations. For the first variable group in `call_001`
(`piYQ`, decoded `a6 26 10`), the relevant segment is:

```text
vm_off 0x10: load byte [0x74b68bcc1d] = 0x0a -> slot16
vm_off 0x20: load byte [0x74b68bcc1e] = 0x62 -> slot17
vm_off 0x30: slot16 = 0x0a << 2 = 0x28
vm_off 0x40: slot17 = 0x62 >> 6 = 0x01
vm_off 0x60: slot16 = 0x28 | 0x01 = 0x29
vm_off 0x80: alphabet[0x29] = 'p'
```

The byte sources are still scratch/window bytes:

```text
0x62:
  0x74b68bbcff --strb@13946358--> 0x74b68bcc1e
  source op: slot2 = 0x74ffafca73 + 0x757524ef = 0x757524ef62

0x0a:
  0x74b68bd069 --strb@14717321--> slot29
  slot29 --strb@14719759--> 0x74b68bcc1d
```

This confirms the Base64 stage is standard, but the current source bytes are
not yet business payload fields; they are copied through VM-managed scratch
buffers before alphabet lookup.

The same chain can now be reproduced with:

```bash
rust/target/debug/tracemiku-cli byte-lineage <call_dir> \
  --addr 0x74b68bcc1e \
  --before-idx 14731017 \
  --depth 8 \
  --lookback 1200000 \
  --summary
```

For the `0x62` path, this follows:

```text
0x74b68bcc1e <- strb@14723253 x14=0x62
slot28       <- str@14723221 x3=0x62
0x74b68bbcff <- strb@13946358 x14=0x757524ef62
slot2        <- str@13946347 x15=0x757524ef62
stop: x15 = x13 + x14, frontier x13=0x74ffafca73 and x14=0x757524ef
```

`byte-lineage --summary` now recognizes this as an end-around carry reduction:

```text
x14 == x13 / 0xff
(x13 + x14) & 0xff == x13 % 0xff == 0x62
```

The summary emits this under `recognized_semantics[].semantic.kind =
mod255_low_byte`, so an AI agent does not have to rediscover the arithmetic
identity from the raw register values on every pass. The remaining boundary is
now the upstream `x13` value (`0x74ffafca73`): it must be traced further to
classify whether it is payload state, digest state, pointer-derived state, or a
table constant.

Tracing the paired quotient register confirms the fold:

```bash
rust/target/debug/tracemiku-cli vm-backtree <call_dir> \
  --idx 13946345 \
  --reg x14 \
  --depth 4 \
  --frontier-with-next \
  --summary
```

`highlights.semantic_formulas[]` reports:

```text
0x757524ef = 0x74ffafca73 / 0xff
```

The `0x74ffafca73` numerator can now be chased deeper with the linear
VM helper:

```bash
rust/target/debug/tracemiku-cli vm-backchain <call_dir> \
  --idx 13946163 \
  --reg w13 \
  --steps 12 \
  --lookback 1200000 \
  --follow-frontier \
  --summary
```

This smoke run exercises three important CLI capabilities needed for AI-driven
result-to-input analysis:

```text
ldp x9, x10, [x25,#0xc0]   expands to separate x9/x10 memory definitions
lsr w0, w13, w4            follows w13, not the shift register w4
add x5, x3, x4             recognizes state + 1 as add_small_delta
mul x3, x6, x4             reports wrapped 64-bit multiplication
```

The resulting chain no longer stops at the pair-load or follows the constant
`1`; it continues through the larger VM state values:

```text
0xd35b7999
<- 0x99bd5d2 + 0xc9bfa3c7
<- 0x99bd5d21d7d8103 >> 0x20
<- 0x99bd5d21d7d8102 + 0x1
<- 0x99bd5d21d7d8102
```

This is still VM/digest state, not yet the final business input. The value is
useful because it proves the CLI can keep walking through interpreter register
loads, pair loads, shifts, wrapped multiplication, and small state increments
without manual register selection at every row.

A longer continuation shows a repeated update shape:

```text
state = (state * 0x5851f42d4c957f2d + 1) mod 2^64
```

`vm-backchain --summary` now reports these adjacent multiply/add pairs under
`recognized_patterns[].kind = affine_mod64_state_step`, with the previous
state, multiplier, delta, odd-multiplier flag, and multiplier inverse
(`0xc097ef87329e28a5` for the multiplier above). This should be treated as a
candidate PRNG/digest-state transition until more surrounding bytecode proves
its exact role.

Continuing backward from the earlier 32-bit state `0x69f5b3cb` reaches a call
return boundary:

```text
mov x3, x23
<- mov x23, x0
<- blr x22 returned x0 = 0x69f5b3cb
```

The concrete call row is:

```text
idx        13831027
pc         0x7601b72790
asm        blr x22
target     x22 = 0x787bf034e8
args       x0=0, x1=1, x2=0x747d0dc500, x3=1, x4=0, x5=0x1010101,
           x6=0x169b, x7=0x2c
return     x0 = 0x69f5b3cb
```

This is an important boundary for reconstruction: the value should not be
attributed to the pre-call `mov x0, x20`; it came back from an indirect
function pointer outside the currently traced instruction stream. The next
question is whether `0x787bf034e8` is a known runtime/JNI helper, an untraced
native helper, or a callback into code that needs a wider trace/hook.

On the currently attached device, resolving the same address range in the
current Taobao process maps places this target in bionic libc:

```text
787beb8000-787bf61000 r-xp 0005b000 ... /apex/com.android.runtime/lib64/bionic/libc.so
addr 0x787bf034e8 -> file offset 0xa64e8 -> time@@LIBC
```

The map part can now be reproduced by CLI:

```bash
rust/target/debug/tracemiku-cli resolve-map-addr /tmp/taobao_7979.maps 0x787bf034e8
```

So the returned value is a Unix timestamp:

```text
0x69f5b3cb == 1777710027 == 2026-05-02T16:20:27 local time
```

This is close to the input timestamp string `1777710018`, but not identical
(`+9s`). For simulator work, treat the affine state chain as seeded or mixed
with the native `time()` result unless a wider trace shows additional writes to
the same VM slot before this call.

The confirmed pieces are captured in a runnable partial simulator:

```bash
uv run python examples/libsgmainso/xsign_partial_sim.py
```

It verifies the standard Base64 decode, the `time()`-seeded LCG sequence above,
the `mod255_low_byte` fold for the `0x62` byte, and the first variable Base64
index `p`. It deliberately reports `complete_algorithm = false` until the full
76-byte payload construction is recovered.

For the paired `0x0a` byte feeding the same Base64 index, a deeper lineage run
reaches a copied word value rather than an ALU merge:

```text
0x74b68bcc1d <- strb@14719759 x19=0x0a
slot29       <- str@14719718 x1=0x0a
0x74b68bd069 <- strb@14717321 x14=0x0a
slot25       <- str@14717262 x3=0x0a
0x74b68bb9a2 <- strb@13835725 x14=0x0a
slot2        <- str@13835683 x1=0x0a
0x756649e1d3 <- str@13781975 x1=0x0a000142
...
stop: ldr w16, [0x74fbf2dc7c] has no observed writer
```

That looks like a VM/static memory table or unobserved pre-trace initialized
word. It is not yet safe to label `0x0a` as a business payload byte.

For the `0x61` byte that contributes to the same group, the current compact
chain reaches a smaller affine step:

```text
0x25a8 = 0xc87 * 0x3 + 0x13
```

`vm-backchain --follow-frontier` now follows `0xc87` rather than the small
multiplier `3`. The next layer currently enters repeated zero-valued `and` and
VM-slot loads, so more boolean/mask-aware summarization is still needed before
this branch can be treated as a real input or constant.

## Next target

The remaining unknown is the 76-byte binary payload before Base64. The next
work item is to trace Base64 table index registers back to payload bytes and
record the VM bytecode pattern that maps three payload bytes into four alphabet
indexes. The immediate next target is to follow the `0x0a`/`0x62` scratch byte
lineage through the new `byte-lineage` frontiers until it reaches either a JNI
input byte, a hash digest/finalizer output, a fixed table, or a bytecode
immediate. Once that
mapping is isolated, the Python simulator should implement:

1. build the 76-byte payload,
2. standard Base64 encode it,
3. URL-encode `+` and `/` as observed by JNI output when needed.
