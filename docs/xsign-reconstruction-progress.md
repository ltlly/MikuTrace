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
- whole-string Base64 decode length: 76 bytes.
- common decoded prefix: `6b360108cd34ef1000`.
- `base64_diff.stable_ranges` reports this as a half-open byte range
  `[0,9)`.
- `base64_diff.first_variable.output_map_args` points to Base64 group `3`, the
  first group after the fixed header.
- corresponding raw base64 prefix: `azYBCM007x`.
- Searching the trace for the decoded payload prefix did not find a contiguous
  raw payload buffer in `call_001`; current evidence points to incremental
  Base64/string assembly rather than a single observed pre-encode buffer.

Example whole-string decoded prefix/suffix:

```text
6b360108cd34ef1000a626105d528b91...
...8554125a7faa708626158de616062616
```

The full x-sign is valid Base64, but trace evidence shows the variable section
after the fixed 12-character prefix is assembled as an unaligned Base64 slice.
For semantic reconstruction, prepend `AA` to the variable tail and ignore the
first synthetic decoded byte:

```text
x-sign                     = azYBCM007xAA || piYQXVKL...
tail                       = piYQXVKL...
base64_decode("AA" + tail) = 00 0a 62 61 05 d5 28 b9 ...
semantic tail              =    0a 62 61 05 d5 28 b9 ...
```

CLI form:

```bash
rust/target/debug/tracemiku-cli scan-jni-output-strings traces \
  --key x-sign \
  --decode-url \
  --diff-base64 \
  --base64-tail-start 12 \
  --base64-tail-align-prefix AA \
  --base64-tail-drop 1
```

The whole-string 76-byte decode is still useful for diffing, but it is not the
buffer shape currently observed in the trace. The traceable scratch bytes for
the first variable group are `0x0a, 0x62, 0x61, ...`, not the whole-string
decoded bytes `a6 26 10`.

The fixed 12-character prefix is now better characterized. Searching trace
memory finds the raw text `azYBCM007xAA`, but not the decoded bytes
`6b360108cd34ef1000`:

```text
raw prefix hits:
  0x74b68bcc1c first_idx=14755491
  0x756649a2d0 first_idx=14761618
  0x756649f510 first_idx=14818316
  0x756649fb35 first_idx=14803456
decoded prefix hits: 0
```

At `0x756649a2d0`, `byte-writer-map --summary` compresses the prefix into three
little-endian word stores:

```text
[0,4)  "azYB"  src=0x42597a61  writer #14755538
[4,8)  "CM00"  src=0x30304d43  writer #14755552
[8,12) "7xAA"  src=0x41417837  writer #14755558
```

So the current simulator boundary is the raw 12-character prefix, not a
directly observed nine-byte pre-Base64 header. The semantic meaning of that
prefix is still unresolved, but the storage form is no longer ambiguous.

The Python simulator now verifies the output encoding layer separately:

```text
xsign == raw_prefix + base64(00 || semantic_tail)[2:]
```

This holds for all current local samples. The remaining work is therefore not
Base64 reconstruction; it is deriving the semantic tail bytes and raw prefix
meaning from portable upstream inputs.

The simulator also reconstructs `call_001`'s 68-byte semantic tail from the
current trace formula classes instead of directly trusting the final byte
string:

```text
tail[0]        = byte_lane_le(0x0a000142, 3)
mask byte      = mod255_low_byte(input)
XOR ranges     = lhs_run ^ parity_mask
formula output = observed semantic tail
full x-sign    = raw_prefix + base64(00 || formula_output)[2:]
```

This verifies the output equation layer end-to-end for one sample. It is still
not a portable algorithm because the large `lhs_run` inputs include
trace-constant and external-boundary values.

Aligned-tail `output-map` form:

```bash
rust/target/debug/tracemiku-cli output-map <call_dir> \
  --key x-sign \
  --base64-tail-start 12 \
  --base64-tail-align-prefix AA \
  --base64-tail-drop 1 \
  --group-start 0 \
  --groups 2 \
  --tree-depth 8 \
  --index-tree-depth 8 \
  --tree-frontier-with-next \
  --summary
```

For `call_001`, this maps aligned group `0` to `AApi`, where decoded byte
offset `0` is synthetic/dropped, semantic offsets `0` and `1` are `0x0a` and
`0x62`; aligned group `1` starts semantic offsets `2..4` as `0x61 0x05 0xd5`.
For direct byte-oriented work, `--semantic-offset 65 --semantic-count 3` selects
aligned group `22` and reports `tail[65:68] = 62 61 62` without manual Base64
group arithmetic.

The semantic tail scratch buffer can now be mapped directly from bytes to their
latest trace writers:

```bash
rust/target/debug/tracemiku-cli byte-writer-map \
  traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms \
  --addr 0x74b68bcc1d \
  --size 68 \
  --idx-hi 14739000 \
  --max 300
```

The validated `call_001` result is complete (`matched=228`, `returned=228`,
`truncated=false`) and reconstructs the 68-byte semantic tail:

```text
0a626105d528b91a5f1a0eaf606261629a8b930b188e93f7209460f1d2295d336dae63ff825bafa0f452f1411dddc5965ac22528554125a7faa708626158de6160626162
```

Its `writer_runs[]` view shows the useful chunking: early bytes are mostly
single `strb` writes, offsets `7..54` are packed 32-bit `str w*` writes, and
offsets `55..67` return to byte stores. This is the compact entry point for
the result-to-input strategy: select each output byte or 4-byte run, then chase
its writer source register with `vm-backchain` or `byte-lineage`.

For quick triage, attach upstream summaries to the first runs:

```bash
rust/target/debug/tracemiku-cli byte-writer-map \
  traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms \
  --addr 0x74b68bcc1d \
  --size 68 \
  --idx-hi 14739000 \
  --max 300 \
  --vm-chain-steps 16 \
  --vm-chain-runs 6 \
  --vm-chain-follow-frontier
```

This keeps one JSON document containing the output bytes, writer chunking, and
the first layer of result-to-input backchains. A short `--vm-chain-steps 12`
run over all current `call_001` writer runs reports:

```text
32 writer runs
add_small_delta: 6
bitwise_or_merge: 16
mod255_low_byte: 7
shift_right: 13
ubfx: 13
xor_identity: 6
xor_mix: 23
```

This confirms three active classes in the semantic tail: XOR byte mixing and
normalization for many single-byte staging writes, packed-word byte extraction
for the middle 4-byte runs, and modulo-255 byte generation for
several single-byte tail positions including the repeated `62 61 62` suffix.
Deeper selected chains also expose MD5-like 32-bit state operations, including
`add_known_constant` with `md5_iv_a = 0x67452301`, `add32_mix`, and 32-bit
shift/extract operations.

The backward byte chains are now lane-aware. Each byte writer map entry records
`source_byte_offset`; `vm-backchain` receives that as `start.byte_lane` and
prefers `upstream.byte_nexts[]` with the same little-endian lane when a
multi-byte load is encountered. This prevents a final `strb` output byte from
being traced to the newest byte of a loaded 32-bit word. For example,
`call_001` semantic tail offset 4 is now correctly summarized as:

```text
tail[4] = 0xd5
step 1: ldr w16, [0x74b68bc100] follows lane 0 -> writer 14704246, value 0xd5
step 4: 0xd5 = 0xb4 ^ 0x61
```

Before lane selection, the same path could incorrectly follow lane 3 of the
word and report `0x1a = 0x78 ^ 0x62`.

Lane selection also applies at semantic ALU frontiers. For `bitwise_or_merge`,
the chain follows the operand that contributes the selected result byte. For
shift/extract semantics, the next hop carries the transformed source lane. This
keeps chains such as `0x78d84ab4 -> 0xd84ab4 -> 0xd84ab467` on the byte that
actually produced the observed output byte instead of drifting to a neighboring
packed-word lane.

`byte-lineage` now uses the same lane discipline for focused memory-byte
investigations. Starting from `0x74b68bb9ec` before #14688014 in `call_001`,
the last writer is #14165584 `strb w6, [x16, x2]`, so the next register seed is
`x6` lane `0`. The chain then follows the matching byte of the VM slot load
into `x13`, carries lane `0` through `lsr x13, x17, x5`, and correctly lands on
`x17` lane `2` because the value was shifted right by `0x10` bits. This fixes a
previous ambiguity where the same byte path stopped at the shift or fell back to
whole-register provenance.

The current Python partial simulator records the first confirmed lane-aware XOR
equations:

```text
tail[3] = 0x67 ^ 0x62 = 0x05
tail[4] = 0xb4 ^ 0x61 = 0xd5
tail[5] = 0x4a ^ 0x62 = 0x28
tail[6] = 0xd8 ^ 0x61 = 0xb9
```

These are now emitted directly by `output-map --summary` under
`semantic_writer_map.byte_equations[]`, together with the adjacent
`mod255_low_byte` equations for `tail[1]` and `tail[2]`. The summary also
collapses this repeated four-byte shape under
`semantic_writer_map.xor_word_templates[]`, so the AI workflow can consume the
word-level relation directly:

```json
{
  "semantic_range": [3, 7],
  "lhs_bytes_hex": "67b44ad8",
  "lhs_word_le": "0xd84ab467",
  "rhs_pattern": {
    "kind": "alternating_two_byte_mask",
    "bytes_hex": "6261",
    "source_offsets": [1, 2]
  },
  "result_bytes_hex": "05d528b9"
}
```

Across the five current `traces/diff` samples, these four XORs reduce to a
stable word template:

```text
tail[3:7] = word32_le(state_word) ^ [tail[1], tail[2], tail[1], tail[2]]
```

The partial simulator verifies:

```text
_truncated_call_006: state=0x3b61d005 masks=baa1 -> bf71db9a
call_001:           state=0xd84ab467 masks=6261 -> 05d528b9
call_003:           state=0xb9f37778 masks=34b9 -> 4ccec700
call_004:           state=0x84e5092b masks=1b54 -> 305dfed0
call_005:           state=0x6f4484fa masks=95c5 -> 6f41d1aa
```

With `--semantic-writer-map-vm-chain-steps 40`, all five samples also trace
that template state word to the same upstream shape:

```text
bswap32(source_word_be) == state_word_le
source_word_be == low32(add32_mix.lhs + add32_mix.rhs)
```

Example cross-sample source words:

```text
_truncated_call_006: source_word_be=0x05d0613b add_idx=7014025
call_001:           source_word_be=0x67b44ad8 add_idx=14678154
call_003:           source_word_be=0x7877f3b9 add_idx=6938214
call_004:           source_word_be=0x2b09e584 add_idx=6918544
call_005:           source_word_be=0xfa84446f add_idx=6960242
```

The run-level chain is good for finding the first template, but packed `str w*`
regions need byte-lane expansion to keep walking later words. The current
validated form is:

```bash
rust/target/debug/tracemiku-cli output-map \
  traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms \
  --key x-sign \
  --base64-tail-start 12 \
  --base64-tail-align-prefix AA \
  --base64-tail-drop 1 \
  --semantic-offset 7 \
  --semantic-count 32 \
  --semantic-writer-map \
  --semantic-writer-map-vm-chain-bytes \
  --semantic-writer-map-vm-chain-steps 55 \
  --semantic-writer-map-vm-chain-runs 32 \
  --semantic-writer-map-vm-chain-follow-frontier \
  --summary
```

That command emits 32 continuous `byte_equations[]` instead of only the old
`0,4,8,...` run starts. It also links the next confirmed call_001 XOR word to
the second state update:

```text
selected semantic offset 7, local range [0,4)
lhs_word_le      = 0x6f783e78
source_word      = 0x783e786f
source_word_match= bswap_lhs_word_le
word_extract     = #14678516 lsr w14, w13, w11
state_update     = #14678176 add x13, x8, x12
low32(0x561d4e18 + 0x22212a57) = 0x783e786f
```

A full 68-byte byte-lane scan with 16 backchain steps is now enough to classify
the output formulas for the whole call_001 semantic tail:

```text
requested_range             = [0, 68)
requested_coverage_status   = complete_in_requested_range
byte_equation_summary.count = 68
covered_range               = [0, 68)
kind_counts                 = byte_lane_extract: 1, mod255_low_byte: 10, xor_mix: 57
xor_rhs_pattern             = offset parity mask
even offsets                = xor rhs 0x61
odd offsets                 = xor rhs 0x62
```

The previously missing semantic offset `0` is a generic byte-lane extraction:

```text
tail[0] = byte_lane_le(0x0a000142, 3) = 0x0a
```

`semantic_byte_input_summary` now gives the next upstream targets without
manual JSON filtering:

```text
byte_lane_sources:
  0x0a000142 lane 3 -> tail[0]
mod255_inputs:
  0x74beabe59c -> 0x61 at tail[2,14,60,66]
  0x74ffafca73 -> 0x62 at tail[1,13,15,59,65,67]
xor_lhs_offsets:
  [3,13), [16,59), [61,65)
```

The first `0x62` mod255 input can be chased with the now-indexed byte equation:

```bash
rust/target/debug/tracemiku-cli vm-backchain <call_dir> \
  --idx 13946345 \
  --reg x13 \
  --steps 45 \
  --follow-frontier \
  --summary
```

That path reaches the 64-bit LCG recurrence already seen elsewhere:

```text
0x74ffafca73 = 0x74ffafbdec + 0xc87
0x74ffafbdec = 0x69adbccc | 0x74b68bb9a4
0x69adbccc    = (0xd35b7999 >> 1) & 0xffffffff
0xd35b7999    = low32(0x099bd5d2 + 0xc9bfa3c7)
0x099bd5d2    = 0x99bd5d21d7d8103 >> 0x20
next states   = state * 0x5851f42d4c957f2d + 1 mod 2^64
```

The CLI now also surfaces this directly as
`recognized_pattern_summary.affine_mod64_recurrences[]`, grouping the seven
observed transitions by multiplier and delta.

The `0x61` mod255 input at `tail[2]` follows a shorter affine state path:

```bash
rust/target/debug/tracemiku-cli vm-backchain <call_dir> \
  --idx 13946997 \
  --reg x13 \
  --steps 45 \
  --follow-frontier \
  --summary
```

The compact recurrence summary reports one transition:

```text
0x25a8 = 0xc87 * 0x3 + 0x13
```

So both known `mod255_low_byte` input classes now have upstream arithmetic
anchors.

The lone `byte_lane_extract` source word is now classified as a static memory
load constant by `vm-backchain --summary`:

```bash
rust/target/debug/tracemiku-cli vm-backchain <call_dir> \
  --idx 13781975 \
  --reg x1 \
  --steps 10 \
  --follow-frontier \
  --summary
```

```text
0x0a000142 <- ldr w16, [x8, x20]
addr       = 0x74fbf2dc7c
bytes      = 42 01 00 0a
pattern    = static_memory_load_constant
```

At the byte-equation layer, the only remaining dynamic sources are therefore
the XOR lhs streams.

The same summary now compresses the 57 XOR left-hand bytes into three
contiguous streams:

```text
[3,13):  67b44ad8783e786fcd01
[16,59): fbe9f26979ecf29541f60193b34b3c510ccc029de339cec2953090237cbfa4f43ba0444a342344c59bc569
[61,65): 3abf0301
```

For simulator-oriented output, the CLI also exposes
`byte_equation_summary.xor_lhs_word_chunks[]`, which splits these streams into
non-overlapping little-endian 32-bit chunks. For example the first chunk of the
large middle stream is:

```text
semantic[16:20] = word32_le(0x69f2e9fb) ^ 61626162
lhs bytes       = fbe9f269
result bytes    = 9a8b930b
```

`xor_word_state_source_summary` now uses these run-aligned chunks instead of
sliding windows. With the full semantic tail probe, the word-template source
coverage is now complete:

```text
semantic range        = [0,68)
run-aligned templates = 13
state sources found   = 13
missing chunks        = 0
source_status counts  = state_update_found: 2, word_source_only: 11
```

This does not mean the full algorithm is recovered. It means every word-sized
XOR `lhs` chunk now has a concrete trace source candidate. The first two chunks
in `[3,11)` reach SHA1-like state updates; most later chunks are still
`word_source_only`, where the trace proves the word value but the portable
upstream formula or external input is not fully derived yet.

The byte-level semantic equation coverage is also complete, but it is stricter
about what each byte actually is:

```text
semantic bytes requested = 68
compact equations        = 68
missing offsets          = none
xor_mix equations        = 56
mod255 equations         = 10
byte-lane extracts       = 2
```

Offset `44` is not an XOR byte. The selected byte is `0x00`, explained as
`byte_lane_le(0xb71300fd, 1)`. Earlier `output-map` summaries took the first
recognized `xor_mix` in that chain, which described neighboring result `0xfd`,
and that produced a false `[44,48)` XOR word template. The compact summary now
prefers a byte-lane explanation when the first semantic formula does not match
the selected byte, so AI prompts no longer treat offset `44` as an XOR formula.

Cross-sample extraction over `call_001`, `call_003`, `call_004`, and `call_005`
shows that the large middle stream is almost fixed, not ASLR-shaped pointer
entropy:

```text
range [16,59), size 43
call_001/call_003/call_004:
  fbe9f26979ecf29541f60193b34b3c510ccc029de339cec2953090237cbfa4f43ba0444a342344c59bc569
call_005:
  fbe9f26979ecf24141f60193b34b3c510ccc029de339cec2953090237cbfa4f43ba0444a342344c59bc569
only differing run-local offset: 7, 0x95 -> 0x41
```

This changes the next search priority. The `[16,59)` `lhs` stream is more
likely a fixed table/salt/VM literal stream with a small sample-dependent
splice than a heap pointer stream that must be reproduced from ASLR. The
pointer-looking byte lineage at `0x74b68bb9ec` still matters, but it is now one
local producer path to explain, not evidence that the whole middle run is
runtime-address-derived.

Dumping the source region at the later consumer cursor shows the large lhs
stream as one VM scratch table:

```bash
rust/target/debug/tracemiku-cli mem-dump \
  traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms \
  --addr 0x74b68bbe00 \
  --count 64 \
  --cursor 14695600 \
  --summary
```

Relevant bytes:

```text
000000fb e9f26979 ecf29541 f60193b3 4b3c510c cc029de3
39cec295 3090237c bfa4f43b a0444a34 2344c59b c5690000
3abf0301
```

`byte-writer-map --summary` over `0x74b68bbe00..0x74b68bbe34` reports
`matched=23`, `truncated=false`, and 16 compact writer runs. So this region is
not an immutable static table; it is a traced VM scratch table. The remaining
work is lifting the table writers themselves, not finding the consumer-side
source buffer.

Representative table writers show that the table has mixed provenance:

```text
#14164352 writes 000000fb
  source = 0x69f2e9fb from stat("/").st_mtim.tv_sec
  formula = (source << 24) & 0xffffffff

#14164406 writes e9f26979
  formula = (stat("/").st_mtim.tv_sec >> 8) | (static_xor_ladder_low_byte << 24)
  stat component   = 0x0069f2e9
  static component = 0x79000000

#14164461 writes ecf29541
  shape = (previous_ladder_word >> 8) | ((next_ladder_word & 0xff) << 24)
  first static load in the expanded chain:
    0x74fbf29208 -> 0x90bf1d91
```

So it is wrong to model the whole lhs stream as a single file timestamp or a
single static salt. The next lifting step needs to summarize the scratch table
writers as mixed external fields plus static-table/XOR ladder formulas.

Important correction: `static_memory_load_constant` means "no writer was found
inside the current lookback window", not proof that no writer exists anywhere
in the trace. Re-running the same table summary with
`--vm-chain-lookback 4000000` shows that reads from `0x7599191020+` do have
earlier traced writers around `#11430997..#11431512`. The truly unresolved
no-writer-in-window table reads in this probe are the `0x74fbf29xxx` values
reached by the `ecf29541` run.

The CLI summary now carries the window metadata (`idx_lo`, `idx_hi`,
`returned`, `maybe_truncated`, `source_boundary`) and a caution string on these
loads. `vm-backchain --summary` also exposes `stop`, so a chain that ends at a
VM bytecode read reports the final row and `no_upstream_next_or_frontier`
instead of looking like a complete proof.
`vm-ops --summary` now also exposes `effects[]`, which condenses VM slot writes,
memory stores, and control updates into short pseudocode rows for AI lifting.

A recent `vm-ops --summary` probe shows why this matters for VM lifting. Around
`#10616026`, the compact effect is:

```text
slot[18] = byte[0x753ddd7fdc] (0x7a)
inputs: slot24 = 0x753ddd7fd0, slot25 = 0xc
```

Dumping `0x753ddd7fd0` at the consuming cursor shows the observed string-like
buffer `QfYBk7NLPEMz...`, so offset `0xc` is byte `0x7a` (`z`). A plain latest
writer map for that byte is not enough here: the latest traced write stores
`0x00`, while the later read observes `0x7a`. `vm-backchain --follow-frontier`
therefore marks this as `observed_read_without_matching_traced_write`. The gap
scan still lists `#10612864 -> libsgmainso+0x163928` and
`#10612910 -> libsgmainso+0x163944` because their arguments cover the buffer,
but the traced callees return without writing the target range. The CLI now
marks both as `traced_callee_no_target_write` and lowers their score, so this
is still a trace-coverage/preexisting-buffer boundary rather than a proven
helper producer.

Using `vm-ops --summary --effects-only` in capped chunks over the surrounding
VM loop shows the full observed byte-load sequence:

```text
10613257  slot[18] = byte[0x753ddd7fd0] (0x51)  Q
10613454  slot[18] = byte[0x753ddd7fd1] (0x66)  f
10613695  slot[18] = byte[0x753ddd7fd2] (0x59)  Y
10613892  slot[18] = byte[0x753ddd7fd3] (0x42)  B
10614172  slot[18] = byte[0x753ddd7fd4] (0x6b)  k
10614413  slot[18] = byte[0x753ddd7fd5] (0x37)  7
10614686  slot[18] = byte[0x753ddd7fd6] (0x4e)  N
10614883  slot[18] = byte[0x753ddd7fd7] (0x4c)  L
10615163  slot[18] = byte[0x753ddd7fd8] (0x50)  P
10615360  slot[18] = byte[0x753ddd7fd9] (0x46)  F
10615557  slot[18] = byte[0x753ddd7fda] (0x45)  E
10615754  slot[18] = byte[0x753ddd7fdb] (0x4d)  M
10616034  slot[18] = byte[0x753ddd7fdc] (0x7a)  z
```

This reconstructs the observed stream `QfYBk7NLPFEMz` at the VM-consumer layer.
It does not explain who produced that buffer. It also is not the final
`x-sign` value: JNI evidence later pairs it with `x-umt`:

```text
15322406  NewStringUTF("x-umt")
15322467  NewStringUTF("QfYBk7NLPFEMzAKd4znOwpUwkCN8v6T0")
15322846  NewStringUTF("x-sign")
15322907  NewStringUTF("azYBCM007xAApiYQXVKLkaXxoOr2...")
```

So this boundary is useful as a generic CLI/VM coverage case, but it is not the
main x-sign reconstruction path. A wide single `vm-ops` request previously hid
later byte loads because the records source was capped. `vm-ops` now chunks
large windows automatically: the same `#10613240..#10616100` probe returns
`source_requested=2860`, `source_returned=2860`, `source_chunks=4`,
`source_maybe_truncated=false`, and all 13 `byte_load_effects[]`. Passing
`--chunk-size 0` reproduces the old single-request cap (`source_returned=1000`,
`source_maybe_truncated=true`, 5 byte loads).

A later probe over the same buffer shows why the index window matters. Around
`#11454867..#11455168`, the VM writes zeroes back into
`0x753ddd7fd0..0x753ddd7fdf`:

```text
11454867  mem[0x753ddd7fd0] = low8(slot[0])   # 0x00
11454911  mem[0x753ddd7fd1] = low8(slot[25])  # 0x00
11454921  mem[0x753ddd7fd2] = low8(slot[25])  # 0x00
11454960  mem[0x753ddd7fd3] = low8(slot[25])  # 0x00
11455075  mem[0x753ddd7fd0] = 0x0
11455119  mem[0x753ddd7fd4] = 0x0
11455125  mem[0x753ddd7fd8] = 0x0
11455168  mem[0x753ddd7fdc] = 0x0
```

`byte-writer-map --addr 0x753ddd7fd0 --size 16 --idx-lo 11454800 --idx-hi
11455200 --summary` returns four 32-bit zero writer runs covering all 16 bytes,
and `mem-dump --cursor 11455200 --addr 0x753ddd7fd0 --count 32 --summary`
shows `0000000000000000000000000000000000000000000000000000000076365430`.
So this later trace segment is a buffer clear/reuse, not the producer for the
earlier observed `QfYBk7NLPFEMz` bytes. The right reconstruction boundary is
still the earlier observed read without a matching traced write.

The full 16-writer summary over the table is now compact enough for an AI to
consume directly. `byte-writer-map --summary` exposes this as
`vm_source_ranges[]` with inclusive offsets:

```text
offsets  bytes       class
0..7     000000fb... memory_boundary_read, stat("/") st_mtim candidate
8..11    ecf29541    static_memory_load_constant / no-writer-window table
12..35   f601...3b   traced_formula_only, earlier VM ladder values
36..43   a044...9b   memory_boundary_read, text bytes "10.6" / "0.10"
44..47   c5690000    traced_formula_only
48..51   3abf0301    unclassified short tail
```

Aggregate pattern counts from these 16 chains are:

```text
memory_boundary_read        = 4
static_memory_load_constant = 10
```

This is the useful split for simulation work: the table is generated, but its
portable inputs are a mixture of `stat("/")`, no-writer-window table reads,
earlier VM-generated ladder values, a short text buffer, and a few literal tail
bytes.

For the `traced_formula_only` ranges, `vm_source_ranges[].stops[]` now points
at VM-IP stop rows. A focused continuation from the first stop:

```bash
rust/target/debug/tracemiku-cli vm-ops \
  traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms \
  --start 10613140 \
  --count 120 \
  --summary \
  --effects-only \
  --max-ops 20
```

returns `bytecode_read_count=44`, `control_effect_count=1`, and
`op_template_count=12`. The first control template is
`bc[0x8:8] effects[control:formula:add]`:

```text
#10613173 bytecode[+0x8] = 0x9
#10613174 add x21, x21, x6, lsl #4
         0x75ebae5970 = 0x75ebae58e0 + 0x9
```

This closes the prompt-surface gap for VM-IP stops: an AI can move from a
byte-writer formula-only range into a compact VM operation window without
loading the full per-op payload.

Expanding the same probe to cover all current formula-only stops:

```bash
rust/target/debug/tracemiku-cli vm-ops \
  traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms \
  --start 10613140 \
  --end 10620150 \
  --summary \
  --effects-only \
  --max-ops 400
```

returns `op_template_count=34` with a highest-frequency template:

```text
count     = 49
signature = bc[0x3:1,0x5:1,0x8:4,0x10:2] effects[slot_write:formula:ubfx]
operands  = 0x3, 0x5, 0x8, 0x10
shape     = slot_write:formula:ubfx
inputs    = slot19 x44, slot20 x5
outputs   = slot19 x27, slot20 x22
skeleton = slot[dst] = ubfx(slot_srcs, bc_0x3_u8, bc_0x5_u8, bc_0x8_u32, bc_0x10_u16)
bound    = slot[bc_0x5_u8] = ubfx(slot[bc_0x3_u8], bc_0x8_u32, bc_0x10_u16)
roles     = bc_0x3_u8 src_slot x49/dst_slot x32; bc_0x5_u8 dst_slot x49/src_slot x32
```

The narrow VM-IP stop probe now also emits the control-flow skeleton
`vm_ip = add(vm_ip, bc_0x8_u64)` for
`bc[0x8:8] effects[control:formula:add]`, with `bc_0x8_u64` marked as a
`control_operand`. These skeletons are intentionally shape-only: exact slot
role binding still comes from `template_operands[].roles[]`, `effect_shapes[]`,
and `sample_ops[]`. `python_with_roles` applies the strongest role counts into a
direct opcode sketch, and per-op `bytecode_reads[].name` lets the sketch be
instantiated with concrete bytecode values from each `op_effects[]` row. It
still needs confirmation against samples before it is treated as semantics. The
next lift target for the `[12,35)` VM ladder is to convert these repeated
bytecode operand layouts plus effect shapes into portable Python VM templates.

The Python reconstruction now uses this split directly:

```text
middle_lhs[0:4]  = word32_le(stat("/").st_mtim.tv_sec)
middle_lhs[4:43] = traced mixed suffix from static/text/literal VM sources
```

The actual scratch writer window is now inspectable as role-bound VM templates:

```bash
rust/target/debug/tracemiku-cli vm-ops \
  traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms \
  --start 14164280 \
  --end 14165320 \
  --summary \
  --effects-only \
  --max-ops 200
```

returns `op_template_count=24`, `effect_count=110`, and
`memory_store_effect_count=16` without truncation. The highest-count templates
include:

```text
count 14  slot[bc_0x2_u8] = add(slot[bc_0x6_u8], bc_0x8_u64, bc_0x10_u16)
count 12  mem[addr] = slot[bc_0x5_u8]
count  9  slot[bc_0x3_u8] = orr(slot[bc_0x3_u8], slot[bc_0x4_u8], slot[bc_0x5_u8], bc_0x10_u16)
```

So the remaining blocker is no longer "find the upstream VM bytecode" for this
range. The blocker is validating each role-bound skeleton against `sample_ops[]`
and implementing portable Python opcode semantics for the scratch table and
tail byte-source windows.

Tracing the first middle word `fbe9f269` in `call_001` found three memory hits:

```text
0x74b68bbe03 first_idx=14691056
0x74b68bc00c first_idx=14700861
0x74fbf31b48 first_idx=14089060
```

The earliest hit is written at #13980743 by `str w1, [x19, x6]` with
`src_value=0x69f2e9fb`, so this is not a static read-only table byte-for-byte.
However the producing chain reaches #13980730 `ldr x8, [x1, x5]` from
`0x74b68bd108`, where the observed load bytes are `fbe9f26900000000` while the
latest traced write to that address is #13979551 `str x6, [x19, x20]` with
`src_value=0x0`. The CLI now marks this as
`observed_read_without_matching_traced_write` and stops the automatic chain
there. Current interpretation: the first middle word crosses a trace coverage
boundary or untraced memory producer; following the stale zero write is
incorrect.

`idxs-touching-addr --with-bytes` confirms the byte-level discontinuity for the
first byte:

```text
addr 0x74b68bd108, cursor #13980730
before: #13979551 w byte=0x00
after:  #13980730 r byte=0xfb
```

Without `--with-bytes`, the same command stays cheap and returns only idx/kind;
with the flag it blocks for MemShadow and exposes the observed byte values that
are needed to distinguish stale traced writes from true memory contents.

The discontinuity is now explained by the gap-call scan attached to
`vm-backstep`. For the same load:

```bash
rust/target/debug/tracemiku-cli vm-backstep \
  traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms \
  --idx 13980732 \
  --reg x8 \
  --context 160 \
  --lookback 300000 \
  --max-writes 8000
```

`upstream.gap_call_candidates.candidates[0]` is:

```text
#13980120 blr x22 -> libc.so+0xa0f5c
x0 = 0x753dcfeac0 -> "/"
x1 = 0x74b68bd0b0
target addr 0x74b68bd108 = x1 + 0x58
```

Resolve the candidate target with the CLI:

```bash
rust/target/debug/tracemiku-cli resolve-elf-symbol \
  /tmp/tracemiku-device-libs/libc.so \
  0xa0f5c
```

Read the pathname argument at the call boundary:

```bash
rust/target/debug/tracemiku-cli mem-dump \
  traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms \
  --addr 0x753dcfeac0 \
  --count 64 \
  --cursor 13980120 \
  --cstr
```

This returns `c_string="/"`. The terminator is not observed in the selected
MemShadow cursor window, so `c_string_terminated=false`; the known byte is still
enough to identify the pathname argument as root.

On the current device libc this returns `stat@@LIBC` exactly. So the first
middle word `fbe9f269` is most likely bytes from a `struct stat` output buffer
written inside libc, outside the current instruction-level trace coverage. The
Android AArch64 NDK layout confirms `offsetof(struct stat, st_mtim.tv_sec) ==
0x58` and `sizeof(struct stat) == 0x80`; the observed eight bytes
`fbe9f26900000000` are therefore little-endian `st_mtim.tv_sec =
0x69f2e9fb`, which is `2026-04-30T13:34:51+08:00` on the current local
timezone. The x-sign simulator should treat this word as the target file's
modification time for the `stat("/")` input unless a future trace/hook proves a different stat-like
structure.

The next candidate `#13980660 libc.so+0x5c4fc` resolves to `free`, and is a later
near-pointer false positive rather than the producer. This is a useful
reconstruction boundary: the simulator should model this word as data supplied
by the stat output structure, or collect the corresponding file metadata, not
as a value produced by the stale traced zero store.

As of the current CLI, `vm-backchain --summary` lifts these discontinuities into
`recognized_pattern_summary.memory_boundary_reads[]`. This is the generic
counterpart to `static_memory_loads[]`: it marks a memory load whose observed
bytes do not match the latest traced writer. For example the `[52,56)` source
chain now reports:

```text
kind       = memory_boundary_read
addr       = 0x756649a2d4
bytes      = 30 2e 31 30
load       = #14082315 ldr w19, [x14, x13]
last write = #14062790 str x0, [x19]
```

This lets an AI stop at the right boundary and ask for a wider trace, boundary
hook, or external metadata instead of following a stale pointer-shaped write.

Rust MemShadow now loads boundary-diff `external_writes.bin` records into the
v5 sidecar as `kind="x"` writes. A new capture with
`--boundary-diff-patterns stat@@,stat64@@,fstatat@@,fstatat64@@,lstat@@,lstat64@@`
should therefore let `byte-lineage` and `mem-writes-in-range` continue through
the stat output structure instead of stopping at this boundary. Direct
last-write probes should pass `--with-external` to include these external
events.

The first real boundary-diff x-sign capture is:

```text
traces/boundary_stat_launch2/calls/call_001_tid11945_8882256r_7389ms
records=8,882,256 truncated=false dropped=0
x-sign value_idx=8,881,466
external_writes.bin = 192 raw events before de-duplication
```

The capture used `uv run python tracemiku trace --launch ...` so the app was
restarted without `pm clear`. The agent attached before `libsgmainso` loaded,
installed six libc boundary-diff targets, and recorded `ext-write +192`.
`stat@@` matching now covers both exact Bionic names such as `stat` and
versioned names such as `stat@@LIBC`; duplicate aliases at the same address are
deduplicated in the agent, and MemShadow v5 also deduplicates identical
`(idx, addr, byte)` external events when reading older captures.

Concrete validation from that capture:

```bash
rust/target/debug/tracemiku-cli last-write-of-addr \
  traces/boundary_stat_launch2/calls/call_001_tid11945_8882256r_7389ms \
  --addr 0x75807e47c0 --before-idx 7570600 --with-external
```

returns `write_kind="x"`, `writer_idx=7570507`, and `src_value="0xfb"`.
`idxs-touching-addr --with-bytes` preserves the same event kind as `x`, so an
AI can distinguish boundary bytes from normal traced stores.

Dumping the containing buffer at the same cursor shows that this boundary is a
substring of a short ASCII value:

```bash
rust/target/debug/tracemiku-cli mem-dump \
  traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms \
  --addr 0x756649a2d0 \
  --count 32 \
  --cursor 14082315 \
  --cstr
```

Result:

```text
c_string = "10.60.10^^"
addr 0x756649a2d4 = substring offset 4 = "0.10"
```

So the `[52,56)` word-source path now has an external text boundary candidate,
not just an unexplained stale-write mismatch.

For the boundary-stat capture, `byte-lineage` from semantic offset `16` now
stops at the first observed memory boundary instead of following a pointer
frontier:

```bash
rust/target/debug/tracemiku-cli byte-lineage \
  traces/boundary_stat_launch2/calls/call_001_tid11945_8882256r_7389ms \
  --addr 0x74974cc16d \
  --before-idx 8319800 \
  --depth 80 \
  --lookback 5000000 \
  --summary
```

The chain reaches `observed_read_without_matching_traced_write` at step `41`:

```text
load addr          = 0x74974cc648
observed bytes     = fbe9f26900000000
latest traced write= #7571629 str x6, [x19, x20]  src_value=0x0
top gap candidate  = #7572198 libc.so+0xa0f5c, addr at x1+0x58 / x6+0x44
```

This classifies the `[16,20)` lhs word `0x69f2e9fb` as a boundary-fed value at
this point in the trace. It is consistent with the separately captured
`stat('/')` external write, but the portable simulator should still model it as
an external file-metadata input rather than as a VM-generated constant.

So the current trace-proven call_001 tail shape is:

```text
tail[0] = 0x0a                      # not yet explained by this summary
tail[i] = mod255_low_byte(input_i)   # 10 known mask/fold positions
tail[i] = lhs_i ^ parity_mask_i       # 56 known XOR positions
```

The remaining reconstruction problem is now narrower: trace the `lhs_i` stream
for the 56 XOR bytes back to its generating VM/hash state, instead of treating
the final x-sign tail as opaque bytes.

For `call_001`, the state word is now traced one layer further. The XOR
template uses `state_word_le = 0xd84ab467`, which is the little-endian view of
the bytes loaded from `0x67b44ad8`. That word is read at #14678409 from
`0x74b68bb6a8`; the last writer before the read is #14678167
`str w1, [x19, x6]` with `src_value = 0x267b44ad8`, whose low 32 bits are
`0x67b44ad8`. The producing ALU op is #14678154:

```text
low32(0x1b57feb14 + 0xb2345fc4) = 0x67b44ad8
bswap32(0x67b44ad8) = 0xd84ab467
```

`vm-ops --summary` now labels this as `add32_mix` even when the native `add x`
full result is wider than 32 bits and the following store truncates through
`str w*`. The same summary now pairs this formula with the following state
buffer store under `state_updates[]`.
For the output-first workflow, `output-map --summary` also exposes the same
link under `semantic_writer_map.xor_word_state_sources[]`, so one command from
the final `x-sign` string now reaches the upstream state update for
`tail[3:7]`.

Expanding the same VM window shows five adjacent low-32 state writes, matching
the SHA-1 state width rather than a four-word MD5-only finalize:

```text
0x74b68bb6a8 = 0x67b44ad8
0x74b68bb6ac = 0x783e786f
0x74b68bb6b0 = 0xcdfca104
0x74b68bb6b4 = 0x4c17da36
0x74b68bb6b8 = 0x6f613fe4
digest_be = 67b44ad8783e786fcdfca1044c17da366f613fe4
```

`crypto-scan` also sees `SHA1_H[4] = 0xc3d2e1f0` in the same constant family,
so the current working label for this component is SHA1-like state finalize.
Only the first word has been connected to `tail[3:7]` so far.

The mask bytes themselves are also cross-sample `mod255_low_byte` folds:

```text
tail[1], tail[2] = (input + input // 0xff) & 0xff
```

The simulator records the two fold inputs for each sample and verifies all
five pairs against the observed semantic tail.

Crypto cross-check:

```bash
rust/target/debug/tracemiku-cli crypto-scan \
  traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms
```

The same VM bytecode window contains MD5/SHA1 IV words:

```text
MD5_A/SHA1_H0 0x67452301 at 0x74fbf3ae98 first_idx=14590463
MD5_B/SHA1_H1 0xefcdab89 at 0x74fbf3aeb8 first_idx=14590471
SHA1_H2/MD5_C 0x98badcfe at 0x74fbf3aef8 first_idx=14590500
MD5_D/SHA1_H3 0x10325476 at 0x74fbf3af18 first_idx=14590508
```

The records around `14590463..14590522` show the VM loading these constants
from bytecode and packing them into VM slots, e.g. `0xefcdab8967452301` and
`0x1032547698badcfe`. This supports an MD5-like state component in the output
tail generation. It is not yet a full proof that the final x-sign contains a
standard MD5 digest, because the 16-byte `hash-finalize-detect` candidates still
need to be connected byte-for-byte to the semantic tail.

The first local `hash-finalize-detect --guess md5` candidates at
`0x74b68bc770`, `0x74b68bc780`, and `0x74b68bca08` are not useful digest
outputs: `byte-writer-map --size 16` shows they are all zero writes in the
queried windows. Treat them as false positives or cleanup/state buffers until a
non-zero candidate is linked back to tail bytes.

A combined candidate-map run confirms this at the `hash-finalize-detect` level:

```bash
rust/target/debug/tracemiku-cli hash-finalize-detect \
  traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms \
  --limit 50 \
  --window 500 \
  --min-size 16 \
  --map-bytes \
  --map-candidates 10 \
  --target-bytes 0a626105d528b91a5f1a0eaf606261629a8b930b188e93f7209460f1d2295d336dae63ff825bafa0f452f1411dddc5965ac22528554125a7faa708626158de6160626162
```

Result: 10 candidates inspected, 7 all-zero, 3 non-zero, 0 candidates whose
bytes occur inside the 68-byte semantic tail. Therefore the current best
result-to-input anchor remains the final semantic tail byte-writer map at
`0x74b68bcc1d`, not the early hash-finalize candidates.

The final-output-to-semantic-tail step is now reproducible with one command:

```bash
rust/target/debug/tracemiku-cli output-map \
  traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms \
  --key x-sign \
  --base64-tail-start 12 \
  --base64-tail-align-prefix AA \
  --base64-tail-drop 1 \
  --semantic-writer-map \
  --semantic-writer-map-vm-chain-steps 4 \
  --semantic-writer-map-vm-chain-runs 3 \
  --semantic-writer-map-vm-chain-follow-frontier \
  --summary
```

It automatically chooses `idx_hi=14747885` from the first final-output writer,
maps the semantic tail at `0x74b68bcc1d`, returns the same complete 68-byte
sequence, reports 32 writer runs, and recognizes two `mod255_low_byte` chains in
the first three expanded runs.

The same automatic writer-map path works across all five current
`traces/diff` x-sign samples:

```text
_truncated_call_006  complete=true size=68 writer_runs=32 idx_hi=7083756  writes=189
call_001            complete=true size=68 writer_runs=32 idx_hi=14747885 writes=228
call_003            complete=true size=68 writer_runs=32 idx_hi=7007945  writes=179
call_004            complete=true size=68 writer_runs=32 idx_hi=6988275  writes=179
call_005            complete=true size=68 writer_runs=32 idx_hi=7029973  writes=179
```

This makes the output-to-input anchor stable enough for differential algorithm
reconstruction: every current sample can be reduced to the same 68-byte semantic
tail shape and the same 32 writer-run chunking without manual trace indexes.

Across the six current samples, the aligned semantic tail has length 68. Tail
offset `0` is always `0x0a`; all other offsets vary in the current sample set.
The CLI reports one repeat/copy-candidate structural invariant under
`base64_tail_diff.repeated_ranges_all_samples[]`:

```text
tail[65:68] == tail[13:16]
```

Examples: `626162 -> 626162` in `call_001`, `95c595 -> 95c595` in
`call_005`, and `47ae47 -> 47ae47` in the JNI-only sample.

Do not treat this as a proven direct memcpy yet. A backward trace of
`call_001` shows `tail[65:68]` is written as Base64 chars `YmFi` at output
offsets `98..102`, then traced through VM scratch bytes at
`0x74b68bcc5e..0x74b68bcc60`. Those three bytes rejoin the already-known
generators:

```text
tail[65] 0x62 <- eor x16, 0, 0x62 <- mod255_low_byte(0x74ffafca73)
tail[66] 0x61 <- eor x16, 0, 0x61 <- mod255_low_byte(0x74beabe59c)
tail[67] 0x62 <- eor x16, 0, 0x62 <- mod255_low_byte(0x74ffafca73)
```

So the current evidence is stronger than string equality but weaker than a
source-level copy proof: the tail repeat is re-encoded from the same upstream
byte producers.

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
the `mod255_low_byte` folds for the `0x62` and `0x61` scratch bytes, the small
`0xc87 * 3 + 0x13 = 0x25a8` affine fragment, and the first variable Base64
group `piYQ`. It also records the corrected interpretation of
`tail[65:68] == tail[13:16]`: a repeated range re-encoded through VM scratch,
not yet a direct output copy. It deliberately reports `complete_algorithm =
false` until the full 76-byte payload construction is recovered.

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
multiplier `3`, and identity additions such as `0xc87 = 0xc87 + 0` continue on
the non-zero source instead of falling into zero-valued side branches. The next
layer reaches VM bytecode/frontier values such as `0x7` and the `x21` bytecode
pointer; this branch is still not recovered far enough to label it as a real
input or fixed constant.

The Base64 index summaries now also label the bit operations directly. For the
first variable group, the compact `output-map --summary` view reports:

```text
p: 0x29 = (0x28 & 0x3c) | (0x62 >> 0x6)
i: 0x22 = 0x62 & 0x3f
Y: 0x18 = 0x61 >> 0x2
Q: 0x10 = 0x610 & 0x30
```

Running the same compact view over semantic offsets `0..68` now returns 68
`payload_formula_table` rows and no missing semantic offsets. That proves the
late Base64 index layer for the whole aligned 68-byte semantic tail. The
remaining unknown is the upstream construction of the semantic byte equation
inputs themselves, especially the XOR lhs stream, the byte-lane source words,
and the mod255/LCG inputs.

## Next target

The remaining unknown is the 76-byte binary payload before Base64, not the
Base64 table lookup layer. The immediate next target is to trace the semantic
tail byte sources, especially the 57-byte XOR lhs stream and the 10 known
`mod255_low_byte` folds, until each reaches either a JNI input byte, a hash
digest/finalizer output, a fixed table, or a bytecode immediate. Once that
mapping is isolated, the Python simulator should implement:

1. build the 76-byte payload,
2. standard Base64 encode it,
3. URL-encode `+` and `/` as observed by JNI output when needed.
