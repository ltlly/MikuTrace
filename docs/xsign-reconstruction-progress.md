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

Cross-sample extraction over the diff-run calls now shows that the large middle
stream is fixed in those samples, not ASLR-shaped pointer entropy:

```text
range [16,59), size 43
call_006/call_001/call_003/call_004/call_005:
  fbe9f26979ecf29541f60193b34b3c510ccc029de339cec2953090237cbfa4f43ba0444a342344c59bc569
```

This changes the next search priority. The `[16,59)` `lhs` stream is more
likely a fixed table/salt/VM literal stream than a heap pointer stream that
must be reproduced from ASLR. The
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
scratch[0:4]        = word32_le(stat("/").st_mtim.tv_sec << 24)
scratch[4:8]        = word32_le((stat_mtim >> 8) | (low8(prev_ladder_slot24) << 24))
scratch[8:48]       = replay suffix words from the scratch-writer VM window
scratch[48:52]      = getpid/table/literal tail word
middle_lhs[0:43]    = scratch[3:46]
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

The same window now emits per-effect `python_with_values` checks, for example:

```text
slot[25] = add(slot[25], 0x10)
slot[4]  = lsl(slot[3], 0x18)
slot[2]  = orr(slot[4], slot[2])
```

The Python partial simulator now validates these opcode semantics against trace
samples:

```text
add/and/lsr/lsl/orr/ubfx samples: all match
store little-endian word sample: e9f26979 == e9f26979
```

It also reconstructs the first scratch-lhs prefix from executable sources:

```text
scratch[0:4] = u32(stat_mtim << 24)                         = 000000fb
scratch[4:8] = u32((stat_mtim >> 8) | (static_byte << 24))   = e9f26979
semantic lhs starts at scratch+3                             = fbe9f26979
```

The `static_byte` in that formula is no longer an independent byte input. The
scratch-writer replay plan shows `slot[5] = 0x95f2ec79` at `#14164330`, then
`slot[3] = lsl(slot[5], 0x18)` at `#14164374`, producing the `0x79000000`
component. That source word is the previous ladder window's final `slot24`, so
the byte is `low8(0x95f2ec79)`. The remaining portability work is therefore the
ladder lift, not a separate unknown static byte.

`call001_lhs_run_bytes()` no longer consumes one opaque
`middle_lhs_mixed_suffix_hex`. It builds the scratch writer dump from
`stat_mtim_tv_sec`, `previous_ladder_slot24`, ten replay suffix words, `getpid`,
and the bytecode-literal tail bytes, then slices `scratch[3:46]`. This still
preserves the existing call_001 tail reconstruction match, but keeps the
remaining trace-derived words visible as replay parameters.
`scratch_writer_replay_model.write_rows` now records all 16 memory writes that
construct the 52-byte scratch dump, including each trace idx, scratch offset,
store width, little-endian bytes, `python_with_values`, and source class. The
first suffix word is now explicitly tied to
`#14164461 mem[0x74b68bbe08] = 0x4195f2ec`; the final four tail bytes are tied
to `getpid`, the getpid-derived LCG byte, and two bytecode literals.

The simulator also emits a machine-readable `middle_lhs_source_manifest` for
semantic range `[16,59)`:

```text
[16,21) formula_validated_stat_mtim_ladder_low_byte  fbe9f26979
[21,25) vm_xor_ladder_from_static_table_seed_pending_lift ecf29541
[25,49) traced_formula_only                     f60193b34b3c510ccc029de339cec2953090237cbfa4f43b
[49,57) confirmed_app_version_text_boundary     a0444a342344c59b
[57,59) traced_formula_only                     c569
```

This covers 43/43 middle lhs bytes and keeps the remaining work segment-scoped
instead of one opaque hex blob.

A targeted lineage probe refined the old `[21,25)` static/no-writer label:

```text
tracemiku-cli byte-lineage <call_dir> --addr 0x74b68bbe08 \
  --before-idx 14164462 --depth 80 --lookback 5000000 --summary

#14164461 str w16, [x2, x5] writes ecf29541 / 0x4195f2ec
0x4195f2ec = 0x41000000 | 0x95f2ec
0x95f2ec   = ubfx(0x95f2ec, 0x0, 0x20)
0x95f2ec   = 0x95f2ec79 >> 0x8
#14019868 str w1, [x19, x6] writes 79ecf295 at 0x74b68bcc24
```

A deeper probe from `#14019868` no longer hits an external boundary. It walks
120 lineage steps through repeated VM slot copies and formulas:

```text
formula_kind_counts: xor_mix=23, shift_left=11, bitmask_extract=10, or_identity=1
0x95f2ec79 = 0x90d2d669 ^ 0x5203a10
static table loads include:
  0x74fbf29208 -> 0x90bf1d91
  0x74fbf29238 -> 0x6ddde4eb
  0x74fbf29888 -> 0x166ccf45
  ...
  0x74fbf297c8 -> 0x05005713
```

So this segment is trace-produced by a VM XOR/shift/mask ladder over static
table seeds, not a confirmed external input. The next open question is lifting
that ladder into portable Python opcode replay or a compact formula.

`vm-ops --compact` makes this ladder directly AI-readable, and
`vm-ops --replay-plan` preserves dynamic order for direct Python translation:

```text
tracemiku-cli vm-ops <call_dir> --start 14015880 --end 14017110 \
  --compact --max-ops 400

source_returned=1230, effect_count=127, compact_template_count=15
slot[bc_0x3_u8] = byte_load(addr_expr)
slot[bc_0x2_u8] = and(slot[bc_0x4_u8], bc_0x8_u64, bc_0x10_u16)
slot[bc_0x3_u8] = lsr(slot[bc_0x3_u8], slot[bc_0x7_u8], bc_0x8_u64, bc_0x10_u16)
slot[bc_0x5_u8] = eor(slot[bc_0x4_u8], slot[bc_0x5_u8], slot[bc_0x6_u8], bc_0x10_u16)

tracemiku-cli vm-ops <call_dir> --start 14015880 --end 14017110 \
  --replay-plan --max-ops 400

replay_step_count=113
slot[29] = and(slot[26], 0xff)
slot[28] = eor(slot[29], slot[28])
slot[28] = lsl(slot[28], 0x3)
```

This is a generic CLI improvement: it is not tied to `libsgmainso`, but it turns
large VM windows into a short replay-template list an agent can consume.
`tools/vm_replay_plan_eval.py --emit-python` can now turn the same replay-plan
JSON into an editable Python replay skeleton. That skeleton keeps trace-index
comments and generic `slots`/`mem` operations, but it remains a trace replay
until every literal/byte-load input is replaced by a proven table, app metadata,
or device/environment parameter.
The emitted skeleton now carries `USER_SEED_SLOTS`, `SUGGESTED_SEED_SLOTS`, and
`OBSERVED_BYTE_LOADS`; it now also carries minimized `EFFECTIVE_SEED_SLOTS` and
`REDUNDANT_SEED_SLOTS`. The generated `replay()` uses effective seeds by default,
so the scratch-writer skeleton replays the same 52-byte scratch dump as the
trace without manual seed plumbing. `OBSERVED_BYTE_LOADS` now uses hex address
keys, keeping those unproven inputs easy to line up with `byte-lineage` probes.
This makes the replay directly executable while keeping unproven inputs visible.
`--verify-emitted-python` now generates that same skeleton, executes it
in-memory, and compares its `slots` and `mem` against the internal no-trust
evaluator. On the scratch-writer window it reports `status=ok`,
`slots_match=true`, `mem_match=true`, `generated_line_count=357`; on the ladder
window it reports the same match with `generated_line_count=446`.
`tools/vm_replay_plan_eval.py --auto-seed-suggestions` also distinguishes
mechanical seed gaps from missing logic. On the scratch-writer window it applies
six formula-derived seed suggestions and replays with `trusted_effects=0`,
`unresolved_read_count=0`, and the 52-byte scratch dump still matching the
trace. On the `[21,25)` ladder window it applies five suggestions and replays
to final `slot24=0x95f2ec79` with no observed fallbacks. The evaluator now also
minimizes the auto-seeded input set: the scratch-writer window keeps all six
suggestions, while the ladder window drops redundant `slot29` and needs only
`slot24`, `slot25`, `slot26`, and `slot28` in addition to user seed `slot0`.
These suggestions are still evidence to prove, not portable inputs by
themselves. With `--seed-lineage-call-dir`, the nested
`auto_seeded_replay.effective_seed_lineage_commands[]` field now emits proof
commands only for those non-redundant suggested seeds.
`vm-ops --replay-plan` now includes `vm_state_base`, so the same tool emits
direct `seed_lineage_commands[]` without a manually supplied slot base; for
example slot26 maps to `0x7744599570`, matching the earlier manual
`byte-lineage` probe. This keeps the next proof step machine-readable for AI
agents.
Running those deeper seed probes on the scratch-writer window moves slot25 from
an opaque pointer into a visible pointer expression:
`0x74b68bcc1c = 0x74b68bb9a0 + 0x127c`, where the `0x127c` delta comes from a
VM bytecode read. `byte-lineage --compact` now keeps formula operands with
roles such as `pointer_base` and `delta`, so this evidence survives the compact
AI-facing view. Slot26 still reaches VM bytecode after a chain of small integer
states. Slot25 and slot28 both pass through long `0x74b68bb9a0` /
`0x74b68bd4c0` base-pointer copy chains; the short probes stop at depth limits,
but the repeated-value summaries make the copy loops explicit enough to expand
the lookback and keep chasing. The compact slot28 probe reports
`repeated_values`: `0x74b68bb9a0` appears 69 times in an 80-step lineage, while
`0x74b68bbdff` appears 7 times. That turns the prior `depth_limit` into an
explicit copy-loop/stable-base signal for the next proof.
Chasing the earlier slot20 writer shows the same base as pointer arithmetic:
`0x74b68bb9a0 = 0x74b68bd4c0 + 0xffffffffffffe4e0`, i.e.
`0x74b68bd4c0 - 0x1b20`. The signed delta is VM-bytecode-backed, while
`0x74b68bd4c0` remains the next pointer-base boundary. Chasing that boundary
now crosses another generic in-place ALU layer instead of cycling on the same
instruction:

```text
0x74b68bd4c0 = 0x74b68bd6d0 - 0x210
0x74b68bd6d0 = align16(0x74b68bd750 - 0x71)
```

The first line is a signed pointer delta carried by compact formula operands.
The second line comes from `sub_small_delta` followed by `align_down_mask` on
`and x8, x8, #0xfffffffffffffff0`. `byte-lineage --compact` now moves the next
seed to the trace index before a self-defining in-place ALU write, so the chain
continues past `and/sub reg, reg, #imm` instead of reporting a false cycle.
The wider probe currently stops at `depth_limit` on further copied pointer
values such as `0x74b68bd7d0`, `0x74b68bda80`, and `0x74b68bdb40`; these remain
base-pointer provenance to prove, not portable semantics. To make that usable
for AI agents, `byte-lineage --compact` now also emits `pointer_transitions[]`.
A 205-step slot28/base probe compresses the pointer migration into:

```text
0x74b68bd4c0 = 0x74b68bd6d0 - 0x210
0x74b68bd6d0 = align16(0x74b68bd6df)
0x74b68bd6df = 0x74b68bd750 - 0x71
0x74b68bd750 = 0x74b68bd7d0 - 0x80
0x74b68bd7d0 = 0x74b68bd920 - 0x150
0x74b68bd920 = 0x74b68bd9d0 - 0xb0
0x74b68bd9d0 = 0x74b68bda80 - 0xb0
0x74b68bda80 = 0x74b68bdb40 - 0xc0
0x74b68bdb40 = 0x74b68bde20 - 0x2e0
```

The same compact view reported `0x74b68bde20` as the next dominant repeated
base (`count=28` in 205 steps, `count=143` in 320 steps). Chasing the first
slot30 write of that value moves it out of the VM copy loop and into an
allocator boundary:

```text
#34902 str x11, [x25, #0xf0] writes 0x74b68bde20
0x74b68bed40 = 0x74b68bedc0 - 0x80
0x74b68bedc0 = 0x74b687edc0 + 0x40000
#7364 bl #0x7601bcbd60 returns x0 = 0x74b687edc0
call target resolves through libc.so+0x5c718 = malloc@@LIBC
call arg x0 = 0x40000
```

This turns the slot28 deep base into heap scratch provenance rather than a
missing portable arithmetic input. The portable model should parameterize it as
`malloc(0x40000)`-derived state, or prove that later operations cancel the ASLR
address, instead of trying to reproduce the concrete pointer value.
The slot25 seed reaches the same boundary when rerun with a deeper search:
`byte-lineage --addr 0x7744599568 --before-idx 14164280 --depth 1000
--lookback 15000000 --compact` returns `call_return_boundary` after 953 steps,
with the same call `#7364 bl #0x7601bcbd60`, `x0=0x40000`, and return value
`0x74b687edc0`.

The `[49,57)` segment is now confirmed as an external text boundary rather than
an unresolved VM source:

```text
scratch[36:40] -> 0x756649a2d0 observed 31302e36 "10.6"
scratch[40:44] -> 0x756649a2d4 observed 302e3130 "0.10"
combined text                         "10.60.10"
lineage stop                          observed_read_without_matching_traced_write
```

The latest traced write to `0x756649a2d0` does not match the observed bytes, so
the portable replay should treat this as an explicit external text parameter.
On the current device, `adb shell dumpsys package com.taobao.taobao` reports
`versionName=10.60.10`, and `docs/frida-codeslab-patch.md` records the same
test target version. This boundary is therefore best modelled as Android
package/app version text, not opaque VM state.

The remaining formula-only scratch writer range also has a compact replay view:

```text
tracemiku-cli vm-ops <call_dir> --start 14164280 --end 14165320 \
  --replay-plan --max-ops 400

source_returned=1040, effect_count=110, compact_template_count=24
replay_step_count=80
mem[addr] = slot[bc_0x5_u8]
slot[bc_0x2_u8] = add(slot[bc_0x6_u8], bc_0x8_u64, bc_0x10_u16)
slot[bc_0x3_u8] = orr(slot[bc_0x3_u8], slot[bc_0x4_u8], slot[bc_0x5_u8], bc_0x10_u16)
combined bitfield ladder over slot[bc_0x2_u8]
first replay steps:
  slot[25] = add(slot[25], 0x10)
  slot[3] = 0x69f2e9fb
  slot[2] = and(slot[2], 0x9)
  slot[2] = lsr(slot[2], 0x8)
  slot[4] = lsl(slot[3], 0x18)
```

This shifts `[25,49)` and `[57,59)` from one opaque trace-byte dependency to
explicit replay words. The remaining work is proving those replay words from
portable static-table, bytecode, app metadata, or device/environment inputs.

`tools/vm_replay_plan_eval.py` now executes replay-plan JSON directly. On the
scratch writer window it reconstructs the full scratch table dump:

```text
tracemiku-cli vm-ops <call_dir> --start 14164280 --end 14165320 \
  --replay-plan --max-ops 400 |
uv run python tools/vm_replay_plan_eval.py --seed-slot 0=0 \
  --dump-mem 0x74b68bbe00:52

computed_effects=100, trusted_effects=5, unresolved_read_count=6
scratch[0:52] complete=true
000000fbe9f26979ecf29541f60193b34b3c510ccc029de339cec2953090237cbfa4f43ba0444a342344c59bc56900003abf0301
```

The evaluator also handles the `[21,25)` ladder window and reaches
`slot[24] = 0x95f2ec79`, but it still needs observed-value fallbacks for missing
initial slot/table values. With `--seed-slot 0=0`, the scratch writer is down to
six unresolved slot reads, and the ladder is down to five unresolved reads. That
keeps this as trace-bound replay rather than a portable x-sign algorithm.

Those remaining reads can be eliminated by explicitly seeding the initial VM
slots inferred from the trace:

```text
scratch writer seeds:
slot0=0, slot2=1, slot25=0x74b68bcc1c, slot26=0x38,
slot27=0x20, slot28=0x74b68bbe00, slot29=0x37
=> trusted_effects=0, unresolved_read_count=0, scratch dump still matches

[21,25) ladder seeds:
slot0=0, slot24=0x7599191126, slot25=0xb,
slot26=0x1f7b3460, slot28=0x6f
=> trusted_effects=0, unresolved_read_count=0, final slot24=0x95f2ec79

auto-seed minimization:
scratch writer effective_seed_slots = slot0,slot2,slot25,slot26,slot27,slot28,slot29
ladder effective_seed_slots = slot0,slot24,slot25,slot26,slot28
ladder redundant_seed_slots = slot29
```

The replay engine can now compute these windows without observed-value
fallbacks. The remaining algorithm work is provenance for these seed values and
multi-sample validation.

Running the filtered effective seed lineage queue gives the current ladder
frontier:

```text
slot24 -> call_return_boundary: malloc(0x12) returned 0x7599191120,
          then six +1 increments produce 0x7599191126
slot25 -> no_local_def / VM bytecode-IP frontier:
          0xb = 0xffffffffffffffff + 0xc
slot26 -> static/preinitialized table boundary:
          0x1f7b3460 = 0x1fda836e ^ 0x0a1b70e,
          table bytes at 0x74fbf29828 = 6e83da1f00000000
slot28 -> static/preinitialized byte boundary:
          0x6f = 0xdb ^ 0xb4,
          observed byte at 0x750cdbef89 = db
```

So the next proof is not "find more replay ops"; the replay ops already close.
The remaining problem is classifying those table/bytecode/preinitialized inputs
as portable parameters or deriving them from earlier traced setup.

The scratch-writer replay skeleton still has five `OBSERVED_BYTE_LOADS` for the
tail word source bytes at `0x74b68bcc4d..0x74b68bcc51`. Focused
`byte-lineage --compact` probes map their current frontier:

```text
0x74b68bcc4d @ #14165182 -> 0x3a, syscall_return_boundary:
          low8(getpid()), from svc #0 with x8=0xac and return x0=0x7b3a
0x74b68bcc4e @ #14165193 -> 0xbf, syscall_return_boundary through shared getpid():
          low8(((getpid() * 0xdd08cee9) + 0x61f5) & 0x7fffffff)
0x74b68bcc4f @ #14165204 -> 0x03, bytecode_read_boundary:
          VM bytecode/immediate literal 0x03
0x74b68bcc50 @ #14165236 -> 0x01, bytecode_read_boundary:
          low byte of VM bytecode/immediate literal 0x01
0x74b68bcc51 @ #14165318 -> 0x00, bytecode_read_boundary:
          high byte lane of VM bytecode/immediate literal 0x01
```

These are no longer anonymous byte defaults. Fixing lane-aware `and` lineage was
required first: before the fix, `byte-lineage` followed the `0x7fffffff` mask
operand instead of the data operand. The later `ldur`/negative-offset,
self-def, `svc` return-boundary, and `bytecode-read` boundary fixes reduce the
five-byte source window to an explicit `getpid()` parameter plus VM bytecode
literal bytes, instead of live handler state.

The evaluator now includes `seed_suggestions` on trusted fallback records. For
example, it can infer `slot25=0x74b68bcc1c` from
`slot[25] = 0x74b68bcc2c = 0x74b68bcc1c + 0x10`, and `slot26=0x1f7b3460` from
`slot[29] = 0x60 = 0x1f7b3460 & 0xff`.

Follow-up seed lineage probes show the current boundary more precisely:

```text
scratch slot2 before #14164280:
  slot2 = 0x1
  writer #14164225: str x16, [x25, x1]
  26 compact steps end at no_local_def on VM bytecode IP 0x74fbf560f0

scratch slot26 before #14164280:
  slot26 = 0x38
  writer #14164105: stp x9, x10, [x25, #0xd0]
  chain includes 0x38 = 0x2f + 0x9 plus OR/shift identities
  160-step compact chain:
    0x38 -> 0x2f -> 0x2e -> 0x24 -> 0xc -> 0x8 -> 0x4
    repeated values: 0x4 x23, 0x38 x11, 0x24/0x2e/0x2f/0x8/0xc x8
    byte load #13952492 reads 0x4 from 0x74b68bd0b8
    final boundary is bytecode-read #13951579: ldr w19, [x21,#8]
    final x21 VM bytecode/IP base: 0x74fbf63700
    shifted IP updates now render as:
      0x74fbf636e0 = 0x74fbf635f0 + (0xf << 0x4)
      operand x3 effective_value = 0xf0

scratch slot27 before #14164280:
  slot27 = 0x20
  writer #14164276: str x8, [x25, x11, lsl #3]
  local formula: 0x20 = 0xfffffffffffffff0 & 0x24

scratch slot28 before #14164280:
  slot28 = 0x74b68bbe00
  writer #14164235: str x5, [x25, x6, lsl #3]
  pointer chain: 0x74b68bb9a0 + 0x200 + 0x25f + 1, then depth_limit
  repeated_values: 0x74b68bb9a0 appears 69 times in an 80-step compact probe
  earlier base expression:
    0x74b68bb9a0 = 0x74b68bd4c0 + 0xffffffffffffe4e0
    operand roles: x8 pointer_base, x7 signed delta (-0x1b20)
  next base expression:
    0x74b68bd4c0 = 0x74b68bd6d0 + 0xfffffffffffffdf0
    0x74b68bd6d0 = align16(0x74b68bd750 - 0x71)
    semantics: sub_small_delta + align_down_mask
  pointer_transitions summary continues:
    0x74b68bd750 = 0x74b68bd7d0 - 0x80
    0x74b68bd7d0 = 0x74b68bd920 - 0x150
    0x74b68bd920 = 0x74b68bd9d0 - 0xb0
    0x74b68bd9d0 = 0x74b68bda80 - 0xb0
    0x74b68bda80 = 0x74b68bdb40 - 0xc0
    0x74b68bdb40 = 0x74b68bde20 - 0x2e0
    0x74b68bedc0 = malloc(0x40000) + 0x40000
  allocation boundary:
    #7364 bl #0x7601bcbd60 -> x0=0x74b687edc0
    target: libc.so+0x5c718 = malloc@@LIBC
    args: x0=0x40000

scratch slot29 before #14164280:
  command: byte-lineage --addr 0x7744599588 --before-idx 14164280 --compact
  slot29 = 0x37
  writer #14164256: str x5, [x25, x6, lsl #3]
  local formula: 0x37 = 0x38 + 0xffffffffffffffff
  upstream: 0xffffffffffffffff is a VM bytecode literal read at #14164253

scratch slot25 before #14164280:
  command: byte-lineage --addr 0x7744599568 --before-idx 14164280 --compact
  slot25 = 0x74b68bcc1c
  writer #14164103: stp x9, x10, [x25, #0xc0]
  pointer expression: 0x74b68bcc1c = 0x74b68bb9a0 + 0x127c
  compact formula operands:
    x13 = 0x74b68bb9a0 role pointer_base
    x14 = 0x127c       role delta
  delta source: VM bytecode read around #14159863..#14159865
  deep command:
    byte-lineage --addr 0x7744599568 --before-idx 14164280 \
      --depth 1000 --lookback 15000000 --compact
  terminal: call_return_boundary at #7364 malloc(0x40000)
  boundary: same heap scratch allocation chain as slot28

[21,25) ladder slot8 around #14017046:
  no longer an initial seed after fixed-offset pair slot handling
  writer #14017046: stp x9, x10, [x25, #0x40]
  slot8 = 0x90d2d669 is computed inside the replay window

[21,25) ladder slot24 before #14015880:
  slot24 is six +1 increments from 0x7599191120
  lineage ends at call_return_boundary #14009734: blr x22
  target x22=0x787beb9718, return x0=0x7599191120
  resolve-trace-addr => libc.so+0x5c718
  resolve-elf-symbol on device libc.so => malloc@@LIBC
  args: x0=0x12, x1=0, x2=8, x3=0x753dc62680,
        x4=0, x5=0x18, x6=0x74b68bd0c4, x7=0x2c

[21,25) ladder slot25/28 before #14015880:
  slot25 = 0xb = 0xffffffffffffffff + 0xc
  slot28 = 0x6f = 0xdb ^ 0xb4
  both end at VM bytecode IP no_local_def frontiers

[21,25) ladder slot26 before #14015880:
  slot26 = 0x1f7b3460
  compact lineage: 0x1f7b3460 = 0x1fda836e ^ 0x0a1b70e
  lhs 0x1fda836e loads from static/preinitialized table
      base 0x74fbf29190 + offset 0x698 = 0x74fbf29828
  rhs 0x0a1b70e is slot26 previous value shifted right by 8
  follow-frontier chain exposes more static table seeds:
    base+0x508 -> 0xa1d1937e
    base+0x6d0 -> 0x66063bca
    base+0x600 -> 0x9b64c2b0
```

So the seed problem is no longer one undifferentiated fallback bucket. The
pair-store fixes removed a false `slot8` seed and false observed-read
boundaries, scratch pointer provenance for `slot25/28` now reaches
malloc-backed heap boundaries, and scratch `slot26` reaches a VM bytecode/IP
boundary with scaled-delta formulas preserved. The remaining hard parts are
ladder chains (`slot24/26`) and deciding whether heap-derived pointer terms
cancel out or must be explicit simulator parameters.

The `slot24` and `slot26` chains now have concrete boundary identities.
`slot24` is derived from
`malloc(0x12)` in Android `libc.so`, not an unknown libsgmainso helper.

```bash
tracemiku-cli resolve-trace-addr <call_dir> 0x787beb9718
# libc.so+0x5c718

tracemiku-cli resolve-elf-symbol /tmp/tracemiku-device-libs/libc.so 0x5c718
# malloc@@LIBC
```

`byte-lineage` also now includes `sp/fp/lr` in its default register set and
stops at missing memory writers before auto-following address-base frontiers.
The function-pointer source path for the call is therefore AI-readable without
manual register overrides:

```text
0x7522b48b98 stack slot
  <- #14009410 str x8, [sp,#0x68]
  <- #14009405 ldr x8, [sp,#0x10]
  <- #14009402 ldr x8, [x8]
terminal: memory_not_found_boundary at 0x74fbf7e650
observed bytes: 50 96 e9 fb 74 00 00 00
```

This turns `slot24` into an allocator-pointer boundary. A portable Python model
must either parameterize allocator-derived pointer values or prove that later
VM operations cancel them out across samples; it should not treat
`0x7599191120` as a stable constant.

`slot26` is now classified as a static-table XOR/shift ladder rather than an
unexplained depth limit:

```text
slot26 = 0x1f7b3460
       = 0x1fda836e ^ 0x0a1b70e

0x1fda836e <- ldr x5, [0x74fbf29190 + 0x698]
             table addr 0x74fbf29828, no traced writer
0x0a1b70e  <- 0x0a1b70eb2 >> 8, from previous slot26 chain
```

So the next portable work is table extraction/labelling and cross-sample
validation for these static-table words, not just increasing lineage depth.
`mem-dump --summary` now exposes aligned, fully known little-endian words in
`words_le64[]`, which makes this table boundary directly machine-readable:

```bash
rust/target/debug/tracemiku-cli mem-dump \
  traces/diff/run1/calls/call_001_tid32013_15323697r_10163ms \
  --addr 0x74fbf29190 \
  --count 2048 \
  --summary
```

Relevant words from the current trace:

```text
base+0x508 = 0xa1d1937e  bytes 7e93d1a100000000
base+0x600 = 0x9b64c2b0  bytes b0c2649b00000000
base+0x698 = 0x1fda836e  bytes 6e83da1f00000000
base+0x6d0 = 0x66063bca  bytes ca3b066600000000
```

The partial simulator now also emits `current_trace_model_input_manifest`.
For `call_001`, the manifest has ten entries:

```text
raw_prefix                           fixed_literal, portable for current samples
stat_mtim_tv_sec                     external_parameter, stat('/').st_mtim.tv_sec
app_versionName                      external_parameter, Android versionName
previous_ladder_slot24               vm_ladder_state_word, not portable yet
scratch_writer_replay_suffix_words   vm_replay_word_parameters, call_001 scoped
middle_lhs_source_segments           segmented_trace_sources, complete for call_001
mod255_input_even                    vm_state_expression, trace-proven one sample
mod255_input_odd                     vm_state_expression, trace-proven one sample
process_id                           syscall_parameter, getpid
scratch_tail_small_bytes             bytecode_literal
```

This is the checklist for turning the current trace replay model into a
portable algorithm: eliminate or parameterize every non-portable manifest entry.

`fixed_prefix_model` now confirms that every current sample uses the same
12-character raw prefix `azYBCM007xAA`. Trace evidence still shows zero direct
hits for the decoded prefix bytes. The simulator now treats the raw prefix as a
fixed literal that is portable for current samples, while keeping deeper
semantics open as non-blocking documentation debt.

`current_trace_model_simulation` now makes the current boundary explicit:

```text
status                  trace_bound_simulation
matches_trace           true
portable_algorithm_ready false
```

So Python can reproduce `call_001` from the trace-derived formulas and manifest,
but this is still not the final portable x-sign algorithm.

`parameterized_simulation_contract` now records the replay boundary. Given five
input groups, the Python model can reproduce `call_001`:

```text
raw_prefix
semantic_byte0_source_value
mod255_even_input
mod255_odd_input
xor_lhs_runs
```

The contract is not a recovered algorithm because `xor_lhs_runs` still contains
opaque/non-portable middle-lhs segments.
Those opaque inputs now include next CLI probes in the JSON output:

```text
[21,25) vm_xor_ladder_static_seed -> vm-ops --replay-plan implementation
[25,49), [57,59) traced_formula_only -> vm-ops --replay-plan implementation
[49,57) app_versionName boundary -> explicit replay parameter
```

The script now emits `completion_audit` with four success criteria:

```text
cli_surfaces                 substantially_available
trace_bound_python_sim       done_for_call001_trace_model
portable_python_algorithm    not_done
multi_sample_generalization  weakly_covered
```

The audit intentionally keeps `goal_complete=false` until the portable algorithm
and multi-sample formula coverage are real, not inferred from trace replay.

The VM CLI work itself is now considered a usable generic surface rather than a
target-specific x-sign shortcut. It handles register-file VM windows, dynamic
opcode/handler grouping, compact effect summaries, replay-plan generation,
seed-suggestion triage, and seed-lineage command emission. The remaining
problem is algorithm recovery: proving or parameterizing the live VM seeds,
static/table boundaries, app metadata, and time/device inputs so the Python
model no longer depends on observed trace bytes.

`multi_sample_formula_coverage` now makes the cross-sample boundary explicit:

```text
available samples  7
covered samples    5
strong offsets     0..19,59,60,61,63,65,66,67
partial offsets    20..58,62,64
strong+partial     68/68
all_match          true
```

This proves the current mod255 pair, the first two xor-word formulas, and the
semantic offset `11` state-high byte across the diff samples; it also proves the
repeated odd/even mod255 mask positions across all available samples. The second
xor-word formula for semantic offsets `7..10` is now source-proven for all five
diff samples through the same `add32_mix -> lsr -> xor_word` shape.
`diff_run1_call_005` still has a degenerate output lane at offset `9`, but
lane-aware backchains show that the lhs byte is a real zero byte inside the
same add32_mix state word. Semantic offset `11` is now source-proven as:

```text
call_006  high8(low32(0xe6a626ee + 0x8581017f)) = high8(0x6c27286d)
call_001  high8(low32(0x2e657df9 + 0x9f97230b)) = high8(0xcdfca104)
call_003  high8(low32(0xbc7c1c4b + 0xfbbcca1d)) = high8(0xb838e668)
call_004  high8(low32(0xbe7455dd + 0x1cc90b7e)) = high8(0xdb3d615b)
call_005  high8(low32(0x4ab15934 + 0x674fb44b)) = high8(0xb2010d7f)
```

The remaining 41 semantic bytes are still mostly call_001-scoped.

`xor_rhs_mask_model` now isolates the repeated xor RHS bytes:

```text
even semantic offsets 2,14,60,66       -> mod255(0x74beabe59c) = 0x61
odd  semantic offsets 1,13,15,59,65,67 -> mod255(0x74ffafca73) = 0x62
```

The odd input is tied to the time-seeded LCG chain; the even input is tied to a
small-affine VM frontier chain. This explains the call_001 parity mask bytes,
but still does not prove the full state schedule for every payload byte.

`semantic_byte_source_model` now covers all 68 semantic bytes for the current
trace model:

```text
byte_lane_extract  1
mod255_low_byte   10
xor_mix           57
covered           68/68
```

Each xor byte records its rhs parity mask and lhs source. This makes the exact
remaining weakness visible: coverage is complete for `call_001`, but several
lhs sources are still trace literals or segmented non-portable sources.

`python_semantic_helper_coverage` now maps every semantic kind currently seen in
the tail writer evidence to a Python helper:

```text
add_small_delta    vm_add
bitwise_or_merge   vm_orr
byte_lane_extract  byte_lane_le
mod255_low_byte    mod255_low_byte
shift_right        vm_lsr
ubfx               vm_ubfx
xor_identity       xor_mix
xor_mix            xor_mix
```

All seen semantic kinds have helpers, and the opcode sample validation now
includes `byte_lane_le`. This is helper coverage, not full-window validation.

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

The next 32-bit lane, `tail[7:11]`, now has the same output-first proof for all
five diff samples:

```text
call_006  word 0x8ef018e6 -> low32(0x163a3ab10 + 0x2b4c6dd6)
call_001  word 0x783e786f -> low32(0x561d4e18 + 0x22212a57)
call_003  word 0xf5e1e4ad -> low32(0x1629d1cea + 0x9344c7c3)
call_004  word 0xbb1885b7 -> low32(0xd4436143 + 0xe6d52474)
call_005  word 0x873300ea -> low32(0x222f1cd6e + 0x6441337c)
```

For `call_005`, `tail[7:11] = 12 f6 95 2f` and the parity mask is
`95 c5 95 c5`, so the inferred lhs is `87 33 00 ea`. Because one lane is zero,
the CLI now emits `xor_word_degenerate_templates[]` with
`kind = word32_zero_lane`, `lhs_word_le = 0xea003387`, and
`zero_lhs_offsets = [2]` in the selected local slice. The lane-aware backchain
for the three non-zero lanes reaches the same `add32_mix` result
`0x873300ea`, so this is now a source-proven zero lane rather than a missing
state-source proof. It remains a useful UI/CLI example: summaries should report
degenerate lanes without losing the underlying word-level source.

The following two bytes, `tail[11:13]`, are also no longer treated as an opaque
trace literal. Across the five diff samples the lhs bytes are:

```text
call_006  lhs 6c 06  = high8(0x6c27286d) || 0x06
call_001  lhs cd 01  = high8(0xcdfca104) || 0x01
call_003  lhs b8 03  = high8(0xb838e668) || 0x03
call_004  lhs db 04  = high8(0xdb3d615b) || 0x04
call_005  lhs b2 05  = high8(0xb2010d7f) || 0x05
```

The first byte comes from another `add32_mix` state result and remains partial.
The second byte is now promoted to strong coverage:
`semantic[12] = low8(meta.callIdx) ^ parity_mask` for the five diff samples.

The first five bytes of the large middle lhs run, `semantic[16:21]`, are stable
across all current samples:

```text
lhs[16:21] = fbe9f26979
formula    = scratch[3:8]
scratch    = u32(stat('/').st_mtim.tv_sec << 24)
          || u32((stat('/').st_mtim.tv_sec >> 8) | (ladder_low8 << 24))
```

For `call_001`, `stat('/').st_mtim.tv_sec = 0x69f2e9fb` and
`ladder_low8 = 0x79`, giving `fbe9f26979`. The first four bytes are now strong
coverage as stat-derived bytes xor parity masks across all current samples. The
fifth byte, `0x79`, still needs source proof before the full prefix can be
treated as portable.

The remaining middle lhs range, `semantic[20:59]`, is now treated as trace-observed
partial coverage across the five diff samples:

```text
sample count        5
stable bytes        43/43
variation count     0
```

This closes the byte-formula accounting gap, but not the algorithmic source
gap: the range still depends on VM scratch/table replay, static table reads,
and app metadata boundaries recorded in `middle_lhs_source_manifest`.

The tail word at `semantic[61:65]` is also now cross-sample formula-covered:

```text
call_006  lhs 3a500301  rhs baa1baa1  -> 80f1b9a0
call_001  lhs 3abf0301  rhs 62616261  -> 58de6160
call_003  lhs 3aa10301  rhs 34b934b9  -> 0e1837b8
call_004  lhs 3a7e0301  rhs 1b541b54  -> 212a1855
call_005  lhs 3aa30302  rhs 95c595c5  -> af6696c7
```

The first and third lanes are now promoted to strong coverage:
`semantic[61] = low8(meta.pid) ^ parity_mask`, and all five `traces/diff/run1`
samples have `meta.pid = 0x7b3a`; `semantic[63] = 0x03 ^ parity_mask`, with
all five checked chains stopping at the same VM `bytecode_read_boundary`
literal. This keeps only `62` and `64` in partial coverage for the tail word:
the XOR word shape is proven, but the variable table/counter lanes still need
source proof.

`semantic[62]` is now refined further for the subset whose lineage reached the
same table boundary. In those samples the left-hand byte is:

```text
lhs62 = low8(((static_table_seed * 0xdd08cee9) + 0x61f5) & 0x7fffffff)
tail[62] = lhs62 ^ parity_mask_even
```

The observed seeds all load from the same no-writer/preinitialized boundary at
`0x74fbf31b80`:

```text
call_006  seed 0x15db0ba3 -> lhs 0x50 -> 0xf1 with mask 0xa1
call_003  seed 0x00f9fecc -> lhs 0xa1 -> 0x18 with mask 0xb9
call_004  seed 0x20f171a1 -> lhs 0x7e -> 0x2a with mask 0x54
call_005  seed 0x4f385b7e -> lhs 0xa3 -> 0x66 with mask 0xc5
```

This is better than an opaque scratch byte, but it is still partial coverage:
the portable Python model must either extract/parameterize that table seed or
prove the earlier initializer that writes it.

`semantic[64]` is now also narrowed. Four samples reduce to a bytecode literal
lane:

```text
tail[64] = 0x01 ^ parity_mask_even

call_006  bytecode 0x01 @ 0x74fbf64d88 -> 0xa0 with mask 0xa1
call_001  bytecode 0x01 @ 0x74fbf7b3b8 -> 0x60 with mask 0x61
call_003  bytecode 0x01 @ 0x74fbf64d88 -> 0xb8 with mask 0xb9
call_004  bytecode 0x01 @ 0x74fbf64d88 -> 0x55 with mask 0x54
```

`call_005` is the exception:

```text
lhs64 = 0x02 = bytecode_literal_0x1 + table_byte_0x1
tail[64] = 0x02 ^ 0xc5 = 0xc7
table byte read: 0x75664d72a4 observed 01000000, no traced writer
table index: bytecode literal 0x04 @ 0x74fbf675b8
```

The new `vm-backchain` lane fix was needed here: without byte-lane inference,
`ldr w19` over `01000000` could follow the last byte writer for the zero high
byte instead of offset `0`, hiding the bytecode-literal path. This is still
partial coverage because the `call_005` table byte has no portable source
proof.

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
The first word is strongly connected to `tail[3:7]`; the second word is now
connected to `tail[7:11]` for all five diff samples, including the source-proven
degenerate zero-lane sample.

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
The current trace-bound simulator is now a real parameterized function chain:
`call001_trace_model_parameters() -> reconstruct_semantic_tail_from_parameters()
-> xsign_from_semantic_tail()`. This keeps all remaining trace-bound inputs in
one explicit parameter object, so replacing constants with portable
app/device/table inputs no longer requires rewriting the simulator control flow.

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
