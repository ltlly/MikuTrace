# AI CLI workflow for reconstructing x-sign-style algorithms

This note describes how an AI agent should use traceMiku CLI surfaces to work
backward from an observed signature/output buffer toward the generating
algorithm. The workflow is target-agnostic; `libsgmainso` and `x-sign` are
examples of the analysis shape, not hardcoded assumptions.

## Principle

Prefer result-to-input analysis:

1. Start from a known output byte sequence, string, return pointer, or JNI
   return object.
2. Locate where those bytes existed in trace memory.
3. Identify the stores that produced them.
4. Backward-taint the source register of each store.
5. Repeatedly expand through memory, call context, string/JNI provenance, and
   decompiled function summaries until the dataflow reaches inputs, constants,
   tables, or recognizable crypto/hash/finalize structure.

This is the same strategy that worked manually with text traces: begin at the
generated x-sign and walk upward.

## CLI surfaces

Use the typed wrappers for common routes:

```bash
./tracemiku info <call_dir> --json
./tracemiku api <call_dir> /api/meta
./tracemiku api <call_dir> /api/query -p kind=records -p q=ret -p limit=50
```

For every Rust web API, use the generic escape hatch:

```bash
./tracemiku api <call_dir> /api/backtrace -p idx=443 -p limit=64
./tracemiku api <call_dir> /api/llil/render --method POST \
  --json-body '{"fn_id":"trace:F0","max_records":600}'
```

If a typed wrapper exists, prefer it because its help text is discoverable:

```bash
rust/target/debug/tracemiku-cli --help
rust/target/debug/tracemiku-cli taint-bwd --help
```

## Output-to-writer path

Convert the known signature or byte sequence to hex, then search memory:

```bash
./tracemiku api <call_dir> /api/find-mem-pattern \
  -p bytes_hex=<hex_bytes> \
  -p max=100
```

For each candidate address range, list writes that produced bytes there:

```bash
./tracemiku api <call_dir> /api/mem-writes-in-range \
  -p idx_lo=0 \
  -p idx_hi=-1 \
  -p addr_lo=<addr> \
  -p addr_hi=<addr_plus_len> \
  -p max=500
```

The `writes[]` rows include `idx`, `asm`, `src_reg`, `src_value`, `dst_addr`,
and `func`. Use `src_reg` and `idx` as the seed for backward taint.

When the output buffer is already known, prefer the byte-oriented wrapper. It
expands overlapping word stores into one latest writer per byte, using
little-endian source values, and also emits compact `writer_runs[]`:

```bash
rust/target/debug/tracemiku-cli byte-writer-map <call_dir> \
  --addr <buffer_addr> \
  --size <byte_count> \
  --idx-lo 0 \
  --idx-hi <before_output_overwrite_idx> \
  --max 5000
```

This is useful when the same scratch address is later reused for the final
string copy. Set `--idx-hi` just before the consumer/encoder reads the buffer;
otherwise the "latest writer" may be a later overwrite of the same address.
For AI reasoning, start from `writer_runs[]` to classify chunks, then use the
per-byte `bytes[]` entries for offsets that need deeper `vm-backchain` or
`byte-lineage` work.

To attach the first few upstream chains in one command:

```bash
rust/target/debug/tracemiku-cli byte-writer-map <call_dir> \
  --addr <buffer_addr> \
  --size <byte_count> \
  --idx-hi <before_output_overwrite_idx> \
  --vm-chain-steps 16 \
  --vm-chain-runs 8 \
  --vm-chain-follow-frontier
```

The added `vm_chains[]` entries are intentionally summaries. They are meant to
rank which byte or run should be investigated next, not to replace a focused
`vm-backchain`/`vm-backtree` run when a branch point matters. The top-level
`vm_chain_summary.semantic_kind_counts[]` shows whether the selected runs are
mostly Base64 bit slicing (`ubfx`/`shift_right`), byte normalization
(`xor_identity`), modulo folding (`mod255_low_byte`), or another repeated
template. Other useful labels include `bitwise_or_merge` for packed-word
assembly, `xor_mix` for non-trivial XOR byte mixing, `add32_mix` for 32-bit
state addition, `add_known_constant` for recognized IV/constants such as MD5,
and `and_identity`/`or_identity` for masking or merging operations that
preserve the value being chased.

`add32_mix` is intentionally low-32-aware. VM handlers may compute with native
`add x*` registers and only later write the low word with `str w*`; in that
case the semantic object includes `lhs_low32`, `rhs_low32`, and
`result_low32`. Treat `result_low32` as the value that flows into subsequent
word stores and byte extraction.

`vm-ops --summary` also exposes `state_updates[]` when an `add32_mix` result is
stored by a nearby memory write. This pairs the formula with the `str w*`
destination address, which is often the exact hash/state buffer word to chase
next.

Byte writer maps are little-endian lane-aware. Each `bytes[]` entry and
single-byte writer run carries `source_byte_offset`, and each compact
`vm_chains[]` seed includes `byte_lane`. This matters when a final output byte
was written with `strb` from the low byte of a register that was previously
loaded as a 32-bit word: without lane selection, a linear chain can accidentally
follow the newest writer of another byte in that word. The auto
`output-map --semantic-writer-map-vm-chain-*` path passes the lane for you.
Semantic frontier selection is lane-aware too: `bitwise_or_merge` follows the
operand that contributes the selected byte, and `lsl`/`lsr`/`asr`/`ubfx` update
the source byte lane when the shift/extract is byte-aligned.

For a focused "one byte upward" investigation, use `byte-lineage` from the
memory byte address consumed by the next layer:

```bash
rust/target/debug/tracemiku-cli byte-lineage <call_dir> \
  --addr <byte_addr> \
  --before-idx <consumer_idx> \
  --depth 12 \
  --summary
```

`byte-lineage` now preserves the source byte lane after the first last-writer
lookup. For example, a `strb` writer seeds lane `0`; a byte inside a `str w*`
writer seeds lane `0..3`; and a byte inside a `str x*` writer seeds lane
`0..7`. Subsequent memory/VM-slot loads prefer the matching
`upstream.byte_nexts[]` entry, and semantic ALU frontiers carry lane
transformations through byte-aligned shifts and extracts. This makes it a
better CLI primitive for the manual result-to-input workflow than whole-register
backward taint when the output byte came from a packed word.

When a traced memory load's observed value does not match the latest traced
write to that address, the CLI marks the upstream as
`observed_read_without_matching_traced_write`, emits `observed_bytes_hex` and
`observed_mismatches[]`, and suppresses automatic `next` / `byte_nexts`.
Treat this as an analysis boundary: the value may come from an untraced library
write, preexisting mapped data, a syscall/JNI side effect, or a trace coverage
gap. Do not keep following the stale traced write just because it is the latest
write in the index.

In `vm-backchain --summary`, the same condition is surfaced under
`recognized_pattern_summary.memory_boundary_reads[]`. Use this compact field
first when an AI needs to decide whether a chain can continue automatically or
needs a wider trace / external metadata hook.

For this boundary case, `vm-backstep` / `byte-lineage` also include
`upstream.gap_call_candidates`. The scan covers the trace-index gap between the
last traced write and the observed read, then ranks calls whose target is
outside the primary traced module or whose argument registers point near the
target address. Use `target_module.name + target_module.offset` plus
`arg_offsets[]` to decide whether an external library call plausibly produced
the bytes. A common pattern is a libc/JNI function writing an output structure:
for example `arg_offsets: [{"reg":"x1","offset":"0x58"}]` means the observed
address lies at `x1 + 0x58` at that call boundary. If symbols are available,
resolve the module offset to distinguish a true output writer such as
`stat/stat64` from a later unrelated call such as `free`.

To inspect the surrounding per-byte read/write history for one address, use:

```bash
rust/target/debug/tracemiku-cli idxs-touching-addr <call_dir> \
  --addr <byte_addr> \
  --cursor <idx> \
  --limit 20 \
  --with-bytes
```

`--with-bytes` may block while loading/building MemShadow, but it lets an AI
agent distinguish "latest traced write" from "last observed read value" when a
scratch address is reused.

To dump a byte range as of a specific trace index, use `mem-dump --cursor`.
Without `--cursor`, it shows the final MemShadow state:

```bash
rust/target/debug/tracemiku-cli mem-dump <call_dir> \
  --addr <addr> \
  --count 128 \
  --cursor <idx>
```

This is useful for external-call parameters, such as reading a C string or
output structure around the call boundary rather than after the buffer has been
reused later in the trace.

For x-sign-like outputs that Base64-encode a variable tail in the same scratch
buffer, `output-map` can now derive the pre-encoding semantic byte map directly
from the final JNI string:

```bash
rust/target/debug/tracemiku-cli output-map <call_dir> \
  --key x-sign \
  --base64-tail-start 12 \
  --base64-tail-align-prefix AA \
  --base64-tail-drop 1 \
  --semantic-writer-map \
  --semantic-writer-map-vm-chain-steps 8 \
  --semantic-writer-map-vm-chain-runs 12 \
  --semantic-writer-map-vm-chain-follow-frontier \
  --summary
```

The command selects the earliest full output buffer, finds the first writer of
the final textual output, and uses that writer index as the exclusive `idx_hi`
for the semantic byte map. This reproduces the manual "final x-sign -> decoded
tail -> last writers -> upstream chain" workflow without hand-picking the
pre-encoding cutoff index. If the buffer layout differs, override the cutoff
with `--semantic-writer-map-idx-hi`. In `--summary` mode,
`semantic_writer_map.vm_chains[]` stays compact and lists each writer run's
`semantic_kinds`, so an AI agent can choose the next unexplained byte range
without reading the full trace-shaped JSON. The same summary also emits
`semantic_writer_map.byte_equations[]` for directly recognized byte formulas
such as `xor_mix` and `mod255_low_byte`; this is the first place to look when
building a Python simulator from trace evidence.

Packed stores need one extra switch. By default the semantic writer map expands
coalesced `writer_runs[]`, which is fast and good for triage. When a 32-bit
`str w*` produced several output bytes and each byte lane must be explained,
add `--semantic-writer-map-vm-chain-bytes`. This seeds each VM backchain from
the corresponding `bytes[]` entry and preserves its little-endian
`source_byte_offset` as `seed.byte_lane`:

```bash
rust/target/debug/tracemiku-cli output-map <call_dir> \
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

The summary marks this with `semantic_writer_map.vm_chain_seed_mode = "bytes"`.
Use it after run-level triage has found a packed region; it is intentionally
opt-in because it may run one backchain per byte.
For long tails, read `semantic_writer_map.byte_equation_summary` before the
full `byte_equations[]` array. It reports coverage, kind counts, and common
XOR mask structure such as an offset-parity mask (`even_byte = 0x61`,
`odd_byte = 0x62`), which is usually the compact form an AI agent should carry
into the simulator. It also emits `xor_lhs_runs[]`, contiguous byte ranges of
the unmasked left-hand stream; use those ranges as the next backtracking seeds
when the final output is mostly `lhs_i ^ mask_i`. For simulator work, prefer
`xor_lhs_word_chunks[]` over manually slicing the hex string: it splits each
contiguous XOR lhs run into non-overlapping little-endian 32-bit chunks plus a
short tail chunk when the run length is not divisible by four.

When four consecutive byte equations are XORs, the summary additionally emits
`semantic_writer_map.xor_word_templates[]`. This is designed for the manual
"start from generated x-sign and walk upward" flow: it turns rows like
`byte = lhs ^ mask` into one word-sized relation with little-endian bytes and,
when applicable, links an alternating two-byte mask back to earlier byte
equation offsets.

Example shape:

```json
{
  "semantic_range": [3, 7],
  "formula": "semantic[start..start+4] = word32_le(lhs_word_le) xor rhs_bytes",
  "lhs_word_le": "0xd84ab467",
  "rhs_pattern": {
    "kind": "alternating_two_byte_mask",
    "source_offsets": [1, 2]
  },
  "result_bytes_hex": "05d528b9"
}
```

When the selected VM backchain reaches the word source, the same summary emits
`semantic_writer_map.xor_word_state_sources[]`. This links the XOR word to the
byte-extraction instruction and the upstream `add32_mix` state update, for
example `source_word = 0x67b44ad8` and `result_low32 = 0x67b44ad8`.
`source_word_match` records whether the source matched `lhs_word_le` directly
or through `bswap_lhs_word_le`. Entries are emitted only when the chain also
reaches a concrete `add32_mix` state update, so this field is suitable for
feeding the Python simulator rather than just listing sliding XOR windows.

## Backward dataflow path

Trace register provenance from a writer or suspicious finalizer instruction:

```bash
rust/target/debug/tracemiku-cli taint-bwd <call_dir> \
  --start <writer_idx> \
  --reg <src_reg> \
  --through-mem \
  --cross-fn-call \
  --max-count 5000
```

When taint becomes too broad, narrow with local context:

```bash
rust/target/debug/tracemiku-cli records <call_dir> --start <lo> --count <n> --regs x0,x1,x2,x3,x8,x9,sp,lr
rust/target/debug/tracemiku-cli backtrace <call_dir> --idx <idx> --limit 128
rust/target/debug/tracemiku-cli call-chain <call_dir> --idx <idx> --depth 16
rust/target/debug/tracemiku-cli block <call_dir> --pc <pc>
rust/target/debug/tracemiku-cli idxs-for-block <call_dir> --pc <block_pc> --near <idx> --max-count 200
```

Use `data-chase` when a register points through stack/heap memory and plain
register taint does not explain the value:

```bash
rust/target/debug/tracemiku-cli data-chase <call_dir> \
  --start <idx> \
  --reg <reg> \
  --max-steps 80
```

## JNI and string provenance

Inputs and outputs often cross JNI boundaries as strings, byte arrays, or
objects:

```bash
rust/target/debug/tracemiku-cli jni-output-strings <call_dir> --key x-sign
rust/target/debug/tracemiku-cli jni-events <call_dir> --kind NewStringUTF --limit 5000
rust/target/debug/tracemiku-cli jni-events <call_dir> --limit 5000
rust/target/debug/tracemiku-cli jni-calls <call_dir> --max 5000
rust/target/debug/tracemiku-cli jni-strings <call_dir> --max 5000 --max-len 256
rust/target/debug/tracemiku-cli jobj-history <call_dir> --jobject <0x...> --max 500
rust/target/debug/tracemiku-cli string-provenance <call_dir> --addr <0x...> --length <n>
```

For x-sign-like outputs, `jni-output-strings --key x-sign` is usually the best
first command. It pairs `NewStringUTF("x-sign")` with the following
`NewStringUTF(<value>)` and returns the exact `key_idx`, `value_idx`, returned
JNI objects, and value length. Use the instruction immediately before
`value_idx` as the `NewStringUTF` callsite seed; on ARM64 this is commonly a
`blr` with `x1` holding the C string pointer.

For an AI agent, the report-oriented shortcut is:

```bash
rust/target/debug/tracemiku-cli output-backtrace <call_dir> --key x-sign
```

It starts at the observed JNI output, adds the percent-decoded byte pattern when
the value is URL-encoded, and also tries a best-effort Base64 decode for
textual outputs. It searches trace memory for each derived byte pattern,
reports the current writer provenance for matching bytes, resolves those writer
instructions back to source registers, and runs bounded backward taint from the
JNI callsite plus discovered writer registers. This captures the manual
strategy that worked before traceMiku existed: begin at the generated x-sign
and walk upward. Use `--no-url-decode` or `--no-base64-decode` when a derived
pattern is not useful for a target.

Each memory hit includes `writer_runs[]`, a compact linear table of output byte
offsets, writer idxs, source registers, source values, and text fragments. This
is the preferred representation when asking an AI to reason about how the final
string is assembled.

When the target is VM-heavy, attach bounded VM chains directly to the output
report:

```bash
rust/target/debug/tracemiku-cli output-backtrace <call_dir> \
  --key x-sign \
  --skip-taint \
  --writes-per-hit 12 \
  --vm-chain-steps 5 \
  --vm-chain-runs 6
```

The resulting `patterns[].hit_reports[].vm_chains[]` entries start from
selected `writer_runs[]` seeds and contain the same ordered chain produced by
`vm-backchain`.

When the output is produced by an OLLVM-style bytecode VM, `writer_runs[]` is
also the best place to choose concrete trace windows. Start from the closest
ranked raw output hit, pick a writer idx near the first output bytes, then slice
the VM context around it:

```bash
rust/target/debug/tracemiku-cli vm-slice <call_dir> \
  --start <writer_idx_minus_context> \
  --count 300 \
  --only-vm
```

`vm-slice` prints a compact dynamic VM view for AI consumption:

- `class`: rough role, such as `bytecode-read`, `vm-reg-load`,
  `vm-reg-store`, `byte-load`, `byte-store`, `dispatch-table-load`, or
  `dispatch-branch`. Common arithmetic/bitwise rows are kept as `alu`, because
  VM transforms often happen between slot loads and stores.
- `def`: best-effort destination register plus the value observed in the next
  trace row. `def.src[]` lists source registers and current values, which is
  especially useful when a chain stops at an ALU row and the agent must choose
  which source branch to follow.
- `store_src`: best-effort source register values for store-style
  instructions.
- `vm_ip`: current bytecode instruction pointer, usually `x21` in the detected
  dispatcher shape.
- `vm_off`: offset from the first observed `vm_ip` in the slice, useful for
  aligning repeated opcode handlers.
- `vm_slot`: decoded virtual register slot for `[x25, ...]` accesses. Both
  byte-offset form (`[x25, x1]`) and scaled slot form
  (`[x25, x19, lsl #3]`) are normalized.
- `mem_addr`: effective memory address for simple ARM64 base/index/immediate
  addressing, including scaled indexes.

This is deliberately not a full VM lifter. It is the bridge between coarse
taint and manual reasoning: use it to see which VM slot holds an input byte,
which VM slot is copied into an output buffer, and where the bytecode IP moves
between those events.

For iterative backward walking, use `vm-backstep` on a concrete writer row:

```bash
rust/target/debug/tracemiku-cli vm-backstep <call_dir> \
  --idx <writer_idx> \
  --reg <source_reg>
```

If `--reg` is omitted, the first store source register is used. The command
finds the register's nearest local definition, then:

- if the definition came from a VM slot load, finds the last write to that VM
  slot within `--lookback`;
- if the definition came from a normal memory load, finds the last write to
  that memory range within `--lookback`;
- returns `upstream.next.idx` and `upstream.next.reg` so the agent can run the
  next `vm-backstep`.
- returns `upstream.writes_tail` for multi-byte loads, because a 32-bit or
  64-bit value may have been assembled by several byte stores and the final
  chronological writer may explain only the last byte.
- returns `frontier[]` with `{idx, reg, value}` candidates derived from
  `local_def.def.src[]`. Use these when `upstream.next` is null, such as at an
  ALU merge or a table lookup where the interesting branch is the index
  register rather than the loaded table byte.

This mirrors the manual trace workflow:

```text
final output store -> source VM slot -> previous slot writer -> source memory
load -> previous memory writer -> ...
```

Use `vm-backchain` when the next hop should be followed automatically:

```bash
rust/target/debug/tracemiku-cli vm-backchain <call_dir> \
  --idx <writer_idx> \
  --reg <source_reg> \
  --byte-lane <source_byte_offset> \
  --steps 8 \
  --summary
```

This emits an ordered `chain[]` of `vm-backstep` results. `--summary` avoids
full register dumps and large `writes_tail[]` payloads, while keeping local
definitions, compact upstream writes, frontiers, and formulas. The command is
intentionally linear: for multi-byte memory loads, inspect the full output or
use `vm-backtree` when different output bytes have different writers.
When the seed came from a byte writer map, pass that byte's
`source_byte_offset` as `--byte-lane`; the summary will record
`decision.kind = upstream_byte_lane` when it selected a matching memory byte.

When following a final encoded output backward, enable frontier following:

```bash
rust/target/debug/tracemiku-cli vm-backchain <call_dir> \
  --idx <writer_idx> \
  --reg <source_reg> \
  --steps 16 \
  --follow-frontier
```

With `--follow-frontier`, the chain still prefers `upstream.next`. If a step
stops at a table lookup or ALU row with no direct writer, it chooses a
non-infrastructure `frontier[]` source register. Recognized semantic formulas
override generic heuristics: `udiv` follows the numerator,
`mod255_low_byte` follows the folded input, and `add_small_delta` follows the
large state value instead of constants such as `1`. `xor_identity` handles
`eor/xor value, 0` and follows the non-zero input; this matters for VM byte
normalization before payload bytes are written. Shift/extract operations such
as `lsl`, `lsr`, `asr`, and `ubfx` follow their first operand, not the shift
amount. The remaining generic table-lookup case still prefers small index-like
values. This is useful for Base64-style table lookups: the alphabet byte has no
writer, but the table index register is usually the dataflow branch to keep
chasing. Each row records `decision.kind` as `upstream_next`, `frontier_auto`,
or `stop`.

The infrastructure-register filter is a preference, not a hard stop. If the
only frontier is a register such as `x23`, the chain still follows it. This is
important around indirect calls where a return value may be saved through a
callee-saved register before being written into a VM slot.

Call returns are explicit boundaries. If a value in `x0` is consumed immediately
after `bl`/`blr`, `vm-backstep` emits a `local_def.class = call-return` row
instead of attributing the value to an older pre-call definition of `x0`. The
row includes the call idx, call target register/value, return value, and
argument registers `x0..x7`. Linear `vm-backchain --follow-frontier` stops at
this boundary; use the call target and args to decide whether the value came
from an external helper, a JNI/runtime callback, or an untraced function.

If a process maps file is available, resolve indirect call targets with:

```bash
rust/target/debug/tracemiku-cli resolve-map-addr /tmp/proc-pid.maps \
  0x787bf034e8
```

The output gives the mapped path and ELF file offset. Use that offset with
`resolve-elf-symbol` to name the external helper from a pulled local copy of
the shared library:

```bash
rust/target/debug/tracemiku-cli resolve-elf-symbol \
  /tmp/tracemiku-device-libs/libc.so \
  0xa0f5c
```

For the first changing x-sign middle word observed in `call_001`, this resolves
`libc.so+0xa0f5c` to `stat@@LIBC`. That turns the trace gap into a concrete
modeling requirement: capture or simulate the pathname plus the `struct stat`
output bytes that the traced code later reads. On Android AArch64,
`struct stat + 0x58` is `st_mtim.tv_sec`; a value such as
`fbe9f26900000000` is the little-endian mtime seconds field, not a stale traced
zero store.

For a fresh capture, keep normal tracing and add a narrow boundary-diff hook
instead of enabling full `--trace-deep`:

```bash
./tracemiku trace ... \
  --boundary-diff-patterns stat@@,stat64@@,fstatat@@,fstatat64@@,lstat@@,lstat64@@
```

This records changed bytes under `external_writes.bin`, which MemShadow exposes
as `kind: "x"` writes. It lets `byte-lineage` continue through external stat
output bytes without following stale in-module writes.

Pair loads are expanded before backtracking. A row such as
`ldp x9, x10, [x25,#0xc0]` contributes separate definitions for `x9` and
`x10`, with memory addresses `base+0` and `base+8`. This prevents a chain for
the second loaded register from incorrectly stopping at the first destination
or treating the second destination as a source operand.

For ALU merge/split rows, use `vm-backtree` instead of a linear chain:

```bash
rust/target/debug/tracemiku-cli vm-backtree <call_dir> \
  --idx <writer_idx> \
  --reg <source_reg> \
  --depth 6 \
  --max-nodes 64
```

`vm-backtree` expands `upstream.next` and, when a row has no direct upstream
writer, all non-infrastructure `frontier[]` source registers. The output is a
flat tree (`nodes[]` with `id`/`parent`) so an AI can follow both sides of
operations such as `orr x4, x14, x17`, `lsl`, `lsr`, and `ubfx`. Use
`--frontier-with-next` when address/index branches are also worth exploring,
but keep `--max-nodes` bounded on large traces.

The same behavior can be attached to `output-backtrace` reports:

```bash
rust/target/debug/tracemiku-cli output-backtrace <call_dir> \
  --key x-sign \
  --skip-taint \
  --writes-per-hit 12 \
  --vm-chain-steps 8 \
  --vm-chain-follow-frontier
```

For Base64-like outputs, use the compact group map when the full
`output-backtrace` report is too large:

```bash
rust/target/debug/tracemiku-cli output-map <call_dir> \
  --key x-sign \
  --hit-order earliest \
  --group-start 3 \
  --groups 1 \
  --tree-depth 8 \
  --tree-max-nodes 220 \
  --index-tree-depth 8 \
  --tree-frontier-with-next
```

`output-map` chooses a ranked memory hit for the observed output string, then
splits the textual output into 4-character Base64 groups, reports each group's
decoded bytes, overlapping writer runs, writer source register, and optional
`vm-backtree`. The default `--hit-order earliest` is meant for generation
analysis: it picks the first full output buffer and walks backward from there.
Use `--hit-order nearest` when you specifically want the final buffer handed to
JNI.

Add `--summary` when the result is meant for an AI prompt or a quick survey
across many groups. It keeps each group's Base64 indices, decoded bytes, lookup
match counts, and compact interesting/semantic formulas, while dropping the
large raw backtree nodes. The summary also includes `decoded_payload[]`, which
maps every decoded payload byte to the Base64 index sources and the formulas
that produced those indices. This is the preferred prompt surface when walking
from output text back toward payload construction.
For an even flatter prompt input, use `payload_formula_table[]`: each row is one
decoded payload byte with its Base64 byte formula plus compact expression lists
for the contributing alphabet indices. The table also carries
`interesting_refs[]` / `semantic_refs[]` entries with trace idx, result reg,
asm, and a `continue_with` hint. An agent can immediately continue with
`vm-backtree --idx <idx> --reg <reg>` on the operation that produced an index
component.
When that continuation reaches VM bytecode reads, `vm-backtree --summary`
includes `bytecode_operands[]`, a compact list of `x21+#offset` operand reads
with value and consuming instruction. Use this to lift repeated VM opcode
templates rather than reading raw terminal nodes.

Each group also includes `base64.indices` and `base64.decoded_bytes`. Use these
fields to line up a traced alphabet index, for example `i2 = 0x18`, with the
payload byte formula such as `((i1 & 0x0f) << 4) | (i2 >> 2)`.
When a tree is attached, `base64_lookup_matches` maps each character in the
current group to the concrete `ldrb alphabet[index]` trace idx and index
register. Add `--index-tree-depth N` to attach a second tree from each matched
index register, which is the shortest path from the Base64 text layer toward
payload bit construction. Each attached match also has
`index_summary.interesting_formulas`, a compact filtered list of small-value
ALU formulas suitable for prompt input, and
`index_summary.semantic_formulas`, a lower-noise list of recognized operations
such as bitmask extraction, shifts, OR merges, modular folds, and state updates.
If `--index-tree-depth` is set without `--tree-depth`, `output-map` now builds
hidden lookup trees automatically so the command does not silently return
`match_count: 0` for every Base64 character.

Do not assume the whole-string Base64 decode is always the semantic generation
buffer. Some x-sign-like formats concatenate a fixed Base64 prefix with a tail
that begins at a non-zero Base64 character offset. In that case, align the tail
explicitly before interpreting bytes. For the current libsgmainso samples, the
first variable tail begins at offset 2, so `base64_decode("AA" + tail)[1:]`
matches the scratch byte stream seen by trace backtracking.

The scan command can emit this aligned-tail view directly:

```bash
rust/target/debug/tracemiku-cli scan-jni-output-strings traces \
  --key x-sign \
  --decode-url \
  --diff-base64 \
  --base64-tail-start 12 \
  --base64-tail-align-prefix AA \
  --base64-tail-drop 1
```

Each pair then includes `base64_tail.semantic_hex`, and the top-level
`base64_tail_diff` compares that aligned semantic tail across samples. It also
reports `repeated_ranges_all_samples[]`, which highlights byte ranges that are
equal at two offsets in every sample. Treat those as copy candidates until a
trace backchain confirms the producer.

Use the same alignment parameters with `output-map` when stepping from tail
bytes back to trace writers:

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

In this mode `group_start` refers to the aligned tail groups. Summary rows keep
both `aligned_decoded_offset` and `semantic_offset`; bytes before
`--base64-tail-drop` are marked `dropped_by_alignment`. When `--tree-depth` is
enabled, `--summary` also keeps compact `groups[].trees[]` entries with the
writer seed, table lookups, word loads, arithmetic semantics, and terminal
frontiers. This keeps output-map useful as an AI prompt without dumping the full
nested route payload.

When you already know the tail byte offset, skip group arithmetic:

```bash
rust/target/debug/tracemiku-cli output-map <call_dir> \
  --key x-sign \
  --base64-tail-start 12 \
  --base64-tail-align-prefix AA \
  --base64-tail-drop 1 \
  --semantic-offset 65 \
  --semantic-count 3 \
  --summary
```

When the tree reaches a table lookup such as `ldrb w3, [alphabet, index]`,
add `--tree-frontier-with-next`. Without it the tree follows the table memory
edge; with it the report also keeps the `index` register branch, which is the
branch that usually leads back to the payload bits.

For word loads from generated buffers, inspect `upstream.byte_nexts`. A row
such as `ldr w19, [buf, off]` can have four byte writers; these are the four
independent character sources that make up the loaded word. This matters for
the x-sign Base64 stage because the VM often builds overlapping 4-character
windows and then combines them with `lsl`/`lsr`/`orr`.

When the full tree is too noisy for an AI prompt, add `--summary`:

```bash
rust/target/debug/tracemiku-cli vm-backtree <call_dir> \
  --idx <trace_idx> \
  --reg <reg> \
  --depth 16 \
  --frontier-with-next \
  --summary
```

The summary drops the raw node tree and keeps the parts that matter for
result-to-input analysis: `word_loads`, Base64 table lookups, low-noise
formulas, small byte loads, bytecode-read frontiers, and terminal nodes.

When a tree stops at bytecode-read frontiers, inspect the dynamic VM execution as
virtual operations:

```bash
rust/target/debug/tracemiku-cli vm-ops <call_dir> \
  --start <idx_before_frontier> \
  --end <idx_after_frontier> \
  --summary \
  --max-ops 40
```

`vm-ops` groups contiguous native records by `x21`/`vm_ip`. Each group reports
bytecode immediate reads, VM slot reads/writes, small byte loads, memory stores,
dispatch branches, and ALU formulas. This is the layer to use after
`vm-backtree --summary` reaches bytecode frontiers: it turns interpreter noise
into a compact sequence such as "load byte 0x0a into slot 16", "load byte 0x62
into slot 17", "compute 0x29 = (0x0a << 2) | (0x62 >> 6)", and "lookup Base64
char p".
Use `--summary` for AI analysis windows; it keeps slot traffic, bytecode reads,
dispatches, semantic formula counts, and compact ALU formulas without the full
record-shaped payload.

For a specific scratch byte, use `byte-lineage` to automate the repeated
last-write/backstep loop:

```bash
rust/target/debug/tracemiku-cli byte-lineage <call_dir> \
  --addr <byte_addr> \
  --before-idx <consumer_idx> \
  --depth 12 \
  --lookback 1200000 \
  --summary
```

The command alternates between `/api/last-write-of-addr` and `vm-backstep`.
`/api/last-write-of-addr` reports the original writer `dst_addr` and `size`,
not just the queried byte address, so a byte inside a `str w` or `str x`
write can preserve its source lane for the next `vm-backchain` hop.
When there is one upstream byte source it continues automatically; when the
source becomes an ALU expression with multiple operands or another branch point,
it stops with explicit frontier candidates. This is the preferred way to walk
from a Base64 scratch byte toward the actual payload byte, hash digest, fixed
table, or JNI input without silently choosing the wrong branch.

Use `--summary` for AI prompts. It keeps the chain, local definitions, selected
frontiers, and compact upstream writes, while avoiding the full nested route
payload. It also surfaces recognized arithmetic identities under
`recognized_semantics[]`. One important x-sign pattern is:

```text
kind: mod255_low_byte
(input + input / 0xff) & 0xff == input % 0xff
```

This comes from an ARM64 VM sequence where a quotient register is added back to
the original value, and only the low byte is stored. Treat it as a collapsed
formula and continue tracing the `input` operand.

Another small but important normalizer is:

```text
kind: xor_identity
result == input ^ 0
```

This prevents `--follow-frontier` from chasing a zero VM slot when an
OLLVM-style sequence computes `eor x16, x20, x5` with `x20=0` and `x5` carrying
the byte of interest.

Another common VM state pattern is:

```text
kind: add_small_delta
result == input + small_delta
```

Treat this as state advancement and continue tracing `input`. The delta is
usually an immediate or bytecode-controlled increment, not the source of the
cryptographic state.

Multiplication rows are reported as 64-bit wrapped arithmetic:

```text
kind: mul_mod64
result == (lhs * rhs) mod 2^64
```

When one operand is an odd repeated constant and the next row is
`add_small_delta`, the pair is likely an LCG-like state update. Use
`vm-backtree` if both multiplicands must be preserved; use linear
`vm-backchain --follow-frontier` when the goal is to continue chasing the state
operand. `vm-backchain --summary` reports these adjacent multiply/add pairs
under `recognized_patterns[]` as `affine_mod64_state_step`:

```text
state == (previous_state * multiplier + delta) mod 2^64
```

When the multiplier is odd, the same pattern includes `multiplier_inverse`.
This gives the exact reverse step:

```text
previous_state == (state - delta) * multiplier_inverse mod 2^64
```

For `mul_mod64` rows with one byte-sized multiplier and one larger operand,
`--follow-frontier` treats the larger operand as the state branch. This avoids
walking into constants such as `3` when the trace contains `state * 3 + 0x13`
style bytecode arithmetic.

`vm-backtree --summary` also includes `highlights.semantic_formulas[]` for
formulas that are easier to consume as semantics than as raw ARM64. Base64 index
construction commonly shows up as:

```text
kind: bitmask_extract
result == input & mask

kind: shift_right
result == input >> shift

kind: bitwise_or_merge
result == lhs | rhs
```

Low-value identity rows such as `ubfx(x, 0, 32)` and `x >> 0` are filtered out
of the semantic summary. Non-small formulas that are still important are kept,
such as:

```text
0x757524ef = 0x74ffafca73 / 0xff
```

For a shorter AI prompt, use `highlights.word_loads` and
`highlights.table_lookups` in the `vm-backtree` JSON. `word_loads` condenses
byte writers into `ascii`/`bytes_hex`; `table_lookups` reports the Base64
character and the small alphabet index register when it can identify one.
`highlights.alu_formulas` condenses bitwise/arithmetic VM rows into value
formulas such as `0x29 = 0x28 | 0x1` or `0x18 = 0x61 >> 0x2`, which is the
shortest view for reconstructing Base64-index and payload-byte logic.

For multi-trace discovery, avoid loading every trace. Scan JNI hook logs first:

```bash
rust/target/debug/tracemiku-cli scan-jni-output-strings traces \
  --key x-sign \
  --decode-url \
  --decode-base64 \
  --decode-base64-full \
  --diff-base64
```

This recursively reads only `jni_hooks.jsonl`, so it is suitable for quickly
finding differential x-sign samples before running heavier MemShadow/taint
commands on selected calls. `--decode-base64-full` includes the full decoded
payload hex for small signature payloads, which makes byte-level multi-sample
diffing straightforward. `--diff-base64` adds `base64_diff`, including
`stable_ranges` as half-open byte ranges `[start,end)`, per-byte stable/variable
classification, `variable_ranges`, `first_variable`, and the decoded payload for
each sample. `first_variable.output_map_args` can be passed directly to
`output-map --group-start ... --groups ...` to start from the first changing
Base64 group. Stable header bytes are useful for identifying format constants,
while variable ranges are usually better seeds for recovering the
request-specific algorithm.

Use `string-provenance` when a string table entry or discovered byte sequence
looks like the x-sign, an input token, timestamp, app key, device id, or encoded
intermediate.

Be careful with memory dumps around output strings: libc `memcpy`/`memset`,
inline C++ string storage, and untraced runtime writes can make final MemShadow
bytes look like an object layout instead of the real transient C string. JNI
hook bytes are the ground truth for `NewStringUTF`; use memory write ranges and
taint to locate who prepared the backing buffer.

## Algorithm structure

Once hot functions and key instructions are identified, summarize and decompile:

```bash
rust/target/debug/tracemiku-cli functions <call_dir>
rust/target/debug/tracemiku-cli fn-summary <call_dir> --fn <function_name> --top-blocks 12
rust/target/debug/tracemiku-cli dec-summary <call_dir>
rust/target/debug/tracemiku-cli dec-fn <call_dir> <fn_id> --tier hot
rust/target/debug/tracemiku-cli llil-render <call_dir> --fn-id <fn_id> --max-records 1000
```

If Binary Ninja sidecar is configured, static HLIL/CFG can enrich dynamic trace
context:

```bash
rust/target/debug/tracemiku-cli bn-sidecar-status <call_dir>
rust/target/debug/tracemiku-cli hlil-for-pc <call_dir> --pc <pc>
rust/target/debug/tracemiku-cli bn-cfg-for-pc <call_dir> --pc <pc> --mode asm
```

## Hypothesis checks

Use these routes to test whether the recovered structure is a known hash,
HMAC, crypto primitive, or finalization pattern:

```bash
rust/target/debug/tracemiku-cli crypto-scan <call_dir>
rust/target/debug/tracemiku-cli hash-finalize-detect <call_dir> --window 500 --min-size 16 --limit 1000
rust/target/debug/tracemiku-cli hash-input-search <call_dir> \
  --target-bytes <hex_output> \
  --inputs <csv_or_known_inputs> \
  --keys <csv_or_empty> \
  --search-in-mem
```

When a finalize candidate looks promising, expand the candidate buffer bytes in
the same command before spending time on deeper taint. This maps each candidate
back to `mem-writes-in-range`, reports whether its current bytes are all zero,
and optionally checks whether the candidate bytes occur inside the known output:

```bash
rust/target/debug/tracemiku-cli hash-finalize-detect <call_dir> \
  --window 500 \
  --min-size 16 \
  --limit 1000 \
  --map-bytes \
  --map-candidates 50 \
  --target-bytes <known_output_hex>
```

Use `--nonzero-only` when scanning large traces interactively. A candidate with
`all_zero: true` is usually a cleanup/state-buffer false positive for
result-to-input work. A candidate with non-empty `target_hits[]` is much more
interesting because its bytes are directly found inside the observed output
sequence.

For differential analysis, collect multiple calls with controlled input changes
and compare traces:

```bash
rust/target/debug/tracemiku-cli diff-traces <call_dir_a> <call_dir_b> --show-offsets --show-per-byte
```

## Success criterion

The CLI workflow is sufficient when an AI agent can produce:

1. The final output writer(s) for the observed x-sign bytes.
2. The backward taint/data-chase chain from those writer(s) to inputs,
   constants, or prior memory state.
3. The hot functions and decompiled/LLIL snippets that implement the transform.
4. A Python simulation that reproduces the observed x-sign on at least one
   captured call, then generalizes across differential traces.
