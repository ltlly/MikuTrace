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
  --steps 8
```

This emits an ordered `chain[]` of `vm-backstep` results. It is intentionally
linear: for multi-byte memory loads, inspect `writes_tail` and branch manually
when different output bytes have different writers.

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
non-infrastructure `frontier[]` source register, preferring small values. This
is useful for Base64-style table lookups: the alphabet byte has no writer, but
the table index register is usually the dataflow branch to keep chasing. Each
row records `decision.kind` as `upstream_next`, `frontier_auto`, or `stop`.

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

Each group also includes `base64.indices` and `base64.decoded_bytes`. Use these
fields to line up a traced alphabet index, for example `i2 = 0x18`, with the
payload byte formula such as `((i1 & 0x0f) << 4) | (i2 >> 2)`.
When a tree is attached, `base64_lookup_matches` maps each character in the
current group to the concrete `ldrb alphabet[index]` trace idx and index
register. Add `--index-tree-depth N` to attach a second tree from each matched
index register, which is the shortest path from the Base64 text layer toward
payload bit construction. Each attached match also has
`index_summary.interesting_formulas`, a compact filtered list of small-value
ALU formulas suitable for prompt input.

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
