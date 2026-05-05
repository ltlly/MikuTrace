# LLIL diff parity spec (frozen 2026-05-03)

The Rust LLIL pipeline (M5) must output equivalent results to the Python
pipeline. This document defines the equivalence relation per stage. M5's
parity tests use exactly these comparisons.

## Why not byte-equal text?

Python `render_hlil` outputs C-like pseudocode. A Rust port producing
1:1 byte-equivalent text would be brittle (`,` vs `, ` whitespace,
`0x10` vs `16` literal style, ordering of redundant fields). Aim for
**semantic equivalence**, not formatting equivalence.

## Per-stage equivalence

### Stage 1: lift (capstone → LlilExpr)

Equivalence: LlilExpr trees are structurally equal, comparing:
- `op` (LLIL opcode enum)
- `size` (bit width: 8/16/32/64)
- `operands` (recursive)

Differ format: `assert_lifted_eq(rust_expr, python_expr)` walks both
trees in parallel; first divergence prints both subtrees with PC and
opcode context.

### Stage 2: SSA (block-local + cross-block phi)

Equivalence: identical (def, use) sets per SSA variable.
- `def_set[var]`: set of (block_id, instruction_idx) where var is defined
- `use_set[var]`: set of (block_id, instruction_idx) where var is used

Differ format: dump both maps, set-symmetric-difference.

### Stage 3: constfold

Equivalence: identical set of LLIL_CONST nodes after fold.
- Each LLIL_CONST node identified by (pc, operand_path, value, size)
- Sets must be equal

Differ format: list nodes only-in-rust and only-in-python.

### Stage 4: dce

Equivalence: identical set of removed instruction PCs.
- `dce_removed: Set<u64>`

Differ format: symmetric difference of removal sets.

### Stage 5: flag_elim

Equivalence: identical set of (cmp_pc, branch_pc) pairs that were
folded into LLIL_IF nodes.

### Stage 6: typelat

Equivalence: identical type-inference output per SSA variable.
- `var_type[var] = TypeLat::{Int, Ptr, Unknown, Composite{...}}`
- TypeLat enum has the same variants in both implementations

### Stage 7: struct_lat

Equivalence: identical inferred struct shapes (set of (offset, size, type) tuples per shape).

### Stage 8: var_unify

Equivalence: identical naming map.
- `name_map: Map<SSAVar, String>` — each SSA var gets the same name in both

Differ format: per-var name diff.

### Stage 9: restructure (CFG → if/while/for)

Equivalence: structurally-equal restructured tree.
- Compare tree shape (Block / If / While / For nesting)
- Within each block, compare instruction ordering by PC
- Ignore string field ordering (e.g., `then_blocks` may appear in different order)

Differ format: pretty-print both trees side-by-side, mark first
divergence.

### Stage 10: render

Equivalence: token-level equality.
- Tokenize both outputs (skip whitespace, parens-grouping nuances)
- Compare token streams
- Tokens are: identifier, integer literal, operator, keyword, string literal, comma, semicolon

Differ format: longest-common-subsequence diff of token streams.

## What is intentionally NOT compared

- Whitespace, indentation, line breaks
- Numeric literal format (`0x10` vs `16` vs `0b10000`)
- Comment text (Python may emit `// trace exec_count=N`, Rust may differ)
- UIDF observation comments (`// → x0=0xff`) — these are debug aids, not semantic

## Tolerance

- LLIL pipeline should be deterministic on the same trace + same env. Any
  flakiness must be investigated, not papered over with "retry until pass."
- Hash-randomization in Rust HashMap should be controlled by using BTreeMap
  or sorted vec for any data structure that flows into a parity comparison.

## Where parity-test code lives

- `rust/crates/tracemiku-core/tests/parity/` — one file per pipeline stage
- One transient script `scripts/llil_parity_check.py` runs both sides on a
  synth trace fixture and prints any diff. Deleted at M7 cutover.
