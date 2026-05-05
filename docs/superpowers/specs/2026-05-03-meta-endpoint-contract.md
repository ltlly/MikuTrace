# /api/meta wire contract (frozen 2026-05-03 by M0)

`GET /api/meta` returns trace + module metadata. Used by the Solid SPA on page
load to populate the header strip and SO filter. This is now a Rust server
contract.

## Response schema (TypeScript notation)

```typescript
interface MetaResponse {
  /** Absolute path to the per-call trace dir on disk. */
  path: string;
  /** Total number of records in trace.bin. */
  records: number;
  /** Primary (first) module from the trace's meta.json. May be null on
   *  raw multi-SO traces with no primary designation. */
  module: ModuleInfo | null;
  /** All modules; primary is always entry [0]. May be empty list. */
  modules: ModuleInfo[];
  /** JNI method name (from per-call meta.json). Empty string if absent. */
  method: string;
  /** JNI cmd value (from per-call meta.json). null if absent. */
  cmd: number | null;
  /** Hex-formatted function entry PC, or null. */
  fn_addr: string | null;
  /** ARM64 register list in canonical order (x0..x30, fp, lr, sp, pc). */
  regs: string[];
}

interface ModuleInfo {
  /** SO/library name (basename, no path). */
  name: string;
  /** Module base PC, hex string with "0x" prefix. */
  base: string;
  /** Module size in bytes (raw int, NOT hex). */
  size: number;
  /** Module end PC = base + size, hex string with "0x" prefix. */
  end: string;
}
```

## Rust side: serde struct definitions

```rust
#[derive(serde::Serialize, Debug)]
pub struct MetaResponse {
    pub path: String,
    pub records: u64,
    pub module: Option<ModuleInfo>,
    pub modules: Vec<ModuleInfo>,
    pub method: String,
    pub cmd: Option<i64>,
    pub fn_addr: Option<String>,
    pub regs: Vec<&'static str>,
}

#[derive(serde::Serialize, Debug)]
pub struct ModuleInfo {
    pub name: String,
    pub base: String,    // hex with "0x"
    pub size: u64,
    pub end: String,     // hex with "0x"
}
```

## ARM64 register list (canonical order, baked constant)

```rust
pub const REG_NAMES: &[&str] = &[
    "x0","x1","x2","x3","x4","x5","x6","x7","x8","x9",
    "x10","x11","x12","x13","x14","x15","x16","x17","x18","x19",
    "x20","x21","x22","x23","x24","x25","x26","x27","x28",
    "fp","lr","sp","pc",
];
```

This must match the Rust core canonical register list and the frontend
`MetaResponse.regs` expectation.

## Per-call meta.json fields consumed

| Field | Type | Required | Source |
|---|---|---|---|
| `tid` | int | yes | per-call meta.json (capture-side) |
| `records` | int | yes | per-call meta.json |
| `ms` | int | yes | per-call meta.json |
| `retval` | hex string | no | per-call meta.json |
| `truncated` | bool | yes | per-call meta.json |
| `last_insn_is_ret` | bool | no | per-call meta.json |
| `known_offsets` | dict[hex_offset, fn_name] | no | per-call meta.json (used by SymbolMap, NOT by /api/meta) |

## Run-level meta.json fields consumed

| Field | Type | Required | Source |
|---|---|---|---|
| `pkg` | string | no | run-level meta.json |
| `so` | string | no | run-level meta.json |
| `method` | string | no | run-level meta.json (→ MetaResponse.method) |
| `cmd` | int | no | run-level meta.json (→ MetaResponse.cmd) |
| `module` | ModuleInfo | no | run-level meta.json (→ MetaResponse.module) |
| `modules` | list[ModuleInfo] | no | run-level meta.json (→ MetaResponse.modules) |
| `fn_addr` | hex string | no | run-level meta.json (→ MetaResponse.fn_addr) |

## Error cases

- `path` does not exist → 404
- `meta.json` missing or malformed → 500 with `{detail: "..."}`

(Other endpoints have their own contracts written when their plan is
authored; this doc covers ONLY `/api/meta`.)
