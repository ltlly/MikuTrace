/** Wire contract: docs/superpowers/specs/2026-05-03-meta-endpoint-contract.md
 *  M1 hand-writes this; M3 will replace with openapi-typescript codegen. */
export interface ModuleInfo {
  name: string;
  base: string;
  size: number;
  end: string;
}

export interface MetaResponse {
  path: string;
  records: number;
  module: ModuleInfo | null;
  modules: ModuleInfo[];
  method: string;
  cmd: number | null;
  fn_addr: string | null;
  regs: string[];
}

// ── /api/records, /api/record/{idx} ───────────────────────────────────────

export interface RecordRow {
  idx: number;
  pc: string;
  rel: string | null;
  module: string | null;
  func: string | null;
  off: string | null;
  asm: string;
  annotation: string | null;
  exec_count: number | null;
  is_branch: boolean;
  is_call: boolean;
  is_ret: boolean;
  regs?: Record<string, string>;
}

export interface RecordsResponse {
  start: number;
  end: number;
  count: number;
  records: RecordRow[];
}

export interface RecordDetail {
  idx: number;
  pc: string;
  rel: string | null;
  func: string | null;
  off: string | null;
  asm: string;
  regs: Record<string, string>;
}

// ── /api/functions ───────────────────────────────────────────────────────

export interface FunctionEntry {
  id: string;
  name: string;
  source: string;
  entry_pc: number | null;
  blocks: number;
  records: number;
  trace_ir_id: string | null;
  bn_start: number | null;
  can_llil: boolean;
  can_bn_hlil: boolean;
}

export interface FunctionsResponse {
  counts: Record<string, number>;
  functions: FunctionEntry[];
}

// ── /api/strings ─────────────────────────────────────────────────────────

export interface StringEntry {
  addr: string;       // "0x7000"
  len: number;
  str: string;
}

export interface StringsResponse {
  status: string;     // "ready"
  count: number;
  cursor: number;     // -1 if no cursor filter
  strings: StringEntry[];
}

// ── /api/mem-dump ────────────────────────────────────────────────────────

export interface MemDumpByte {
  addr: string;
  byte: number | null;
  kind: string;       // "r" | "w" | "x" | "??"
  src_idx: number | null;
}

export interface MemDumpResponse {
  status: string;
  addr: string;
  count: number;
  bytes: MemDumpByte[];
}

// ── /api/call-tree ────────────────────────────────────────────────────────

export interface CallNode {
  fn?: string;          // omitted from wire when null/unknown
  /**
   * Static entry PC of callee (0 for root). Wire type is JSON number;
   * safe for ARM64 user-space PCs (under 2^48). If kernel-space PCs or
   * unusual ASLR slides ever push this past 2^53, switch both the Rust
   * serializer and this field to hex string (RecordRow.pc already does).
   */
  fn_pc: number;
  enter_idx: number;
  exit_idx: number;
  depth: number;
  children: CallNode[];
  truncated_children?: number;
}

export interface CallTreeResponse {
  tree: CallNode;
}
