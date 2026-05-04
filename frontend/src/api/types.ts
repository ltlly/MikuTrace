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

// ── /api/cfg-svg ─────────────────────────────────────────────────────────

export interface CfgSvgReadyResponse {
  status: "ready";
  svg: string;
  fn: string | null;
  block_count: number;
  total_block_count: number;
  cached: boolean;
}

export interface CfgSvgEmptyResponse {
  status: "empty";
  fn: string | null;
  svg: null;
}

export interface CfgSvgErrorResponse {
  status: "error";
  err: string;
}

export type CfgSvgResponse =
  | CfgSvgReadyResponse
  | CfgSvgEmptyResponse
  | CfgSvgErrorResponse;

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

// ── /api/idxs-touching-addr ─────────────────────────────────────────────

export interface TouchingAddrEntry {
  idx: number;
  kind: string;       // "r" | "w"
}

export interface TouchingAddrResponse {
  status: string;
  addr: string;
  cursor?: number;
  before: TouchingAddrEntry[];
  after: TouchingAddrEntry[];
  total_before: number;
  total_after: number;
}

export interface TouchingRangeResponse {
  status: string;
  addr: string;
  size: number;
  cursor: number;
  writers_before: number[];
  writers_after: number[];
  writers_total: number;
  readers_before: number[];
  readers_after: number[];
  readers_total: number;
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

// ── /api/mem-diff ────────────────────────────────────────────────────────

export interface MemDiffByte {
  addr: string;
  before: number | null;
  after: number | null;
  changed: boolean;
}

export interface MemDiffResponse {
  idx: number;
  addr: string;
  size: number;
  bytes: MemDiffByte[];
  changed_count: number;
}

// ── /api/idxs-for-pc ─────────────────────────────────────────────────────

export interface IdxsForPcResponse {
  status: string;
  pc: string;
  cursor: number;
  before: number[];
  after: number[];
  total_before: number;
  total_after: number;
  before_capped: boolean;
  after_capped: boolean;
}

// ── /api/search, /api/search-pc ──────────────────────────────────────────

export interface SearchHit {
  idx: number;
  pc: string;
  rel: string | null;
  func: string | null;
  off: string | null;
  asm: string;
}

export interface SearchResponse {
  count: number;
  pattern: string;
  hits: SearchHit[];
}

export interface SearchPcResponse {
  pc: string;
  count: number;
  idxs: number[];
  truncated: boolean;
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

// ── /api/backtrace ───────────────────────────────────────────────────────

export interface BacktraceFrame {
  call_site_idx: number;
  call_pc: string;
  call_pc_fmt: string | null;
  callee_pc: string | null;
  callee_pc_fmt: string | null;
  fn: string | null;
}

export interface BacktraceResponse {
  status: string;
  idx: number;
  stack: BacktraceFrame[];
  depth: number;
}

// ── /api/fork-events ─────────────────────────────────────────────────────

export interface ForkEvent {
  child_pid?: number;
  attach_status?: string;
  is_fork_like?: boolean;
  [key: string]: unknown;
}

export interface ForkEventsResponse {
  count: number;
  events: ForkEvent[];
}

// ── /api/forward-taint, /api/backward-taint ───────────────────────────────

export interface TaintRow {
  idx: number;
  pc: string;
  rel: string | null;
  func: string | null;
  asm: string;
  why?: string;     // forward
  via?: string;     // backward
  frame_depth?: number;   // present iff cross_fn_call=true was passed
}

export interface ForwardTaintResponse {
  count: number;
  from: number;
  reg: string;
  hits: TaintRow[];
  stopped_at_max: boolean;
  max_count_used: number;
}

export interface BackwardTaintResponse {
  count: number;
  from: number;
  reg: string;
  chain: TaintRow[];
  stopped_at_max: boolean;
  max_count_used: number;
}

// ── /api/dec/summary ──────────────────────────────────────────────────────

export interface DecFnEntry {
  id: string;
  name: string;
  blocks: number;
  loops: number;
  calls: number;
  type_anchors: number;
  entry_idx: number | null;
  exit_idx: number | null;
  source: string;          // "trace-ir" | "symbol" (M3-ε) | "bn" (M5+)
  trace_ir_id: string | null;
}

export interface DecSummaryResponse {
  records: number;
  module_name: string;
  module_base: number;
  module_size: number;
  truncated: boolean;
  fns: DecFnEntry[];
  vm_candidates: unknown[];
  summary_md: string;
}

export interface DecFnResponse {
  fn_id: string;
  name: string;
  tier: string;
  markdown: string;
}

export interface DecModelsResponse {
  models: string[];
  api_keys_configured: Record<string, boolean>;
}

export interface OpenApiResponse {
  openapi: string;
  info: {
    title: string;
    version: string;
  };
  paths: Record<string, unknown>;
}

export interface DecLlmCallPayload {
  fn_id: string;
  model: string;
  max_tokens: number;
  lang: string;
  tier: string;
}

export interface DecLlmCallResponse {
  ok: boolean;
  model: string;
  error: string | null;
  c_code: string | null;
  in_tokens: number | null;
  out_tokens: number | null;
  latency_ms: number | null;
  estimated_prompt_tokens: number;
  cache_hit: boolean;
}

export interface LlilRenderPayload {
  fn_id: string;
  max_records: number;
  ssa: boolean;
  constfold: boolean;
  flag_elim: boolean;
  dce: boolean;
}

export interface LlilRenderResponse {
  fn_id: string;
  name: string;
  records: number;
  truncated: boolean;
  lift_total: number;
  lift_intrinsic: number;
  lift_coverage: number;
  flag_elim_pairs: [string, string][];
  types: Record<string, string>;
  struct_shapes: unknown;
  var_names: Record<string, string>;
  uidf: unknown;
  structured: unknown;
  removed_pcs: string[];
  pseudocode: string;
}

// ── /api/hlil-for-fn ─────────────────────────────────────────────────────

export interface HlilFunctionInfo {
  name: string;
  start: number;
  end: number;
}

export interface HlilLine {
  pc: string;
  text: string;
  tokens: unknown[];
}

export interface HlilForFnResponse {
  ok: boolean;
  ready: boolean;
  fn?: HlilFunctionInfo;
  lines?: HlilLine[];
  vars?: unknown[];
  error?: string;
}
