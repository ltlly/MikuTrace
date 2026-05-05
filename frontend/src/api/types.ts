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

// ── /api/so-stats ────────────────────────────────────────────────────────

export interface SoStatsModule {
  name: string;
  base: string;
  end: string;
  size: number;
  records: number;
  percent: number;
}

export interface SoStatsResponse {
  records: number;
  modules_total: number;
  unknown_records: number;
  unknown_percent: number;
  modules: SoStatsModule[];
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
  returned?: number;
  requested_count?: number;
  max_count_used?: number;
  truncated?: boolean;
  request_start?: number;
  request_count?: number;
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
  prev_regs?: Record<string, string> | null;
  regs_annotated?: Record<string, string>;
  regs_def?: string[];
  regs_use?: string[];
  exec_count?: number | null;
  block_pc?: string | null;
  cfg_status?: string;
  is_branch?: boolean;
  is_call?: boolean;
  is_ret?: boolean;
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

export interface CfgSvgLargeResponse {
  status: "large";
  fn: string | null;
  svg: string | null;
  block_count: number;
  edge_count: number;
  total_block_count: number;
  dot_bytes: number;
}

export type CfgSvgResponse =
  | CfgSvgReadyResponse
  | CfgSvgEmptyResponse
  | CfgSvgErrorResponse
  | CfgSvgLargeResponse;

// ── /api/asm-tokens-for-pcs ──────────────────────────────────────────────

export interface AsmToken {
  t: string;
  c: string;
  a?: string | null;
}

export interface AsmTokensResponse {
  ready: boolean;
  status: string;
  tokens: Record<string, AsmToken[]>;
  error?: string | null;
  request_pcs?: string[];
}

// ── /api/bn-cfg-svg-for-pc ───────────────────────────────────────────────

export interface BnCfgFunctionInfo {
  name: string;
  start: number | string;
  end: number | string;
}

export interface BnCfgSvgForPcResponse {
  ok: boolean;
  ready: boolean;
  svg: string;
  error?: unknown;
  status?: string;
  pc?: string;
  mode?: string;
  fn?: BnCfgFunctionInfo | null;
  block_count?: number;
  edge_count?: number;
  dyn_only_count?: number;
  fn_total_exec?: number;
  request_pc?: string;
  request_mode?: string;
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
  returned: number;
  truncated: boolean;
  cursor: number;     // -1 if no cursor filter
  strings: StringEntry[];
  request_min_len?: number;
  request_q?: string;
  request_limit?: number;
  request_cursor?: number;
}

// ── /api/string-provenance ──────────────────────────────────────────────

export interface StringProvByte {
  addr: string;
  byte: number | null;
  kind: string;
  writers: number[];
  readers: number[];
  writers_total: number;
  readers_total: number;
}

export interface StringProvenanceResponse {
  status: string;
  addr: string;
  length: number;
  bytes: StringProvByte[];
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
  request_addr?: string;
  request_size?: number;
  request_cursor?: number;
  request_limit?: number;
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
  request_addr?: string;
  request_count?: number;
}

// ── /api/mem-diff ────────────────────────────────────────────────────────

export interface MemDiffByte {
  addr: string;
  before: number | null;
  after: number | null;
  changed: boolean;
}

export interface MemDiffResponse {
  status: string;
  idx: number;
  addr: string;
  size: number;
  bytes: MemDiffByte[];
  changed_count: number;
  request_idx?: number;
  request_addr?: string;
  request_size?: number;
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
  request_pc?: string;
  request_cursor?: number;
  request_limit?: number;
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
  returned?: number;
  total_matches?: number;
  truncated?: boolean;
  max_results_used?: number;
  pattern: string;
  cursor?: number;
  hits: SearchHit[];
  request_pattern?: string;
  request_max_results?: number;
  request_cursor?: number;
}

export interface SearchPcResponse {
  pc: string;
  count: number;
  idxs: number[];
  truncated: boolean;
  request_pc?: string;
  request_limit?: number;
}

// ── /api/reg-value-at, /api/last-write-of-reg ────────────────────────────

export interface RegValueAtResponse {
  status: string;
  idx: number;
  reg: string;
  value: string | null;
  annotation?: string;
  error?: string;
}

export interface LastWriteOfRegResponse {
  status?: string;
  idx: number | null;
  value?: string | null;
  err?: string;
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
  request_max_depth?: number;
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
  returned?: number;
  truncated?: boolean;
  request_limit?: number;
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
  returned?: number;
  truncated?: boolean;
  events: ForkEvent[];
  request_status?: string;
  request_limit?: number;
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
  edge_kind?: string;
  parent_idxs?: number[];
  taint_depth?: number;
  frame_depth?: number;   // present iff cross_fn_call=true was passed
}

export interface ForwardTaintResponse {
  status: string;
  count: number;
  from: number;
  reg: string;
  hits: TaintRow[];
  stopped_at_max: boolean;
  max_count_used: number;
}

export interface BackwardTaintResponse {
  status: string;
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
  request_split_top_k?: number;
  request_split_min_records?: number;
  request_with_memshadow?: boolean;
}

export interface DecFnResponse {
  fn_id: string;
  name: string;
  tier: string;
  markdown: string;
  request_fn_id?: string;
  request_tier?: string;
  request_split_top_k?: number;
  request_split_min_records?: number;
  request_with_memshadow?: boolean;
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

// ── /api/bg-status, /api/decomp-status ───────────────────────────────────

export interface BgTaskStatus {
  status: string;
  started_at?: number | null;
  ready_at?: number | null;
  err?: string | null;
  [key: string]: unknown;
}

export interface DecompStatusResponse {
  status: string;
  name?: string | null;
  err?: string | null;
  started_at?: number | null;
  ready_at?: number | null;
  so_path?: string | null;
  elapsed?: number | null;
}

export interface ParallelismStatus {
  available: number;
  records: number;
  workers: {
    index: number;
    symbols: number;
    cfg: number;
    memshadow: number;
    reg_timeline: number;
    jni_calls: number;
    [key: string]: number;
  };
  env?: Record<string, string | null>;
}

export interface BgStatusResponse {
  cfg: BgTaskStatus;
  pc_inst: BgTaskStatus;
  pc_to_block: BgTaskStatus;
  block_idxs: BgTaskStatus;
  index: BgTaskStatus;
  mem: BgTaskStatus;
  decomp: DecompStatusResponse;
  parallelism?: ParallelismStatus;
  [key: string]: BgTaskStatus | DecompStatusResponse | ParallelismStatus | undefined;
}

// ── /api/mem-writes-in-range ─────────────────────────────────────────────

export interface MemWriteRow {
  idx: number;
  pc: string;
  rel: string | null;
  func: string | null;
  asm: string;
  dst_addr: string;
  size: number;
  src_reg: string | null;
  src_value: string;
  byte0: number;
}

export interface MemWritesInRangeResponse {
  idx_range: number[];
  matched: number;
  returned: number;
  truncated: boolean;
  writes: MemWriteRow[];
  status?: string | null;
}

// ── CFG navigation helpers ───────────────────────────────────────────────

export interface BlockForPcResponse {
  pc: string;
  block: string | null;
  cfg_status?: string | null;
}

export interface IdxsForBlockResponse {
  status: string;
  idxs: number[];
}

export interface DecLlmCallPayload {
  fn_id: string;
  model: string;
  max_tokens: number;
  lang: string;
  tier: string;
  with_memshadow?: boolean;
  split_top_k?: number;
  split_min_records?: number;
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

export interface LlilLlmPayload {
  fn_id: string;
  model: string;
  max_tokens: number;
  lang: string;
  max_records: number;
}

export interface LlilLlmResponse {
  ok: boolean;
  fn_id: string;
  model: string;
  error: string | null;
  c_code: string;
  in_tokens: number;
  out_tokens: number;
  latency_ms: number;
  llil_records: number;
  estimated_prompt_tokens: number;
}

// ── /api/hlil-for-fn ─────────────────────────────────────────────────────

export interface HlilFunctionInfo {
  name: string;
  start: number | string;
  end: number | string;
}

export interface HlilLine {
  pc: string;
  text: string;
  indent?: number;
  tokens?: AsmToken[] | null;
}

export interface HlilVar {
  name?: string;
  type?: string;
  type_name?: string;
  storage?: string;
  [key: string]: unknown;
}

export interface HlilTraceFnInfo {
  name: string;
  off?: string;
}

export interface HlilForFnResponse {
  ok: boolean;
  ready: boolean;
  fn?: HlilFunctionInfo;
  lines?: HlilLine[];
  vars?: HlilVar[];
  error?: string;
  request_fn_id?: string;
}

export interface HlilForPcResponse extends HlilForFnResponse {
  pc?: string;
  status?: string;
  backend?: string;
  in_range?: boolean;
  current_line_idx?: number;
  trace_fn?: HlilTraceFnInfo | null;
  request_pc?: string;
}
