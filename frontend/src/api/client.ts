import type {
  MetaResponse,
  SoStatsResponse,
  RecordsResponse,
  RecordDetail,
  FunctionsResponse,
  StringsResponse,
  StringProvenanceResponse,
  TouchingAddrResponse,
  TouchingRangeResponse,
  MemDumpResponse,
  MemDiffResponse,
  IdxsForPcResponse,
  OpenApiResponse,
  BgStatusResponse,
  DecompStatusResponse,
  MemWritesInRangeResponse,
  BlockForPcResponse,
  IdxsForBlockResponse,
  SearchPcResponse,
  TraceQueryKind,
  TraceQueryResponse,
  SearchResponse,
  RegValueAtResponse,
  LastWriteOfRegResponse,
  NextUseOfRegResponse,
  WatchpointKind,
  WatchpointsResponse,
  CallTreeResponse,
  BacktraceResponse,
  ForkEventsResponse,
  ForwardTaintResponse,
  BackwardTaintResponse,
  HlilForFnResponse,
  HlilForPcResponse,
  AsmTokensResponse,
  CfgSvgResponse,
  BnCfgSvgForPcResponse,
  CryptoAnalysisResponse,
} from "./types";

// ---------------------------------------------------------------------------
// API debug logger
//
// Toggle: localStorage.setItem("tracemiku-api-debug", "1") (or use the dev
// overlay's "log API calls" checkbox). When on, every API request is logged
// to the console with method, URL, sequence number, status, duration, and
// (where available) byte size or abort/error reason. Off by default — zero
// runtime cost beyond a localStorage read per request.
// ---------------------------------------------------------------------------

let __apiSeq = 0;

function apiDebugEnabled(): boolean {
  try {
    return typeof localStorage !== "undefined" && localStorage.getItem("tracemiku-api-debug") === "1";
  } catch {
    return false;
  }
}

async function fx(input: string, init?: RequestInit): Promise<Response> {
  const dbg = apiDebugEnabled();
  const seq = ++__apiSeq;
  const t0 = performance.now();
  const method = (init?.method ?? "GET").toUpperCase();
  if (dbg) console.log(`[api #${seq}] -> ${method} ${input}`);
  try {
    const r = await fetch(input, init);
    const dt = performance.now() - t0;
    if (dbg) {
      const cl = r.headers.get("content-length");
      console.log(
        `[api #${seq}] <- ${r.status} ${method} ${input} ${dt.toFixed(0)}ms${cl ? " " + cl + "B" : ""}`,
      );
    }
    return r;
  } catch (err) {
    const dt = performance.now() - t0;
    const aborted = (err as { name?: string } | null)?.name === "AbortError";
    if (dbg) {
      const fn = aborted ? console.warn : console.error;
      fn(
        `[api #${seq}] x ${method} ${input} ${dt.toFixed(0)}ms ${aborted ? "aborted" : String(err)}`,
      );
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// 通用请求层：所有 fetcher 收敛到 apiGet/apiPost，统一
// 「拼 query → fx → !ok throw → r.json() → 回显 request_*」五段式。
// echo 显式声明要盖在响应上的请求回显字段（request_pc 等），
// 供面板做 isCurrent 一致性校验。
// ---------------------------------------------------------------------------

async function apiGet<T extends object>(
  path: string,
  params?: URLSearchParams,
  echo?: Partial<T>,
  signal?: AbortSignal,
): Promise<T> {
  const qs = params?.toString();
  const r = await fx(`${path}${qs ? "?" + qs : ""}`, { signal });
  if (!r.ok) throw new Error(`${path} returned ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as T;
  return echo ? Object.assign(out, echo) : out;
}

async function apiPost<T extends object>(path: string, body: unknown): Promise<T> {
  const r = await fx(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${path} returned ${r.status}: ${await r.text()}`);
  return (await r.json()) as T;
}

export async function fetchMeta(): Promise<MetaResponse> {
  return apiGet<MetaResponse>("/api/meta");
}

export async function fetchSoStats(top = 200, all = false): Promise<SoStatsResponse> {
  const params = new URLSearchParams({ top: String(top), all: String(all) });
  return apiGet<SoStatsResponse>("/api/so-stats", params);
}

export interface FetchRecordsOpts {
  start?: number;
  count?: number;
  regs?: string;
  signal?: AbortSignal;
}

export async function fetchRecords(opts: FetchRecordsOpts = {}): Promise<RecordsResponse> {
  const params = new URLSearchParams();
  if (opts.start !== undefined) params.set("start", String(opts.start));
  if (opts.count !== undefined) params.set("count", String(opts.count));
  if (opts.regs) params.set("regs", opts.regs);
  return apiGet<RecordsResponse>(
    "/api/records",
    params,
    {
      request_start: opts.start ?? 0,
      request_count: opts.count ?? 100,
    },
    opts.signal,
  );
}

export async function fetchRecord(idx: number, signal?: AbortSignal): Promise<RecordDetail> {
  return apiGet<RecordDetail>(`/api/record/${idx}`, undefined, undefined, signal);
}

export async function fetchFunctions(): Promise<FunctionsResponse> {
  return apiGet<FunctionsResponse>("/api/functions");
}

export interface FetchCfgSvgOpts {
  fnName?: string;
  pc?: string;
  localDepth?: number;
  timeout?: number;
  force?: boolean;
  signal?: AbortSignal;
}

export async function fetchCfgSvg(opts: FetchCfgSvgOpts = {}): Promise<CfgSvgResponse> {
  const params = new URLSearchParams();
  if (opts.fnName) params.set("fn", opts.fnName);
  if (opts.pc) params.set("pc", opts.pc);
  if (opts.localDepth !== undefined) params.set("local_depth", String(opts.localDepth));
  if (opts.timeout !== undefined) params.set("timeout", String(opts.timeout));
  if (opts.force) params.set("force", "true");
  return apiGet<CfgSvgResponse>("/api/cfg-svg", params, undefined, opts.signal);
}

export async function fetchBnCfgSvgForPc(
  pc: string,
  mode = "asm",
  timeout = 30,
  signal?: AbortSignal,
): Promise<BnCfgSvgForPcResponse> {
  const params = new URLSearchParams({ pc, mode, timeout: String(timeout) });
  return apiGet<BnCfgSvgForPcResponse>(
    "/api/bn-cfg-svg-for-pc",
    params,
    { request_pc: pc, request_mode: mode },
    signal,
  );
}

export async function fetchAsmTokensForPcs(
  pcs: string[],
  signal?: AbortSignal,
): Promise<AsmTokensResponse> {
  const unique = [...new Set(pcs.filter(Boolean))];
  const params = new URLSearchParams({ pcs: unique.join(",") });
  return apiGet<AsmTokensResponse>(
    "/api/asm-tokens-for-pcs",
    params,
    { request_pcs: unique },
    signal,
  );
}

export async function fetchStrings(
  minLen = 4,
  q = "",
  limit = 500,
  cursor = -1,
  signal?: AbortSignal,
): Promise<StringsResponse> {
  const params = new URLSearchParams({ min_len: String(minLen) });
  if (q) params.set("q", q);
  if (limit > 0) params.set("limit", String(limit));
  if (cursor >= 0) params.set("cursor", String(cursor));
  return apiGet<StringsResponse>(
    "/api/strings",
    params,
    {
      request_min_len: minLen,
      request_q: q,
      request_limit: limit,
      request_cursor: cursor,
    },
    signal,
  );
}

export async function fetchStringProvenance(
  addr: string,
  length = 64,
  signal?: AbortSignal,
): Promise<StringProvenanceResponse> {
  const params = new URLSearchParams({ addr, length: String(length) });
  return apiGet<StringProvenanceResponse>("/api/string-provenance", params, undefined, signal);
}

export async function fetchIdxsTouchingAddr(
  addr: string,
  cursor = 0,
  limit = 30,
): Promise<TouchingAddrResponse> {
  const params = new URLSearchParams({
    addr,
    cursor: String(cursor),
    limit: String(limit),
  });
  return apiGet<TouchingAddrResponse>("/api/idxs-touching-addr", params);
}

export async function fetchIdxsTouchingRange(
  addr: string,
  size = 1,
  cursor = 0,
  limit = 30,
  signal?: AbortSignal,
): Promise<TouchingRangeResponse> {
  const params = new URLSearchParams({
    addr,
    size: String(size),
    cursor: String(cursor),
    limit: String(limit),
  });
  return apiGet<TouchingRangeResponse>(
    "/api/idxs-touching-range",
    params,
    {
      request_addr: addr,
      request_size: size,
      request_cursor: cursor,
      request_limit: limit,
    },
    signal,
  );
}

export async function fetchMemDump(
  addr: string,
  count = 128,
  signal?: AbortSignal,
): Promise<MemDumpResponse> {
  const params = new URLSearchParams({ addr, count: String(count) });
  return apiGet<MemDumpResponse>(
    "/api/mem-dump",
    params,
    { request_addr: addr, request_count: count },
    signal,
  );
}

export async function fetchMemDiff(
  idx: number,
  addr: string,
  size = 16,
  signal?: AbortSignal,
): Promise<MemDiffResponse> {
  const params = new URLSearchParams({
    idx: String(idx),
    addr,
    size: String(size),
  });
  return apiGet<MemDiffResponse>(
    "/api/mem-diff",
    params,
    { request_idx: idx, request_addr: addr, request_size: size },
    signal,
  );
}

export async function fetchIdxsForPc(
  pc: string,
  cursor = 0,
  limit = 30,
  signal?: AbortSignal,
): Promise<IdxsForPcResponse> {
  const params = new URLSearchParams({
    pc,
    cursor: String(cursor),
    limit: String(limit),
  });
  return apiGet<IdxsForPcResponse>(
    "/api/idxs-for-pc",
    params,
    { request_pc: pc, request_cursor: cursor, request_limit: limit },
    signal,
  );
}

export async function fetchSearch(
  pattern: string,
  maxResults = 200,
  signal?: AbortSignal,
  cursor?: number,
): Promise<SearchResponse> {
  const params = new URLSearchParams({
    pattern,
    max_results: String(maxResults),
  });
  if (cursor !== undefined) params.set("cursor", String(cursor));
  return apiGet<SearchResponse>(
    "/api/search",
    params,
    {
      request_pattern: pattern,
      request_max_results: maxResults,
      request_cursor: cursor,
    },
    signal,
  );
}

export async function fetchSearchPc(
  pc: string,
  limit = 50,
  signal?: AbortSignal,
): Promise<SearchPcResponse> {
  const params = new URLSearchParams({
    pc,
    limit: String(limit),
  });
  return apiGet<SearchPcResponse>(
    "/api/search-pc",
    params,
    { request_pc: pc, request_limit: limit },
    signal,
  );
}

export interface FetchTraceQueryOpts {
  kind: TraceQueryKind;
  q?: string;
  idx?: number;
  reg?: string;
  addr?: string;
  len?: number;
  limit?: number;
  signal?: AbortSignal;
}

export async function fetchTraceQuery(opts: FetchTraceQueryOpts): Promise<TraceQueryResponse> {
  const params = new URLSearchParams({ kind: opts.kind });
  if (opts.q) params.set("q", opts.q);
  if (opts.idx !== undefined) params.set("idx", String(opts.idx));
  if (opts.reg) params.set("reg", opts.reg);
  if (opts.addr) params.set("addr", opts.addr);
  if (opts.len !== undefined) params.set("len", String(opts.len));
  if (opts.limit !== undefined) params.set("limit", String(opts.limit));
  return apiGet<TraceQueryResponse>(
    "/api/query",
    params,
    {
      request_kind: opts.kind,
      request_q: opts.q ?? "",
      request_idx: opts.idx,
      request_reg: opts.reg,
      request_addr: opts.addr,
      request_len: opts.len,
      request_limit: opts.limit,
    },
    opts.signal,
  );
}

export async function fetchRegValueAt(
  idx: number,
  reg: string,
  signal?: AbortSignal,
): Promise<RegValueAtResponse> {
  const params = new URLSearchParams({ idx: String(idx), reg });
  return apiGet<RegValueAtResponse>("/api/reg-value-at", params, undefined, signal);
}

export async function fetchLastWriteOfReg(
  before: number,
  reg: string,
  signal?: AbortSignal,
): Promise<LastWriteOfRegResponse> {
  const params = new URLSearchParams({ before: String(before), reg });
  return apiGet<LastWriteOfRegResponse>("/api/last-write-of-reg", params, undefined, signal);
}

export async function fetchNextUseOfReg(
  after: number,
  reg: string,
  signal?: AbortSignal,
): Promise<NextUseOfRegResponse> {
  const params = new URLSearchParams({ after: String(after), reg });
  return apiGet<NextUseOfRegResponse>("/api/next-use-of-reg", params, undefined, signal);
}

export interface FetchWatchpointsOpts {
  kind: WatchpointKind;
  reg?: string;
  addr?: string;
  value?: string;
  size?: number;
  cursor?: number;
  limit?: number;
  signal?: AbortSignal;
}

export async function fetchWatchpoints(opts: FetchWatchpointsOpts): Promise<WatchpointsResponse> {
  const params = new URLSearchParams({ kind: opts.kind });
  if (opts.reg) params.set("reg", opts.reg);
  if (opts.addr) params.set("addr", opts.addr);
  if (opts.value) params.set("value", opts.value);
  if (opts.size !== undefined) params.set("size", String(opts.size));
  if (opts.cursor !== undefined) params.set("cursor", String(opts.cursor));
  if (opts.limit !== undefined) params.set("limit", String(opts.limit));
  return apiGet<WatchpointsResponse>("/api/watchpoints", params, undefined, opts.signal);
}

export async function fetchCallTree(maxDepth = 10, signal?: AbortSignal): Promise<CallTreeResponse> {
  const params = new URLSearchParams({ max_depth: String(maxDepth) });
  return apiGet<CallTreeResponse>(
    "/api/call-tree",
    params,
    { request_max_depth: maxDepth },
    signal,
  );
}

export async function fetchBacktrace(idx: number, limit = 256): Promise<BacktraceResponse> {
  const params = new URLSearchParams({ idx: String(idx), limit: String(limit) });
  return apiGet<BacktraceResponse>(
    "/api/backtrace",
    params,
    { request_limit: limit },
  );
}

export async function fetchForkEvents(status = "", limit = 1000): Promise<ForkEventsResponse> {
  const params = new URLSearchParams();
  if (status) params.set("status", status);
  params.set("limit", String(limit));
  return apiGet<ForkEventsResponse>(
    "/api/fork-events",
    params,
    { request_status: status, request_limit: limit },
  );
}

export interface TaintFlags {
  through_mem?: boolean;
  data_only?: boolean;
  cross_fn_call?: boolean;
}

function taintParams(
  traceIdx: number,
  reg: string,
  maxCount: number,
  flags: TaintFlags,
): URLSearchParams {
  const params = new URLSearchParams({
    trace_idx: String(traceIdx),
    reg,
    max_count: String(maxCount),
  });
  if (flags.through_mem) params.set("through_mem", "true");
  if (flags.data_only) params.set("data_only", "true");
  if (flags.cross_fn_call) params.set("cross_fn_call", "true");
  return params;
}

export async function fetchForwardTaint(
  traceIdx: number,
  reg: string,
  maxCount = 200,
  flags: TaintFlags = {},
  signal?: AbortSignal,
): Promise<ForwardTaintResponse> {
  return apiGet<ForwardTaintResponse>(
    "/api/forward-taint",
    taintParams(traceIdx, reg, maxCount, flags),
    undefined,
    signal,
  );
}

export async function fetchBackwardTaint(
  traceIdx: number,
  reg: string,
  maxCount = 200,
  flags: TaintFlags = {},
  signal?: AbortSignal,
): Promise<BackwardTaintResponse> {
  return apiGet<BackwardTaintResponse>(
    "/api/backward-taint",
    taintParams(traceIdx, reg, maxCount, flags),
    undefined,
    signal,
  );
}

export async function fetchOpenApi(): Promise<OpenApiResponse> {
  return apiGet<OpenApiResponse>("/openapi.json");
}

export async function fetchBgStatus(): Promise<BgStatusResponse> {
  return apiGet<BgStatusResponse>("/api/bg-status");
}

export async function fetchDecompStatus(): Promise<DecompStatusResponse> {
  return apiGet<DecompStatusResponse>("/api/decomp-status");
}

export interface FetchMemWritesInRangeOpts {
  idxLo: number;
  idxHi?: number;
  srcByte?: string;
  addrLo?: string;
  addrHi?: string;
  max?: number;
  signal?: AbortSignal;
}

export async function fetchMemWritesInRange(
  opts: FetchMemWritesInRangeOpts,
): Promise<MemWritesInRangeResponse> {
  const params = new URLSearchParams({ idx_lo: String(opts.idxLo) });
  if (opts.idxHi !== undefined) params.set("idx_hi", String(opts.idxHi));
  if (opts.srcByte) params.set("src_byte", opts.srcByte);
  if (opts.addrLo) params.set("addr_lo", opts.addrLo);
  if (opts.addrHi) params.set("addr_hi", opts.addrHi);
  if (opts.max !== undefined) params.set("max", String(opts.max));
  return apiGet<MemWritesInRangeResponse>("/api/mem-writes-in-range", params, undefined, opts.signal);
}

export async function fetchBlockForPc(pc: string): Promise<BlockForPcResponse> {
  const params = new URLSearchParams({ pc });
  return apiGet<BlockForPcResponse>("/api/block-for-pc", params);
}

export async function fetchIdxsForBlock(
  pc: string,
  maxCount = 1,
  near?: number,
): Promise<IdxsForBlockResponse> {
  const params = new URLSearchParams({ pc, max_count: String(maxCount) });
  if (near !== undefined) params.set("near", String(near));
  return apiGet<IdxsForBlockResponse>("/api/idxs-for-block", params);
}

export async function fetchHlilForFn(fnId: string): Promise<HlilForFnResponse> {
  const params = new URLSearchParams({ fn_id: fnId });
  return apiGet<HlilForFnResponse>(
    "/api/hlil-for-fn",
    params,
    { request_fn_id: fnId },
  );
}

export async function fetchHlilForPc(
  pc: string,
  signal?: AbortSignal,
): Promise<HlilForPcResponse> {
  const params = new URLSearchParams({ pc });
  return apiGet<HlilForPcResponse>(
    "/api/hlil-for-pc",
    params,
    { request_pc: pc },
    signal,
  );
}

// ---------------------------------------------------------------------------
// Slice / forward-dep-tree (peer-trace-tools-style backward + forward DAGs)
// ---------------------------------------------------------------------------

export interface BfsSliceSeed {
  kind: "idx" | "reg" | "addr" | "none";
  idx: number | null;
  reg: string | null;
  addr: string | null;
  before: number | null;
  note: string | null;
}

export interface BfsSliceEdgeStats {
  reg: number;
  address: number;
  mem: number;
  control: number;
  total: number;
}

export interface DepNode {
  id: string;
  idx: number;
  depth: number;
  pc: string;
  func: string | null;
  asm: string;
  via: string;
  expression: string;
}

export interface BfsSliceResponse {
  status: "ready" | "error";
  seed: BfsSliceSeed;
  seeds: BfsSliceSeed[];
  slice: number[];
  /// First N rows of `slice` enriched with pc/asm/func; capped server-side.
  rows: DepNode[];
  rows_capped: boolean;
  slice_count: number;
  truncated: boolean;
  node_limit: number;
  data_only: boolean;
  edge_stats: BfsSliceEdgeStats;
  mode: "union" | "intersection";
}

interface SeedQueryOpts {
  idx?: number;
  idxs?: readonly number[];
  reg?: string;
  regs?: readonly string[];
  addr?: string;
  addrs?: readonly string[];
  before?: number;
  dataOnly?: boolean;
  limit?: number;
}

function appendSeedQueryParams(params: URLSearchParams, opts: SeedQueryOpts): URLSearchParams {
  if (opts.idx !== undefined) params.set("idx", String(opts.idx));
  if (opts.idxs && opts.idxs.length > 0) params.set("idxs", opts.idxs.join(","));
  if (opts.reg) params.set("reg", opts.reg);
  if (opts.regs && opts.regs.length > 0) params.set("regs", opts.regs.join(","));
  if (opts.addr) params.set("addr", opts.addr);
  if (opts.addrs && opts.addrs.length > 0) params.set("addrs", opts.addrs.join(","));
  if (opts.before !== undefined) params.set("before", String(opts.before));
  if (opts.dataOnly) params.set("data_only", "true");
  if (opts.limit !== undefined) params.set("limit", String(opts.limit));
  return params;
}

export interface FetchBfsSliceOpts extends SeedQueryOpts {
  mode?: "union" | "intersection";
  signal?: AbortSignal;
}

export async function fetchBfsSlice(opts: FetchBfsSliceOpts = {}): Promise<BfsSliceResponse> {
  const params = appendSeedQueryParams(new URLSearchParams(), opts);
  if (opts.mode) params.set("mode", opts.mode);
  return apiGet<BfsSliceResponse>("/api/bfs-slice", params, undefined, opts.signal);
}

export type ForwardDepTreeNode = DepNode;

export interface ForwardDepTreeEdge {
  from: string;
  to: string;
  kind: "reg" | "addr" | "mem" | "control";
  label: string;
}

export interface ForwardDepTreeResponse {
  status: "ready" | "error";
  seed: BfsSliceSeed;
  graph: {
    nodes: ForwardDepTreeNode[];
    edges: ForwardDepTreeEdge[];
    node_count: number;
    edge_count: number;
    hidden_edges: number;
    truncated: boolean;
    depth_limit: number;
    node_limit: number;
    data_only: boolean;
  };
}

export interface FetchForwardDepTreeOpts extends SeedQueryOpts {
  depth?: number;
  signal?: AbortSignal;
}

export async function fetchForwardDepTree(
  opts: FetchForwardDepTreeOpts = {},
): Promise<ForwardDepTreeResponse> {
  const params = appendSeedQueryParams(new URLSearchParams(), opts);
  if (opts.depth !== undefined) params.set("depth", String(opts.depth));
  return apiGet<ForwardDepTreeResponse>("/api/forward-dep-tree", params, undefined, opts.signal);
}

export async function fetchCryptoAnalysis(): Promise<CryptoAnalysisResponse> {
  return apiGet<CryptoAnalysisResponse>("/api/crypto-analysis");
}

// 保留 JSON POST 统一入口（服务端 /api/hash-input-search、/api/diff-traces
// 为 POST 路由）；前端 fetcher 尚未接入这两个端点。
export { apiPost };
