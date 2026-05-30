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
  DecFnResponse,
  DecLlmCallPayload,
  DecLlmCallResponse,
  DecModelsResponse,
  DecSummaryResponse,
  LlilRenderPayload,
  LlilRenderResponse,
  LlilLlmPayload,
  LlilLlmResponse,
  HlilForFnResponse,
  HlilForPcResponse,
  LlilPipelinePayload,
  PipelineResponse,
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

export async function fetchMeta(): Promise<MetaResponse> {
  const r = await fx("/api/meta");
  if (!r.ok) {
    throw new Error(`/api/meta returned ${r.status}: ${await r.text()}`);
  }
  return (await r.json()) as MetaResponse;
}

export async function fetchSoStats(top = 200, all = false): Promise<SoStatsResponse> {
  const params = new URLSearchParams({ top: String(top), all: String(all) });
  const r = await fx(`/api/so-stats?${params}`);
  if (!r.ok) throw new Error(`/api/so-stats returned ${r.status}: ${await r.text()}`);
  return (await r.json()) as SoStatsResponse;
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
  const qs = params.toString();
  const r = await fx(`/api/records${qs ? "?" + qs : ""}`, { signal: opts.signal });
  if (!r.ok) throw new Error(`/api/records returned ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as RecordsResponse;
  out.request_start = opts.start ?? 0;
  out.request_count = opts.count ?? 100;
  return out;
}

export async function fetchRecord(idx: number, signal?: AbortSignal): Promise<RecordDetail> {
  const r = await fx(`/api/record/${idx}`, { signal });
  if (!r.ok) throw new Error(`/api/record/${idx} returned ${r.status}: ${await r.text()}`);
  return (await r.json()) as RecordDetail;
}

export async function fetchFunctions(): Promise<FunctionsResponse> {
  const r = await fx("/api/functions");
  if (!r.ok) throw new Error(`/api/functions returned ${r.status}: ${await r.text()}`);
  return (await r.json()) as FunctionsResponse;
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
  const qs = params.toString();
  const r = await fx(`/api/cfg-svg${qs ? "?" + qs : ""}`, { signal: opts.signal });
  if (!r.ok) throw new Error(`/api/cfg-svg returned ${r.status}: ${await r.text()}`);
  return (await r.json()) as CfgSvgResponse;
}

export async function fetchBnCfgSvgForPc(
  pc: string,
  mode = "asm",
  timeout = 30,
  signal?: AbortSignal,
): Promise<BnCfgSvgForPcResponse> {
  const params = new URLSearchParams({ pc, mode, timeout: String(timeout) });
  const r = await fx(`/api/bn-cfg-svg-for-pc?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/bn-cfg-svg-for-pc ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as BnCfgSvgForPcResponse;
  out.request_pc = pc;
  out.request_mode = mode;
  return out;
}

export async function fetchAsmTokensForPcs(
  pcs: string[],
  signal?: AbortSignal,
): Promise<AsmTokensResponse> {
  const unique = [...new Set(pcs.filter(Boolean))];
  const params = new URLSearchParams({ pcs: unique.join(",") });
  const r = await fx(`/api/asm-tokens-for-pcs?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/asm-tokens-for-pcs ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as AsmTokensResponse;
  out.request_pcs = unique;
  return out;
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
  const r = await fx(`/api/strings?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/strings ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as StringsResponse;
  out.request_min_len = minLen;
  out.request_q = q;
  out.request_limit = limit;
  out.request_cursor = cursor;
  return out;
}

export async function fetchStringProvenance(
  addr: string,
  length = 64,
  signal?: AbortSignal,
): Promise<StringProvenanceResponse> {
  const params = new URLSearchParams({ addr, length: String(length) });
  const r = await fx(`/api/string-provenance?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/string-provenance ${r.status}: ${await r.text()}`);
  return (await r.json()) as StringProvenanceResponse;
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
  const r = await fx(`/api/idxs-touching-addr?${params}`);
  if (!r.ok) throw new Error(`/api/idxs-touching-addr ${r.status}: ${await r.text()}`);
  return (await r.json()) as TouchingAddrResponse;
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
  const r = await fx(`/api/idxs-touching-range?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/idxs-touching-range ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as TouchingRangeResponse;
  out.request_addr = addr;
  out.request_size = size;
  out.request_cursor = cursor;
  out.request_limit = limit;
  return out;
}

export async function fetchMemDump(
  addr: string,
  count = 128,
  signal?: AbortSignal,
): Promise<MemDumpResponse> {
  const params = new URLSearchParams({ addr, count: String(count) });
  const r = await fx(`/api/mem-dump?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/mem-dump ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as MemDumpResponse;
  out.request_addr = addr;
  out.request_count = count;
  return out;
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
  const r = await fx(`/api/mem-diff?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/mem-diff ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as MemDiffResponse;
  out.request_idx = idx;
  out.request_addr = addr;
  out.request_size = size;
  return out;
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
  const r = await fx(`/api/idxs-for-pc?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/idxs-for-pc ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as IdxsForPcResponse;
  out.request_pc = pc;
  out.request_cursor = cursor;
  out.request_limit = limit;
  return out;
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
  const r = await fx(`/api/search?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/search ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as SearchResponse;
  out.request_pattern = pattern;
  out.request_max_results = maxResults;
  out.request_cursor = cursor;
  return out;
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
  const r = await fx(`/api/search-pc?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/search-pc ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as SearchPcResponse;
  out.request_pc = pc;
  out.request_limit = limit;
  return out;
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
  const r = await fx(`/api/query?${params}`, { signal: opts.signal });
  if (!r.ok) throw new Error(`/api/query ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as TraceQueryResponse;
  out.request_kind = opts.kind;
  out.request_q = opts.q ?? "";
  out.request_idx = opts.idx;
  out.request_reg = opts.reg;
  out.request_addr = opts.addr;
  out.request_len = opts.len;
  out.request_limit = opts.limit;
  return out;
}

export async function fetchRegValueAt(
  idx: number,
  reg: string,
  signal?: AbortSignal,
): Promise<RegValueAtResponse> {
  const params = new URLSearchParams({ idx: String(idx), reg });
  const r = await fx(`/api/reg-value-at?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/reg-value-at ${r.status}: ${await r.text()}`);
  return (await r.json()) as RegValueAtResponse;
}

export async function fetchLastWriteOfReg(
  before: number,
  reg: string,
  signal?: AbortSignal,
): Promise<LastWriteOfRegResponse> {
  const params = new URLSearchParams({ before: String(before), reg });
  const r = await fx(`/api/last-write-of-reg?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/last-write-of-reg ${r.status}: ${await r.text()}`);
  return (await r.json()) as LastWriteOfRegResponse;
}

export async function fetchNextUseOfReg(
  after: number,
  reg: string,
  signal?: AbortSignal,
): Promise<NextUseOfRegResponse> {
  const params = new URLSearchParams({ after: String(after), reg });
  const r = await fx(`/api/next-use-of-reg?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/next-use-of-reg ${r.status}: ${await r.text()}`);
  return (await r.json()) as NextUseOfRegResponse;
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
  const r = await fx(`/api/watchpoints?${params}`, { signal: opts.signal });
  if (!r.ok) throw new Error(`/api/watchpoints ${r.status}: ${await r.text()}`);
  return (await r.json()) as WatchpointsResponse;
}

export async function fetchCallTree(maxDepth = 10, signal?: AbortSignal): Promise<CallTreeResponse> {
  const params = new URLSearchParams({ max_depth: String(maxDepth) });
  const r = await fx(`/api/call-tree?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/call-tree ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as CallTreeResponse;
  out.request_max_depth = maxDepth;
  return out;
}

export async function fetchBacktrace(idx: number, limit = 256): Promise<BacktraceResponse> {
  const params = new URLSearchParams({ idx: String(idx), limit: String(limit) });
  const r = await fx(`/api/backtrace?${params}`);
  if (!r.ok) throw new Error(`/api/backtrace ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as BacktraceResponse;
  out.request_limit = limit;
  return out;
}

export async function fetchForkEvents(status = "", limit = 1000): Promise<ForkEventsResponse> {
  const params = new URLSearchParams();
  if (status) params.set("status", status);
  params.set("limit", String(limit));
  const qs = params.toString();
  const r = await fx(`/api/fork-events${qs ? "?" + qs : ""}`);
  if (!r.ok) throw new Error(`/api/fork-events ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as ForkEventsResponse;
  out.request_status = status;
  out.request_limit = limit;
  return out;
}

export interface TaintFlags {
  through_mem?: boolean;
  data_only?: boolean;
  cross_fn_call?: boolean;
}

export async function fetchForwardTaint(
  traceIdx: number,
  reg: string,
  maxCount = 200,
  flags: TaintFlags = {},
  signal?: AbortSignal,
): Promise<ForwardTaintResponse> {
  const params = new URLSearchParams({
    trace_idx: String(traceIdx),
    reg,
    max_count: String(maxCount),
  });
  if (flags.through_mem) params.set("through_mem", "true");
  if (flags.data_only) params.set("data_only", "true");
  if (flags.cross_fn_call) params.set("cross_fn_call", "true");
  const r = await fx(`/api/forward-taint?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/forward-taint ${r.status}: ${await r.text()}`);
  return (await r.json()) as ForwardTaintResponse;
}

export async function fetchBackwardTaint(
  traceIdx: number,
  reg: string,
  maxCount = 200,
  flags: TaintFlags = {},
  signal?: AbortSignal,
): Promise<BackwardTaintResponse> {
  const params = new URLSearchParams({
    trace_idx: String(traceIdx),
    reg,
    max_count: String(maxCount),
  });
  if (flags.through_mem) params.set("through_mem", "true");
  if (flags.data_only) params.set("data_only", "true");
  if (flags.cross_fn_call) params.set("cross_fn_call", "true");
  const r = await fx(`/api/backward-taint?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/backward-taint ${r.status}: ${await r.text()}`);
  return (await r.json()) as BackwardTaintResponse;
}

export interface DecIrOptions {
  withMemshadow?: boolean;
  splitTopK?: number;
  splitMinRecords?: number;
}

function appendDecIrOptions(params: URLSearchParams, opts: DecIrOptions = {}) {
  if (opts.withMemshadow) params.set("with_memshadow", "true");
  if (opts.splitTopK !== undefined) params.set("split_top_k", String(opts.splitTopK));
  if (opts.splitMinRecords !== undefined) params.set("split_min_records", String(opts.splitMinRecords));
}

export async function fetchDecSummary(
  opts: DecIrOptions = {},
  signal?: AbortSignal,
): Promise<DecSummaryResponse> {
  const params = new URLSearchParams();
  appendDecIrOptions(params, opts);
  const qs = params.toString();
  const r = await fx(`/api/dec/summary${qs ? "?" + qs : ""}`, { signal });
  if (!r.ok) throw new Error(`/api/dec/summary ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as DecSummaryResponse;
  out.request_split_top_k = opts.splitTopK;
  out.request_split_min_records = opts.splitMinRecords;
  out.request_with_memshadow = opts.withMemshadow ?? false;
  return out;
}

export async function fetchDecFn(
  fnId: string,
  tier = "hot",
  opts: DecIrOptions = {},
  signal?: AbortSignal,
): Promise<DecFnResponse> {
  const params = new URLSearchParams({ tier });
  appendDecIrOptions(params, opts);
  const r = await fx(`/api/dec/fn/${encodeURIComponent(fnId)}?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/dec/fn/${fnId} ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as DecFnResponse;
  out.request_fn_id = fnId;
  out.request_tier = tier;
  out.request_split_top_k = opts.splitTopK;
  out.request_split_min_records = opts.splitMinRecords;
  out.request_with_memshadow = opts.withMemshadow ?? false;
  return out;
}

export async function fetchDecModels(): Promise<DecModelsResponse> {
  const r = await fx("/api/dec/models");
  if (!r.ok) throw new Error(`/api/dec/models ${r.status}: ${await r.text()}`);
  return (await r.json()) as DecModelsResponse;
}

export async function fetchOpenApi(): Promise<OpenApiResponse> {
  const r = await fx("/openapi.json");
  if (!r.ok) throw new Error(`/openapi.json ${r.status}: ${await r.text()}`);
  return (await r.json()) as OpenApiResponse;
}

export async function fetchBgStatus(): Promise<BgStatusResponse> {
  const r = await fx("/api/bg-status");
  if (!r.ok) throw new Error(`/api/bg-status ${r.status}: ${await r.text()}`);
  return (await r.json()) as BgStatusResponse;
}

export async function fetchDecompStatus(): Promise<DecompStatusResponse> {
  const r = await fx("/api/decomp-status");
  if (!r.ok) throw new Error(`/api/decomp-status ${r.status}: ${await r.text()}`);
  return (await r.json()) as DecompStatusResponse;
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
  const r = await fx(`/api/mem-writes-in-range?${params}`, { signal: opts.signal });
  if (!r.ok) throw new Error(`/api/mem-writes-in-range ${r.status}: ${await r.text()}`);
  return (await r.json()) as MemWritesInRangeResponse;
}

export async function fetchBlockForPc(pc: string): Promise<BlockForPcResponse> {
  const params = new URLSearchParams({ pc });
  const r = await fx(`/api/block-for-pc?${params}`);
  if (!r.ok) throw new Error(`/api/block-for-pc ${r.status}: ${await r.text()}`);
  return (await r.json()) as BlockForPcResponse;
}

export async function fetchIdxsForBlock(
  pc: string,
  maxCount = 1,
  near?: number,
): Promise<IdxsForBlockResponse> {
  const params = new URLSearchParams({ pc, max_count: String(maxCount) });
  if (near !== undefined) params.set("near", String(near));
  const r = await fx(`/api/idxs-for-block?${params}`);
  if (!r.ok) throw new Error(`/api/idxs-for-block ${r.status}: ${await r.text()}`);
  return (await r.json()) as IdxsForBlockResponse;
}

export async function callDecLlm(payload: DecLlmCallPayload): Promise<DecLlmCallResponse> {
  const r = await fx("/api/dec/llm-call", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!r.ok) throw new Error(`/api/dec/llm-call ${r.status}: ${await r.text()}`);
  return (await r.json()) as DecLlmCallResponse;
}

export async function renderLlil(payload: LlilRenderPayload): Promise<LlilRenderResponse> {
  const r = await fx("/api/llil/render", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!r.ok) throw new Error(`/api/llil/render ${r.status}: ${await r.text()}`);
  return (await r.json()) as LlilRenderResponse;
}

export async function fetchLlilPipeline(
  payload: LlilPipelinePayload,
  signal?: AbortSignal,
): Promise<PipelineResponse> {
  const r = await fx("/api/llil/pipeline", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
    signal,
  });
  if (!r.ok) throw new Error(`/api/llil/pipeline ${r.status}: ${await r.text()}`);
  return (await r.json()) as PipelineResponse;
}

export async function callLlilLlm(payload: LlilLlmPayload): Promise<LlilLlmResponse> {
  const r = await fx("/api/llil/llm", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!r.ok) throw new Error(`/api/llil/llm ${r.status}: ${await r.text()}`);
  return (await r.json()) as LlilLlmResponse;
}

export async function fetchHlilForFn(fnId: string): Promise<HlilForFnResponse> {
  const params = new URLSearchParams({ fn_id: fnId });
  const r = await fx(`/api/hlil-for-fn?${params}`);
  if (!r.ok) throw new Error(`/api/hlil-for-fn ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as HlilForFnResponse;
  out.request_fn_id = fnId;
  return out;
}

export async function fetchHlilForPc(
  pc: string,
  signal?: AbortSignal,
): Promise<HlilForPcResponse> {
  const params = new URLSearchParams({ pc });
  const r = await fx(`/api/hlil-for-pc?${params}`, { signal });
  if (!r.ok) throw new Error(`/api/hlil-for-pc ${r.status}: ${await r.text()}`);
  const out = (await r.json()) as HlilForPcResponse;
  out.request_pc = pc;
  return out;
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
  const qs = params.toString();
  const r = await fx(`/api/bfs-slice${qs ? "?" + qs : ""}`, { signal: opts.signal });
  if (!r.ok) throw new Error(`/api/bfs-slice ${r.status}: ${await r.text()}`);
  return (await r.json()) as BfsSliceResponse;
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
  const qs = params.toString();
  const r = await fx(`/api/forward-dep-tree${qs ? "?" + qs : ""}`, { signal: opts.signal });
  if (!r.ok) throw new Error(`/api/forward-dep-tree ${r.status}: ${await r.text()}`);
  return (await r.json()) as ForwardDepTreeResponse;
}

export async function fetchCryptoAnalysis(): Promise<CryptoAnalysisResponse> {
  const r = await fx("/api/crypto-analysis");
  if (!r.ok) throw new Error(`/api/crypto-analysis ${r.status}: ${await r.text()}`);
  return (await r.json()) as CryptoAnalysisResponse;
}
