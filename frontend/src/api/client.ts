import type {
  MetaResponse,
  RecordsResponse,
  RecordDetail,
  FunctionsResponse,
  StringsResponse,
  TouchingAddrResponse,
  MemDumpResponse,
  MemDiffResponse,
  IdxsForPcResponse,
  OpenApiResponse,
  SearchPcResponse,
  SearchResponse,
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
  HlilForFnResponse,
  CfgSvgResponse,
} from "./types";

export async function fetchMeta(): Promise<MetaResponse> {
  const r = await fetch("/api/meta");
  if (!r.ok) {
    throw new Error(`/api/meta returned ${r.status}: ${await r.text()}`);
  }
  return (await r.json()) as MetaResponse;
}

export interface FetchRecordsOpts {
  start?: number;
  count?: number;
  regs?: string;
}

export async function fetchRecords(opts: FetchRecordsOpts = {}): Promise<RecordsResponse> {
  const params = new URLSearchParams();
  if (opts.start !== undefined) params.set("start", String(opts.start));
  if (opts.count !== undefined) params.set("count", String(opts.count));
  if (opts.regs) params.set("regs", opts.regs);
  const qs = params.toString();
  const r = await fetch(`/api/records${qs ? "?" + qs : ""}`);
  if (!r.ok) throw new Error(`/api/records returned ${r.status}: ${await r.text()}`);
  return (await r.json()) as RecordsResponse;
}

export async function fetchRecord(idx: number): Promise<RecordDetail> {
  const r = await fetch(`/api/record/${idx}`);
  if (!r.ok) throw new Error(`/api/record/${idx} returned ${r.status}: ${await r.text()}`);
  return (await r.json()) as RecordDetail;
}

export async function fetchFunctions(): Promise<FunctionsResponse> {
  const r = await fetch("/api/functions");
  if (!r.ok) throw new Error(`/api/functions returned ${r.status}: ${await r.text()}`);
  return (await r.json()) as FunctionsResponse;
}

export interface FetchCfgSvgOpts {
  fnName?: string;
  timeout?: number;
}

export async function fetchCfgSvg(opts: FetchCfgSvgOpts = {}): Promise<CfgSvgResponse> {
  const params = new URLSearchParams();
  if (opts.fnName) params.set("fn", opts.fnName);
  if (opts.timeout !== undefined) params.set("timeout", String(opts.timeout));
  const qs = params.toString();
  const r = await fetch(`/api/cfg-svg${qs ? "?" + qs : ""}`);
  if (!r.ok) throw new Error(`/api/cfg-svg returned ${r.status}: ${await r.text()}`);
  return (await r.json()) as CfgSvgResponse;
}

export async function fetchStrings(minLen = 4, q = ""): Promise<StringsResponse> {
  const params = new URLSearchParams({ min_len: String(minLen) });
  if (q) params.set("q", q);
  const r = await fetch(`/api/strings?${params}`);
  if (!r.ok) throw new Error(`/api/strings ${r.status}: ${await r.text()}`);
  return (await r.json()) as StringsResponse;
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
  const r = await fetch(`/api/idxs-touching-addr?${params}`);
  if (!r.ok) throw new Error(`/api/idxs-touching-addr ${r.status}: ${await r.text()}`);
  return (await r.json()) as TouchingAddrResponse;
}

export async function fetchMemDump(addr: string, count = 64): Promise<MemDumpResponse> {
  const params = new URLSearchParams({ addr, count: String(count) });
  const r = await fetch(`/api/mem-dump?${params}`);
  if (!r.ok) throw new Error(`/api/mem-dump ${r.status}: ${await r.text()}`);
  return (await r.json()) as MemDumpResponse;
}

export async function fetchMemDiff(
  idx: number,
  addr: string,
  size = 16,
): Promise<MemDiffResponse> {
  const params = new URLSearchParams({
    idx: String(idx),
    addr,
    size: String(size),
  });
  const r = await fetch(`/api/mem-diff?${params}`);
  if (!r.ok) throw new Error(`/api/mem-diff ${r.status}: ${await r.text()}`);
  return (await r.json()) as MemDiffResponse;
}

export async function fetchIdxsForPc(
  pc: string,
  cursor = 0,
  limit = 30,
): Promise<IdxsForPcResponse> {
  const params = new URLSearchParams({
    pc,
    cursor: String(cursor),
    limit: String(limit),
  });
  const r = await fetch(`/api/idxs-for-pc?${params}`);
  if (!r.ok) throw new Error(`/api/idxs-for-pc ${r.status}: ${await r.text()}`);
  return (await r.json()) as IdxsForPcResponse;
}

export async function fetchSearch(pattern: string, maxResults = 200): Promise<SearchResponse> {
  const params = new URLSearchParams({
    pattern,
    max_results: String(maxResults),
  });
  const r = await fetch(`/api/search?${params}`);
  if (!r.ok) throw new Error(`/api/search ${r.status}: ${await r.text()}`);
  return (await r.json()) as SearchResponse;
}

export async function fetchSearchPc(pc: string, limit = 50): Promise<SearchPcResponse> {
  const params = new URLSearchParams({
    pc,
    limit: String(limit),
  });
  const r = await fetch(`/api/search-pc?${params}`);
  if (!r.ok) throw new Error(`/api/search-pc ${r.status}: ${await r.text()}`);
  return (await r.json()) as SearchPcResponse;
}

export async function fetchCallTree(maxDepth = 10): Promise<CallTreeResponse> {
  const params = new URLSearchParams({ max_depth: String(maxDepth) });
  const r = await fetch(`/api/call-tree?${params}`);
  if (!r.ok) throw new Error(`/api/call-tree ${r.status}: ${await r.text()}`);
  return (await r.json()) as CallTreeResponse;
}

export async function fetchBacktrace(idx: number): Promise<BacktraceResponse> {
  const params = new URLSearchParams({ idx: String(idx) });
  const r = await fetch(`/api/backtrace?${params}`);
  if (!r.ok) throw new Error(`/api/backtrace ${r.status}: ${await r.text()}`);
  return (await r.json()) as BacktraceResponse;
}

export async function fetchForkEvents(status = ""): Promise<ForkEventsResponse> {
  const params = new URLSearchParams();
  if (status) params.set("status", status);
  const qs = params.toString();
  const r = await fetch(`/api/fork-events${qs ? "?" + qs : ""}`);
  if (!r.ok) throw new Error(`/api/fork-events ${r.status}: ${await r.text()}`);
  return (await r.json()) as ForkEventsResponse;
}

export interface TaintFlags {
  through_mem?: boolean;
  data_only?: boolean;
  cross_fn_call?: boolean;
}

export async function fetchForwardTaint(
  start: number,
  reg: string,
  maxCount = 200,
  flags: TaintFlags = {},
): Promise<ForwardTaintResponse> {
  const params = new URLSearchParams({
    start: String(start),
    reg,
    max_count: String(maxCount),
  });
  if (flags.through_mem) params.set("through_mem", "true");
  if (flags.data_only) params.set("data_only", "true");
  if (flags.cross_fn_call) params.set("cross_fn_call", "true");
  const r = await fetch(`/api/forward-taint?${params}`);
  if (!r.ok) throw new Error(`/api/forward-taint ${r.status}: ${await r.text()}`);
  return (await r.json()) as ForwardTaintResponse;
}

export async function fetchBackwardTaint(
  start: number,
  reg: string,
  maxCount = 200,
  flags: TaintFlags = {},
): Promise<BackwardTaintResponse> {
  const params = new URLSearchParams({
    start: String(start),
    reg,
    max_count: String(maxCount),
  });
  if (flags.through_mem) params.set("through_mem", "true");
  if (flags.data_only) params.set("data_only", "true");
  if (flags.cross_fn_call) params.set("cross_fn_call", "true");
  const r = await fetch(`/api/backward-taint?${params}`);
  if (!r.ok) throw new Error(`/api/backward-taint ${r.status}: ${await r.text()}`);
  return (await r.json()) as BackwardTaintResponse;
}

export async function fetchDecSummary(): Promise<DecSummaryResponse> {
  const r = await fetch("/api/dec/summary");
  if (!r.ok) throw new Error(`/api/dec/summary ${r.status}: ${await r.text()}`);
  return (await r.json()) as DecSummaryResponse;
}

export async function fetchDecFn(fnId: string, tier = "hot"): Promise<DecFnResponse> {
  const params = new URLSearchParams({ tier });
  const r = await fetch(`/api/dec/fn/${encodeURIComponent(fnId)}?${params}`);
  if (!r.ok) throw new Error(`/api/dec/fn/${fnId} ${r.status}: ${await r.text()}`);
  return (await r.json()) as DecFnResponse;
}

export async function fetchDecModels(): Promise<DecModelsResponse> {
  const r = await fetch("/api/dec/models");
  if (!r.ok) throw new Error(`/api/dec/models ${r.status}: ${await r.text()}`);
  return (await r.json()) as DecModelsResponse;
}

export async function fetchOpenApi(): Promise<OpenApiResponse> {
  const r = await fetch("/openapi.json");
  if (!r.ok) throw new Error(`/openapi.json ${r.status}: ${await r.text()}`);
  return (await r.json()) as OpenApiResponse;
}

export async function callDecLlm(payload: DecLlmCallPayload): Promise<DecLlmCallResponse> {
  const r = await fetch("/api/dec/llm-call", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!r.ok) throw new Error(`/api/dec/llm-call ${r.status}: ${await r.text()}`);
  return (await r.json()) as DecLlmCallResponse;
}

export async function renderLlil(payload: LlilRenderPayload): Promise<LlilRenderResponse> {
  const r = await fetch("/api/llil/render", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!r.ok) throw new Error(`/api/llil/render ${r.status}: ${await r.text()}`);
  return (await r.json()) as LlilRenderResponse;
}

export async function fetchHlilForFn(fnId: string): Promise<HlilForFnResponse> {
  const params = new URLSearchParams({ fn_id: fnId });
  const r = await fetch(`/api/hlil-for-fn?${params}`);
  if (!r.ok) throw new Error(`/api/hlil-for-fn ${r.status}: ${await r.text()}`);
  return (await r.json()) as HlilForFnResponse;
}
