import type {
  MetaResponse,
  RecordsResponse,
  RecordDetail,
  FunctionsResponse,
  StringsResponse,
  MemDumpResponse,
  CallTreeResponse,
  ForwardTaintResponse,
  BackwardTaintResponse,
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

export async function fetchStrings(minLen = 4, q = ""): Promise<StringsResponse> {
  const params = new URLSearchParams({ min_len: String(minLen) });
  if (q) params.set("q", q);
  const r = await fetch(`/api/strings?${params}`);
  if (!r.ok) throw new Error(`/api/strings ${r.status}: ${await r.text()}`);
  return (await r.json()) as StringsResponse;
}

export async function fetchMemDump(addr: string, count = 64): Promise<MemDumpResponse> {
  const params = new URLSearchParams({ addr, count: String(count) });
  const r = await fetch(`/api/mem-dump?${params}`);
  if (!r.ok) throw new Error(`/api/mem-dump ${r.status}: ${await r.text()}`);
  return (await r.json()) as MemDumpResponse;
}

export async function fetchCallTree(maxDepth = 10): Promise<CallTreeResponse> {
  const params = new URLSearchParams({ max_depth: String(maxDepth) });
  const r = await fetch(`/api/call-tree?${params}`);
  if (!r.ok) throw new Error(`/api/call-tree ${r.status}: ${await r.text()}`);
  return (await r.json()) as CallTreeResponse;
}

export async function fetchForwardTaint(
  start: number,
  reg: string,
  maxCount = 200,
): Promise<ForwardTaintResponse> {
  const params = new URLSearchParams({
    start: String(start),
    reg,
    max_count: String(maxCount),
  });
  const r = await fetch(`/api/forward-taint?${params}`);
  if (!r.ok) throw new Error(`/api/forward-taint ${r.status}: ${await r.text()}`);
  return (await r.json()) as ForwardTaintResponse;
}

export async function fetchBackwardTaint(
  start: number,
  reg: string,
  maxCount = 200,
): Promise<BackwardTaintResponse> {
  const params = new URLSearchParams({
    start: String(start),
    reg,
    max_count: String(maxCount),
  });
  const r = await fetch(`/api/backward-taint?${params}`);
  if (!r.ok) throw new Error(`/api/backward-taint ${r.status}: ${await r.text()}`);
  return (await r.json()) as BackwardTaintResponse;
}
