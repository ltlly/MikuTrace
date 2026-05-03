import type { MetaResponse } from "./types";

export async function fetchMeta(): Promise<MetaResponse> {
  const r = await fetch("/api/meta");
  if (!r.ok) {
    throw new Error(`/api/meta returned ${r.status}: ${await r.text()}`);
  }
  return (await r.json()) as MetaResponse;
}
