import { createMemo, createResource, onCleanup } from "solid-js";
import type { Accessor } from "solid-js";

export function createGuardedResource<S, T>(
  source: Accessor<S | undefined>,
  fetcher: (source: S, signal?: AbortSignal) => Promise<T>,
  isCurrent: (value: T, source: S) => boolean,
) {
  let abort: AbortController | undefined;
  const [resource] = createResource<T | undefined, S | undefined>(
    source,
    (s) => {
      abort?.abort();
      abort = undefined;
      if (s === undefined) return undefined;
      abort = new AbortController();
      return fetcher(s, abort.signal);
    },
  );
  onCleanup(() => {
    abort?.abort();
    abort = undefined;
  });
  const current = createMemo<T | undefined>(() => {
    const s = source();
    const value = resource();
    if (s === undefined || value === undefined) return undefined;
    return isCurrent(value, s) ? value : undefined;
  });
  return [resource, current] as const;
}
