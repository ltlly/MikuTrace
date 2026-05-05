import { createMemo, createResource } from "solid-js";
import type { Accessor } from "solid-js";

export function createGuardedResource<S, T>(
  source: Accessor<S | undefined>,
  fetcher: (source: S) => Promise<T>,
  isCurrent: (value: T, source: S) => boolean,
) {
  const [resource] = createResource<T | undefined, S | undefined>(
    source,
    (s) => (s === undefined ? undefined : fetcher(s)),
  );
  const current = createMemo<T | undefined>(() => {
    const s = source();
    const value = resource();
    if (s === undefined || value === undefined) return undefined;
    return isCurrent(value, s) ? value : undefined;
  });
  return [resource, current] as const;
}
