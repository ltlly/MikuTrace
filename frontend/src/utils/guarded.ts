// Command-style race guards shared across panels.
//
// Every panel previously hand-rolled the same sequence-token + AbortController
// dance: `let seq = 0; let abort: AbortController | undefined;` then
// `cancel()`, `++seq`, a new AbortController, a `seq !== X || aborted`
// check after every await, and a `finally` that clears the reference.
// That pattern was copy-pasted across ~10 files. This module is the single
// implementation; behavior is identical to the old hand-rolled code.

export interface GuardHandle {
  /** Monotonic token captured at begin(); compared against the live token. */
  seq: number;
  /** Request abort created at begin(). Always present for the guard lifecycle. */
  abort: AbortController;
  /** Optional extra consistency check (parameter snapshot, token match). */
  check?: () => boolean;
}

export class Guarded {
  private liveSeq = 0;
  private liveAbort: AbortController | undefined;

  /** Invalidate any in-flight call and interrupt its request. Idempotent. */
  cancel(): void {
    this.liveSeq += 1;
    this.liveAbort?.abort();
    this.liveAbort = undefined;
  }

  /** Alias for onCleanup: cancel without extra ceremony. Idempotent. */
  cleanup(): void {
    this.cancel();
  }

  /**
   * Start a new guarded call. Returns a handle to pass to `isCurrent` after
   * each await. The caller owns the returned `abort.signal` (pass it to the
   * fetch) and must leave `check` unused unless it captured a snapshot.
   */
  begin(check?: () => boolean): GuardHandle {
    this.liveSeq += 1;
    const seq = this.liveSeq;
    const abort = new AbortController();
    this.liveAbort = abort;
    return { seq, abort, check };
  }

  /** True iff the handle still belongs to the latest call. */
  isCurrent(h: GuardHandle): boolean {
    if (h.seq !== this.liveSeq) return false;
    if (h.abort.signal.aborted) return false;
    if (h.check && !h.check()) return false;
    return true;
  }

  /** True iff the handle's abort is still the registered one. */
  ownsAbort(h: GuardHandle): boolean {
    return h.abort === this.liveAbort;
  }

  /** Release the abort reference if it is still the current one. */
  release(h: GuardHandle): void {
    if (h.abort === this.liveAbort) {
      this.liveAbort = undefined;
    }
  }
}

/** Convenience factory for `const guard = useGuarded()` in a component. */
export function useGuarded(): Guarded {
  return new Guarded();
}
