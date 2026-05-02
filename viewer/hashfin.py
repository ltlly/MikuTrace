"""Hash finalize-output region detection.

Heuristic: scan MemShadow for contiguous 20-byte (SHA-1) or 16-byte (MD5)
write regions completed within a short trace-idx window (~100-500 idxs).
This identifies WHERE the hash digest was stored — closing the loop with
crypto-scan (which finds WHERE the IV was loaded, i.e. the algorithm input).

Returns:
  list[{
    "addr": "0x...",          # base addr of the contiguous output
    "size": int,              # bytes covered (≥ 16, typical 20 or 32)
    "enter_idx": int,         # first write idx
    "exit_idx": int,          # last write idx
    "kind": "u32x5" | "byte_seq",  # store granularity
    "guess": "sha1" | "md5" | "sha256" | None,  # by size
  }]

Two patterns:
  1. **u32x5**: 5 contiguous 4-byte writes at base+0,4,8,12,16 → SHA-1 H[0..4]
     finalize. Or 4 × u32 → MD5 digest.
  2. **byte_seq**: 20 contiguous 1-byte writes at base+0..19 (byte-swap + strb
     loop emits this).
"""
from __future__ import annotations
from typing import Optional
import numpy as np


def _digest_size_to_guess(size: int) -> Optional[str]:
    if size == 16: return "md5"
    if size == 20: return "sha1"
    if size == 32: return "sha256"
    if size == 28: return "sha224"
    if size == 64: return "sha512"
    return None


def hash_finalize_detect(trace, mem, window: int = 500,
                          min_size: int = 16) -> list[dict]:
    """Scan MemShadow.writes for contiguous output regions completed within
    `window` trace-idx range.

    Algorithm:
      1. Sort writes by addr.
      2. Walk addr-sorted writes; group by contiguity (each next addr ==
         prev_addr + prev_size).
      3. For each contiguous run with total bytes >= min_size, check the
         max-min idx of the run is <= window.
      4. Emit candidate.
    """
    if mem.w_addr.size == 0:
        return []
    addrs = mem.w_addr.copy().astype(np.int64)
    sizes = mem.w_size.copy().astype(np.int64)
    idxs = mem.w_idx.copy().astype(np.int64)
    order = np.argsort(addrs, kind="stable")
    addrs = addrs[order]; sizes = sizes[order]; idxs = idxs[order]

    out = []
    i = 0
    n = len(addrs)
    while i < n:
        run_start = addrs[i]
        run_end = addrs[i] + sizes[i]
        run_min_idx = int(idxs[i])
        run_max_idx = int(idxs[i])
        run_kinds = {int(sizes[i])}
        j = i + 1
        while j < n and addrs[j] == run_end:
            run_end = addrs[j] + sizes[j]
            run_min_idx = min(run_min_idx, int(idxs[j]))
            run_max_idx = max(run_max_idx, int(idxs[j]))
            run_kinds.add(int(sizes[j]))
            j += 1
        run_size = int(run_end - run_start)
        run_window = run_max_idx - run_min_idx
        if run_size >= min_size and run_window <= window:
            kind = "u32x5" if run_kinds == {4} and run_size >= 20 \
                else ("byte_seq" if run_kinds == {1} else "mixed")
            out.append({
                "addr": hex(int(run_start)),
                "size": run_size,
                "enter_idx": run_min_idx,
                "exit_idx": run_max_idx,
                "kind": kind,
                "guess": _digest_size_to_guess(run_size),
            })
        i = j
    return out
