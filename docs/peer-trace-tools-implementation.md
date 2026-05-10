# Peer-Trace-Tools — Implementation Plan + Notes (2026-05-10)

> Companion to [`peer-trace-tools-survey.md`](peer-trace-tools-survey.md) and
> [`peer-trace-tools-algorithms.md`](peer-trace-tools-algorithms.md). This file
> records what we picked up from the peer survey, what landed in code, and why.

## 0. Scope and discipline

We are a single-developer project with no external API contract; the survey
explicitly authorises destructive change. The aim of this round is to **adopt
the strongest peer ideas** without rewriting analysis we already ship.

The peer survey converges on this short list as the highest-leverage gaps:

* §1.8 trace-ui `query/slice.rs` — BFS backward slicing on a pre-built CSR
  dependency matrix, returning a compact `BitVec`. We already have the CSR
  (`analysis_index::DependencyIndex`); we lacked a fast standalone BFS slice.
* §1.9 trace-ui `query/dep_tree.rs` — Forward def→use DAG from a sink. We had
  the *backward* DAG via `dep_graph` but no forward direction, so DEF-arrow
  navigation in the UI cannot fan out.
* §2.5 GumTrace `SCAN_LIMIT_REACHED` watchdog — stop a taint walk after N
  consecutive steps with zero events. Our `taint::forward_taint` /
  `taint::backward_taint` only stop at `max_count`.
* §1.6 chunked CSR + patch row — already approximated by the persisted
  `DependencyIndex` (single CSR, on-disk sidecar). The persistent CSR has the
  same query shape as the chunked-CSR rows; we treat the chunked variant as a
  later compatibility-only optimisation.
* §1.7 LDP/STP pair-split with bit-tag arrival — `taint::store_source_regs_for_addr`
  already disambiguates pair halves by overlapping the explicit memop address.
  We add an extra unit test to lock the behaviour rather than retrofit a
  separate bit-tag space.

This document keeps the running plan; each section ends with the actual files
that landed.

## 1. Backward BFS slice (trace-ui §1.8)

### 1.1 Goal

Given a seed (trace index, register-before-cursor, or address-before-cursor),
return the set of rows the seed transitively depends on, walked through the
persistent `DependencyIndex` we already build at startup.

The compact representation is a `Vec<u64>` bitset (1 bit per trace row), which
is `O(n/8)` regardless of fan-out. For a 24M-row trace that is ~3 MB, exactly
the same scaling that lets trace-ui ship "12.5 MB BitVec on 100M lines."

The output also carries a `Vec<usize>` of the slice rows for direct use by
callers that want a list (e.g. taint panel highlights) without paying for a
sort over the bitset.

### 1.2 Algorithm

```
function bfs_slice(seeds, data_only, max_nodes):
    marked = Bitset(n)
    queue  = VecDeque<usize>
    for seed in seeds:
        if seed < n and !marked[seed]:
            marked[seed] = true
            queue.push_back(seed)
    while !queue.empty() and slice_count < max_nodes:
        idx = queue.pop_front()
        for edge in deps.row(idx):
            if data_only and edge.kind == Control: continue
            if !marked[edge.idx]:
                marked[edge.idx] = true
                queue.push_back(edge.idx)
                slice_count += 1
    return (marked, ordered_idxs, truncated)
```

* `data_only` filters the edge, not the node — same as trace-ui (control/data
  separation is a property of the dep edge).
* The walk uses the persistent CSR (`DependencyIndex`); no allocation per row
  and no rebuild between queries.
* `max_nodes` caps long walks; the response sets `truncated=true` when the cap
  fires so the UI can show "and N more".

### 1.3 Layout

* New core module: `tracemiku_core::bfs_slice` containing
  `Bitset`, `SliceOptions`, `bfs_slice()`, and seed-resolution helpers.
* New server route: `GET /api/bfs-slice?idx=…|reg=…|addr=…&data_only=…&limit=…`.
* Routed through `tokio::task::spawn_blocking` and listed as heavy in
  `api_infra_tests`.

## 2. Forward def→use DAG (trace-ui §1.9)

### 2.1 Goal

Given a sink, walk the inverse direction of the dep graph: which later rows
*used* this one. Same query as trace-ui's `query/dep_tree.rs`. Useful for
"where does this value go" navigation, complement to `dep_graph` which goes
backwards.

### 2.2 Implementation

The `DependencyIndex` only stores predecessor edges (`row(idx)` returns the
rows `idx` depends on). To walk forward we need the inverse map: for each
`predecessor`, the list of rows that pointed at it.

We compute that inverse lazily — once per `AnalysisIndex` instance — and cache
it on the shared `AppState`. The structure is another CSR
(`Vec<u32> row_offsets, Vec<u32> users`) so it is exactly 1× the size of the
forward edges; for 24M rows × ~3 edges each that is ~300 MB which is still
acceptable next to the persisted analysis sidecar. We use `u32` because the
trace contract caps records well under 2³².

The BFS itself mirrors §1 with one twist:

```
queue.push_back((seed, depth=0))
while !queue.empty() and node_count < limit:
    (idx, depth) = queue.pop_front()
    if depth >= max_depth: continue
    for user_idx in users.row(idx):
        if !visited[user_idx]:
            edges.push((idx, user_idx))
            queue.push_back((user_idx, depth+1))
            nodes.push(user_idx)
```

We emit nodes + edges directly in the same response shape as `dep_graph` so
the frontend can use the same renderer.

### 2.3 Layout

* New core helper: `tracemiku_core::analysis_index::DependencyUsers`.
* New core module: `tracemiku_core::forward_dep_tree`.
* New server route: `GET /api/forward-dep-tree`.

## 3. SCAN_LIMIT_REACHED (GumTrace §2.5)

### 3.1 Goal

Right now `forward_taint` / `backward_taint` stop only at `max_count`. On long
traces a tainted-mem set that goes empty often keeps triggering false events
in noisy regions. GumTrace stops the walk when it sees N consecutive events
without finding any new propagation. We adopt the same idea.

### 3.2 Behaviour

* New optional argument: `scan_limit: Option<usize>`.
  * `None` → off (backwards compatible with current callers).
  * `Some(n)` → walk stops after `n` consecutive event pops produced no new
    entries in `out`/`raw_out`. Sets a new `StopReason::ScanLimitReached`.
* Surface as `stop_reason: "scan_limit"` in the route response, distinct from
  `truncated: true` (which corresponds to `max_count`).

Implementation point: track `since_last_hit` in the BFS loop. Every time we
push a `TaintHit`, reset to 0; every iteration that is filtered out
(visited, deduped, no propagation) increments the counter; on overflow break
with the new flag set.

## 4. Pair-split lock-in (trace-ui §1.7)

`backward_taint_pair_load_chases_matching_store_half` already covers the LDP
side; `forward_taint_pair_split_walks_correct_half` is added to cover the
forward direction symmetrically and lock in the existing
`store_source_regs_for_addr` fix.

## 5. Performance posture

* All new routes go through `spawn_blocking` and join the heavy-route classifier
  table (`api_infra::HEAVY_ROUTE_FILES`).
* `DependencyUsers` is built on the first request that needs it and cached in
  `Arc<OnceLock<…>>` on the shared state. Subsequent calls are O(1) lookup +
  O(slice) walk.
* `bfs_slice` returns a slim JSON shape (just node ids + the few fields needed
  for the panel), so even the truncated response is < 1 MB at the default
  cap.

## 6. Validation

* `cargo test -p tracemiku-core` covers the new BFS / forward-DAG / scan-limit
  paths with synthetic 5–9 row traces. After this round: 147 core tests pass.
* `cargo test -p tracemiku-server --test api_infra_tests` keeps OpenAPI list
  ↔ frontend client ↔ axum router three-way parity. The new routes are
  classified as heavy.
* Workspace total after this round: 594 tests, all passing.
* Manually exercising on a real call directory is gated behind
  `scripts/rust_web_smoke.py`. `make test-v2` runs the lot.

## 7. Landed code (delta, 2026-05-10)

**core**

* `tracemiku_core::bfs_slice` — `Bitset` (1 bit per row, masked iter, idxs
  constructor), `bfs_slice` / `bfs_slice_one`, `slice_edge_stats`. 13 unit
  tests covering diamond graphs, control-edge filtering, max-nodes
  truncation, stale-edge tolerance, bitset round-trip + mask invariants.
* `tracemiku_core::forward_dep_tree` — `DependencyUsers` (inverted CSR with
  `src_row` and `edge.idx` capped at `n_rows`), `forward_dep_tree` (Bitset
  visited set, single-source `hidden_edges` accounting). 12 unit tests
  including a regression for the original audit's double-count bug.
* `tracemiku_core::taint::TaintOptions` / `TaintWalkResult` /
  `forward_taint_ext` / `backward_taint_ext` — GumTrace-style scan-limit
  watchdog. Legacy `(Vec<TaintHit>, bool)` shape preserved as a thin
  wrapper, so all existing callers keep working. Added 7 unit tests.

**server**

* `routes::bfs_slice::bfs_slice_handler` (`GET /api/bfs-slice`).
* `routes::forward_dep_tree::forward_dep_tree_handler` (`GET /api/forward-dep-tree`).
* `routes::forward_taint` / `routes::backward_taint` now expose
  `stop_reason` and `scan_limit_used` in the JSON shape, with `scan_limit=0`
  as the disable opt-out.
* Both new routes registered in `openapi.json` and classified as heavy in
  `api_infra_tests::HEAVY_ROUTE_FILES`. `state::AppStateInner::dep_users`
  caches the inverted CSR via `OnceLock`.
* 14 new server-route tests + 6 amended taint-route tests.

**audit fixes (round 2)**

* `Bitset::iter` masks the trailing word to `len` so it never returns
  out-of-range indices when the buffer carries stale bits.
* `DependencyUsers::build` caps `src_row` at `n_rows` so a stale persisted
  CSR never seeds out-of-range users.
* `forward_dep_tree`'s `visited` set switched from `Vec<bool>`
  (~100 MB / 100M rows) to `Bitset` (~12.5 MB / 100M rows).
* `hidden_edges` no longer double-counts cap-blocked destinations — the
  post-process retain step is now the single source of truth for
  cap-induced hidden edges. `forward_dep_tree_max_nodes_truncates` pins the
  exact count.
* `/api/bfs-slice` and `/api/forward-dep-tree` reject malformed `addr=`
  literals with an explicit note instead of silently mapping them to `0x0`.

## 8. Not landed (deliberately)

* Chunked CSR + patch row (trace-ui §1.6). Our persisted single-CSR
  `DependencyIndex` already stores the same query shape; chunking buys
  scaling at the cost of re-architecting the sidecar. Worth it on >10⁸-row
  traces, but not on current targets.
* Exhaustive `InsnClass` enum (trace-ui §1.2). Replaces the existing
  Capstone-driven `def_use` path; large refactor that should land alongside
  a wider lift overhaul.
* SAILR-style structuring passes (algorithms §5.1) and DecompileBench
  replacement loops (§5.7). LLIL/decompiler-side work that warrants its
  own spec.

## 9. Round 2 deltas (2026-05-10, after parallel Opus audits)

**core**

* `bfs_slice::SliceMode` (Union | Intersection) and `bfs_slice_multi`. Lets
  callers seed multiple rows and either combine their lineages (union) or
  ask "what rows did *both* operations transitively read?" (intersection).
  `Bitset::intersect_in_place` / `union_in_place` carry the AND/OR.
* `Bitset::iter` masks the trailing word against `len`, defending
  `iter()` against stale dirty bits past the end of the buffer.
* `Bitset::from_idxs` constructor for the post-process visible-set
  in `forward_dep_tree` and the row-coverage bitsets in tests.

**server**

* `routes::seed_resolver` — single source of truth for `parse_u64`,
  `split_csv`, `ResolvedSeed`, `resolve_reg`, `resolve_addr`,
  `resolve_one`, `annotate_outside_trace`, `edge_kind_str`,
  `edge_label_str`, `node_id`, and `render_dep_node`. `dep_graph`,
  `bfs_slice`, and `forward_dep_tree` now share these helpers — about
  300 lines deduped across the three routes.
* `dep_graph` BFS visited set is now `Bitset` instead of `HashSet<usize>`;
  bounded memory on 100M-row traces.
* `dep_graph` and `forward_dep_tree` reuse the `DepNode` payload; the
  edge label/kind functions are also shared.
* `/api/bfs-slice` accepts `idxs=`, `regs=`, `addrs=`, and `mode=union|intersection|intersect|and`.
  Up to 16 seeds. Returns a flat `slice` integer list **plus** an enriched
  `rows` array (first 2000 rows with pc/asm/func/expression) so the
  frontend doesn't need a follow-up `/api/record` round trip.
* `/api/forward-dep-tree`'s `depth=0` now means "seed only" (audit
  P0-1 fix); the previous `.max(1)` rewrite was silently wrong.
* `/api/dep-graph` no longer maps a malformed `addr=` literal to `0x0`
  (audit P0-2). All three routes now report `"invalid address literal"`.
* All three routes are still classified heavy in `api_infra_tests`.

**frontend**

* New `panels/slice/SlicePanel.tsx`. Backward + forward in a single panel,
  with optional second seed and union/intersection toggle, `data_only`
  checkbox, depth control for the forward direction, cap-notice (matches
  XrefPanel/TaintPanel), and a refresh button. Stable `query` memo plus
  `createGuardedResource` to reject stale frames. Registered in the
  stability audit's allowlist.
* `frontend/src/api/client.ts` exposes `fetchBfsSlice` and
  `fetchForwardDepTree` with shared `appendSeedQueryParams` helper.
  `BfsSliceResponse.rows` carries the enriched per-row shape so the
  panel renders `idx · pc · fn · asm` without a second request.
* `App.tsx` left-tab list now includes "Slice"; the help blurb explains
  when to prefer Slice over Taint.

**audit-driven test additions (round 2)**

* `bfs_slice_all_seeds_outside_returns_empty_slice_with_notes` — multi-seed
  all-invalid, P2-1.
* `bfs_slice_intersection_with_partial_validity_collapses_to_valid_seed` —
  P2-2.
* `bfs_slice_caps_seeds_at_16` — P2-7.
* `bfs_slice_response_carries_enriched_rows` — confirms new
  `rows`/`rows_capped` fields ship.
* `bfs_slice_edge_stats_per_kind_match_synthetic_fixture` — P2-4.
* `forward_dep_tree_addr_seed_resolves_to_writer` — P2-8.
* `forward_dep_tree_truncation_reports_hidden_edges` — P2-5.
* `forward_dep_tree_depth_zero_returns_seed_only` — pins audit P0-1 fix.
* `dep_graph_self_loop_does_not_double_visit` — P2-6, regression test
  for the Bitset migration.
* `backward_taint_scan_limit_zero_disables_watchdog` and
  `backward_taint_scan_limit_one_trips_watchdog` — P2-3.

**totals**: 626 workspace tests passing (up from 594 at end of round 1).
`make test-v2` green end-to-end (cargo fmt, core/server/cli, frontend
build, parity smoke, stability/UI/cap audits).
