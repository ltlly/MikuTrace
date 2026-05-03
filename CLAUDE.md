# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

**traceMiku** = Android real-device ARM64 instruction-level trace toolchain. Three layers:

1. **`tracer/`** (Frida agent, JS) — runs on device, follows a target SO function with Stalker, dumps `trace.bin` (272 B/record: PC + 31 GPR + SP + raw inst). Agents: `agent_cmodule_v5.js` (default, CModule + SPSC ring + on-device file + gzip pull), `agent_cmodule_v3.js` (legacy, IPC), `agent_generic.js` (JS callout fallback).
2. **`viewer/`** (Python core) — mmap parser, capstone decoder, CFG rebuilder, taint, MemShadow, SymbolMap, plus `viewer/decompiler/llil/` (in-house ARM64 LLIL → SSA → passes → C-like pseudocode, **does not depend on any LLM**). Same module is consumed three ways: Python SDK (`from viewer import ...`), CLI (`python -m viewer <subcmd>`), Web backend.
3. **`webui/`** (FastAPI + vanilla JS SPA) — primary UI. Single-page app, no build tool. `webui/server.py` imports `viewer` directly, exposes ~29 REST endpoints with strict Pydantic Union schemas (consumed by `app.js` and by LLM tooling via `/openapi.json`).

Top-level CLI is **`./tracemiku`** (one Python script, dispatches to `trace / web / list / info / finalize / dec / dec-bench / view / query`). `tracemiku-view` is a deprecated alias.

## Architectural rules (read before editing)

- **Web is the only UI.** The textual TUI in `viewer/app.py` is **frozen** — do not add features there, do not fix non-blocker bugs there. New analysis features land in Web (server endpoint + SPA tab) first, then Python SDK / CLI.
- **No MCP server.** LLM friendliness is delivered by three pieces: CLI (`python -m viewer <subcmd>`, JSON output), REST (`/openapi.json`), Python SDK (`viewer/__init__.py` exports). Do not add MCP wrappers.
- **End-to-end pipeline is fragile — verify the full link.** Any change touching `agent → host → meta.json → viewer → display` must be tested end-to-end (e.g. modules array, JNI events, fork events, per-call dirs). Do not "fix" only one side.
- **The project goal is the tool, not the SO.** `libsgmainso-6.8.260403.so` / Taobao 70102 / xsign are the *example*. Don't hardcode SO names, function offsets, or anti-debug specifics into core code — push them to JSON specs under `tools/hooks/` or to `examples/<so>/known_offsets.json`.
- **Trace formats are stable on-disk.** `trace.bin` record layout (272 B) and per-call directory layout (`calls/<idx>_tid<T>_<records>r_<ms>ms/`) are committed contracts. Bumping needs a meta version bump and migration.
- **TODO.md is the only backlog.** New work items go there. Do not start parallel TODO lists in subdir READMEs.
- **Don't crash the device.** Agent additions must be memory-bounded. Frida pitfalls are documented in user memory and `docs/` — read them before editing `tracer/agent_*.js`.

## Common commands

```bash
# Tests
make test                                  # full pytest run
make test-fast                             # -m "not slow", skips BN/device/browser
make test-slow                             # only @slow markers
pytest tests/test_llil_render.py -q        # one file
pytest tests/test_llil_render.py::test_X   # one test
# Markers: `slow` = real-trace / BN / browser; `device` = needs adb real device.

# Install (editable, with test deps)
make install-test                          # pip install -e .[test]

# Web SPA on an existing trace
make webui RUN=traces/run1                 # PORT=8765 default
./tracemiku web traces/run1 --port 8080 --no-browser
./tracemiku web <trace> --so /path/to/lib.so   # enables BN-backed HLIL/CFG tabs

# Trace collection (needs adb-rooted device + patched frida-server)
./vendor/frida-patched/install-stealth.sh  # installs to /data/local/tmp/.miku-srv
./tracemiku trace --pkg com.example.app --so libfoo \
  --fn-offset 0x1234 --duration 60 --out traces/run1
./tracemiku trace ... --cold-launch        # force-stop + pm clear + auto-tap consent
./tracemiku trace ... --trace-deep --jni-hooks tools/hooks/libart_jni.json \
  --patch-suicide --hide-rwx-maps          # anti-debug bundle (see README §反调试)

# Inspect existing traces
./tracemiku list traces/run1
./tracemiku info <call_dir>
python -m viewer stats <trace>             # JSON metadata
python -m viewer --help                    # 31 subcommands, JSON output

# Trace decompile (LLM-assisted, route B)
./tracemiku dec <call_dir>                 # → <trace>/decompile/{summary.md, fns/F*.md}
./tracemiku dec <trace> --fn F1 --call-llm mimo|claude|deepseek|qwen
./tracemiku dec-bench <trace> --models claude,deepseek,mimo --fn F1
```

The top-level `tracemiku` script auto-fallbacks to a system Python if the env-resolved one lacks `capstone`. `frida` is imported lazily inside `cmd_trace`, so `web/list/info/dec` work without it.

## Code map (where things live, big picture)

```
tracemiku                # top CLI (single file, ~2k lines, dispatches subcommands)
tracer/                  # device-side Frida JS agents (v5 default, v3 legacy, generic fallback)
viewer/
  __init__.py            # Public SDK surface (Trace, load, build_cfg, Index, MemShadow,
                         #   forward_taint, backward_taint, decode, make_backend, ...)
  __main__.py            # 31 CLI subcommands (`python -m viewer <cmd>`)
  trace.py               # mmap binary trace parser; Record/Module/TraceMeta dataclasses
  disasm.py              # capstone wrapper, def/use extraction, lru_cache(200_000)
  index.py               # reg_defs/uses, mem_writes/reads — heap-based taint substrate
  cfg.py                 # BB-CFG rebuild from trace, Tarjan SCC, dot writer
  taint.py               # forward/backward taint (heap, O(|hits|·log N))
  memshadow.py           # sparse byte-level memory shadow + sidecar (.memshadow.v2.npz)
  symbols.py             # PC→fn map, auto-discovers examples/<so>/known_offsets.json
  display.py             # pwndbg-style annotations, multi-module classify
  decompiler/
    backend.py           # FieldHint / Function / Variable dataclasses
    backends/{binja,ghidra,ida,none,r2}.py   # only binja is real, rest are stubs
    llil/                # ★ in-house ARM64 LLIL decompiler (route LLIL, no LLM)
      lift.py            # capstone → LLIL expression trees (~80 ARM64 ops)
      ssa.py             # block-local SSA + cross-block phi, AAPCS64 caller-saved kill
      pass_*.py          # constfold, dce, flag_elim, typelat, struct, var_unify,
                         #   restructure (CFG → if/while/for), uidf (trace-truth inject)
      render.py          # HLIL pseudocode, prologue/epilogue fold, var naming, string deref
    builder.py           # high-level "trace → IR markdown" pipeline (route B, used by `dec`)
    llm_client.py        # claude/deepseek/qwen/mimo backends for `dec --call-llm`
    type_anchor.py       # JSON-spec → typed pointer hints
    vm_candidate.py      # OLLVM VM dispatcher detection
  hashfin.py             # hash-finalize-detect (closes the loop with crypto-scan)
  ollvmdet.py            # ollvm-detect-vm heuristic (confidence-scored)
  calltree.py            # bl/ret pair-walking → nested call tree
  app.py                 # ⚠ deprecated TUI, frozen
webui/
  server.py              # FastAPI app factory; CFG rendered in subprocess (avoids GIL)
  schemas.py             # strict Pydantic Union schemas → /openapi.json
  cfg_render.py          # graphviz dot helpers (pure functions)
  index.html, app.js, styles.css   # SPA, no bundler, no framework
tools/hooks/              # JSON-driven specs (JNI hooks, suicide patch, type anchors)
examples/                 # llm_cookbook.py + per-SO known_offsets.json samples
docs/                     # design docs (decompiler IL, per-call layout, frida patches, anti-debug)
vendor/frida-patched/     # patched frida-server (codeslab fix + stealth string rename)
tests/                    # ~80 pytest files; uses tests/synth_targets/ + traces/<small>/ fixtures
```

## How the three consumers stay in sync

`viewer.*` is the single source of truth. **Web → CLI → SDK** is the propagation order: a new analysis lands first as a `viewer.*` function, then `viewer/__main__.py` adds a `--help`-rich subcommand, then `webui/server.py` adds a JSON endpoint with a strict schema in `webui/schemas.py`. When you change a `viewer.*` signature, run `pytest tests/test_webui.py` and the relevant `tests/test_cli_*.py` to catch shears.

## Trace decompile: two routes

Both consume the same `trace.bin` and `viewer/` core. They are not redundant — they target different problems:

- **Route B — IR markdown + LLM** (`tracemiku dec`, `viewer/decompiler/builder.py` + `llm_client.py`). The machine folds trace into a compact structured-IR markdown (CFG, sub-fn split, hot/warm/cold tiers, type anchors, VM-dispatcher hints, induction-var detection). LLM does the semantic step. Used for "what does this fn do" on huge OLLVM bodies.
- **Route LLIL — in-house decompiler** (`viewer/decompiler/llil/`, web tab `?pass=llil`). BN/IDA-style LLIL trees + block-local SSA + UIDF (inject trace-truth values into constfold env) + 8 main passes + extras (memshadow LOAD-fold, string deref). Outputs C-like pseudocode without any LLM. Long-term goal: replicate x-sign 100% from trace alone.

Both routes are active development. Don't merge them; don't delete one for the other.

## Things that look like bugs but aren't

- `viewer/app.py` (TUI) and `cfg.py:write_dot` / `cfg.py:textual_summary` look unused — they are kept for the deprecated TUI. Don't tidy-delete; coordinate with TODO.
- `tracemiku-view` is a thin deprecated wrapper; new entry is `tracemiku view` subcommand.
- The top-level `tracemiku` script does an `os.execv` Python-fallback dance at import — that's intentional (see header comment), don't "simplify" it.
- `frida` is imported lazily inside `cmd_trace`. Other subcommands must work without `frida` installed.
- `agent_cmodule_v3.js` underperforms `v5` by ~10× — kept on purpose for regression comparison.

## Documentation index

- `README.md` — top-level usage + architecture
- `TODO.md` — single backlog (P0/P1/P2 progress, anti-debug findings)
- `viewer/README.md` — SDK + CLI deep dive
- `tracer/README.md` — agent internals (SPSC ring, gzip pull pipeline)
- `docs/trace-decompiler-design.md` + `docs/trace-decompiler-il-design.md` — both decompile routes
- `docs/frida-codeslab-patch.md` — why the patched frida-server exists
- `docs/PER_CALL_TRACE_DESIGN.md` — per-call directory contract
- `docs/anti-debug-libart.md` — `--trace-deep` self-kill root cause analysis
- `tests/COVERAGE.md` — what's tested
- `CODE_REVIEW.md` — 2026-05-01 audit (most items shipped)

## User preferences (durable, project-scope)

These are persistent instructions for AI assistants working on this repo. Single user, prototype phase, breaking changes acceptable.

- **Default to subagent-driven-development** for any multi-step implementation task. Don't ask "subagent or inline?" — just dispatch subagents. Inline is only for trivial 1-2 file edits or when the user explicitly says inline.
- **Don't pause between milestones for confirmation.** When a plan completes (parity script `OK`, tests pass, docs synced), automatically: write the next plan, then start dispatching its tasks. Stop only on (a) genuine BLOCKED states a subagent escalates, (b) destructive-action confirmation gates per the system prompt, (c) context-window pressure where compaction is needed, (d) user interruption.
- **Skip the "Two execution options... Which approach?" handoff at end of plans.** It's been answered once: subagent. Plans should still document the choice in their text (for re-execution from a fresh session), but don't echo the question to the user.
- **`doneMeansMerged: true` is set.** Treat "done" as "PR-ready or self-contained next step handed off" — not "first stopping point reached."
- **Long-running milestone work** should stream commits to the current branch (no PR until user requests one). The user reviews via `git log` after the fact.
