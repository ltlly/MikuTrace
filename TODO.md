# TODO — traceMiku Decompiler

> Last updated: 2026-05-14 (late)

## P0 — Core Correctness

- [x] ARM64 lifter: 99.93-100% LLIL coverage, 0 bare Intrinsic
- [x] Call target name resolution: `0xHEX()` → `sub_xxx()`
- [x] Flag elimination: cmp+b.cond → direct comparison
- [x] **Call parameters**: trace x0-x7 values extracted and displayed at call sites
- [x] **Indirect call resolution**: blr x8 → resolve actual target from trace data
- [x] **Function boundaries**: ret/blr boundary detection, sub_8a7b8: 438→75 lines

## P1 — Decompile UI (对标 IDA/BN/Ghidra)

- [x] **Cursor sync (click→jump)**: click decompile line → jump assembly cursor to matching PC
- [x] **Line click → jump**: extract PC from line, resolve via /api/idxs-for-pc, jump
- [x] **Variable hover**: mouseover variable → show value(s) from trace records
- [x] **Variable rename**: double-click var → rename, propagate across function
- [x] **Variable type**: right-click → set type (int32_t/uint64_t/char*/struct*)
- [x] **Fold/unfold blocks**: collapse {} code blocks, collapse stack frame
- [x] **Highlight current line**: cursor moves → highlight matching decompile line

## P2 — Analysis

- [ ] Xrefs from decompile: right-click → show all references to variable
- [ ] Decompile diff: compare two trace snapshots
- [ ] Global variable resolution from ELF symbols
- [ ] Stack variable auto-naming
- [ ] Type recovery through call boundaries

## P3 — Polish

- [x] Decompile-to-C export
- [x] Search within decompile
- [x] Decompile history (back/forward)

## Done (Recent)

- [x] Ghidra-style Pass framework: 55/62 Actions, 6-phase pipeline
- [x] Decompile panel: LLIL/MLIL/HLIL sub-tabs, lazy text loading
- [x] 7 ARM64 test binaries, 56+ functions, 563+ tests
- [x] BN vs traceMiku systematic comparison
- [x] Android .so compiled + pushed to device

## Bugs

- [x] **Assembly scroll freeze**: at ~5857033-5857088 / 7,200,380 records, the Records panel can't scroll down. Suspect virtual scrolling boundary issue in the Records panel component. Fixed: lowered SAFE_SCROLL_HEIGHT 30M→15M to stay within browser scrollable height limits.
