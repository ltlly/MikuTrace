# TODO — traceMiku Decompiler

> Last updated: 2026-05-14

## P0 — Core Correctness

- [x] ARM64 lifter: 99.93-100% LLIL coverage, 0 bare Intrinsic
- [x] Call target name resolution: `0xHEX()` → `sub_xxx()`
- [x] Flag elimination: cmp+b.cond → direct comparison
- [ ] **Call parameters**: show `sub_xxx(arg1=0x.., arg2=0x..)` with trace values
- [ ] **Indirect call resolution**: blr x8 → resolve actual target from trace data
- [ ] **Function boundaries**: stop at first ret; don't include dead code after return

## P1 — Decompile UI (对标 IDA/BN/Ghidra)

- [ ] **Cursor sync**: decompile panel ↔ assembly bidirectional scroll
- [ ] **Line click → jump**: click decompile line → jump assembly cursor to that PC
- [ ] **Variable hover**: mouseover variable → show value(s) from trace records
- [ ] **Variable rename**: double-click var → rename, propagate across function
- [ ] **Variable type**: right-click → set type (int32_t/uint64_t/char*/struct*)
- [ ] **Fold/unfold blocks**: collapse {} code blocks, collapse stack frame
- [ ] **Highlight current line**: cursor moves → highlight matching decompile line

## P2 — Analysis

- [ ] Xrefs from decompile: right-click → show all references to variable
- [ ] Decompile diff: compare two trace snapshots
- [ ] Global variable resolution from ELF symbols
- [ ] Stack variable auto-naming
- [ ] Type recovery through call boundaries

## P3 — Polish

- [ ] Decompile-to-C export
- [ ] Search within decompile
- [ ] Decompile history (back/forward)

## Done (Recent)

- [x] Ghidra-style Pass framework: 55/62 Actions, 6-phase pipeline
- [x] Decompile panel: LLIL/MLIL/HLIL sub-tabs, lazy text loading
- [x] 7 ARM64 test binaries, 56+ functions, 563+ tests
- [x] BN vs traceMiku systematic comparison
- [x] Android .so compiled + pushed to device
