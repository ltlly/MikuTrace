# TODO — traceMiku

> Last updated: 2026-05-14

## In Progress

- [ ] Type inference pass: integrate InferredType into HLIL renderer output (int32_t/int64_t)
- [ ] Stack frame folding: hide frame ops in renderer when `frame_op` annotation present
- [ ] Cursor sync: click decompile line → jump to corresponding record in assembly view
- [ ] Android .so on-device Frida tracing (libtrace_test.so ready on device)

## Done (Recent)

- [x] ARM64 lifter: 99.93-100% LLIL coverage on real traces (was 93%)
- [x] Intrinsic elimination: 0 bare Intrinsic across LLIL/MLIL/HLIL
- [x] Call target resolution: 0 Intrinsic() calls (was 33)
- [x] Flag elimination: cmp+b.cond → direct comparison
- [x] Ghidra-style Pass framework: 55/62 Actions replicated, 6-phase pipeline
- [x] Decompile panel: LLIL/MLIL/HLIL sub-tabs, lazy text loading
- [x] 7 ARM64 test binaries, 56+ functions
- [x] Algorithm test suite: AES-128, Base64, RC4, CRC32, QuickSort, BST, etc.

## Backlog

- [ ] Real on-device Frida tracing of native .so tests
- [ ] More Ghidra Rules (~130 rules in ruleaction.hh)
- [ ] WebAssembly decompiler target
- [ ] Variable rename/label UI in decompile view
- [ ] Diff decompile: compare two trace snapshots
