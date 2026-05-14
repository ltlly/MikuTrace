# Benchmarks — traceMiku Decompiler

> Last updated: 2026-05-14

## LLIL Coverage (Real Traces)

| Trace | Records | Functions | Coverage | Intrinsic |
|---|---|---|---|---|
| multiso_real/call_004 | 7.2M | F0-F6 | **99.92-100%** | 0 |
| multiso_real/call_004 | ~ | sub_8a7b8 | **99.94%** | 0 |
| boundary_stat_launch2 | 8.8M | top-15 | 91.8-100% | 0 |

## Decompilation Performance

| Metric | Value |
|---|---|
| Avg time/instruction (LLIL→MLIL→HLIL) | **8.28 µs** |
| 500-record decompile | **<1s** (stats only), **<5s** (with text) |
| 5000-record decompile | **<30s** (all 3 layers) |
| 92K-record trace parsing | **2.35s** |

## ARM64 Instruction Coverage

| Batch | Count | Status |
|---|---|---|
| Core (mov/add/sub/ldr/str/b/bl/ret) | ~40 mnemonics | 100% |
| Extended (smull/madd/msub/extr/csel) | ~10 | 100% |
| Bitfield (ubfm/sbfm/ubfx/sbfx/bfxil) | 5 | 100% |
| Conditional (cinc/cinv/cneg) | 3 | 100% |
| Atomic (ldarb/ldaxrb/stlrb) | 3 | 100% |
| System (mrs/dmb/isb) | 3 | 100% |
| Remaining (ccmp/ccmn) | 2 | intentional intrinsic |

## Test Suite

| Category | Tests | Coverage |
|---|---|---|
| Unit tests | 323 | all pass |
| BN comparison | 15 | 100% each |
| Algorithm tests (AES/Base64/RC4/etc) | 116 | ≥90% each |
| ls-like tests | 13 | ≥90% each |
| Native .so tests | 8 | ≥90% each |
| Decompilation verify | 44 | ≥85% each |

## ARM64 Test Binaries

| Binary | Functions | Size |
|---|---|---|
| decomp_test_suite | 44 | 707KB |
| test_algorithms (AES/SHA/RC4/etc) | 22 | 705KB |
| test_lslike (syscalls) | 13 | 705KB |
| test_strings | 9 | 705KB |
| test_linkedlist | 3 | 705KB |
| test_arrays | 3 | 705KB |
| test_hash | 3 | 705KB |
| test_fsm | 2 | 705KB |
| libtrace_test.so (Android) | 8 | 70KB |
