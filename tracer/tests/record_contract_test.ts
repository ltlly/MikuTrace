/**
 * Black-box contract tests for the agent-side 272-byte record format.
 *
 * The Frida agent (state.ts) and the Rust core (trace/record.rs) both commit
 * to the same on-disk layout: [pc:u64, x0..x28:u64, fp:u64, lr:u64, sp:u64,
 * nzcv:u32, inst:u32] = 272 bytes. This test pins the agent-side constants
 * so a layout drift is caught without a device.
 *
 * Run: node --experimental-strip-types tests/record_contract_test.ts
 * (Node >= 22.6; no Frida runtime needed — state.ts has no Frida imports).
 */
import {
  REC_SIZE,
  DEFAULT_RING_RECS,
  MAX_RING_RECS,
  RING_RECS,
  ringBytes,
  setRingRecs,
  WORKER_RING_RECS,
  WORKER_RING_BYTES,
  SIMD_REC_SIZE,
  SIMD_RING_RECS,
  SIMD_RING_BYTES,
} from "../src/core/state.ts";

let failures = 0;

function check(name: string, cond: boolean): void {
  if (cond) {
    console.log(`ok   ${name}`);
  } else {
    failures += 1;
    console.error(`FAIL ${name}`);
  }
}

// On-disk contract shared with Rust core: 33 u64 slots + 2 u32.
check("REC_SIZE is 272 (33*8 + 2*4)", REC_SIZE === 272);

// Rust core REC_NUM_REGS = 31 (x0..x28 + fp + lr); pc(8) + 31*8 + sp(8) +
// nzcv(4) + inst(4) must equal REC_SIZE.
check(
  "layout math: 8 + 31*8 + 8 + 4 + 4 == 272",
  8 + 31 * 8 + 8 + 4 + 4 === REC_SIZE,
);

check("RING_RECS defaults to 65536 (17MiB ring)", RING_RECS === 65536);
check("ringBytes() == REC_SIZE * RING_RECS", ringBytes() === REC_SIZE * RING_RECS);

// Ring capacity is configurable; its byte budget must follow the effective
// capacity, including the lower and upper safety bounds.
try {
  setRingRecs(4096);
  check("configured ring holds 4096 records", RING_RECS === 4096);
  check("configured ring byte budget follows capacity", ringBytes() === 272 * 4096);
  setRingRecs(0);
  check("ring capacity cannot drop below 1024", RING_RECS === 1024);
  check("minimum ring byte budget", ringBytes() === 272 * 1024);
  setRingRecs(MAX_RING_RECS + 1);
  check("ring capacity cannot exceed the hard limit", RING_RECS === MAX_RING_RECS);
  check("maximum ring byte budget", ringBytes() === REC_SIZE * MAX_RING_RECS);
} finally {
  setRingRecs(DEFAULT_RING_RECS);
}

check("WORKER_RING_RECS is 8192", WORKER_RING_RECS === 8192);
check(
  "WORKER_RING_BYTES == REC_SIZE * WORKER_RING_RECS",
  WORKER_RING_BYTES === REC_SIZE * WORKER_RING_RECS,
);

// SIMD sidecar: trace_idx:u64 + q0..q31:u128 = 8 + 32*16 = 520.
check("SIMD_REC_SIZE is 520 (8 + 32*16)", SIMD_REC_SIZE === 520);
check("SIMD_RING_RECS is 8192", SIMD_RING_RECS === 8192);
check(
  "SIMD_RING_BYTES == SIMD_REC_SIZE * SIMD_RING_RECS",
  SIMD_RING_BYTES === SIMD_REC_SIZE * SIMD_RING_RECS,
);

if (failures > 0) {
  console.error(`\n${failures} contract failure(s)`);
  process.exit(1);
}
console.log("\nall record-format contracts hold");
