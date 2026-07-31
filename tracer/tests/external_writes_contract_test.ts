/**
 * Contract tests for the external-writes sidecar format and cap policy.
 *
 * Pins the 17-byte on-disk record (idx:u64, addr:u64, byte:u8) and the
 * total-cap allowance against the Rust core's
 * `EXTERNAL_WRITE_RECORD_SIZE` / merge_external_writes, so the agent and
 * core cannot drift. Pure module — no Frida runtime needed.
 *
 * Run: node --experimental-strip-types tests/external_writes_contract_test.ts
 */
import {
  EXT_WRITE_RECORD_SIZE,
  encodeExtWriteEvent,
  extWriteAllowance,
} from "../src/core/ext_write_cap.ts";

let failures = 0;

function check(name: string, cond: boolean): void {
  if (cond) {
    console.log(`ok   ${name}`);
  } else {
    failures += 1;
    console.error(`FAIL ${name}`);
  }
}

// ── format ──────────────────────────────────────────────────────────────
check("record size is 17 bytes", EXT_WRITE_RECORD_SIZE === 17);

{
  const ev = { attrIdx: 0x1234, addr: "0x1000", byte: 0xab };
  const rec = encodeExtWriteEvent(ev);
  check("encoded length is 17", rec.length === 17);
  const dv = new DataView(rec.buffer);
  check(
    "idx little-endian u64",
    dv.getUint32(0, true) === 0x1234 && dv.getUint32(4, true) === 0,
  );
  check(
    "addr little-endian u64",
    dv.getUint32(8, true) === 0x1000 && dv.getUint32(12, true) === 0,
  );
  check("byte is u8", dv.getUint8(16) === 0xab);
}

{
  // Large idx/addr must round-trip through the split u32 halves.
  const big = { attrIdx: 0x1_0000_0001, addr: "0xFFFF000000000000", byte: 1 };
  const rec = encodeExtWriteEvent(big);
  const dv = new DataView(rec.buffer);
  check(
    "large idx high word",
    dv.getUint32(0, true) === 1 && dv.getUint32(4, true) === 1,
  );
  check(
    "large addr high word",
    dv.getUint32(8, true) === 0 && dv.getUint32(12, true) === 0xffff0000,
  );
}

// ── cap policy ──────────────────────────────────────────────────────────
check("cap 0 drops everything", extWriteAllowance(0, 0, 5) === 0);
check("cap reached drops rest", extWriteAllowance(100, 100, 5) === 0);
check("cap exact fit", extWriteAllowance(90, 100, 10) === 10);
check("cap partial fit", extWriteAllowance(95, 100, 10) === 5);
check("cap over-remaining", extWriteAllowance(50, 100, 100) === 50);
check("never negative", extWriteAllowance(200, 100, 1) === 0);

if (failures > 0) {
  console.error(`\n${failures} FAILED`);
  process.exit(1);
}
console.log("\nall external-writes contract holds");
