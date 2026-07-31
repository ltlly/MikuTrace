/**
 * Pure helpers for the external-writes sidecar (`external_writes.bin`).
 *
 * Kept free of Frida imports so the format and the total-cap policy can be
 * contract-tested in Node (see tests/external_writes_contract_test.ts) and
 * shared by the agent (boundary_diff.ts) and any host-side consumer.
 *
 * On-disk record: <Q idx> <Q addr> <B byte> = 17 bytes, little-endian —
 * matches `EXTERNAL_WRITE_RECORD_SIZE` in tracemiku-core/src/memshadow.rs.
 */

export const EXT_WRITE_RECORD_SIZE = 17;

export interface ExtWriteEvent {
  attrIdx: number;
  addr: string; // hex string without 0x
  byte: number;
}

/** Encode one event to its 17-byte little-endian on-disk record. */
export function encodeExtWriteEvent(ev: ExtWriteEvent): Uint8Array {
  const out = new Uint8Array(EXT_WRITE_RECORD_SIZE);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, ev.attrIdx >>> 0, true);
  dv.setUint32(4, Math.floor(ev.attrIdx / 0x100000000), true);
  const addr = BigInt(ev.addr.startsWith("0x") ? ev.addr : `0x${ev.addr}`);
  dv.setUint32(8, Number(addr & 0xffffffffn), true);
  dv.setUint32(12, Number((addr >> 32n) & 0xffffffffn), true);
  dv.setUint8(16, ev.byte & 0xff);
  return out;
}

/**
 * Total-cap policy for external-write events. Returns the number of events
 * allowed under `cap` given the count already emitted. Once the cap is hit,
 * all further events are dropped (the analysis degrades gracefully instead
 * of unbounded growth).
 */
export function extWriteAllowance(emitted: number, cap: number, incoming: number): number {
  if (cap <= 0) return 0;
  const remaining = cap - emitted;
  if (remaining <= 0) return 0;
  return Math.min(remaining, incoming);
}
