/**
 * SIMD sidecar — optional Q0..Q31 ring buffer + flush
 *
 * 独立 ring, 与主 trace ring 并行. 每 N 条主 trace 记录采样一次 SIMD 寄存器.
 */

import { STATE, SIMD_REC_SIZE, SIMD_RING_RECS } from "../core/state";

/** Flush SIMD ring to disk file */
export function flushSimdRingToDisk(_reason?: string): void {
    if (!STATE.simdSidecar || !STATE.simdTraceFile) return;

    const h = STATE.simdHeadBuf!.readU64().toNumber();
    const t = STATE.simdTailBuf!.readU64().toNumber();
    const avail = h - t;
    if (avail <= 0) return;

    const tOff = t % SIMD_RING_RECS;
    const hOff = h % SIMD_RING_RECS;

    if (avail >= SIMD_RING_RECS) {
        STATE.simdTraceFile.write(
            STATE.simdRingBuf!.add(tOff * SIMD_REC_SIZE).readByteArray((SIMD_RING_RECS - tOff) * SIMD_REC_SIZE)
        );
        if (tOff > 0) {
            STATE.simdTraceFile.write(STATE.simdRingBuf!.readByteArray(tOff * SIMD_REC_SIZE));
        }
    } else if (hOff > tOff) {
        STATE.simdTraceFile.write(
            STATE.simdRingBuf!.add(tOff * SIMD_REC_SIZE).readByteArray(avail * SIMD_REC_SIZE)
        );
    } else {
        STATE.simdTraceFile.write(
            STATE.simdRingBuf!.add(tOff * SIMD_REC_SIZE).readByteArray((SIMD_RING_RECS - tOff) * SIMD_REC_SIZE)
        );
        if (hOff > 0) {
            STATE.simdTraceFile.write(STATE.simdRingBuf!.readByteArray(hOff * SIMD_REC_SIZE));
        }
    }
    STATE.simdTailBuf!.writeU64(h);
}
