/** SIMD 同样由 native 分批落盘；结束时排空并 fsync。 */
import { STATE } from "../core/state";
export function flushSimdRingToDisk(_reason?: string): void {
    if (STATE.simdSidecar && STATE.simdTraceFile) STATE.flushSimdNative();
}
