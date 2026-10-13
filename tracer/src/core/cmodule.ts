/** Native 分批写盘；生产线程承担背压，不等待 JavaScript 消费者。 */
import { STATE, REC_SIZE, RING_RECS, SIMD_REC_SIZE, TraceRingState } from "./state";
import { getExport, log } from "./utils";
import { nativeIoSymbols } from "./native_io";

function source(simd: boolean, semantic: boolean): string {
    return `
#include <gum/gumstalker.h>
#include <string.h>
#define REC ${REC_SIZE}
extern unsigned char ring[];
extern unsigned long long ring_recs;
extern volatile unsigned long long head;
extern volatile unsigned long long tail;
extern int trace_io[];
extern int active;
extern int mutex[];
extern int lock(void *mutex);
extern int unlock(void *mutex);
extern void write_all(int *state, const unsigned char *buf, unsigned long size);
extern void sync_all(int *state);

static void drain_trace(void) {
    unsigned long long h = head, t = tail;
    while (t < h) {
        unsigned long long offset = t % ring_recs;
        unsigned long long count = ring_recs - offset;
        if (count > h - t) count = h - t;
        write_all(trace_io, ring + offset * REC, count * REC);
        t += count;
        tail = t;
    }
}
void flush_trace(void) {
    lock(mutex);
    active = 0;
    drain_trace();
    sync_all(trace_io);
    unlock(mutex);
}
${simd ? `
#define SIMD_REC ${SIMD_REC_SIZE}
extern unsigned char simd_ring[];
extern unsigned long long simd_ring_recs;
extern unsigned long long simd_stride;
extern volatile unsigned long long simd_head;
extern volatile unsigned long long simd_tail;
extern int simd_io[];
typedef char check_vector_size[(sizeof(((GumCpuContext *)0)->v) == 512) ? 1 : -1];
static void drain_simd(void) {
    unsigned long long h = simd_head, t = simd_tail;
    while (t < h) {
        unsigned long long offset = t % simd_ring_recs;
        unsigned long long count = simd_ring_recs - offset;
        if (count > h - t) count = h - t;
        write_all(simd_io, simd_ring + offset * SIMD_REC, count * SIMD_REC);
        t += count;
        simd_tail = t;
    }
}
void flush_simd(void) {
    lock(mutex);
    drain_simd();
    sync_all(simd_io);
    unlock(mutex);
}
static void write_simd(GumCpuContext *ctx, unsigned long long idx) {
    if (simd_stride > 1 && idx % simd_stride != 0) return;
    unsigned long long h = simd_head;
    unsigned char *p = simd_ring + (h % simd_ring_recs) * SIMD_REC;
    *(unsigned long long *)p = idx;
    memcpy(p + 8, ctx->v, 512);
    simd_head = h + 1;
    if (simd_head - simd_tail == simd_ring_recs) drain_simd();
}
` : ""}
${semantic ? `extern void on_svc_event(unsigned long long idx, unsigned long long pc,
    unsigned long long nr, unsigned long long x0, unsigned long long x1,
    unsigned long long x2, unsigned long long x3, unsigned long long x4, unsigned long long x5);` : ""}
void on_insn(GumCpuContext *ctx, void *user_data) {
    lock(mutex);
    if (!active) { unlock(mutex); return; }
    unsigned long long h = head;
    unsigned char *p = ring + (h % ring_recs) * REC;
    unsigned long long *cu = (unsigned long long *)ctx;
    *(unsigned long long *)(p + 0) = cu[0];
    memcpy(p + 8, &cu[3], 31 * 8);
    *(unsigned long long *)(p + 256) = cu[1];
    *(unsigned int *)(p + 264) = (unsigned int)cu[2];
    unsigned int inst = *(unsigned int *)cu[0];
    *(unsigned int *)(p + 268) = inst;
    ${simd ? "write_simd(ctx, h);" : ""}
    head = h + 1;
    if (head - tail == ring_recs) drain_trace();
    unlock(mutex);
    ${semantic ? `if ((inst & 0xffe0001fU) == 0xd4000001U)
        on_svc_event(h, cu[0], cu[11], cu[3], cu[4], cu[5], cu[6], cu[7], cu[8]);` : ""}
}
`;
}

function compile(ring: TraceRingState, simd = false, semantic = false): CModule {
    const symbols: Record<string, NativePointer> = {
        ...nativeIoSymbols(),
        ring: ring.ringBuf, ring_recs: ring.ringRecsBuf,
        head: ring.headBuf, tail: ring.tailBuf, trace_io: ring.ioState,
        active: ring.active, mutex: Memory.alloc(64), lock: getExport("pthread_mutex_lock")!,
        unlock: getExport("pthread_mutex_unlock")!,
    };
    if (simd) Object.assign(symbols, {
        simd_ring: STATE.simdRingBuf, simd_ring_recs: STATE.simdRingRecsBuf,
        simd_stride: STATE.simdStrideBuf, simd_head: STATE.simdHeadBuf,
        simd_tail: STATE.simdTailBuf, simd_io: STATE.simdIoState,
    });
    if (semantic) symbols.on_svc_event = STATE.onSvcEventCb!;
    const cm = new CModule(source(simd, semantic), symbols);
    // extern 数据的 JS 句柄与 writer 同寿命，特别是没有其他 STATE 引用的 mutex。
    (cm as any).keepAlive = symbols;
    ring.flushNative = new NativeFunction((cm as any).flush_trace, "void", []);
    return cm;
}

export function buildCModule(): void {
    const ring = {
        ringBuf: STATE.ringBuf!, headBuf: STATE.headBuf!, tailBuf: STATE.tailBuf!,
        ringRecsBuf: STATE.ringRecsBuf!, ioState: STATE.traceIoState!,
        active: STATE.active!, flushNative: null,
    } as unknown as TraceRingState;
    STATE.cm = compile(ring, STATE.simdSidecar, STATE.semanticEvents);
    STATE.flushNative = ring.flushNative;
    if (STATE.simdSidecar) STATE.flushSimdNative = new NativeFunction(STATE.cm.flush_simd, "void", []);
    STATE.onInsnPtr = STATE.cm.on_insn;
    log(`[+] native writer: batch=${RING_RECS}, disk backpressure, no record cap`);
}

export function buildTraceRingCModule(ring: TraceRingState): CModule {
    return compile(ring);
}
