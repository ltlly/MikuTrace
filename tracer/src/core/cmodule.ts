/**
 * CModule — SPSC ring producer (ARM64 native, runs in Stalker context)
 *
 * 生成 C 源码, 通过 Frida CModule 编译到 on_insn callout.
 * 支持可选 SIMD sidecar 和 semantic SVC event callback.
 */

import { STATE, REC_SIZE, RING_RECS, SIMD_REC_SIZE, SIMD_RING_RECS, TraceRingState } from "./state";
import { log } from "./utils";

/**
 * Build and compile the CModule with SPSC ring producer.
 * Must be called after STATE ring buffers are allocated.
 */
export function buildCModule(): void {
    const simdDecls = STATE.simdSidecar ? `
#define SIMD_REC ${SIMD_REC_SIZE}
#define C_ASSERT(name, expr) typedef char c_assert_##name[(expr) ? 1 : -1]
extern unsigned char simd_ring[];
extern unsigned long long simd_ring_recs;
extern unsigned long long simd_stride;
extern volatile unsigned long long simd_head;
extern volatile unsigned long long simd_tail;
extern volatile unsigned long long simd_dropped;
C_ASSERT(simd_rec_size, SIMD_REC == ${SIMD_REC_SIZE});
C_ASSERT(arm64_vector_reg_size, sizeof(((GumCpuContext *) 0)->v[0]) == 16);
C_ASSERT(arm64_vector_q_size, sizeof(((GumCpuContext *) 0)->v[0].q) == 16);
C_ASSERT(arm64_vector_count, sizeof(((GumCpuContext *) 0)->v) == (32 * 16));

static void write_simd_snapshot(GumCpuContext *ctx, unsigned long long trace_idx) {
    if (simd_stride > 1 && (trace_idx % simd_stride) != 0) return;
    unsigned long long h = simd_head;
    unsigned long long t = simd_tail;
    if (h - t >= simd_ring_recs) { simd_dropped = simd_dropped + 1; return; }
    unsigned char *p = simd_ring + ((h % simd_ring_recs) * SIMD_REC);
    *(unsigned long long *)(p + 0) = trace_idx;
    for (int i = 0; i < 32; i++) {
        memcpy(p + 8 + (i * 16), ctx->v[i].q, 16);
    }
    simd_head = h + 1;
}
` : "";

    const semanticDecls = STATE.semanticEvents ? `
extern void on_svc_event(unsigned long long idx,
                         unsigned long long pc,
                         unsigned long long nr,
                         unsigned long long x0,
                         unsigned long long x1,
                         unsigned long long x2,
                         unsigned long long x3,
                         unsigned long long x4,
                         unsigned long long x5);
` : "";

    const simdWrite = STATE.simdSidecar ? `    write_simd_snapshot(ctx, h);\n` : "";

    const semanticWrite = STATE.semanticEvents ? `
    if ((inst & 0xffe0001fU) == 0xd4000001U) {
        on_svc_event(h, cu[0], cu[3+8], cu[3+0], cu[3+1], cu[3+2], cu[3+3], cu[3+4], cu[3+5]);
    }
` : "";

    const src = `
#include <gum/gumstalker.h>
#include <string.h>
#define REC ${REC_SIZE}
#define SPIN_MAX 200000000

extern unsigned char ring[];
extern unsigned long long ring_recs;
extern volatile unsigned long long head;
extern volatile unsigned long long tail;
extern volatile unsigned long long dropped;
extern unsigned long long max_records;
${simdDecls}
${semanticDecls}

void on_insn(GumCpuContext *ctx, void *user_data) {
    unsigned long long h = head;       /* 64-bit aligned read on ARM64 = atomic */
    if (max_records > 0 && h >= max_records) return;  /* hard cap */
    unsigned long long t = tail;
    unsigned long long spin = 0;
    while (h - t >= ring_recs) {
        if (++spin > SPIN_MAX) { dropped = dropped + 1; return; }
        t = tail;
    }
    unsigned long long off = (h % ring_recs) * REC;
    unsigned char *p = ring + off;
    unsigned long long *cu = (unsigned long long *)ctx;
    *(unsigned long long *)(p + 0) = cu[0];          // pc
    memcpy(p + 8, &cu[3], 29 * 8);                    // x0..x28
    *(unsigned long long *)(p + 8 + 29*8) = cu[3+29]; // fp
    *(unsigned long long *)(p + 8 + 30*8) = cu[3+30]; // lr
    *(unsigned long long *)(p + 256) = cu[1];         // sp
    *(unsigned int *)(p + 264) = (unsigned int)(cu[2] & 0xffffffffULL);
    /* inst: 读 pc 处 4 字节机器码 */
    unsigned int inst = *(unsigned int *)cu[0];
    *(unsigned int *)(p + 268) = inst;
${simdWrite}${semanticWrite}
    head = h + 1;     /* volatile store */
}
`;

    const symbols: Record<string, NativePointer> = {
        ring: STATE.ringBuf!,
        ring_recs: STATE.ringRecsBuf!,
        head: STATE.headBuf!,
        tail: STATE.tailBuf!,
        dropped: STATE.droppedBuf!,
        max_records: STATE.maxRecordsBuf!,
    };

    if (STATE.simdSidecar) {
        symbols.simd_ring = STATE.simdRingBuf!;
        symbols.simd_ring_recs = STATE.simdRingRecsBuf!;
        symbols.simd_stride = STATE.simdStrideBuf!;
        symbols.simd_head = STATE.simdHeadBuf!;
        symbols.simd_tail = STATE.simdTailBuf!;
        symbols.simd_dropped = STATE.simdDroppedBuf!;
    }

    if (STATE.semanticEvents) {
        symbols.on_svc_event = STATE.onSvcEventCb!;
    }

    STATE.cm = new CModule(src, symbols);
    STATE.onInsnPtr = (STATE.cm as any).on_insn;
    log(`[+] CModule loaded: on_insn @ ${(STATE.cm as any).on_insn} ` +
        `(SPSC lock-free, simd=${STATE.simdSidecar ? "on" : "off"}, ` +
        `semantic=${STATE.semanticEvents ? "on" : "off"})`);
}

export function buildTraceRingCModule(ring: TraceRingState): any {
    const src = `
#include <gum/gumstalker.h>
#include <string.h>
#define REC ${REC_SIZE}
#define SPIN_MAX 200000000

extern unsigned char ring[];
extern unsigned long long ring_recs;
extern volatile unsigned long long head;
extern volatile unsigned long long tail;
extern volatile unsigned long long dropped;
extern unsigned long long max_records;

void on_insn(GumCpuContext *ctx, void *user_data) {
    unsigned long long h = head;
    if (max_records > 0 && h >= max_records) return;
    unsigned long long t = tail;
    unsigned long long spin = 0;
    while (h - t >= ring_recs) {
        if (++spin > SPIN_MAX) { dropped = dropped + 1; return; }
        t = tail;
    }
    unsigned long long off = (h % ring_recs) * REC;
    unsigned char *p = ring + off;
    unsigned long long *cu = (unsigned long long *)ctx;
    *(unsigned long long *)(p + 0) = cu[0];
    memcpy(p + 8, &cu[3], 29 * 8);
    *(unsigned long long *)(p + 8 + 29*8) = cu[3+29];
    *(unsigned long long *)(p + 8 + 30*8) = cu[3+30];
    *(unsigned long long *)(p + 256) = cu[1];
    *(unsigned int *)(p + 264) = (unsigned int)(cu[2] & 0xffffffffULL);
    unsigned int inst = *(unsigned int *)cu[0];
    *(unsigned int *)(p + 268) = inst;
    head = h + 1;
}
`;

    return new CModule(src, {
        ring: ring.ringBuf,
        ring_recs: ring.ringRecsBuf,
        head: ring.headBuf,
        tail: ring.tailBuf,
        dropped: ring.droppedBuf,
        max_records: ring.maxRecordsBuf,
    });
}
