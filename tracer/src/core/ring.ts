/**
 * SPSC lock-free ring buffer — V8 consumer (flush to disk)
 *
 * 架构:
 *   cmodule on_insn → SPSC ring (17MB, head/tail monotonic 计数, atomic) →
 *   v8 setInterval 10ms → File.write → device file
 */

import { STATE, REC_SIZE, RING_RECS, FLUSH_INTERVAL_MS } from "./state";
import { log, getExport } from "./utils";
import { flushSimdRingToDisk } from "../sidecar/simd";

/** Flush main trace ring to disk */
export function flushRingToDisk(_reason?: string): void {
    if (!STATE.traceFile) return;
    const h = STATE.headBuf!.readU64().toNumber();
    const t = STATE.tailBuf!.readU64().toNumber();
    const avail = h - t;
    if (avail <= 0) return;

    const tOff = t % RING_RECS;
    const hOff = h % RING_RECS;

    if (avail >= RING_RECS) {
        // Ring wrote full circle
        STATE.traceFile.write(
            STATE.ringBuf!.add(tOff * REC_SIZE).readByteArray((RING_RECS - tOff) * REC_SIZE)
        );
        if (tOff > 0) {
            STATE.traceFile.write(STATE.ringBuf!.readByteArray(tOff * REC_SIZE));
        }
    } else if (hOff > tOff) {
        // No wrap: single segment
        STATE.traceFile.write(
            STATE.ringBuf!.add(tOff * REC_SIZE).readByteArray(avail * REC_SIZE)
        );
    } else {
        // Wrap: two segments
        STATE.traceFile.write(
            STATE.ringBuf!.add(tOff * REC_SIZE).readByteArray((RING_RECS - tOff) * REC_SIZE)
        );
        if (hOff > 0) {
            STATE.traceFile.write(STATE.ringBuf!.readByteArray(hOff * REC_SIZE));
        }
    }
    STATE.tailBuf!.writeU64(h);
    STATE.batchSeq++;
}

/** Resolve libc mkdir via getExport (handles linker namespace issues) */
function getMkdirFn(): NativeFunction<number, [NativePointerValue, number]> | null {
    const ptr = getExport("mkdir");
    if (ptr) {
        return new NativeFunction(ptr, "int", ["pointer", "int"]);
    }
    return null;
}

/** Ensure trace dir exists, with fallbacks for attach-pid mode */
export function ensureTraceDir(): void {
    if (STATE.traceDir) return;

    // Try multiple methods to get package name
    if (!STATE.pkg) {
        try {
            const cmdF = new File("/proc/self/cmdline", "rb");
            const buf = (cmdF as any).read(256);
            cmdF.close();
            const pkg = String.fromCharCode.apply(null, new Uint8Array(buf) as any).split("\0")[0];
            if (pkg && pkg.length > 0 && pkg !== "unknown") {
                STATE.pkg = pkg;
            }
        } catch (_) {}
    }

    if (!STATE.pkg || STATE.pkg === "unknown") {
        try {
            const attrF = new File("/proc/self/attr/current", "rb");
            const buf = (attrF as any).read(256);
            attrF.close();
            const context = String.fromCharCode.apply(null, new Uint8Array(buf) as any).split("\0")[0];
            const parts = context.split(":");
            if (parts.length >= 4) {
                const lastPart = parts[3];
                const commaParts = lastPart.split(",");
                for (const part of commaParts) {
                    if (part.includes(".") && part.length > 3) {
                        STATE.pkg = part;
                        break;
                    }
                }
            }
        } catch (_) {}
    }

    if (!STATE.pkg || STATE.pkg === "unknown") {
        STATE.pkg = "unknown";
    }

    const mkdir = getMkdirFn();
    if (!mkdir) {
        // Cannot find mkdir at all — use /data/local/tmp and hope File() can create
        log("[!] mkdir 符号未找到, 尝试直接 File 写入 /data/local/tmp");
        STATE.traceDir = `/data/local/tmp/.miku_${Process.id}`;
        return;
    }

    // Primary location: app private cache (no permission issues)
    if (STATE.pkg !== "unknown") {
        const primaryDir = `/data/data/${STATE.pkg}/cache/.miku`;
        const result = mkdir(Memory.allocUtf8String(primaryDir), 0o755) as unknown as number;
        if (result === 0 || result === -1) {
            // result === -1 is EEXIST which is fine
            STATE.traceDir = primaryDir;
            log(`[+] trace dir = ${STATE.traceDir}`);
            return;
        }
        log(`[!] mkdir primary failed (rc=${result}), will try fallback`);
    }

    // Fallback: /data/local/tmp (requires root/shell writable)
    const fallbackDir = `/data/local/tmp/.miku_${Process.id}`;
    const rc = mkdir(Memory.allocUtf8String(fallbackDir), 0o755) as unknown as number;
    if (rc === 0 || rc === -1) {
        STATE.traceDir = fallbackDir;
        log(`[+] trace dir (fallback) = ${STATE.traceDir}`);
    } else {
        // Last resort — set it anyway, openTraceFile will fail with a clear error
        STATE.traceDir = fallbackDir;
        log(`[!] mkdir fallback 也失败了 (rc=${rc}), 继续尝试写入`);
    }
}

/** Open trace output file for a call */
export function openTraceFile(callIdx: number, tid: number): void {
    ensureTraceDir();
    const path = `${STATE.traceDir}/trace_call${callIdx}_tid${tid}.bin`;
    STATE.traceFile = new File(path, "wb");
    STATE.traceFilePath = path;
    log(`[+] trace 文件 = ${path}`);

    if (STATE.simdSidecar) {
        const { SIMD_REC_SIZE } = require("./state");
        const simdPath = `${STATE.traceDir}/simd_trace_call${callIdx}_tid${tid}.bin`;
        STATE.simdTraceFile = new File(simdPath, "wb");
        STATE.simdTraceFilePath = simdPath;
        log(`[+] SIMD sidecar 文件 = ${simdPath} (record=${SIMD_REC_SIZE} stride=${STATE.simdSampleStride})`);
    } else {
        STATE.simdTraceFile = null;
        STATE.simdTraceFilePath = null;
    }
}

export function closeTraceFile(): void {
    if (STATE.traceFile) {
        try { STATE.traceFile.close(); } catch (_) {}
        STATE.traceFile = null;
    }
}

export function closeSimdTraceFile(): void {
    if (STATE.simdTraceFile) {
        try { STATE.simdTraceFile.close(); } catch (_) {}
        STATE.simdTraceFile = null;
    }
}

/** Start the periodic flush timer + heartbeat watchdog */
export function ensureFlushTimer(): void {
    if (STATE.flushTimer) return;

    STATE.flushTimer = setInterval(() => {
        flushRingToDisk("interval");
        flushSimdRingToDisk("interval");
    }, FLUSH_INTERVAL_MS);

    if (!STATE.hbTimer) {
        STATE.hbTimer = setInterval(() => {
            const h = STATE.headBuf!.readU64().toNumber();
            const t = STATE.tailBuf!.readU64().toNumber();
            const dropped = STATE.droppedBuf!.readU64().toNumber();
            const ringQueue = h - t;
            const total = h;

            send({
                type: "hb", head: h, tail: t, queued: ringQueue,
                total, dropped, fnEntered: STATE.fnEntered, callIdx: STATE.callIdx
            });

            // maxRecords cap: if CModule stopped producing, finalize the call
            if (STATE.fnEntered && STATE.maxRecords > 0 && total >= STATE.maxRecords && ringQueue === 0) {
                log(`[!] maxRecords cap reached (${total} >= ${STATE.maxRecords}), finalizing call #${STATE.callIdx}`);
                try { Stalker.unfollow(STATE.primaryTid); } catch (_) {}
                try { Stalker.flush(); } catch (_) {}
                flushRingToDisk("max-records");
                flushSimdRingToDisk("max-records");
                closeTraceFile();
                closeSimdTraceFile();
                const ms = Date.now() - STATE.started;
                const dropped = STATE.droppedBuf!.readU64().toNumber();

                const { flushJniHookEvents } = require("../hooks/jni_vtable");
                const { flushSemanticEvents } = require("../sidecar/semantic");
                const { flushExtWriteEvents } = require("../hooks/boundary_diff");
                const { flushForkEvents } = require("../hooks/fork_monitor");
                try { flushJniHookEvents(STATE.callIdx); } catch (e) { log(`[!] flushJni: ${e}`); }
                try { flushSemanticEvents(STATE.callIdx); } catch (e) { log(`[!] flushSemantic: ${e}`); }
                try { flushExtWriteEvents(); } catch (e) { log(`[!] flushExt: ${e}`); }
                try { flushForkEvents(STATE.callIdx); } catch (e) { log(`[!] flushFork: ${e}`); }

                const { SIMD_REC_SIZE } = require("./state");
                send({
                    type: "trace-end", callIdx: STATE.callIdx,
                    tid: STATE.primaryTid, retval: "?",
                    ms, total, dropped, truncated: true,
                    devicePath: STATE.traceFilePath,
                    simdDevicePath: STATE.simdTraceFilePath,
                    simdRecords: STATE.simdSidecar ? STATE.simdHeadBuf!.readU64().toNumber() : 0,
                    simdDropped: STATE.simdSidecar ? STATE.simdDroppedBuf!.readU64().toNumber() : 0,
                    simdRecordSize: SIMD_REC_SIZE,
                    simdSampleStride: STATE.simdSampleStride
                });
                STATE.fnEntered = false;
                STATE.stuckSecs = 0;
                STATE.lastTotal = total;
                return;
            }

            if (STATE.fnEntered && total === STATE.lastTotal && ringQueue === 0) {
                STATE.stuckSecs++;
                if (STATE.stuckSecs >= STATE.stuckThreshold) {
                    log(`[!] watchdog: call #${STATE.callIdx} 卡死 ${STATE.stuckSecs}s, 强制结束`);
                    try { Stalker.unfollow(STATE.primaryTid); } catch (_) {}
                    try { Stalker.flush(); } catch (_) {}
                    flushRingToDisk("watchdog");
                    flushSimdRingToDisk("watchdog");
                    closeTraceFile();
                    closeSimdTraceFile();
                    const ms = Date.now() - STATE.started;

                    // Flush sidecar events
                    const { flushJniHookEvents } = require("../hooks/jni_vtable");
                    const { flushSemanticEvents } = require("../sidecar/semantic");
                    const { flushExtWriteEvents } = require("../hooks/boundary_diff");
                    const { flushForkEvents } = require("../hooks/fork_monitor");
                    try { flushJniHookEvents(STATE.callIdx); } catch (e) { log(`[!] flushJni: ${e}`); }
                    try { flushSemanticEvents(STATE.callIdx); } catch (e) { log(`[!] flushSemantic: ${e}`); }
                    try { flushExtWriteEvents(); } catch (e) { log(`[!] flushExt: ${e}`); }
                    try { flushForkEvents(STATE.callIdx); } catch (e) { log(`[!] flushFork: ${e}`); }

                    const { SIMD_REC_SIZE } = require("./state");
                    send({
                        type: "trace-end", callIdx: STATE.callIdx,
                        tid: STATE.primaryTid, retval: "?",
                        ms, total, dropped, truncated: true,
                        devicePath: STATE.traceFilePath,
                        simdDevicePath: STATE.simdTraceFilePath,
                        simdRecords: STATE.simdSidecar ? STATE.simdHeadBuf!.readU64().toNumber() : 0,
                        simdDropped: STATE.simdSidecar ? STATE.simdDroppedBuf!.readU64().toNumber() : 0,
                        simdRecordSize: SIMD_REC_SIZE,
                        simdSampleStride: STATE.simdSampleStride
                    });
                    STATE.fnEntered = false;
                    STATE.stuckSecs = 0;
                }
            } else {
                STATE.stuckSecs = 0;
            }
            STATE.lastTotal = total;
        }, 1000);
    }
}
