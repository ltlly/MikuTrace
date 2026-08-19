/**
 * SPSC lock-free ring buffer — V8 consumer (flush to disk)
 *
 * 架构:
 *   cmodule on_insn → SPSC ring (17MB, head/tail monotonic 计数, atomic) →
 *   v8 setInterval 10ms → File.write → device file
 */

import { STATE, REC_SIZE, RING_RECS, FLUSH_INTERVAL_MS, TraceRingState, WorkerTraceState } from "./state";
import { log, getExport } from "./utils";
import { flushSimdRingToDisk } from "../sidecar/simd";

/** flush-error 上报节流间隔 (ms): 磁盘满时每 10ms 一次会刷屏 */
const FLUSH_ERROR_REPORT_INTERVAL_MS = 5000;
let lastFlushErrorTs = 0;

function sendFlushError(e: unknown): void {
    const now = Date.now();
    if (now - lastFlushErrorTs < FLUSH_ERROR_REPORT_INTERVAL_MS) return;
    lastFlushErrorTs = now;
    send({
        type: "flush-error",
        callIdx: STATE.callIdx,
        traceFilePath: STATE.traceFilePath,
        error: String(e),
        ts: now,
    });
}

/** Flush main trace ring to disk */
export function flushRingToDisk(_reason?: string): void {
    if (!STATE.traceFile) return;
    const flushed = flushTraceRingToFile({
        ringBuf: STATE.ringBuf!,
        headBuf: STATE.headBuf!,
        tailBuf: STATE.tailBuf!,
        droppedBuf: STATE.droppedBuf!,
        ringRecsBuf: STATE.ringRecsBuf!,
        maxRecordsBuf: STATE.maxRecordsBuf!,
        ringRecs: RING_RECS,
        file: STATE.traceFile,
        filePath: STATE.traceFilePath,
    });
    if (flushed) STATE.batchSeq++;
}

export function flushTraceRingToFile(ring: TraceRingState): boolean {
    if (!ring.file) return false;
    const h = ring.headBuf.readU64().toNumber();
    const t = ring.tailBuf.readU64().toNumber();
    const avail = h - t;
    if (avail <= 0) return false;

    const tOff = t % ring.ringRecs;
    const hOff = h % ring.ringRecs;

    // 写盘失败 (磁盘满/IO 错误) 不能让异常逃逸: timer 回调里会刷屏且 tail 永不推进.
    // 失败时报告 host 并保持 tail 不变, 下个周期重试; 持续失败由环满降级终结本 call.
    try {
        if (avail >= ring.ringRecs) {
            // Ring wrote full circle
            ring.file.write(
                ring.ringBuf.add(tOff * REC_SIZE).readByteArray((ring.ringRecs - tOff) * REC_SIZE)
            );
            if (tOff > 0) {
                ring.file.write(ring.ringBuf.readByteArray(tOff * REC_SIZE));
            }
        } else if (hOff > tOff) {
            // No wrap: single segment
            ring.file.write(
                ring.ringBuf.add(tOff * REC_SIZE).readByteArray(avail * REC_SIZE)
            );
        } else {
            // Wrap: two segments
            ring.file.write(
                ring.ringBuf.add(tOff * REC_SIZE).readByteArray((ring.ringRecs - tOff) * REC_SIZE)
            );
            if (hOff > 0) {
                ring.file.write(ring.ringBuf.readByteArray(hOff * REC_SIZE));
            }
        }
    } catch (e) {
        sendFlushError(e);
        return false;
    }
    ring.tailBuf.writeU64(h);
    return true;
}

export function flushWorkerTraceRings(_reason?: string): void {
    for (const key of Object.keys(STATE.workerTraces || {})) {
        flushTraceRingToFile(STATE.workerTraces[key]);
    }
}

export function closeWorkerTraceFiles(): void {
    for (const key of Object.keys(STATE.workerTraces || {})) {
        const worker = STATE.workerTraces[key];
        if (worker.file) {
            try { worker.file.close(); } catch (_) {}
            worker.file = null;
        }
    }
}

export function workerTraceSummaries(): any[] {
    const out: any[] = [];
    for (const key of Object.keys(STATE.workerTraces || {})) {
        const worker = STATE.workerTraces[key] as WorkerTraceState;
        out.push({
            tid: worker.tid,
            pthread: worker.pthread,
            start: worker.start,
            devicePath: worker.filePath,
            records: worker.headBuf.readU64().toNumber(),
            dropped: worker.droppedBuf.readU64().toNumber(),
            recordSize: REC_SIZE,
            // pthread_create 返回后 1ms 取第一个新 tid 是启发式归因, 消费方须知
            tid_attribution: "heuristic",
        });
    }
    return out;
}

export function unfollowWorkerThreads(): void {
    for (const key of Object.keys(STATE.workerTraces || {})) {
        try { Stalker.unfollow(STATE.workerTraces[key].tid); } catch (_) {}
    }
}

/** 释放上一 call 的 worker 资源: CModule 显式 unload + 文件关闭.
 *  第二个 call 复用同 tid 时若旧 CModule 不 unload, native 内存 (ring buffer +
 *  编译产物) 会持续泄漏. onEnter 重置 workerTraces 前调用. */
export function releaseWorkerTraces(): void {
    for (const key of Object.keys(STATE.workerTraces || {})) {
        const worker = STATE.workerTraces[key];
        if (worker.file) {
            try { worker.file.close(); } catch (_) {}
            worker.file = null;
        }
        if (worker.cm) {
            try { (worker.cm as any).unload(); } catch (_) {}
            worker.cm = null;
        }
    }
}

/** Resolve libc mkdir via getExport (handles linker namespace issues) */
function getMkdirFn(): NativeFunction<number, [NativePointerValue, number]> | null {
    const ptr = getExport("mkdir");
    if (ptr) {
        return new NativeFunction(ptr, "int", ["pointer", "int"]);
    }
    return null;
}

/** 实际探测目录可写: 创建并删除探测文件.
 *  mkdir 返回 -1 无法区分 EEXIST 与 EPERM/EACCES — 只有真实写入才能确认. */
function probeDirWritable(dir: string): boolean {
    const probePath = `${dir}/.miku_probe_${Date.now()}`;
    try {
        const f = new File(probePath, "wb");
        f.write(new Uint8Array(1).buffer);
        f.close();
    } catch (_) {
        return false;
    }
    try {
        const unlinkPtr = getExport("unlink");
        if (unlinkPtr) {
            const unlink = new NativeFunction(unlinkPtr, "int", ["pointer"]);
            unlink(Memory.allocUtf8String(probePath));
        }
    } catch (_) { /* unlink 失败只残留 1 字节探测文件, 无害 */ }
    return true;
}

/** Ensure trace dir exists, with fallbacks for attach-pid mode */
export function ensureTraceDir(): void {
    if (STATE.traceDir) return;

    // Try multiple methods to get package name
    if (!STATE.pkg) {
        try {
            // Frida 的 File 没有 read(); readAllBytes 可处理 cmdline 的 NUL 分隔
            const buf = (File as any).readAllBytes("/proc/self/cmdline") as ArrayBuffer;
            const pkg = String.fromCharCode.apply(null, new Uint8Array(buf) as any).split("\0")[0];
            if (pkg && pkg.length > 0 && pkg !== "unknown") {
                STATE.pkg = pkg;
            }
        } catch (_) {}
    }

    if (!STATE.pkg || STATE.pkg === "unknown") {
        try {
            const buf = (File as any).readAllBytes("/proc/self/attr/current") as ArrayBuffer;
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
        // mkdir rc=-1 兼 EEXIST 与 EPERM — 必须实际写入探测, 不可写则降级 fallback
        if ((result === 0 || result === -1) && probeDirWritable(primaryDir)) {
            STATE.traceDir = primaryDir;
            log(`[+] trace dir = ${STATE.traceDir}`);
            return;
        }
        log(`[!] primary 目录不可写 (mkdir rc=${result}), 降级 /data/local/tmp`);
    }

    // Fallback: /data/local/tmp (requires root/shell writable)
    const fallbackDir = `/data/local/tmp/.miku_${Process.id}`;
    const rc = mkdir(Memory.allocUtf8String(fallbackDir), 0o755) as unknown as number;
    if ((rc === 0 || rc === -1) && probeDirWritable(fallbackDir)) {
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

/** 环满降级阈值: 连续 N 个心跳 (每个 1s) 观察到主 ring 满载即强制终结.
 *  环满时生产端自旋 (SPIN_MAX 后丢记录), 且 watchdog 的 ringQueue===0 前置条件
 *  永不满足 — 必须独立降级路径, 否则磁盘满会让 call 永远挂着. */
const RING_FULL_FINALIZE_HEARTBEATS = 5;

/**
 * 强制终结当前 call: unfollow + flush + 关文件 + sidecar 事件 + trace-end(truncated).
 * maxRecords / watchdog / 环满降级三条路径共用. 置 callFinalized 防 onLeave 重复发 trace-end.
 */
function finalizeActiveCall(reason: string): void {
    try { Stalker.unfollow(STATE.primaryTid); } catch (_) {}
    unfollowWorkerThreads();
    try { Stalker.flush(); } catch (_) {}
    flushRingToDisk(reason);
    flushWorkerTraceRings(reason);
    flushSimdRingToDisk(reason);
    closeTraceFile();
    closeWorkerTraceFiles();
    closeSimdTraceFile();
    const ms = Date.now() - STATE.started;
    const total = STATE.headBuf!.readU64().toNumber();
    const dropped = STATE.droppedBuf!.readU64().toNumber();

    const { flushJniHookEvents } = require("../hooks/jni_vtable");
    const { flushSemanticEvents } = require("../sidecar/semantic");
    const { flushExtWriteEvents } = require("../hooks/boundary_diff");
    const { flushForkEvents } = require("../hooks/fork_monitor");
    const { flushWorkerEvents } = require("../hooks/pthread_follow");
    try { flushJniHookEvents(STATE.callIdx); } catch (e) { log(`[!] flushJni: ${e}`); }
    try { flushSemanticEvents(STATE.callIdx); } catch (e) { log(`[!] flushSemantic: ${e}`); }
    try { flushExtWriteEvents(); } catch (e) { log(`[!] flushExt: ${e}`); }
    try { flushForkEvents(STATE.callIdx); } catch (e) { log(`[!] flushFork: ${e}`); }
    try { flushWorkerEvents(STATE.callIdx); } catch (e) { log(`[!] flushWorkers: ${e}`); }

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
        simdSampleStride: STATE.simdSampleStride,
        workerTraces: workerTraceSummaries()
    });
    STATE.fnEntered = false;
    STATE.callFinalized = true;
    STATE.stuckSecs = 0;
    STATE.ringFullSecs = 0;
    STATE.lastTotal = total;
}

/** Start the periodic flush timer + heartbeat watchdog */
export function ensureFlushTimer(): void {
    if (STATE.flushTimer) return;

    STATE.flushTimer = setInterval(() => {
        try {
            flushRingToDisk("interval");
            flushWorkerTraceRings("interval");
            flushSimdRingToDisk("interval");
        } catch (e) {
            sendFlushError(e);
        }
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
                finalizeActiveCall("max-records");
                return;
            }

            // 环满降级: 消费端 (磁盘满/IO 卡死) 持续落后, 生产端已开始丢记录.
            if (STATE.fnEntered && ringQueue >= RING_RECS) {
                STATE.ringFullSecs++;
                if (STATE.ringFullSecs >= RING_FULL_FINALIZE_HEARTBEATS) {
                    log(`[!] ring 满载 ${STATE.ringFullSecs}s (queued=${ringQueue}, dropped=${dropped}), ` +
                        `降级终结 call #${STATE.callIdx}`);
                    finalizeActiveCall("ring-full");
                    return;
                }
            } else {
                STATE.ringFullSecs = 0;
            }

            if (STATE.fnEntered && total === STATE.lastTotal && ringQueue === 0) {
                STATE.stuckSecs++;
                if (STATE.stuckSecs >= STATE.stuckThreshold) {
                    log(`[!] watchdog: call #${STATE.callIdx} 卡死 ${STATE.stuckSecs}s, 强制结束`);
                    finalizeActiveCall("watchdog");
                }
            } else {
                STATE.stuckSecs = 0;
            }
            STATE.lastTotal = total;
        }, 1000);
    }
}
