/** native 写盘生命周期：路径探测、打开、封口、线程收尾。 */

import { STATE, REC_SIZE, TraceRingState, WorkerTraceState } from "./state";
import { log, getExport } from "./utils";
import { flushSimdRingToDisk } from "../sidecar/simd";

import { NativeFile } from "./native_io";

/** 只在生产结束或显式停止后刷尾部；采集期间由 native 满批写入。 */
export function flushRingToDisk(_reason?: string): void {
    if (STATE.traceFile) STATE.flushNative();
}
export function flushTraceRingToFile(ring: TraceRingState): boolean {
    if (!ring.file) return false;
    ring.flushNative();
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
            worker.file.close();
            worker.file = null;
        }
    }
}

export function workerTraceSummaries(): any[] {
    const out: any[] = [];
    const currentHead = STATE.headBuf ? STATE.headBuf.readU64().toNumber() : 0;
    for (const key of Object.keys(STATE.workerTraces || {})) {
        const worker = STATE.workerTraces[key] as WorkerTraceState;
        const spawnedAtIdx = typeof worker.spawnedAtIdx === "number" ? worker.spawnedAtIdx : 0;
        const endedAtIdx = typeof worker.endedAtIdx === "number" ? worker.endedAtIdx : currentHead;
        out.push({
            tid: worker.tid,
            file: `worker_trace_tid${worker.tid}.bin`,
            pthread: worker.pthread,
            start: worker.start,
            devicePath: worker.filePath,
            records: worker.headBuf.readU64().toNumber(),
            dropped: worker.droppedBuf.readU64().toNumber(),
            recordSize: REC_SIZE,
            spawnedAtIdx,
            endedAtIdx,
            anchorHeadIdx: spawnedAtIdx,
            // pthread_create 返回后 1ms 取第一个新 tid 是启发式归因, 消费方须知
            tid_attribution: "heuristic",
        });
    }
    return out;
}

export function unfollowWorkerThreads(): void {
    const endedIdx = STATE.headBuf ? STATE.headBuf.readU64().toNumber() : 0;
    for (const key of Object.keys(STATE.workerTraces || {})) {
        const worker = STATE.workerTraces[key];
        if (worker.endedAtIdx === null || worker.endedAtIdx === undefined) {
            worker.endedAtIdx = endedIdx;
        }
        try { Stalker.unfollow(worker.tid); } catch (_) {}
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
            try { (worker.cm as any).dispose(); } catch (_) {}
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

/** 用实际目标 UID 做创建、写入、fsync 和回读探测。 */
function probeDirWritable(dir: string): boolean {
    const path = `${dir}/.probe_${Date.now()}`;
    try {
        const file = new NativeFile(path);
        file.write("tracemiku-probe");
        file.close();
        const bytes = new Uint8Array(File.readAllBytes(path));
        if (String.fromCharCode(...bytes) !== "tracemiku-probe") return false;
        const unlink = new NativeFunction(getExport("unlink")!, "int", ["pointer"]);
        return unlink(Memory.allocUtf8String(path)) === 0;
    } catch (_) { return false; }
}

/** 只采用经过目标进程写探测的路径；host 随后必须验证同一个 session.json。 */
export function ensureTraceDir(): void {
    const mkdir = getMkdirFn();
    if (!mkdir) throw new Error("mkdir unavailable");
    if (STATE.traceDir) {
        mkdir(Memory.allocUtf8String(STATE.traceDir), 0o700);
        if (!probeDirWritable(STATE.traceDir)) throw new Error(`trace directory is not writable: ${STATE.traceDir}`);
        return;
    }
    if (!STATE.pkg) {
        try {
            STATE.pkg = String.fromCharCode(...new Uint8Array(File.readAllBytes("/proc/self/cmdline"))).split("\0")[0];
        } catch (_) {}
    }
    const parents: string[] = [];
    // 路径只是候选，绝不以包名推断可写性或回传源。
    if (STATE.pkg && /^[a-zA-Z0-9_.]+$/.test(STATE.pkg)) {
        parents.push(`/data/data/${STATE.pkg}/files/.miku`);
        try {
            const uid = new NativeFunction(getExport("getuid")!, "uint", [])();
            parents.unshift(`/data/user/${Math.floor(uid / 100000)}/${STATE.pkg}/files/.miku`);
        } catch (_) {}
    }
    parents.push("/data/local/tmp");
    for (const parent of parents) {
        // 全新安装的 app 在 spawn 挂起点尚未调用 Context.getFilesDir()。
        // 用目标 UID 创建自己的 files，不能要求 host 代写或 chmod 私有目录。
        if (parent.endsWith("/files/.miku")) {
            mkdir(Memory.allocUtf8String(parent.slice(0, -6)), 0o700);
        }
        mkdir(Memory.allocUtf8String(parent), 0o700);
        const dir = `${parent}/session_${Process.id}_${Date.now()}`;
        if (mkdir(Memory.allocUtf8String(dir), 0o700) !== 0) continue;
        if (probeDirWritable(dir)) {
            STATE.traceDir = dir;
            log(`[+] verified target writable spool: ${dir}`);
            return;
        }
    }
    throw new Error("no target-writable spool directory; specify --device-dir");
}

/** Open trace output file for a call */
export function openTraceFile(callIdx: number, tid: number): void {
    ensureTraceDir();
    const path = `${STATE.traceDir}/trace_call${callIdx}_tid${tid}.bin`;
    STATE.traceFile = new NativeFile(path, STATE.traceIoState!);
    STATE.traceFilePath = path;
    STATE.active!.writeS32(1);
    log(`[+] trace 文件 = ${path}`);

    if (STATE.simdSidecar) {
        const { SIMD_REC_SIZE } = require("./state");
        const simdPath = `${STATE.traceDir}/simd_trace_call${callIdx}_tid${tid}.bin`;
        STATE.simdTraceFile = new NativeFile(simdPath, STATE.simdIoState!);
        STATE.simdTraceFilePath = simdPath;
        log(`[+] SIMD sidecar 文件 = ${simdPath} (record=${SIMD_REC_SIZE} stride=${STATE.simdSampleStride})`);
    } else {
        STATE.simdTraceFile = null;
        STATE.simdTraceFilePath = null;
    }
}

export function closeTraceFile(): void {
    if (STATE.traceFile) {
        STATE.traceFile.close();
        STATE.traceFile = null;
    }
}

export function closeSimdTraceFile(): void {
    if (STATE.simdTraceFile) {
        STATE.simdTraceFile.close();
        STATE.simdTraceFile = null;
    }
}

/** 心跳只观测，不以无进展时间决定调用结束。 */
export function ensureFlushTimer(): void {
    if (STATE.hbTimer) return;
    STATE.hbTimer = setInterval(() => {
        const h = STATE.headBuf!.readU64().toNumber();
        const t = STATE.tailBuf!.readU64().toNumber();
        send({ type: "hb", head: h, tail: t, queued: h - t, total: h,
            dropped: 0, fnEntered: STATE.fnEntered, callIdx: STATE.callIdx,
            io_errno: STATE.traceIoState?.add(4).readS32() || 0 });
    }, 1000);
}
