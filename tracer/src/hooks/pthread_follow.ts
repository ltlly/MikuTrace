import { persistEvents } from "../transport/manifest";
/**
 * Optional pthread worker Stalker follow.
 *
 * This is intentionally opt-in and bounded: the main trace ring remains the
 * same 272-byte global stream, and only a small number of newly created worker
 * threads are followed. Events are flushed into meta so users can tell exactly
 * which tids were followed.
 */

import {
    STATE, REC_SIZE, WORKER_RING_BYTES, WORKER_RING_RECS, WorkerTraceState,
    HARD_EXCL, ART_EXCL, SOFT_EXCL,
} from "../core/state";
import { log, getExport, currentTraceIdx, PTR_UNTAG_MASK } from "../core/utils";
import { createTransform } from "../core/stalker";
import { NativeFile } from "../core/native_io";
import { buildTraceRingCModule } from "../core/cmodule";

const SYSTEM_THREAD_EXACT = new Set([
    "gum-js-loop", "gmain", "gdbus", "pool-frida",
    "HeapTaskDaemon", "ReferenceQueueD", "FinalizerDaemon", "FinalizerWatchd",
    "Profile Saver", "Jit thread pool", "RenderThread", "queued-work-loo",
    "Signal Catcher",
]);

const SYSTEM_THREAD_PREFIXES = [
    "frida", "Binder:", "hwuiTask", "ADB-JDWP", "Studio:",
    "ImageDecompress", " ImageDecompress", "mali-", "ged-",
];

const EXCLUDED_WORKER_START_MODULES = [
    ...HARD_EXCL, ...ART_EXCL, ...SOFT_EXCL,
    "libhwui.so", "libandroid_runtime.so",
];

function findExport(name: string): NativePointer | null {
    return getExport(name);
}

function readThreadComm(tid: number): string | null {
    const path = `/proc/self/task/${tid}/comm`;
    try {
        if (typeof (File as any)?.readAllText === "function") {
            const text = (File as any).readAllText(path);
            if (typeof text === "string") return text.trim();
        }
    } catch (_) {}
    try {
        if (typeof (File as any)?.readAllBytes === "function") {
            const bytes = new Uint8Array((File as any).readAllBytes(path));
            let s = "";
            for (let i = 0; i < bytes.length && bytes[i] !== 0 && bytes[i] !== 10; i++) {
                s += String.fromCharCode(bytes[i]);
            }
            return s.trim();
        }
    } catch (_) {}
    try {
        const openPtr = getExport("open");
        const readPtr = getExport("read");
        const closePtr = getExport("close");
        if (openPtr && readPtr && closePtr) {
            const openFn = new NativeFunction(openPtr, "int", ["pointer", "int", "int"]);
            const readFn = new NativeFunction(readPtr, "long", ["int", "pointer", "ulong"]);
            const closeFn = new NativeFunction(closePtr, "int", ["int"]);
            const fd = openFn(Memory.allocUtf8String(path), 0, 0) as unknown as number;
            if (fd >= 0) {
                try {
                    const buf = Memory.alloc(64);
                    const n = Number(readFn(fd, buf, 63));
                    if (n > 0) {
                        buf.add(n).writeU8(0);
                        return (buf.readUtf8String(n) || "").trim();
                    }
                } finally {
                    closeFn(fd);
                }
            }
        }
    } catch (_) {}
    return null;
}

export function isSystemOrInternalThread(tid: number, commOverride?: string | null): boolean {
    const comm = commOverride !== undefined ? commOverride : readThreadComm(tid);
    if (!comm) return false;
    const trimmed = comm.trim();
    if (SYSTEM_THREAD_EXACT.has(trimmed)) return true;
    for (const prefix of SYSTEM_THREAD_PREFIXES) {
        if (trimmed.startsWith(prefix) || comm.startsWith(prefix)) return true;
    }
    return false;
}

function isAddressInIncludeRanges(addr: NativePointer | null): boolean {
    if (!addr || addr.isNull()) return false;
    const untagged = (() => {
        try { return addr.and(PTR_UNTAG_MASK); } catch (_) { return addr; }
    })();
    if (STATE.target) {
        try {
            if (untagged.compare(STATE.target.base) >= 0 && untagged.compare(STATE.target.end) < 0) {
                return true;
            }
        } catch (_) {}
    }
    const ranges = STATE.includeRanges || [];
    for (let i = 0; i < ranges.length; i++) {
        try {
            if (untagged.compare(ranges[i].base) >= 0 && untagged.compare(ranges[i].end) < 0) {
                return true;
            }
        } catch (_) {}
    }
    return false;
}

function findExcludedSystemModuleForAddress(addr: NativePointer | null): string | null {
    if (!addr || addr.isNull()) return null;
    if (isAddressInIncludeRanges(addr)) return null;
    const untagged = (() => {
        try { return addr.and(PTR_UNTAG_MASK); } catch (_) { return addr; }
    })();
    try {
        if (typeof (Process as any).findModuleByAddress === "function") {
            const m = (Process as any).findModuleByAddress(untagged);
            if (m && m.name && EXCLUDED_WORKER_START_MODULES.some(p => m.name.indexOf(p) !== -1)) {
                return m.name;
            }
        }
    } catch (_) {}
    try {
        if (typeof Process.enumerateModules === "function") {
            for (const m of Process.enumerateModules()) {
                if (!m || !m.base || !m.size) continue;
                const end = m.base.add(m.size);
                if (untagged.compare(m.base) >= 0 && untagged.compare(end) < 0) {
                    if (EXCLUDED_WORKER_START_MODULES.some(p => m.name.indexOf(p) !== -1)) {
                        return m.name;
                    }
                    return null;
                }
            }
        }
    } catch (_) {}
    return null;
}

function shouldSkipSystemThreadSpawn(start: NativePointer | null, caller: NativePointer | null): { skip: boolean; mod?: string } {
    if (STATE.deepTrace || STATE.traceAll) return { skip: false };
    const startSysMod = findExcludedSystemModuleForAddress(start);
    if (startSysMod) {
        return { skip: true, mod: startSysMod };
    }
    if (isAddressInIncludeRanges(start)) {
        return { skip: false };
    }
    if (STATE.target || (STATE.includeRanges && STATE.includeRanges.length > 0)) {
        const callerSysMod = findExcludedSystemModuleForAddress(caller);
        return { skip: true, mod: callerSysMod || "outside-target" };
    }
    return { skip: false };
}

function rememberWorkerEvent(event: Record<string, unknown>): void {
    const anchorHeadIdx = currentTraceIdx(STATE.headBuf);
    STATE.workerEvents.push({
        type: "worker-thread",
        ts: Date.now(),
        anchorHeadIdx,
        ...event,
    });
    if (STATE.workerEvents.length >= 128) flushWorkerEvents(STATE.callIdx);
}

function openWorkerTrace(tid: number, pthread: string, start: NativePointer, spawnedAtIdx?: number): WorkerTraceState {
    const path = `${STATE.traceDir}/worker_trace_call${STATE.callIdx}_tid${tid}.bin`;
    const file = new NativeFile(path);
    const anchorIdx = typeof spawnedAtIdx === "number" ? spawnedAtIdx : currentTraceIdx(STATE.headBuf);
    const worker: WorkerTraceState = {
        tid,
        pthread,
        start: start ? start.toString() : "0x0",
        spawnedAtIdx: anchorIdx,
        endedAtIdx: null,
        ringBuf: Memory.alloc(WORKER_RING_BYTES),
        headBuf: Memory.alloc(8),
        tailBuf: Memory.alloc(8),
        droppedBuf: Memory.alloc(8),
        ringRecsBuf: Memory.alloc(8),
        ringRecs: WORKER_RING_RECS,
        file, ioState: file.state, flushNative: null, active: Memory.alloc(4),
        filePath: path,
        cm: null,
        onInsnPtr: NULL,
    };
    worker.active.writeS32(1);
    worker.headBuf.writeU64(0);
    worker.tailBuf.writeU64(0);
    worker.droppedBuf.writeU64(0);
    worker.ringRecsBuf.writeU64(WORKER_RING_RECS);
    worker.cm = buildTraceRingCModule(worker);
    worker.onInsnPtr = (worker.cm as any).on_insn;
    STATE.workerTraces[String(tid)] = worker;
    log(`[pthread-follow] worker ring tid=${tid} path=${path} record=${REC_SIZE} ring=${WORKER_RING_RECS} spawnedAtIdx=${anchorIdx}`);
    return worker;
}

let pendingWorkerReservations = 0;

function activeOrReservedWorkerCount(): number {
    return Object.keys(STATE.followedWorkerTids).length + pendingWorkerReservations;
}

export function followResidentWorkerThreads(): void {
    if (!STATE.followWorkers || !STATE.traceDir) return;
    const hasTargetRanges = !!(STATE.target || (STATE.includeRanges && STATE.includeRanges.length > 0));
    let threads: ThreadDetails[] = [];
    try { threads = Process.enumerateThreads(); } catch (e) {
        rememberWorkerEvent({ status: "failed", error: String(e), pthread: "resident", start: "0x0" });
        return;
    }
    for (const t of threads) {
        const tid = t.id;
        const key = String(tid);
        if (tid === STATE.primaryTid || tid === Process.id || STATE.followedWorkerTids[key]) continue;
        const comm = (t as any).name !== undefined ? String((t as any).name) : readThreadComm(tid);
        if (isSystemOrInternalThread(tid, comm)) {
            rememberWorkerEvent({ status: "skipped_system", start: "resident", tid, comm: comm || null });
            continue;
        }
        const ctxPc = (t as any).context?.pc as NativePointer | undefined;
        const ctxLr = (t as any).context?.lr as NativePointer | undefined;
        if (!STATE.deepTrace && !STATE.traceAll && hasTargetRanges) {
            const inRange = isAddressInIncludeRanges(ctxPc || null);
            const lrSysMod = findExcludedSystemModuleForAddress(ctxLr || null);
            if (!inRange || lrSysMod) {
                const sysMod = findExcludedSystemModuleForAddress(ctxPc || null) || lrSysMod;
                rememberWorkerEvent({
                    status: "skipped_system",
                    start: "resident",
                    tid,
                    comm: comm || null,
                    module: sysMod || "outside-target",
                });
                continue;
            }
        }
        if (activeOrReservedWorkerCount() >= STATE.maxWorkerThreads) {
            rememberWorkerEvent({ status: "skipped_cap", start: "resident", tid });
            break;
        }
        const spawnedAtIdx = currentTraceIdx(STATE.headBuf);
        let worker: WorkerTraceState | null = null;
        try {
            worker = openWorkerTrace(tid, "resident", NULL, spawnedAtIdx);
            const ranges = STATE.includeRanges.map(r => ({ base: r.base, end: r.end }));
            Stalker.follow(tid, {
                events: { call: false, ret: false, exec: false, block: false, compile: false },
                transform: createTransform(worker.onInsnPtr, ranges),
            });
            STATE.followedWorkerTids[key] = true;
            rememberWorkerEvent({
                status: "followed",
                tid,
                pthread: "resident",
                start: "0x0",
                devicePath: worker.filePath,
                recordSize: REC_SIZE,
                spawnedAtIdx,
                anchorHeadIdx: spawnedAtIdx,
            });
            log(`[pthread-follow] Stalker.follow resident tid=${tid}`);
        } catch (e) {
            if (worker) {
                try { worker.file?.close(); } catch (_) {}
                try { worker.cm?.dispose(); } catch (_) {}
                delete STATE.workerTraces[key];
            }
            rememberWorkerEvent({ status: "failed", error: String(e), pthread: "resident", start: "0x0", tid });
            log(`[pthread-follow][!] resident follow failed tid=${tid}: ${e}`);
        }
    }
}

export function installPthreadFollowOnce(): void {
    if (!STATE.followWorkers) return;
    followResidentWorkerThreads();
    if (STATE.pthreadHooksInstalled) return;

    const pthreadCreate = findExport("pthread_create");
    if (!pthreadCreate) {
        rememberWorkerEvent({ status: "failed", error: "pthread_create symbol not found", start: "0x0" });
        log("[pthread-follow] pthread_create not found");
        return;
    }

    Interceptor.attach(pthreadCreate, {
        onEnter(args) {
            (this as any)._threadPtr = args[0];
            (this as any)._start = args[2];
            (this as any)._caller = (this as any).returnAddress || null;
            (this as any)._spawnedAtIdx = currentTraceIdx(STATE.headBuf);
            (this as any)._enterCallIdx = STATE.callIdx;
            const preTids: Record<string, boolean> = {};
            try {
                for (const t of Process.enumerateThreads()) {
                    preTids[String(t.id)] = true;
                }
            } catch (_) {}
            (this as any)._preTids = preTids;
        },
        onLeave(rv) {
            if ((!STATE.fnEntered && !STATE.preEntryActive) || !STATE.followWorkers || !STATE.traceDir) return;
            if ((this as any)._enterCallIdx !== STATE.callIdx) return;
            if (rv.toInt32() !== 0) return;
            const start = (this as any)._start as NativePointer;
            const caller = (this as any)._caller as NativePointer | null;
            const preTids: Record<string, boolean> = (this as any)._preTids || {};
            const spawnedAtIdx = typeof (this as any)._spawnedAtIdx === "number"
                ? (this as any)._spawnedAtIdx
                : currentTraceIdx(STATE.headBuf);
            const sysCheck = shouldSkipSystemThreadSpawn(start, caller);
            if (sysCheck.skip) {
                rememberWorkerEvent({
                    status: "skipped_system",
                    start: start ? start.toString() : "0x0",
                    module: sysCheck.mod || null,
                    spawnedAtIdx,
                    anchorHeadIdx: spawnedAtIdx,
                });
                return;
            }
            if (activeOrReservedWorkerCount() >= STATE.maxWorkerThreads) {
                rememberWorkerEvent({
                    status: "skipped_cap",
                    start: String(start),
                    spawnedAtIdx,
                    anchorHeadIdx: spawnedAtIdx,
                });
                return;
            }
            pendingWorkerReservations++;
            let pthreadValue = "0x0";
            try { pthreadValue = (this as any)._threadPtr.readPointer().toString(); } catch (_) {}
            rememberWorkerEvent({
                status: "created",
                pthread: pthreadValue,
                start: start.toString(),
                spawnedAtIdx,
                anchorHeadIdx: spawnedAtIdx,
            });
            const callIdx = STATE.callIdx;

            setTimeout(() => {
                pendingWorkerReservations = Math.max(0, pendingWorkerReservations - 1);
                if ((!STATE.fnEntered && !STATE.preEntryActive) || STATE.callFinalized || STATE.callIdx !== callIdx) return;
                if (Object.keys(STATE.followedWorkerTids).length >= STATE.maxWorkerThreads) {
                    rememberWorkerEvent({
                        status: "skipped_cap",
                        start: String(start),
                        spawnedAtIdx,
                        anchorHeadIdx: spawnedAtIdx,
                    });
                    return;
                }
                let worker: WorkerTraceState | null = null;
                let chosenKey: string | null = null;
                try {
                    const threads = Process.enumerateThreads();
                    for (const t of threads) {
                        const tid = t.id;
                        const key = String(tid);
                        if (tid === STATE.primaryTid || tid === Process.id || preTids[key] || STATE.followedWorkerTids[key]) continue;
                        const comm = (t as any).name !== undefined ? String((t as any).name) : readThreadComm(tid);
                        if (isSystemOrInternalThread(tid, comm)) {
                            continue;
                        }
                        chosenKey = key;
                        worker = openWorkerTrace(tid, pthreadValue, start, spawnedAtIdx);
                        const ranges = STATE.includeRanges.map(r => ({ base: r.base, end: r.end }));
                        Stalker.follow(tid, {
                            events: { call: false, ret: false, exec: false, block: false, compile: false },
                            transform: createTransform(worker.onInsnPtr, ranges),
                        });
                        STATE.followedWorkerTids[key] = true;
                        rememberWorkerEvent({
                            status: "followed",
                            tid,
                            pthread: pthreadValue,
                            start: start.toString(),
                            devicePath: worker.filePath,
                            recordSize: REC_SIZE,
                            spawnedAtIdx,
                            anchorHeadIdx: spawnedAtIdx,
                        });
                        log(`[pthread-follow] Stalker.follow tid=${tid} start=${start} spawnedAtIdx=${spawnedAtIdx}`);
                        return;
                    }
                    rememberWorkerEvent({
                        status: "no_new_tid",
                        pthread: pthreadValue,
                        start: start.toString(),
                        spawnedAtIdx,
                        anchorHeadIdx: spawnedAtIdx,
                    });
                } catch (e) {
                    if (worker && chosenKey) {
                        try { worker.file?.close(); } catch (_) {}
                        try { worker.cm?.dispose(); } catch (_) {}
                        delete STATE.workerTraces[chosenKey];
                    }
                    rememberWorkerEvent({
                        status: "failed",
                        error: String(e),
                        pthread: pthreadValue,
                        start: start.toString(),
                        spawnedAtIdx,
                        anchorHeadIdx: spawnedAtIdx,
                    });
                    log(`[pthread-follow][!] ${e}`);
                }
            }, 1);
        }
    });
    STATE.pthreadHooksInstalled = true;
    log(`[pthread-follow] installed pthread_create hook max=${STATE.maxWorkerThreads}`);
}

export function flushWorkerEvents(callIdx: number): number {
    if (!STATE.workerEvents || STATE.workerEvents.length === 0) return 0;
    const events = STATE.workerEvents;
    persistEvents("worker_events.jsonl", events);
    STATE.workerEvents = [];

    return events.length;
}
