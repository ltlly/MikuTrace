/**
 * Optional pthread worker Stalker follow.
 *
 * This is intentionally opt-in and bounded: the main trace ring remains the
 * same 272-byte global stream, and only a small number of newly created worker
 * threads are followed. Events are flushed into meta so users can tell exactly
 * which tids were followed.
 */

import { STATE, REC_SIZE, WORKER_RING_BYTES, WORKER_RING_RECS, WorkerTraceState } from "../core/state";
import { log } from "../core/utils";
import { createTransform } from "../core/stalker";
import { buildTraceRingCModule } from "../core/cmodule";

function findExport(name: string): NativePointer | null {
    try { return Module.findExportByName(null, name); } catch (_) {}
    try { return Module.findExportByName("libc.so", name); } catch (_) {}
    return null;
}

function rememberWorkerEvent(event: Record<string, unknown>): void {
    STATE.workerEvents.push({ type: "worker-thread", ts: Date.now(), ...event });
}

function openWorkerTrace(tid: number, pthread: string, start: NativePointer): WorkerTraceState {
    const path = `${STATE.traceDir}/worker_trace_call${STATE.callIdx}_tid${tid}.bin`;
    const worker: WorkerTraceState = {
        tid,
        pthread,
        start: start.toString(),
        ringBuf: Memory.alloc(WORKER_RING_BYTES),
        headBuf: Memory.alloc(8),
        tailBuf: Memory.alloc(8),
        droppedBuf: Memory.alloc(8),
        ringRecsBuf: Memory.alloc(8),
        maxRecordsBuf: Memory.alloc(8),
        ringRecs: WORKER_RING_RECS,
        file: new File(path, "wb"),
        filePath: path,
        cm: null,
        onInsnPtr: NULL,
    };
    worker.headBuf.writeU64(0);
    worker.tailBuf.writeU64(0);
    worker.droppedBuf.writeU64(0);
    worker.ringRecsBuf.writeU64(WORKER_RING_RECS);
    worker.maxRecordsBuf.writeU64(STATE.maxRecords);
    worker.cm = buildTraceRingCModule(worker);
    worker.onInsnPtr = (worker.cm as any).on_insn;
    STATE.workerTraces[String(tid)] = worker;
    log(`[pthread-follow] worker ring tid=${tid} path=${path} record=${REC_SIZE} ring=${WORKER_RING_RECS}`);
    return worker;
}

export function installPthreadFollowOnce(): void {
    if (!STATE.followWorkers || STATE.pthreadHooksInstalled) return;
    STATE.pthreadHooksInstalled = true;

    const pthreadCreate = findExport("pthread_create");
    if (!pthreadCreate) {
        log("[pthread-follow] pthread_create not found");
        return;
    }

    Interceptor.attach(pthreadCreate, {
        onEnter(args) {
            (this as any)._threadPtr = args[0];
            (this as any)._start = args[2];
        },
        onLeave(rv) {
            if (!STATE.fnEntered || !STATE.followWorkers || !STATE.traceDir) return;
            if (rv.toInt32() !== 0) return;
            const followedCount = Object.keys(STATE.followedWorkerTids).length;
            if (followedCount >= STATE.maxWorkerThreads) {
                rememberWorkerEvent({ status: "skipped_cap", start: String((this as any)._start) });
                return;
            }
            let pthreadValue = "0x0";
            try { pthreadValue = (this as any)._threadPtr.readPointer().toString(); } catch (_) {}
            const start = (this as any)._start as NativePointer;
            rememberWorkerEvent({ status: "created", pthread: pthreadValue, start: start.toString() });

            setTimeout(() => {
                try {
                    const tids = Process.enumerateThreads().map(t => t.id);
                    for (const tid of tids) {
                        const key = String(tid);
                        if (tid === STATE.primaryTid || STATE.followedWorkerTids[key]) continue;
                        STATE.followedWorkerTids[key] = true;
                        const worker = openWorkerTrace(tid, pthreadValue, start);
                        const ranges = STATE.includeRanges.map(r => ({ base: r.base, end: r.end }));
                        Stalker.follow(tid, {
                            events: { call: false, ret: false, exec: false, block: false, compile: false },
                            transform: createTransform(worker.onInsnPtr, ranges),
                        });
                        rememberWorkerEvent({
                            status: "followed",
                            tid,
                            pthread: pthreadValue,
                            start: start.toString(),
                            devicePath: worker.filePath,
                            recordSize: REC_SIZE,
                        });
                        log(`[pthread-follow] Stalker.follow tid=${tid} start=${start}`);
                        return;
                    }
                    rememberWorkerEvent({ status: "no_new_tid", pthread: pthreadValue, start: start.toString() });
                } catch (e) {
                    rememberWorkerEvent({ status: "failed", error: String(e), pthread: pthreadValue, start: start.toString() });
                    log(`[pthread-follow][!] ${e}`);
                }
            }, 1);
        }
    });
    log(`[pthread-follow] installed pthread_create hook max=${STATE.maxWorkerThreads}`);
}

export function flushWorkerEvents(callIdx: number): number {
    if (!STATE.workerEvents || STATE.workerEvents.length === 0) return 0;
    const events = STATE.workerEvents;
    STATE.workerEvents = [];
    send({ type: "worker-events", callIdx, tid: STATE.primaryTid, count: events.length, events });
    return events.length;
}
