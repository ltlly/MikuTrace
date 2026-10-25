import { encodeExtWriteEvent, EXT_WRITE_RECORD_SIZE } from "../core/external_writes";
/** 设备是采集结果的事实源；IPC 仅提供进度，不承载唯一副本。 */
import { STATE, REC_SIZE, SIMD_REC_SIZE } from "../core/state";
import { getExport } from "../core/utils";
import { NativeFile, syncDirectory } from "../core/native_io";
import { entryAddress } from "../core/entry";
import { drainTargetPluginEvents } from "../target_plugins";

type Artifact = { name: string; device_path: string; bytes?: number; record_size?: number; records?: number };
let files: Artifact[] = [];
let streams: Record<string, NativeFile> = {};
let counts: Record<string, number> = {};
let snapshot: any = null;
let manifest: any = null;
let sessionId = "";
let calls: string[] = [];

function atomicJson(path: string, value: any): void {
    const temp = `${path}.${Date.now()}.tmp`;
    const file = new NativeFile(temp);
    file.write(JSON.stringify(value));
    file.close();
    const rename = new SystemFunction(getExport("rename")!, "int", ["pointer", "pointer"]);
    const result = rename(Memory.allocUtf8String(temp), Memory.allocUtf8String(path));
    if (result.value !== 0) throw new Error(`manifest rename errno=${(result as any).errno}`);
    syncDirectory(STATE.traceDir!);
}

export function prepareManifest(id: string): void {
    if (!/^[a-f0-9]{32}$/.test(id)) throw new Error("invalid session id");
    sessionId = id;
    const file = new NativeFile(`${STATE.traceDir}/session.json`);
    file.write(JSON.stringify({
        schema_version: 1, session_id: sessionId, pid: Process.id,
        device_dir: STATE.traceDir, state: "READY", calls,
    }));
    file.close();
    syncDirectory(STATE.traceDir!);
}

export function beginManifest(): void {
    files = [{ name: "trace.bin", device_path: STATE.traceFilePath!, record_size: REC_SIZE }];
    streams = {}; counts = {}; snapshot = null;
    if (STATE.simdSidecar) files.push({
        name: "simd_trace.bin", device_path: STATE.simdTraceFilePath!, record_size: SIMD_REC_SIZE,
    });
    const path = `${STATE.traceDir}/call_${STATE.callIdx}.json`;
    manifest = {
        schema_version: 1, session_id: sessionId, state: "CAPTURING", files,
        meta: {
            callIdx: STATE.callIdx, pid: Process.id, tid: STATE.primaryTid,
            format_version: 1, record_size: REC_SIZE, started_at: STATE.started / 1000,
            devicePath: STATE.traceFilePath, truncated: true, records: null, bytes: null,
            method: STATE.methodName || STATE.exportName,
            fn_addr: STATE.target && STATE.fnOffset != null ? STATE.target.base.add(STATE.fnOffset).toString() : null,
            module: STATE.target ? { name: STATE.target.name, base: STATE.target.base.toString(),
                size: STATE.target.end.sub(STATE.target.base).toUInt32() } : null,
            modules: Process.enumerateModules().map(m => ({
                name: m.name, base: m.base.toString(), size: m.size, path: m.path,
            })),
        },
    };
    atomicJson(path, manifest);
    calls.push(path);
    atomicJson(`${STATE.traceDir}/session.json`, {
        schema_version: 1, session_id: sessionId, pid: Process.id,
        device_dir: STATE.traceDir, state: "CAPTURING", calls,
    });
    persistEvents("target_plugin_events.jsonl", drainTargetPluginEvents());
}

/** 批大小由调用者控制；不保留已写入事件，不设置事件总数上限。 */
export function persistEvents(name: string, events: any[]): void {
    if (!manifest || events.length === 0) return;
    let file = streams[name];
    if (!file) {
        const path = `${STATE.traceDir}/call${STATE.callIdx}_${name}`;
        file = streams[name] = new NativeFile(path);
        files.push({ name, device_path: path });
    }
    if (name === "external_writes.bin") {
        const data = new Uint8Array(events.length * EXT_WRITE_RECORD_SIZE);
        events.forEach((event, i) => data.set(encodeExtWriteEvent(event), i * EXT_WRITE_RECORD_SIZE));
        file.write(data.buffer);
    } else {
        file.write(events.map(event => JSON.stringify(event) + "\n").join(""));
    }
    counts[name] = (counts[name] || 0) + events.length;
}

export function registerSnapshot(info: any): void {
    snapshot = info;
    files.push({ name: "memory_snapshot.bin", device_path: info.devicePath, bytes: info.bytes });
}

export function sealManifest(end: any, sessionComplete: boolean): string {
    const expected = entryAddress()?.toString() || null;
    const isInitWindow = end.entryBoundary === "module-init-and-entry";
    const entryComplete = isInitWindow
        ? (expected !== null && end.entryObserved === true && end.firstPc !== null)
        : (expected !== null && end.firstPc === expected);
    if (!entryComplete) persistEvents("coverage_gaps.jsonl", [{
        reason: "entry-not-observed", evidence: "runtime", expected_pc: expected,
        first_pc: end.firstPc ?? null,
    }]);
    persistEvents("target_plugin_events.jsonl", drainTargetPluginEvents());
    for (const [name, stream] of Object.entries(streams)) {
        stream.close();
        const artifact = files.find(file => file.name === name)!;
        artifact.bytes = stream.bytes;
        artifact.records = counts[name];
        if (name === "external_writes.bin") artifact.record_size = 17;
    }
    files[0].bytes = end.total * REC_SIZE;
    files[0].records = end.total;
    if (STATE.simdSidecar) Object.assign(files[1], {
        bytes: end.simdRecords * SIMD_REC_SIZE, records: end.simdRecords,
    });
    for (const worker of end.workerTraces || []) files.push({
        name: `worker_trace_tid${worker.tid}.bin`, device_path: worker.devicePath,
        bytes: worker.records * REC_SIZE, records: worker.records, record_size: REC_SIZE,
    });
    const fnAddr = expected || (STATE.target && STATE.fnOffset != null
        ? STATE.target.base.add(STATE.fnOffset).toString() : manifest.meta.fn_addr);
    const modInfo = STATE.target ? {
        name: STATE.target.name,
        base: STATE.target.base.toString(),
        size: STATE.target.end.sub(STATE.target.base).toUInt32(),
    } : manifest.meta.module;
    Object.assign(manifest.meta, end, {
        fn_addr: fnAddr,
        module: modInfo,
        modules: Process.enumerateModules().map(m => ({
            name: m.name, base: m.base.toString(), size: m.size, path: m.path,
        })),
        records: end.total, device_records: end.total, bytes: end.total * REC_SIZE,
        closed_at: Date.now() / 1000, event_counts: counts,
        truncated: end.truncated || (counts["snapshot_errors.jsonl"] || 0) > 0 ||
            (counts["coverage_gaps.jsonl"] || 0) > 0,
        capture_scope: {
            primary_tid: STATE.primaryTid, include_ranges: STATE.includeRanges.map(range => ({
                name: range.name, base: range.base.toString(), end: range.end.toString(),
            })),
            entry_boundary: isInitWindow ? "module-init-and-entry" : "relocated-instruction",
            exit_boundary: "interceptor-onleave",
            expected_entry_pc: expected, first_pc: end.firstPc ?? null, entry_complete: entryComplete,
            return_observed: end.returnObserved === true,
            simd_sample_stride: STATE.simdSidecar ? STATE.simdSampleStride : null,
            coverage_gaps: counts["coverage_gaps.jsonl"] || 0,
        },
        semantic_events_count: counts["semantic_events.jsonl"] || 0,
        ext_writes: counts["external_writes.bin"] || 0,
    });
    if (snapshot) manifest.meta.memory_snapshot = {
        file: "memory_snapshot.bin", regions: snapshot.regions, bytes: snapshot.bytes,
    };
    if (STATE.simdSidecar) manifest.meta.simd_sidecar = {
        file: "simd_trace.bin", record_size: SIMD_REC_SIZE, records: end.simdRecords,
        bytes: end.simdRecords * SIMD_REC_SIZE, dropped: end.simdDropped,
        sample_stride: STATE.simdSampleStride,
    };
    manifest.state = "SEALED";
    const path = `${STATE.traceDir}/call_${STATE.callIdx}.json`;
    atomicJson(path, manifest);
    publishSession(sessionComplete ? "SEALED" : "WAITING");
    return path;
}

function publishSession(state: string): void {
    atomicJson(`${STATE.traceDir}/session.json`, {
        schema_version: 1, session_id: sessionId, pid: Process.id,
        device_dir: STATE.traceDir, state, calls,
    });
}

export function sealSession(error?: string): void {
    if (error) atomicJson(`${STATE.traceDir}/session.json`, {
        schema_version: 1, session_id: sessionId, pid: Process.id,
        device_dir: STATE.traceDir, state: "FAILED", calls, error,
    });
    else publishSession(calls.length ? "SEALED" : "STOPPED");
}
