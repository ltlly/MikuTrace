import { internalFds, internalIoActive } from "../core/native_io";
import { persistEvents } from "../transport/manifest";
/**
 * Semantic events sidecar — libc/syscall Interceptor hooks
 *
 * 在 Stalker trace 同时捕获 libc 调用 (open/read/write/mmap/...) 和
 * inline SVC 指令 (通过 CModule callback), 记录为 semantic events 落盘.
 */

import { STATE } from "../core/state";
import { log, getExport, ptrToStringMaybe, syscallName, currentTraceIdx, u64Dec, u64Num } from "../core/utils";

type SemanticSpec = {
    name: string;
    kind: string;
    argc: number;
    strings?: Record<number, string>;
    outStrings?: Record<number, string>;
    fds?: number[];
    stream?: boolean;
    returnsFd?: boolean;
    returnsStream?: boolean;
};

function capturePayload(out: Record<string, any>, buffer: NativePointer, count: NativePointer): void {
    const size = count.compare(ptr(128)) > 0 ? 128 : count.toUInt32();
    out.data_truncated = count.compare(ptr(128)) > 0;
    try {
        const data = size > 0 ? buffer.readByteArray(size) : new ArrayBuffer(0);
        if (data === null) throw new Error("unreadable buffer");
        out.data_hex = Array.from(new Uint8Array(data), byte => byte.toString(16).padStart(2, "0")).join("");
    } catch (error) {
        out.data_hex = null;
        out.data_truncated = true;
        out.data_error = String(error);
    }
}

/** Push a semantic event to buffer. Auto-flushes at 128 events. */
export function pushSemanticEvent(ev: Record<string, any>): void {
    if (!STATE.semanticEvents || (!STATE.fnEntered && !STATE.preEntryActive)) return;
    if (!STATE.semanticEventBuf) STATE.semanticEventBuf = [];

    const out = ev || {};
    out.event_id = STATE.semanticEventSeq++;
    if (out.trace_idx === undefined || out.trace_idx === null) {
        out.trace_idx = currentTraceIdx(STATE.headBuf);
    }
    if (!out.tid) out.tid = STATE.primaryTid;
    out.ts_ms = Date.now();
    STATE.semanticEventBuf.push(out);

    if (STATE.semanticEventBuf.length >= 128) {
        flushSemanticEvents(STATE.callIdx);
    }
}

/** Flush buffered semantic events to host */
export function flushSemanticEvents(callIdx: number): number {
    if (!STATE.semanticEvents || !STATE.semanticEventBuf || STATE.semanticEventBuf.length === 0) return 0;
    const events = STATE.semanticEventBuf;
    persistEvents("semantic_events.jsonl", events);
    STATE.semanticEventBuf = [];

    return events.length;
}

/** Install libc/syscall semantic hooks (once) */
export function installSemanticHooksOnce(): void {
    if (!STATE.semanticEvents || STATE.semanticHooksInstalled) return;

    const specs: SemanticSpec[] = [
        { name: "syscall", kind: "syscall_wrapper", argc: 7 },
        { name: "open", kind: "libc", argc: 3, strings: { 0: "path" }, returnsFd: true },
        { name: "openat", kind: "libc", argc: 4, strings: { 1: "path" }, fds: [0], returnsFd: true },
        { name: "close", kind: "libc", argc: 1, fds: [0] },
        { name: "fclose", kind: "libc", argc: 1, stream: true },
        { name: "dup", kind: "libc", argc: 1, fds: [0], returnsFd: true },
        { name: "dup2", kind: "libc", argc: 2, fds: [0, 1], returnsFd: true },
        { name: "dup3", kind: "libc", argc: 3, fds: [0, 1], returnsFd: true },
        { name: "fopen", kind: "libc", argc: 2, strings: { 0: "path", 1: "mode" }, returnsStream: true },
        { name: "fdopen", kind: "libc", argc: 2, strings: { 1: "mode" }, fds: [0], returnsStream: true },
        { name: "read", kind: "libc", argc: 3, fds: [0] },
        { name: "write", kind: "libc", argc: 3, fds: [0] },
        { name: "pread64", kind: "libc", argc: 4, fds: [0] },
        { name: "pwrite64", kind: "libc", argc: 4, fds: [0] },
        { name: "lseek", kind: "libc", argc: 3, fds: [0] },
        { name: "lseek64", kind: "libc", argc: 3, fds: [0] },
        { name: "fstat", kind: "libc", argc: 2, fds: [0] },
        { name: "newfstatat", kind: "libc", argc: 4, strings: { 1: "path" }, fds: [0] },
        { name: "fstatat", kind: "libc", argc: 4, strings: { 1: "path" }, fds: [0] },
        { name: "access", kind: "libc", argc: 2, strings: { 0: "path" } },
        { name: "faccessat", kind: "libc", argc: 4, strings: { 1: "path" }, fds: [0] },
        { name: "unlink", kind: "libc", argc: 1, strings: { 0: "path" } },
        { name: "unlinkat", kind: "libc", argc: 3, strings: { 1: "path" }, fds: [0] },
        { name: "rename", kind: "libc", argc: 2, strings: { 0: "old_path", 1: "new_path" } },
        { name: "renameat", kind: "libc", argc: 4, strings: { 1: "old_path", 3: "new_path" }, fds: [0, 2] },
        { name: "mmap", kind: "libc", argc: 6, fds: [4] },
        { name: "mmap64", kind: "libc", argc: 6, fds: [4] },
        { name: "mprotect", kind: "libc", argc: 3 },
        { name: "munmap", kind: "libc", argc: 2 },
        { name: "ioctl", kind: "libc", argc: 3, fds: [0] },
        { name: "__system_property_get", kind: "libc", argc: 2, strings: { 0: "name" }, outStrings: { 1: "value" } },
    ];
    const readlinkAddress = getExport("readlink");
    const readlink = readlinkAddress ? new NativeFunction(readlinkAddress, "long", ["pointer", "pointer", "ulong"]) : null;
    const filenoAddress = getExport("fileno");
    const fileno = filenoAddress ? new NativeFunction(filenoAddress, "int", ["pointer"]) : null;
    function describeFd(out: Record<string, any>, fd: number, prefix = ""): void {
        out[prefix + "fd"] = fd;
        if (fd < 0 || !readlink) return;
        try {
            const buffer = Memory.alloc(160);
            const length = Number(readlink(Memory.allocUtf8String(`/proc/self/fd/${fd}`), buffer, 160));
            if (length < 0) return;
            out[prefix + "fd_path"] = buffer.readUtf8String(length);
            out[prefix + "fd_path_truncated"] = length === 160;
        } catch (_) {}
    }

    let installed = 0;
    let skipped = 0;

    for (const spec of specs) {
        let fp: NativePointer | null = null;
        try { fp = getExport(spec.name); } catch (_) {}
        if (!fp || fp.isNull()) { skipped++; continue; }

        try {
            Interceptor.attach(fp, {
                onEnter(args) {
                    if ((!STATE.fnEntered && !STATE.preEntryActive) || this.threadId !== STATE.primaryTid || internalIoActive(this.threadId)) {
                        (this as any)._skip = true;
                        return;
                    }
                    const descriptorArgs = (spec.fds || []).map(index => args[index].toInt32());
                    if (spec.stream && fileno) descriptorArgs.push(fileno(args[0]));
                    if (spec.name === "syscall") {
                        const syscallSpec = specs.find(candidate => candidate.name === syscallName(args[0].toUInt32()));
                        for (const index of syscallSpec?.fds || []) descriptorArgs.push(args[index + 1].toInt32());
                    }
                    if (descriptorArgs.some(fd => internalFds.has(fd))) {
                        (this as any)._skip = true;
                        return;
                    }
                    (this as any)._spec = spec;
                    (this as any)._traceIdx = currentTraceIdx(STATE.headBuf);
                    (this as any)._args = {} as Record<string, any>;
                    (this as any)._outStringPtrs = [];
                    descriptorArgs.forEach((fd, index) => describeFd((this as any)._args, fd, index === 0 ? "" : `arg${index}_`));
                    if (["read", "pread64"].includes(spec.name)) (this as any)._readBuffer = args[1];
                    if (["write", "pwrite64"].includes(spec.name)) capturePayload((this as any)._args, args[1], args[2]);

                    for (let i = 0; i < spec.argc; i++) {
                        const key = `x${i}`;
                        (this as any)._args[key] = args[i].toString();
                        if (spec.strings && (spec.strings as any)[i]) {
                            const s = ptrToStringMaybe(args[i], 160);
                            if (s !== null) (this as any)._args[(spec.strings as any)[i]] = s;
                        }
                        if (spec.outStrings && (spec.outStrings as any)[i]) {
                            (this as any)._outStringPtrs.push({ name: (spec.outStrings as any)[i], ptr: args[i] });
                        }
                    }
                    if (spec.name === "syscall") {
                        const nr = args[0].toUInt32();
                        (this as any)._args.syscall_nr = nr;
                        (this as any)._args.syscall = syscallName(nr);
                    }
                },
                onLeave(retv) {
                    if ((this as any)._skip) return;
                    if ((this as any)._readBuffer && !retv.isNull() && retv.compare(ptr("0x7fffffffffffffff")) <= 0) {
                        capturePayload((this as any)._args, (this as any)._readBuffer, retv);
                    }
                    let returnedFd = -1;
                    if (spec.returnsFd) returnedFd = retv.toInt32();
                    if (spec.returnsStream && fileno && !retv.isNull()) returnedFd = fileno(retv);
                    if (internalFds.has(returnedFd)) return;
                    if (returnedFd >= 0) describeFd((this as any)._args, returnedFd, "result_");
                    for (const out of (this as any)._outStringPtrs || []) {
                        const s = ptrToStringMaybe(out.ptr, 160);
                        if (s !== null) (this as any)._args[out.name] = s;
                    }
                    const kind = (this as any)._spec.name === "syscall" ? "syscall" : "libc";
                    pushSemanticEvent({
                        kind,
                        source: (this as any)._spec.kind,
                        name: (this as any)._args.syscall || (this as any)._spec.name,
                        trace_idx: (this as any)._traceIdx,
                        args: (this as any)._args,
                        ret: retv.toString(),
                        tid: this.threadId,
                    });
                }
            });
            installed++;
        } catch (e) {
            log(`[semantic][!] ${spec.name}: ${e}`);
            skipped++;
        }
    }

    STATE.semanticHooksInstalled = true;
    log(`[semantic] libc/syscall hooks: ${installed}/${specs.length} installed (${skipped} skipped)`);
}

/**
 * Create the CModule SVC event callback (inline SVC detection from CModule).
 * Returns a NativeCallback to pass as symbol to CModule.
 */
export function createSvcEventCallback(): NativePointer {
    return new NativeCallback(
        function (idx: UInt64, pc: UInt64, nr: UInt64, x0: UInt64, x1: UInt64, x2: UInt64, x3: UInt64, x4: UInt64, x5: UInt64) {
            const nrNum = u64Num(nr);
            pushSemanticEvent({
                kind: "syscall",
                source: "inline_svc",
                name: syscallName(nrNum),
                trace_idx: u64Num(idx),
                pc: u64Dec(pc),
                syscall_nr: nrNum,
                args: {
                    x0: u64Dec(x0), x1: u64Dec(x1), x2: u64Dec(x2),
                    x3: u64Dec(x3), x4: u64Dec(x4), x5: u64Dec(x5),
                },
                ret: null,
                note: "inline svc event is captured before execution; return value is visible in the next trace record",
                tid: STATE.primaryTid,
            });
        },
        "void",
        ["uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64", "uint64"]
    );
}
