/**
 * Semantic events sidecar — libc/syscall Interceptor hooks
 *
 * 在 Stalker trace 同时捕获 libc 调用 (open/read/write/mmap/...) 和
 * inline SVC 指令 (通过 CModule callback), 记录为 semantic events 落盘.
 */

import { STATE } from "../core/state";
import { log, getExport, ptrToStringMaybe, syscallName, currentTraceIdx, u64Dec, u64Num } from "../core/utils";

/** Push a semantic event to buffer. Auto-flushes at 128 events. */
export function pushSemanticEvent(ev: Record<string, any>): void {
    if (!STATE.semanticEvents || !STATE.fnEntered) return;
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
    STATE.semanticEventBuf = [];
    send({ type: "semantic-events", callIdx, count: events.length, events });
    return events.length;
}

/** Install libc/syscall semantic hooks (once) */
export function installSemanticHooksOnce(): void {
    if (!STATE.semanticEvents || STATE.semanticHooksInstalled) return;

    const specs = [
        { name: "syscall", kind: "syscall_wrapper", argc: 7, strings: null as any, outStrings: null as any },
        { name: "open", kind: "libc", argc: 3, strings: { 0: "path" } as any, outStrings: null as any },
        { name: "openat", kind: "libc", argc: 4, strings: { 1: "path" } as any, outStrings: null as any },
        { name: "read", kind: "libc", argc: 3, strings: null as any, outStrings: null as any },
        { name: "write", kind: "libc", argc: 3, strings: null as any, outStrings: null as any },
        { name: "pread64", kind: "libc", argc: 4, strings: null as any, outStrings: null as any },
        { name: "pwrite64", kind: "libc", argc: 4, strings: null as any, outStrings: null as any },
        { name: "mmap", kind: "libc", argc: 6, strings: null as any, outStrings: null as any },
        { name: "mmap64", kind: "libc", argc: 6, strings: null as any, outStrings: null as any },
        { name: "mprotect", kind: "libc", argc: 3, strings: null as any, outStrings: null as any },
        { name: "munmap", kind: "libc", argc: 2, strings: null as any, outStrings: null as any },
        { name: "ioctl", kind: "libc", argc: 3, strings: null as any, outStrings: null as any },
        { name: "__system_property_get", kind: "libc", argc: 2, strings: { 0: "name" } as any, outStrings: { 1: "value" } as any },
    ];

    let installed = 0;
    let skipped = 0;

    for (const spec of specs) {
        let fp: NativePointer | null = null;
        try { fp = getExport(spec.name); } catch (_) {}
        if (!fp || fp.isNull()) { skipped++; continue; }

        try {
            Interceptor.attach(fp, {
                onEnter(args) {
                    if (!STATE.fnEntered || this.threadId !== STATE.primaryTid) {
                        (this as any)._skip = true;
                        return;
                    }
                    (this as any)._spec = spec;
                    (this as any)._traceIdx = currentTraceIdx(STATE.headBuf);
                    (this as any)._args = {} as Record<string, any>;
                    (this as any)._outStringPtrs = [];

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
