/**
 * JSON-driven JNI vtable hooks (libart, Interceptor — not Stalker)
 *
 * 用户配置 JSON 描述要 hook 的 JNI vtable 函数 (offset + 参数类型 + 返回值类型).
 * Interceptor 不依赖 Stalker → 不创建 RWX 块缓存 → 反检测看不到.
 */

import { STATE } from "../core/state";
import { log, PTR_UNTAG_MASK } from "../core/utils";
import { pushSemanticEvent } from "../sidecar/semantic";

/** Direct JNIEnv* acquisition without Java module (Frida 17 removed it) */
function getJNIEnvDirect(): NativePointer | null {
    let getVMs: NativePointer | null = null;
    try { getVMs = Module.findExportByName(null, "JNI_GetCreatedJavaVMs"); } catch (_) {}
    if (!getVMs) {
        try { getVMs = Module.findExportByName("libart.so", "JNI_GetCreatedJavaVMs"); } catch (_) {}
    }
    if (!getVMs) return null;

    try {
        const fn = new NativeFunction(getVMs, "int", ["pointer", "int", "pointer"]);
        const vms = Memory.alloc(8);
        const nVMs = Memory.alloc(4);
        if ((fn(vms, 1, nVMs) as unknown as number) !== 0) return null;
        if (nVMs.readU32() < 1) return null;
        const jvm = vms.readPointer();
        if (jvm.isNull()) return null;
        const vtable = jvm.readPointer();
        const getEnvFn = new NativeFunction(vtable.add(0x30).readPointer(), "int", ["pointer", "pointer", "int"]);
        const envOut = Memory.alloc(8);
        if ((getEnvFn(jvm, envOut, 0x10006) as unknown as number) !== 0) return null;
        return envOut.readPointer();
    } catch (_) { return null; }
}

function _readArgVal(arg: NativePointer, spec: any): any {
    if (!spec || !spec.type) return arg.toString();
    const maxLen = spec.max_len || 256;
    switch (spec.type) {
        case "ptr":     return arg.toString();
        case "int":     return arg.toInt32();
        case "long":    return arg.toString();
        case "void":    return null;
        case "cstring": {
            try { return arg.readUtf8String(); } catch (_) {}
            try { return arg.readUtf8String(maxLen); } catch (_) {}
            try { return arg.and(PTR_UNTAG_MASK).readUtf8String(); } catch (_) {}
            try { return arg.and(PTR_UNTAG_MASK).readUtf8String(maxLen); } catch (_) {}
            return null;
        }
        case "utf16": {
            try { return arg.readUtf16String(); } catch (_) {}
            try { return arg.readUtf16String(maxLen); } catch (_) {}
            try { return arg.and(PTR_UNTAG_MASK).readUtf16String(); } catch (_) {}
            return null;
        }
        case "bytes": {
            const tryRead = (p: NativePointer) => {
                try {
                    const buf = p.readByteArray(maxLen);
                    if (!buf) return null;
                    const u8 = new Uint8Array(buf);
                    let hex = "";
                    for (let i = 0; i < u8.length; i++) hex += u8[i].toString(16).padStart(2, "0");
                    return hex;
                } catch (_) { return null; }
            };
            return tryRead(arg) || tryRead(arg.and(PTR_UNTAG_MASK));
        }
        default: return arg.toString();
    }
}

function _makeJsonHookHandler(spec: any) {
    return {
        onEnter(this: InvocationContext, args: InvocationArguments) {
            if (this.threadId !== STATE.primaryTid) { (this as any)._skip = true; return; }
            (this as any)._spec = spec;
            (this as any)._argVals = new Array(spec.args.length);
            (this as any)._pendingArgs = [];
            for (let i = 0; i < spec.args.length; i++) {
                const aSpec = spec.args[i];
                if (aSpec.read_in_onleave) {
                    (this as any)._pendingArgs.push({ idx: i, ptr: args[i] });
                    (this as any)._argVals[i] = null;
                } else {
                    (this as any)._argVals[i] = _readArgVal(args[i], aSpec);
                }
            }
        },
        onLeave(this: InvocationContext, retv: InvocationReturnValue) {
            if ((this as any)._skip) return;
            for (const p of (this as any)._pendingArgs) {
                (this as any)._argVals[p.idx] = _readArgVal(p.ptr, (this as any)._spec.args[p.idx]);
            }
            const ret = ((this as any)._spec.ret && (this as any)._spec.ret.type === "void")
                ? null
                : _readArgVal(retv as unknown as NativePointer, (this as any)._spec.ret || { type: "ptr" });
            const head = STATE.headBuf!.readU64().toNumber();
            const argsObj: Record<string, any> = {};
            for (let i = 0; i < (this as any)._spec.args.length; i++) {
                argsObj[(this as any)._spec.args[i].name] = (this as any)._argVals[i];
            }
            const event = {
                id: (this as any)._spec.id,
                trace_idx: head,
                args: argsObj,
                ret,
            };
            STATE.jniHookEvents.push(event);
            pushSemanticEvent({
                kind: "jni",
                source: "jni_vtable",
                name: (this as any)._spec.id,
                trace_idx: head,
                args: argsObj,
                ret,
                tid: this.threadId,
            });
        }
    };
}

/** Install JNI vtable hooks from specs. Called once per trace session. */
export function installJniHooksOnce(): void {
    if (STATE.jniHooksInstalled) return;
    const specs = STATE.jniHookSpecs;
    if (!Array.isArray(specs) || specs.length === 0) {
        STATE.jniHooksInstalled = true;
        return;
    }
    const envPtr = getJNIEnvDirect();
    if (!envPtr) {
        log("[hooks] no JNIEnv (JavaVM not initialized?), will retry next call");
        return;
    }
    const vtable = envPtr.readPointer();
    STATE.jniHookEvents = STATE.jniHookEvents || [];
    let installed = 0, skipped = 0;
    for (const spec of specs) {
        try {
            const off = parseInt(spec.vtable_offset);
            if (isNaN(off)) { skipped++; continue; }
            const fnPtr = vtable.add(off).readPointer();
            if (fnPtr.isNull()) { skipped++; continue; }
            Interceptor.attach(fnPtr, _makeJsonHookHandler(spec));
            installed++;
        } catch (e) {
            log(`[hooks][!] ${spec.id}: ${e}`);
            skipped++;
        }
    }
    STATE.jniHooksInstalled = true;
    log(`[hooks] JSON-driven JNI hooks: ${installed}/${specs.length} installed (${skipped} skipped)`);
}

/** Flush buffered JNI hook events to host */
export function flushJniHookEvents(callIdx: number): number {
    if (!STATE.jniHookEvents || STATE.jniHookEvents.length === 0) return 0;
    const events = STATE.jniHookEvents;
    STATE.jniHookEvents = [];
    send({ type: "jni-hooks", callIdx, count: events.length, events });
    return events.length;
}
