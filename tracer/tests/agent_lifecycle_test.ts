/** 实际 onLeave 的封口顺序、无记录上限、停止等待语义及 JNI 事件持久化。 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import ts from "typescript";

const noop = () => {};
const source = readFileSync(new URL("../src/agent.ts", import.meta.url), "utf8") +
    "\nexport { installFnHook, armWithModule, beginCaptureSession };\n" +
    "export function acceptCallsForTest() { acceptingCalls = true; }\n";
const compiled = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;

for (const [total, fault] of [[0, ""], [2000, ""], [5_000_001, ""], [50_000_001, ""],
    [3, "close"], [3, "jni"], [3, "seal"]] as const) {
    const order: string[] = [];
    const events: any[] = [];
    let failure: string | undefined;
    const step = (name: string) => {
        order.push(name);
        if (fault === name) throw new Error(`fixture ${name} failure`);
    };
    const state: any = {
        callIdx: 1, callFinalized: false, fnEntered: true, started: Date.now(),
        headBuf: { readU64: () => ({ toNumber: () => total }) },
        tailBuf: { readU64: () => ({ toNumber: () => total }) },
        droppedBuf: { readU64: () => ({ toNumber: () => 0 }) },
        simdSidecar: false, traceFilePath: "/spool/trace.bin",
        cm: { firstCapturedPc: { readPointer: () => ({ toString: () => "0x1000" }) } },
    };
    let callbacks: any;
    const modules: Record<string, any> = {
        "./core/state": { STATE: state, SIMD_REC_SIZE: 520 },
        "./core/entry": { attachEntryHook: (_fp: any, handlers: any) => { callbacks = handlers; }, releaseEntryHook: noop },
        "./core/utils": { log: noop }, "./core/cmodule": {}, "./core/native_io": { ioHealth: () => [] },
        "./core/ring": {
            unfollowWorkerThreads: noop, flushRingToDisk: () => order.push("flush"),
            flushWorkerTraceRings: noop, closeTraceFile: () => step("close"),
            closeWorkerTraceFiles: noop, closeSimdTraceFile: noop, workerTraceSummaries: () => [],
        },
        "./core/stalker": {}, "./sidecar/simd": { flushSimdRingToDisk: noop },
        "./sidecar/mem_snapshot": {}, "./sidecar/semantic": { flushSemanticEvents: noop },
        "./hooks/jni_vtable": { flushJniHookEvents: () => step("jni") },
        "./hooks/fork_monitor": { flushForkEvents: noop },
        "./hooks/pthread_follow": { flushWorkerEvents: noop },
        "./hooks/boundary_diff": { flushExtWriteEvents: noop },
        "./anti_detect/plugin_interface": {}, "./target_plugins": { runTargetPlugins: () => true },
        "./transport/control": { controlAddress: noop },
        "./transport/manifest": {
            sealManifest: () => { step("seal"); return "/spool/call_1.json"; },
            sealSession: (error: string) => { failure = error; },
        },
    };
    const exports: any = {};
    const rpc: any = {};
    runInNewContext(compiled, {
        exports, rpc, send: (event: any) => { order.push("notify"); events.push(event); },
        Stalker: { unfollow: noop, flush: noop }, clearInterval: noop, setImmediate: noop,
        Process: { id: 1, enumerateModules: () => [] },
        Interceptor: { attach: (_fp: any, handlers: any) => { callbacks = handlers; } },
        require: (name: string) => { assert.ok(name in modules, name); return modules[name]; },
    });
    exports.installFnHook({}, {});
    // host 离开等待只关闭新的调用窗口，不能截断正在执行的函数。
    assert.equal(rpc.exports.stopCapture(), "capturing");
    assert.equal(state.callFinalized, false);
    assert.equal(events.length, 0);
    const context = { _tid: 42, _callIdx: 1 };
    callbacks.onLeave.call(context, { toString: () => "0x42" });
    if (fault) {
        assert.match(failure!, new RegExp(`fixture ${fault} failure`));
        assert.equal(rpc.exports.stats().error, failure);
        assert.equal(rpc.exports.stats().completedCalls, 0);
        assert.equal(events.length, 0, "封口失败不能通知 trace-end");
        assert.equal(state.fnEntered, false);
        callbacks.onLeave.call(context, { toString: () => "0x42" });
        assert.equal(events.length, 0);
        continue;
    }
    assert.equal(events.length, 1);
    assert.equal(events[0].total, total);
    assert.equal(events[0].truncated, false);
    assert.equal(events[0].returnObserved, true);
    assert.deepEqual(order, ["flush", "close", "jni", "seal", "notify"]);
    assert.equal(rpc.exports.stats().completedCalls, 1);
    assert.equal(state.fnEntered, false);
    callbacks.onLeave.call(context, { toString: () => "0x42" });
    assert.equal(events.length, 1, "一次返回只封口一次");
    if (total === 2000) {
        state.exportName = "missing";
        state.fnOffset = null;
        const address = { add() { return this; }, toString() { return "0x1000"; } };
        assert.throws(() => exports.armWithModule({ name: "fixture.so", base: address, size: 4096,
            enumerateExports: () => [], enumerateSymbols: () => [] }, {}), /export "missing" not found/,
        "没有时间上限时，解析失败必须立即报错，不能无限等待未安装的 hook");
        let failure: string | undefined;
        modules["./transport/manifest"].sealSession = (error: string) => { failure = error; };
        modules["./target_plugins"].runTargetPlugins = (phase: string) => {
            assert.equal(phase, "beforeTrace");
            return false;
        };
        state.callIdx = 0;
        exports.acceptCallsForTest();
        const skippedEntry: any = { threadId: 42 };
        callbacks.onEnter.call(skippedEntry, []);
        assert.equal(skippedEntry._skip, true, "beforeTrace 返回 false 应跳过当前调用");
        assert.equal(failure, undefined, "跳过调用不应终止采集会话");
        assert.equal(state.fnEntered, false);

        modules["./target_plugins"].runTargetPlugins = (phase: string) => {
            assert.equal(phase, "beforeTrace");
            throw new Error("fixture refusal");
        };
        const entry: any = { threadId: 42 };
        callbacks.onEnter.call(entry, []);
        assert.equal(entry._skip, true);
        assert.match(failure!, /fixture refusal/);
        assert.equal(rpc.exports.stats().error, failure,
            "插件拒绝采集必须持久化失败并告知 host，不能无限等待目标返回");
        assert.equal(state.fnEntered, false);
    }
}
// Frida 17 无静态 Module.findExportByName；实际 JNI 模块必须使用共享解析器。
const jniExports: any = {};
const jniHandlers: any[] = [];
const getVMs = {};
const getEnv = {};
const env: any = { readPointer: () => ({ add: () => ({ readPointer: () => ({ isNull: () => false }) }) }) };
const vm: any = {
    isNull: () => false,
    readPointer: () => ({ add: (offset: number) => {
        assert.equal(offset, 0x30);
        return { readPointer: () => getEnv };
    } }),
};
const jniState: any = {
    jniHooksInstalled: false, jniHookSpecs: [{ id: "NewStringUTF", vtable_offset: "0x538", args: [], ret: { type: "void" } }],
    jniHookEvents: [], primaryTid: 42, fnEntered: true,
    headBuf: { readU64: () => ({ toNumber: () => 7 }) },
};
const jniSource = readFileSync(new URL("../src/hooks/jni_vtable.ts", import.meta.url), "utf8");
runInNewContext(ts.transpileModule(jniSource, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText, {
    exports: jniExports,
    // 故意不提供 Module，也不提供 Java bridge。
    NativeFunction: function (address: any) {
        if (address === getVMs) return (vms: any, _count: number, count: any) => {
            vms.readPointer = () => vm; count.readU32 = () => 1; return 0;
        };
        assert.equal(address, getEnv);
        return (_vm: any, out: any) => { out.readPointer = () => env; return 0; };
    },
    Memory: { alloc: () => ({}) },
    Interceptor: { attach: (_address: any, handlers: any) => jniHandlers.push(handlers) },
    require: (name: string) => {
        if (name === "../transport/manifest") return { persistEvents: noop };
        if (name === "../core/state") return { STATE: jniState };
        if (name === "../core/utils") return { log: noop, getExport: (symbol: string) => {
            assert.equal(symbol, "JNI_GetCreatedJavaVMs"); return getVMs;
        } };
        assert.equal(name, "../sidecar/semantic");
        return { pushSemanticEvent: noop };
    },
});
jniExports.installJniHooksOnce();
assert.equal(jniHandlers.length, 1);
assert.equal(jniState.jniHooksInstalled, true);
for (const active of [true, false]) {
    jniState.fnEntered = active;
    const context = { threadId: 42 };
    jniHandlers[0].onEnter.call(context, []);
    jniHandlers[0].onLeave.call(context, {});
}
assert.equal(jniState.jniHookEvents.length, 1, "调用结束后的 JNI 事件不能混入已封口的 trace");
assert.equal(jniState.jniHookEvents[0].trace_idx, 7);

// Pre-entry initialization window (--trace-init) and resident worker follow contracts.
{
    const preEvents: any[] = [];
    const preState: any = {
        callIdx: 0, callFinalized: false, fnEntered: false, preEntryActive: false, traceInit: true,
        started: 0, primaryTid: 0, simdSidecar: false, traceFilePath: "/spool/trace.bin",
        headBuf: { writeU64: noop, readU64: () => ({ toNumber: () => 12 }) },
        tailBuf: { writeU64: noop, readU64: () => ({ toNumber: () => 12 }) },
        droppedBuf: { writeU64: noop, readU64: () => ({ toNumber: () => 0 }) },
        includeRanges: [], workerTraces: {}, followedWorkerTids: {}, workerEvents: [],
        cm: { firstCapturedPc: { readPointer: () => ({ toString: () => "0x800" }) } },
    };
    let hookCallbacks: any;
    let sealedMeta: any;
    const preModules: Record<string, any> = {
        "./core/state": { STATE: preState, SIMD_REC_SIZE: 520 },
        "./core/entry": { attachEntryHook: (_fp: any, handlers: any) => { hookCallbacks = handlers; }, releaseEntryHook: noop },
        "./core/utils": { log: noop }, "./core/cmodule": {}, "./core/native_io": { ioHealth: () => [] },
        "./core/ring": {
            openTraceFile: noop, ensureFlushTimer: noop, releaseWorkerTraces: noop,
            unfollowWorkerThreads: noop, flushRingToDisk: noop, flushWorkerTraceRings: noop,
            closeTraceFile: noop, closeWorkerTraceFiles: noop, closeSimdTraceFile: noop,
            workerTraceSummaries: () => [],
        },
        "./core/stalker": { applyExcludesOnce: noop, buildIncludeRanges: noop, createTransform: () => noop },
        "./sidecar/simd": { flushSimdRingToDisk: noop },
        "./sidecar/mem_snapshot": { captureMemorySnapshot: noop },
        "./sidecar/semantic": { installSemanticHooksOnce: noop, flushSemanticEvents: noop },
        "./hooks/jni_vtable": { installJniHooksOnce: noop, flushJniHookEvents: noop },
        "./hooks/fork_monitor": { installForkHooksOnce: noop, flushForkEvents: noop },
        "./hooks/pthread_follow": { installPthreadFollowOnce: noop, flushWorkerEvents: noop },
        "./hooks/boundary_diff": { refreshWritableRanges: noop, flushExtWriteEvents: noop },
        "./anti_detect/plugin_interface": {}, "./target_plugins": { runTargetPlugins: () => true },
        "./transport/control": { controlAddress: noop },
        "./transport/manifest": {
            beginManifest: noop,
            sealManifest: (end: any) => { sealedMeta = end; return "/spool/call_1.json"; },
            sealSession: noop,
            persistEvents: noop,
        },
    };
    const preExports: any = {};
    const preRpc: any = {};
    runInNewContext(compiled, {
        exports: preExports, rpc: preRpc, send: (ev: any) => preEvents.push(ev),
        Stalker: { follow: noop, unfollow: noop, flush: noop }, clearInterval: noop, setImmediate: noop,
        Process: { id: 1, enumerateModules: () => [], getCurrentThreadId: () => 42 },
        Interceptor: { attach: (_fp: any, handlers: any) => { hookCallbacks = handlers; } },
        require: (name: string) => preModules[name],
    });
    preExports.acceptCallsForTest();
    preExports.beginCaptureSession(42, {}, true);
    assert.equal(preState.preEntryActive, true);
    assert.equal(preState.fnEntered, false);
    assert.equal(preState.callIdx, 1);

    preExports.installFnHook({}, {});
    const ctx: any = { threadId: 42 };
    hookCallbacks.onEnter.call(ctx, []);
    assert.equal(preState.fnEntered, true);
    assert.equal(ctx._callIdx, 1);
    assert.equal(ctx._preEntry, true);
    hookCallbacks.onLeave.call(ctx, { toString: () => "0x0" });
    assert.equal(sealedMeta.entryBoundary, "module-init-and-entry");
    assert.equal(sealedMeta.entryObserved, true);
    assert.equal(sealedMeta.firstPc, "0x800");
}

// --spawn + --trace-init during dlopen waiting period:
// Must NOT start Stalker or call beginCaptureSession in dlopen.onEnter (while target SO is unmapped
// and linker holds g_dl_mutex), and MUST start pre-entry capture in dlopen.onLeave once mapped.
{
    const dlopenEvents: any[] = [];
    const followedTids: number[] = [];
    const unfollowedTids: number[] = [];
    let pthreadInstalledCount = 0;
    let dlopenHandlers: any = null;
    let jniOnLoadHandlers: any = null;
    let fnHookHandlers: any = null;
    let sealedMeta: any = null;
    let loadedModules: any[] = [];
    const dlopenAddr = { name: "dlopen" };
    const jniOnLoadAddr = { isNull: () => false, toString: () => "0x70000400" };
    const spawnState: any = {
        callIdx: 0, callFinalized: false, fnEntered: false, preEntryActive: false, traceInit: true,
        fnHooked: false, target: null, soPattern: null, fnOffset: null, exportName: null, methodName: null,
        started: 0, primaryTid: 0, simdSidecar: false, traceFilePath: "/spool/trace.bin",
        onInsnPtr: { toString: () => "0x9999" },
        headBuf: { writeU64: noop, readU64: () => ({ toNumber: () => 25 }) },
        tailBuf: { writeU64: noop, readU64: () => ({ toNumber: () => 25 }) },
        droppedBuf: { writeU64: noop, readU64: () => ({ toNumber: () => 0 }) },
        includeRanges: [], workerTraces: {}, followedWorkerTids: {}, workerEvents: [],
        cm: { firstCapturedPc: { readPointer: () => ({ toString: () => "0x1040" }) } },
    };
    const spawnModules: Record<string, any> = {
        "./core/state": {
            STATE: spawnState, RING_RECS: 4096, ringBytes: () => 4096 * 272,
            setRingRecs: (n: number) => n, SIMD_RING_BYTES: 0, SIMD_RING_RECS: 0, SIMD_REC_SIZE: 520,
        },
        "./core/entry": {
            attachEntryHook: (_fp: any, handlers: any) => { fnHookHandlers = handlers; },
            releaseEntryHook: noop,
        },
        "./core/utils": {
            log: noop,
            getExport: (name: string) => name === "android_dlopen_ext" ? dlopenAddr : null,
            ptrToStringMaybe: (p: any) => {
                try { return p?.readUtf8String?.() ?? p?.readCString?.() ?? null; } catch (_) { return null; }
            },
            PTR_UNTAG_MASK: { toString: () => "0x00ffffffffffffff" },
        },
        "./core/cmodule": { buildCModule: () => { spawnState.onInsnPtr = { toString: () => "0x9999" }; } },
        "./core/native_io": { ioState: () => ({}), ioHealth: () => [] },
        "./core/ring": {
            openTraceFile: noop, ensureFlushTimer: noop, releaseWorkerTraces: noop,
            unfollowWorkerThreads: noop, flushRingToDisk: noop, flushWorkerTraceRings: noop,
            closeTraceFile: noop, closeWorkerTraceFiles: noop, closeSimdTraceFile: noop,
            workerTraceSummaries: () => [], ensureTraceDir: noop,
        },
        "./core/stalker": {
            applyExcludesOnce: noop,
            buildIncludeRanges: () => {
                if (spawnState.target) {
                    spawnState.includeRanges = [{
                        base: spawnState.target.base, end: spawnState.target.end, name: spawnState.target.name,
                    }];
                }
            },
            createTransform: () => noop,
        },
        "./sidecar/simd": { flushSimdRingToDisk: noop },
        "./sidecar/mem_snapshot": { captureMemorySnapshot: noop },
        "./sidecar/semantic": { createSvcEventCallback: noop, installSemanticHooksOnce: noop, flushSemanticEvents: noop },
        "./hooks/jni_vtable": { installJniHooksOnce: noop, flushJniHookEvents: noop },
        "./hooks/fork_monitor": { installForkHooksOnce: noop, flushForkEvents: noop },
        "./hooks/pthread_follow": {
            installPthreadFollowOnce: () => { pthreadInstalledCount++; },
            flushWorkerEvents: noop,
        },
        "./hooks/boundary_diff": { refreshWritableRanges: noop, flushExtWriteEvents: noop },
        "./anti_detect/plugin_interface": { BUILTIN_PLUGINS: {} },
        "./target_plugins": { installTargetPlugins: noop, runTargetPlugins: () => true, invokeTargetPlugin: noop },
        "./transport/control": { controlAddress: noop },
        "./transport/manifest": {
            prepareManifest: noop,
            beginManifest: noop,
            sealManifest: (end: any) => { sealedMeta = end; return "/spool/call_1.json"; },
            sealSession: noop,
            persistEvents: noop,
        },
    };
    const spawnExports: any = {};
    const spawnRpc: any = {};
    runInNewContext(compiled, {
        exports: spawnExports, rpc: spawnRpc, send: (ev: any) => dlopenEvents.push(ev),
        Frida: { version: "17.0.0" },
        Memory: { alloc: () => ({ writeU64: noop, readU64: () => ({ toNumber: () => 25 }), writeS32: noop }) },
        Stalker: {
            follow: (tid: number) => followedTids.push(tid),
            unfollow: (tid: number) => unfollowedTids.push(tid),
            flush: noop,
            garbageCollect: noop,
        },
        clearInterval: noop, setImmediate: noop,
        Process: { id: 100, enumerateModules: () => loadedModules, getCurrentThreadId: () => 77 },
        Interceptor: {
            attach: (fp: any, handlers: any) => {
                if (fp === dlopenAddr) dlopenHandlers = handlers;
                else if (fp === jniOnLoadAddr) jniOnLoadHandlers = handlers;
            },
            detachAll: noop,
        },
        require: (name: string) => spawnModules[name],
    });

    const initRes = spawnRpc.exports.init({ soPattern: "libtarget.so", fnOffset: 0x1200, traceInit: true });
    assert.equal(initRes, "waiting-dlopen");
    spawnRpc.exports.startCapture();
    assert.equal(followedTids.length, 0, "waiting-dlopen 阶段不得提前启动 Stalker");

    // 1. 其他无关 SO 的 dlopen
    const otherDlopenCtx: any = { threadId: 77 };
    dlopenHandlers.onEnter.call(otherDlopenCtx, [{ readCString: () => "/system/lib64/lib unrelated.so" }]);
    assert.equal(followedTids.length, 0);
    dlopenHandlers.onLeave.call(otherDlopenCtx, {});
    assert.equal(followedTids.length, 0);

    // 2. 目标 SO 的 dlopen.onEnter（此时尚未映射，linker 持锁）
    const targetDlopenCtx: any = { threadId: 88 };
    dlopenHandlers.onEnter.call(targetDlopenCtx, [{ readCString: () => "/data/app/lib/arm64/libtarget.so" }]);
    assert.equal(followedTids.length, 0, "dlopen.onEnter 内绝不能启动 Stalker 或进入 preEntryActive");
    assert.equal(spawnState.preEntryActive, false);

    // 3. 目标 SO 映射完成，进入 dlopen.onLeave（挂接 JNI_OnLoad 与目标入口，不在 libnativeloader 内直接 follow）
    const baseAddr: any = {
        add: (off: number) => ({
            sub: () => ({ toUInt32: () => off }),
            toString: () => `0x${(0x70000000 + off).toString(16)}`,
        }),
        toString: () => "0x70000000",
    };
    loadedModules = [{
        name: "libtarget.so",
        base: baseAddr,
        size: 0x10000,
        findExportByName: (name: string) => name === "JNI_OnLoad" ? jniOnLoadAddr : null,
    }];
    dlopenHandlers.onLeave.call(targetDlopenCtx, {});

    assert.equal(spawnState.fnHooked, true, "dlopen.onLeave 应完成目标入口 hook 安装");
    assert.ok(jniOnLoadHandlers, "dlopen.onLeave 应挂接 JNI_OnLoad 钩子");
    assert.equal(followedTids.length, 0, "dlopen.onLeave 返回 libnativeloader 栈帧期间不启动 Stalker");

    // 4. JNI_OnLoad 执行期间采集初始化窗口，返回时 unfollow 避免回退到系统栈帧
    const jniCtx: any = { threadId: 88 };
    jniOnLoadHandlers.onEnter.call(jniCtx, []);
    assert.equal(spawnState.preEntryActive, true, "JNI_OnLoad.onEnter 应启动目标入口前的初始化窗口采集");
    assert.equal(spawnState.fnEntered, false);
    assert.deepEqual(followedTids, [88]);
    assert.equal(pthreadInstalledCount, 0, "pre-entry 阶段不枚举全局后台线程，防止跟着系统线程崩溃");
    jniOnLoadHandlers.onLeave.call(jniCtx, {});
    assert.deepEqual(unfollowedTids, [88], "JNI_OnLoad.onLeave 应暂停 Stalker，避免跟入 libart/libbinder 间隙");

    // 5. 随后目标入口被调用并自然返回，合并封口为同一个 call
    const fnCtx: any = { threadId: 99 };
    fnHookHandlers.onEnter.call(fnCtx, []);
    assert.equal(spawnState.fnEntered, true);
    assert.equal(spawnRpc.exports.stopCapture(), "capturing", "fnEntered 期间 stopCapture 不能提前封口");
    assert.deepEqual(followedTids, [88, 99], "进入目标函数时重新对调用线程启动 Stalker");
    assert.equal(pthreadInstalledCount, 1, "正式进入目标函数后启用 pthread_follow");
    fnHookHandlers.onLeave.call(fnCtx, { toString: () => "0x1" });
    assert.equal(sealedMeta.entryBoundary, "module-init-and-entry");
    assert.equal(sealedMeta.total, 25);
}

// Worker thread safe filtering & main-thread headBuf causality anchoring
{
    const pthreadSource = readFileSync(new URL("../src/hooks/pthread_follow.ts", import.meta.url), "utf8");
    const ringSource = readFileSync(new URL("../src/core/ring.ts", import.meta.url), "utf8");
    const pthreadCompiled = ts.transpileModule(pthreadSource, {
        compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
    }).outputText;
    const ringCompiled = ts.transpileModule(ringSource, {
        compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
    }).outputText;

    let currentMainHead = 15;
    const followedWorkers: number[] = [];
    const unfollowedWorkers: number[] = [];
    let pthreadHook: any = null;
    const pendingTimers: Array<() => void> = [];

    const makePtr = (hex: string): any => ({
        isNull: () => hex === "0x0",
        and: () => makePtr(hex),
        add: (off: number) => makePtr("0x" + (BigInt(hex) + BigInt(off)).toString(16)),
        compare: (other: any) => {
            const a = BigInt(hex);
            const b = BigInt(other.toString());
            return a < b ? -1 : (a > b ? 1 : 0);
        },
        toString: () => hex,
    });

    const wState: any = {
        followWorkers: true, maxWorkerThreads: 2, traceDir: "/spool",
        callIdx: 1, primaryTid: 100, fnEntered: true, preEntryActive: false, callFinalized: false,
        deepTrace: false, traceAll: false,
        target: { name: "libtarget.so", base: makePtr("0x70000000"), end: makePtr("0x70010000") },
        includeRanges: [{ name: "libtarget.so", base: makePtr("0x70000000"), end: makePtr("0x70010000") }],
        headBuf: { readU64: () => ({ toNumber: () => currentMainHead }) },
        followedWorkerTids: {}, workerEvents: [], workerTraces: {}, pthreadHooksInstalled: false,
    };

    const commByTid: Record<number, string> = {
        101: "gum-js-loop\n",
        102: "HeapTaskDaemon\n",
        103: "Binder:100_2\n",
        104: "RenderThread\n",
        105: "mali-cmar-backe\n",
        106: "target-worker-1\n",
        107: "target-worker-2\n",
    };
    let activeThreads = [100, 101, 102, 103, 104, 105, 106];

    const sharedModules: Record<string, any> = {
        "../transport/manifest": { persistEvents: noop },
        "../core/state": {
            STATE: wState, REC_SIZE: 272, WORKER_RING_BYTES: 8192 * 272, WORKER_RING_RECS: 8192,
            HARD_EXCL: ["libc.so", "libart.so"], ART_EXCL: ["libart.so"], SOFT_EXCL: ["libbinder.so", "libgui.so"],
        },
        "./state": { STATE: wState, REC_SIZE: 272 },
        "../core/utils": {
            log: noop,
            getExport: (name: string) => name === "pthread_create" ? makePtr("0x7e000100") : null,
            currentTraceIdx: (hb: any) => hb.readU64().toNumber(),
            PTR_UNTAG_MASK: makePtr("0x00ffffffffffffff"),
        },
        "./utils": { log: noop, getExport: noop },
        "../core/stalker": { createTransform: () => noop },
        "../core/native_io": {
            NativeFile: class {
                state = {};
                path: string;
                constructor(path: string) { this.path = path; }
                close() {}
            },
        },
        "./native_io": {
            NativeFile: class {
                state = {};
                path: string;
                constructor(path: string) { this.path = path; }
                close() {}
            },
        },
        "../core/cmodule": {
            buildTraceRingCModule: (w: any) => {
                w.flushNative = noop;
                return { on_insn: makePtr("0x8888"), dispose: noop };
            },
        },
        "../sidecar/simd": { flushSimdRingToDisk: noop },
    };

    const pthreadExports: any = {};
    const ringExports: any = {};
    const sandbox = {
        exports: pthreadExports,
        NULL: makePtr("0x0"),
        File: {
            readAllText: (p: string) => {
                const m = /\/proc\/self\/task\/(\d+)\/comm$/.exec(p);
                return m ? (commByTid[Number(m[1])] || "unknown\n") : "";
            },
        },
        Memory: {
            alloc: () => {
                let val = 0;
                return {
                    writeS32: noop,
                    writeU64: (v: number) => { val = v; },
                    readU64: () => ({ toNumber: () => val }),
                };
            },
        },
        Process: {
            id: 99,
            enumerateThreads: () => activeThreads.map(id => ({
                id,
                context: id === 106 ? { pc: makePtr("0x70000100"), lr: makePtr("0x70000200") } : undefined,
            })),
            enumerateModules: () => [
                { name: "libtarget.so", base: makePtr("0x70000000"), size: 0x10000 },
                { name: "libbinder.so", base: makePtr("0x7b000000"), size: 0x10000 },
                { name: "libhwui.so", base: makePtr("0x7c000000"), size: 0x10000 },
            ],
        },
        Stalker: {
            follow: (tid: number) => followedWorkers.push(tid),
            unfollow: (tid: number) => unfollowedWorkers.push(tid),
        },
        Interceptor: {
            attach: (_addr: any, handlers: any) => { pthreadHook = handlers; },
        },
        setTimeout: (fn: () => void) => { pendingTimers.push(fn); },
        require: (name: string) => {
            assert.ok(name in sharedModules, name);
            return sharedModules[name];
        },
    };
    runInNewContext(pthreadCompiled, sandbox);
    runInNewContext(ringCompiled, { ...sandbox, exports: ringExports });

    // 1. 常驻线程枚举：必须跳过 gum-js-loop / HeapTaskDaemon / Binder / RenderThread / mali-*，只跟业务线程 106
    pthreadExports.installPthreadFollowOnce();
    assert.deepEqual(followedWorkers, [106], "常驻线程筛选必须排除系统/Frida/ART 守护线程");
    const skippedSysEvents = wState.workerEvents.filter((e: any) => e.status === "skipped_system");
    assert.equal(skippedSysEvents.length, 5);
    assert.equal(wState.workerTraces["106"].spawnedAtIdx, 15, "常驻 worker 应锚定启动时的主线程 headBuf 索引");

    // 2. pthread_create 创建系统模块线程 (libbinder.so) -> 应跳过并记录 skipped_system，不消耗 worker 槽位
    currentMainHead = 30;
    const sysSpawnCtx: any = { returnAddress: makePtr("0x7b000100") };
    pthreadHook.onEnter.call(sysSpawnCtx, [
        { readPointer: () => makePtr("0x9001") },
        makePtr("0x0"),
        makePtr("0x7b000200"), // start inside libbinder.so
    ]);
    pthreadHook.onLeave.call(sysSpawnCtx, { toInt32: () => 0 });
    assert.equal(pendingTimers.length, 0, "系统模块线程应在 pthread_create.onLeave 直接拦截，不启动延迟枚举");
    assert.equal(wState.workerEvents.at(-1).status, "skipped_system");
    assert.equal(wState.workerEvents.at(-1).anchorHeadIdx, 30);

    // 3. pthread_create 创建目标 SO 线程 (libtarget.so) -> 应正常跟踪并锚定 spawnedAtIdx
    currentMainHead = 42;
    const targetSpawnCtx: any = { returnAddress: makePtr("0x70000500") };
    pthreadHook.onEnter.call(targetSpawnCtx, [
        { readPointer: () => makePtr("0x9002") },
        makePtr("0x0"),
        makePtr("0x70000800"), // start inside libtarget.so
    ]);
    activeThreads.push(107);
    pthreadHook.onLeave.call(targetSpawnCtx, { toInt32: () => 0 });
    assert.equal(pendingTimers.length, 1);
    // 并发再发起一次 pthread_create（此时 maxWorkerThreads=2 已由 106 + 待决 107 占满）
    const extraSpawnCtx: any = { returnAddress: makePtr("0x70000500") };
    pthreadHook.onEnter.call(extraSpawnCtx, [
        { readPointer: () => makePtr("0x9003") },
        makePtr("0x0"),
        makePtr("0x70000800"),
    ]);
    pthreadHook.onLeave.call(extraSpawnCtx, { toInt32: () => 0 });
    assert.equal(pendingTimers.length, 1, "待决槽位预约应阻止超出 maxWorkerThreads 的并发定时器");
    assert.equal(wState.workerEvents.at(-1).status, "skipped_cap");

    pendingTimers.shift()!();
    assert.deepEqual(followedWorkers, [106, 107]);
    assert.equal(wState.workerTraces["107"].spawnedAtIdx, 42);

    // 4. 调用结束 unfollowWorkerThreads 时锚定 endedAtIdx，并在 workerTraceSummaries() 中输出因果窗口 [spawnedAtIdx, endedAtIdx]
    currentMainHead = 128;
    wState.workerTraces["106"].headBuf.writeU64(9);
    wState.workerTraces["107"].headBuf.writeU64(17);
    ringExports.unfollowWorkerThreads();
    assert.deepEqual(unfollowedWorkers, [106, 107]);
    const summaries = ringExports.workerTraceSummaries();
    assert.equal(summaries.length, 2);
    const sum106 = summaries.find((s: any) => s.tid === 106);
    const sum107 = summaries.find((s: any) => s.tid === 107);
    assert.equal(sum106.spawnedAtIdx, 15);
    assert.equal(sum106.endedAtIdx, 128);
    assert.equal(sum106.anchorHeadIdx, 15);
    assert.equal(sum106.records, 9);
    assert.equal(sum106.recordSize, 272);
    assert.equal(sum107.spawnedAtIdx, 42);
    assert.equal(sum107.endedAtIdx, 128);
    assert.equal(sum107.anchorHeadIdx, 42);
    assert.equal(sum107.records, 17);
    assert.equal(sum107.recordSize, 272);
}
console.log("agent lifecycle/JNI contracts hold");
