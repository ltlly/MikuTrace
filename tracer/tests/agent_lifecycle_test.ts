/** 实际 onLeave 的封口顺序、无记录上限、停止等待语义及 JNI 事件持久化。 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import ts from "typescript";

const noop = () => {};
const source = readFileSync(new URL("../src/agent.ts", import.meta.url), "utf8") +
    "\nexport { installFnHook, armWithModule };\n" +
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
        "./anti_detect/plugin_interface": {}, "./target_plugins": { runTargetPlugins: noop },
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
            throw new Error("fixture refusal");
        };
        state.callIdx = 0;
        exports.acceptCallsForTest();
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
console.log("agent lifecycle/JNI contracts hold");
