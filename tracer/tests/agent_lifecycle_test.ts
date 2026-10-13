/** 在 mock Frida 上执行实际 onLeave：快速返回不能绕过采集上限的截断语义。 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import ts from "typescript";

const noop = () => {};
const state: any = {};
let callbacks: any;
let events: any[] = [];
const modules: Record<string, any> = {
    "./core/state": { STATE: state, SIMD_REC_SIZE: 520 },
    "./core/utils": { log: noop },
    "./core/cmodule": {},
    "./core/ring": {
        unfollowWorkerThreads: noop, flushRingToDisk: noop, flushWorkerTraceRings: noop,
        closeTraceFile: noop, closeWorkerTraceFiles: noop, closeSimdTraceFile: noop,
        workerTraceSummaries: () => [],
    },
    "./core/stalker": {},
    "./sidecar/simd": { flushSimdRingToDisk: noop },
    "./sidecar/mem_snapshot": {},
    "./sidecar/semantic": { flushSemanticEvents: noop },
    "./hooks/jni_vtable": { flushJniHookEvents: noop },
    "./hooks/fork_monitor": { flushForkEvents: noop },
    "./hooks/pthread_follow": { flushWorkerEvents: noop },
    "./hooks/boundary_diff": { flushExtWriteEvents: noop },
    "./anti_detect/plugin_interface": {},
    "./transport/spool": { installSpoolTransport: noop },
    "./target_plugins": {},
};
// 仅在测试编译时暴露私有 hook 安装函数，不复制生产回调实现。
const source = readFileSync(new URL("../src/agent.ts", import.meta.url), "utf8") +
    "\nexport { installFnHook };\n";
const compiled = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
const exports: any = {};
runInNewContext(compiled, {
    exports, rpc: {}, send: (event: any) => events.push(event),
    Stalker: { unfollow: noop, flush: noop },
    Interceptor: { attach: (_fp: any, handlers: any) => { callbacks = handlers; } },
    require: (name: string) => {
        assert.ok(name in modules, `unmocked module ${name}`);
        return modules[name];
    },
});
exports.installFnHook({}, {});

for (const [total, cap, dropped, truncated] of [
    [1999, 2000, 0, false],
    [2000, 2000, 0, true],
    [2001, 2000, 0, true],
    [2000, 0, 0, false],
    [1999, 2000, 1, true],
]) {
    events = [];
    Object.assign(state, {
        callFinalized: false, fnEntered: true, started: Date.now(), maxRecords: cap,
        headBuf: { readU64: () => ({ toNumber: () => total }) },
        droppedBuf: { readU64: () => ({ toNumber: () => dropped }) },
        simdSidecar: false, traceFilePath: "/spool/trace.bin",
    });
    const context = { _tid: 42, _callIdx: 1 };
    callbacks.onLeave.call(context, { toString: () => "0x42" });
    assert.equal(events.length, 1);
    assert.equal(events[0].type, "trace-end");
    assert.equal(events[0].total, total);
    assert.equal(events[0].truncated, truncated, `total=${total}, cap=${cap}, dropped=${dropped}`);
    assert.equal(state.fnEntered, false);
    callbacks.onLeave.call(context, { toString: () => "0x42" });
    assert.equal(events.length, 1, "已封口的调用不能重复发 trace-end");
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
