import { controlAddress } from "./transport/control";
import { beginManifest, sealManifest, prepareManifest, sealSession, persistEvents } from "./transport/manifest";
/**
 * traceMiku Agent — modular entry point
 *
 * Architecture:
 *   CModule on_insn → 有界 native 批缓冲 → 同步写盘背压 → 函数返回后 fsync/manifest
 *   Optional: SIMD sidecar, semantic events, JNI hooks, fork monitor, anti-detect plugins
 *
 * Build: frida-compile src/agent.ts -o _agent.js
 */

import {
    STATE, RING_RECS, ringBytes, setRingRecs, SIMD_RING_BYTES, SIMD_RING_RECS,
    SIMD_REC_SIZE, InitOptions
} from "./core/state";
import { log, getExport } from "./core/utils";
import { ioState, ioHealth } from "./core/native_io";
import { attachEntryHook, releaseEntryHook } from "./core/entry";
import { buildCModule } from "./core/cmodule";
import {
    flushRingToDisk,
    openTraceFile,
    closeTraceFile,
    closeSimdTraceFile,
    ensureFlushTimer,
    ensureTraceDir,
    flushWorkerTraceRings,
    closeWorkerTraceFiles,
    unfollowWorkerThreads,
    releaseWorkerTraces,
    workerTraceSummaries,
} from "./core/ring";
import { applyExcludesOnce, buildIncludeRanges, createTransform } from "./core/stalker";
import { flushSimdRingToDisk } from "./sidecar/simd";
import { captureMemorySnapshot } from "./sidecar/mem_snapshot";
import { createSvcEventCallback, installSemanticHooksOnce, flushSemanticEvents } from "./sidecar/semantic";
import { installJniHooksOnce, flushJniHookEvents } from "./hooks/jni_vtable";
import { installForkHooksOnce, flushForkEvents } from "./hooks/fork_monitor";
import { installPthreadFollowOnce, flushWorkerEvents } from "./hooks/pthread_follow";
import { refreshWritableRanges, flushExtWriteEvents } from "./hooks/boundary_diff";
import { BUILTIN_PLUGINS } from "./anti_detect/plugin_interface";
import { installTargetPlugins, runTargetPlugins, invokeTargetPlugin } from "./target_plugins";

let acceptingCalls = false;
let endedManifest: string | null = null;
let completedCalls = 0;
let lastHead = 0;
let lastTail = 0;
let retired = false;
let fatalError: string | null = null;
function retireCapture(): void {
    if (retired) return;
    retired = true;
    acceptingCalls = false;
    if (STATE.hbTimer) { clearInterval(STATE.hbTimer); STATE.hbTimer = null; }
    // 下一个 JS tick 已离开 onLeave；先回收 Stalker 翻译，再释放生产器及批缓冲。
    setImmediate(() => {
        releaseEntryHook();
        Interceptor.detachAll();
        Stalker.garbageCollect();
        releaseWorkerTraces();
        STATE.workerTraces = {};
        if (STATE.cm) { STATE.cm.dispose(); STATE.cm = null; }
        STATE.flushNative = null; STATE.flushSimdNative = null; STATE.onInsnPtr = null;
        STATE.ringBuf = null; STATE.headBuf = null; STATE.tailBuf = null;
        STATE.simdRingBuf = null; STATE.simdHeadBuf = null; STATE.simdTailBuf = null;
    });
}
let maxCalls = 1;

/** 封口/安装异常不能只留控制台日志，否则 host 会永远等待或误报完成。 */
function failCapture(error: unknown): void {
    fatalError = String(error);
    acceptingCalls = false;
    STATE.callFinalized = true;
    STATE.active?.writeS32(0);
    try { Stalker.unfollow(STATE.primaryTid!); } catch (_) {}
    unfollowWorkerThreads();
    STATE.fnEntered = false;
    try { sealSession(fatalError); }
    catch (manifestError) { fatalError += `; failed to publish failure: ${manifestError}`; }
    retireCapture();
}

// ─────────── RegisterNatives fallback ────────

function hookRegisterNatives(onResolved: (fp: NativePointer) => void): boolean {
    // Frida 17 移除了静态 Module.findExportByName; getExport 带 global 兜底
    const sym = getExport("JNI_GetCreatedJavaVMs");
    if (!sym) return false;
    try {
        const fn = new NativeFunction(sym, "int", ["pointer", "int", "pointer"]);
        const buf = Memory.alloc(8);
        const np = Memory.alloc(8);
        fn(buf, 1, np);
        if (np.readInt() < 1) return false;
        const vm = buf.readPointer();
        const invokeIface = vm.readPointer();
        const attachThread = invokeIface.add(4 * 8).readPointer();
        const envPtr = Memory.alloc(8);
        const at = new NativeFunction(attachThread, "int", ["pointer", "pointer", "pointer"]);
        if ((at(vm, envPtr, NULL) as unknown as number) !== 0) return false;
        const env = envPtr.readPointer();
        const nativeIface = env.readPointer();
        const regNat = nativeIface.add(215 * 8).readPointer();
        log(`[+] RegisterNatives @ ${regNat}`);
        Interceptor.attach(regNat, {
            onEnter(args) {
                const methods = args[2];
                const n = args[3].toInt32();
                for (let i = 0; i < n; i++) {
                    const e = methods.add(i * 24);
                    let nm = "?";
                    try { nm = e.readPointer().readCString()!; } catch (_) {}
                    let sg = "?";
                    try { sg = e.add(8).readPointer().readCString()!; } catch (_) {}
                    let fp = NULL;
                    try { fp = e.add(16).readPointer(); } catch (_) {}
                    if (nm === STATE.methodName) {
                        log(`[reg] 找到 ${nm} ${sg} -> ${fp}`);
                        send({ type: "register-native", name: nm, sig: sg, fp: fp.toString() });
                        onResolved(fp);
                    }
                }
            }
        });
        return true;
    } catch (e) {
        log(`[!] RegisterNatives hook 失败: ${e}`);
        return false;
    }
}

// ─────────── Main hook installation ─────────────────────────────────────────

function installFnHook(fp: NativePointer, onInsn: NativePointer): void {
    if (STATE.target) STATE.fnOffset = fp.sub(STATE.target.base).toUInt32();
    attachEntryHook(fp, {
        onEnter(args) {
            if (!acceptingCalls || STATE.callIdx >= maxCalls) {
                (this as any)._skip = true;
                return;
            }
            if (STATE.cmdValue != null && STATE.cmdArg != null) {
                const c = args[STATE.cmdArg!].toInt32();
                if (c !== STATE.cmdValue) { (this as any)._skip = true; return; }
            }
            if (STATE.fnEntered) { (this as any)._skip = true; return; }
            try {
                try { runTargetPlugins("beforeTrace", { args, tid: this.threadId, address: fp }); }
                catch (e) {
                    (this as any)._skip = true;
                    fatalError = `target plugin refused capture: ${e}`;
                    sealSession(fatalError);
                    retireCapture();
                    return;
                }
                STATE.fnEntered = true;
                STATE.callFinalized = false;
                (this as any)._tid = this.threadId;
                STATE.callIdx++;
                (this as any)._callIdx = STATE.callIdx;
                STATE.primaryTid = (this as any)._tid;
                STATE.started = Date.now();

                // Reset SPSC counters (per-call)
                STATE.headBuf!.writeU64(0);
                STATE.tailBuf!.writeU64(0);
                STATE.droppedBuf!.writeU64(0);
                if (STATE.simdSidecar) {
                    STATE.simdHeadBuf!.writeU64(0);
                    STATE.simdTailBuf!.writeU64(0);
                    STATE.simdDroppedBuf!.writeU64(0);
                }
                if (STATE.semanticEvents) {
                    STATE.semanticEventBuf = [];
                }
                STATE.workerEvents = [];
                STATE.followedWorkerTids = {};
                // 上一 call 的 worker CModule 必须显式 unload: 下一 call 复用同 tid 时
                // 旧实例的 native 内存 (ring + 编译产物) 不释放会持续泄漏
                releaseWorkerTraces();
                STATE.workerTraces = {};
                STATE.batchSeq = 0;

                openTraceFile((this as any)._callIdx, (this as any)._tid);
                beginManifest();
                log(`[>] call #${(this as any)._callIdx} tid=${(this as any)._tid}`);
                send({
                    type: "trace-begin", callIdx: (this as any)._callIdx,
                    tid: (this as any)._tid, ts: STATE.started,
                    devicePath: STATE.traceFilePath,
                    simdDevicePath: STATE.simdTraceFilePath,
                    simdRecordSize: SIMD_REC_SIZE,
                    simdSampleStride: STATE.simdSampleStride
                });
                ensureFlushTimer();

                // Anti-detect (installed before Stalker.follow creates RWX pages)
                if (STATE.hideRwxMaps) {
                    try {
                        const { plugin } = require("./anti_detect/hide_rwx_maps");
                        plugin.install();
                    } catch (e) { log(`[hide-rwx-maps][!] ${e}`); }
                }
                if (STATE.patchSuicide) {
                    try {
                        const { plugin } = require("./anti_detect/patch_suicide");
                        plugin.install({ spec: STATE.suicidePatchSpec });
                    } catch (e) { log(`[patch-suicide][!] ${e}`); }
                }
                if (STATE.blockSelfKill) {
                    try {
                        const { plugin } = require("./anti_detect/block_self_kill");
                        plugin.install();
                    } catch (e) { log(`[block-self-kill][!] ${e}`); }
                }

                applyExcludesOnce();

                if (STATE.deepTrace || (STATE.diffSyms && STATE.diffSyms.length > 0)) {
                    refreshWritableRanges();
                }

                installJniHooksOnce();
                installSemanticHooksOnce();
                if (STATE.enableForkHook) {
                    installForkHooksOnce();
                }

                buildIncludeRanges();
                const ranges = STATE.includeRanges.map(r => ({ base: r.base, end: r.end }));

                // Initial memory snapshot (t=0 ground truth for pre-trace data).
                // Captured here, after excludes/ranges are set but before Stalker
                // starts, so the bytecode tables / .rodata are in their decrypted
                // initial state. Best-effort; never throws into the trace path.
                try { captureMemorySnapshot((this as any)._callIdx); }
                catch (e) { persistEvents("snapshot_errors.jsonl", [{ reason: "snapshot-failed", error: String(e) }]); }

                Stalker.follow((this as any)._tid, {
                    events: { call: false, ret: false, exec: false, block: false, compile: false },
                    transform: createTransform(onInsn, ranges),
                });
                installPthreadFollowOnce();
                log(`[+] Stalker.follow tid=${(this as any)._tid} (native writer, device-spool)`);
                send({ type: "follow", tid: (this as any)._tid });
            } catch (error) {
                (this as any)._skip = true;
                failCapture(error);
            }
        },
        onLeave(retv) {
            if ((this as any)._skip) return;
            // onLeave 幂等；不能重开或重复提交已封口文件。
            if (STATE.callFinalized) {
                log(`[!] call #${(this as any)._callIdx} 已被强制终结, 跳过 onLeave 重复 trace-end`);
                return;
            }
            STATE.callFinalized = true;
            try {
                Stalker.unfollow((this as any)._tid);
                unfollowWorkerThreads();
                Stalker.flush();
                flushRingToDisk("end");
                flushWorkerTraceRings("end");
                flushSimdRingToDisk("end");
                closeTraceFile();
                closeWorkerTraceFiles();
                closeSimdTraceFile();

                const elapsed = Date.now() - STATE.started;
                const total = STATE.headBuf!.readU64().toNumber();
                const dropped = STATE.droppedBuf!.readU64().toNumber();
                const simdTotal = STATE.simdSidecar ? STATE.simdHeadBuf!.readU64().toNumber() : 0;
                const simdDropped = STATE.simdSidecar ? STATE.simdDroppedBuf!.readU64().toNumber() : 0;
                const workerTraces = workerTraceSummaries();
                const rate = (total / Math.max(elapsed / 1000, 1e-3)).toFixed(0);

                flushJniHookEvents((this as any)._callIdx);
                flushSemanticEvents((this as any)._callIdx);
                flushExtWriteEvents();
                flushForkEvents((this as any)._callIdx);
                flushWorkerEvents((this as any)._callIdx);

                log(`[<] call #${(this as any)._callIdx} ret=${retv} recs=${total} dropped=${dropped} ms=${elapsed} (${rate} rec/s) → ${STATE.traceFilePath}`);
                const end = {
                    type: "trace-end", callIdx: (this as any)._callIdx,
                    tid: (this as any)._tid, retval: retv.toString(),
                    ms: elapsed, total, dropped,
                    firstPc: total > 0 ? STATE.cm.firstCapturedPc.readPointer().toString() : null,
                    truncated: dropped > 0 || simdDropped > 0,
                    returnObserved: true,
                    devicePath: STATE.traceFilePath,
                    simdDevicePath: STATE.simdTraceFilePath,
                    simdRecords: simdTotal, simdDropped: simdDropped,
                    simdRecordSize: SIMD_REC_SIZE,
                    simdSampleStride: STATE.simdSampleStride,
                    workerTraces
                };
                const manifestPath = sealManifest(end, STATE.callIdx >= maxCalls || !acceptingCalls);
                endedManifest = manifestPath;
                completedCalls++;
                send({ ...end, manifestPath });
                lastHead = total; lastTail = total;
                if (STATE.callIdx >= maxCalls || !acceptingCalls) retireCapture();
                clearInterval(STATE.hbTimer); STATE.hbTimer = null;

                STATE.fnEntered = false;
            } catch (error) { failCapture(error); }
        }
    });
}

// ─────────── Target resolution and arming ───────────────────────────────────

function armWithModule(m: Module, onInsn: NativePointer): void {
    runTargetPlugins("onModule", { module: m });
    STATE.target = { name: m.name, base: m.base, end: m.base.add(m.size) };
    log(`[+] target ${m.name} base=${m.base} end=${m.base.add(m.size)}`);
    send({ type: "module", name: m.name, base: m.base.toString(), size: m.size, pid: Process.id });
    send({
        type: "modules",
        modules: Process.enumerateModules().map(mod => ({
            name: mod.name, base: mod.base.toString(), size: mod.size
        })),
        pid: Process.id
    });

    // Resolve hook target: fnOffset > exportName > methodName
    let fp: NativePointer | null = null;
    let label = "";

    if (STATE.fnOffset !== null && STATE.fnOffset !== undefined) {
        fp = m.base.add(STATE.fnOffset);
        label = `${STATE.soPattern}+0x${STATE.fnOffset.toString(16)}`;
    } else if (STATE.exportName) {
        // Try multiple resolution strategies
        if (typeof m.findExportByName === "function") {
            fp = m.findExportByName(STATE.exportName);
        }
        if (!fp && typeof (m as any).getExportByName === "function") {
            try { fp = (m as any).getExportByName(STATE.exportName); } catch (_) {}
        }
        if (!fp) {
            try {
                const exps = m.enumerateExports();
                const e = exps.find(x => x.name === STATE.exportName);
                if (e) fp = e.address;
            } catch (_) {}
        }
        if (!fp) {
            // 未 strip 的静态/PIE 二进制没有 .dynsym 导出, 只有 .symtab 符号表
            // (NDK 默认构建即如此); enumerateSymbols 是唯一解析途径.
            try {
                const syms = m.enumerateSymbols();
                const s = syms.find(x => x.name === STATE.exportName);
                if (s) fp = s.address;
            } catch (_) {}
        }
        if (!fp) {
            throw new Error(`export "${STATE.exportName}" not found in ${m.name}`);
        }
        STATE.fnOffset = fp.sub(m.base).toInt32();
        label = `${STATE.soPattern}!${STATE.exportName}`;
    } else if (STATE.methodName) {
        // RegisterNatives fallback: wait for JNI registration
        log(`[*] waiting for RegisterNatives("${STATE.methodName}")...`);
        const ok = hookRegisterNatives((resolvedFp) => {
            try {
                installFnHook(resolvedFp, onInsn);
                log(`[+] hook ${STATE.methodName} @ ${resolvedFp} via RegisterNatives`);
            } catch (error) { failCapture(error); }
        });
        if (!ok) {
            throw new Error("RegisterNatives hook unavailable; use a resolved export or offset");
        }
        return;
    } else {
        log(`[!!] 必须传 --fn-offset / --export / --method 之一`);
        return;
    }

    installFnHook(fp, onInsn);
    log(`[+] hook ${label} @ ${fp} (offset 0x${STATE.fnOffset!.toString(16)})`);
}

// ─────────── RPC exports ────────────────────────────────────────────────────

rpc.exports = {
    controlAddress,
    startCapture() {
        if (retired) throw new Error("capture session already sealed");
        acceptingCalls = true; return "ok";
    },
    prepareSpool(opts: { sessionId: string; pkg?: string; traceDir?: string }) {
        STATE.pkg = opts.pkg || null;
        STATE.traceDir = opts.traceDir || null;
        ensureTraceDir();
        prepareManifest(opts.sessionId);
        return { deviceDir: STATE.traceDir, sessionId: opts.sessionId,
            manifestPath: `${STATE.traceDir}/session.json`, pid: Process.id };
    },
    init(opts: InitOptions) {
        // soPattern required
        STATE.soPattern = opts.soPattern;
        if (!STATE.soPattern) {
            throw new Error("init: opts.soPattern required (e.g. 'libtarget', 'libfoo'). No hardcoded default.");
        }
        STATE.exportName = opts.exportName || null;
        STATE.methodName = opts.methodName || null;
        STATE.fnOffset = (opts.fnOffset != null) ? opts.fnOffset : null;
        if (STATE.fnOffset == null && !STATE.exportName && !STATE.methodName) {
            throw new Error("init: must provide fnOffset OR exportName OR methodName");
        }
        installTargetPlugins((opts as any).targetPlugins || []);
        maxCalls = (opts as any).maxCalls ?? 1;
        if (!Number.isSafeInteger(maxCalls) || maxCalls < 1) throw new Error("maxCalls must be positive");

        // Anti-detect config
        STATE.suicidePatchSpec = (opts as any).suicidePatchSpec || null;
        STATE.patchSuicide = !!(opts as any).patchSuicide;
        STATE.hideRwxMaps = !!(opts as any).hideRwxMaps;
        STATE.blockSelfKill = !!(opts as any).blockSelfKill;

        if (opts.cmdValue !== undefined) STATE.cmdValue = opts.cmdValue!;
        if (opts.cmdArg !== undefined) STATE.cmdArg = opts.cmdArg!;
        STATE.pkg = opts.pkg || null;
        // host 预建的 trace 目录: 优先于 app 私有 cache (后者随 app 退出被清理)
        if (opts.traceDir) STATE.traceDir = opts.traceDir;
        STATE.includeSoPatterns = Array.isArray(opts.includeSoPatterns) ? opts.includeSoPatterns : [];
        STATE.deepTrace = !!opts.deepTrace;
        STATE.execOnly = !!opts.execOnly;
        STATE.traceAll = !!opts.traceAll;
        // --trace-all implies the per-symbol deep path machinery (writable-range
        // tracking etc.), so turn deepTrace on too when traceAll is requested.
        if (STATE.traceAll) STATE.deepTrace = true;
        STATE.stalkerExcludePatterns = Array.isArray(opts.stalkerExcludePatterns) && opts.stalkerExcludePatterns.length
            ? opts.stalkerExcludePatterns : null;
        STATE.boundaryDiffPatterns = Array.isArray(opts.boundaryDiffPatterns) ? opts.boundaryDiffPatterns : null;
        // JNI hooks
        STATE.jniHookSpecs = Array.isArray(opts.jniHooks) ? opts.jniHooks : null;

        // Semantic events
        STATE.semanticEvents = !!opts.semanticEvents;
        STATE.semanticEventBuf = [];
        STATE.semanticEventSeq = 0;
        STATE.semanticHooksInstalled = false;
        if (STATE.semanticEvents && !STATE.onSvcEventCb) {
            STATE.onSvcEventCb = createSvcEventCallback();
        }

        // Initial memory snapshot
        STATE.snapshotMem = !!opts.snapshotMem;
        // SIMD sidecar
        STATE.simdSidecar = !!opts.simdSidecar;
        const stride = parseInt(String(opts.simdSampleStride || 1));
        STATE.simdSampleStride = Number.isFinite(stride) && stride > 0 ? stride : 1;

        // Fork hook
        STATE.enableForkHook = !!opts.enableForkHook;
        STATE.followWorkers = !!(opts as any).followWorkers;
        const workerCap = parseInt(String((opts as any).maxWorkerThreads || 4));
        STATE.maxWorkerThreads = Number.isFinite(workerCap) && workerCap > 0 ? Math.min(workerCap, 32) : 4;

        const effRecs = opts.ringRecs ? setRingRecs(opts.ringRecs) : RING_RECS;

        // 分批同步写入的有界缓冲
        STATE.active = Memory.alloc(4);
        STATE.traceIoState = ioState();
        STATE.simdIoState = ioState();
        STATE.ringBuf = Memory.alloc(ringBytes());
        STATE.headBuf = Memory.alloc(8); STATE.headBuf.writeU64(0);
        STATE.tailBuf = Memory.alloc(8); STATE.tailBuf.writeU64(0);
        STATE.droppedBuf = Memory.alloc(8); STATE.droppedBuf.writeU64(0);
        STATE.ringRecsBuf = Memory.alloc(8); STATE.ringRecsBuf.writeU64(effRecs);

        if (STATE.simdSidecar) {
            STATE.simdRingBuf = Memory.alloc(SIMD_RING_BYTES);
            STATE.simdHeadBuf = Memory.alloc(8); STATE.simdHeadBuf.writeU64(0);
            STATE.simdTailBuf = Memory.alloc(8); STATE.simdTailBuf.writeU64(0);
            STATE.simdDroppedBuf = Memory.alloc(8); STATE.simdDroppedBuf.writeU64(0);
            STATE.simdRingRecsBuf = Memory.alloc(8); STATE.simdRingRecsBuf.writeU64(SIMD_RING_RECS);
            STATE.simdStrideBuf = Memory.alloc(8); STATE.simdStrideBuf.writeU64(STATE.simdSampleStride);
        }

        log(`[*] traceMiku agent (modular) native backpressure, buffer=${(ringBytes() / 1024 / 1024).toFixed(1)}MB/${effRecs}recs ` +
            `pkg=${STATE.pkg}, ` +
            `simd=${STATE.simdSidecar ? "on" : "off"}, semantic=${STATE.semanticEvents ? "on" : "off"}, ` +
            `workers=${STATE.followWorkers ? STATE.maxWorkerThreads : "off"}`);
        send({ type: "hello", pid: Process.id, frida: Frida.version });

        // Build CModule
        try { buildCModule(); }
        catch (e) { log(`[!!] CModule 编译失败: ${e}`); return "no-cmodule"; }

        const onInsn = STATE.onInsnPtr!;

        // Load anti-detect plugins (user-specified)
        if (opts.antiDetect && opts.antiDetect.length > 0) {
            for (const pluginId of opts.antiDetect) {
                if (BUILTIN_PLUGINS[pluginId]) {
                    try {
                        // Synchronous dynamic require for bundled plugins
                        const mod = require(`./anti_detect/${pluginId}`);
                        const pluginConfig = opts.antiDetectConfig?.[pluginId] || {};
                        mod.plugin.install(pluginConfig);
                        log(`[plugin] ${pluginId} installed`);
                    } catch (e) {
                        log(`[plugin][!] ${pluginId} failed: ${e}`);
                    }
                } else {
                    log(`[plugin][!] unknown plugin: ${pluginId}`);
                }
            }
        }

        // Find target SO and arm
        const m = Process.enumerateModules().find(x => x.name.indexOf(STATE.soPattern!) !== -1);
        if (!m) {
            log("[!] no SO yet, hooking dlopen to wait");
            const dlopen = getExport("android_dlopen_ext") || getExport("dlopen");
            if (!dlopen) { log("[!!] dlopen sym not found"); return "no-dlopen"; }
            Interceptor.attach(dlopen, {
                onEnter(a) { try { (this as any)._p = a[0].readCString(); } catch (_) {} },
                onLeave(_rv) {
                    if (!(this as any)._p || (this as any)._p.indexOf(STATE.soPattern!) < 0) return;
                    if (STATE.target) return;
                    const m2 = Process.enumerateModules().find(x => x.name.indexOf(STATE.soPattern!) !== -1);
                    if (m2) {
                        try { armWithModule(m2, onInsn); }
                        catch (error) { failCapture(error); }
                    }
                }
            });
            return "waiting-dlopen";
        }
        try { armWithModule(m, onInsn); }
        catch (error) { failCapture(error); throw error; }
        return "armed";
    },

    pluginCall(id: string, payload: any) { return invokeTargetPlugin(id, payload); },
    disposePlugins() { runTargetPlugins("dispose"); return "ok"; },
    stopCapture() {
        acceptingCalls = false;
        if (!STATE.fnEntered) { sealSession(); retireCapture(); }
        return STATE.fnEntered ? "capturing" : "stopped";
    },

    stats() {
        return {
            endedManifest, acceptingCalls, completedCalls, error: fatalError,
            blockedIo: ioHealth(),
            target: STATE.target ? STATE.target.name : null,
            head: STATE.headBuf ? STATE.headBuf.readU64().toNumber() : lastHead,
            tail: STATE.tailBuf ? STATE.tailBuf.readU64().toNumber() : lastTail,
            dropped: STATE.droppedBuf ? STATE.droppedBuf.readU64().toNumber() : 0,
            primaryTid: STATE.primaryTid,
            callIdx: STATE.callIdx,
            traceFilePath: STATE.traceFilePath,
        };
    }
};
