/**
 * traceMiku Agent — modular entry point
 *
 * Architecture:
 *   CModule on_insn → SPSC ring (17MB) → V8 setInterval flush → device file
 *   Optional: SIMD sidecar, semantic events, JNI hooks, fork monitor, anti-detect plugins
 *
 * Build: frida-compile src/agent.ts -o _agent.js
 */

import {
    STATE, RING_BYTES, RING_RECS, SIMD_RING_BYTES, SIMD_RING_RECS,
    SIMD_REC_SIZE, FLUSH_INTERVAL_MS, InitOptions
} from "./core/state";
import { log, getExport } from "./core/utils";
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
    workerTraceSummaries,
} from "./core/ring";
import { applyExcludesOnce, buildIncludeRanges, createTransform } from "./core/stalker";
import { flushSimdRingToDisk } from "./sidecar/simd";
import { createSvcEventCallback, installSemanticHooksOnce, flushSemanticEvents } from "./sidecar/semantic";
import { installJniHooksOnce, flushJniHookEvents } from "./hooks/jni_vtable";
import { installForkHooksOnce, flushForkEvents } from "./hooks/fork_monitor";
import { installPthreadFollowOnce, flushWorkerEvents } from "./hooks/pthread_follow";
import { refreshWritableRanges, flushExtWriteEvents } from "./hooks/boundary_diff";
import { BUILTIN_PLUGINS } from "./anti_detect/plugin_interface";

// ─────────── RegisterNatives fallback (merged from agent_generic.js) ────────

function hookRegisterNatives(onResolved: (fp: NativePointer) => void): boolean {
    const sym = Module.findExportByName(null, "JNI_GetCreatedJavaVMs");
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
    Interceptor.attach(fp, {
        onEnter(args) {
            if (STATE.cmdValue != null && STATE.cmdArg != null) {
                const c = args[STATE.cmdArg!].toInt32();
                if (c !== STATE.cmdValue) { (this as any)._skip = true; return; }
            }
            if (STATE.fnEntered) { (this as any)._skip = true; return; }
            STATE.fnEntered = true;
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
            STATE.workerTraces = {};
            STATE.batchSeq = 0;

            openTraceFile((this as any)._callIdx, (this as any)._tid);
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

            try { installJniHooksOnce(); } catch (_) {}
            try { installSemanticHooksOnce(); } catch (e) { log("[semantic][!] " + e); }
            if (STATE.enableForkHook) {
                try { installForkHooksOnce(); } catch (e) { log("[fork][!] " + e); }
            }

            buildIncludeRanges();
            const ranges = STATE.includeRanges.map(r => ({ base: r.base, end: r.end }));

            Stalker.follow((this as any)._tid, {
                events: { call: false, ret: false, exec: false, block: false, compile: false },
                transform: createTransform(onInsn, ranges),
            });
            try { installPthreadFollowOnce(); } catch (e) { log("[pthread-follow][!] " + e); }
            log(`[+] Stalker.follow tid=${(this as any)._tid} (SPSC lock-free, device-spool)`);
            send({ type: "follow", tid: (this as any)._tid });
        },
        onLeave(retv) {
            if ((this as any)._skip) return;
            try { Stalker.unfollow((this as any)._tid); } catch (_) {}
            unfollowWorkerThreads();
            try { Stalker.flush(); } catch (_) {}
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

            try { flushJniHookEvents((this as any)._callIdx); } catch (e) { log(`[!] flushJni: ${e}`); }
            try { flushSemanticEvents((this as any)._callIdx); } catch (e) { log(`[!] flushSemantic: ${e}`); }
            try { flushExtWriteEvents(); } catch (e) { log(`[!] flushExt: ${e}`); }
            try { flushForkEvents((this as any)._callIdx); } catch (e) { log(`[!] flushFork: ${e}`); }
            try { flushWorkerEvents((this as any)._callIdx); } catch (e) { log(`[!] flushWorkers: ${e}`); }

            log(`[<] call #${(this as any)._callIdx} ret=${retv} recs=${total} dropped=${dropped} ms=${elapsed} (${rate} rec/s) → ${STATE.traceFilePath}`);
            send({
                type: "trace-end", callIdx: (this as any)._callIdx,
                tid: (this as any)._tid, retval: retv.toString(),
                ms: elapsed, total, dropped, truncated: false,
                devicePath: STATE.traceFilePath,
                simdDevicePath: STATE.simdTraceFilePath,
                simdRecords: simdTotal, simdDropped: simdDropped,
                simdRecordSize: SIMD_REC_SIZE,
                simdSampleStride: STATE.simdSampleStride,
                workerTraces
            });
            STATE.fnEntered = false;
        }
    });
}

// ─────────── Target resolution and arming ───────────────────────────────────

function armWithModule(m: Module, onInsn: NativePointer): void {
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
            fp = Module.findExportByName(m.name, STATE.exportName);
        }
        if (!fp) {
            try {
                const exps = m.enumerateExports();
                const e = exps.find(x => x.name === STATE.exportName);
                if (e) fp = e.address;
            } catch (_) {}
        }
        if (!fp) {
            log(`[!!] export "${STATE.exportName}" not found in ${m.name}`);
            return;
        }
        STATE.fnOffset = fp.sub(m.base).toInt32();
        label = `${STATE.soPattern}!${STATE.exportName}`;
    } else if (STATE.methodName) {
        // RegisterNatives fallback: wait for JNI registration
        log(`[*] waiting for RegisterNatives("${STATE.methodName}")...`);
        const ok = hookRegisterNatives((resolvedFp) => {
            installFnHook(resolvedFp, onInsn);
            log(`[+] hook ${STATE.methodName} @ ${resolvedFp} via RegisterNatives`);
        });
        if (!ok) {
            log(`[!] RegisterNatives hook failed, will retry`);
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

        // Anti-detect config
        STATE.suicidePatchSpec = (opts as any).suicidePatchSpec || null;
        STATE.patchSuicide = !!(opts as any).patchSuicide;
        STATE.hideRwxMaps = !!(opts as any).hideRwxMaps;
        STATE.blockSelfKill = !!(opts as any).blockSelfKill;

        if (opts.cmdValue !== undefined) STATE.cmdValue = opts.cmdValue!;
        if (opts.cmdArg !== undefined) STATE.cmdArg = opts.cmdArg!;
        STATE.pkg = opts.pkg || null;
        STATE.includeSoPatterns = Array.isArray(opts.includeSoPatterns) ? opts.includeSoPatterns : [];
        STATE.deepTrace = !!opts.deepTrace;
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

        // SIMD sidecar
        STATE.simdSidecar = !!opts.simdSidecar;
        const stride = parseInt(String(opts.simdSampleStride || 1));
        STATE.simdSampleStride = Number.isFinite(stride) && stride > 0 ? stride : 1;

        // Fork hook
        STATE.enableForkHook = !!opts.enableForkHook;
        STATE.followWorkers = !!(opts as any).followWorkers;
        const workerCap = parseInt(String((opts as any).maxWorkerThreads || 4));
        STATE.maxWorkerThreads = Number.isFinite(workerCap) && workerCap > 0 ? Math.min(workerCap, 32) : 4;

        // maxRecords enforcement (0 = unlimited)
        const maxR = (opts.maxRecords != null && opts.maxRecords > 0) ? opts.maxRecords : 0;
        STATE.maxRecords = maxR;

        // Allocate SPSC ring buffers
        STATE.ringBuf = Memory.alloc(RING_BYTES);
        STATE.headBuf = Memory.alloc(8); STATE.headBuf.writeU64(0);
        STATE.tailBuf = Memory.alloc(8); STATE.tailBuf.writeU64(0);
        STATE.droppedBuf = Memory.alloc(8); STATE.droppedBuf.writeU64(0);
        STATE.ringRecsBuf = Memory.alloc(8); STATE.ringRecsBuf.writeU64(RING_RECS);
        STATE.maxRecordsBuf = Memory.alloc(8); STATE.maxRecordsBuf.writeU64(maxR);

        if (STATE.simdSidecar) {
            STATE.simdRingBuf = Memory.alloc(SIMD_RING_BYTES);
            STATE.simdHeadBuf = Memory.alloc(8); STATE.simdHeadBuf.writeU64(0);
            STATE.simdTailBuf = Memory.alloc(8); STATE.simdTailBuf.writeU64(0);
            STATE.simdDroppedBuf = Memory.alloc(8); STATE.simdDroppedBuf.writeU64(0);
            STATE.simdRingRecsBuf = Memory.alloc(8); STATE.simdRingRecsBuf.writeU64(SIMD_RING_RECS);
            STATE.simdStrideBuf = Memory.alloc(8); STATE.simdStrideBuf.writeU64(STATE.simdSampleStride);
        }

        log(`[*] traceMiku agent (modular) SPSC lock-free, ring=${(RING_BYTES / 1024 / 1024).toFixed(1)}MB ` +
            `(${RING_RECS} recs), flush=${FLUSH_INTERVAL_MS}ms, pkg=${STATE.pkg}, ` +
            `simd=${STATE.simdSidecar ? "on" : "off"}, semantic=${STATE.semanticEvents ? "on" : "off"}, ` +
            `workers=${STATE.followWorkers ? STATE.maxWorkerThreads : "off"}`);
        send({ type: "hello", pid: Process.id, frida: Frida.version, mode: "tracemiku-modular-agent" });

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
                    if (m2) armWithModule(m2, onInsn);
                }
            });
            return "waiting-dlopen";
        }
        armWithModule(m, onInsn);
        return "armed";
    },

    forceFlush() {
        flushRingToDisk("force");
        return "ok";
    },

    stats() {
        return {
            target: STATE.target ? STATE.target.name : null,
            head: STATE.headBuf ? STATE.headBuf.readU64().toNumber() : 0,
            tail: STATE.tailBuf ? STATE.tailBuf.readU64().toNumber() : 0,
            dropped: STATE.droppedBuf ? STATE.droppedBuf.readU64().toNumber() : 0,
            primaryTid: STATE.primaryTid,
            callIdx: STATE.callIdx,
            traceFilePath: STATE.traceFilePath,
        };
    }
};
