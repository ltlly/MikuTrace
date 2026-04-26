// Trace a dynamically-registered JNI method by hooking ART RegisterNatives.
// When the target method (default "doCommandNative") is registered, install
// our own Interceptor on the native function ptr; trace executions where
// the cmdId arg (x2 by AAPCS64: env/this/jint cmdId) matches TARGET_CMD.
//
// init opts: { soPattern, methodName, cmdArg, cmdValue, maxRecords }

const REC_SIZE = 272;
const BATCH_RECS = 4096;
const BATCH_BYTES = REC_SIZE * BATCH_RECS;
const FLUSH_INTERVAL_MS = 200;

const EXCLUDE_PATTERNS = [
    "libc.so", "libm.so", "libdl.so",
    "libart.so", "libartbase.so", "libartpalette.so",
    "libnativehelper.so", "libnativeloader.so",
    "linker", "linker64",
    "libbase.so", "libcutils.so", "liblog.so", "libutils.so",
    "libstdc++.so", "libc++.so",
    "libnetd_client.so", "libssl.so", "libcrypto.so",
    "libsync.so", "libui.so", "libgui.so",
    "libbinder.so", "libbinder_ndk.so", "libhwbinder.so",
    "libopenjdk.so", "libjavacore.so",
    "libGLESv2.so", "libEGL.so",
];

const STATE = {
    soPattern: null, methodName: "doCommandNative",
    cmdArg: 2,            // arg index for cmd id (x0=env x1=this x2=cmdId by default)
    cmdValue: 70102,
    maxRecords: 2000000,  // doCommandNative can be huge; allow up to 2M
    target: null, regHooked: false, fnHooked: false,
    fnPtr: null, javaClass: null, javaSig: null,
    followed: new Set(),
    batch: null, batchOff: 0, batchSeq: 0, totalRecs: 0,
    lastFlush: 0, flushTimer: null, started: 0, capped: false,
    excluded: 0,
    pendingTid: null,
    seenCalls: 0
};

function log(...a) { send({ type: "log", msg: a.map(String).join(" ") }); }

function moduleByPattern(pat) {
    for (const m of Process.enumerateModules())
        if (m.name.indexOf(pat) !== -1) return m;
    return null;
}

function newBatch() { STATE.batch = Memory.alloc(BATCH_BYTES); STATE.batchOff = 0; }

function flush(reason) {
    if (!STATE.batch || STATE.batchOff === 0) return;
    const off = STATE.batchOff, recs = off / REC_SIZE;
    const blob = STATE.batch.readByteArray(off);
    STATE.totalRecs += recs;
    send({ type: "frames", seq: STATE.batchSeq++, recs, bytes: off,
           total: STATE.totalRecs, reason }, blob);
    newBatch();
    STATE.lastFlush = Date.now();
}

function ensureFlushTimer() {
    if (STATE.flushTimer) return;
    STATE.flushTimer = setInterval(() => {
        if (STATE.batchOff > 0 && Date.now() - STATE.lastFlush >= FLUSH_INTERVAL_MS)
            flush("interval");
    }, FLUSH_INTERVAL_MS);
}

function recordInsn(ctx) {
    if (STATE.capped) return;
    if (STATE.totalRecs + STATE.batchOff/REC_SIZE >= STATE.maxRecords) {
        STATE.capped = true;
        log(`[!] cap reached at ${STATE.maxRecords} — stop`);
        flush("cap");
        for (const tid of STATE.followed) { try { Stalker.unfollow(tid); } catch (_) {} }
        try { Stalker.flush(); } catch (_) {}
        STATE.followed.clear();
        return;
    }
    if (STATE.batchOff + REC_SIZE > BATCH_BYTES) flush("size");
    const p = STATE.batch.add(STATE.batchOff);
    p.writePointer(ctx.pc);
    p.add(8).writePointer(ctx.x0);   p.add(16).writePointer(ctx.x1);
    p.add(24).writePointer(ctx.x2);  p.add(32).writePointer(ctx.x3);
    p.add(40).writePointer(ctx.x4);  p.add(48).writePointer(ctx.x5);
    p.add(56).writePointer(ctx.x6);  p.add(64).writePointer(ctx.x7);
    p.add(72).writePointer(ctx.x8);  p.add(80).writePointer(ctx.x9);
    p.add(88).writePointer(ctx.x10); p.add(96).writePointer(ctx.x11);
    p.add(104).writePointer(ctx.x12);p.add(112).writePointer(ctx.x13);
    p.add(120).writePointer(ctx.x14);p.add(128).writePointer(ctx.x15);
    p.add(136).writePointer(ctx.x16);p.add(144).writePointer(ctx.x17);
    p.add(152).writePointer(ctx.x18);p.add(160).writePointer(ctx.x19);
    p.add(168).writePointer(ctx.x20);p.add(176).writePointer(ctx.x21);
    p.add(184).writePointer(ctx.x22);p.add(192).writePointer(ctx.x23);
    p.add(200).writePointer(ctx.x24);p.add(208).writePointer(ctx.x25);
    p.add(216).writePointer(ctx.x26);p.add(224).writePointer(ctx.x27);
    p.add(232).writePointer(ctx.x28);p.add(240).writePointer(ctx.fp);
    p.add(248).writePointer(ctx.lr); p.add(256).writePointer(ctx.sp);
    p.add(264).writeU32(0);
    let inst = 0; try { inst = ctx.pc.readU32(); } catch (_) {}
    p.add(268).writeU32(inst);
    STATE.batchOff += REC_SIZE;
}

function applyExcludes() {
    let n = 0;
    for (const m of Process.enumerateModules()) {
        for (const pat of EXCLUDE_PATTERNS) {
            if (m.name.indexOf(pat) !== -1) {
                try { Stalker.exclude({ base: m.base, size: m.size }); n++; break; }
                catch (e) { log(`[!] exclude ${m.name} failed: ${e}`); }
            }
        }
    }
    STATE.excluded = n;
    log(`[+] Stalker excluded ${n} modules`);
}

function startFollow(tid) {
    if (STATE.followed.has(tid)) return;
    STATE.followed.add(tid);
    newBatch();
    STATE.batchSeq = 0; STATE.totalRecs = 0; STATE.capped = false;
    STATE.lastFlush = Date.now();
    ensureFlushTimer();
    if (STATE.excluded === 0) applyExcludes();
    const tBase = STATE.target.base, tEnd = STATE.target.end;
    Stalker.follow(tid, {
        events: { call:false, ret:false, exec:false, block:false, compile:false },
        transform(iter) {
            const first = iter.next();
            if (first === null) return;
            const ir0 = first.address.compare(tBase) >= 0 && first.address.compare(tEnd) < 0;
            if (ir0) iter.putCallout(recordInsn);
            iter.keep();
            let ins;
            while ((ins = iter.next()) !== null) {
                const ir = ins.address.compare(tBase) >= 0 && ins.address.compare(tEnd) < 0;
                if (ir) iter.putCallout(recordInsn);
                iter.keep();
            }
        }
    });
    log(`[+] Stalker.follow tid=${tid}`);
}

function hookFnPtr(fnPtr) {
    if (STATE.fnHooked) return;
    STATE.fnHooked = true;
    STATE.fnPtr = fnPtr;
    const cmdArg = STATE.cmdArg;
    const cmdValue = STATE.cmdValue;
    log(`[+] hooking ${STATE.methodName} @ ${fnPtr} filter x${cmdArg}==${cmdValue}`);
    send({ type: "fn-resolved", name: STATE.methodName, addr: fnPtr.toString() });
    if (!STATE._cmdHist) STATE._cmdHist = {};
    Interceptor.attach(fnPtr, {
        onEnter(args) {
            STATE.seenCalls++;
            const cmd = args[cmdArg].toInt32();
            STATE._cmdHist[cmd] = (STATE._cmdHist[cmd] || 0) + 1;
            if (cmd !== cmdValue) {
                // periodic histogram dump to host
                if (STATE.seenCalls % 100 === 1) {
                    send({ type: "cmd-hist", hist: STATE._cmdHist, total: STATE.seenCalls });
                }
                this._skip = true;
                return;
            }
            this._tid = this.threadId;
            STATE.started = Date.now();
            log(`[>] ${STATE.methodName}(cmd=${cmd}) tid=${this._tid} match!`);
            send({ type: "trace-begin", tid: this._tid, ts: STATE.started, cmd });
            startFollow(this._tid);
        },
        onLeave(retv) {
            if (this._skip) return;
            const tid = this._tid;
            try { Stalker.unfollow(tid); } catch (_) {}
            try { Stalker.flush(); } catch (_) {}
            STATE.followed.delete(tid);
            flush("end");
            const elapsed = Date.now() - STATE.started;
            log(`[<] ${STATE.methodName} return=${retv} recs=${STATE.totalRecs} ms=${elapsed}`);
            send({ type: "trace-end", tid, total: STATE.totalRecs, ms: elapsed,
                   retval: retv.toString() });
        }
    });
}

function resolveRegisterNativesViaVtable() {
    // RegisterNatives is internal to libart (not in export table).
    // Resolve via the JNIEnv* vtable: idx 215 of JNINativeInterface.
    const sym = (Module.findGlobalExportByName || Module.getGlobalExportByName)("JNI_GetCreatedJavaVMs");
    if (!sym) { log("[!] JNI_GetCreatedJavaVMs not found"); return null; }
    const fn = new NativeFunction(sym, 'int', ['pointer', 'int', 'pointer']);
    const buf = Memory.alloc(8), np = Memory.alloc(8);
    fn(buf, 1, np);
    if (np.readInt() < 1) { log("[!] no JavaVMs"); return null; }
    const vm = buf.readPointer();
    const invokeIface = vm.readPointer();
    const attachThread = invokeIface.add(4*8).readPointer();
    const envPtr = Memory.alloc(8);
    const at = new NativeFunction(attachThread, 'int', ['pointer','pointer','pointer']);
    if (at(vm, envPtr, NULL) !== 0) { log("[!] AttachCurrentThread failed"); return null; }
    const env = envPtr.readPointer();
    const nativeIface = env.readPointer();
    const regNat = nativeIface.add(215*8).readPointer();
    return regNat;
}

function hookRegisterNatives() {
    if (STATE.regHooked) return false;
    let p = null;
    try { p = resolveRegisterNativesViaVtable(); }
    catch (e) { log(`[!] resolve RegisterNatives threw: ${e}`); }
    let sym = null;
    if (!p) { log("[ ] RegisterNatives not yet resolvable; will retry"); return false; }
    try { sym = DebugSymbol.fromAddress(p).name; } catch (_) {}
    log(`[+] RegisterNatives @ ${p} (${sym})`);
    Interceptor.attach(p, {
        onEnter(args) {
            const env = args[0];
            const cls = args[1];
            const methods = args[2];
            const n = args[3].toInt32();
            for (let i = 0; i < n; i++) {
                const e = methods.add(i * 24);     // JNINativeMethod = 3 ptrs
                let nm = "?", sig = "?", fp = NULL;
                try { nm = e.readPointer().readCString(); } catch (_) {}
                try { sig = e.add(8).readPointer().readCString(); } catch (_) {}
                try { fp = e.add(16).readPointer(); } catch (_) {}
                if (nm === STATE.methodName) {
                    log(`[reg] ${nm} ${sig} -> ${fp}`);
                    STATE.javaSig = sig;
                    send({ type: "register-native", name: nm, sig, fp: fp.toString() });
                    hookFnPtr(fp);
                }
            }
        }
    });
    STATE.regHooked = true;
    return true;
}

function armOnTarget() {
    if (STATE.target) return true;
    const m = moduleByPattern(STATE.soPattern);
    if (!m) return false;
    STATE.target = { name: m.name, base: m.base, end: m.base.add(m.size), size: m.size };
    log(`[+] target ${m.name} base=${m.base} size=0x${m.size.toString(16)}`);
    send({ type: "module", name: m.name, base: m.base.toString(), size: m.size, pid: Process.id });
    return true;
}

function installDlopenHooks() {
    for (const sym of ["android_dlopen_ext", "__loader_android_dlopen_ext"]) {
        let p = null;
        try { p = (Module.findGlobalExportByName || Module.getGlobalExportByName)(sym); } catch (_) {}
        if (!p) continue;
        try {
            Interceptor.attach(p, {
                onEnter(args) { try { this._path = args[0].readUtf8String(); } catch (_) { this._path = "?"; } },
                onLeave(retv) {
                    if (!this._path || !STATE.soPattern) return;
                    if (this._path.indexOf(STATE.soPattern) === -1) return;
                    log(`[loader] dlopen("${this._path}")`);
                    armOnTarget();
                }
            });
            log(`[+] hooked ${sym} @ ${p}`);
        } catch (e) { log(`[!] hook ${sym} failed: ${e}`); }
    }
}

rpc.exports = {
    init(opts) {
        opts = opts || {};
        STATE.soPattern = opts.soPattern || "libsgmainso";
        STATE.methodName = opts.methodName || "doCommandNative";
        STATE.cmdArg = opts.cmdArg !== undefined ? opts.cmdArg : 2;
        STATE.cmdValue = opts.cmdValue !== undefined ? opts.cmdValue : 70102;
        STATE.maxRecords = opts.maxRecords || 2000000;
        STATE.fnOffset = opts.fnOffset !== undefined ? opts.fnOffset : null;  // direct hook by offset
        log(`[*] docmd-tracer up frida=${Frida.version} pid=${Process.id} `
            + `target=${STATE.methodName} cmdArg=x${STATE.cmdArg} cmdValue=${STATE.cmdValue}`);
        send({ type: "hello", pid: Process.id, frida: Frida.version,
               recSize: REC_SIZE, batchRecs: BATCH_RECS,
               method: STATE.methodName, cmdValue: STATE.cmdValue,
               maxRecords: STATE.maxRecords });
        try { installDlopenHooks(); } catch (e) { log("[!] dlopen hooks: " + e); }
        armOnTarget();

        const tryDirectHookByOffset = () => {
            if (STATE.fnHooked) return true;
            if (STATE.fnOffset === null) return false;
            if (!STATE.target) return false;
            const fp = STATE.target.base.add(STATE.fnOffset);
            log(`[*] direct hook by offset: base+0x${STATE.fnOffset.toString(16)} = ${fp}`);
            hookFnPtr(fp);
            return true;
        };
        const tryRegister = () => {
            try { if (hookRegisterNatives()) return true; }
            catch (e) { log("[!] hookRegisterNatives threw: " + e); }
            return false;
        };

        // Prefer direct offset (works on already-running processes that
        // already passed RegisterNatives). Fall back to hooking RegisterNatives.
        if (!tryDirectHookByOffset() && !tryRegister()) {
            const id = setInterval(() => {
                if (tryDirectHookByOffset() || tryRegister()) clearInterval(id);
            }, 50);
        }
        return "armed";
    },
    forceFlush() { flush("force"); return "ok"; },
    stats() {
        return { target: STATE.target ? STATE.target.name : null,
                 totalRecs: STATE.totalRecs, batchOff: STATE.batchOff,
                 followed: Array.from(STATE.followed),
                 fnHooked: STATE.fnHooked,
                 seenCalls: STATE.seenCalls,
                 capped: STATE.capped, excluded: STATE.excluded };
    }
};
