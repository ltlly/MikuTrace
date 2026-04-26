// Full-thread doCommandNative tracer.
//
// Strategy: hook the target native function on the calling thread (existing
// behavior). ALSO hook pthread_create so any worker thread spawned during
// or after the call can be Stalker-followed if it ever executes inside
// our target SO. This captures the async portion of cmd 70102 etc.
//
// Trace records from all threads stream into one trace.bin (host writes
// per-PID; agent tags batches with tid in `meta` field).
//
// init opts: { soPattern, methodName, cmdArg, cmdValue, fnOffset?,
//              maxRecords, followAllThreads (default true) }

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
    cmdArg: 2, cmdValue: 70102,
    maxRecords: 5000000,
    fnOffset: null,
    followAllThreads: true,

    target: null,
    fnPtr: null, fnHooked: false,

    followed: new Set(),
    excluded: false,

    batches: new Map(),  // tid -> {batch, batchOff, batchSeq, totalRecs, lastFlush}
    flushTimer: null,
    started: 0,
    capped: false,
    seenCalls: 0,
    primaryTid: 0,
    threadHooked: false,
    threadKnownAt: new Set(),  // tids we already check
};

function log(...a) { send({ type: "log", msg: a.map(String).join(" ") }); }
function moduleByPattern(pat) {
    for (const m of Process.enumerateModules())
        if (m.name.indexOf(pat) !== -1) return m;
    return null;
}
function findExport(mod, name) {
    try { const a = mod.findExportByName(name); if (a) return a; } catch (_) {}
    for (const e of mod.enumerateExports()) if (e.name === name) return e.address;
    return null;
}

function getOrInitBatch(tid) {
    let b = STATE.batches.get(tid);
    if (!b) {
        b = {
            batch: Memory.alloc(BATCH_BYTES), batchOff: 0,
            batchSeq: 0, totalRecs: 0, lastFlush: Date.now(),
        };
        STATE.batches.set(tid, b);
    }
    return b;
}

function flush(tid, reason) {
    const b = STATE.batches.get(tid);
    if (!b || b.batchOff === 0) return;
    const off = b.batchOff, recs = off / REC_SIZE;
    const blob = b.batch.readByteArray(off);
    b.totalRecs += recs;
    send({ type: "frames", tid, seq: b.batchSeq++, recs, bytes: off,
           total: b.totalRecs, reason }, blob);
    b.batch = Memory.alloc(BATCH_BYTES);
    b.batchOff = 0;
    b.lastFlush = Date.now();
}

function ensureFlushTimer() {
    if (STATE.flushTimer) return;
    STATE.flushTimer = setInterval(() => {
        const now = Date.now();
        for (const [tid, b] of STATE.batches) {
            if (b.batchOff > 0 && now - b.lastFlush >= FLUSH_INTERVAL_MS)
                flush(tid, "interval");
        }
    }, FLUSH_INTERVAL_MS);
}

function totalAcrossAllTids() {
    let s = 0;
    for (const b of STATE.batches.values()) s += b.totalRecs + b.batchOff/REC_SIZE;
    return s;
}

function recordInsn(ctx) {
    if (STATE.capped) return;
    if (totalAcrossAllTids() >= STATE.maxRecords) {
        STATE.capped = true;
        log(`[!] cap reached at ${STATE.maxRecords} records — stop`);
        for (const tid of STATE.followed) {
            try { Stalker.unfollow(tid); } catch (_) {}
            flush(tid, "cap");
        }
        try { Stalker.flush(); } catch (_) {}
        STATE.followed.clear();
        return;
    }
    const tid = Process.getCurrentThreadId();
    const b = getOrInitBatch(tid);
    if (b.batchOff + REC_SIZE > BATCH_BYTES) flush(tid, "size");
    const p = b.batch.add(b.batchOff);
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
    b.batchOff += REC_SIZE;
}

function applyExcludesOnce() {
    if (STATE.excluded) return;
    let n = 0;
    for (const m of Process.enumerateModules()) {
        for (const pat of EXCLUDE_PATTERNS) {
            if (m.name.indexOf(pat) !== -1) {
                try { Stalker.exclude({ base: m.base, size: m.size }); n++; break; }
                catch (e) { log(`[!] exclude ${m.name} failed: ${e}`); }
            }
        }
    }
    log(`[+] Stalker excluded ${n} modules`);
    STATE.excluded = true;
}

function followThread(tid, label) {
    if (STATE.followed.has(tid)) return;
    if (STATE.capped) return;
    STATE.followed.add(tid);
    ensureFlushTimer();
    applyExcludesOnce();
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
    log(`[+] follow tid=${tid} (${label})`);
    send({ type: "follow", tid, label });
}

function hookFnPtr(fnPtr) {
    if (STATE.fnHooked) return;
    STATE.fnHooked = true;
    STATE.fnPtr = fnPtr;
    log(`[+] hooking ${STATE.methodName} @ ${fnPtr} filter x${STATE.cmdArg}==${STATE.cmdValue}`);
    send({ type: "fn-resolved", name: STATE.methodName, addr: fnPtr.toString() });
    Interceptor.attach(fnPtr, {
        onEnter(args) {
            STATE.seenCalls++;
            const cmd = args[STATE.cmdArg].toInt32();
            if (cmd !== STATE.cmdValue) { this._skip = true; return; }
            this._tid = this.threadId;
            STATE.primaryTid = this._tid;
            STATE.started = Date.now();
            log(`[>] ${STATE.methodName}(cmd=${cmd}) tid=${this._tid} match!`);
            send({ type: "trace-begin", tid: this._tid, ts: STATE.started, cmd });
            followThread(this._tid, "primary");
            // Also follow ALL existing threads so worker threads already up
            // get instrumented (their work for this cmd may run on them).
            if (STATE.followAllThreads) {
                hookAllExistingThreads();
                hookPthreadCreate();
            }
        },
        onLeave(retv) {
            if (this._skip) return;
            const tid = this._tid;
            // unfollow primary (but keep workers alive — they may still be active)
            try { Stalker.unfollow(tid); } catch (_) {}
            try { Stalker.flush(); } catch (_) {}
            STATE.followed.delete(tid);
            flush(tid, "primary-end");
            const elapsed = Date.now() - STATE.started;
            log(`[<] ${STATE.methodName} return=${retv} primaryRecs=${STATE.batches.get(tid)?.totalRecs||0} ms=${elapsed}`);
            send({ type: "trace-end", tid, retval: retv.toString(), ms: elapsed });
        }
    });
}

function hookAllExistingThreads() {
    let n = 0;
    for (const t of Process.enumerateThreads()) {
        if (STATE.followed.has(t.id)) continue;
        if (STATE.threadKnownAt.has(t.id)) continue;
        STATE.threadKnownAt.add(t.id);
        followThread(t.id, "existing");
        n++;
    }
    log(`[+] followed ${n} existing threads`);
}

function hookPthreadCreate() {
    if (STATE.threadHooked) return;
    const sym = (Module.findGlobalExportByName||Module.getGlobalExportByName)("pthread_create");
    if (!sym) { log("[!] pthread_create not found"); return; }
    Interceptor.attach(sym, {
        onLeave(retv) {
            // After a successful pthread_create, the new thread will appear
            // in enumerateThreads soon. Schedule a delayed sweep.
            setTimeout(() => {
                for (const t of Process.enumerateThreads()) {
                    if (!STATE.threadKnownAt.has(t.id)) {
                        STATE.threadKnownAt.add(t.id);
                        followThread(t.id, "spawned");
                    }
                }
            }, 50);
        }
    });
    STATE.threadHooked = true;
    log(`[+] hooked pthread_create @ ${sym}`);
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
        try { p = (Module.findGlobalExportByName||Module.getGlobalExportByName)(sym); } catch (_) {}
        if (!p) continue;
        try {
            Interceptor.attach(p, {
                onEnter(args) { try { this._path = args[0].readUtf8String(); } catch (_) { this._path = "?"; } },
                onLeave(retv) {
                    if (!this._path || this._path.indexOf(STATE.soPattern) === -1) return;
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
        STATE.maxRecords = opts.maxRecords || 5000000;
        STATE.fnOffset = opts.fnOffset !== undefined ? opts.fnOffset : null;
        STATE.followAllThreads = opts.followAllThreads !== false;
        send({ type: "hello", pid: Process.id, frida: Frida.version,
               recSize: REC_SIZE, batchRecs: BATCH_RECS,
               method: STATE.methodName, cmdValue: STATE.cmdValue,
               maxRecords: STATE.maxRecords,
               followAllThreads: STATE.followAllThreads });
        try { installDlopenHooks(); } catch (e) { log("[!] dlopen hooks: " + e); }
        armOnTarget();

        const tryHook = () => {
            if (STATE.fnHooked) return true;
            if (!STATE.target) return false;
            if (STATE.fnOffset !== null) {
                const fp = STATE.target.base.add(STATE.fnOffset);
                log(`[*] direct hook by offset: base+0x${STATE.fnOffset.toString(16)} = ${fp}`);
                hookFnPtr(fp);
                return true;
            }
            return false;
        };
        if (!tryHook()) {
            const id = setInterval(() => { if (tryHook()) clearInterval(id); }, 50);
        }
        return "armed";
    },
    forceFlush() {
        for (const tid of STATE.batches.keys()) flush(tid, "force");
        return "ok";
    },
    stats() {
        const tids = {};
        for (const [tid, b] of STATE.batches) tids[tid] = b.totalRecs + b.batchOff/REC_SIZE;
        return { target: STATE.target ? STATE.target.name : null,
                 fnHooked: STATE.fnHooked, seenCalls: STATE.seenCalls,
                 primaryTid: STATE.primaryTid,
                 followed: Array.from(STATE.followed),
                 perTid: tids,
                 capped: STATE.capped };
    }
};
