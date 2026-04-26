// Variant that EXCLUDES libc / libart / linker / libdl / etc. from Stalker
// instrumentation. This avoids the Frida Stalker LL/SC bug (where inserting
// code between ARM64 LDXR/STXR breaks the exclusive monitor and causes
// infinite atomic spin loops in libc helpers). Calls from libsgmainso into
// excluded modules run natively and return correctly, so our libsgmainso
// trace continues past the first JNI call.
const REC_SIZE = 272;
const BATCH_RECS = 4096;
const BATCH_BYTES = REC_SIZE * BATCH_RECS;
const FLUSH_INTERVAL_MS = 200;
const MAX_RECORDS = 500000;

// Modules whose internals we don't want Stalker to touch.
// Add module-name substrings here. Anything else (the target SO) gets traced.
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
];

const STATE = {
    soPattern: null, exportName: "JNI_OnLoad",
    target: null, followed: new Set(),
    batch: null, batchOff: 0, batchSeq: 0, totalRecs: 0,
    lastFlush: 0, flushTimer: null, started: 0, armed: false,
    capped: false, excluded: 0
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
    if (STATE.totalRecs + STATE.batchOff/REC_SIZE >= MAX_RECORDS) {
        STATE.capped = true;
        log(`[!] cap reached at ${MAX_RECORDS} — stop`);
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

// Stalker.exclude every loaded module that matches EXCLUDE_PATTERNS.
// Must be called BEFORE Stalker.follow.
function applyExcludes() {
    let n = 0;
    for (const m of Process.enumerateModules()) {
        for (const pat of EXCLUDE_PATTERNS) {
            if (m.name.indexOf(pat) !== -1) {
                try {
                    Stalker.exclude({ base: m.base, size: m.size });
                    n++;
                    break;
                } catch (e) {
                    log(`[!] exclude ${m.name} failed: ${e}`);
                }
            }
        }
    }
    STATE.excluded = n;
    log(`[+] Stalker excluded ${n} modules (libc/libart/linker etc.)`);
}

function startFollow(tid) {
    if (STATE.followed.has(tid)) return;
    STATE.followed.add(tid);
    newBatch();
    STATE.batchSeq = 0; STATE.totalRecs = 0;
    STATE.lastFlush = Date.now();
    ensureFlushTimer();
    applyExcludes();
    const tBase = STATE.target.base, tEnd = STATE.target.end;
    Stalker.follow(tid, {
        events: { call:false, ret:false, exec:false, block:false, compile:false },
        transform(iter) {
            const first = iter.next();
            if (first === null) return;
            // record only if PC is inside our target SO (Stalker won't even
            // visit excluded modules so this is a cheap belt-and-suspenders)
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
    log(`[+] Stalker.follow tid=${tid} (excluded ${STATE.excluded} modules)`);
}

function armOnTarget() {
    if (STATE.armed) return true;
    const m = moduleByPattern(STATE.soPattern);
    if (!m) return false;
    STATE.target = { name: m.name, base: m.base, end: m.base.add(m.size), size: m.size };
    log(`[+] target ${m.name} base=${m.base} size=0x${m.size.toString(16)}`);
    send({ type: "module", name: m.name, base: m.base.toString(), size: m.size, pid: Process.id });
    const exp = findExport(m, STATE.exportName);
    if (!exp) { log(`[!] ${STATE.exportName} not in ${m.name}`); return true; }
    log(`[+] ${STATE.exportName} @ ${exp}`);
    send({ type: "export-resolved", name: STATE.exportName, addr: exp.toString() });
    Interceptor.attach(exp, {
        onEnter(args) {
            this._tid = this.threadId;
            STATE.started = Date.now();
            log(`[>] ${STATE.exportName} enter tid=${this._tid}`);
            send({ type: "trace-begin", tid: this._tid, ts: STATE.started });
            startFollow(this._tid);
        },
        onLeave(retv) {
            const tid = this._tid;
            try { Stalker.unfollow(tid); } catch (_) {}
            try { Stalker.flush(); } catch (_) {}
            STATE.followed.delete(tid);
            flush("end");
            const elapsed = Date.now() - STATE.started;
            log(`[<] ${STATE.exportName} return=${retv} recs=${STATE.totalRecs} ms=${elapsed}`);
            send({ type: "trace-end", tid, total: STATE.totalRecs, ms: elapsed,
                   retval: retv.toString() });
        }
    });
    STATE.armed = true;
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
                    log(`[loader] dlopen("${this._path}") = ${retv}`);
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
        STATE.exportName = opts.exportName || "JNI_OnLoad";
        send({ type: "hello", pid: Process.id, frida: Frida.version,
               recSize: REC_SIZE, batchRecs: BATCH_RECS,
               soPattern: STATE.soPattern, export: STATE.exportName,
               mode: "exclude" });
        try { installDlopenHooks(); }
        catch (e) { log("[!] installDlopenHooks failed: " + e); }
        if (armOnTarget()) {
            log(`[*] already loaded; armed`);
            return "armed";
        }
        return "scheduled";
    },
    forceFlush() { flush("force"); return "ok"; },
    stats() {
        return { target: STATE.target ? STATE.target.name : null,
                 totalRecs: STATE.totalRecs, batchOff: STATE.batchOff,
                 followed: Array.from(STATE.followed), armed: STATE.armed,
                 excluded: STATE.excluded, capped: STATE.capped };
    }
};
