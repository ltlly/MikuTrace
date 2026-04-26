// traceMiku Stage-1 agent: per-instruction ARM64 register snapshot tracer.
//
// Flow:
//   1. Call rpc.exports.init({soPattern, exportName?, mode?}) from host.
//   2. Either the target SO is already mapped (attach mode) OR we hook
//      android_dlopen_ext to catch its load.
//   3. When the SO is present, resolve `exportName` (default "JNI_OnLoad").
//      Interceptor.attach it; on entry start Stalker.follow on this thread
//      with a transform that inserts a per-instruction callout iff the
//      instruction's address lies inside the SO range.
//   4. Each callout snapshots PC, X0..X30, SP, raw insn bytes into a native
//      batch buffer; when full or flush-interval elapses, send() the batch
//      as a binary blob.
//   5. On Interceptor.onLeave, unfollow + flush + notify host.
//
// Record layout (little-endian, 272 bytes per record):
//   0x00 u64 pc
//   0x08 u64 x[31]        (x0..x30, where x29=fp, x30=lr)
//   0x100 u64 sp
//   0x108 u32 nzcv        (always 0 for now; Frida CpuContext exposes it but
//                          may be zero on some plats — keep field for future)
//   0x10c u32 inst        (raw 4-byte ARM64 instruction at pc)
const REC_SIZE = 272;
const BATCH_RECS = 4096;          // ~1.06 MB per batch
const BATCH_BYTES = REC_SIZE * BATCH_RECS;
const FLUSH_INTERVAL_MS = 200;

const STATE = {
    soPattern: null,
    exportName: "JNI_OnLoad",
    target: null,                 // {name, base, end, size}
    followed: new Set(),          // tids currently followed
    batch: null, batchOff: 0,
    batchSeq: 0,
    totalRecs: 0,
    droppedRecs: 0,
    lastFlush: 0,
    flushTimer: null,
    started: 0,
    stopped: false
};

function log(...a) { send({ type: "log", msg: a.map(String).join(" ") }); }

function moduleByPattern(pattern) {
    for (const m of Process.enumerateModules()) {
        if (m.name.indexOf(pattern) !== -1) return m;
    }
    return null;
}

function findExport(mod, name) {
    try {
        const a = mod.findExportByName(name);
        if (a) return a;
    } catch (_) {}
    for (const e of mod.enumerateExports()) {
        if (e.name === name) return e.address;
    }
    return null;
}

function newBatch() {
    STATE.batch = Memory.alloc(BATCH_BYTES);
    STATE.batchOff = 0;
}

function flush(reason) {
    if (!STATE.batch || STATE.batchOff === 0) return;
    const off = STATE.batchOff;
    const recs = off / REC_SIZE;
    const blob = STATE.batch.readByteArray(off);
    STATE.totalRecs += recs;
    send({ type: "frames",
           seq: STATE.batchSeq++,
           recs: recs,
           bytes: off,
           total: STATE.totalRecs,
           reason: reason || "size" }, blob);
    newBatch();
    STATE.lastFlush = Date.now();
}

function ensureFlushTimer() {
    if (STATE.flushTimer) return;
    STATE.flushTimer = setInterval(() => {
        const now = Date.now();
        if (STATE.batchOff > 0 && now - STATE.lastFlush >= FLUSH_INTERVAL_MS) {
            flush("interval");
        }
    }, FLUSH_INTERVAL_MS);
}

// Hot path: invoked per traced instruction.
function recordInsn(ctx) {
    if (STATE.batchOff + REC_SIZE > BATCH_BYTES) flush("size");
    const p = STATE.batch.add(STATE.batchOff);
    p.writePointer(ctx.pc);
    // x0..x28
    p.add(8).writePointer(ctx.x0);
    p.add(16).writePointer(ctx.x1);
    p.add(24).writePointer(ctx.x2);
    p.add(32).writePointer(ctx.x3);
    p.add(40).writePointer(ctx.x4);
    p.add(48).writePointer(ctx.x5);
    p.add(56).writePointer(ctx.x6);
    p.add(64).writePointer(ctx.x7);
    p.add(72).writePointer(ctx.x8);
    p.add(80).writePointer(ctx.x9);
    p.add(88).writePointer(ctx.x10);
    p.add(96).writePointer(ctx.x11);
    p.add(104).writePointer(ctx.x12);
    p.add(112).writePointer(ctx.x13);
    p.add(120).writePointer(ctx.x14);
    p.add(128).writePointer(ctx.x15);
    p.add(136).writePointer(ctx.x16);
    p.add(144).writePointer(ctx.x17);
    p.add(152).writePointer(ctx.x18);
    p.add(160).writePointer(ctx.x19);
    p.add(168).writePointer(ctx.x20);
    p.add(176).writePointer(ctx.x21);
    p.add(184).writePointer(ctx.x22);
    p.add(192).writePointer(ctx.x23);
    p.add(200).writePointer(ctx.x24);
    p.add(208).writePointer(ctx.x25);
    p.add(216).writePointer(ctx.x26);
    p.add(224).writePointer(ctx.x27);
    p.add(232).writePointer(ctx.x28);
    p.add(240).writePointer(ctx.fp);   // x29
    p.add(248).writePointer(ctx.lr);   // x30
    p.add(256).writePointer(ctx.sp);
    p.add(264).writeU32(0);            // nzcv reserved
    let inst = 0;
    try { inst = ctx.pc.readU32(); } catch (_) {}
    p.add(268).writeU32(inst);
    STATE.batchOff += REC_SIZE;
}

function setupTarget(modName, base, size) {
    if (STATE.target) return;
    STATE.target = { name: modName, base: base, end: base.add(size), size: size };
    log(`[+] target SO: ${modName} base=${base} size=0x${size.toString(16)}`);
    send({ type: "module",
           name: modName,
           base: base.toString(),
           size: size,
           pid: Process.id });

    const m = Process.findModuleByName(modName);
    if (!m) { log("[!] module disappeared"); return; }
    const exp = findExport(m, STATE.exportName);
    if (!exp) {
        log(`[!] export ${STATE.exportName} not found; available exports listed below`);
        let n = 0;
        for (const e of m.enumerateExports()) { log(`    ${e.type} ${e.name} @ ${e.address}`); if (++n > 10) break; }
        return;
    }
    log(`[+] hooking ${STATE.exportName} @ ${exp}`);
    send({ type: "export-resolved", name: STATE.exportName, addr: exp.toString() });
    Interceptor.attach(exp, {
        onEnter(args) {
            this._tid = this.threadId;
            if (STATE.followed.has(this._tid)) return;
            STATE.started = Date.now();
            log(`[>] ${STATE.exportName} enter tid=${this._tid} vm=${args[0]}`);
            send({ type: "trace-begin", tid: this._tid, ts: STATE.started });
            startFollow(this._tid);
        },
        onLeave(retv) {
            if (!STATE.followed.has(this._tid)) return;
            try { Stalker.unfollow(this._tid); } catch (_) {}
            try { Stalker.flush(); } catch (_) {}
            STATE.followed.delete(this._tid);
            flush("end");
            const elapsed = Date.now() - STATE.started;
            log(`[<] ${STATE.exportName} return=${retv} recs=${STATE.totalRecs} elapsed=${elapsed}ms `
                + `rate=${(STATE.totalRecs / Math.max(elapsed/1000,1e-3)).toFixed(0)} insn/s`);
            send({ type: "trace-end",
                   tid: this._tid,
                   total: STATE.totalRecs,
                   ms: elapsed,
                   retval: retv.toString() });
        }
    });
}

function startFollow(tid) {
    if (STATE.followed.has(tid)) return;
    STATE.followed.add(tid);
    newBatch();
    STATE.batchSeq = 0;
    STATE.totalRecs = 0;
    STATE.lastFlush = Date.now();
    ensureFlushTimer();
    const tBase = STATE.target.base, tEnd = STATE.target.end;
    Stalker.follow(tid, {
        events: { call: false, ret: false, exec: false, block: false, compile: false },
        transform(iter) {
            const first = iter.next();
            if (first === null) return;
            const inRange0 = first.address.compare(tBase) >= 0 && first.address.compare(tEnd) < 0;
            if (inRange0) iter.putCallout(recordInsn);
            iter.keep();
            let ins;
            while ((ins = iter.next()) !== null) {
                const inRange = ins.address.compare(tBase) >= 0 && ins.address.compare(tEnd) < 0;
                if (inRange) iter.putCallout(recordInsn);
                iter.keep();
            }
        }
    });
    log(`[+] Stalker.follow tid=${tid} (in-range insn -> snapshot)`);
}

function installLoadHooks() {
    for (const sym of ["android_dlopen_ext", "__loader_android_dlopen_ext", "dlopen"]) {
        let p = null;
        try { p = (Module.findGlobalExportByName || Module.getGlobalExportByName)(sym); } catch (_) {}
        if (!p) continue;
        try {
            Interceptor.attach(p, {
                onEnter(args) {
                    try { this._path = args[0].readUtf8String(); } catch (_) { this._path = "?"; }
                },
                onLeave(retv) {
                    if (!this._path || !STATE.soPattern) return;
                    if (this._path.indexOf(STATE.soPattern) === -1) return;
                    log(`[loader] ${sym}("${this._path}") = ${retv}`);
                    setImmediate(() => {
                        const m = moduleByPattern(STATE.soPattern);
                        if (m) setupTarget(m.name, m.base, m.size);
                    });
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
        log(`[*] traceMiku agent up frida=${Frida.version} pid=${Process.id} runtime=${Script.runtime}`);
        log(`[*] config: soPattern="${STATE.soPattern}" export=${STATE.exportName} `
            + `recSize=${REC_SIZE} batch=${BATCH_RECS}`);

        send({ type: "hello",
               pid: Process.id,
               frida: Frida.version,
               recSize: REC_SIZE,
               batchRecs: BATCH_RECS });

        const m = moduleByPattern(STATE.soPattern);
        if (m) {
            log(`[i] target already loaded`);
            setupTarget(m.name, m.base, m.size);
        } else {
            installLoadHooks();
        }
        return "ok";
    },
    forceFlush() {
        flush("force");
        return "ok";
    },
    stats() {
        return {
            target: STATE.target ? STATE.target.name : null,
            totalRecs: STATE.totalRecs,
            batchOff: STATE.batchOff,
            followed: Array.from(STATE.followed),
            stopped: STATE.stopped
        };
    }
};
