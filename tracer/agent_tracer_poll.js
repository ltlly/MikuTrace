// Variant of agent_tracer that AVOIDS Interceptor.attach on dlopen.
// TB inspects libc functions for inline trampolines; hooking them gets us
// killed. Instead we poll Process.enumerateModules() until libsgmainso
// appears, then hook JNI_OnLoad (which is in our target SO, not in libc).
// We hook JNI_OnLoad ASAP, but if libsgmainso has already started executing
// JNI_OnLoad we'll be too late.
const REC_SIZE = 272;
const BATCH_RECS = 4096;
const BATCH_BYTES = REC_SIZE * BATCH_RECS;
const FLUSH_INTERVAL_MS = 200;
const POLL_INTERVAL_MS = 5;

const STATE = {
    soPattern: null, exportName: "JNI_OnLoad",
    target: null, followed: new Set(),
    batch: null, batchOff: 0, batchSeq: 0, totalRecs: 0,
    lastFlush: 0, flushTimer: null, started: 0,
    armed: false
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

function startFollow(tid) {
    if (STATE.followed.has(tid)) return;
    STATE.followed.add(tid);
    newBatch();
    STATE.batchSeq = 0; STATE.totalRecs = 0;
    STATE.lastFlush = Date.now();
    ensureFlushTimer();
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

rpc.exports = {
    init(opts) {
        opts = opts || {};
        STATE.soPattern = opts.soPattern || "libsgmainso";
        STATE.exportName = opts.exportName || "JNI_OnLoad";
        // VERY light: do not enumerate modules here; that may block when the
        // process is in spawn-gated SIGSTOP state. Defer all work to a timer
        // that will run after the process resumes.
        send({ type: "hello", pid: Process.id, frida: Frida.version,
               recSize: REC_SIZE, batchRecs: BATCH_RECS,
               soPattern: STATE.soPattern, export: STATE.exportName });
        const id = setInterval(() => {
            try {
                if (!STATE.armed && armOnTarget()) { /* keep running for safety */ }
            } catch (e) { send({ type: "log", msg: "poll err: " + e }); }
        }, POLL_INTERVAL_MS);
        return "scheduled";
    },
    forceFlush() { flush("force"); return "ok"; },
    stats() {
        return { target: STATE.target ? STATE.target.name : null,
                 totalRecs: STATE.totalRecs, batchOff: STATE.batchOff,
                 followed: Array.from(STATE.followed), armed: STATE.armed };
    }
};
