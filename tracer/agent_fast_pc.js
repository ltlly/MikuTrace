// 极速 PC-only trace agent. 用 Stalker `events: {exec: true}` 全 native
// 收集 PC 流, 无 JS callout 开销. 比每条 insn 全寄存器快照快 ~100x.
//
// Trace 文件格式: 每条 8 字节 = u64 PC. 不含寄存器/指令机器码.
// 为了支持寄存器查询, 配合稀疏 SNAPSHOT (每 N 条 callout 一次全寄存器).
//
// init opts: { soPattern, methodName, fnOffset, cmdValue, cmdArg,
//              snapshotInterval (默认 0=禁用), maxRecords }

const PC_REC_SIZE = 8;     // u64 pc only
const SNAP_REC_SIZE = 264; // u64 pc + 31×u64 regs + u64 sp = 33*8 = 264
const BATCH_PC = 65536;    // 65k pcs/batch = 512KB
const BATCH_SNAP = 1024;
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
    soPattern: null, fnOffset: 0x57770, cmdArg: 2, cmdValue: 70102,
    methodName: "doCommandNative",
    maxRecords: 50000000,    // 默认 50M (够大)
    snapshotInterval: 0,     // 0 = pure PC mode

    target: null, fnHooked: false, excluded: false,
    primaryTid: 0,
    pcBatch: null, pcBatchOff: 0, pcBatchSeq: 0, totalPCs: 0,
    snapBatch: null, snapBatchOff: 0, snapBatchSeq: 0, totalSnaps: 0,
    callouts: 0,
    flushTimer: null, started: 0, capped: false, callIdx: 0,
};

function log(...a) { send({ type: "log", msg: a.map(String).join(" ") }); }

function moduleByPattern(pat) {
    for (const m of Process.enumerateModules())
        if (m.name.indexOf(pat) !== -1) return m;
    return null;
}

function newPCBatch() {
    STATE.pcBatch = Memory.alloc(BATCH_PC * PC_REC_SIZE);
    STATE.pcBatchOff = 0;
}
function newSnapBatch() {
    STATE.snapBatch = Memory.alloc(BATCH_SNAP * SNAP_REC_SIZE);
    STATE.snapBatchOff = 0;
}

function flushPC(reason) {
    if (!STATE.pcBatch || STATE.pcBatchOff === 0) return;
    const off = STATE.pcBatchOff;
    const blob = STATE.pcBatch.readByteArray(off);
    STATE.totalPCs += off / PC_REC_SIZE;
    send({ type: "pc-frames", seq: STATE.pcBatchSeq++, count: off / PC_REC_SIZE,
           bytes: off, total: STATE.totalPCs, reason }, blob);
    newPCBatch();
}
function flushSnap(reason) {
    if (!STATE.snapBatch || STATE.snapBatchOff === 0) return;
    const off = STATE.snapBatchOff;
    const blob = STATE.snapBatch.readByteArray(off);
    STATE.totalSnaps += off / SNAP_REC_SIZE;
    send({ type: "snap-frames", seq: STATE.snapBatchSeq++, count: off / SNAP_REC_SIZE,
           bytes: off, total: STATE.totalSnaps, reason }, blob);
    newSnapBatch();
}

function ensureFlushTimer() {
    if (STATE.flushTimer) return;
    STATE.flushTimer = setInterval(() => {
        if (STATE.pcBatchOff > 0) flushPC("interval");
        if (STATE.snapBatchOff > 0) flushSnap("interval");
    }, FLUSH_INTERVAL_MS);
}

// 偶发的全寄存器快照 (每 snapshotInterval 次 callout)
function snapshotCallout(ctx) {
    STATE.callouts++;
    if (STATE.snapBatch === null) newSnapBatch();
    if (STATE.snapBatchOff + SNAP_REC_SIZE > BATCH_SNAP * SNAP_REC_SIZE)
        flushSnap("size");
    const p = STATE.snapBatch.add(STATE.snapBatchOff);
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
    STATE.snapBatchOff += SNAP_REC_SIZE;
}

function applyExcludesOnce() {
    if (STATE.excluded) return;
    let n = 0;
    for (const m of Process.enumerateModules()) {
        for (const pat of EXCLUDE_PATTERNS) {
            if (m.name.indexOf(pat) !== -1) {
                try { Stalker.exclude({ base: m.base, size: m.size }); n++; break; }
                catch (_) {}
            }
        }
    }
    log(`[+] Stalker.exclude ${n} 个 system 模块`);
    STATE.excluded = true;
}

function followFast(tid) {
    ensureFlushTimer();
    applyExcludesOnce();
    newPCBatch();
    if (STATE.snapshotInterval > 0) newSnapBatch();
    const tBase = STATE.target.base, tEnd = STATE.target.end;
    const snapInt = STATE.snapshotInterval;
    let insn_counter = 0;
    let in_range_seen = 0;
    Stalker.follow(tid, {
        // Native 模式: exec event 自动写到 stalker buffer, JS onReceive 拿
        events: { exec: true, compile: false, block: false, call: false, ret: false },
        onReceive(events) {
            // events 是 binary buffer, 每条 GumExecEvent = {type:u32, pad:u32, location:u64}
            // = 16 字节. 我们只要 location, 过滤 in_range.
            try {
                const u8 = new Uint8Array(events);
                const view = new DataView(events);
                const n = events.byteLength / 16;
                for (let i = 0; i < n; i++) {
                    const off = i * 16;
                    // location 在 offset 8 (skip 8 bytes header)
                    const lo = view.getUint32(off + 8, true);
                    const hi = view.getUint32(off + 12, true);
                    const pc = (BigInt(hi) << 32n) | BigInt(lo);
                    // in-range check
                    const tBaseN = BigInt(tBase.toString());
                    const tEndN = BigInt(tEnd.toString());
                    if (pc < tBaseN || pc >= tEndN) continue;
                    in_range_seen++;
                    if (STATE.capped) continue;
                    if (in_range_seen >= STATE.maxRecords) {
                        STATE.capped = true;
                        log(`[!] cap ${STATE.maxRecords}`);
                        flushPC("cap");
                        try { Stalker.unfollow(tid); } catch (_) {}
                        try { Stalker.flush(); } catch (_) {}
                        return;
                    }
                    if (STATE.pcBatch === null) newPCBatch();
                    if (STATE.pcBatchOff + PC_REC_SIZE > BATCH_PC * PC_REC_SIZE)
                        flushPC("size");
                    STATE.pcBatch.add(STATE.pcBatchOff).writeU64(pc);
                    STATE.pcBatchOff += PC_REC_SIZE;
                }
            } catch (e) { send({ type: "log", msg: "onReceive err: " + e }); }
        },
        // 可选稀疏寄存器快照
        ...(snapInt > 0 ? {
            transform(iter) {
                let ins;
                while ((ins = iter.next()) !== null) {
                    insn_counter++;
                    const inRange = ins.address.compare(tBase) >= 0 && ins.address.compare(tEnd) < 0;
                    if (inRange && (insn_counter % snapInt) === 0) {
                        iter.putCallout(snapshotCallout);
                    }
                    iter.keep();
                }
            }
        } : {})
    });
    log(`[+] follow tid=${tid} (PC-only fast mode${snapInt > 0 ? `, snap every ${snapInt}` : ''})`);
    send({ type: "follow", tid, label: "primary" });
}

function hookFn(fp) {
    if (STATE.fnHooked) return;
    STATE.fnHooked = true;
    log(`[+] hook ${STATE.methodName} @ ${fp} cmd=${STATE.cmdValue}`);
    Interceptor.attach(fp, {
        onEnter(args) {
            const cmd = args[STATE.cmdArg].toInt32();
            if (cmd !== STATE.cmdValue) { this._skip = true; return; }
            this._tid = this.threadId;
            STATE.callIdx++;
            STATE.primaryTid = this._tid;
            STATE.started = Date.now();
            log(`[>] call #${STATE.callIdx} tid=${this._tid}`);
            send({ type: "trace-begin", tid: this._tid, ts: STATE.started, call: STATE.callIdx });
            followFast(this._tid);
        },
        onLeave(retv) {
            if (this._skip) return;
            try { Stalker.unfollow(this._tid); } catch (_) {}
            try { Stalker.flush(); } catch (_) {}
            flushPC("end"); flushSnap("end");
            const elapsed = Date.now() - STATE.started;
            log(`[<] call #${STATE.callIdx} ret=${retv} pcs=${STATE.totalPCs} ms=${elapsed} (${(STATE.totalPCs/Math.max(elapsed/1000,1e-3)).toFixed(0)} pc/s)`);
            send({ type: "trace-end", tid: this._tid, retval: retv.toString(),
                   ms: elapsed, pcs: STATE.totalPCs });
        }
    });
}

function arm() {
    if (STATE.target) return true;
    const m = moduleByPattern(STATE.soPattern);
    if (!m) return false;
    STATE.target = { name: m.name, base: m.base, end: m.base.add(m.size), size: m.size };
    log(`[+] 目标 ${m.name} @ ${m.base}`);
    send({ type: "module", name: m.name, base: m.base.toString(), size: m.size, pid: Process.id });
    return true;
}

rpc.exports = {
    init(opts) {
        opts = opts || {};
        STATE.soPattern = opts.soPattern || "libsgmainso";
        STATE.fnOffset = opts.fnOffset !== undefined ? opts.fnOffset : 0x57770;
        STATE.cmdValue = opts.cmdValue !== undefined ? opts.cmdValue : 70102;
        STATE.cmdArg = opts.cmdArg !== undefined ? opts.cmdArg : 2;
        STATE.maxRecords = opts.maxRecords || 50000000;
        STATE.snapshotInterval = opts.snapshotInterval || 0;
        log(`[*] fast-pc agent up | snapInterval=${STATE.snapshotInterval}`);
        send({ type: "hello", pid: Process.id, frida: Frida.version,
               mode: "fast-pc", recSize: PC_REC_SIZE,
               snapshotInterval: STATE.snapshotInterval });
        arm();
        const tryHook = () => {
            if (STATE.fnHooked) return true;
            if (!STATE.target) return false;
            const fp = STATE.target.base.add(STATE.fnOffset);
            log(`[*] 直接 hook 偏移 0x${STATE.fnOffset.toString(16)}`);
            hookFn(fp);
            return true;
        };
        if (!tryHook()) {
            const id = setInterval(() => { if (tryHook()) clearInterval(id); }, 50);
        }
        return "armed";
    },
    forceFlush() { flushPC("force"); flushSnap("force"); return "ok"; },
    stats() {
        return {
            target: STATE.target ? STATE.target.name : null,
            pcs: STATE.totalPCs,
            snaps: STATE.totalSnaps,
            callouts: STATE.callouts,
            primaryTid: STATE.primaryTid,
            capped: STATE.capped,
        };
    }
};
