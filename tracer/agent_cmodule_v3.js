// CModule full-trace agent v3 — JS transform + C on_insn callout (hybrid).
// 历史: 纯 C transform 在 TB 真机上 4675 条后 stalker 卡死.
// 改用 JS transform (filter in_range), 但 callout 用 CModule on_insn (零 JS 抖动 hot path).
const STATE = {
    soPattern: "libsgmainso", fnOffset: 0x57770,
    cmdValue: 0, cmdArg: 2,
    target: null, fnHooked: false, excluded: false, fnEntered: false,
    cm: null, onInsnPtr: null,
    ringBuf: null, headBuf: null, totalBuf: null, droppedBuf: null,
    ringSizeBuf: null,
    flushTimer: null, hbTimer: null, batchSeq: 0, started: 0, callIdx: 0, primaryTid: 0,
};
const REC_SIZE = 272;
const RING_RECS = 16384;
const RING_BYTES = REC_SIZE * RING_RECS;
const FLUSH_INTERVAL_MS = 50;

const EXCL = ["libc.so","libm.so","libdl.so","libart.so","libartbase.so",
              "libartpalette.so","libnativehelper.so","libnativeloader.so",
              "linker","linker64","libbase.so","libcutils.so","liblog.so",
              "libutils.so","libstdc++.so","libc++.so","libnetd_client.so",
              "libssl.so","libcrypto.so","libsync.so","libui.so","libgui.so",
              "libbinder.so","libbinder_ndk.so","libhwbinder.so",
              "libopenjdk.so","libjavacore.so","libGLESv2.so","libEGL.so"];

function log(...a) { send({ type: "log", msg: a.map(String).join(" ") }); }

function buildCModule() {
    // 仅 callout 一个: on_insn. transform 留给 JS.
    const src = `
#include <gum/gumstalker.h>
#include <string.h>
#define REC 272

extern unsigned char ring[];
extern unsigned long long ring_size;
extern unsigned long long head;
extern unsigned long long total_written;
extern unsigned long long dropped;

void on_insn(GumCpuContext *ctx, void *user_data) {
    if (head + REC > ring_size) { dropped++; return; }
    unsigned char *p = ring + head;
    unsigned long long *cu = (unsigned long long *)ctx;
    *(unsigned long long *)(p + 0) = cu[0];          // pc
    memcpy(p + 8, &cu[3], 29 * 8);                    // x0..x28
    *(unsigned long long *)(p + 8 + 29*8) = cu[3+29]; // fp
    *(unsigned long long *)(p + 8 + 30*8) = cu[3+30]; // lr
    *(unsigned long long *)(p + 256) = cu[1];         // sp
    *(unsigned int *)(p + 264) = (unsigned int)(cu[2] & 0xffffffffULL);
    *(unsigned int *)(p + 268) = 0;
    head += REC;
    total_written++;
}
`;
    STATE.cm = new CModule(src, {
        ring: STATE.ringBuf,
        ring_size: STATE.ringSizeBuf,
        head: STATE.headBuf,
        total_written: STATE.totalBuf,
        dropped: STATE.droppedBuf,
    });
    STATE.onInsnPtr = STATE.cm.on_insn;
    log(`[+] CModule loaded: on_insn @ ${STATE.cm.on_insn}`);
}

function flushRing(reason) {
    const head = STATE.headBuf.readU64().toNumber();
    if (head === 0) return;
    const blob = STATE.ringBuf.readByteArray(head);
    const total = STATE.totalBuf.readU64().toNumber();
    const dropped = STATE.droppedBuf.readU64().toNumber();
    send({ type: "frames", seq: STATE.batchSeq++, recs: head / REC_SIZE,
           bytes: head, total, dropped, reason }, blob);
    STATE.headBuf.writeU64(0);
}

function ensureFlushTimer() {
    if (STATE.flushTimer) return;
    STATE.flushTimer = setInterval(() => {
        if (STATE.headBuf.readU64().toNumber() > 0) flushRing("interval");
    }, FLUSH_INTERVAL_MS);
    if (!STATE.hbTimer) {
        STATE.hbTimer = setInterval(() => {
            send({type:"hb",
                  head:   STATE.headBuf.readU64().toNumber(),
                  total:  STATE.totalBuf.readU64().toNumber(),
                  dropped:STATE.droppedBuf.readU64().toNumber(),
                  fnEntered: STATE.fnEntered});
        }, 1000);
    }
}

function applyExcludesOnce() {
    if (STATE.excluded) return;
    let n = 0;
    for (const m of Process.enumerateModules())
        for (const pat of EXCL) if (m.name.indexOf(pat) !== -1) {
            try { Stalker.exclude({base:m.base, size:m.size}); n++; break; } catch(_){}
        }
    log(`[+] Stalker.exclude ${n} 个 system 模块`);
    STATE.excluded = true;
}

rpc.exports = {
    init(opts) {
        opts = opts || {};
        STATE.soPattern = opts.soPattern || "libsgmainso";
        STATE.fnOffset = opts.fnOffset !== undefined ? opts.fnOffset : 0x57770;
        STATE.cmdValue = opts.cmdValue || 0;
        STATE.cmdArg = opts.cmdArg !== undefined ? opts.cmdArg : 2;

        STATE.ringBuf  = Memory.alloc(RING_BYTES);
        STATE.headBuf  = Memory.alloc(8);  STATE.headBuf.writeU64(0);
        STATE.totalBuf = Memory.alloc(8);  STATE.totalBuf.writeU64(0);
        STATE.droppedBuf = Memory.alloc(8); STATE.droppedBuf.writeU64(0);
        STATE.ringSizeBuf = Memory.alloc(8); STATE.ringSizeBuf.writeU64(RING_BYTES);

        log(`[*] cmodule-v3 hybrid agent up, ring=${RING_BYTES/1024/1024}MB`);
        send({ type: "hello", pid: Process.id, frida: Frida.version, mode: "cmodule-v3-hybrid" });

        try { buildCModule(); }
        catch (e) { log(`[!!] CModule 编译失败: ${e}`); return "no-cmodule"; }

        const m = Process.enumerateModules().find(x => x.name.indexOf(STATE.soPattern) !== -1);
        if (!m) { log("[!] no SO"); return "no-so"; }
        STATE.target = { name: m.name, base: m.base, end: m.base.add(m.size) };
        log(`[+] target ${m.name} base=${m.base} end=${m.base.add(m.size)}`);
        send({ type: "module", name: m.name, base: m.base.toString(), size: m.size, pid: Process.id });

        const fp = m.base.add(STATE.fnOffset);
        const tBase = STATE.target.base, tEnd = STATE.target.end;
        const onInsn = STATE.onInsnPtr;

        Interceptor.attach(fp, {
            onEnter(args) {
                if (STATE.cmdValue) {
                    const c = args[STATE.cmdArg].toInt32();
                    if (c !== STATE.cmdValue) { this._skip = true; return; }
                }
                if (STATE.fnEntered) { this._skip = true; return; }
                STATE.fnEntered = true;
                this._tid = this.threadId;
                STATE.callIdx++;
                STATE.primaryTid = this._tid;
                STATE.started = Date.now();
                log(`[>] call #${STATE.callIdx} tid=${this._tid}`);
                send({ type: "trace-begin", tid: this._tid, ts: STATE.started, call: STATE.callIdx });
                ensureFlushTimer();
                applyExcludesOnce();
                Stalker.follow(this._tid, {
                    events: { call:false, ret:false, exec:false, block:false, compile:false },
                    transform(iter) {
                        let ins;
                        while ((ins = iter.next()) !== null) {
                            const a = ins.address;
                            if (a.compare(tBase) >= 0 && a.compare(tEnd) < 0) {
                                iter.putCallout(onInsn);
                            }
                            iter.keep();
                        }
                    }
                });
                log(`[+] Stalker.follow tid=${this._tid} (JS xform + C callout)`);
                send({ type: "follow", tid: this._tid });
            },
            onLeave(retv) {
                if (this._skip) return;
                try { Stalker.unfollow(this._tid); } catch(_){}
                try { Stalker.flush(); } catch(_){}
                flushRing("end");
                const elapsed = Date.now() - STATE.started;
                const total = STATE.totalBuf.readU64().toNumber();
                const dropped = STATE.droppedBuf.readU64().toNumber();
                const rate = (total / Math.max(elapsed/1000, 1e-3)).toFixed(0);
                log(`[<] call #${STATE.callIdx} ret=${retv} recs=${total} dropped=${dropped} ms=${elapsed} (${rate} rec/s)`);
                send({ type: "trace-end", tid: this._tid, retval: retv.toString(),
                       ms: elapsed, total, dropped });
                STATE.fnEntered = false;
            }
        });
        log(`[+] hook ${STATE.soPattern}+0x${STATE.fnOffset.toString(16)} @ ${fp}`);
        return "armed";
    },
    forceFlush() { flushRing("force"); return "ok"; },
    stats() {
        return {
            target: STATE.target ? STATE.target.name : null,
            total: STATE.totalBuf.readU64().toNumber(),
            head: STATE.headBuf.readU64().toNumber(),
            dropped: STATE.droppedBuf.readU64().toNumber(),
            primaryTid: STATE.primaryTid, callIdx: STATE.callIdx,
        };
    }
};
