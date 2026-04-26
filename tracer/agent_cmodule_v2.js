// CModule trace v2 — 整个 transform 函数都在 C 里 (Frinet 同款模式).
// JS 只做 Stalker.follow({transform: cm.transform}), 不参与每条 insn 的处理.
// 预期 30K rec/s → 数百K rec/s 的加速.
const STATE = {
    soPattern: "libsgmainso", fnOffset: 0x57770,
    target: null, fnHooked: false, excluded: false, fnEntered: false,
    cm: null, calloutPtr: null, transformPtr: null,
    ring: null, ringHead: null, ringTotal: null, ringDropped: null,
    ringSizePtr: null, basePtr: null, endPtr: null,
    flushTimer: null, batchSeq: 0, started: 0, callIdx: 0, primaryTid: 0,
};
const REC_SIZE = 272;
const RING_RECS = 16384;
const RING_BYTES = REC_SIZE * RING_RECS;
const FLUSH_INTERVAL_MS = 50;

const EXCLUDE_PATTERNS = [
    "libc.so","libm.so","libdl.so","libart.so","libartbase.so",
    "libartpalette.so","libnativehelper.so","libnativeloader.so",
    "linker","linker64","libbase.so","libcutils.so","liblog.so",
    "libutils.so","libstdc++.so","libc++.so","libnetd_client.so",
    "libssl.so","libcrypto.so","libsync.so","libui.so","libgui.so",
    "libbinder.so","libbinder_ndk.so","libhwbinder.so",
    "libopenjdk.so","libjavacore.so","libGLESv2.so","libEGL.so"
];

function log(...a) { send({ type: "log", msg: a.map(String).join(" ") }); }

function buildCModule() {
    const src = `
#include <gum/gumstalker.h>
#include <gum/gummetalhash.h>
#include <string.h>

typedef struct _GumCpuContext GumCpuContext;
typedef struct _GumStalkerIterator GumStalkerIterator;
typedef struct _GumStalkerOutput GumStalkerOutput;

extern unsigned char *ring;
extern unsigned long long *ring_size_p;
extern unsigned long long *head;
extern unsigned long long *total_written;
extern unsigned long long *dropped;
extern unsigned long long *base;
extern unsigned long long *end;

#define REC 272

// per-insn record callout (called by Stalker through gum_stalker_iterator_put_callout)
void on_insn(GumCpuContext *ctx, void *user_data) {
    unsigned long long h = *head;
    unsigned long long sz = *ring_size_p;
    if (h + REC > sz) { (*dropped)++; return; }
    unsigned char *p = ring + h;
    // GumCpuContext arm64 layout (gum/arch-arm64/gumcpucontext.h):
    //   guint64 pc, sp, nzcv;
    //   guint64 x[29];
    //   guint64 fp, lr;
    //   GumArm64VectorReg v[32];
    unsigned long long *cu = (unsigned long long *)ctx;
    *(unsigned long long *)(p + 0) = cu[0];      // pc
    memcpy(p + 8, &cu[3], 29 * 8);                // x[29] starts at offset 24 = cu[3]
    *(unsigned long long *)(p + 8 + 29*8) = cu[3+29];   // fp
    *(unsigned long long *)(p + 8 + 30*8) = cu[3+30];   // lr
    *(unsigned long long *)(p + 256) = cu[1];    // sp
    *(unsigned int *)(p + 264) = (unsigned int)(cu[2] & 0xffffffffULL);  // nzcv
    *(unsigned int *)(p + 268) = *(unsigned int *)(unsigned long long)cu[0];  // raw inst
    *head = h + REC;
    (*total_written)++;
}

// transform: called by Stalker per basic block at JIT time
void transform(GumStalkerIterator *iterator, GumStalkerOutput *output,
               void *user_data) {
    typedef struct cs_insn cs_insn;
    cs_insn *insn;
    unsigned long long b = *base, e = *end;
    while (gum_stalker_iterator_next(iterator, &insn)) {
        // insn->address is at offset 8 of cs_insn (after id at offset 0, address at 8)
        // actually cs_insn struct layout: { unsigned int id; uint64_t address; ... }
        // id is 4 bytes, then 4 bytes padding, then address (8 bytes) at offset 8
        unsigned long long addr = *(unsigned long long *)((unsigned char *)insn + 8);
        if (addr >= b && addr < e) {
            gum_stalker_iterator_put_callout(iterator, on_insn, 0, 0);
        }
        gum_stalker_iterator_keep(iterator);
    }
}
`;
    STATE.cm = new CModule(src, {
        ring: STATE.ring,
        ring_size_p: STATE.ringSizePtr,
        head: STATE.ringHead,
        total_written: STATE.ringTotal,
        dropped: STATE.ringDropped,
        base: STATE.basePtr,
        end: STATE.endPtr,
    });
    STATE.transformPtr = STATE.cm.transform;
    log(`[+] CModule loaded: transform @ ${STATE.cm.transform}, on_insn @ ${STATE.cm.on_insn}`);
}

function flushRing(reason) {
    const head = STATE.ringHead.readU64().toNumber();
    if (head === 0) return;
    const blob = STATE.ring.readByteArray(head);
    const total = STATE.ringTotal.readU64().toNumber();
    const dropped = STATE.ringDropped.readU64().toNumber();
    send({ type: "frames", seq: STATE.batchSeq++, recs: head / REC_SIZE,
           bytes: head, total, dropped, reason }, blob);
    STATE.ringHead.writeU64(0);
}

function ensureFlushTimer() {
    if (STATE.flushTimer) return;
    STATE.flushTimer = setInterval(() => {
        if (STATE.ringHead.readU64().toNumber() > 0) flushRing("interval");
    }, FLUSH_INTERVAL_MS);
}

function applyExcludesOnce() {
    if (STATE.excluded) return;
    let n = 0;
    for (const m of Process.enumerateModules())
        for (const pat of EXCLUDE_PATTERNS) if (m.name.indexOf(pat) !== -1) {
            try { Stalker.exclude({base:m.base, size:m.size}); n++; break; } catch(_){}
        }
    log(`[+] Stalker.exclude ${n} 个 system 模块`);
    STATE.excluded = true;
}

function followNative(tid) {
    ensureFlushTimer();
    applyExcludesOnce();
    Stalker.follow(tid, {
        events: { call:false, ret:false, exec:false, block:false, compile:false },
        transform: STATE.transformPtr,
    });
    log(`[+] Stalker.follow tid=${tid} (native C transform)`);
    send({ type: "follow", tid });
}

rpc.exports = {
    init(opts) {
        opts = opts || {};
        STATE.soPattern = opts.soPattern || "libsgmainso";
        STATE.fnOffset = opts.fnOffset !== undefined ? opts.fnOffset : 0x57770;
        STATE.cmdValue = opts.cmdValue || 0;
        STATE.cmdArg = opts.cmdArg !== undefined ? opts.cmdArg : 2;

        STATE.ring = Memory.alloc(RING_BYTES);
        STATE.ringHead = Memory.alloc(8); STATE.ringHead.writeU64(0);
        STATE.ringTotal = Memory.alloc(8); STATE.ringTotal.writeU64(0);
        STATE.ringDropped = Memory.alloc(8); STATE.ringDropped.writeU64(0);
        STATE.ringSizePtr = Memory.alloc(8); STATE.ringSizePtr.writeU64(RING_BYTES);
        STATE.basePtr = Memory.alloc(8); STATE.basePtr.writeU64(0);
        STATE.endPtr = Memory.alloc(8); STATE.endPtr.writeU64(0);

        log(`[*] cmodule-v2 agent up (native C transform), ring=${RING_BYTES/1024/1024}MB`);
        send({ type: "hello", pid: Process.id, frida: Frida.version });
        try { buildCModule(); }
        catch (e) { log(`[!!] CModule 编译失败: ${e}`); return "no-cmodule"; }

        // 找 SO + 设置 base/end
        const m = Process.enumerateModules().find(x => x.name.indexOf(STATE.soPattern) !== -1);
        if (!m) { log("[!] no SO"); return "no-so"; }
        STATE.target = { name: m.name, base: m.base, end: m.base.add(m.size) };
        STATE.basePtr.writePointer(m.base);
        STATE.endPtr.writePointer(m.base.add(m.size));
        log(`[+] ${m.name} @ ${m.base} ~ ${m.base.add(m.size)}`);
        send({ type: "module", name: m.name, base: m.base.toString(), size: m.size, pid: Process.id });

        // hook function
        const fp = m.base.add(STATE.fnOffset);
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
                followNative(this._tid);
            },
            onLeave(retv) {
                if (this._skip) return;
                try { Stalker.unfollow(this._tid); } catch(_){}
                try { Stalker.flush(); } catch(_){}
                flushRing("end");
                const elapsed = Date.now() - STATE.started;
                const total = STATE.ringTotal.readU64().toNumber();
                const dropped = STATE.ringDropped.readU64().toNumber();
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
            total: STATE.ringTotal.readU64().toNumber(),
            ringHead: STATE.ringHead.readU64().toNumber(),
            dropped: STATE.ringDropped.readU64().toNumber(),
            primaryTid: STATE.primaryTid, callIdx: STATE.callIdx,
        };
    }
};
