// 极速 FULL trace agent — 用 Frida CModule 在 C 里 memcpy CpuContext.
//
// 原 JS callout 每条指令做 33 次 ctx.x{0..30} 属性访问 = ~30µs/insn (30K rec/s).
// CModule callout 直接 memcpy 256 字节 = ~1µs/insn 预期 (理论 ~1M rec/s).
//
// Record 格式仍是 272 B (PC + X0..X30 + SP + nzcv + inst), 完全兼容现有 viewer.
// 无上限 (除非 maxRecords > 0 显式指定).

const REC_SIZE = 272;
const RING_RECS = 16384;          // ring = 4.4 MB (保守, 防 OOM)
const RING_BYTES = REC_SIZE * RING_RECS;
const FLUSH_INTERVAL_MS = 50;     // 频繁 flush 减小峰值占用

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
    soPattern: null, fnOffset: 0x57770, cmdArg: 2, cmdValue: 0,
    methodName: "doCommandNative",
    maxRecords: 0,                  // 0 = 无上限
    target: null, fnHooked: false, excluded: false,

    cmodule: null, calloutPtr: null,
    ring: null, ringHead: null, ringTotal: null, ringDropped: null,
    flushTimer: null, batchSeq: 0,
    started: 0, primaryTid: 0, callIdx: 0, capped: false,
};

function log(...a) { send({ type: "log", msg: a.map(String).join(" ") }); }

function moduleByPattern(pat) {
    for (const m of Process.enumerateModules())
        if (m.name.indexOf(pat) !== -1) return m;
    return null;
}

// ---------- CModule: 每条 insn 的极速 record ----------
//
// GumCpuContext (ARM64) 布局 (frida-gum/arch-arm64/gumcpucontext.h):
//   guint64 pc          @ 0
//   guint64 sp          @ 8
//   guint64 nzcv        @ 16
//   guint64 x[29]       @ 24   // x0..x28
//   guint64 fp          @ 24+29*8 = 256   // x29
//   guint64 lr          @ 264             // x30
//   GumArm64VectorReg v[32]               // 不要
//
// 我们的 record 格式 (272 字节):
//   u64 pc              @ 0
//   u64 x[31]           @ 8   // x0..x28, fp=x29, lr=x30
//   u64 sp              @ 256
//   u32 nzcv            @ 264
//   u32 inst            @ 268
//
// 重排 + 取 4 字节 inst.
function buildCModule() {
    // 全部用指针传入避免 CModule 的标量 vs 指针歧义
    const cm = new CModule(`
#include <string.h>

typedef struct {
    unsigned long long pc;
    unsigned long long sp;
    unsigned long long nzcv;
    unsigned long long x[29];   // x0..x28
    unsigned long long fp;       // x29
    unsigned long long lr;       // x30
    // SIMD 等忽略
} CpuCtx;

#define REC 272
extern unsigned char *ring;
extern unsigned long long *ring_size_p;
extern unsigned long long *head;
extern unsigned long long *total_written;
extern unsigned long long *dropped;
extern unsigned long long *max_records_p;

void on_insn(CpuCtx *ctx, void *user_data) {
    unsigned long long max_r = *max_records_p;
    if (max_r != 0 && *total_written >= max_r) {
        (*dropped)++;
        return;
    }
    unsigned long long h = *head;
    unsigned long long sz = *ring_size_p;
    if (h + REC > sz) {
        (*dropped)++;
        return;
    }
    unsigned char *p = ring + h;
    *(unsigned long long *)(p + 0) = ctx->pc;
    memcpy(p + 8, ctx->x, 29 * 8);
    *(unsigned long long *)(p + 8 + 29*8) = ctx->fp;
    *(unsigned long long *)(p + 8 + 30*8) = ctx->lr;
    *(unsigned long long *)(p + 256) = ctx->sp;
    *(unsigned int *)(p + 264) = (unsigned int)(ctx->nzcv & 0xffffffff);
    *(unsigned int *)(p + 268) = *(unsigned int *)(unsigned long long)ctx->pc;
    *head = h + REC;
    (*total_written)++;
}
`, {
        ring: STATE.ring,
        ring_size_p: STATE.ringSizePtr,
        head: STATE.ringHead,
        total_written: STATE.ringTotal,
        dropped: STATE.ringDropped,
        max_records_p: STATE.maxRecordsPtr,
    });
    STATE.cmodule = cm;
    STATE.calloutPtr = cm.on_insn;
    log(`[+] CModule loaded, on_insn @ ${cm.on_insn}`);
}

function flushRing(reason) {
    const head = STATE.ringHead.readU64().toNumber();
    if (head === 0) return;
    const blob = STATE.ring.readByteArray(head);
    const total = STATE.ringTotal.readU64().toNumber();
    const dropped = STATE.ringDropped.readU64().toNumber();
    send({ type: "frames", seq: STATE.batchSeq++, recs: head / REC_SIZE,
           bytes: head, total, dropped, reason }, blob);
    // reset head (但 total / dropped 是累加的)
    STATE.ringHead.writeU64(0);
}

function ensureFlushTimer() {
    if (STATE.flushTimer) return;
    STATE.flushTimer = setInterval(() => {
        const head = STATE.ringHead.readU64().toNumber();
        if (head > 0) flushRing("interval");
    }, FLUSH_INTERVAL_MS);
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

// 双路 callout: native CModule (默认) + JS-fallback 用来诊断 Stalker.follow 工作不
let JS_CALLOUT_COUNT = 0;
function _diagCallout(_ctx) { JS_CALLOUT_COUNT++; }

function followFast(tid) {
    ensureFlushTimer();
    applyExcludesOnce();
    const tBase = STATE.target.base, tEnd = STATE.target.end;
    const calloutPtr = STATE.calloutPtr;
    const useJS = !!STATE.useJSCallout;
    Stalker.follow(tid, {
        events: { call:false, ret:false, exec:false, block:false, compile:false },
        transform(iter) {
            let ins;
            while ((ins = iter.next()) !== null) {
                const inRange = ins.address.compare(tBase) >= 0 && ins.address.compare(tEnd) < 0;
                if (inRange) iter.putCallout(useJS ? _diagCallout : calloutPtr);
                iter.keep();
            }
        }
    });
    log(`[+] Stalker.follow tid=${tid} (${useJS ? "JS-diag" : "CModule"})`);
    send({ type: "follow", tid, label: "primary" });
}

function hookFn(fp) {
    if (STATE.fnHooked) return;
    STATE.fnHooked = true;
    log(`[+] hook ${STATE.methodName} @ ${fp}` + (STATE.cmdValue ? ` filter cmd==${STATE.cmdValue}` : ""));
    Interceptor.attach(fp, {
        onEnter(args) {
            if (STATE.cmdValue) {
                const cmd = args[STATE.cmdArg].toInt32();
                if (cmd !== STATE.cmdValue) { this._skip = true; return; }
            }
            // 只 follow 第一次 call (并发 Stalker.follow 会让 agent 崩)
            if (STATE.fnEntered) { this._skip = true; return; }
            STATE.fnEntered = true;
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
            flushRing("end");
            const elapsed = Date.now() - STATE.started;
            const total = STATE.ringTotal.readU64().toNumber();
            const dropped = STATE.ringDropped.readU64().toNumber();
            const jshits = JS_CALLOUT_COUNT;
            const rate = (total / Math.max(elapsed/1000, 1e-3)).toFixed(0);
            log(`[<] call #${STATE.callIdx} ret=${retv} cmodule_recs=${total} jsHits=${jshits} dropped=${dropped} ms=${elapsed} (${rate} rec/s)`);
            send({ type: "trace-end", tid: this._tid, retval: retv.toString(),
                   ms: elapsed, total, dropped, jsHits: jshits });
            STATE.fnEntered = false;   // 允许下次再 trace
        }
    });
}

function arm() {
    if (STATE.target) return true;
    const m = moduleByPattern(STATE.soPattern);
    if (!m) return false;
    STATE.target = { name: m.name, base: m.base, end: m.base.add(m.size), size: m.size };
    log(`[+] target ${m.name} @ ${m.base}`);
    send({ type: "module", name: m.name, base: m.base.toString(), size: m.size, pid: Process.id });
    return true;
}

rpc.exports = {
    init(opts) {
        opts = opts || {};
        STATE.soPattern = opts.soPattern || "libsgmainso";
        STATE.fnOffset = opts.fnOffset !== undefined ? opts.fnOffset : 0x57770;
        STATE.cmdValue = opts.cmdValue !== undefined ? opts.cmdValue : 0;
        STATE.cmdArg = opts.cmdArg !== undefined ? opts.cmdArg : 2;
        STATE.maxRecords = opts.maxRecords || 0;     // 0 = 无上限
        STATE.useJSCallout = !!opts.useJSCallout;    // 诊断用

        // 分配 ring + 元数据指针
        STATE.ring = Memory.alloc(RING_BYTES);
        STATE.ringHead = Memory.alloc(8); STATE.ringHead.writeU64(0);
        STATE.ringTotal = Memory.alloc(8); STATE.ringTotal.writeU64(0);
        STATE.ringDropped = Memory.alloc(8); STATE.ringDropped.writeU64(0);
        STATE.ringSizePtr = Memory.alloc(8); STATE.ringSizePtr.writeU64(RING_BYTES);
        STATE.maxRecordsPtr = Memory.alloc(8); STATE.maxRecordsPtr.writeU64(STATE.maxRecords);

        log(`[*] fast-full agent up | maxRecords=${STATE.maxRecords || '∞'} ring=${RING_BYTES/1024/1024}MB`);
        send({ type: "hello", pid: Process.id, frida: Frida.version,
               mode: "cmodule-fast-full", recSize: REC_SIZE,
               maxRecords: STATE.maxRecords, ringMB: RING_BYTES/1024/1024 });
        try {
            buildCModule();
        } catch (e) {
            log(`[!!] CModule 编译失败: ${e}`);
            send({ type: "log", msg: "CModule failed: " + e });
            return "no-cmodule";
        }
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
    forceFlush() { flushRing("force"); return "ok"; },
    stats() {
        return {
            target: STATE.target ? STATE.target.name : null,
            total: STATE.ringTotal.readU64().toNumber(),
            ringHead: STATE.ringHead.readU64().toNumber(),
            dropped: STATE.ringDropped.readU64().toNumber(),
            jsCalloutHits: JS_CALLOUT_COUNT,
            primaryTid: STATE.primaryTid,
            callIdx: STATE.callIdx,
            useJS: STATE.useJSCallout,
        };
    }
};
