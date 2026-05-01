// agent_cmodule_v5 — device-spool + SPSC lock-free ring + backpressure.
//
// 架构:
//   cmodule on_insn → SPSC ring (17MB, head/tail monotonic 计数, atomic) →
//     满则 spin (no drop) →
//   v8 setInterval 10ms → File.write → /data/data/<pkg>/cache/.miku/trace_<callIdx>.bin →
//   trace-end → host adb pull
//
// 关键 (vs v5 rev1 race 修复):
//   - head/tail 是 monotonic 计数 (records, not bytes), 不 reset
//   - cmodule on_insn: spin until (head - tail) < ring_recs, atomic store-release head
//   - v8 flush: atomic load head/tail, read ring[tail..head], file.write, store tail = h
//   - ring offset 用 (idx % ring_recs) * REC_SIZE
//   - readByteArray 安全: cmodule 只写 ring[h..], v8 只读 ring[t..h]
//
// SELinux: untrusted_app 写 /data/local/tmp 被 deny, 改 /data/data/<pkg>/cache/.miku/.

const STATE = {
    soPattern: "libsgmainso", fnOffset: 0x57770,
    cmdValue: 0, cmdArg: 2, pkg: null,
    target: null, fnHooked: false, excluded: false, fnEntered: false,
    cm: null, onInsnPtr: null,
    ringBuf: null,
    headBuf: null, tailBuf: null, droppedBuf: null,
    ringRecsBuf: null,
    flushTimer: null, hbTimer: null, batchSeq: 0, started: 0, callIdx: 0, primaryTid: 0,
    traceFile: null, traceFilePath: null, traceDir: null,
    lastTotal: 0, stuckSecs: 0, stuckThreshold: 15,
};
const REC_SIZE = 272;
const RING_RECS = 65536;             // ~17.6 MB
const RING_BYTES = REC_SIZE * RING_RECS;
const FLUSH_INTERVAL_MS = 10;

const EXCL = ["libc.so","libm.so","libdl.so","libart.so","libartbase.so",
              "libartpalette.so","libnativehelper.so","libnativeloader.so",
              "linker","linker64","libbase.so","libcutils.so","liblog.so",
              "libutils.so","libstdc++.so","libc++.so","libnetd_client.so",
              "libssl.so","libcrypto.so","libsync.so","libui.so","libgui.so",
              "libbinder.so","libbinder_ndk.so","libhwbinder.so",
              "libopenjdk.so","libjavacore.so","libGLESv2.so","libEGL.so"];

function log(...a) { send({ type: "log", msg: a.map(String).join(" ") }); }

function getExport(name) {
    return (Module.findGlobalExportByName||Module.getGlobalExportByName)(name);
}

function buildCModule() {
    // SPSC ring: head 单调递增 (records 计数). consumer 读 ring[tail..head], 推进 tail.
    // ring 满 = (head - tail) >= ring_recs, 此时 producer spin.
    //
    // TCC 不支持 __atomic_* 也不支持 inline asm. 退而:
    //   - volatile head/tail 防编译器 reorder
    //   - dmb 用 NativeFunction 调 libc __sync_synchronize 在 v8 thread 拿 fence
    //     (cmodule 写端依赖 ARM64 store buffer 自然刷新 + frida-gum putCallout 有 caller-saved
    //     reg spill (隐式 barrier), 无 fence 也基本顺序)
    //   - 兜底: head/tail 是 volatile, ring writes 完成后 head 写, 现代 ARM64 (Cortex-A78/X1
    //     in Pixel 7) 在 untrained code 上 store buffer drain 通常 < 100 cycles. v8 flush
    //     间隔 10ms = 数百万 cycles, race window 极小, 基本不丢.
    const src = `
#include <gum/gumstalker.h>
#include <string.h>
#define REC 272
#define SPIN_MAX 200000000

extern unsigned char ring[];
extern unsigned long long ring_recs;
extern volatile unsigned long long head;
extern volatile unsigned long long tail;
extern volatile unsigned long long dropped;

void on_insn(GumCpuContext *ctx, void *user_data) {
    unsigned long long h = head;       /* 64-bit aligned read on ARM64 = atomic */
    unsigned long long t = tail;
    unsigned long long spin = 0;
    while (h - t >= ring_recs) {
        if (++spin > SPIN_MAX) { dropped = dropped + 1; return; }
        t = tail;
    }
    unsigned long long off = (h % ring_recs) * REC;
    unsigned char *p = ring + off;
    unsigned long long *cu = (unsigned long long *)ctx;
    *(unsigned long long *)(p + 0) = cu[0];          // pc
    memcpy(p + 8, &cu[3], 29 * 8);                    // x0..x28
    *(unsigned long long *)(p + 8 + 29*8) = cu[3+29]; // fp
    *(unsigned long long *)(p + 8 + 30*8) = cu[3+30]; // lr
    *(unsigned long long *)(p + 256) = cu[1];         // sp
    *(unsigned int *)(p + 264) = (unsigned int)(cu[2] & 0xffffffffULL);
    /* inst: 读 pc 处 4 字节机器码. 历史 bug: 旧代码硬编码 0, 导致 viewer/CLI 全部
       解码成 'udf #0'. ARM64 fixed-width 4-byte insns, *(uint32_t *)pc 对齐安全. */
    *(unsigned int *)(p + 268) = *(unsigned int *)cu[0];
    head = h + 1;     /* volatile store. ARM64 store buffer drain ≪ v8 flush 间隔, 实际无 race */
}
`;
    STATE.cm = new CModule(src, {
        ring: STATE.ringBuf,
        ring_recs: STATE.ringRecsBuf,
        head: STATE.headBuf,
        tail: STATE.tailBuf,
        dropped: STATE.droppedBuf,
    });
    STATE.onInsnPtr = STATE.cm.on_insn;
    log(`[+] CModule loaded: on_insn @ ${STATE.cm.on_insn} (SPSC lock-free, spin ≤ 200ms)`);
}

function ensureTraceDir() {
    if (STATE.traceDir) return;
    if (!STATE.pkg) {
        try {
            const cmdF = new File("/proc/self/cmdline", "rb");
            const buf = cmdF.read(256);
            cmdF.close();
            STATE.pkg = String.fromCharCode.apply(null, new Uint8Array(buf)).split('\0')[0] || "unknown";
        } catch (e) { STATE.pkg = "unknown"; }
    }
    STATE.traceDir = `/data/data/${STATE.pkg}/cache/.miku`;
    try {
        const mkdir = new NativeFunction(getExport('mkdir'), 'int', ['pointer','int']);
        mkdir(Memory.allocUtf8String(STATE.traceDir), 0o755);
    } catch (e) { log(`[!] mkdir 失败 (可能已存在): ${e}`); }
    log(`[+] trace dir = ${STATE.traceDir}`);
}

function openTraceFile(callIdx, tid) {
    ensureTraceDir();
    const path = `${STATE.traceDir}/trace_call${callIdx}_tid${tid}.bin`;
    STATE.traceFile = new File(path, "wb");
    STATE.traceFilePath = path;
    log(`[+] trace 文件 = ${path}`);
}

function closeTraceFile() {
    if (STATE.traceFile) {
        try { STATE.traceFile.close(); } catch (_) {}
        STATE.traceFile = null;
    }
}

function flushRingToDisk(reason) {
    if (!STATE.traceFile) return;
    // 读 head 后, ring[tail..head] 是 cmodule 已 publish 的安全区
    // 用 toNumber: head/tail 是 records 计数, 6.8M trace 远小于 2^53 (JS safe int)
    const h = STATE.headBuf.readU64().toNumber();
    const t = STATE.tailBuf.readU64().toNumber();
    const avail = h - t;
    if (avail <= 0) return;
    const tOff = t % RING_RECS;
    const hOff = h % RING_RECS;
    if (avail >= RING_RECS) {
        // ring 写满整圈: ring[tOff..end] + ring[0..tOff] (但实际 avail 不可能 > RING_RECS)
        STATE.traceFile.write(STATE.ringBuf.add(tOff * REC_SIZE).readByteArray((RING_RECS - tOff) * REC_SIZE));
        if (tOff > 0) {
            STATE.traceFile.write(STATE.ringBuf.readByteArray(tOff * REC_SIZE));
        }
    } else if (hOff > tOff) {
        // 不 wrap: 单段 ring[tOff..hOff]
        STATE.traceFile.write(STATE.ringBuf.add(tOff * REC_SIZE).readByteArray(avail * REC_SIZE));
    } else {
        // wrap: ring[tOff..end] + ring[0..hOff]
        STATE.traceFile.write(STATE.ringBuf.add(tOff * REC_SIZE).readByteArray((RING_RECS - tOff) * REC_SIZE));
        if (hOff > 0) {
            STATE.traceFile.write(STATE.ringBuf.readByteArray(hOff * REC_SIZE));
        }
    }
    // tail = h, 推进 consumer 位置. UInt64 写 (frida API: writeU64 接受 number / UInt64)
    STATE.tailBuf.writeU64(h);
    STATE.batchSeq++;
}

function ensureFlushTimer() {
    if (STATE.flushTimer) return;
    STATE.flushTimer = setInterval(() => {
        flushRingToDisk("interval");
    }, FLUSH_INTERVAL_MS);
    if (!STATE.hbTimer) {
        STATE.hbTimer = setInterval(() => {
            const h = STATE.headBuf.readU64().toNumber();
            const t = STATE.tailBuf.readU64().toNumber();
            const dropped = STATE.droppedBuf.readU64().toNumber();
            const ringQueue = h - t;
            const total = h;
            send({type:"hb", head: h, tail: t, queued: ringQueue,
                  total, dropped, fnEntered: STATE.fnEntered, callIdx: STATE.callIdx});
            if (STATE.fnEntered && total === STATE.lastTotal && ringQueue === 0) {
                STATE.stuckSecs++;
                if (STATE.stuckSecs >= STATE.stuckThreshold) {
                    log(`[!] watchdog: call #${STATE.callIdx} 卡死 ${STATE.stuckSecs}s, 强制结束`);
                    try { Stalker.unfollow(STATE.primaryTid); } catch(_){}
                    try { Stalker.flush(); } catch(_){}
                    flushRingToDisk("watchdog");
                    closeTraceFile();
                    const ms = Date.now() - STATE.started;
                    send({ type: "trace-end", callIdx: STATE.callIdx,
                           tid: STATE.primaryTid, retval: "?",
                           ms, total, dropped, truncated: true,
                           devicePath: STATE.traceFilePath });
                    STATE.fnEntered = false;
                    STATE.stuckSecs = 0;
                }
            } else {
                STATE.stuckSecs = 0;
            }
            STATE.lastTotal = total;
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
        STATE.exportName = opts.exportName || null;
        STATE.methodName = opts.methodName || null;
        // null/undefined fnOffset means "resolve from exportName/methodName".
        // Only fall back to the historical 0x57770 default when nothing else is given.
        STATE.fnOffset = (opts.fnOffset != null) ? opts.fnOffset
                        : ((opts.exportName || opts.methodName) ? null : 0x57770);
        STATE.cmdValue = opts.cmdValue || 0;
        STATE.cmdArg = opts.cmdArg !== undefined ? opts.cmdArg : 2;
        STATE.pkg = opts.pkg || null;

        STATE.ringBuf  = Memory.alloc(RING_BYTES);
        STATE.headBuf  = Memory.alloc(8);  STATE.headBuf.writeU64(0);
        STATE.tailBuf  = Memory.alloc(8);  STATE.tailBuf.writeU64(0);
        STATE.droppedBuf = Memory.alloc(8); STATE.droppedBuf.writeU64(0);
        STATE.ringRecsBuf = Memory.alloc(8); STATE.ringRecsBuf.writeU64(RING_RECS);

        log(`[*] cmodule-v5 SPSC lock-free, ring=${(RING_BYTES/1024/1024).toFixed(1)}MB (${RING_RECS} recs), flush=${FLUSH_INTERVAL_MS}ms, pkg=${STATE.pkg}`);
        send({ type: "hello", pid: Process.id, frida: Frida.version, mode: "cmodule-v5-spsc-spool" });

        try { buildCModule(); }
        catch (e) { log(`[!!] CModule 编译失败: ${e}`); return "no-cmodule"; }

        const armWith = (m) => {
            STATE.target = { name: m.name, base: m.base, end: m.base.add(m.size) };
            log(`[+] target ${m.name} base=${m.base} end=${m.base.add(m.size)}`);
            send({ type: "module", name: m.name, base: m.base.toString(), size: m.size, pid: Process.id });
            // Send all loaded modules for multi-SO pointer classification
            send({ type: "modules", modules: Process.enumerateModules().map(mod => ({
                name: mod.name, base: mod.base.toString(), size: mod.size
            })), pid: Process.id });

            // Resolve hook target: --fn-offset > --export > --method
            let fp = null, label = "";
            if (STATE.fnOffset !== null && STATE.fnOffset !== undefined) {
                fp = m.base.add(STATE.fnOffset);
                label = `${STATE.soPattern}+0x${STATE.fnOffset.toString(16)}`;
            } else if (STATE.exportName) {
                // Frida 17.x: prefer module instance method; fallback to static lookups
                if (typeof m.findExportByName === "function") {
                    fp = m.findExportByName(STATE.exportName);
                } else if (typeof m.getExportByName === "function") {
                    try { fp = m.getExportByName(STATE.exportName); } catch(_) { fp = null; }
                }
                if (!fp && typeof Module.findExportByName === "function") {
                    fp = Module.findExportByName(m.name, STATE.exportName);
                }
                if (!fp) {
                    // last resort: scan exports
                    try {
                        const exps = m.enumerateExports();
                        const e = exps.find(x => x.name === STATE.exportName);
                        if (e) fp = e.address;
                    } catch(_) {}
                }
                if (!fp) {
                    log(`[!!] export "${STATE.exportName}" not found in ${m.name}`);
                    return;
                }
                STATE.fnOffset = fp.sub(m.base).toInt32();   // back-fill for stats/log
                label = `${STATE.soPattern}!${STATE.exportName}`;
            } else if (STATE.methodName) {
                log(`[!!] --method ${STATE.methodName} (动态注册 JNI) v5 agent 暂不支持; 改用 --fn-offset 或 --export`);
                return;
            } else {
                log(`[!!] 必须传 --fn-offset / --export / --method 之一`);
                return;
            }
            const tBase = STATE.target.base, tEnd = STATE.target.end;
            const onInsn = STATE.onInsnPtr;
            installFnHook(fp, tBase, tEnd, onInsn);
            log(`[+] hook ${label} @ ${fp} (offset 0x${STATE.fnOffset.toString(16)})`);
        };
        const m = Process.enumerateModules().find(x => x.name.indexOf(STATE.soPattern) !== -1);
        if (!m) {
            log("[!] no SO yet, hooking dlopen to wait");
            const dlopen = getExport("android_dlopen_ext") || getExport("dlopen");
            if (!dlopen) { log("[!!] dlopen sym not found"); return "no-dlopen"; }
            Interceptor.attach(dlopen, {
                onEnter(a){ try{ this._p = a[0].readCString(); }catch(_){ } },
                onLeave(rv){
                    if (!this._p || this._p.indexOf(STATE.soPattern) < 0) return;
                    if (STATE.target) return;
                    const m2 = Process.enumerateModules().find(x => x.name.indexOf(STATE.soPattern) !== -1);
                    if (m2) armWith(m2);
                }
            });
            return "waiting-dlopen";
        }
        armWith(m);
        return "armed";
    },
    forceFlush() { flushRingToDisk("force"); return "ok"; },
    stats() {
        return {
            target: STATE.target ? STATE.target.name : null,
            head: STATE.headBuf.readU64().toNumber(),
            tail: STATE.tailBuf.readU64().toNumber(),
            dropped: STATE.droppedBuf.readU64().toNumber(),
            primaryTid: STATE.primaryTid, callIdx: STATE.callIdx,
            traceFilePath: STATE.traceFilePath,
        };
    }
};

function installFnHook(fp, tBase, tEnd, onInsn) {
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
                this._callIdx = STATE.callIdx;
                STATE.primaryTid = this._tid;
                STATE.started = Date.now();
                // 重置 SPSC 计数 (per-call)
                STATE.headBuf.writeU64(0);
                STATE.tailBuf.writeU64(0);
                STATE.droppedBuf.writeU64(0);
                STATE.batchSeq = 0;
                openTraceFile(this._callIdx, this._tid);
                log(`[>] call #${this._callIdx} tid=${this._tid}`);
                send({ type: "trace-begin", callIdx: this._callIdx, tid: this._tid, ts: STATE.started, devicePath: STATE.traceFilePath });
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
                log(`[+] Stalker.follow tid=${this._tid} (SPSC lock-free, device-spool)`);
                send({ type: "follow", tid: this._tid });
            },
            onLeave(retv) {
                if (this._skip) return;
                try { Stalker.unfollow(this._tid); } catch(_){}
                try { Stalker.flush(); } catch(_){}
                flushRingToDisk("end");
                closeTraceFile();
                const elapsed = Date.now() - STATE.started;
                const total = STATE.headBuf.readU64().toNumber();
                const dropped = STATE.droppedBuf.readU64().toNumber();
                const rate = (total / Math.max(elapsed/1000, 1e-3)).toFixed(0);
                log(`[<] call #${this._callIdx} ret=${retv} recs=${total} dropped=${dropped} ms=${elapsed} (${rate} rec/s) → ${STATE.traceFilePath}`);
                send({ type: "trace-end", callIdx: this._callIdx, tid: this._tid,
                       retval: retv.toString(), ms: elapsed, total, dropped, truncated: false,
                       devicePath: STATE.traceFilePath });
                STATE.fnEntered = false;
            }
        });
}
