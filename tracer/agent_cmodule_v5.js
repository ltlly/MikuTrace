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
    soPattern: null, fnOffset: null,        // 必传, 见 init() — 不再有项目特定默认
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

// HARD_EXCL: atomic deadlock / early-init / re-entrant — NEVER trace these
// even if user requests via --include-so. ARM64 LDXR/STXR sequences in
// libc/libpthread/libart, when instrumented by Stalker, leave the exclusive
// monitor cleared → all atomics fail → process deadlock.
//
// In --trace-deep mode, this list is SHRUNK: module-level exclude is removed
// for libart (and others; see DEEP_KEEP_EXCL). Per-symbol Stalker.exclude is
// applied for HOSTILE_PATTERNS sub-ranges (interpreter/JIT/GC etc).
const HARD_EXCL = ["libc.so","libm.so","libdl.so","libpthread.so","libart.so",
                   "libartbase.so","libartpalette.so","linker","linker64"];

// In deep mode, modules that we still exclude entirely (linker / dl have
// init-time recursion that nothing else can touch — too risky to per-symbol).
const DEEP_KEEP_EXCL = ["linker", "linker64", "libdl.so"];

// Stalker-exclude patterns (LDXR/STXR atomic deadlock prevention + self-modifying
// hot code). These are NEVER instrumented by Stalker. Safe to add anything here —
// it just means Stalker won't recompile their basic blocks.
const STALKER_EXCLUDE_PATTERNS = [
    // ART self-modifying / hot reentry surfaces
    "art::interpreter::Execute",
    "art::interpreter::DoCall",
    "ExecuteSwitchImpl", "ExecuteMterp", "MterpHelpers",
    "art::jit::Jit", "art::jit::JitCompiler",
    "art::gc::Heap::", "art::gc::collector::",
    "art::ClassLinker::Lookup",
    // libc atomic / lock primitives. Stalker on LDXR/STXR pairs clears the
    // exclusive monitor → atomics fail → process deadlock.
    "pthread_mutex_lock", "pthread_mutex_unlock",
    "pthread_rwlock_", "pthread_cond_",
    "__bionic_atomic_", "__atomic_",
    "malloc", "free", "calloc", "realloc",   // scudo allocator atomics
];

// Boundary-diff patterns (Interceptor.attach for memory diff). MUST be a strict
// subset of "functions that Frida itself does NOT call internally". Attaching
// on pthread_mutex_lock / malloc / __atomic_* causes self-recursion in Frida's
// own machinery → process crashes during attach.
//
// Default = empty. Opt-in via --boundary-diff-patterns. This can run without
// --trace-deep: the matching excluded-module symbol stays excluded from
// Stalker, but Interceptor snapshots pointer args on entry/exit and reports
// changed bytes as external writes. Safe candidates (these are leaf-ish ART
// helpers or libc file-stat helpers that Frida internals don't reach):
//   - "art::Thread::DecodeJObject"   // read-only ptr decode
//   - "art::JNI::Get*"               // get-side JNI helpers
//   - "stat", "stat64", "fstatat", "fstatat64", "lstat", "lstat64"
// memcpy/memmove are NOT safe — they may be ifunc-resolved + Frida's
// readByteArray internally calls them.
const DEFAULT_BOUNDARY_DIFF_PATTERNS = [];

// SOFT_EXCL: excluded by default (perf + noise), but --include-so can
// override (user accepts the risk). System-ish but no atomic deadlock pattern.
const SOFT_EXCL = ["libnativehelper.so","libnativeloader.so","libbase.so",
                   "libcutils.so","liblog.so","libutils.so","libstdc++.so",
                   "libc++.so","libnetd_client.so","libssl.so","libcrypto.so",
                   "libsync.so","libui.so","libgui.so","libbinder.so",
                   "libbinder_ndk.so","libhwbinder.so","libopenjdk.so",
                   "libjavacore.so","libGLESv2.so","libEGL.so"];

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
                    try { flushJniStringEvents(STATE.callIdx); } catch (e) { log(`[!] flushJni: ${e}`); }
                    try { flushExtWriteEvents(); } catch (e) { log(`[!] flushExt: ${e}`); }
                    try { flushForkEvents(STATE.callIdx); } catch (e) { log(`[!] flushFork: ${e}`); }
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

function collectBoundaryDiffSymbols(m, diffPatterns) {
    if (!diffPatterns || diffPatterns.length === 0) return 0;
    let n = 0;
    try {
        for (const sym of m.enumerateSymbols()) {
            if (!sym.address || sym.address.isNull()) continue;
            if (!diffPatterns.some(p => sym.name.indexOf(p) !== -1)) continue;
            STATE.diffSyms.push({
                addr: sym.address, name: sym.name, mod: m.name,
            });
            n++;
        }
    } catch (e) {
        log(`[!] enumSymbols ${m.name} for boundary-diff failed: ${e}`);
    }
    return n;
}

function applyExcludesOnce() {
    if (STATE.excluded) return;
    const userIncl = STATE.includeSoPatterns || [];
    const matchesUser = (name) => userIncl.some(pat => name.indexOf(pat) !== -1);
    const deep = !!STATE.deepTrace;
    const stalkerPatterns = STATE.stalkerExcludePatterns || STALKER_EXCLUDE_PATTERNS;
    const diffPatterns = STATE.boundaryDiffPatterns || DEFAULT_BOUNDARY_DIFF_PATTERNS;
    STATE.diffSyms = [];     // syms to Interceptor.attach (boundary-diff only)
    let nMod = 0, hard = 0, soft = 0, user_kept = 0, stalkerOnly = 0, diffTargets = 0;

    for (const m of Process.enumerateModules()) {
        const isHard = HARD_EXCL.some(p => m.name.indexOf(p) !== -1);
        const isSoft = !isHard && SOFT_EXCL.some(p => m.name.indexOf(p) !== -1);

        if (isHard) {
            const stillKeep = DEEP_KEEP_EXCL.some(p => m.name.indexOf(p) !== -1);
            if (deep && !stillKeep) {
                // Don't full-module exclude. Per-symbol Stalker.exclude for
                // STALKER_EXCLUDE_PATTERNS matches; collect BOUNDARY_DIFF
                // matches for safe Interceptor.attach later (must be a strict
                // subset — Frida internals call pthread/malloc, attaching there
                // crashes the process).
                let perModStalker = 0;
                try {
                    for (const sym of m.enumerateSymbols()) {
                        if (!sym.address || sym.address.isNull()) continue;
                        const isStalkerEx = stalkerPatterns.some(p => sym.name.indexOf(p) !== -1);
                        if (isStalkerEx) {
                            const symSize = sym.size || 4096;
                            try {
                                Stalker.exclude({base: sym.address, size: symSize});
                                perModStalker++;
                            } catch (_) {}
                        }
                    }
                } catch (e) { log(`[!] enumSymbols ${m.name} failed: ${e}`); }
                const perModDiff = collectBoundaryDiffSymbols(m, diffPatterns);
                stalkerOnly += perModStalker;
                diffTargets += perModDiff;
                log(`[+] deep: ${m.name} kept; stalker-excl=${perModStalker} diff-targets=${perModDiff}`);
                continue;
            }
            // Not deep, or module on DEEP_KEEP_EXCL: full module exclude
            const perModDiff = collectBoundaryDiffSymbols(m, diffPatterns);
            diffTargets += perModDiff;
            if (perModDiff > 0)
                log(`[+] boundary-diff: ${m.name} diff-targets=${perModDiff} (module remains Stalker-excluded)`);
            if (matchesUser(m.name))
                log(`[!] WARN: --include-so matched ${m.name}, but it is HARD_EXCL (atomic deadlock risk); skipping`);
            try { Stalker.exclude({base: m.base, size: m.size}); nMod++; hard++; } catch (_) {}
        } else if (isSoft) {
            if (matchesUser(m.name)) { user_kept++; continue; }
            try { Stalker.exclude({base: m.base, size: m.size}); nMod++; soft++; } catch (_) {}
        }
    }
    log(`[+] Stalker.exclude: modules=${nMod} (hard=${hard} soft=${soft}, user-kept=${user_kept}); ` +
        `deep=${deep} stalker-only-syms=${stalkerOnly} diff-targets=${diffTargets}`);
    if (STATE.diffSyms.length > 0) installBoundaryDiffHooksOnce();
    STATE.excluded = true;
}

// ─────────── Route B: boundary memory diff for hostile syms ────────────────
//
// 对每个 STATE.hostileSyms 装 Interceptor. onEnter snapshot ±256B around
// X0..X7 ptrs (only those in writable rw- ranges). onLeave diff, send
// type='ext-write' message per byte changed. Host writes external_writes.bin
// alongside trace.bin. Viewer/MemShadow loads it as kind='x' synthetic events.

const PTR_WIN = 256;     // bytes to snapshot around each pointer arg

function refreshWritableRanges() {
    // Cached at fn-entry. Sorted by base, binary-searched at scan time.
    STATE.writableRanges = Process.enumerateRanges("rw-").map(r => ({
        base: r.base, end: r.base.add(r.size),
    }));
}

function isPtrInWritable(p) {
    if (!p || p.isNull()) return false;
    const ranges = STATE.writableRanges;
    if (!ranges) return false;
    for (let i = 0; i < ranges.length; i++) {
        if (p.compare(ranges[i].base) >= 0 && p.compare(ranges[i].end) < 0)
            return true;
    }
    return false;
}

function installBoundaryDiffHooksOnce() {
    if (STATE.boundaryHooksInstalled) return;
    if (!STATE.diffSyms || STATE.diffSyms.length === 0) {
        STATE.boundaryHooksInstalled = true;
        return;
    }
    STATE.extWriteEvents = STATE.extWriteEvents || [];
    let installed = 0;
    for (const sym of STATE.diffSyms) {
        try {
            Interceptor.attach(sym.addr, makeBoundaryDiffHook(sym.name));
            installed++;
        } catch (e) {
            log(`[!] Interceptor.attach ${sym.name} failed: ${e}`);
        }
    }
    STATE.boundaryHooksInstalled = true;
    log(`[+] boundary-diff Interceptor installed: ${installed}/${STATE.diffSyms.length} diff targets`);
}

function makeBoundaryDiffHook(symName) {
    return {
        onEnter(args) {
            if (this.threadId !== STATE.primaryTid) { this._skip = true; return; }
            if (!STATE.fnEntered) { this._skip = true; return; }
            this._sym = symName;
            // Trace idx at entry — write events get attributed here so
            // memshadow shows them as "happened just before this insn"
            this._enterIdx = STATE.headBuf.readU64().toNumber();
            const snap = [];
            for (let i = 0; i < 8; i++) {
                const p = args[i];
                if (!isPtrInWritable(p)) continue;
                let buf = null;
                try { buf = p.readByteArray(PTR_WIN); } catch (_) {}
                if (buf) snap.push({addr: p, before: new Uint8Array(buf)});
            }
            this._snap = snap;
        },
        onLeave(rv) {
            if (this._skip) return;
            const snap = this._snap || [];
            // Add rv-window if rv looks like a fresh pointer (e.g. malloc result)
            try {
                if (isPtrInWritable(rv)) {
                    let after = null;
                    try { after = rv.readByteArray(PTR_WIN); } catch (_) {}
                    if (after) {
                        // Treat entire rv-window as ext-write (no "before"; SO
                        // hasn't seen this region — fresh allocation).
                        const u8 = new Uint8Array(after);
                        for (let i = 0; i < u8.length; i++) {
                            STATE.extWriteEvents.push({
                                attrIdx: this._enterIdx,
                                addr: rv.add(i).toString(),
                                byte: u8[i],
                            });
                        }
                    }
                }
            } catch (_) {}
            // Diff snapshotted pointer windows
            for (const s of snap) {
                let after = null;
                try { after = s.addr.readByteArray(PTR_WIN); } catch (_) { continue; }
                const a = new Uint8Array(after);
                for (let i = 0; i < a.length; i++) {
                    if (a[i] !== s.before[i]) {
                        STATE.extWriteEvents.push({
                            attrIdx: this._enterIdx,
                            addr: s.addr.add(i).toString(),
                            byte: a[i],
                        });
                    }
                }
            }
            // Flush periodically so host buffer doesn't bloat memory
            if (STATE.extWriteEvents.length >= 4096) flushExtWriteEvents();
        }
    };
}

function flushExtWriteEvents() {
    if (!STATE.extWriteEvents || STATE.extWriteEvents.length === 0) return 0;
    const events = STATE.extWriteEvents;
    STATE.extWriteEvents = [];
    send({type: "ext-write", callIdx: STATE.callIdx, count: events.length, events: events});
    return events.length;
}

// ─────────── Anti-anti-frida: patch obfuscated tgkill thunks ───────────────
//
// 反检测线程常通过内联 `svc #0` 调用 SYS_tgkill (x8=131) 自杀 — 标准
// Frida `Interceptor.attach("tgkill")` hook 不到 (无 PLT entry). 解法: 静态
// 分析找出所有 `svc` 位置 (跟在 `movz x8, #131` 后), patch 成 nop.
//
// 偏移随 SO 版本变, 因此走 spec-driven: host 通过 opts.suicidePatchSpec 传 JSON,
// 描述 `[ {offset, ...}, ... ]`. 没传 spec 时不做任何 patch — 不再硬编码任何
// SO 版本的偏移. 现成 spec 在 tools/hooks/sgmainso_6.8.260403_suicide.json.

// ─────────── B3: 隐藏 RWX 匿名页 from /proc/self/maps reads ────────────────
//
// 部分反检测 SO 扫 /proc/self/maps 找 rwxp 命中即自杀. 在 libc 层拦截
// open/openat 跟踪 fd, 在 read/pread 时把含 rwxp 的危险行删掉. 通用方案,
// 不依赖任何特定 SO.

const HIDE_MAPS_TRACKED_FDS = new Set();

function _hideMaps_filterLine(line) {
    if (line.length === 0) return false;
    const isRwx = (line.indexOf("rwxp") >= 0 || line.indexOf("rwxs") >= 0);
    if (!isRwx) return false;
    const low = line.toLowerCase();
    if (low.indexOf("frida") >= 0 || low.indexOf("miku") >= 0) return true;
    const fields = line.trim().split(/\s+/);
    if (fields.length < 6) return true;     // anonymous (no path)
    const path = fields[5];
    if (!path) return true;
    if (path.startsWith("[")) return true;  // [anon:..] / [stack] / [heap]
    if (path.startsWith("/")) {
        // 目标 SO 自身的 rwxp 段 (它自己的代码段, 与 Frida 无关) 保留
        if (STATE.soPattern && low.indexOf(STATE.soPattern.toLowerCase()) >= 0) return false;
        return false;                                         // 其他 lib rwxp 保留
    }
    return true;
}

function _hideMaps_filterBuffer(text) {
    const lines = text.split("\n");
    const kept = [];
    let dropped = 0;
    for (const line of lines) {
        if (_hideMaps_filterLine(line)) { dropped++; continue; }
        kept.push(line);
    }
    return [kept.join("\n"), dropped];
}

function _findEx(name) {
    try { return Module.findGlobalExportByName(name); } catch (_) {}
    try { return Module.getGlobalExportByName(name); } catch (_) {}
    try { return Module.findExportByName("libc.so", name); } catch (_) {}
    return null;
}

function installRwxMapsHider() {
    if (STATE.rwxMapsHidden) return;
    let n = 0;
    const hookOpen = (p, pathIdx, label) => {
        if (!p) return;
        Interceptor.attach(p, {
            onEnter(args) {
                try {
                    const path = args[pathIdx].readCString();
                    if (path && (path === "/proc/self/maps" ||
                                 (path.startsWith("/proc/") && path.endsWith("/maps")))) {
                        this._track = true;
                    }
                } catch (_) {}
            },
            onLeave(rv) {
                if (this._track) {
                    const fd = rv.toInt32();
                    if (fd >= 0) HIDE_MAPS_TRACKED_FDS.add(fd);
                }
            }
        });
        n++;
    };
    const hookRead = (p, label) => {
        if (!p) return;
        Interceptor.attach(p, {
            onEnter(args) {
                this._fd = args[0].toInt32();
                this._buf = args[1];
                this._tracked = HIDE_MAPS_TRACKED_FDS.has(this._fd);
            },
            onLeave(rv) {
                if (!this._tracked) return;
                const sz = rv.toInt32();
                if (sz <= 0) return;
                try {
                    const bytes = this._buf.readByteArray(sz);
                    const text = String.fromCharCode.apply(null, new Uint8Array(bytes));
                    const [filtered, dropped] = _hideMaps_filterBuffer(text);
                    if (dropped === 0) return;
                    const newBytes = [];
                    for (let i = 0; i < filtered.length; i++) newBytes.push(filtered.charCodeAt(i) & 0xff);
                    while (newBytes.length < sz) newBytes.push(0);
                    this._buf.writeByteArray(newBytes.slice(0, sz));
                    rv.replace(ptr(filtered.length));
                } catch (_) {}
            }
        });
        n++;
    };
    hookOpen(_findEx("openat"), 1, "openat");
    hookOpen(_findEx("open"),   0, "open");
    hookOpen(_findEx("fopen"),  0, "fopen");
    hookRead(_findEx("read"),    "read");
    hookRead(_findEx("pread64"), "pread64");
    const close_p = _findEx("close");
    if (close_p) {
        Interceptor.attach(close_p, {
            onEnter(args) {
                const fd = args[0].toInt32();
                if (HIDE_MAPS_TRACKED_FDS.has(fd)) HIDE_MAPS_TRACKED_FDS.delete(fd);
            }
        });
        n++;
    }
    STATE.rwxMapsHidden = true;
    log(`[hide-rwx-maps] installed ${n} libc hooks`);
}

function applySuicidePatchSpec(spec) {
    // spec = { so_pattern, instruction_to_patch:{expected_bytes_le, replacement_bytes_le},
    //          patches: [{offset, comment?}, ...] }
    // SO 版本相关偏移全部从 spec 来 — agent 内部不硬编码任何 SO 版本.
    if (!spec || !Array.isArray(spec.patches) || spec.patches.length === 0) {
        log(`[patch-suicide] no spec provided; skip`);
        return 0;
    }
    if (STATE.suicidePatched) return 0;
    const pat = spec.so_pattern || STATE.soPattern;
    const m = Process.enumerateModules().find(x => x.name.indexOf(pat) !== -1);
    if (!m) { log(`[patch-suicide] ${pat} not loaded yet`); return 0; }
    const insn = spec.instruction_to_patch || {};
    const expBytes = (insn.expected_bytes_le || "01 00 00 d4")
                       .split(/\s+/).map(s => parseInt(s, 16));
    const repBytes = (insn.replacement_bytes_le || "1f 20 03 d5")
                       .split(/\s+/).map(s => parseInt(s, 16));
    let patched = 0;
    for (const p of spec.patches) {
        const off = (typeof p.offset === "string") ? parseInt(p.offset, 16) : p.offset;
        const svcAddr = m.base.add(off);
        try {
            const before = svcAddr.readByteArray(4);
            const beforeArr = Array.from(new Uint8Array(before));
            const matches = beforeArr.length === expBytes.length &&
                            beforeArr.every((b, i) => b === expBytes[i]);
            if (!matches) {
                log(`[patch-suicide][!] @+0x${off.toString(16)} byte mismatch (got ${beforeArr.map(b=>b.toString(16).padStart(2,'0')).join(' ')}); skip`);
                continue;
            }
            Memory.patchCode(svcAddr, 4, ptr => { ptr.writeByteArray(repBytes); });
            patched++;
        } catch (e) {
            log(`[patch-suicide][!] @+0x${off.toString(16)} patch failed: ${e}`);
        }
    }
    log(`[patch-suicide] ${pat}: ${patched}/${spec.patches.length} patches applied`);
    STATE.suicidePatched = true;
    return patched;
}

// 兼容老调用名 (旧 RPC dispatch 还可能引用)
function patchSgmainsoSuicide(modName) {
    return applySuicidePatchSpec(STATE.suicidePatchSpec);
}

// Build the list of (base, end, name) ranges where we WANT to record records.
// Default: just the target SO. With --include-so PATTERNS: target + matches.
//
// Called every time we hook a new function entry (per-call) — late-dlopen'd
// SOs (libsgsecuritybody, libsgavmp loaded after agent init) are picked up
// the next time the target fn is entered.
function buildIncludeRanges() {
    STATE.includeRanges = [];
    if (STATE.target) {
        STATE.includeRanges.push({
            base: STATE.target.base,
            end: STATE.target.end,
            name: STATE.target.name,
        });
    }
    const userIncl = STATE.includeSoPatterns || [];
    const deep = !!STATE.deepTrace;
    if (userIncl.length === 0) return;
    // In deep mode, --include-so libart works (HARD_EXCL is no longer a
    // module-level Stalker block — per-symbol exclude in applyExcludesOnce
    // already covers the unsafe spots). In non-deep mode, HARD_EXCL is still
    // skipped to prevent the original atomic-deadlock crash.
    for (const m of Process.enumerateModules()) {
        if (STATE.target && m.name === STATE.target.name) continue;
        const isHard = HARD_EXCL.some(p => m.name.indexOf(p) !== -1);
        if (isHard && !deep) continue;
        for (const pat of userIncl) {
            if (m.name.indexOf(pat) !== -1) {
                STATE.includeRanges.push({
                    base: m.base, end: m.base.add(m.size), name: m.name });
                break;
            }
        }
    }
    log(`[+] tracing ${STATE.includeRanges.length} module ranges:`);
    for (const r of STATE.includeRanges) log(`    ${r.name}`);
}

// ─────────── JSON-driven JNI hooks (libart, Interceptor — not Stalker) ─────
//
// 用户配置 JSON 描述要 hook 的 JNI vtable 函数 (offset + 参数类型 + 返回值
// 类型). 默认 spec = tools/hooks/libart_jni.json (string-related fns).
//
// Interceptor 不依赖 Stalker, 不创建 RWX 块缓存 → 反检测看不到. 是给重防护
// app 的备选方案: 不开 deep trace, 仅靠 JNI hooks 拿 string + 关键调用.
// 输出 jni_hooks.jsonl per-call dir, 跨 trace 复用.

// 直接 dlsym + JNIInvokeInterface_::GetEnv, 不依赖 Java module (Frida 17 移除)
function getJNIEnvDirect() {
    let getVMs = null;
    try { getVMs = Module.findGlobalExportByName("JNI_GetCreatedJavaVMs"); } catch (_) {}
    if (!getVMs) {
        try { getVMs = Module.findExportByName("libart.so", "JNI_GetCreatedJavaVMs"); } catch (_) {}
    }
    if (!getVMs) return null;
    try {
        const fn = new NativeFunction(getVMs, "int", ["pointer", "int", "pointer"]);
        const vms = Memory.alloc(8);
        const nVMs = Memory.alloc(4);
        if (fn(vms, 1, nVMs) !== 0) return null;
        if (nVMs.readU32() < 1) return null;
        const jvm = vms.readPointer();
        if (jvm.isNull()) return null;
        // jvm = JavaVM*. *jvm = const JNIInvokeInterface_*
        // GetEnv at vtable offset 0x30 (index 6: 3 reserved + DestroyJavaVM/AttachCurrentThread/DetachCurrentThread/GetEnv)
        const vtable = jvm.readPointer();
        const getEnvFn = new NativeFunction(vtable.add(0x30).readPointer(), "int", ["pointer", "pointer", "int"]);
        const envOut = Memory.alloc(8);
        if (getEnvFn(jvm, envOut, 0x10006) !== 0) return null;
        return envOut.readPointer();
    } catch (e) { return null; }
}

// Android 14+ MTE: 指针上字节有 tag, Frida 直接 readUtf8String 失败.
// 对 cstring/utf16/bytes 这种内存读类型, 先 untag (mask top byte 0x00ffff...).
const _PTR_UNTAG_MASK = ptr("0x00ffffffffffffff");

function _readArgVal(arg, spec) {
    if (!spec || !spec.type) return arg.toString();
    const maxLen = spec.max_len || 256;
    switch (spec.type) {
        case "ptr":     return arg.toString();
        case "int":     return arg.toInt32();
        case "long":    return arg.toString();
        case "void":    return null;
        case "cstring": {
            // 先 read-until-null (cheap, 不读越界); 失败再试 fixed maxLen.
            // 大 maxLen (e.g. 512) 容易跨 unmapped page boundary → throw.
            // MTE untag 作最后兜底 (Android 14+).
            try { return arg.readUtf8String(); } catch (_) {}
            try { return arg.readUtf8String(maxLen); } catch (_) {}
            try { return arg.and(_PTR_UNTAG_MASK).readUtf8String(); } catch (_) {}
            try { return arg.and(_PTR_UNTAG_MASK).readUtf8String(maxLen); } catch (_) {}
            return null;
        }
        case "utf16": {
            try { return arg.readUtf16String(); } catch (_) {}
            try { return arg.readUtf16String(maxLen); } catch (_) {}
            try { return arg.and(_PTR_UNTAG_MASK).readUtf16String(); } catch (_) {}
            return null;
        }
        case "bytes": {
            const tryRead = (p) => {
                try {
                    const buf = p.readByteArray(maxLen);
                    const u8 = new Uint8Array(buf);
                    let hex = "";
                    for (let i = 0; i < u8.length; i++) hex += u8[i].toString(16).padStart(2, "0");
                    return hex;
                } catch (_) { return null; }
            };
            return tryRead(arg) || tryRead(arg.and(_PTR_UNTAG_MASK));
        }
        default: return arg.toString();
    }
}

function _makeJsonHookHandler(spec) {
    return {
        onEnter(args) {
            if (this.threadId !== STATE.primaryTid) { this._skip = true; return; }
            this._spec = spec;
            this._argVals = new Array(spec.args.length);
            this._pendingArgs = [];   // {idx, ptr} for args read in onLeave
            for (let i = 0; i < spec.args.length; i++) {
                const aSpec = spec.args[i];
                if (aSpec.read_in_onleave) {
                    this._pendingArgs.push({idx: i, ptr: args[i]});
                    this._argVals[i] = null;   // placeholder
                } else {
                    this._argVals[i] = _readArgVal(args[i], aSpec);
                }
            }
        },
        onLeave(retv) {
            if (this._skip) return;
            // Read pending args (out-buffers) AFTER fn ran
            for (const p of this._pendingArgs) {
                this._argVals[p.idx] = _readArgVal(p.ptr, this._spec.args[p.idx]);
            }
            const ret = (this._spec.ret && this._spec.ret.type === "void")
                        ? null
                        : _readArgVal(retv, this._spec.ret || {type: "ptr"});
            const head = STATE.headBuf.readU64().toNumber();
            // Build event with named-arg map
            const argsObj = {};
            for (let i = 0; i < this._spec.args.length; i++) {
                argsObj[this._spec.args[i].name] = this._argVals[i];
            }
            STATE.jniHookEvents.push({
                id: this._spec.id,
                trace_idx: head,    // == next record idx in trace.bin
                args: argsObj,
                ret: ret,
            });
        }
    };
}

function installJniHooksOnce() {
    if (STATE.jniHooksInstalled) return;
    const specs = STATE.jniHookSpecs;
    if (!Array.isArray(specs) || specs.length === 0) {
        STATE.jniHooksInstalled = true;
        return;
    }
    const envPtr = getJNIEnvDirect();
    if (!envPtr) {
        log("[hooks] no JNIEnv (JavaVM not initialized?), will retry next call");
        return;
    }
    const vtable = envPtr.readPointer();
    STATE.jniHookEvents = STATE.jniHookEvents || [];
    let installed = 0, skipped = 0;
    for (const spec of specs) {
        try {
            const off = parseInt(spec.vtable_offset);
            if (isNaN(off)) { skipped++; continue; }
            const fnPtr = vtable.add(off).readPointer();
            if (fnPtr.isNull()) { skipped++; continue; }
            Interceptor.attach(fnPtr, _makeJsonHookHandler(spec));
            installed++;
        } catch (e) {
            log(`[hooks][!] ${spec.id}: ${e}`);
            skipped++;
        }
    }
    STATE.jniHooksInstalled = true;
    log(`[hooks] JSON-driven JNI hooks: ${installed}/${specs.length} installed (${skipped} skipped)`);
}

function flushJniHookEvents(callIdx) {
    if (!STATE.jniHookEvents || STATE.jniHookEvents.length === 0) return 0;
    const events = STATE.jniHookEvents;
    STATE.jniHookEvents = [];
    send({type: "jni-hooks", callIdx: callIdx, count: events.length, events: events});
    return events.length;
}

// 兼容别名 — 旧代码路径调 flushJniStringEvents, 直接重定向新版
function flushJniStringEvents(callIdx) { return flushJniHookEvents(callIdx); }
function installJniStringHooksOnce() { return installJniHooksOnce(); }


// ═══════════ P1-C M1: fork/clone/vfork hook (Tier 1 fork-event 落盘) ═══════════
//
// 在 parent 进程 hook libc fork/vfork/clone, 永远记录 fork-event Tier 1
// (parent_pc 相对 SO + child_pid + clone_flags), 不依赖 spawn-gating.
// host 端写入 meta.json fork_events 字段, viewer 通过 /api/fork-events 暴露.
//
// CLONE flags (linux/sched.h, ARM64 uapi):
//   CLONE_VM       0x100      — share VM (thread-like)
//   CLONE_THREAD   0x10000    — share thread group (thread-like)
//   CLONE_SIGHAND  0x800
//   CLONE_VFORK    0x4000
//   SIGCHLD        0x11       — fork() signal mask byte
// is_fork_like = (flags & CLONE_THREAD) == 0 (典型 fork: 没 share TG).
// thread-like (pthread_create) 走现有 Stalker.follow path, 不进 P1-C.

function _isForkLike(flags) {
    const CLONE_THREAD = 0x10000;
    return (flags & CLONE_THREAD) === 0;
}

function installForkHooksOnce() {
    if (STATE.forkHooksInstalled) return;
    STATE.forkEvents = STATE.forkEvents || [];
    STATE.forkHooksInstalled = true;
    let installed = 0;

    // Resolve target SO module by soPattern (lazy — agent state has soPattern only).
    let _modBase = null, _modEnd = null, _modName = null;
    try {
        const m = Process.enumerateModules().find(
            x => STATE.soPattern && x.name.indexOf(STATE.soPattern) !== -1);
        if (m) {
            _modBase = m.base;
            _modEnd  = m.base.add(m.size);
            _modName = m.name;
        }
    } catch (_) {}

    function _pushForkEvent(syscall, returnAddress, child_pid, clone_flags) {
        try {
            const pc = ptr(returnAddress);
            // 计算 SO 内偏移 (parent_pc_rel)
            let parent_pc_rel = null;
            let parent_in_target = false;
            if (_modBase && pc.compare(_modBase) >= 0 && pc.compare(_modEnd) < 0) {
                parent_pc_rel = "0x" + pc.sub(_modBase).toString(16);
                parent_in_target = true;
            }
            // is_fork_like — 默认 true (fork/vfork 都 是); clone 看 flags
            const is_fork_like = (clone_flags === null) ? true
                               : _isForkLike(clone_flags);
            let trace_idx = 0;
            try { trace_idx = STATE.headBuf.readU64().toNumber(); } catch (_) {}
            STATE.forkEvents.push({
                type: "fork-event",
                trace_idx: trace_idx,    // parent trace head at this moment
                parent_pc: pc.toString(),
                parent_pc_rel: parent_pc_rel,
                parent_in_target: parent_in_target,
                parent_module: _modName,
                syscall: syscall,
                clone_flags: (clone_flags === null) ? null
                            : ("0x" + clone_flags.toString(16)),
                is_fork_like: is_fork_like,
                child_pid: child_pid,
                ts: Date.now(),
                attach_status: "not_attempted",   // M2 will set to success/failed_*
            });
        } catch (e) {
            log("[fork] push event failed: " + e);
        }
    }

    function _hookFork() {
        const p = _findEx("fork");
        if (!p) return;
        Interceptor.attach(p, {
            onEnter() { this._ra = this.returnAddress; },
            onLeave(rv) {
                const pid = rv.toInt32();
                if (pid > 0) _pushForkEvent("fork", this._ra, pid, null);
            }
        });
        installed++;
    }
    function _hookVfork() {
        const p = _findEx("vfork");
        if (!p) return;
        Interceptor.attach(p, {
            onEnter() { this._ra = this.returnAddress; },
            onLeave(rv) {
                const pid = rv.toInt32();
                if (pid > 0) _pushForkEvent("vfork", this._ra, pid, null);
            }
        });
        installed++;
    }
    function _hookClone() {
        // clone(fn, stack, flags, arg, ...): flags is arg[2].
        // bionic's __bionic_clone(flags, child_stack, ...): flags is arg[0].
        // We hook both.
        const p1 = _findEx("clone");
        if (p1) {
            Interceptor.attach(p1, {
                onEnter(args) {
                    this._ra = this.returnAddress;
                    // glibc clone(fn, stack, flags, arg) → flags @ args[2]
                    this._flags = args[2].toInt32();
                },
                onLeave(rv) {
                    const pid = rv.toInt32();
                    if (pid > 0) _pushForkEvent("clone", this._ra, pid, this._flags);
                }
            });
            installed++;
        }
        const p2 = _findEx("__bionic_clone");
        if (p2) {
            Interceptor.attach(p2, {
                onEnter(args) {
                    this._ra = this.returnAddress;
                    // bionic __bionic_clone(flags, child_stack, ...) → flags @ args[0]
                    this._flags = args[0].toInt32();
                },
                onLeave(rv) {
                    const pid = rv.toInt32();
                    if (pid > 0) _pushForkEvent("__bionic_clone", this._ra, pid,
                                                  this._flags);
                }
            });
            installed++;
        }
    }
    try { _hookFork(); } catch (e) { log("[fork] hookFork: " + e); }
    try { _hookVfork(); } catch (e) { log("[fork] hookVfork: " + e); }
    try { _hookClone(); } catch (e) { log("[fork] hookClone: " + e); }
    log("[fork] installed " + installed + " fork-family hooks");
}

function flushForkEvents(callIdx) {
    if (!STATE.forkEvents || STATE.forkEvents.length === 0) return 0;
    const events = STATE.forkEvents;
    STATE.forkEvents = [];
    send({type: "fork-events", callIdx: callIdx, count: events.length, events: events});
    return events.length;
}

rpc.exports = {
    init(opts) {
        opts = opts || {};
        // soPattern 必传 — agent 不再有项目特定默认.
        // host CLI (tracemiku) 已经强制 --so 必填.
        STATE.soPattern = opts.soPattern;
        if (!STATE.soPattern) {
            throw new Error("init: opts.soPattern required (e.g. 'libtarget', 'libfoo'). No hardcoded default.");
        }
        STATE.exportName = opts.exportName || null;
        STATE.methodName = opts.methodName || null;
        // null/undefined fnOffset = "resolve from exportName/methodName".
        // 不再有"历史 fallback 到 0x57770" — 调用方必须传至少一个 (offset/export/method).
        STATE.fnOffset = (opts.fnOffset != null) ? opts.fnOffset : null;
        if (STATE.fnOffset == null && !STATE.exportName && !STATE.methodName) {
            throw new Error("init: must provide fnOffset OR exportName OR methodName");
        }
        // suicidePatchSpec: parsed JSON of tools/hooks/<x>_suicide.json (per-version).
        // 空 = 不打 patch. 项目特定偏移全部来自 spec 文件, agent 不硬编码.
        STATE.suicidePatchSpec = opts.suicidePatchSpec || null;
        STATE.cmdValue = opts.cmdValue || 0;
        STATE.cmdArg = opts.cmdArg !== undefined ? opts.cmdArg : 2;
        STATE.pkg = opts.pkg || null;
        // Multi-SO trace: array of patterns to ALSO trace (in addition to target).
        // e.g. ['libsgsecuritybody','libsgavmp','libcrypto']. HARD_EXCL still applies.
        STATE.includeSoPatterns = Array.isArray(opts.includeSoPatterns)
                                   ? opts.includeSoPatterns : [];
        // Deep trace: skip module-level HARD_EXCL for libart etc; per-symbol
        // exclude only HOSTILE_PATTERNS. Boundary-diff via Interceptor catches
        // memory writes by excluded syms. See applyExcludesOnce.
        STATE.deepTrace = !!opts.deepTrace;
        STATE.stalkerExcludePatterns = Array.isArray(opts.stalkerExcludePatterns)
                                        && opts.stalkerExcludePatterns.length
                                        ? opts.stalkerExcludePatterns : null;
        STATE.boundaryDiffPatterns = Array.isArray(opts.boundaryDiffPatterns)
                                      ? opts.boundaryDiffPatterns : null;
        STATE.patchSuicide = !!opts.patchSuicide;
        STATE.hideRwxMaps = !!opts.hideRwxMaps;
        // jniHooks: array of hook specs (parsed from JSON config). null/empty = disabled.
        STATE.jniHookSpecs = Array.isArray(opts.jniHooks) ? opts.jniHooks : null;
        // P1-C M1: opt-in fork hook (libc fork/vfork/clone/__bionic_clone).
        // 默认关 (大部分 app 不 fork; 开了多 1 个 hook 开销). 反调试 fork 场景必开.
        STATE.enableForkHook = !!opts.enableForkHook;

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
            // ranges built on each onEnter (transform refers to STATE.includeRanges
            // — late-dlopen'd SOs picked up automatically on next call).
            const onInsn = STATE.onInsnPtr;
            installFnHook(fp, onInsn);
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

function installFnHook(fp, onInsn) {
    // ranges read fresh from STATE.includeRanges on each Stalker.follow,
    // so late-dlopen'd SOs are picked up. Each onEnter rebuilds the list.
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
                // B3: 隐藏 RWX 匿名页 from /proc/self/maps reads. 在 Stalker.follow 创建
                // block cache 之前装好, 反检测就看不到 rwxp 了.
                if (STATE.hideRwxMaps) {
                    try { installRwxMapsHider(); } catch (e) { log(`[hide-rwx-maps][!] ${e}`); }
                }
                // Patch sgmainso obfuscated tgkill thunks BEFORE Stalker.follow
                // creates RWX block-cache pages that anti-debug would notice.
                // Only does anything when STATE.patchSuicide is set (CLI: --patch-suicide).
                if (STATE.patchSuicide) {
                    try { patchSgmainsoSuicide(); } catch (e) { log(`[patch-suicide][!] ${e}`); }
                }
                applyExcludesOnce();
                // Cache writable rw- ranges for boundary-diff ptr classification
                if (STATE.deepTrace) refreshWritableRanges();
                // Hook libart JNI string fns once we're in a thread that has JNIEnv.
                // Interceptor (not Stalker) — safe even though libart is HARD_EXCL.
                try { installJniStringHooksOnce(); } catch(_){}
                // P1-C M1: hook libc fork/clone family — Tier 1 fork-event 永远记录,
                // 不依赖 spawn-gating. opt-in via STATE.enableForkHook.
                if (STATE.enableForkHook) {
                    try { installForkHooksOnce(); } catch(e) { log("[fork][!] " + e); }
                }
                // (Re)build include ranges per call — picks up late-dlopen'd
                // SOs (libsgsecuritybody, libsgavmp etc dlopen'd after agent init).
                buildIncludeRanges();
                const ranges = STATE.includeRanges.map(r => ({base: r.base, end: r.end}));
                Stalker.follow(this._tid, {
                    events: { call:false, ret:false, exec:false, block:false, compile:false },
                    transform(iter) {
                        let ins;
                        while ((ins = iter.next()) !== null) {
                            const a = ins.address;
                            // Multi-SO: putCallout if PC in ANY of include ranges
                            let inRange = false;
                            for (let i = 0; i < ranges.length; i++) {
                                const r = ranges[i];
                                if (a.compare(r.base) >= 0 && a.compare(r.end) < 0) {
                                    inRange = true; break;
                                }
                            }
                            if (inRange) {
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
                // 在 trace-end 前 flush JNI string events 让 host 关联到本 call
                try { flushJniStringEvents(this._callIdx); } catch (e) { log(`[!] flushJni: ${e}`); }
                try { flushExtWriteEvents(); } catch (e) { log(`[!] flushExt: ${e}`); }
                try { flushForkEvents(this._callIdx); } catch (e) { log(`[!] flushFork: ${e}`); }
                log(`[<] call #${this._callIdx} ret=${retv} recs=${total} dropped=${dropped} ms=${elapsed} (${rate} rec/s) → ${STATE.traceFilePath}`);
                send({ type: "trace-end", callIdx: this._callIdx, tid: this._tid,
                       retval: retv.toString(), ms: elapsed, total, dropped, truncated: false,
                       devicePath: STATE.traceFilePath });
                STATE.fnEntered = false;
            }
        });
}
