// 通用 trace agent — 任意 SO 任意函数, per-call 独立 trace.
//
// 每次 onEnter 自增 callIdx; frames/trace-begin/trace-end 都带 callIdx,
// host 用 callIdx 把每次调用写到独立目录.
//
// init opts:
//   soPattern: SO 文件名子串 (必填)
//   exportName: 直接 hook 的导出名 (与 fnOffset 二选一)
//   fnOffset:   直接 hook 的相对偏移 (16 进制字符串或数字)
//   methodName: JNI 注册名 (与 cmdValue/cmdArg 配合)
//   cmdValue:   过滤的 cmd id (可选, 0 = 不过滤)
//   cmdArg:     cmd id 在第几个参数 (默认 2)
//   maxRecords: 最大记录数 (默认 5e6)
//   followAllThreads: 是否跟踪所有新线程 (默认 true)
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
    soPattern: null, methodName: null, exportName: null, fnOffset: null,
    cmdArg: 2, cmdValue: 0,
    maxRecords: 5000000,
    followAllThreads: true,

    target: null, fnPtr: null, fnHooked: false, regHooked: false,
    excluded: false,
    followed: new Set(),                 // tids currently Stalker-followed
    threadKnownAt: new Set(),
    callIdx: 0,                          // monotonically increasing per onEnter
    tidCall: new Map(),                  // tid -> active callIdx on that tid
    activeCall: 0,                       // most recent primary callIdx (worker attribution)
    batches: new Map(),                  // callIdx -> {batch, batchOff, batchSeq, totalRecs, tid, lastFlush, startedAt}
    flushTimer: null,
    started: 0, capped: false, seenCalls: 0, primaryTid: 0,
    cmdHist: {},
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

function getOrInitBatch(callIdx, tid) {
    let b = STATE.batches.get(callIdx);
    if (!b) {
        b = { batch: Memory.alloc(BATCH_BYTES), batchOff: 0,
              batchSeq: 0, totalRecs: 0, tid: tid || 0,
              lastFlush: Date.now(), startedAt: Date.now() };
        STATE.batches.set(callIdx, b);
    }
    if (!b.tid && tid) b.tid = tid;
    return b;
}
function flush(callIdx, reason) {
    const b = STATE.batches.get(callIdx);
    if (!b || b.batchOff === 0) return;
    const off = b.batchOff, recs = off / REC_SIZE;
    const blob = b.batch.readByteArray(off);
    b.totalRecs += recs;
    send({ type: "frames", callIdx, tid: b.tid, seq: b.batchSeq++,
           recs, bytes: off, total: b.totalRecs, reason }, blob);
    b.batch = Memory.alloc(BATCH_BYTES);
    b.batchOff = 0; b.lastFlush = Date.now();
}
function ensureFlushTimer() {
    if (STATE.flushTimer) return;
    STATE.flushTimer = setInterval(() => {
        const now = Date.now();
        for (const [callIdx, b] of STATE.batches) {
            if (b.batchOff > 0 && now - b.lastFlush >= FLUSH_INTERVAL_MS)
                flush(callIdx, "interval");
        }
    }, FLUSH_INTERVAL_MS);
}
function totalAcrossAllCalls() {
    let s = 0;
    for (const b of STATE.batches.values()) s += b.totalRecs + b.batchOff/REC_SIZE;
    return s;
}

function recordInsn(ctx) {
    if (STATE.capped) return;
    if (totalAcrossAllCalls() >= STATE.maxRecords) {
        STATE.capped = true;
        log(`[!] 达到上限 ${STATE.maxRecords} 条记录, 停止追踪`);
        for (const tid of STATE.followed) {
            try { Stalker.unfollow(tid); } catch (_) {}
        }
        try { Stalker.flush(); } catch (_) {}
        // 把每个未结束的 call 标 truncated 上报
        for (const [tid, callIdx] of STATE.tidCall) {
            flush(callIdx, "cap");
            const b = STATE.batches.get(callIdx);
            send({ type: "trace-end", callIdx, tid, retval: "?",
                   ms: Date.now() - (b ? b.startedAt : Date.now()),
                   total: b ? b.totalRecs : 0, dropped: 0, truncated: true });
        }
        STATE.tidCall.clear();
        STATE.followed.clear();
        return;
    }
    const tid = Process.getCurrentThreadId();
    let callIdx = STATE.tidCall.get(tid);
    if (!callIdx) callIdx = STATE.activeCall;   // worker thread: attribute to active primary
    if (!callIdx) return;                        // 未知归属 — 丢弃 (应不发生)
    const b = getOrInitBatch(callIdx, tid);
    if (b.batchOff + REC_SIZE > BATCH_BYTES) flush(callIdx, "size");
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
                catch (_) {}
            }
        }
    }
    log(`[+] Stalker.exclude 排除 ${n} 个 system 模块`);
    STATE.excluded = true;
}

function followThread(tid, label) {
    if (STATE.followed.has(tid) || STATE.capped) return;
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
    log(`[+] 跟踪线程 tid=${tid} (${label})`);
    send({ type: "follow", tid, label });
}

function hookFnPtr(fnPtr) {
    if (STATE.fnHooked) return;
    STATE.fnHooked = true; STATE.fnPtr = fnPtr;
    const filterMsg = STATE.cmdValue ? `, 过滤 x${STATE.cmdArg}==${STATE.cmdValue}` : "";
    log(`[+] hook 函数 @ ${fnPtr}${filterMsg}`);
    send({ type: "fn-resolved", addr: fnPtr.toString() });
    Interceptor.attach(fnPtr, {
        onEnter(args) {
            STATE.seenCalls++;
            if (STATE.cmdValue) {
                const cmd = args[STATE.cmdArg].toInt32();
                STATE.cmdHist[cmd] = (STATE.cmdHist[cmd] || 0) + 1;
                if (cmd !== STATE.cmdValue) {
                    if (STATE.seenCalls % 100 === 1)
                        send({ type: "cmd-hist", hist: STATE.cmdHist, total: STATE.seenCalls });
                    this._skip = true; return;
                }
            }
            this._tid = this.threadId;
            STATE.callIdx++;
            this._callIdx = STATE.callIdx;
            STATE.tidCall.set(this._tid, this._callIdx);
            STATE.activeCall = this._callIdx;
            STATE.primaryTid = this._tid;
            STATE.started = Date.now();
            // 预创建 batch 以便记录 startedAt
            getOrInitBatch(this._callIdx, this._tid).startedAt = STATE.started;
            log(`[>] call #${this._callIdx} 进入函数 tid=${this._tid}` +
                (STATE.cmdValue ? ` cmd=${STATE.cmdValue}` : ""));
            send({ type: "trace-begin", callIdx: this._callIdx, tid: this._tid, ts: STATE.started });
            followThread(this._tid, "primary");
            // 只 hook pthread_create 等 NEW 线程；不 follow 已存在的 346 个
            // (那会把进程拖死)。新生成的 worker 线程才 follow。
            if (STATE.followAllThreads) {
                hookPthreadCreate();
            }
        },
        onLeave(retv) {
            if (this._skip) return;
            const tid = this._tid;
            const callIdx = this._callIdx;
            try { Stalker.unfollow(tid); } catch (_) {}
            try { Stalker.flush(); } catch (_) {}
            STATE.followed.delete(tid);
            flush(callIdx, "primary-end");
            const b = STATE.batches.get(callIdx);
            const elapsed = Date.now() - STATE.started;
            const recs = b ? b.totalRecs : 0;
            STATE.tidCall.delete(tid);
            if (STATE.activeCall === callIdx) STATE.activeCall = 0;
            log(`[<] call #${callIdx} 函数返回=${retv} 记录数=${recs} 用时=${elapsed}ms`);
            send({ type: "trace-end", callIdx, tid, retval: retv.toString(),
                   ms: elapsed, total: recs, dropped: 0, truncated: false });
        }
    });
}

function hookAllExistingThreads() {
    let n = 0;
    for (const t of Process.enumerateThreads()) {
        if (STATE.followed.has(t.id) || STATE.threadKnownAt.has(t.id)) continue;
        STATE.threadKnownAt.add(t.id);
        followThread(t.id, "existing"); n++;
    }
    log(`[+] 已跟踪 ${n} 个已存在的线程`);
}
function hookPthreadCreate() {
    if (STATE._threadHooked) return;
    const sym = (Module.findGlobalExportByName||Module.getGlobalExportByName)("pthread_create");
    if (!sym) return;
    Interceptor.attach(sym, {
        onLeave(_retv) {
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
    STATE._threadHooked = true;
    log(`[+] hook pthread_create`);
}

function hookRegisterNatives() {
    if (STATE.regHooked) return false;
    // 通过 JNIEnv vtable[215] 拿 RegisterNatives 函数指针
    const sym = (Module.findGlobalExportByName||Module.getGlobalExportByName)("JNI_GetCreatedJavaVMs");
    if (!sym) return false;
    try {
        const fn = new NativeFunction(sym, 'int', ['pointer','int','pointer']);
        const buf = Memory.alloc(8), np = Memory.alloc(8);
        fn(buf, 1, np);
        if (np.readInt() < 1) return false;
        const vm = buf.readPointer();
        const invokeIface = vm.readPointer();
        const attachThread = invokeIface.add(4*8).readPointer();
        const envPtr = Memory.alloc(8);
        const at = new NativeFunction(attachThread, 'int', ['pointer','pointer','pointer']);
        if (at(vm, envPtr, NULL) !== 0) return false;
        const env = envPtr.readPointer();
        const nativeIface = env.readPointer();
        const regNat = nativeIface.add(215*8).readPointer();
        log(`[+] RegisterNatives @ ${regNat}`);
        Interceptor.attach(regNat, {
            onEnter(args) {
                const methods = args[2];
                const n = args[3].toInt32();
                for (let i = 0; i < n; i++) {
                    const e = methods.add(i * 24);
                    let nm = "?", sg = "?", fp = NULL;
                    try { nm = e.readPointer().readCString(); } catch (_) {}
                    try { sg = e.add(8).readPointer().readCString(); } catch (_) {}
                    try { fp = e.add(16).readPointer(); } catch (_) {}
                    if (nm === STATE.methodName) {
                        log(`[reg] 找到 ${nm} ${sg} -> ${fp}`);
                        send({ type: "register-native", name: nm, sig: sg, fp: fp.toString() });
                        hookFnPtr(fp);
                    }
                }
            }
        });
        STATE.regHooked = true;
        return true;
    } catch (e) { log(`[!] RegisterNatives hook 失败: ${e}`); return false; }
}

function armOnTarget() {
    if (STATE.target) return true;
    const m = moduleByPattern(STATE.soPattern);
    if (!m) return false;
    STATE.target = { name: m.name, base: m.base, end: m.base.add(m.size), size: m.size };
    log(`[+] 目标 SO ${m.name} base=${m.base} size=0x${m.size.toString(16)}`);
    send({ type: "module", name: m.name, base: m.base.toString(), size: m.size, pid: Process.id });
    // Send all loaded modules for multi-SO pointer classification
    send({ type: "modules", modules: Process.enumerateModules().map(mod => ({
        name: mod.name, base: mod.base.toString(), size: mod.size
    })), pid: Process.id });
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
                onLeave(_) {
                    if (!this._path || this._path.indexOf(STATE.soPattern) === -1) return;
                    log(`[loader] dlopen("${this._path}")`);
                    armOnTarget();
                }
            });
        } catch (e) { log(`[!] hook ${sym} 失败: ${e}`); }
    }
}

rpc.exports = {
    init(opts) {
        opts = opts || {};
        STATE.soPattern = opts.soPattern;
        STATE.methodName = opts.methodName || null;
        STATE.exportName = opts.exportName || null;
        STATE.fnOffset = opts.fnOffset !== undefined ? opts.fnOffset : null;
        STATE.cmdArg = opts.cmdArg !== undefined ? opts.cmdArg : 2;
        STATE.cmdValue = opts.cmdValue !== undefined ? opts.cmdValue : 0;
        STATE.maxRecords = opts.maxRecords || 5000000;
        STATE.followAllThreads = !!opts.followAllThreads;  // 默认 false (太重)
        if (!STATE.soPattern) { log("[!] 必须指定 soPattern"); return "no-so"; }
        log(`[*] traceMiku 通用agent up frida=${Frida.version} pid=${Process.id} (per-call)`);
        log(`[*] target=${STATE.soPattern} method=${STATE.methodName} export=${STATE.exportName} `
            + `fnOffset=${STATE.fnOffset} cmd=${STATE.cmdValue}`);
        send({ type: "hello", pid: Process.id, frida: Frida.version,
               recSize: REC_SIZE, batchRecs: BATCH_RECS,
               soPattern: STATE.soPattern, methodName: STATE.methodName,
               exportName: STATE.exportName, fnOffset: STATE.fnOffset,
               cmdValue: STATE.cmdValue, maxRecords: STATE.maxRecords,
               perCall: true });
        try { installDlopenHooks(); } catch (e) { log("[!] " + e); }
        armOnTarget();

        const tryHook = () => {
            if (STATE.fnHooked) return true;
            if (!STATE.target) return false;
            // 按偏移直接 hook
            if (STATE.fnOffset !== null) {
                const fp = STATE.target.base.add(STATE.fnOffset);
                log(`[*] 按偏移 hook: base+0x${STATE.fnOffset.toString(16)} = ${fp}`);
                hookFnPtr(fp); return true;
            }
            // 按导出名 hook
            if (STATE.exportName) {
                const m = Process.findModuleByName(STATE.target.name);
                const fp = m && findExport(m, STATE.exportName);
                if (fp) { log(`[*] 按导出名 hook: ${STATE.exportName} @ ${fp}`); hookFnPtr(fp); return true; }
            }
            // 通过 RegisterNatives hook
            if (STATE.methodName) {
                if (hookRegisterNatives()) return true;
            }
            return false;
        };
        if (!tryHook()) {
            const id = setInterval(() => { if (tryHook()) clearInterval(id); }, 50);
        }
        return "armed";
    },
    forceFlush() {
        for (const callIdx of STATE.batches.keys()) flush(callIdx, "force");
        return "ok";
    },
    stats() {
        const calls = {};
        for (const [callIdx, b] of STATE.batches)
            calls[callIdx] = { tid: b.tid, recs: b.totalRecs + b.batchOff/REC_SIZE };
        return { target: STATE.target ? STATE.target.name : null,
                 fnHooked: STATE.fnHooked, regHooked: STATE.regHooked,
                 seenCalls: STATE.seenCalls, callIdx: STATE.callIdx,
                 primaryTid: STATE.primaryTid, activeCall: STATE.activeCall,
                 followed: Array.from(STATE.followed),
                 perCall: calls, capped: STATE.capped, cmdHist: STATE.cmdHist };
    }
};
