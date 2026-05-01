// probe_deep_safe.js — 纯隔离探测: 测 deep mode (per-sym Stalker.exclude libart/libc)
// 是否会让任意进程崩溃, 不依赖具体目标 SO.
//
// 流程:
//   1. 枚举模块, 对 libart/libc/libartbase 做 per-symbol Stalker.exclude
//      (跟 agent --trace-deep 完全一样的逻辑)
//   2. 选当前线程做 Stalker.follow with empty transformer (不 putCallout)
//   3. setTimeout 5s 后 Stalker.unfollow
//   4. 期间 send 心跳, 等失联 = 进程死了
//
// 如果存活 → deep 模式本身没问题, 那 taobao 崩是 libsgmainso 反检测
// 如果崩 → 我们的 Stalker.exclude per-sym 实现 / frida-gum 在 deep 下有 bug
//
// 用法:
//   frida -H 127.0.0.1:6699 -p <pid> -l tools/probe_deep_safe.js

const HARD_EXCL = ["libc.so","libm.so","libdl.so","libpthread.so","libart.so",
                   "libartbase.so","libartpalette.so","linker","linker64"];
const DEEP_KEEP_EXCL = ["linker","linker64","libdl.so"];
const STALKER_EXCLUDE_PATTERNS = [
    "art::interpreter::Execute","art::interpreter::DoCall",
    "ExecuteSwitchImpl","ExecuteMterp","MterpHelpers",
    "art::jit::Jit","art::jit::JitCompiler",
    "art::gc::Heap::","art::gc::collector::",
    "art::ClassLinker::Lookup",
    "pthread_mutex_lock","pthread_mutex_unlock",
    "pthread_rwlock_","pthread_cond_",
    "__bionic_atomic_","__atomic_",
    "malloc","free","calloc","realloc",
];

function log(s) { send({type:"log", msg:s}); }

log(`[probe] Frida ${Frida.version} starting`);
log(`[probe] pid=${Process.id}`);

let stalkerOnly = 0;
for (const m of Process.enumerateModules()) {
    const isHard = HARD_EXCL.some(p => m.name.indexOf(p) !== -1);
    const isKeep = DEEP_KEEP_EXCL.some(p => m.name.indexOf(p) !== -1);
    if (!isHard) continue;
    if (isKeep) {
        try { Stalker.exclude({base:m.base, size:m.size}); } catch(_){}
        log(`[probe] full-exclude ${m.name}`);
        continue;
    }
    let perMod = 0;
    try {
        for (const sym of m.enumerateSymbols()) {
            if (!sym.address || sym.address.isNull()) continue;
            if (!STALKER_EXCLUDE_PATTERNS.some(p => sym.name.indexOf(p) !== -1)) continue;
            const sz = sym.size || 4096;
            try { Stalker.exclude({base:sym.address, size:sz}); perMod++; } catch(_){}
        }
    } catch(e) { log(`[probe][!] enum ${m.name}: ${e}`); }
    stalkerOnly += perMod;
    log(`[probe] deep: ${m.name} kept; per-sym excl=${perMod}`);
}
log(`[probe] total per-sym Stalker.exclude: ${stalkerOnly}`);

// 选一个非 main thread (main UI follow 后会 ANR 被系统 kill)
const threads = Process.enumerateThreads();
log(`[probe] ${threads.length} threads`);
if (threads.length === 0) {
    log("[probe][!] no threads — abort");
} else {
    // 跳过 tid==pid (main) + UI 类名字, 选末尾的 worker/binder
    const myPid = Process.id;
    const candidates = threads.filter(t => t.id !== myPid &&
                                            !/main|UI|Render/i.test(t.name || ''));
    const t = candidates[candidates.length - 1] || threads[threads.length - 1];
    log(`[probe] follow tid=${t.id} name=${t.name || '?'}`);
    try {
        Stalker.follow(t.id, {
            events: { call:false, ret:false, exec:false, block:false, compile:false },
            transform(iter) {
                let ins;
                while ((ins = iter.next()) !== null) iter.keep();
            }
        });
        log(`[probe] Stalker.follow OK`);
        send({type:"follow-ok", tid: t.id});

        // 心跳 1Hz, 5s 后 unfollow
        let beat = 0;
        const hb = setInterval(() => {
            beat++;
            send({type:"heartbeat", beat, alive: true});
            if (beat >= 2) {
                clearInterval(hb);
                try { Stalker.unfollow(t.id); } catch(e) { log(`[probe][!] unfollow: ${e}`); }
                try { Stalker.flush(); } catch(_){}
                send({type:"done", beats: beat});
                log(`[probe] DONE — Stalker.unfollow OK after ${beat}s`);
            }
        }, 1000);
    } catch (e) {
        log(`[probe][!] Stalker.follow err: ${e}`);
        send({type:"follow-err", err: String(e)});
    }
}
