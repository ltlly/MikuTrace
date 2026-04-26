// Minimal Stalker plumbing test. Hooks a frequently-called libc function;
// the first invocation gives us a real thread id, we Stalker.follow it for
// `durationMs` and count blocks/instructions.
let g_blocks = 0, g_insns = 0;
let g_start = 0, g_lastReport = 0;
let g_followedTid = null;
let g_perInsn = false;
let g_done = false;

function log(...a) { send({ type: "log", msg: a.map(String).join(" ") }); }

function onCallout(ctx) {
    if (g_perInsn) g_insns++;
    else g_blocks++;
    const now = Date.now();
    if (now - g_lastReport > 500) {
        g_lastReport = now;
        send({ type: "progress", blocks: g_blocks, insns: g_insns, pc: ctx.pc.toString() });
    }
}

function startFollow(tid, durationMs) {
    if (g_followedTid !== null) return;
    g_followedTid = tid;
    g_start = Date.now();
    g_lastReport = g_start;
    log(`[+] Stalker.follow tid=${tid} perInsn=${g_perInsn}`);
    try {
        Stalker.follow(tid, {
            events: { call: false, ret: false, exec: false, block: false, compile: false },
            transform(iter) {
                const first = iter.next();
                if (first === null) return;
                if (g_perInsn) {
                    iter.putCallout(onCallout);
                    iter.keep();
                    let ins;
                    while ((ins = iter.next()) !== null) {
                        iter.putCallout(onCallout);
                        iter.keep();
                    }
                } else {
                    iter.putCallout(onCallout);
                    iter.keep();
                    let ins;
                    while ((ins = iter.next()) !== null) iter.keep();
                }
            }
        });
    } catch (e) {
        log(`[!] follow failed: ${e}`);
        g_followedTid = null;
        return;
    }
    setTimeout(() => {
        if (g_done) return;
        g_done = true;
        try { Stalker.unfollow(tid); } catch (_) {}
        try { Stalker.flush(); } catch (_) {}
        const elapsed = Date.now() - g_start;
        const events = g_perInsn ? g_insns : g_blocks;
        const rate = (events / Math.max(elapsed/1000, 1e-3)).toFixed(0);
        log(`[done] elapsed=${elapsed}ms blocks=${g_blocks} insns=${g_insns} rate=${rate}/s`);
        send({ type: "final", blocks: g_blocks, insns: g_insns, ms: elapsed });
    }, durationMs);
}

rpc.exports = {
    init(opts) {
        opts = opts || {};
        const durationMs = opts.durationMs || 3000;
        g_perInsn = !!opts.perInsn;
        const trigger = opts.trigger || "gettid";
        log(`[*] agent up frida=${Frida.version} pid=${Process.id} runtime=${Script.runtime}`);

        // Hook a high-frequency libc function so the first call gives us a real
        // thread id we can follow.
        let p = null;
        try { p = (Module.findGlobalExportByName || Module.getGlobalExportByName)(trigger); } catch (_) {}
        if (!p) { log(`[!] no export ${trigger}`); return "no-trigger"; }
        log(`[+] trigger ${trigger} @ ${p}`);

        let armed = true;
        Interceptor.attach(p, {
            onEnter() {
                if (!armed) return;
                armed = false;
                const tid = this.threadId;
                log(`[trig] ${trigger} fired on tid=${tid}`);
                // start follow for a window
                startFollow(tid, durationMs);
            }
        });
        return "armed";
    }
};
