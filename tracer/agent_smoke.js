// Smoke test: prove the Stalker pipeline end-to-end on whatever target.
//
// Modes (chosen by `init({mode, soPattern, exportName})`):
//   - "module": when soPattern matches a loaded SO and exportName resolves
//               in it, hook that export, start Stalker on entry, count blocks
//               in that SO, unfollow on return.
//   - "any":    on the first dlopen of *any* SO matching soPattern, just log
//               its base/size and start Stalker on the current thread for N ms,
//               counting all blocks regardless of module.
//
// Either way: per-block callout from a transform that filters by PC range.
const STATE = {
    soPattern: null,
    exportName: null,
    mode: "module",
    target: null,        // {name, base, end}
    followed: new Set(),
    blockCount: 0,
    instrCount: 0,
    lastReport: Date.now()
};

function log(...a) { send({ type: "log", msg: a.map(String).join(" ") }); }

function moduleByPattern(pattern) {
    for (const m of Process.enumerateModules()) {
        if (m.name.indexOf(pattern) !== -1) return m;
    }
    return null;
}

function findExport(mod, name) {
    try {
        const a = mod.findExportByName(name);
        if (a) return a;
    } catch (_) {}
    for (const e of mod.enumerateExports()) {
        if (e.name === name) return e.address;
    }
    return null;
}

function setupTarget(modName, base, size) {
    if (STATE.target) return;
    STATE.target = { name: modName, base: base, end: base.add(size) };
    log(`[+] target SO: ${modName} base=${base} size=0x${size.toString(16)}`);
    if (STATE.mode === "module") {
        const m = Process.findModuleByName(modName);
        if (!m) { log("[!] no module handle"); return; }
        const exp = findExport(m, STATE.exportName);
        if (!exp) {
            log(`[!] export ${STATE.exportName} not found in ${modName}`);
            return;
        }
        log(`[+] hooking ${STATE.exportName} @ ${exp}`);
        Interceptor.attach(exp, {
            onEnter() {
                this._tid = this.threadId;
                if (STATE.followed.has(this._tid)) return;
                STATE.followed.add(this._tid);
                log(`[>] ${STATE.exportName} enter tid=${this._tid}`);
                followCurrent();
            },
            onLeave(retv) {
                if (STATE.followed.has(this._tid)) {
                    try { Stalker.unfollow(this._tid); } catch (_) {}
                    try { Stalker.flush(); } catch (_) {}
                    STATE.followed.delete(this._tid);
                    log(`[<] ${STATE.exportName} return=${retv} blocks=${STATE.blockCount}`);
                }
            }
        });
    } else if (STATE.mode === "any") {
        // Just trace whoever calls us
        followCurrent();
        setTimeout(() => {
            for (const t of STATE.followed) { try { Stalker.unfollow(t); } catch (_) {} }
            try { Stalker.flush(); } catch (_) {}
            log(`[stop] any-mode timeout, blocks=${STATE.blockCount}`);
        }, 5000);
    }
}

function followCurrent() {
    const tid = Process.getCurrentThreadId();
    if (STATE.followed.has(tid)) return;
    STATE.followed.add(tid);
    const tBase = STATE.target.base, tEnd = STATE.target.end;
    Stalker.follow(tid, {
        events: { call: false, ret: false, exec: false, block: false, compile: false },
        transform(iter) {
            const first = iter.next();
            if (first === null) return;
            const pc = first.address;
            const inRange = pc.compare(tBase) >= 0 && pc.compare(tEnd) < 0;
            if (inRange) {
                iter.putCallout(onBlock);
            }
            iter.keep();
            let ins;
            while ((ins = iter.next()) !== null) iter.keep();
        }
    });
    log(`[+] Stalker.follow tid=${tid}`);
}

function onBlock(ctx) {
    STATE.blockCount++;
    const now = Date.now();
    if (now - STATE.lastReport > 1000) {
        STATE.lastReport = now;
        send({ type: "progress",
               blocks: STATE.blockCount,
               pc: ctx.pc.toString() });
    }
}

function installLoadHooks() {
    for (const sym of ["android_dlopen_ext", "__loader_android_dlopen_ext", "dlopen"]) {
        let p;
        try {
            p = (Module.findGlobalExportByName || Module.getGlobalExportByName)(sym);
        } catch (_) { p = null; }
        if (!p) continue;
        try {
            Interceptor.attach(p, {
                onEnter(args) {
                    try { this._path = args[0].readUtf8String(); } catch (_) { this._path = "?"; }
                },
                onLeave(retv) {
                    if (!this._path || !STATE.soPattern) return;
                    if (this._path.indexOf(STATE.soPattern) === -1) return;
                    log(`[loader] ${sym}("${this._path}") = ${retv}`);
                    setImmediate(() => {
                        const m = moduleByPattern(STATE.soPattern);
                        if (m) setupTarget(m.name, m.base, m.size);
                        else log(`[!] dlopen returned but module not visible`);
                    });
                }
            });
            log(`[+] hooked ${sym} @ ${p}`);
        } catch (e) {
            log(`[!] hook ${sym} failed: ${e}`);
        }
    }
}

rpc.exports = {
    init(opts) {
        opts = opts || {};
        STATE.soPattern = opts.soPattern || "libsgmainso";
        STATE.exportName = opts.exportName || "JNI_OnLoad";
        STATE.mode = opts.mode || "module";
        log(`[*] agent up frida=${Frida.version} runtime=${Script.runtime} pid=${Process.id}`);
        log(`[*] config: pattern="${STATE.soPattern}" export=${STATE.exportName} mode=${STATE.mode}`);
        const m = moduleByPattern(STATE.soPattern);
        if (m) {
            log(`[i] target already loaded`);
            setupTarget(m.name, m.base, m.size);
        } else {
            installLoadHooks();
        }
        return "ok";
    }
};
