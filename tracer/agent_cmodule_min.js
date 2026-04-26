// 最小 CModule callout 测试 — 只 ++counter, 不写 ring.
// 排除 ring 写入逻辑可能导致的 crash.
const STATE = {
    soPattern: "libsgmainso", fnOffset: 0x57770,
    target: null, fnHooked: false, excluded: false,
    count: null, calloutPtr: null,
};

function log(...a) { send({ type: "log", msg: a.map(String).join(" ") }); }

function applyExcludesOnce() {
    if (STATE.excluded) return;
    const EXCL = ["libc.so","libm.so","libdl.so","libart.so","libartbase.so",
                  "libartpalette.so","libnativehelper.so","libnativeloader.so",
                  "linker","linker64","libbase.so","libcutils.so","liblog.so",
                  "libutils.so","libstdc++.so","libc++.so","libnetd_client.so",
                  "libssl.so","libcrypto.so","libsync.so","libui.so","libgui.so",
                  "libbinder.so","libbinder_ndk.so","libhwbinder.so",
                  "libopenjdk.so","libjavacore.so","libGLESv2.so","libEGL.so"];
    let n = 0;
    for (const m of Process.enumerateModules())
        for (const pat of EXCL) if (m.name.indexOf(pat) !== -1) {
            try { Stalker.exclude({base:m.base, size:m.size}); n++; break; } catch(_){}
        }
    log(`[+] Stalker.exclude ${n} 个 system 模块`);
    STATE.excluded = true;
}

rpc.exports = {
    init() {
        STATE.count = Memory.alloc(8); STATE.count.writeU64(0);
        const cm = new CModule(`
extern unsigned long long *count;
void on_insn(void *ctx, void *user_data) { (*count)++; }
`, { count: STATE.count });
        // 关键: 必须用 NativeCallback wrap, 不能直接传 NativePointer
        STATE.calloutPtr = new NativeCallback(cm.on_insn, "void", ["pointer", "pointer"]);
        log(`[*] minimal CModule up, on_insn @ ${cm.on_insn}`);
        send({ type: "hello" });

        // 找 SO + hook
        const m = Process.enumerateModules().find(x => x.name.indexOf("libsgmainso") !== -1);
        if (!m) { log("[!] no SO"); return "no-so"; }
        STATE.target = { name: m.name, base: m.base, end: m.base.add(m.size) };
        log(`[+] ${m.name} @ ${m.base}`);
        const fp = m.base.add(0x57770);
        Interceptor.attach(fp, {
            onEnter() {
                if (STATE.fnEntered) return;
                STATE.fnEntered = true;
                this._tid = this.threadId;
                log(`[>] enter tid=${this._tid}`);
                applyExcludesOnce();
                const tBase = STATE.target.base, tEnd = STATE.target.end;
                const cb = STATE.calloutPtr;
                Stalker.follow(this._tid, {
                    events: { call:false, ret:false, exec:false, block:false, compile:false },
                    transform(iter) {
                        let ins;
                        while ((ins = iter.next()) !== null) {
                            const ir = ins.address.compare(tBase) >= 0 && ins.address.compare(tEnd) < 0;
                            if (ir) iter.putCallout(cb);
                            iter.keep();
                        }
                    }
                });
                log(`[+] follow tid=${this._tid}`);
            },
            onLeave() {
                if (!STATE.fnEntered) return;
                try { Stalker.unfollow(this._tid); } catch(_){}
                try { Stalker.flush(); } catch(_){}
                const c = STATE.count.readU64().toNumber();
                log(`[<] leave count=${c}`);
                send({ type: "result", count: c });
                STATE.fnEntered = false;
            }
        });
        log(`[+] hook @ ${fp}`);
        return "armed";
    },
    stats() { return { count: STATE.count.readU64().toNumber() }; }
};
