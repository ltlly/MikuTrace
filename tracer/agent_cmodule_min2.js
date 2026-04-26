// 极简 CModule 测试: native transform 只统计走过的指令数, 不写 ring.
const STATE = { count: null, target: null, fnEntered: false };

function log(...a) { send({ type: "log", msg: a.map(String).join(" ") }); }

rpc.exports = {
    init() {
        STATE.count = Memory.alloc(8); STATE.count.writeU64(0);
        // 极简 transform: 走每条 insn, ++count, keep
        const cm = new CModule(`
#include <gum/gumstalker.h>
#include <capstone.h>
extern unsigned long long *count;
void transform(GumStalkerIterator *iter, GumStalkerOutput *o, void *u) {
    (*count)++;   // transform 入口立刻 ++ — 验证有没有被调
    cs_insn *insn;
    while (gum_stalker_iterator_next(iter, &insn)) {
        gum_stalker_iterator_keep(iter);
    }
}
`, { count: STATE.count });
        log(`[+] CModule transform @ ${cm.transform}`);
        send({ type: "hello" });

        const m = Process.enumerateModules().find(x => x.name.indexOf("libsgmainso") !== -1);
        if (!m) { log("[!] no SO"); return "no-so"; }
        STATE.target = { name: m.name, base: m.base, end: m.base.add(m.size) };
        log(`[+] ${m.name} @ ${m.base}`);
        // 排除 system 模块防止 LL/SC bug
        for (const mm of Process.enumerateModules()) {
            const nm = mm.name;
            if (/^libc\.so|^libart|^libdl|^libnative|^linker|^libcrypto|^libssl|^libc\+\+|^libstdc\+\+|^libm\.so|^liblog|^libutils|^libbase|^libcutils|^libbinder|^libnetd/.test(nm)) {
                try { Stalker.exclude({base: mm.base, size: mm.size}); } catch(_){}
            }
        }
        const fp = m.base.add(0x57770);
        Interceptor.attach(fp, {
            onEnter() {
                if (STATE.fnEntered) return;
                STATE.fnEntered = true;
                this._tid = this.threadId;
                log(`[>] enter tid=${this._tid}`);
                // 对照: 先用 JS transform 验证 Stalker 工作 ✓
                let jsCount = 0;
                const useJS = false;   // 切换 true=JS, false=C
                if (useJS) {
                    Stalker.follow(this._tid, {
                        transform(iter) {
                            let ins; while ((ins = iter.next()) !== null) {
                                jsCount++; iter.keep();
                            }
                        }
                    });
                    setInterval(() => log(`[js-trans] count=${jsCount}`), 1000);
                } else {
                    Stalker.follow(this._tid, { transform: cm.transform });
                }
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
