// 极简 test: 不依赖任何 hook, 直接 Stalker.follow 当前线程, 用 CModule transform.
// 在 sleep / 简单进程上跑, 确认 transform 是否被调用.
const STATE = { count: null, jscount: 0 };

function log(...a) { send({ type: "log", msg: a.map(String).join(" ") }); }

rpc.exports = {
    init() {
        STATE.count = Memory.alloc(8); STATE.count.writeU64(0);
        const cm = new CModule(`
#include <gum/gumstalker.h>
#include <capstone.h>
extern unsigned long long *count;
void transform(GumStalkerIterator *iter, GumStalkerOutput *o, void *u) {
    (*count)++;     // transform 入口立即 ++
    cs_insn *insn;
    while (gum_stalker_iterator_next(iter, &insn)) {
        gum_stalker_iterator_keep(iter);
    }
}
`, { count: STATE.count });
        log(`[+] cm.transform = ${cm.transform}`);
        send({ type: "hello" });
        return "ok";
    },
    callDirect() {
        // 直接调 cm.transform 作为 NativeFunction, 跳过 Stalker
        // 用 int 返回值, 避开 import 问题
        log("[callDirect] testing cm.transform as direct NativeFunction");
        const cm = new CModule(`
int sample_fn(void *a, void *b, void *c) {
    return 0xdeadbeef;
}
`);
        log(`[callDirect] cm.sample_fn = ${cm.sample_fn}`);
        const f = new NativeFunction(cm.sample_fn, "int", ["pointer","pointer","pointer"]);
        const r = f(NULL, NULL, NULL);
        log(`[callDirect] returned = 0x${r.toString(16)}`);
        return r.toString(16);
    },
    callImport() {
        // 正确写法: extern T name (no pointer) — name 的存储 IS 传入的 buf
        log("[callImport] correct CModule import semantics test");
        const buf = Memory.alloc(8); buf.writeU64(0);
        log(`[callImport] buf=${buf}`);
        const cm = new CModule(`
extern unsigned long long counter;
void inc(void) { counter++; }
unsigned long long read(void) { return counter; }
`, { counter: buf });
        const inc = new NativeFunction(cm.inc, "void", []);
        const rd = new NativeFunction(cm.read, "uint64", []);
        inc(); inc(); inc();
        log(`[callImport] C read=0x${rd().toString(16)}, JS buf=0x${buf.readU64().toString(16)}`);
        return { c: rd().toString(16), js: buf.readU64().toString(16) };
    },
    runc() {
        log("[runC] follow current thread w/ C transform");
        const tid = Process.getCurrentThreadId();
        const cm = new CModule(`
#include <gum/gumstalker.h>
#include <capstone.h>
extern unsigned long long *count;
void transform(GumStalkerIterator *iter, GumStalkerOutput *o, void *u) {
    (*count)++;
    cs_insn *insn;
    while (gum_stalker_iterator_next(iter, &insn)) {
        gum_stalker_iterator_keep(iter);
    }
}
`, { count: STATE.count });
        // Reset count for fresh measurement
        STATE.count.writeU64(0);
        Stalker.follow(tid, { transform: cm.transform });
        // 跑代码 — Stalker 必须看到 JS 引擎执行的指令
        let s = 0;
        for (let i = 0; i < 100000; i++) s += i;
        // 调一些 native 函数让 Stalker 必然看到
        const m = Process.findModuleByName("libc.so");
        if (m) {
            const getpid = m.findExportByName("getpid");
            if (getpid) {
                const f = new NativeFunction(getpid, "int", []);
                for (let i = 0; i < 100; i++) f();
            }
        }
        Stalker.unfollow(tid);
        Stalker.flush();
        const c = STATE.count.readU64().toNumber();
        log(`[runC] sum=${s} c-transform-count=${c}`);
        return c;
    },
    runjs() {
        log("[runJS] follow current thread w/ JS transform");
        const tid = Process.getCurrentThreadId();
        let local = 0;
        Stalker.follow(tid, {
            transform(iter) {
                local++;
                let ins; while ((ins = iter.next()) !== null) iter.keep();
            }
        });
        let s = 0;
        for (let i = 0; i < 100000; i++) s += i;
        const m = Process.findModuleByName("libc.so");
        if (m) {
            const getpid = m.findExportByName("getpid");
            if (getpid) {
                const f = new NativeFunction(getpid, "int", []);
                for (let i = 0; i < 100; i++) f();
            }
        }
        Stalker.unfollow(tid);
        Stalker.flush();
        log(`[runJS] sum=${s} js-transform-count=${local}`);
        return local;
    },
};
