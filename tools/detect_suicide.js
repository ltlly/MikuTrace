// detect_suicide.js — 探测 libsgmainso (或任何反 Frida SO) 的自杀点
//
// 用法:
//   frida -H 127.0.0.1:6699 -p <taobao_pid> -l tools/detect_suicide.js
//
// hook tgkill / raise / abort / pthread_kill / kill / _exit / exit /
//      __cxa_throw,在 onEnter 打印 lr (调用者 PC) + 信号号 + thread tid.
// 不阻止崩溃 (本来就要崩) — 目的是找出 LR 落在哪个模块/偏移,定位反检测代码.

function modAt(addr) {
    try {
        const m = Process.findRangeByAddress(addr);
        if (!m) return null;
        const mod = Process.findModuleByAddress(addr);
        if (mod) return `${mod.name}+0x${addr.sub(mod.base).toString(16)}`;
        return `<rwx-anon@${addr}>`;
    } catch (_) { return `<err@${addr}>`; }
}

function modName(addr) {
    try {
        const mod = Process.findModuleByAddress(addr);
        return mod ? mod.name : "<anon>";
    } catch (_) { return "<err>"; }
}

function backtraceFrames(ctx, n) {
    try {
        const bt = Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, n);
        return bt.map(a => `${a} ${modAt(a)}`);
    } catch (e) {
        return [`<bt-err: ${e}>`];
    }
}

function hook(name, sigArgIdx, label) {
    let p = null;
    try { p = Module.findGlobalExportByName(name); } catch (_) {}
    if (!p) {
        try { p = Module.getGlobalExportByName(name); } catch (_) {}
    }
    if (!p) {
        try {
            // Some are in libc.so explicitly
            p = Module.findExportByName("libc.so", name);
        } catch (_) {}
    }
    if (!p) { send({type:"log", msg:`[!] ${name} not found`}); return; }
    try {
        Interceptor.attach(p, {
            onEnter(args) {
                const sig = sigArgIdx >= 0 ? args[sigArgIdx].toInt32() : -1;
                const lr = this.context.lr;
                const lrMod = modAt(lr);
                const tid = this.threadId;
                const bt = backtraceFrames(this.context, 8);
                send({
                    type: "suicide-call",
                    fn: name, label, signal: sig, tid,
                    lr: lr.toString(), lrMod,
                    bt,
                });
            }
        });
        send({type:"log", msg:`[+] hooked ${name} @ ${p}`});
    } catch (e) {
        send({type:"log", msg:`[!] hook ${name} failed: ${e}`});
    }
}

send({type:"log", msg:`[*] Frida ${Frida.version} detect_suicide.js loaded`});

// 标准 libc 信号/退出 API
hook("tgkill", 2, "syscall to specific thread");
hook("tkill", 1, "deprecated thread kill");
hook("raise", 0, "raise to self");
hook("kill", 1, "kill any pid");
hook("pthread_kill", 1, "pthread signal");
hook("abort", -1, "libc abort");
hook("_exit", -1, "fast exit");
hook("exit", -1, "exit with cleanup");
hook("__cxa_throw", -1, "C++ exception throw");

// 也 hook 几个 anti-debug 常用偷渡点
hook("__libc_format_buffer_va_list", -1, "libc format (sometimes used in detection messages)");

// tgkill via syscall(SYS_tgkill, ...) — hook syscall() 函数本身
let syscall_p = null;
try { syscall_p = Module.findGlobalExportByName("syscall"); } catch (_) {}
if (syscall_p) {
    Interceptor.attach(syscall_p, {
        onEnter(args) {
            const nr = args[0].toInt32();
            // SYS_tgkill = 131 (arm64), SYS_kill = 129, SYS_exit_group = 94
            if (nr === 131 || nr === 129 || nr === 94 || nr === 93) {
                const sig = nr === 131 ? args[3].toInt32()
                          : nr === 129 ? args[2].toInt32() : -1;
                const lr = this.context.lr;
                const bt = backtraceFrames(this.context, 8);
                send({
                    type: "suicide-syscall", nr, signal: sig,
                    tid: this.threadId,
                    lr: lr.toString(), lrMod: modAt(lr), bt,
                });
            }
        }
    });
    send({type:"log", msg:`[+] hooked syscall @ ${syscall_p}`});
}

send({type:"log", msg:`[*] watching... trigger taobao 70102 (e.g. open app, scroll page)`});
