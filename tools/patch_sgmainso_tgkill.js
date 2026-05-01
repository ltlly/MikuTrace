// patch_sgmainso_tgkill.js
//
// libsgmainso-6.8.260403.so 反 Frida 自杀 patch.
//
// 静态分析 (Binary Ninja + 字节扫) 发现 8 处 obfuscated tgkill block, 其中 6 处
// 有完整 `mov x8, x6; svc #0; ret` thunk pattern. 反检测线程通过这些 svc 调用
// SYS_tgkill (131) 给 worker 线程发 SIGILL 自杀.
//
// 标准 libc wrapper (tgkill / raise / kill / pthread_kill) 全是内联 svc 绕过的,
// `Interceptor.attach` hook 抓不到. 唯一办法: 把 svc 字节 patch 成 nop.
//
// 用法: 在 deep-mode trace 启动 *之前* 加载这个 patch (作为 prelude script).
//
// 验证: 跑前 6 个 svc 都是 0xd4000001;跑后都是 0xd503201f (nop). 反检测调用时
// nop 不做任何 syscall, ret 平静返回,自杀不触发.

const TGKILL_SVC_OFFSETS = [
    0x54f10 + 0x10,    // svc @ 0x54f20
    0x5be9c + 0x14,    // svc @ 0x5beb0  (这里 svc 在 +0x14, 不是 +0x10 — 单独验证下)
    0x67260 + 0x14,    // svc @ 0x67274
    0xfe320 + 0x14,    // svc @ 0xfe334
    0x14828c + 0x10,   // svc @ 0x14829c
    0x15b6bc + 0x18,   // svc @ 0x15b6d4
];

// 上面偏移有问题 — 重看静态分析:
//   0x54f10: movz +0,  br +4,  data +8/12, mov x8,x6 +16, svc +20, ret +24
//   不是 +0x10 = +16 = mov x8,x6;不是 svc.
// 修正: SVC 在 +20 (0x14)
const SVC_OFFSETS_FROM_MOVZ = {
    0x4e3e0:  null,    // 没找到 svc within 28 bytes (skip — 可能是不同 syscall)
    0x54f10:  0x14,    // svc @ +0x14 = 0x54f24
    0x5be9c:  0x14,    // svc @ 0x5beb0
    0x67260:  0x14,    // svc @ 0x67274
    0xef980:  null,    // 没找到 svc within 28 bytes (skip)
    0xfe320:  0x14,    // svc @ 0xfe334
    0x14828c: 0x10,    // svc @ 0x14829c (这个 case 布局不同, mov x8,x6 在 +0xc)
    0x15b6bc: 0x18,    // svc @ 0x15b6d4
};

// patch 入口: 拿 libsgmainso 基址,对每个 svc offset patch 4 字节为 nop
function patchSgmainsoTgkill() {
    const NOP = [0x1f, 0x20, 0x03, 0xd5];   // d503201f LE
    const m = Process.enumerateModules().find(x => x.name.indexOf("libsgmainso") !== -1);
    if (!m) {
        send({type: "log", msg: "[patch] libsgmainso 未加载, hook dlopen 等..."});
        return false;
    }
    send({type: "log", msg: `[patch] libsgmainso base = ${m.base}`});
    let patched = 0, skipped = 0;
    for (const movzOff in SVC_OFFSETS_FROM_MOVZ) {
        const svcOff = SVC_OFFSETS_FROM_MOVZ[movzOff];
        if (svcOff === null) {
            send({type: "log", msg: `[patch] skip movz@0x${parseInt(movzOff).toString(16)} — no svc nearby`});
            skipped++;
            continue;
        }
        const svcAddr = m.base.add(parseInt(movzOff) + svcOff);
        const before = svcAddr.readByteArray(4);
        const beforeHex = Array.from(new Uint8Array(before)).map(b => b.toString(16).padStart(2,'0')).join(' ');
        if (beforeHex !== '01 00 00 d4') {
            send({type: "log", msg: `[patch][!] svc@${svcAddr} bytes mismatch: ${beforeHex} (expect 01 00 00 d4) — skip`});
            skipped++;
            continue;
        }
        try {
            Memory.patchCode(svcAddr, 4, ptr => {
                ptr.writeByteArray(NOP);
            });
            patched++;
            send({type: "log", msg: `[patch] OK svc@${svcAddr} (movz+0x${parseInt(movzOff).toString(16)}) → nop`});
        } catch (e) {
            send({type: "log", msg: `[patch][!] failed at ${svcAddr}: ${e}`});
            skipped++;
        }
    }
    send({type: "log", msg: `[patch] done: ${patched} svc patched, ${skipped} skipped`});
    return patched > 0;
}

// 等 libsgmainso 加载. 如果已加载直接 patch;否则 hook dlopen.
const found = patchSgmainsoTgkill();
if (!found) {
    const dlopen = Module.findGlobalExportByName("android_dlopen_ext") ||
                   Module.findGlobalExportByName("dlopen");
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter(a) { try { this._p = a[0].readCString(); } catch(_){ } },
            onLeave() {
                if (this._p && this._p.indexOf("libsgmainso") >= 0) {
                    setTimeout(() => patchSgmainsoTgkill(), 50);
                }
            }
        });
        send({type: "log", msg: "[patch] hooked dlopen, will patch when libsgmainso loads"});
    }
}
