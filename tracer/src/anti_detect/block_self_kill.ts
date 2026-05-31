/**
 * Anti-detect plugin: block self-directed signal exits through libc.
 *
 * Complements spec-driven inline SVC patching by covering calls that go through
 * libc wrappers: tgkill, tkill, kill, pthread_kill, raise, and abort.
 */

import { STATE } from "../core/state";
import { log } from "../core/utils";
import type { AntiDetectPlugin } from "./plugin_interface";

function findExport(name: string): NativePointer | null {
    try { return Module.findExportByName(null, name); } catch (_) {}
    try { return Module.findExportByName("libc.so", name); } catch (_) {}
    return null;
}

function install(): void {
    if ((STATE as any).selfKillBlocked) return;
    (STATE as any).selfKillBlocked = true;
    let installed = 0;
    const selfPid = Process.id;
    const signals = new Set([3, 4, 5, 6, 7, 8, 9, 11, 31]);

    const attachReplaceZero = (name: string, shouldBlock: (args: InvocationArguments) => boolean) => {
        const p = findExport(name);
        if (!p) return;
        Interceptor.attach(p, {
            onEnter(args) {
                try { (this as any)._block = shouldBlock(args); } catch (_) { (this as any)._block = false; }
            },
            onLeave(rv) {
                if ((this as any)._block) rv.replace(ptr(0));
            }
        });
        installed++;
    };

    attachReplaceZero("kill", (args) => {
        const pid = args[0].toInt32();
        const sig = args[1].toInt32();
        return (pid === selfPid || pid === 0 || pid === -1) && signals.has(sig);
    });
    attachReplaceZero("tgkill", (args) => {
        const tgid = args[0].toInt32();
        const sig = args[2].toInt32();
        return (tgid === selfPid || tgid === 0) && signals.has(sig);
    });
    attachReplaceZero("tkill", (args) => signals.has(args[1].toInt32()));
    attachReplaceZero("pthread_kill", (args) => signals.has(args[1].toInt32()));
    attachReplaceZero("raise", (args) => signals.has(args[0].toInt32()));
    attachReplaceZero("abort", () => true);

    log(`[block-self-kill] installed ${installed} libc hooks`);
}

export const plugin: AntiDetectPlugin = {
    id: "block_self_kill",
    name: "Block Self Kill",
    description: "Return success from libc self-kill paths (kill/tgkill/tkill/pthread_kill/raise/abort)",
    install,
};

export default plugin;
