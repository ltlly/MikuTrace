/**
 * Fork/clone/vfork hook — Tier 1 fork-event logging
 *
 * 在 parent 进程 hook libc fork/vfork/clone, 记录 fork-event
 * (parent_pc + child_pid + clone_flags). Host writes meta.json fork_events.
 */

import { STATE } from "../core/state";
import { log } from "../core/utils";

function _findEx(name: string): NativePointer | null {
    try { return Module.findExportByName(null, name); } catch (_) {}
    try { return Module.findExportByName("libc.so", name); } catch (_) {}
    return null;
}

function _isForkLike(flags: number): boolean {
    const CLONE_THREAD = 0x10000;
    return (flags & CLONE_THREAD) === 0;
}

/** Install fork/vfork/clone hooks (once). Opt-in via STATE.enableForkHook. */
export function installForkHooksOnce(): void {
    if (STATE.forkHooksInstalled) return;
    STATE.forkEvents = STATE.forkEvents || [];
    STATE.forkHooksInstalled = true;
    let installed = 0;

    // Resolve target SO module
    let _modBase: NativePointer | null = null;
    let _modEnd: NativePointer | null = null;
    let _modName: string | null = null;
    try {
        const m = Process.enumerateModules().find(
            x => STATE.soPattern && x.name.indexOf(STATE.soPattern) !== -1
        );
        if (m) {
            _modBase = m.base;
            _modEnd = m.base.add(m.size);
            _modName = m.name;
        }
    } catch (_) {}

    function _pushForkEvent(syscall: string, returnAddress: NativePointer, child_pid: number, clone_flags: number | null) {
        try {
            const pc = returnAddress;
            let parent_pc_rel: string | null = null;
            let parent_in_target = false;
            if (_modBase && pc.compare(_modBase) >= 0 && pc.compare(_modEnd!) < 0) {
                parent_pc_rel = "0x" + pc.sub(_modBase).toString(16);
                parent_in_target = true;
            }
            const is_fork_like = (clone_flags === null) ? true : _isForkLike(clone_flags);
            let trace_idx = 0;
            try { trace_idx = STATE.headBuf!.readU64().toNumber(); } catch (_) {}
            STATE.forkEvents.push({
                type: "fork-event",
                trace_idx,
                parent_pc: pc.toString(),
                parent_pc_rel,
                parent_in_target,
                parent_module: _modName,
                syscall,
                clone_flags: (clone_flags === null) ? null : ("0x" + clone_flags.toString(16)),
                is_fork_like,
                child_pid,
                ts: Date.now(),
                attach_status: "not_attempted",
            });
        } catch (e) {
            log("[fork] push event failed: " + e);
        }
    }

    function _hookFork() {
        const p = _findEx("fork");
        if (!p) return;
        Interceptor.attach(p, {
            onEnter() { (this as any)._ra = this.returnAddress; },
            onLeave(rv) {
                const pid = rv.toInt32();
                if (pid > 0) _pushForkEvent("fork", (this as any)._ra, pid, null);
            }
        });
        installed++;
    }

    function _hookVfork() {
        const p = _findEx("vfork");
        if (!p) return;
        Interceptor.attach(p, {
            onEnter() { (this as any)._ra = this.returnAddress; },
            onLeave(rv) {
                const pid = rv.toInt32();
                if (pid > 0) _pushForkEvent("vfork", (this as any)._ra, pid, null);
            }
        });
        installed++;
    }

    function _hookClone() {
        const p1 = _findEx("clone");
        if (p1) {
            Interceptor.attach(p1, {
                onEnter(args) {
                    (this as any)._ra = this.returnAddress;
                    (this as any)._flags = args[2].toInt32();
                },
                onLeave(rv) {
                    const pid = rv.toInt32();
                    if (pid > 0) _pushForkEvent("clone", (this as any)._ra, pid, (this as any)._flags);
                }
            });
            installed++;
        }
        const p2 = _findEx("__bionic_clone");
        if (p2) {
            Interceptor.attach(p2, {
                onEnter(args) {
                    (this as any)._ra = this.returnAddress;
                    (this as any)._flags = args[0].toInt32();
                },
                onLeave(rv) {
                    const pid = rv.toInt32();
                    if (pid > 0) _pushForkEvent("__bionic_clone", (this as any)._ra, pid, (this as any)._flags);
                }
            });
            installed++;
        }
    }

    try { _hookFork(); } catch (e) { log("[fork] hookFork: " + e); }
    try { _hookVfork(); } catch (e) { log("[fork] hookVfork: " + e); }
    try { _hookClone(); } catch (e) { log("[fork] hookClone: " + e); }
    log("[fork] installed " + installed + " fork-family hooks");
}

/** Flush buffered fork events to host */
export function flushForkEvents(callIdx: number): number {
    if (!STATE.forkEvents || STATE.forkEvents.length === 0) return 0;
    const events = STATE.forkEvents;
    STATE.forkEvents = [];
    send({ type: "fork-events", callIdx, count: events.length, events });
    return events.length;
}
