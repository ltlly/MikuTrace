/**
 * Boundary memory diff — Interceptor-based external write detection
 *
 * 对 Stalker 排除的函数 (无法在内部观察), 通过 Interceptor.attach 在
 * onEnter snapshot 指针参数周围 ±256B, onLeave diff 检测内存变化.
 * 输出 ext-write events 供 MemShadow.
 */

import { STATE } from "../core/state";
import { log } from "../core/utils";

const PTR_WIN = 256;  // bytes to snapshot around each pointer arg

function symbolMatchesBoundaryPattern(name: string, pat: string): boolean {
    if (!pat) return false;
    if (pat.endsWith("@@")) {
        const stem = pat.slice(0, -2);
        return name === stem || name.indexOf(stem + "@@") !== -1;
    }
    return name.indexOf(pat) !== -1;
}

/** Refresh writable rw- memory ranges (called at fn-entry) */
export function refreshWritableRanges(): void {
    STATE.writableRanges = Process.enumerateRanges("rw-").map(r => ({
        base: r.base, end: r.base.add(r.size),
    }));
}

function isPtrInWritable(p: NativePointer | null): boolean {
    if (!p || p.isNull()) return false;
    const ranges = STATE.writableRanges;
    if (!ranges) return false;
    for (let i = 0; i < ranges.length; i++) {
        if (p.compare(ranges[i].base) >= 0 && p.compare(ranges[i].end) < 0) return true;
    }
    return false;
}

/**
 * Collect symbols from module matching boundary-diff patterns.
 * Returns the number of new symbols added.
 */
export function collectBoundaryDiffSymbols(m: Module, diffPatterns: string[]): number {
    if (!diffPatterns || diffPatterns.length === 0) return 0;
    if (!STATE.diffSymAddrs) STATE.diffSymAddrs = {};
    let n = 0;
    try {
        for (const sym of m.enumerateSymbols()) {
            if (!sym.address || sym.address.isNull()) continue;
            if (!diffPatterns.some(p => symbolMatchesBoundaryPattern(sym.name, p))) continue;
            const key = sym.address.toString();
            if (STATE.diffSymAddrs[key]) continue;
            STATE.diffSymAddrs[key] = true;
            STATE.diffSyms.push({
                addr: sym.address, name: sym.name, mod: m.name,
            });
            n++;
        }
    } catch (e) {
        log(`[!] enumSymbols ${m.name} for boundary-diff failed: ${e}`);
    }
    return n;
}

function makeBoundaryDiffHook(symName: string) {
    return {
        onEnter(this: InvocationContext, args: InvocationArguments) {
            if (this.threadId !== STATE.primaryTid) { (this as any)._skip = true; return; }
            if (!STATE.fnEntered) { (this as any)._skip = true; return; }
            (this as any)._sym = symName;
            (this as any)._enterIdx = STATE.headBuf!.readU64().toNumber();
            const snap: Array<{ addr: NativePointer; before: Uint8Array }> = [];
            for (let i = 0; i < 8; i++) {
                const p = args[i];
                if (!isPtrInWritable(p)) continue;
                let buf: ArrayBuffer | null = null;
                try { buf = p.readByteArray(PTR_WIN); } catch (_) {}
                if (buf) snap.push({ addr: p, before: new Uint8Array(buf) });
            }
            (this as any)._snap = snap;
        },
        onLeave(this: InvocationContext, rv: InvocationReturnValue) {
            if ((this as any)._skip) return;
            const snap = (this as any)._snap || [];

            // Check if rv looks like a fresh allocation pointer
            try {
                if (isPtrInWritable(rv as unknown as NativePointer)) {
                    let after: ArrayBuffer | null = null;
                    try { after = (rv as unknown as NativePointer).readByteArray(PTR_WIN); } catch (_) {}
                    if (after) {
                        const u8 = new Uint8Array(after);
                        for (let i = 0; i < u8.length; i++) {
                            STATE.extWriteEvents.push({
                                attrIdx: (this as any)._enterIdx,
                                addr: (rv as unknown as NativePointer).add(i).toString(),
                                byte: u8[i],
                            });
                        }
                    }
                }
            } catch (_) {}

            // Diff snapshotted pointer windows
            for (const s of snap) {
                let after: ArrayBuffer | null = null;
                try { after = s.addr.readByteArray(PTR_WIN); } catch (_) { continue; }
                const a = new Uint8Array(after!);
                for (let i = 0; i < a.length; i++) {
                    if (a[i] !== s.before[i]) {
                        STATE.extWriteEvents.push({
                            attrIdx: (this as any)._enterIdx,
                            addr: s.addr.add(i).toString(),
                            byte: a[i],
                        });
                    }
                }
            }
            if (STATE.extWriteEvents.length >= 4096) flushExtWriteEvents();
        }
    };
}

/** Install boundary-diff Interceptor hooks for collected symbols */
export function installBoundaryDiffHooksOnce(): void {
    if (STATE.boundaryHooksInstalled) return;
    if (!STATE.diffSyms || STATE.diffSyms.length === 0) {
        STATE.boundaryHooksInstalled = true;
        return;
    }
    STATE.extWriteEvents = STATE.extWriteEvents || [];
    let installed = 0;
    for (const sym of STATE.diffSyms) {
        try {
            Interceptor.attach(sym.addr, makeBoundaryDiffHook(sym.name));
            installed++;
        } catch (e) {
            log(`[!] Interceptor.attach ${sym.name} failed: ${e}`);
        }
    }
    STATE.boundaryHooksInstalled = true;
    log(`[+] boundary-diff Interceptor installed: ${installed}/${STATE.diffSyms.length} diff targets`);
}

/** Flush ext-write events to host */
export function flushExtWriteEvents(): number {
    if (!STATE.extWriteEvents || STATE.extWriteEvents.length === 0) return 0;
    const events = STATE.extWriteEvents;
    STATE.extWriteEvents = [];
    send({ type: "ext-write", callIdx: STATE.callIdx, count: events.length, events });
    return events.length;
}
