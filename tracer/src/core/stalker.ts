import { persistEvents } from "../transport/manifest";
/**
 * Stalker configuration — module excludes, include-ranges, and transform callback
 */

import {
    STATE, HARD_EXCL, SOFT_EXCL, DEEP_KEEP_EXCL, TRACE_ALL_KEEP_EXCL,
    STALKER_EXCLUDE_PATTERNS, IncludeRange, ART_EXCL,
} from "./state";
import { log } from "./utils";
import { entryInstruction, isEntryRedirect } from "./entry";
import { collectBoundaryDiffSymbols, installBoundaryDiffHooksOnce } from "../hooks/boundary_diff";

/** Default boundary-diff patterns (empty — opt-in via --boundary-diff-patterns) */
const DEFAULT_BOUNDARY_DIFF_PATTERNS: string[] = [];

/**
 * Apply Stalker.exclude for all system modules (respecting deep-trace mode).
 * Must be called once before Stalker.follow.
 */
export function applyExcludesOnce(): void {
    if (STATE.excluded) return;

    const userIncl = STATE.includeSoPatterns || [];
    const matchesUser = (name: string) => userIncl.some(pat => name.indexOf(pat) !== -1);
    const deep = !!STATE.deepTrace;
    const execOnly = !!STATE.execOnly;
    const traceAll = !!STATE.traceAll;
    const stalkerPatterns = STATE.stalkerExcludePatterns || STALKER_EXCLUDE_PATTERNS;
    const diffPatterns = STATE.boundaryDiffPatterns || DEFAULT_BOUNDARY_DIFF_PATTERNS;

    STATE.diffSyms = [];
    STATE.diffSymAddrs = {};

    // ── --trace-all: capture EVERYTHING safe ─────────────────────────────
    // Module-level exclude only TRACE_ALL_KEEP_EXCL: the structural linker set
    // (recursion) + the ART apex family (self-modifying & stripped, see note in
    // state.ts). Every other module — target SO, vendor/app SOs, libc, libm — is
    // instrumented except blocks marked exclusive by Stalker. Those blocks
    // remain runnable but unrecorded, with explicit coverage gaps. We do NOT
    // enumerateSymbols here: it is useless on stripped libart and hangs the
    // traced thread when looped over every module.
    if (traceAll) {
        let kept = 0, instrumented = 0;
        for (const m of Process.enumerateModules()) {
            if (TRACE_ALL_KEEP_EXCL.some(p => m.name.indexOf(p) !== -1)) {
                try { Stalker.exclude({ base: m.base, size: m.size }); kept++; } catch (_) {}
            } else {
                instrumented++;
            }
        }
        log(`[+] TRACE-ALL: instrumenting ${instrumented} modules; module-excluded=${kept} ` +
            `(${TRACE_ALL_KEEP_EXCL.join(",")}); exclusive-block coverage gaps reported. ` +
            `NOTE: live ART interpreter/JIT/GC not traceable (Frida limitation).`);
        STATE.excluded = true;
        return;
    }

    let nMod = 0, hard = 0, soft = 0, user_kept = 0, stalkerOnly = 0, diffTargets = 0;

    for (const m of Process.enumerateModules()) {
        const isHard = HARD_EXCL.some(p => m.name.indexOf(p) !== -1);
        const isSoft = !isHard && SOFT_EXCL.some(p => m.name.indexOf(p) !== -1);

        if (isHard) {
            const stillKeep = DEEP_KEEP_EXCL.some(p => m.name.indexOf(p) !== -1);
            if (deep && !stillKeep) {
                // Deep mode: per-symbol Stalker.exclude instead of module-level
                let perModStalker = 0;
                try {
                    for (const sym of m.enumerateSymbols()) {
                        if (!sym.address || sym.address.isNull()) continue;
                        const isStalkerEx = stalkerPatterns.some(p => sym.name.indexOf(p) !== -1);
                        if (isStalkerEx) {
                            const symSize = sym.size || 4096;
                            try {
                                Stalker.exclude({ base: sym.address, size: symSize });
                                perModStalker++;
                            } catch (_) {}
                        }
                    }
                } catch (e) { log(`[!] enumSymbols ${m.name} failed: ${e}`); }
                const perModDiff = collectBoundaryDiffSymbols(m, diffPatterns);
                stalkerOnly += perModStalker;
                diffTargets += perModDiff;
                log(`[+] deep: ${m.name} kept; stalker-excl=${perModStalker} diff-targets=${perModDiff}`);
                continue;
            }
            // Not deep or DEEP_KEEP_EXCL: full module exclude
            const perModDiff = collectBoundaryDiffSymbols(m, diffPatterns);
            diffTargets += perModDiff;
            if (perModDiff > 0) {
                log(`[+] boundary-diff: ${m.name} diff-targets=${perModDiff} (module remains Stalker-excluded)`);
            }
            if (matchesUser(m.name)) {
                log(`[!] WARN: --include-so matched ${m.name}, but it is HARD_EXCL (atomic deadlock risk); skipping`);
            }
            try { Stalker.exclude({ base: m.base, size: m.size }); nMod++; hard++; } catch (_) {}
        } else if (isSoft) {
            if (matchesUser(m.name)) { user_kept++; continue; }
            try { Stalker.exclude({ base: m.base, size: m.size }); nMod++; soft++; } catch (_) {}
        }
    }

    log(`[+] Stalker.exclude: modules=${nMod} (hard=${hard} soft=${soft}, user-kept=${user_kept}); ` +
        `deep=${deep} stalker-only-syms=${stalkerOnly} diff-targets=${diffTargets}`);

    if (STATE.diffSyms.length > 0) installBoundaryDiffHooksOnce();
    STATE.excluded = true;
}

/**
 * Build the list of (base, end, name) ranges to trace.
 * Called on each fn-entry to pick up late-dlopen'd SOs.
 */
export function buildIncludeRanges(): void {
    STATE.includeRanges = [];

    if (STATE.target) {
        STATE.includeRanges.push({
            base: STATE.target.base,
            end: STATE.target.end,
            name: STATE.target.name,
        });
    }

    const userIncl = STATE.includeSoPatterns || [];
    const deep = !!STATE.deepTrace;
    const execOnly = !!STATE.execOnly;
    const traceAll = !!STATE.traceAll;

    // --trace-all: every module except the structural linker set is in-range.
    if (traceAll) {
        for (const m of Process.enumerateModules()) {
            if (STATE.target && m.name === STATE.target.name) continue;
            if (TRACE_ALL_KEEP_EXCL.some(p => m.name.indexOf(p) !== -1)) continue;
            STATE.includeRanges.push({
                base: m.base, end: m.base.add(m.size), name: m.name
            });
        }
        log(`[+] TRACE-ALL: ${STATE.includeRanges.length} module ranges in-range`);
        return;
    }

    if (userIncl.length === 0) return;

    for (const m of Process.enumerateModules()) {
        if (STATE.target && m.name === STATE.target.name) continue;
        // --trace-exec 只放开 exec 类模块; ART apex 继续排除(跟它必 SIGSEGV)
        const hardList: string[] = execOnly ? ART_EXCL : HARD_EXCL;
        const isHard = hardList.some((p: string) => m.name.indexOf(p) !== -1);
        if (isHard && !deep) continue;
        for (const pat of userIncl) {
            if (m.name.indexOf(pat) !== -1) {
                STATE.includeRanges.push({
                    base: m.base, end: m.base.add(m.size), name: m.name
                });
                break;
            }
        }
    }

    log(`[+] tracing ${STATE.includeRanges.length} module ranges:`);
    for (const r of STATE.includeRanges) log(`    ${r.name}`);
}

/**
 * Create the Stalker transform callback.
 * Returns a function suitable for Stalker.follow({ transform: ... }).
 */
export function createTransform(
    onInsn: NativePointer,
    ranges: Array<{ base: NativePointer; end: NativePointer }>
): (iter: StalkerArm64Iterator) => void {
    const targetBase = STATE.target ? STATE.target.base : null;
    const targetEnd = STATE.target ? STATE.target.end : null;

    return function transform(iter: StalkerArm64Iterator) {
        try {
            let ins: Arm64Instruction | null;

            while ((ins = iter.next()) !== null) {
                const a = ins.address;
                const relocated = entryInstruction(a);
                const original = relocated?.pc || a;

                // Fast path: target SO range
                let inRange = false;
                if (targetBase && targetEnd) {
                    if (original.compare(targetBase) >= 0 && original.compare(targetEnd) < 0) {
                        inRange = true;
                    }
                }

                // Multi-SO: also check include ranges
                if (!inRange && ranges.length > 0) {
                    for (let i = 0; i < ranges.length; i++) {
                        const r = ranges[i];
                        if (original.compare(r.base) >= 0 && original.compare(r.end) < 0) {
                            inRange = true;
                            break;
                        }
                    }
                }

                if (inRange && !isEntryRedirect(a)) {
                    // memoryAccess 描述整个翻译块；含独占访问的块不能插入读写
                    // 内存的 callout。记录翻译缺口，不能当作完整运行时覆盖。
                    if (iter.memoryAccess === "exclusive") {
                        persistEvents("coverage_gaps.jsonl", [{ pc: a.toString(),
                            reason: "exclusive-monitor", evidence: "translation", instruction: ins.toString() }]);
                    } else {
                        try { iter.putCallout(onInsn, relocated?.data || NULL); }
                        catch (error) {
                            persistEvents("coverage_gaps.jsonl", [{ pc: a.toString(),
                                reason: "callout-failed", evidence: "translation", error: String(error) }]);
                        }
                    }
                }
                iter.keep();
            }
        } catch (e) {
            persistEvents("coverage_gaps.jsonl", [{ reason: "transform-failed", error: String(e), evidence: "translation" }]);
            let ins: Arm64Instruction | null;
            while ((ins = iter.next()) !== null) {
                iter.keep();
            }
        }
    };
}
