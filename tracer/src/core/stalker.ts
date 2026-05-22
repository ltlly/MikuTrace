/**
 * Stalker configuration — module excludes, include-ranges, and transform callback
 */

import {
    STATE, HARD_EXCL, SOFT_EXCL, DEEP_KEEP_EXCL,
    STALKER_EXCLUDE_PATTERNS, IncludeRange
} from "./state";
import { log } from "./utils";
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
    const stalkerPatterns = STATE.stalkerExcludePatterns || STALKER_EXCLUDE_PATTERNS;
    const diffPatterns = STATE.boundaryDiffPatterns || DEFAULT_BOUNDARY_DIFF_PATTERNS;

    STATE.diffSyms = [];
    STATE.diffSymAddrs = {};
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
    if (userIncl.length === 0) return;

    for (const m of Process.enumerateModules()) {
        if (STATE.target && m.name === STATE.target.name) continue;
        const isHard = HARD_EXCL.some(p => m.name.indexOf(p) !== -1);
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
            let count = 0;
            const MAX_INSNS = 100000;

            while ((ins = iter.next()) !== null) {
                count++;
                if (count > MAX_INSNS) {
                    log(`[!] transform: block exceeds ${MAX_INSNS} insns, truncating`);
                    break;
                }

                const a = ins.address;

                // Fast path: target SO range
                let inRange = false;
                if (targetBase && targetEnd) {
                    if (a.compare(targetBase) >= 0 && a.compare(targetEnd) < 0) {
                        inRange = true;
                    }
                }

                // Multi-SO: also check include ranges
                if (!inRange && ranges.length > 0) {
                    for (let i = 0; i < ranges.length; i++) {
                        const r = ranges[i];
                        if (a.compare(r.base) >= 0 && a.compare(r.end) < 0) {
                            inRange = true;
                            break;
                        }
                    }
                }

                if (inRange) {
                    try {
                        iter.putCallout(onInsn);
                    } catch (_) {
                        // putCallout can fail on some instructions
                    }
                }
                iter.keep();
            }
        } catch (e) {
            log(`[!] transform error: ${e}`);
            let ins: Arm64Instruction | null;
            while ((ins = iter.next()) !== null) {
                iter.keep();
            }
        }
    };
}
