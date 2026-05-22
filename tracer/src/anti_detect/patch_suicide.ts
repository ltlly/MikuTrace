/**
 * Anti-detect plugin: Patch obfuscated tgkill thunks
 *
 * 反检测线程通过内联 `svc #0` 调用 SYS_tgkill (x8=131) 自杀 —
 * 标准 Frida hook 不到 (无 PLT entry). 解法: spec-driven 静态 patch.
 *
 * 偏移随 SO 版本变, 走 spec-driven: host 通过 config 传 JSON,
 * 描述 patches: [{offset, ...}]. 没传 spec 时不做任何 patch.
 */

import { STATE } from "../core/state";
import { log } from "../core/utils";
import type { AntiDetectPlugin } from "./plugin_interface";

export interface SuicidePatchSpec {
    so_pattern?: string;
    instruction_to_patch?: {
        expected_bytes_le?: string;
        replacement_bytes_le?: string;
    };
    patches: Array<{ offset: number | string; comment?: string }>;
}

function install(config?: { spec?: SuicidePatchSpec }): void {
    const spec = config?.spec || STATE.suicidePatchSpec;
    if (!spec || !Array.isArray(spec.patches) || spec.patches.length === 0) {
        log(`[patch-suicide] no spec provided; skip`);
        return;
    }
    if (STATE.suicidePatched) return;

    const pat = spec.so_pattern || STATE.soPattern;
    const m = Process.enumerateModules().find(x => x.name.indexOf(pat!) !== -1);
    if (!m) { log(`[patch-suicide] ${pat} not loaded yet`); return; }

    const insn = spec.instruction_to_patch || {};
    const expBytes = (insn.expected_bytes_le || "01 00 00 d4")
        .split(/\s+/).map((s: string) => parseInt(s, 16));
    const repBytes = (insn.replacement_bytes_le || "1f 20 03 d5")
        .split(/\s+/).map((s: string) => parseInt(s, 16));

    let patched = 0;
    for (const p of spec.patches) {
        const off = (typeof p.offset === "string") ? parseInt(p.offset, 16) : p.offset;
        const svcAddr = m.base.add(off);
        try {
            const before = svcAddr.readByteArray(4);
            if (!before) continue;
            const beforeArr = Array.from(new Uint8Array(before));
            const matches = beforeArr.length === expBytes.length &&
                beforeArr.every((b, i) => b === expBytes[i]);
            if (!matches) {
                log(`[patch-suicide][!] @+0x${off.toString(16)} byte mismatch ` +
                    `(got ${beforeArr.map(b => b.toString(16).padStart(2, "0")).join(" ")}); skip`);
                continue;
            }
            Memory.patchCode(svcAddr, 4, (code) => { code.writeByteArray(repBytes); });
            patched++;
        } catch (e) {
            log(`[patch-suicide][!] @+0x${off.toString(16)} patch failed: ${e}`);
        }
    }
    log(`[patch-suicide] ${pat}: ${patched}/${spec.patches.length} patches applied`);
    STATE.suicidePatched = true;
}

/** Plugin export */
export const plugin: AntiDetectPlugin = {
    id: "patch_suicide",
    name: "Patch Suicide (tgkill)",
    description: "Spec-driven patch of obfuscated SVC tgkill thunks to NOP",
    install,
};

export default plugin;
