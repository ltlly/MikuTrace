/**
 * Initial memory snapshot sidecar.
 *
 * Captures real device memory at trace start (t=0) so the host MemShadow can
 * resolve bytes that were initialized BEFORE the trace window opened
 * (pre-trace .rodata constants, decrypted runtime tables such as a VM bytecode
 * blob, embedded keys). This is the `i` layer of the byte oracle — see
 * docs/memory-completeness-design.md.
 *
 * Default capture set:
 *   - the target SO's mapped segments (all perms) → .rodata constants
 *   - readable rw-/r-- anonymous / heap regions   → decrypted runtime tables
 * Capped by STATE.snapshotMaxBytes to protect the device.
 *
 * File format `snapshot_call<idx>.bin` (little-endian):
 *   magic   "TMSNAP\0\0"  (8 bytes)
 *   version u32           (= 1)
 *   count   u32           (region count)
 *   [per region] base u64, size u64, perms u32, flags u32, data[size]
 */

import { STATE } from "../core/state";
import { log } from "../core/utils";

const SNAPSHOT_MAGIC = [0x54, 0x4d, 0x53, 0x4e, 0x41, 0x50, 0x00, 0x00]; // "TMSNAP\0\0"
const SNAPSHOT_VERSION = 1;
const MAX_REGION_BYTES = 64 * 1024 * 1024; // skip any single region larger than this

function permsBits(prot: string): number {
    let b = 0;
    if (prot[0] === "r") b |= 1;
    if (prot[1] === "w") b |= 2;
    if (prot[2] === "x") b |= 4;
    return b;
}

/**
 * Decide which ranges to snapshot. Returns ranges (base, size, prot) covering
 * the target SO plus readable anon/heap regions, in address order, trimmed to
 * the byte budget.
 */
function selectRanges(maxBytes: number): Array<{ base: NativePointer; size: number; prot: string }> {
    const picked: Array<{ base: NativePointer; size: number; prot: string }> = [];
    let budget = maxBytes;

    const target = STATE.target;
    const targetLo = target ? target.base : null;
    const targetHi = target ? target.end : null;

    // Enumerate readable ranges once.
    let ranges: RangeDetails[] = [];
    try {
        ranges = Process.enumerateRanges("r--");
    } catch (e) {
        log(`[mem-snapshot][!] enumerateRanges failed: ${e}`);
        return picked;
    }

    const inTarget = (base: NativePointer, size: number) =>
        targetLo && targetHi &&
        base.compare(targetLo) >= 0 && base.compare(targetHi) <= 0;

    for (const r of ranges) {
        if (budget <= 0) break;
        const size = r.size;
        if (size <= 0 || size > MAX_REGION_BYTES) continue;

        const isTarget = inTarget(r.base, size);
        // Capture: target SO (any readable seg) + writable/anon/heap data.
        // Skip pure read-only code of OTHER modules (huge, low value, the SO
        // bytes are already on disk). file-backed r-x non-target → skip.
        const file = r.file ? r.file.path : null;
        const isExecOnly = r.protection[2] === "x" && r.protection[1] !== "w";
        if (!isTarget) {
            // keep: anonymous (no file) regions, and rw- data segments
            const isAnon = !file;
            const isWritable = r.protection[1] === "w";
            if (!isAnon && !isWritable) continue;
            if (isExecOnly) continue;
        }

        const take = Math.min(size, budget);
        picked.push({ base: r.base, size: take, prot: r.protection });
        budget -= take;
    }
    return picked;
}

/**
 * Capture the initial memory snapshot to a device file. Called once on target
 * function entry, before Stalker.follow. Best-effort: unreadable regions are
 * skipped, never throws into the trace path.
 */
export function captureMemorySnapshot(callIdx: number): void {
    if (!STATE.snapshotMem || !STATE.traceDir) return;
    const maxBytes = STATE.snapshotMaxBytes > 0 ? STATE.snapshotMaxBytes : 512 * 1024 * 1024;

    let ranges: Array<{ base: NativePointer; size: number; prot: string }>;
    try {
        ranges = selectRanges(maxBytes);
    } catch (e) {
        log(`[mem-snapshot][!] selectRanges failed: ${e}`);
        return;
    }
    if (ranges.length === 0) {
        log("[mem-snapshot] no ranges selected; skipping");
        return;
    }

    const path = `${STATE.traceDir}/snapshot_call${callIdx}.bin`;
    let file: any;
    try {
        file = new File(path, "wb");
    } catch (e) {
        log(`[mem-snapshot][!] open ${path} failed: ${e}`);
        return;
    }

    // 第一遍: 只探测每个 region 的可读性与字节数, 数据立即丢弃.
    // 不能把所有 region 的 ArrayBuffer 同时驻留 — 那会把 snapshotMaxBytes 预算
    // (默认 512MB) 变成设备端内存峰值. Frida File 无 seek, 计数字段在 16 字节
    // 文件头里, 只能先确定 count 再流式写 region.
    const readable: Array<{ base: NativePointer; perms: number; size: number }> = [];
    let totalBytes = 0;
    for (const r of ranges) {
        let byteLen = 0;
        try {
            const buf = r.base.readByteArray(r.size);
            byteLen = buf ? buf.byteLength : 0;
        } catch (_) {
            byteLen = 0; // unreadable; skip
        }
        if (byteLen <= 0) continue;
        readable.push({ base: r.base, perms: permsBits(r.prot), size: byteLen });
        totalBytes += byteLen;
    }

    if (readable.length === 0) {
        log("[mem-snapshot] all selected regions unreadable; skipping");
        try { file.close(); } catch (_) {}
        return;
    }

    // Write header.
    const header = new Uint8Array(16);
    header.set(SNAPSHOT_MAGIC, 0);
    const dv = new DataView(header.buffer);
    dv.setUint32(8, SNAPSHOT_VERSION, true);
    dv.setUint32(12, readable.length, true);
    file.write(header.buffer);

    // 第二遍: 逐 region 读→写→释放, 内存峰值 = 单个 region (≤ MAX_REGION_BYTES).
    for (const reg of readable) {
        const rh = new Uint8Array(24);
        const rdv = new DataView(rh.buffer);
        // u64 base (split into lo/hi to avoid BigInt dependency)
        const baseStr = reg.base.toString();
        const baseBig = BigInt(baseStr);
        rdv.setUint32(0, Number(baseBig & 0xffffffffn), true);
        rdv.setUint32(4, Number((baseBig >> 32n) & 0xffffffffn), true);
        rdv.setUint32(8, reg.size & 0xffffffff, true);
        rdv.setUint32(12, Math.floor(reg.size / 0x100000000), true);
        rdv.setUint32(16, reg.perms, true);
        rdv.setUint32(20, 0, true); // flags
        let data: ArrayBuffer | null = null;
        try {
            data = reg.base.readByteArray(reg.size);
        } catch (_) {
            data = null;
        }
        if (!data || data.byteLength !== reg.size) {
            // 极小概率: 两遍之间 region 被解映射/改变. 用 0 填充保持文件
            // 布局合法 (count 与每个 region 的 size 头都已写入).
            data = new Uint8Array(reg.size).buffer;
        }
        file.write(rh.buffer);
        file.write(data);
        data = null;
    }
    try { file.flush(); } catch (_) {}
    try { file.close(); } catch (_) {}

    log(`[mem-snapshot] call#${callIdx}: ${readable.length} regions, ` +
        `${(totalBytes / 1024 / 1024).toFixed(1)}MB → ${path}`);
    send({
        type: "mem-snapshot",
        callIdx,
        devicePath: path,
        regions: readable.length,
        bytes: totalBytes,
    });
}
