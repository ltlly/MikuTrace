/** 初始快照：按固定内存块读取配置范围，不按总字节数或 region 大小截断。 */
import { STATE } from "../core/state";
import { NativeFile } from "../core/native_io";
import { log } from "../core/utils";
import { persistEvents, registerSnapshot } from "../transport/manifest";

const CHUNK_BYTES = 1024 * 1024;

function permsBits(prot: string): number {
    return (prot[0] === "r" ? 1 : 0) | (prot[1] === "w" ? 2 : 0) | (prot[2] === "x" ? 4 : 0);
}

export function captureMemorySnapshot(callIdx: number): void {
    if (!STATE.snapshotMem || !STATE.traceDir) return;
    const path = `${STATE.traceDir}/snapshot_call${callIdx}.bin`;
    const file = new NativeFile(path);
    // 保持 v1 格式：成功读取的 chunk 各自作为 region，结束后回填实际数量。
    const header = new Uint8Array(16);
    header.set([0x54, 0x4d, 0x53, 0x4e, 0x41, 0x50, 0, 0]);
    new DataView(header.buffer).setUint32(8, 1, true);
    file.write(header.buffer);
    let regions = 0;
    let unreadable = 0;
    for (const range of Process.enumerateRanges("r--")) {
        const target = STATE.target;
        const inTarget = target && range.base.compare(target.base) >= 0 && range.base.compare(target.end) < 0;
        const writable = range.protection[1] === "w";
        const executable = range.protection[2] === "x";
        if (!inTarget && ((range.file && !writable) || (executable && !writable))) continue;
        for (let offset = 0; offset < range.size; offset += CHUNK_BYTES) {
            const base = range.base.add(offset);
            const size = Math.min(CHUNK_BYTES, range.size - offset);
            let data: ArrayBuffer | null = null;
            try { data = base.readVolatile(size); } catch (_) {}
            if (!data || data.byteLength !== size) {
                // 地址已失效不能用伪造的 0 字节替代；证据缺失单独持久化。
                persistEvents("snapshot_errors.jsonl", [{ base: base.toString(), size, reason: "unreadable" }]);
                unreadable++;
                continue;
            }
            const rh = new Uint8Array(24);
            const view = new DataView(rh.buffer);
            const address = BigInt(base.toString());
            view.setUint32(0, Number(address & 0xffffffffn), true);
            view.setUint32(4, Number(address >> 32n), true);
            view.setUint32(8, size, true);
            view.setUint32(16, permsBits(range.protection), true);
            file.write(rh.buffer);
            file.write(data);
            regions++;
        }
    }
    const count = new Uint8Array(4);
    new DataView(count.buffer).setUint32(0, regions, true);
    file.writeAt(12, count.buffer);
    file.close();
    registerSnapshot({ callIdx, devicePath: path, regions, bytes: file.bytes, unreadable });
    log(`[mem-snapshot] regions=${regions}, bytes=${file.bytes}, unreadable=${unreadable}`);
}
