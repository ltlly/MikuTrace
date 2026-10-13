/** QEMU/GumJS 测试入口；正式采集器及 writer 全部使用生产实现。 */
import "../src/agent";
import { getExport } from "../src/core/utils";

const getenv = new NativeFunction(getExport("getenv")!, "pointer", ["pointer"]);
function env(name: string): string {
    const value = getenv(Memory.allocUtf8String(name));
    if (value.isNull()) throw new Error(`missing fixture environment ${name}`);
    return value.readUtf8String()!;
}

const module = Process.getModuleByName("libtracemiku_offline.so");
// 排除内嵌 Gum 主程序，等价于设备上的 libfrida 独立模块；目标是另一个 SO。
for (const item of Process.enumerateModules()) {
    if (!item.base.equals(module.base)) Stalker.exclude({ base: item.base, size: item.size });
}
const exports = rpc.exports;
const prepared = exports.prepareSpool({ sessionId: "a".repeat(32), traceDir: env("TRACEMIKU_OUT") });
exports.init({
    soPattern: module.name, exportName: env("TRACEMIKU_CASE"), ringRecs: 1024,
    simdSidecar: true, jniHooks: [], maxCalls: Number(env("TRACEMIKU_CALLS")),
});
exports.startCapture();
send({ type: "fixture-ready", prepared });
