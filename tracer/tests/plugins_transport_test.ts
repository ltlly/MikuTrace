/** 实际 agent 模块在 mock Frida API 上执行，锁定协议与生命周期。 */
import assert from "node:assert/strict";
import { installSpoolTransport } from "../src/transport/spool.ts";
import { installTargetPlugins, runTargetPlugins, invokeTargetPlugin } from "../src/target_plugins.ts";

let receiver: any;
let responses: any[] = [];
let binary: ArrayBuffer | null = null;
let closes = 0;
const contents = new Uint8Array([1, 2, 3, 4]);
(globalThis as any).recv = (_type: string, callback: any) => { receiver = callback; };
(globalThis as any).send = (p: any, data?: ArrayBuffer) => { responses.push(p); binary = data ?? null; };
(globalThis as any).File = class {
    offset = 0;
    seek(offset: number, origin: number) { this.offset = origin === 2 ? contents.length : offset; }
    tell() { return this.offset; }
    readBytes(count: number) { const out = contents.slice(this.offset, this.offset + count); this.offset += count; return out.buffer; }
    close() { closes++; }
};
const state = { traceDir: "/spool", traceFile: null, traceFilePath: "/spool/trace.bin", workerTraces: {} };
installSpoolTransport(state);
const id = "a".repeat(32);
function req(op: string, fields: any = {}) {
    receiver({ payload: { id, op, ...fields } });
    return responses.at(-1);
}
assert.match(req("open", { path: "/secret.bin", maxBytes: 100 }).error, /outside/);
assert.match(req("open", { path: "/spool/../secret.bin", maxBytes: 100 }).error, /outside/);
assert.match(req("open", { path: "/spool/trace.bin", maxBytes: 3 }).error, /budget/);
assert.equal(req("open", { path: "/spool/trace.bin", maxBytes: 100 }).size, 4);
assert.equal(req("read", { offset: 0, count: 4 }).offset, 0);
assert.deepEqual(Array.from(new Uint8Array(binary!)), [1, 2, 3, 4]);
assert.equal(req("close").error, undefined);
assert.ok(closes >= 2);
req("open", { path: "/spool/trace.bin", maxBytes: 100 });
assert.match(req("read", { offset: 1, count: 1 }).error, /invalid/);
assert.equal(req("open", { path: "/spool/trace.bin", maxBytes: 100 }).size, 4);
req("cancel");

installTargetPlugins([{ id: "demo", config: { v: 7 }, source: `module.exports = {
    apiVersion: 1,
    install(ctx) { ctx.emit({v: ctx.config.v}); },
    onModule(ctx) { ctx.emit({name: ctx.module.name}); },
    beforeTrace(ctx) { if (ctx.fail) throw new Error('refused'); },
    invoke(ctx) { return ctx.payload; }
};` }]);
assert.ok(responses.some(p => p.type === "target-plugin" && p.phase === "install" && p.status === "ok"));
runTargetPlugins("onModule", { module: { name: "demo" } });
runTargetPlugins("beforeTrace", {});
assert.deepEqual(invokeTargetPlugin("demo", { hello: true }), { hello: true });
assert.throws(() => invokeTargetPlugin("missing", {}), /unavailable/);
assert.throws(() => invokeTargetPlugin("demo", "a".repeat(65537)), /exceeds/);
responses = [];
for (let i = 0; i < 300; i++) runTargetPlugins("beforeTrace", {});
assert.throws(() => runTargetPlugins("beforeTrace", { fail: true }), /refused/);
assert.equal(responses.at(-1).status, "failed", "事件预算用尽仍须报告首次失败");
assert.ok(responses.length <= 200);
console.log("plugins/spool contracts hold");
