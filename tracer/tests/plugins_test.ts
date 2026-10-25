/** 实际 agent 模块在 mock Frida API 上执行，锁定协议与生命周期。 */
import assert from "node:assert/strict";
import {
    installTargetPlugins, runTargetPlugins, invokeTargetPlugin, drainTargetPluginEvents,
} from "../src/target_plugins.ts";

let responses: any[] = [];
(globalThis as any).send = (p: any) => { responses.push(p); };

installTargetPlugins([{ id: "demo", config: { v: 7, expectArg: 70102 }, source: `module.exports = {
    apiVersion: 1,
    install(ctx) { ctx.emit({v: ctx.config.v}); },
    onModule(ctx) { ctx.emit({name: ctx.module.name}); },
    beforeTrace(ctx) {
        if (ctx.marker) ctx.emit({marker: ctx.marker});
        if (ctx.fail) throw new Error('refused');
        if (ctx.arg0 !== undefined && ctx.arg0 !== ctx.config.expectArg) {
            return { skip: true, reason: 'arg0-mismatch' };
        }
    },
    afterTrace(ctx) {
        ctx.emit({after: ctx.records});
    },
    invoke(ctx) { return ctx.payload; }
};` }]);
assert.ok(responses.some(p => p.type === "target-plugin" && p.phase === "install" && p.status === "ok"));
runTargetPlugins("onModule", { module: { name: "demo" } });
assert.equal(runTargetPlugins("beforeTrace", {}), true);
assert.equal(runTargetPlugins("beforeTrace", { arg0: 10601 }), false, "返回 {skip: true} 应跳过本次调用");
assert.equal(runTargetPlugins("beforeTrace", { arg0: 70102 }), true, "匹配参数应放行采集");
runTargetPlugins("afterTrace", { records: 42 });
assert.deepEqual(invokeTargetPlugin("demo", { hello: true }), { hello: true });
assert.throws(() => invokeTargetPlugin("missing", {}), /unavailable/);
assert.throws(() => invokeTargetPlugin("demo", "a".repeat(65537)), /exceeds/);
assert.deepEqual(drainTargetPluginEvents(), responses, "IPC 通知须保留一份供设备文件持久化");
assert.deepEqual(drainTargetPluginEvents(), [], "已交付事件不能重复写入");
(globalThis as any).send = () => {};
runTargetPlugins("beforeTrace", { marker: "host-disconnected" });
assert.deepEqual(drainTargetPluginEvents().map(event => [event.phase, event.status, event.detail]), [
    ["beforeTrace", "event", { marker: "host-disconnected" }],
    ["beforeTrace", "ok", null],
], "host 断开后仍须保留插件事件");
(globalThis as any).send = (p: any) => { responses.push(p); };
responses = [];
for (let i = 0; i < 300; i++) runTargetPlugins("beforeTrace", {});
assert.throws(() => runTargetPlugins("beforeTrace", { fail: true }), /refused/);
assert.equal(responses.at(-1).status, "failed", "事件预算用尽仍须报告首次失败");
assert.ok(responses.length <= 200);
assert.deepEqual(drainTargetPluginEvents(), responses);
console.log("target plugin contracts hold");
