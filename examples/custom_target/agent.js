/* 通用目标扩展插件示例：在入口处按调用参数/寄存器过滤，并在返回后记录摘要。 */
module.exports = {
    apiVersion: 1,
    install(ctx) {
        ctx.emit({ enabled: ctx.config.enabled ?? true });
    },
    onModule(ctx) {
        ctx.emit({ module: ctx.module.name, base: ctx.module.base.toString() });
    },
    beforeTrace(ctx) {
        // 示例：按配置的参数下标与期望整数值过滤调用（如 argIndex=0 或 2、expectInt=70102）。
        // 返回 false 或 { skip: true, reason } 会跳过本次调用并继续等待下一次调用；
        // 抛出 Error 则表示致命拒绝，立即终止整个采集会话。
        if (ctx.config && typeof ctx.config.argIndex === "number" && typeof ctx.config.expectInt === "number") {
            const actual = ctx.args[ctx.config.argIndex].toInt32();
            if (actual !== ctx.config.expectInt) {
                return { skip: true, reason: `arg[${ctx.config.argIndex}]=${actual} !== ${ctx.config.expectInt}` };
            }
            ctx.emit({ matchedArgIndex: ctx.config.argIndex, matchedValue: actual, tid: ctx.tid });
        }
        return true;
    },
    afterTrace(ctx) {
        ctx.emit({ callIdx: ctx.callIdx, records: ctx.records, retval: ctx.retval ? ctx.retval.toString() : null });
    },
    invoke(ctx) {
        return { received: ctx.payload };
    },
    dispose(_ctx) {
        /* 用户可在此处 detach 自行安装的额外 hooks。 */
    }
};

