/* 在 0x57b60 分发入口按 x2 命令号过滤：只采集热启动命令序列，跳过 10601 心跳重试环。 */
var WANTED = new Set([10103, 10602, 10603, 22301, 22302, 20102]);

module.exports = {
    apiVersion: 1,
    install(ctx) {
        ctx.emit({ wanted: Array.from(WANTED).sort(function (a, b) { return a - b; }) });
    },
    beforeTrace(ctx) {
        // 0x57b60 入口的命令号在 x2；ctx.args 可能 RangeError，故读 context。
        var cmd = ctx.context.x2.toInt32();
        if (!WANTED.has(cmd)) {
            return { skip: true, reason: "x2=" + cmd + " not in wanted set" };
        }
        ctx.emit({ matchedCmd: cmd, tid: ctx.tid });
        return true;
    },
};
