/* 脱敏扩展点演示；不安装目标补丁，不声称绕过任何检测。 */
module.exports = {
    apiVersion: 1,
    install(ctx) { ctx.emit({ enabled: ctx.config.enabled }); },
    onModule(ctx) { ctx.emit({ module: ctx.module.name }); },
    beforeTrace(ctx) { /* 用户可在这里调整已验证的 app 级行为。 */ },
    invoke(ctx) { return { received: ctx.payload }; },
    dispose(ctx) { /* 用户应在这里 detach 自己安装的 hooks。 */ }
};
