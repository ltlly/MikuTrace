/** 可信用户 JS 模块；无需重新编译 agent。插件不是安全沙箱。 */
export interface TargetPluginSpec { id: string; source: string; config: any; }
type Phase = "install" | "onModule" | "beforeTrace" | "afterTrace" | "dispose";
let plugins: { id: string; api: any; config: any }[] = [];
let eventCount = 0;
const MAX_EVENTS = 200;
let failureReported = false;
let pendingEvents: any[] = [];

/** 生命周期通知必须随设备结果保存，不能只依赖已断开的 host 消息通道。 */
export function drainTargetPluginEvents(): any[] {
    const events = pendingEvents;
    pendingEvents = [];
    return events;
}

function emit(id: string, phase: string, status: string, detail?: any): void {
    // 为失败保留一个通知槽；正常事件耗尽预算不能把拒绝采集变成静默成功。
    if (status === "failed") {
        if (failureReported) return;
        failureReported = true;
    } else if (eventCount >= MAX_EVENTS - 1) return;
    const text = JSON.stringify(detail ?? null);
    if (text.length > 16384) throw new Error("plugin event exceeds 16KiB");
    eventCount++;
    const event = { type: "target-plugin", id, phase, status, detail: JSON.parse(text) };
    pendingEvents.push(event);
    send(event);
}

/**
 * 执行指定生命周期钩子。
 * 在 `beforeTrace` 阶段，若任意插件返回 `false` 或 `{ skip: true }`，返回 `false`
 * 表示跳过本次调用并继续等待下一次调用；抛出异常表示致命拒绝。
 */
export function runTargetPlugins(phase: Phase, context: any = {}): boolean {
    for (const plugin of plugins) {
        try {
            const fn = plugin.api[phase];
            if (fn !== undefined && typeof fn !== "function") throw new Error(`invalid ${phase} handler`);
            if (fn) {
                const result = fn({ ...context, config: plugin.config,
                    emit: (detail: any) => emit(plugin.id, phase, "event", detail) });
                if (result?.then) throw new Error("lifecycle handlers must be synchronous");
                if (phase === "beforeTrace" && (result === false || (result && typeof result === "object" && result.skip === true))) {
                    const reason = result && typeof result === "object" && result.reason !== undefined ? result.reason : null;
                    emit(plugin.id, phase, "skipped", reason);
                    return false;
                }
            }
            emit(plugin.id, phase, "ok");
        } catch (e) {
            emit(plugin.id, phase, "failed", String(e).slice(0, 500));
            throw new Error(`target plugin ${plugin.id}/${phase}: ${e}`);
        }
    }
    return true;
}

export function installTargetPlugins(specs: TargetPluginSpec[]): void {
    if (!Array.isArray(specs) || specs.length > 8) throw new Error("maximum 8 target plugins");
    if (plugins.length) throw new Error("target plugins already initialized");
    const ids = new Set<string>();
    for (const spec of specs) {
        if (typeof spec.id !== "string" || spec.id.length < 1 || spec.id.length > 64 || ids.has(spec.id) ||
            typeof spec.source !== "string" || spec.source.length > 1024 * 1024 ||
            !spec.config || typeof spec.config !== "object" || JSON.stringify(spec.config).length > 65536) {
            throw new Error("invalid target plugin spec");
        }
        ids.add(spec.id);
        const module = { exports: {} as any };
        // CommonJS 风格普通 JS 文件。Frida 原生 API 在该 Script 全局可见。
        new Function("module", "exports", spec.source)(module, module.exports);
        if (module.exports.apiVersion !== 1) throw new Error(`plugin ${spec.id}: apiVersion must be 1`);
        plugins.push({ id: spec.id, api: module.exports, config: spec.config });
    }
    runTargetPlugins("install");
}

export function invokeTargetPlugin(id: string, payload: any): any {
    if (JSON.stringify(payload).length > 65536) throw new Error("plugin request exceeds 64KiB");
    const plugin = plugins.find(p => p.id === id);
    if (!plugin || typeof plugin.api.invoke !== "function") throw new Error("plugin invoke unavailable");
    const result = plugin.api.invoke({ config: plugin.config, payload });
    if (result?.then) throw new Error("plugin invoke must be synchronous");
    const encoded = JSON.stringify(result ?? null);
    if (encoded.length > 65536) throw new Error("plugin response exceeds 64KiB");
    return JSON.parse(encoded);
}
