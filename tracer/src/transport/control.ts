/** 可卸载的 host 控制脚本通过此窄接口访问独立存活的采集器。 */
const METHODS = new Set(["startCapture", "stopCapture", "stats", "pluginCall", "disposePlugins"]);
let reply: NativePointer | null = null;
let bridge: NativePointer | null = null;

export function controlAddress(): string {
    if (!bridge) bridge = new NativeCallback((request: NativePointer) => {
        let result: any;
        try {
            const text = request.readUtf8String()!;
            if (text.length > 65536) throw new Error("control request exceeds 64KiB");
            const message = JSON.parse(text);
            if (!METHODS.has(message.method) || !Array.isArray(message.args)) throw new Error("invalid control method");
            const value = (rpc.exports as any)[message.method](...message.args);
            result = { ok: true, value: value ?? null };
        } catch (error) { result = { ok: false, error: String(error).slice(0, 1000) }; }
        let encoded = JSON.stringify(result);
        if (encoded.length > 65536) encoded = JSON.stringify({ ok: false, error: "control response exceeds 64KiB" });
        // 控制脚本在返回后立即复制；宿主调用者必须串行使用此 mailbox。
        reply = Memory.allocUtf8String(encoded);
        return reply;
    }, "pointer", ["pointer"]);
    return bridge.toString();
}
