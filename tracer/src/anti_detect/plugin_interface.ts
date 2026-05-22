/**
 * Anti-detect plugin interface
 *
 * 每个 anti-detect 模块 export 一个符合此接口的 plugin 对象.
 * agent.ts 在 init 时根据用户配置按需加载.
 */

export interface AntiDetectPlugin {
    /** Unique plugin ID (used in --anti-detect arg) */
    id: string;
    /** Human-readable name */
    name: string;
    /** One-line description */
    description: string;
    /**
     * Install the anti-detect hook.
     * @param config Optional per-plugin config from user
     */
    install(config?: any): void;
}

/** Registry of all built-in anti-detect plugins */
export const BUILTIN_PLUGINS: Record<string, () => Promise<AntiDetectPlugin>> = {
    "hide_rwx_maps": async () => (await import("./hide_rwx_maps")).plugin,
    "patch_suicide": async () => (await import("./patch_suicide")).plugin,
};
