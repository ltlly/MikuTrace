/**
 * Anti-detect plugin: 隐藏 RWX 匿名页 from /proc/self/maps reads
 *
 * 部分反检测 SO 扫 /proc/self/maps 找 rwxp 命中即自杀.
 * 在 libc 层拦截 open/openat/fopen + read/pread64,
 * 把含 rwxp 的 Frida/anonymous 行删掉.
 */

import { STATE } from "../core/state";
import { log } from "../core/utils";
import type { AntiDetectPlugin } from "./plugin_interface";

const TRACKED_FDS = new Set<number>();

function _filterLine(line: string): boolean {
    if (line.length === 0) return false;
    const isRwx = (line.indexOf("rwxp") >= 0 || line.indexOf("rwxs") >= 0);
    if (!isRwx) return false;
    const low = line.toLowerCase();
    if (low.indexOf("frida") >= 0 || low.indexOf("miku") >= 0) return true;
    const fields = line.trim().split(/\s+/);
    if (fields.length < 6) return true;  // anonymous
    const path = fields[5];
    if (!path) return true;
    if (path.startsWith("[")) return true;
    if (path.startsWith("/")) {
        // Target SO's own rwxp segment — keep
        if (STATE.soPattern && low.indexOf(STATE.soPattern.toLowerCase()) >= 0) return false;
        return false;
    }
    return true;
}

function _filterBuffer(text: string): [string, number] {
    const lines = text.split("\n");
    const kept: string[] = [];
    let dropped = 0;
    for (const line of lines) {
        if (_filterLine(line)) { dropped++; continue; }
        kept.push(line);
    }
    return [kept.join("\n"), dropped];
}

function _findEx(name: string): NativePointer | null {
    try { return Module.findExportByName(null, name); } catch (_) {}
    try { return Module.findExportByName("libc.so", name); } catch (_) {}
    return null;
}

function _isMapsPath(path: string | null): boolean {
    return !!path && (path === "/proc/self/maps" ||
        (path.startsWith("/proc/") && path.endsWith("/maps")));
}

function install(): void {
    if (STATE.rwxMapsHidden) return;
    let n = 0;

    const hookOpen = (p: NativePointer | null, pathIdx: number, _label: string) => {
        if (!p) return;
        Interceptor.attach(p, {
            onEnter(args) {
                try {
                    const path = args[pathIdx].readCString();
                    if (_isMapsPath(path)) {
                        (this as any)._track = true;
                    }
                } catch (_) {}
            },
            onLeave(rv) {
                if ((this as any)._track) {
                    const fd = rv.toInt32();
                    if (fd >= 0) TRACKED_FDS.add(fd);
                }
            }
        });
        n++;
    };

    const hookRead = (p: NativePointer | null, _label: string) => {
        if (!p) return;
        Interceptor.attach(p, {
            onEnter(args) {
                (this as any)._fd = args[0].toInt32();
                (this as any)._buf = args[1];
                (this as any)._tracked = TRACKED_FDS.has((this as any)._fd);
            },
            onLeave(rv) {
                if (!(this as any)._tracked) return;
                const sz = rv.toInt32();
                if (sz <= 0) return;
                try {
                    const bytes = (this as any)._buf.readByteArray(sz);
                    const text = String.fromCharCode.apply(null, new Uint8Array(bytes) as any);
                    const [filtered, dropped] = _filterBuffer(text);
                    if (dropped === 0) return;
                    const newBytes: number[] = [];
                    for (let i = 0; i < filtered.length; i++) newBytes.push(filtered.charCodeAt(i) & 0xff);
                    while (newBytes.length < sz) newBytes.push(0);
                    (this as any)._buf.writeByteArray(newBytes.slice(0, sz));
                    rv.replace(ptr(filtered.length));
                } catch (_) {}
            }
        });
        n++;
    };

    hookOpen(_findEx("openat"), 1, "openat");
    hookOpen(_findEx("open"), 0, "open");
    hookOpen(_findEx("fopen"), 0, "fopen");
    hookRead(_findEx("read"), "read");
    hookRead(_findEx("pread64"), "pread64");

    const hookReadlink = (p: NativePointer | null, pathIdx: number, bufIdx: number, label: string) => {
        if (!p) return;
        Interceptor.attach(p, {
            onEnter(args) {
                (this as any)._buf = args[bufIdx];
                try { (this as any)._track = _isMapsPath(args[pathIdx].readCString()); } catch (_) {}
            },
            onLeave(rv) {
                if (!(this as any)._track) return;
                const sz = rv.toInt32();
                if (sz <= 0) return;
                try {
                    (this as any)._buf.writeUtf8String("/proc/self/maps");
                    rv.replace(ptr(Math.min(sz, "/proc/self/maps".length)));
                } catch (_) {}
            }
        });
        n++;
        log(`[hide-rwx-maps] hook ${label}`);
    };

    const hookFread = (p: NativePointer | null) => {
        if (!p) return;
        Interceptor.attach(p, {
            onEnter(args) {
                (this as any)._buf = args[0];
                (this as any)._size = args[1].toInt32();
                (this as any)._nmemb = args[2].toInt32();
            },
            onLeave(rv) {
                const nmemb = rv.toInt32();
                const total = nmemb * Math.max(1, (this as any)._size || 1);
                if (total <= 0 || total > 1024 * 1024) return;
                try {
                    const bytes = (this as any)._buf.readByteArray(total);
                    const text = String.fromCharCode.apply(null, new Uint8Array(bytes) as any);
                    if (text.indexOf("rwx") < 0 && text.indexOf("frida") < 0) return;
                    const [filtered, dropped] = _filterBuffer(text);
                    if (dropped === 0) return;
                    const newBytes: number[] = [];
                    for (let i = 0; i < filtered.length; i++) newBytes.push(filtered.charCodeAt(i) & 0xff);
                    while (newBytes.length < total) newBytes.push(0);
                    (this as any)._buf.writeByteArray(newBytes.slice(0, total));
                } catch (_) {}
            }
        });
        n++;
    };

    hookReadlink(_findEx("readlink"), 0, 1, "readlink");
    hookReadlink(_findEx("readlinkat"), 1, 2, "readlinkat");
    hookFread(_findEx("fread"));

    const close_p = _findEx("close");
    if (close_p) {
        Interceptor.attach(close_p, {
            onEnter(args) {
                const fd = args[0].toInt32();
                if (TRACKED_FDS.has(fd)) TRACKED_FDS.delete(fd);
            }
        });
        n++;
    }

    STATE.rwxMapsHidden = true;
    log(`[hide-rwx-maps] installed ${n} libc hooks`);
}

/** Plugin export */
export const plugin: AntiDetectPlugin = {
    id: "hide_rwx_maps",
    name: "Hide RWX Maps",
    description: "Filter rwxp lines from /proc/self/maps reads to hide Frida/Stalker memory",
    install,
};

export default plugin;
