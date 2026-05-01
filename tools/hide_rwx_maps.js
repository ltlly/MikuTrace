// hide_rwx_maps.js — 隐藏 Frida Stalker block cache 等 RWX 匿名页
//
// libsgmainso 6.8.260403 反检测扫 /proc/self/maps 找 rwxp 匿名段, 命中即
// 内联 svc tgkill 自杀. 我们在 libc 层拦截 open/openat + 后续 read, 把
// 危险行 (rwxp 匿名 / [anon:guard] / frida / miku) 删掉再交给调用方.
//
// 用法: 作为独立 Frida script 加载, 或集成进 agent (init 早期 install).

const TRACKED_FDS = new Set();
let DEBUG = false;

function log(s) { send({type: "log", msg: "[hide-maps] " + s}); }

function shouldDropLine(line) {
    // line 格式: "addr-addr perm offset dev:dev inode    path"
    if (line.length === 0) return false;
    const perm = line.substring(17, 22);   // 5 chars at offset 17 typically
    // RWX 是核心信号. 任何 rwxp 都隐藏 (Frida block cache + 我们 patch'd .text 临时态).
    const isRwx = (line.indexOf("rwxp") >= 0 || line.indexOf("rwxs") >= 0);
    if (!isRwx) return false;

    // 整行小写化方便匹配
    const low = line.toLowerCase();
    // frida/miku 字串直接删
    if (low.indexOf("frida") >= 0 || low.indexOf("miku") >= 0) return true;

    // 匿名 rwxp = 一定删 (Stalker block cache / Memory.alloc executable)
    // path 字段为空 / 是 [anon:...] / 是 [stack] (但 stack 通常非 RWX)
    // 用 /\s/ split 取最后一段作 path
    const fields = line.trim().split(/\s+/);
    if (fields.length < 6) return true;     // 没 path = 完全匿名
    const path = fields[5];
    if (!path) return true;
    if (path.startsWith("[")) {
        // [anon:xxx] / [stack] / [heap] — RWX 的话基本是 frida 痕迹
        return true;
    }
    // 真正属于 lib 的 rwxp (e.g. libsgmainso 自己的 packer 段) 保留 — 反检测自己不会
    // 检测自己的 rwxp.
    if (path.startsWith("/")) {
        if (low.indexOf("libsgmain") >= 0) return false;     // sgmain 自己的 rwxp 别动
        // 其他 .so 的 rwxp 也保留 (legitimate JIT 缓存等)
        return false;
    }
    return true;
}

function filterMapsBuffer(text) {
    const lines = text.split("\n");
    const kept = [];
    let dropped = 0;
    for (const line of lines) {
        if (shouldDropLine(line)) { dropped++; continue; }
        kept.push(line);
    }
    if (DEBUG && dropped > 0) log(`filtered ${dropped} rwxp/frida lines`);
    return [kept.join("\n"), dropped];
}

function hookOpen(p, pathIdx, label) {
    if (!p) return;
    Interceptor.attach(p, {
        onEnter(args) {
            try {
                const path = args[pathIdx].readCString();
                if (path && (path === "/proc/self/maps" ||
                             path.startsWith("/proc/") && path.endsWith("/maps"))) {
                    this._track = true;
                    if (DEBUG) log(`${label} ${path}`);
                }
            } catch (_) {}
        },
        onLeave(rv) {
            if (this._track) {
                const fd = rv.toInt32();
                if (fd >= 0) {
                    TRACKED_FDS.add(fd);
                    if (DEBUG) log(`tracked fd=${fd} (${label})`);
                }
            }
        }
    });
}

function hookRead(p, label) {
    if (!p) return;
    Interceptor.attach(p, {
        onEnter(args) {
            this._fd = args[0].toInt32();
            this._buf = args[1];
            this._size = args[2].toInt32();
            this._tracked = TRACKED_FDS.has(this._fd);
        },
        onLeave(rv) {
            if (!this._tracked) return;
            const n = rv.toInt32();
            if (n <= 0) return;
            try {
                const bytes = this._buf.readByteArray(n);
                const text = String.fromCharCode.apply(null, new Uint8Array(bytes));
                const [filtered, dropped] = filterMapsBuffer(text);
                if (dropped === 0) return;
                // 重写 buffer + 调整返回 size
                const newBytes = [];
                for (let i = 0; i < filtered.length; i++) newBytes.push(filtered.charCodeAt(i) & 0xff);
                // pad 用 0 让 buffer 干净 (调用方可能不看 size 后字节)
                while (newBytes.length < n) newBytes.push(0);
                this._buf.writeByteArray(newBytes.slice(0, n));
                rv.replace(ptr(filtered.length));
                if (DEBUG) log(`${label}(fd=${this._fd}): ${n}→${filtered.length} bytes (${dropped} lines hidden)`);
            } catch (e) { log(`${label} filter err: ${e}`); }
        }
    });
}

function hookClose(p) {
    if (!p) return;
    Interceptor.attach(p, {
        onEnter(args) {
            const fd = args[0].toInt32();
            if (TRACKED_FDS.has(fd)) {
                TRACKED_FDS.delete(fd);
                if (DEBUG) log(`untracked fd=${fd}`);
            }
        }
    });
}

function findEx(name) {
    try { return Module.findGlobalExportByName(name); } catch (_) {}
    try { return Module.getGlobalExportByName(name); } catch (_) {}
    try { return Module.findExportByName("libc.so", name); } catch (_) {}
    return null;
}

function installRwxMapsHider(opts) {
    if (opts && opts.debug) DEBUG = true;
    let installed = 0;
    // openat: int openat(int dirfd, const char *path, int flags, mode_t mode);
    const openat_p = findEx("openat");
    if (openat_p) { hookOpen(openat_p, 1, "openat"); installed++; }
    const open_p = findEx("open");
    if (open_p) { hookOpen(open_p, 0, "open"); installed++; }
    const fopen_p = findEx("fopen");
    if (fopen_p) { hookOpen(fopen_p, 0, "fopen"); installed++; }
    // read variants
    const read_p = findEx("read");
    if (read_p) { hookRead(read_p, "read"); installed++; }
    const pread_p = findEx("pread64");
    if (pread_p) { hookRead(pread_p, "pread64"); installed++; }
    // close to clean up tracked fds
    const close_p = findEx("close");
    if (close_p) { hookClose(close_p); installed++; }
    log(`installed ${installed} hooks (openat/open/fopen/read/pread64/close)`);
}

// 独立 script 模式: 直接 install
if (typeof rpc === "undefined" || !rpc.exports) {
    installRwxMapsHider({debug: true});
}
