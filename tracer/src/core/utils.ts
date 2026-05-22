/**
 * 通用工具函数
 */

export function log(...a: any[]): void {
    send({ type: "log", msg: a.map(String).join(" ") });
}

export function getExport(name: string): NativePointer | null {
    try {
        const p = Module.findExportByName(null, name);
        if (p) return p;
    } catch (_) {}
    try {
        return (Module as any).getGlobalExportByName(name);
    } catch (_) {}
    try {
        return (Module as any).findGlobalExportByName(name);
    } catch (_) {}
    return null;
}

/** Android 14+ MTE: mask top byte tag from pointers */
export const PTR_UNTAG_MASK = ptr("0x00ffffffffffffff");

export function ptrToStringMaybe(p: NativePointer | null, maxLen?: number): string | null {
    if (!p || p.isNull()) return null;
    try { return p.readUtf8String()!; } catch (_) {}
    try { return p.readUtf8String(maxLen || 160)!; } catch (_) {}
    try { return p.and(PTR_UNTAG_MASK).readUtf8String()!; } catch (_) {}
    try { return p.and(PTR_UNTAG_MASK).readUtf8String(maxLen || 160)!; } catch (_) {}
    return null;
}

export function u64Dec(v: UInt64): string {
    try { return v.toString(); } catch (_) { return String(v); }
}

export function u64Num(v: UInt64): number {
    const n = parseInt(u64Dec(v), 10);
    return Number.isFinite(n) ? n : 0;
}

export function currentTraceIdx(headBuf: NativePointer | null): number {
    try { return headBuf!.readU64().toNumber(); } catch (_) { return 0; }
}

/** ARM64 syscall number → name mapping */
export const ARM64_SYSCALL_NAMES: Record<number, string> = {
    56: "openat", 57: "close", 62: "lseek", 63: "read", 64: "write",
    65: "readv", 66: "writev", 67: "pread64", 68: "pwrite64",
    78: "readlinkat", 79: "newfstatat", 93: "exit", 94: "exit_group",
    131: "tgkill", 134: "rt_sigaction", 135: "rt_sigprocmask",
    172: "getpid", 178: "gettid", 198: "socket", 203: "connect",
    215: "munmap", 220: "clone", 221: "execve", 222: "mmap",
    226: "mprotect", 260: "wait4", 278: "getrandom", 283: "memfd_create",
};

export function syscallName(nr: number): string {
    return ARM64_SYSCALL_NAMES[nr] || `syscall_${nr}`;
}
