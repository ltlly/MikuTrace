/** 有界内存、无丢弃的本地写入。短写续写，EINTR 重试，磁盘错误施加背压。 */
import { getExport } from "./utils";
import { STATE } from "./state";

let module: CModule | null = null;
let writeAll: any;
let syncAll: any;
let writeAt: any;
let openRetry: any;
let openFd: any;
let closeFd: any;
export const internalFds = new Set<number>();
const internalThreads = new Map<number, number>();
const activeFiles = new Map<NativePointer, string>();
export function ioHealth(): any[] {
    const blocked: any[] = [];
    for (const [state, path] of activeFiles) {
        const errno = state.add(4).readS32();
        if (errno) blocked.push({ path, errno, retries: state.add(8).readU64().toNumber(),
            written_bytes: state.add(16).readU64().toNumber() });
    }
    return blocked;
}
export function internalIoActive(tid: number): boolean { return (internalThreads.get(tid) || 0) > 0; }
function internal<T>(call: () => T): T {
    const tid = Process.getCurrentThreadId();
    internalThreads.set(tid, (internalThreads.get(tid) || 0) + 1);
    try { return call(); }
    finally {
        const depth = internalThreads.get(tid)! - 1;
        if (depth) internalThreads.set(tid, depth); else internalThreads.delete(tid);
    }
}

export function nativeIoSymbols(): Record<string, NativePointer> {
    if (!module) {
        const symbols: Record<string, NativePointer> = {};
        for (const name of ["write", "pwrite64", "open", "fsync", "usleep", "__errno"]) {
            const address = getExport(name);
            if (!address) throw new Error(`missing libc ${name}`);
            symbols[`io_${name}`] = address;
        }
        module = new CModule(`
extern long io_write(int fd, const void *buf, unsigned long size);
extern long io_pwrite64(int fd, const void *buf, unsigned long size, long long offset);
extern int io_open(const char *path, int flags, int mode);
extern int io_fsync(int fd);
extern int io_usleep(unsigned int usec);
extern int *io___errno(void);
void open_retry(int *state, const char *path) {
    int fd;
    while ((fd = io_open(path, 1 | 64 | 128 | 0x80000, 0600)) < 0) {
        state[1] = *io___errno();
        ((unsigned long long *) state)[1] += 1;
        io_usleep(100000);
    }
    state[0] = fd;
    state[1] = 0;
}
/* state: fd, last_errno, retry_count, written_bytes. 单个 writer 串行调用。 */
void write_all(int *state, const unsigned char *buf, unsigned long size) {
    unsigned long done = 0;
    while (done < size) {
        long n = io_write(state[0], buf + done, size - done);
        if (n > 0) {
            done += n;
            ((unsigned long long *) state)[2] += n;
            state[1] = 0;
        } else {
            state[1] = n == 0 ? 5 : *io___errno();
            ((unsigned long long *) state)[1] += 1;
            if (state[1] != 4) io_usleep(100000);
        }
    }
}
void sync_all(int *state) {
    while (io_fsync(state[0]) != 0) {
        state[1] = *io___errno();
        ((unsigned long long *) state)[1] += 1;
        if (state[1] != 4) io_usleep(100000);
    }
    state[1] = 0;
}
void write_at(int *state, const unsigned char *buf, unsigned long size, long long offset) {
    unsigned long done = 0;
    while (done < size) {
        long n = io_pwrite64(state[0], buf + done, size - done, offset + done);
        if (n > 0) { done += n; state[1] = 0; }
        else {
            state[1] = n == 0 ? 5 : *io___errno();
            ((unsigned long long *) state)[1] += 1;
            if (state[1] != 4) io_usleep(100000);
        }
    }
}
`, symbols);
        writeAll = new NativeFunction((module as any).write_all, "void", ["pointer", "pointer", "ulong"]);
        syncAll = new NativeFunction((module as any).sync_all, "void", ["pointer"]);
        writeAt = new NativeFunction((module as any).write_at, "void", ["pointer", "pointer", "ulong", "int64"]);
        openRetry = new NativeFunction((module as any).open_retry, "void", ["pointer", "pointer"]);
        openFd = new SystemFunction(getExport("open")!, "int", ["pointer", "int", "int"]);
        closeFd = new SystemFunction(getExport("close")!, "int", ["int"]);
    }
    return { write_all: (module as any).write_all, sync_all: (module as any).sync_all };
}

export function ioState(): NativePointer {
    const state = Memory.alloc(24);
    state.writeS32(-1);
    return state;
}

export class NativeFile {
    readonly state: NativePointer;
    private closed = false;
    constructor(readonly path: string, state?: NativePointer) {
        nativeIoSymbols();
        this.state = state || ioState();
        activeFiles.set(this.state, path);
        // O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC：绝不覆盖恢复源。
        const result = internal(() => openFd(Memory.allocUtf8String(path), 1 | 64 | 128 | 0x80000, 0o600));
        if (result.value < 0) {
            if (!STATE.fnEntered) {
                activeFiles.delete(this.state);
                throw new Error(`open ${path}: errno=${result.errno}`);
            }
            // 已进入采集窗口后，路径或磁盘故障必须阻塞生产，不允许异常使目标继续漏跑。
            internal(() => openRetry(this.state, Memory.allocUtf8String(path)));
        } else this.state.writeS32(result.value);
        internalFds.add(this.state.readS32());
        this.state.add(4).writeU32(0);
        this.state.add(8).writeU64(0);
        this.state.add(16).writeU64(0);
    }
    write(bytes: ArrayBuffer | string): void {
        if (this.closed) throw new Error(`write closed ${this.path}`);
        const data = typeof bytes === "string"
            ? Uint8Array.from(unescape(encodeURIComponent(bytes)), c => c.charCodeAt(0)).buffer
            : bytes;
        const buf = Memory.alloc(Math.max(data.byteLength, 1));
        buf.writeByteArray(data);
        internal(() => writeAll(this.state, buf, data.byteLength));
    }
    flush(): void { if (!this.closed) internal(() => syncAll(this.state)); }
    writeAt(offset: number, bytes: ArrayBuffer): void {
        if (this.closed) throw new Error(`write closed ${this.path}`);
        const data = Memory.alloc(bytes.byteLength);
        data.writeByteArray(bytes);
        internal(() => writeAt(this.state, data, bytes.byteLength, offset));
    }
    close(): void {
        if (this.closed) return;
        this.flush();
        internalFds.delete(this.state.readS32());
        const result = internal(() => closeFd(this.state.readS32()));
        this.closed = true;
        activeFiles.delete(this.state);
        this.state.writeS32(-1);
        if (result.value !== 0) throw new Error(`close ${this.path}: errno=${result.errno}`);
    }
    get bytes(): number { return this.state.add(16).readU64().toNumber(); }
}

export function syncDirectory(path: string): void {
    nativeIoSymbols();
    const result = internal(() => openFd(Memory.allocUtf8String(path), 0x10000 | 0x80000, 0));
    if (result.value < 0) throw new Error(`open directory ${path}: errno=${result.errno}`);
    const state = ioState();
    state.writeS32(result.value);
    try { syncAll(state); } finally { closeFd(result.value); }
}
