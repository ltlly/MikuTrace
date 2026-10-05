/** host 驱动、单块窗口的回传服务。不 fork/exec，不删除设备恢复源。 */
let STATE: any;

const MAX_BYTES = 8 * 1024 ** 3;
const CHUNK_BYTES = 256 * 1024;
const IDLE_MS = 30000;
let current: { id: string; file: File; size: number; offset: number; timer: ReturnType<typeof setTimeout> } | null = null;

function close(): void {
    if (!current) return;
    clearTimeout(current.timer);
    try { current.file.close(); } catch (_) {}
    current = null;
}

function touch(): void {
    if (!current) return;
    clearTimeout(current.timer);
    current.timer = setTimeout(close, IDLE_MS);
}

function handle(p: any): void {
    const response: any = { type: "spool-response", id: p?.id, op: p?.op };
    try {
        if (typeof p?.id !== "string" || !/^[a-f0-9]{32}$/.test(p.id)) throw new Error("invalid transfer id");
        if (p.op === "cancel") {
            if (current?.id === p.id) close();
            return;
        }
        if (p.op === "open") {
            if (current) throw new Error("spool busy");
            // 只允许当前采集目录中的直接子文件；不暴露任意文件读取 RPC。
            const dir = STATE.traceDir;
            if (!dir || typeof p.path !== "string" || !p.path.startsWith(dir + "/") ||
                !/^[a-zA-Z0-9_.-]+\.bin$/.test(p.path.slice(dir.length + 1))) {
                throw new Error("path outside trace spool");
            }
            // 未封口文件不能回传，防止大小探测与生产并发。
            if ((STATE.traceFile && p.path === STATE.traceFilePath) ||
                (STATE.simdTraceFile && p.path === STATE.simdTraceFilePath) ||
                Object.values(STATE.workerTraces || {}).some((w: any) => w.file && w.filePath === p.path)) {
                throw new Error("spool file still active");
            }
            if (!Number.isSafeInteger(p.maxBytes) || p.maxBytes < 1 || p.maxBytes > MAX_BYTES) throw new Error("invalid byte budget");
            const file = new File(p.path, "rb");
            try {
                file.seek(0, 2);
                const size = file.tell();
                if (!Number.isSafeInteger(size) || size < 0 || size > p.maxBytes) throw new Error("spool exceeds byte budget");
                file.seek(0, 0);
                current = { id: p.id, file, size, offset: 0, timer: setTimeout(close, IDLE_MS) };
                response.size = size;
            } catch (e) { file.close(); throw e; }
        } else {
            if (!current || current.id !== p.id) throw new Error("unknown transfer");
            touch();
            if (p.op === "read") {
                if (p.offset !== current.offset || !Number.isSafeInteger(p.count) ||
                    p.count < 1 || p.count > CHUNK_BYTES || p.offset + p.count > current.size) throw new Error("invalid chunk request");
                const bytes = current.file.readBytes(p.count);
                if (bytes.byteLength !== p.count) throw new Error("short spool read");
                response.offset = current.offset;
                current.offset += bytes.byteLength;
                send(response, bytes);
                return;
            } else if (p.op === "close") {
                if (current.offset !== current.size) throw new Error("transfer incomplete");
                close();
            } else throw new Error("unknown spool op");
        }
    } catch (e) {
        response.error = String(e).slice(0, 500);
        if (current?.id === p?.id) close();
    }
    send(response);
}

export function installSpoolTransport(state: any): void {
    STATE = state;
    function listen(): void {
        recv("spool-request", message => {
            handle(message.payload);
            listen();
        });
    }
    listen();
}
