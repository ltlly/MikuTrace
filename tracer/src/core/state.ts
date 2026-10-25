/**
 * traceMiku agent 全局状态和常量
 */

export const REC_SIZE = 272;
/** ring 容量默认值；initOpts.ringRecs 可在运行时下调/上调（硬上限 4M 条 ≈ 1.09 GB）。 */
export const DEFAULT_RING_RECS = 4096;        // ~1.1 MB
export const MAX_RING_RECS = 4194304;          // ~1.14 GB
/** 生效值：init() 时按 opts.ringRecs 设定。 */
export let RING_RECS = DEFAULT_RING_RECS;
export function setRingRecs(n: number): number {
    const v = Math.max(1024, Math.min(MAX_RING_RECS, Math.floor(n)));
    RING_RECS = v;
    return v;
}
export function ringBytes(): number { return REC_SIZE * RING_RECS; }
export const WORKER_RING_RECS = 8192;         // ~2.1 MB per optional worker
export const WORKER_RING_BYTES = REC_SIZE * WORKER_RING_RECS;
export const SIMD_REC_SIZE = 8 + 32 * 16;     // trace_idx:u64 + q0..q31 = 520
export const SIMD_RING_RECS = 8192;           // ~4.1 MB
export const SIMD_RING_BYTES = SIMD_REC_SIZE * SIMD_RING_RECS;

// HARD_EXCL: atomic deadlock / early-init / re-entrant — NEVER trace these
/** --trace-exec: 放开 libc/libm/libdl/libpthread（memcpy/memset 等会写输出缓冲），
 *  但继续排除 ART apex（libart 自修改+stripped, Stalker 跟它必 SIGSEGV）与 linker。 */
export const EXEC_HARD_EXCL = [
    "libc.so", "libm.so", "libdl.so", "libpthread.so"
];
export const ART_EXCL = ["libart.so", "libartbase.so", "libartpalette.so", "libnativeloader.so"];

export const HARD_EXCL = [
    "libc.so", "libm.so", "libdl.so", "libpthread.so", "libart.so",
    "libartbase.so", "libartpalette.so", "libnativeloader.so", "linker", "linker64"
];

// In deep mode, modules that we still exclude entirely
export const DEEP_KEEP_EXCL = ["linker", "linker64", "libdl.so", "libnativeloader.so"];

// TRACE_ALL_KEEP_EXCL: even in --trace-all (capture everything) mode, these
// stay fully Stalker-excluded at MODULE level. Two distinct reasons:
//
// 1. STRUCTURAL re-entrancy (linker/libdl): the dynamic linker runs during
//    Stalker's own dlopen/symbol-resolve path → instrumenting it makes Stalker
//    recurse into code it is currently compiling → deadlock/abort.
//
// 2. SELF-MODIFYING + STRIPPED (the ART apex family): libart's Nterp
//    interpreter, JIT, and GC rewrite/relocate their own code at runtime, which
//    Stalker's block-cache cannot follow (→ SIGSEGV null-deref, verified
//    2026-06-27: trace-all into nterp_op_new_instance → NterpAllocateObject →
//    art::gc::Heap::AddFinalizerReference → SEGV_MAPERR @ 0x0). We CANNOT
//    surgically per-symbol exclude just the unsafe parts because libart is
//    stripped at runtime (enumerateSymbols returns nothing useful, and looping
//    it over every module also hangs the traced thread). So the whole ART apex
//    family is excluded. Consequence: --trace-all captures the target SO, all
//    userland/vendor SOs, and libc/libm (recovering the stat/time boundary
//    gaps), but NOT live Java-bytecode execution inside ART. Tracing the live
//    interpreter/JIT/GC is a hard Frida-Stalker limitation; it needs hardware
//    trace (CoreSight ETM), not a software instrumenter.
export const TRACE_ALL_KEEP_EXCL = [
    "linker", "linker64", "libdl.so", "libnativeloader.so",
    "libart.so", "libartbase.so", "libartpalette.so",
];

// Stalker-exclude patterns (LDXR/STXR atomic deadlock + self-modifying hot code)
export const STALKER_EXCLUDE_PATTERNS = [
    "art::interpreter::Execute", "art::interpreter::DoCall",
    "ExecuteSwitchImpl", "ExecuteMterp", "MterpHelpers",
    "art::jit::Jit", "art::jit::JitCompiler",
    "art::gc::Heap::", "art::gc::collector::",
    "art::ClassLinker::Lookup",
    "pthread_mutex_lock", "pthread_mutex_unlock",
    "pthread_rwlock_", "pthread_cond_",
    "__bionic_atomic_", "__atomic_",
    "malloc", "free", "calloc", "realloc",
];

// SELF_MODIFYING_EXCL: ART internals that Stalker can NEVER safely recompile.
// Self-modifying / runtime-relocated code: the Nterp interpreter rewrites its
// own dispatch, the JIT patches entrypoints, and the GC relocates objects +
// code. Stalker's block-cache assumes code is stable, so following these →
// stale/null entrypoints → SIGSEGV null-deref (verified 2026-06-27: trace-all
// into nterp_op_new_instance → NterpAllocateObject →
// art::gc::Heap::AddFinalizerReference → SEGV_MAPERR @ 0x0, 29-frame real
// stack, NOT anti-debug). This is a DIFFERENT failure from the LDXR/STXR atomic
// deadlock (now handled per-instruction) and from anti-debug suicide.
//
// NOTE: this list is documentation of WHICH symbols are unsafe, but it canNOT
// be used for per-symbol Stalker.exclude on a real device: libart is stripped
// at runtime so enumerateSymbols() does not expose these names, and looping
// symbol enumeration over every module hangs the traced thread. The working
// mitigation is module-level exclusion of the whole ART apex family — see
// TRACE_ALL_KEEP_EXCL above. Kept here as a reference for anyone tempted to
// re-attempt per-symbol exclusion (it does not work without a symbolized libart).
export const SELF_MODIFYING_EXCL = [
    // Nterp (new interpreter) — self-modifying dispatch, executes Java bytecode
    "nterp_", "Nterp", "ExecuteNterp",
    // Old interpreter / mterp — computed-goto self-modifying hot loop
    "art::interpreter::Execute", "art::interpreter::DoCall",
    "ExecuteSwitchImpl", "ExecuteMterp", "MterpHelpers",
    // JIT — patches its own entrypoints and code cache
    "art::jit::Jit", "art::jit::JitCompiler", "art_quick_invoke",
    // GC — relocates objects and code, rewrites references mid-execution
    "art::gc::Heap::", "art::gc::collector::", "AddFinalizerReference",
    "AllocObject", "AllocateObject",
];

// SOFT_EXCL: excluded by default, --include-so can override
export const SOFT_EXCL = [
    "libnativehelper.so", "libnativeloader.so", "libbase.so",
    "libcutils.so", "liblog.so", "libutils.so", "libstdc++.so",
    "libc++.so", "libnetd_client.so", "libssl.so", "libcrypto.so",
    "libsync.so", "libui.so", "libgui.so", "libbinder.so",
    "libbinder_ndk.so", "libhwbinder.so", "libopenjdk.so",
    "libjavacore.so", "libGLESv2.so", "libEGL.so"
];

export interface IncludeRange {
    base: NativePointer;
    end: NativePointer;
    name: string;
}

export interface TraceRingState {
    ringBuf: NativePointer;
    headBuf: NativePointer;
    tailBuf: NativePointer;
    droppedBuf: NativePointer;
    ringRecsBuf: NativePointer;
    ioState: NativePointer;
    flushNative: any;
    active: NativePointer;
    ringRecs: number;
    file: any | null;
    filePath: string | null;
}

export interface WorkerTraceState extends TraceRingState {
    tid: number;
    pthread: string;
    start: string;
    spawnedAtIdx: number;
    endedAtIdx: number | null;
    cm: any;
    onInsnPtr: NativePointer;
}

export interface InitOptions {
    soPattern: string;
    exportName?: string | null;
    methodName?: string | null;
    fnOffset?: number | null;
    pkg?: string | null;
    /** 只放开 libc/libm/libdl/libpthread, 继续排除 libart/linker (比 --trace-deep 安全) */
    execOnly?: boolean | null;
    /** native 分批写盘的固定缓冲容量；不是采集条数上限。 */
    ringRecs?: number | null;
    /** host 预建的 trace 目录; 必须避开 app 私有 cache (app 退出时会被清理) */
    traceDir?: string | null;
    includeSoPatterns?: string[];
    deepTrace?: boolean;
    traceAll?: boolean;
    stalkerExcludePatterns?: string[] | null;
    boundaryDiffPatterns?: string[] | null;
    // Hooks
    jniHooks?: any[] | null;
    enableForkHook?: boolean;
    followWorkers?: boolean;
    maxWorkerThreads?: number;
    traceInit?: boolean;
    // Sidecars
    simdSidecar?: boolean;
    simdSampleStride?: number;
    semanticEvents?: boolean;
    snapshotMem?: boolean;
    // Anti-detect plugins (list of module ids to load)
    antiDetect?: string[];
    antiDetectConfig?: Record<string, any>;
}

export interface AgentState {
    soPattern: string | null;
    exportName: string | null;
    methodName: string | null;
    fnOffset: number | null;
    pkg: string | null;
    /** --trace-exec: 放开 exec 类模块, 但继续排除 ART apex */
    execOnly: boolean;
    target: { name: string; base: NativePointer; end: NativePointer } | null;
    fnHooked: boolean;
    excluded: boolean;
    fnEntered: boolean;
    traceInit: boolean;
    preEntryActive: boolean;
    /** 本次调用只允许封口一次。 */
    callFinalized: boolean;

    includeSoPatterns: string[];
    includeRanges: IncludeRange[];
    deepTrace: boolean;
    traceAll: boolean;
    stalkerExcludePatterns: string[] | null;
    boundaryDiffPatterns: string[] | null;

    cm: any | null;
    onInsnPtr: NativePointer | null;
    ringBuf: NativePointer | null;
    headBuf: NativePointer | null;
    tailBuf: NativePointer | null;
    droppedBuf: NativePointer | null;
    ringRecsBuf: NativePointer | null;
    active: NativePointer | null;
    traceIoState: NativePointer | null;
    simdIoState: NativePointer | null;
    flushNative: any;
    flushSimdNative: any;

    simdSidecar: boolean;
    simdSampleStride: number;
    simdRingBuf: NativePointer | null;
    simdHeadBuf: NativePointer | null;
    simdTailBuf: NativePointer | null;
    simdDroppedBuf: NativePointer | null;
    simdRingRecsBuf: NativePointer | null;
    simdStrideBuf: NativePointer | null;
    simdTraceFile: any | null;
    simdTraceFilePath: string | null;

    semanticEvents: boolean;
    semanticEventBuf: any[];
    semanticHooksInstalled: boolean;
    semanticEventSeq: number;
    onSvcEventCb: NativePointer | null;

    snapshotMem: boolean;

    hbTimer: any;
    batchSeq: number;
    started: number;
    callIdx: number;
    primaryTid: number;
    traceFile: any | null;
    traceFilePath: string | null;
    /** trace 输出目录; host 可通过 initOpts.traceDir 指定以避开 app 私有 cache */
    traceDir: string | null;

    jniHookSpecs: any[] | null;
    jniHookEvents: any[];
    jniHooksInstalled: boolean;
    enableForkHook: boolean;
    forkEvents: any[];
    forkHooksInstalled: boolean;
    followWorkers: boolean;
    maxWorkerThreads: number;
    followedWorkerTids: Record<string, boolean>;
    workerEvents: any[];
    workerTraces: Record<string, WorkerTraceState>;
    pthreadHooksInstalled: boolean;

    diffSyms: any[];
    diffSymAddrs: Record<string, boolean>;
    boundaryHooksInstalled: boolean;
    extWriteEvents: any[];
    writableRanges: any[] | null;

    rwxMapsHidden: boolean;
    suicidePatched: boolean;
    suicidePatchSpec: any;
    patchSuicide: boolean;
    hideRwxMaps: boolean;
    blockSelfKill: boolean;
    selfKillBlocked: boolean;
}

export function createInitialState(): AgentState {
    return {
        soPattern: null, exportName: null, methodName: null,
        fnOffset: null, pkg: null, execOnly: false,
        target: null, fnHooked: false, excluded: false, fnEntered: false,
        traceInit: false, preEntryActive: false, callFinalized: false,

        includeSoPatterns: [], includeRanges: [],
        deepTrace: false, traceAll: false, stalkerExcludePatterns: null, boundaryDiffPatterns: null,

        cm: null, onInsnPtr: null,
        ringBuf: null, headBuf: null, tailBuf: null, droppedBuf: null, ringRecsBuf: null,
        active: null, traceIoState: null, simdIoState: null, flushNative: null, flushSimdNative: null,

        simdSidecar: false, simdSampleStride: 1,
        simdRingBuf: null, simdHeadBuf: null, simdTailBuf: null,
        simdDroppedBuf: null, simdRingRecsBuf: null, simdStrideBuf: null,
        simdTraceFile: null, simdTraceFilePath: null,

        semanticEvents: false, semanticEventBuf: [], semanticHooksInstalled: false,
        semanticEventSeq: 0, onSvcEventCb: null,

        snapshotMem: false,

        hbTimer: null, batchSeq: 0, started: 0,
        callIdx: 0, primaryTid: 0,
        traceFile: null, traceFilePath: null, traceDir: null,

        jniHookSpecs: null, jniHookEvents: [], jniHooksInstalled: false,
        enableForkHook: false, forkEvents: [], forkHooksInstalled: false,
        followWorkers: false, maxWorkerThreads: 4, followedWorkerTids: {},
        workerEvents: [], workerTraces: {}, pthreadHooksInstalled: false,

        diffSyms: [], diffSymAddrs: {}, boundaryHooksInstalled: false,
        extWriteEvents: [], writableRanges: null,

        rwxMapsHidden: false, suicidePatched: false,
        suicidePatchSpec: null, patchSuicide: false, hideRwxMaps: false,
        blockSelfKill: false, selfKillBlocked: false,
    };
}

/** Singleton state */
export const STATE: AgentState = createInitialState();
