/**
 * traceMiku agent 全局状态和常量
 */

export const REC_SIZE = 272;
export const RING_RECS = 65536;               // ~17.6 MB
export const RING_BYTES = REC_SIZE * RING_RECS;
export const SIMD_REC_SIZE = 8 + 32 * 16;     // trace_idx:u64 + q0..q31 = 520
export const SIMD_RING_RECS = 8192;           // ~4.1 MB
export const SIMD_RING_BYTES = SIMD_REC_SIZE * SIMD_RING_RECS;
export const FLUSH_INTERVAL_MS = 10;

// HARD_EXCL: atomic deadlock / early-init / re-entrant — NEVER trace these
export const HARD_EXCL = [
    "libc.so", "libm.so", "libdl.so", "libpthread.so", "libart.so",
    "libartbase.so", "libartpalette.so", "linker", "linker64"
];

// In deep mode, modules that we still exclude entirely
export const DEEP_KEEP_EXCL = ["linker", "linker64", "libdl.so"];

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

export interface InitOptions {
    soPattern: string;
    exportName?: string | null;
    methodName?: string | null;
    fnOffset?: number | null;
    cmdValue?: number | null;
    cmdArg?: number | null;
    maxRecords?: number | null;
    pkg?: string | null;
    includeSoPatterns?: string[];
    deepTrace?: boolean;
    stalkerExcludePatterns?: string[] | null;
    boundaryDiffPatterns?: string[] | null;
    // Hooks
    jniHooks?: any[] | null;
    enableForkHook?: boolean;
    // Sidecars
    simdSidecar?: boolean;
    simdSampleStride?: number;
    semanticEvents?: boolean;
    // Anti-detect plugins (list of module ids to load)
    antiDetect?: string[];
    antiDetectConfig?: Record<string, any>;
}

export interface AgentState {
    soPattern: string | null;
    exportName: string | null;
    methodName: string | null;
    fnOffset: number | null;
    cmdValue: number | null;
    cmdArg: number | null;
    pkg: string | null;
    target: { name: string; base: NativePointer; end: NativePointer } | null;
    fnHooked: boolean;
    excluded: boolean;
    fnEntered: boolean;

    includeSoPatterns: string[];
    includeRanges: IncludeRange[];
    deepTrace: boolean;
    stalkerExcludePatterns: string[] | null;
    boundaryDiffPatterns: string[] | null;

    cm: any | null;
    onInsnPtr: NativePointer | null;
    ringBuf: NativePointer | null;
    headBuf: NativePointer | null;
    tailBuf: NativePointer | null;
    droppedBuf: NativePointer | null;
    ringRecsBuf: NativePointer | null;
    maxRecords: number;
    maxRecordsBuf: NativePointer | null;

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

    flushTimer: any;
    hbTimer: any;
    batchSeq: number;
    started: number;
    callIdx: number;
    primaryTid: number;
    traceFile: any | null;
    traceFilePath: string | null;
    traceDir: string | null;
    lastTotal: number;
    stuckSecs: number;
    stuckThreshold: number;

    jniHookSpecs: any[] | null;
    jniHookEvents: any[];
    jniHooksInstalled: boolean;
    enableForkHook: boolean;
    forkEvents: any[];
    forkHooksInstalled: boolean;

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
}

export function createInitialState(): AgentState {
    return {
        soPattern: null, exportName: null, methodName: null,
        fnOffset: null, cmdValue: null, cmdArg: null, pkg: null,
        target: null, fnHooked: false, excluded: false, fnEntered: false,

        includeSoPatterns: [], includeRanges: [],
        deepTrace: false, stalkerExcludePatterns: null, boundaryDiffPatterns: null,

        cm: null, onInsnPtr: null,
        ringBuf: null, headBuf: null, tailBuf: null, droppedBuf: null, ringRecsBuf: null,
        maxRecords: 0, maxRecordsBuf: null,

        simdSidecar: false, simdSampleStride: 1,
        simdRingBuf: null, simdHeadBuf: null, simdTailBuf: null,
        simdDroppedBuf: null, simdRingRecsBuf: null, simdStrideBuf: null,
        simdTraceFile: null, simdTraceFilePath: null,

        semanticEvents: false, semanticEventBuf: [], semanticHooksInstalled: false,
        semanticEventSeq: 0, onSvcEventCb: null,

        flushTimer: null, hbTimer: null, batchSeq: 0, started: 0,
        callIdx: 0, primaryTid: 0,
        traceFile: null, traceFilePath: null, traceDir: null,
        lastTotal: 0, stuckSecs: 0, stuckThreshold: 15,

        jniHookSpecs: null, jniHookEvents: [], jniHooksInstalled: false,
        enableForkHook: false, forkEvents: [], forkHooksInstalled: false,

        diffSyms: [], diffSymAddrs: {}, boundaryHooksInstalled: false,
        extWriteEvents: [], writableRanges: null,

        rwxMapsHidden: false, suicidePatched: false,
        suicidePatchSpec: null, patchSuicide: false, hideRwxMaps: false,
    };
}

/** Singleton state */
export const STATE: AgentState = createInitialState();
