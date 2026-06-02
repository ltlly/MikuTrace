//! CALLOTHER extension point — syscalls, JNI, and platform operations.
//!
//! Mirrors Ghidra's CALLOTHER pcode op: an opaque call-like operation with
//! known semantics that can be rendered with meaningful names instead of raw
//! addresses or opcodes.
//!
//! ## Opcode space
//! - `0x0000_0000` – `0x3FFF_FFFF`: Linux ARM64 syscall numbers (raw syscall
//!   nr as defined in `<asm/unistd.h>`).
//! - `0x4000_0000` – `0x7FFF_FFFF`: JNI function IDs (`0x4000_0000 + JNI
//!   function index`).
//! - `0x8000_0000` – `0xFFFF_FFFF`: platform / runtime / user-defined ops.

use std::collections::HashMap;

// --- Registry entry ----------------------------------------------------------

/// Descriptor for a single CALLOTHER operation.
#[derive(Debug, Clone)]
pub struct CallOtherHandler {
    /// Human-readable name (e.g. `"sys_mprotect"`, `"JNI::FindClass"`).
    pub name: String,
    /// Unique opcode for this operation.
    pub opcode: u32,
    /// Expected number of input operands (0 = variable / unchecked).
    pub inputs: u32,
    /// Expected number of output operands (0 = void / variable).
    pub outputs: u32,
    /// Whether the operation has externally visible side effects beyond its
    /// return value (e.g. memory writes, I/O, process state changes).
    pub side_effects: bool,
}

// --- Registry ---------------------------------------------------------------

/// A mutable registry of CALLOTHER handlers keyed by opcode.
///
/// Construct with [`CallOtherRegistry::default`] (populated with the entire
/// syscall + JNI catalogue) or [`CallOtherRegistry::empty`] for a minimal
/// starting point.
#[derive(Debug, Clone)]
pub struct CallOtherRegistry {
    handlers: HashMap<u32, CallOtherHandler>,
}

impl CallOtherRegistry {
    /// Create an empty registry.
    pub fn empty() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler.  Replaces any existing entry for the same opcode.
    pub fn register(&mut self, handler: CallOtherHandler) {
        self.handlers.insert(handler.opcode, handler);
    }

    /// Look up a handler by opcode.
    pub fn lookup(&self, opcode: u32) -> Option<&CallOtherHandler> {
        self.handlers.get(&opcode)
    }

    /// Number of registered handlers.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// True when no handlers are registered.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

impl Default for CallOtherRegistry {
    /// Returns a registry pre-populated with all known syscall and JNI
    /// handlers.
    fn default() -> Self {
        let mut reg = Self::empty();
        register_syscall_handlers(&mut reg);
        register_jni_handlers(&mut reg);
        reg
    }
}

// --- Syscall catalogue (Linux ARM64) -----------------------------------------

/// Register Linux ARM64 syscall handlers.
///
/// Opcodes are the raw syscall numbers.  Names follow the `sys_` prefix
/// convention from the kernel source (`include/linux/syscalls.h`).
pub fn register_syscall_handlers(registry: &mut CallOtherRegistry) {
    // -- Memory management --
    sys(registry, 222, "sys_mmap", 6, 1, true);
    sys(registry, 215, "sys_munmap", 2, 1, true);
    sys(registry, 226, "sys_mprotect", 3, 1, true);
    sys(registry, 216, "sys_mremap", 5, 1, true);
    sys(registry, 214, "sys_brk", 1, 1, true);
    sys(registry, 233, "sys_madvise", 3, 1, false);
    sys(registry, 230, "sys_msync", 3, 1, true);
    sys(registry, 234, "sys_mincore", 3, 1, false);
    sys(registry, 239, "sys_mlock", 2, 1, true);
    sys(registry, 240, "sys_munlock", 2, 1, true);
    sys(registry, 241, "sys_mlockall", 1, 1, true);
    sys(registry, 242, "sys_munlockall", 0, 1, true);

    // -- File descriptors --
    sys(registry, 56, "sys_openat", 4, 1, true);
    sys(registry, 57, "sys_close", 1, 1, true);
    sys(registry, 63, "sys_read", 3, 1, true);
    sys(registry, 64, "sys_write", 3, 1, true);
    sys(registry, 65, "sys_readv", 3, 1, true);
    sys(registry, 66, "sys_writev", 3, 1, true);
    sys(registry, 67, "sys_pread64", 4, 1, true);
    sys(registry, 68, "sys_pwrite64", 4, 1, true);
    sys(registry, 72, "sys_fcntl", 3, 1, true);
    sys(registry, 73, "sys_flock", 2, 1, true);
    sys(registry, 74, "sys_fsync", 1, 1, true);
    sys(registry, 75, "sys_fdatasync", 1, 1, true);
    sys(registry, 79, "sys_fstatfs", 2, 1, false);
    sys(registry, 80, "sys_fstat", 2, 1, false);
    sys(registry, 46, "sys_ftruncate", 2, 1, true);
    sys(registry, 49, "sys_lseek", 3, 1, false);

    // -- Filesystem / path --
    sys(registry, 34, "sys_mkdirat", 3, 1, true);
    sys(registry, 35, "sys_unlinkat", 3, 1, true);
    sys(registry, 36, "sys_symlinkat", 3, 1, true);
    sys(registry, 37, "sys_linkat", 5, 1, true);
    sys(registry, 38, "sys_renameat", 4, 1, true);
    sys(registry, 191, "sys_statfs", 2, 1, false);
    sys(registry, 192, "sys_fstatfs", 2, 1, false); // 0xc0, actual statfs on arm64

    // -- Stat family --
    sys(registry, 291, "sys_statx", 5, 1, false);

    // -- Process / thread --
    sys(registry, 93, "sys_exit", 1, 0, true);
    sys(registry, 94, "sys_exit_group", 1, 0, true);
    sys(registry, 129, "sys_kill", 2, 1, true);
    sys(registry, 130, "sys_tkill", 1, 1, true);
    sys(registry, 131, "sys_tgkill", 3, 1, true);
    sys(registry, 165, "sys_getpid", 0, 1, false);
    sys(registry, 166, "sys_getppid", 0, 1, false);
    sys(registry, 167, "sys_getuid", 0, 1, false);
    sys(registry, 168, "sys_geteuid", 0, 1, false);
    sys(registry, 169, "sys_getgid", 0, 1, false);
    sys(registry, 170, "sys_getegid", 0, 1, false);
    sys(registry, 171, "sys_gettid", 0, 1, false);
    sys(registry, 174, "sys_setsid", 0, 1, true);
    sys(registry, 178, "sys_getpgid", 1, 1, false);
    sys(registry, 134, "sys_sigaction", 3, 1, true);
    sys(registry, 135, "sys_sigprocmask", 3, 1, true);
    sys(registry, 137, "sys_rt_sigreturn", 0, 0, true);
    sys(registry, 138, "sys_rt_sigaction", 4, 1, true);
    sys(registry, 139, "sys_rt_sigprocmask", 4, 1, true);

    // -- Clone / fork --
    sys(registry, 220, "sys_clone", 5, 1, true);
    sys(registry, 260, "sys_wait4", 4, 1, true);
    sys(registry, 261, "sys_prctl", 5, 1, true);

    // -- Futex --
    sys(registry, 98, "sys_futex", 6, 1, true);

    // -- Nano-sleep / clock --
    sys(registry, 101, "sys_nanosleep", 2, 1, true);
    sys(registry, 113, "sys_clock_gettime", 2, 1, false);
    sys(registry, 114, "sys_clock_getres", 2, 1, false);
    sys(registry, 115, "sys_clock_nanosleep", 4, 1, true);
    sys(registry, 118, "sys_gettimeofday", 2, 1, false);

    // -- IPC / pipe --
    sys(registry, 59, "sys_pipe2", 2, 1, true);

    // -- Socket / networking --
    sys(registry, 198, "sys_socket", 3, 1, true);
    sys(registry, 199, "sys_socketpair", 4, 1, true);
    sys(registry, 200, "sys_bind", 3, 1, true);
    sys(registry, 201, "sys_listen", 2, 1, true);
    sys(registry, 202, "sys_accept", 3, 1, true);
    sys(registry, 203, "sys_connect", 3, 1, true);
    sys(registry, 204, "sys_getsockname", 3, 1, false);
    sys(registry, 205, "sys_getpeername", 3, 1, false);
    sys(registry, 206, "sys_sendto", 6, 1, true);
    sys(registry, 207, "sys_recvfrom", 6, 1, true);
    sys(registry, 208, "sys_setsockopt", 5, 1, true);
    sys(registry, 209, "sys_getsockopt", 5, 1, false);
    sys(registry, 210, "sys_shutdown", 2, 1, true);
    sys(registry, 211, "sys_sendmsg", 3, 1, true);
    sys(registry, 212, "sys_recvmsg", 3, 1, true);

    // -- epoll --
    sys(registry, 20, "sys_epoll_create1", 1, 1, true);
    sys(registry, 21, "sys_epoll_ctl", 4, 1, true);
    sys(registry, 22, "sys_epoll_pwait", 6, 1, true);

    // -- Inotify --
    sys(registry, 27, "sys_inotify_init1", 1, 1, true);
    sys(registry, 28, "sys_inotify_add_watch", 3, 1, true);
    sys(registry, 29, "sys_inotify_rm_watch", 2, 1, true);

    // -- Eventfd / signalfd / timerfd --
    sys(registry, 16, "sys_eventfd2", 2, 1, true);
    sys(registry, 5, "sys_signalfd4", 4, 1, true);
    sys(registry, 88, "sys_timerfd_create", 2, 1, true);
    sys(registry, 89, "sys_timerfd_settime", 4, 1, true);
    sys(registry, 90, "sys_timerfd_gettime", 2, 1, false);

    // -- Misc --
    sys(registry, 0, "sys_io_setup", 2, 1, true);
    sys(registry, 1, "sys_io_destroy", 1, 1, true);
    sys(registry, 2, "sys_io_submit", 3, 1, true);
    sys(registry, 135, "sys_sigaltstack", 2, 1, true);
    sys(registry, 278, "sys_getrandom", 3, 1, false);
    sys(registry, 179, "sys_sched_yield", 0, 1, false);
    sys(registry, 180, "sys_sched_getaffinity", 3, 1, false);
    sys(registry, 181, "sys_sched_setaffinity", 3, 1, true);
    sys(registry, 157, "sys_prlimit64", 4, 1, true);
    sys(registry, 221, "sys_execve", 3, 0, true);
    sys(registry, 281, "sys_execveat", 5, 0, true);
    sys(registry, 160, "sys_getcwd", 2, 1, false);
    sys(registry, 161, "sys_chdir", 1, 1, true);
    sys(registry, 106, "sys_sysinfo", 1, 1, false);
    sys(registry, 132, "sys_utimes", 2, 1, true);
    sys(registry, 25, "sys_faccessat", 3, 1, false);
    sys(registry, 26, "sys_fchmodat", 3, 1, true);
    sys(registry, 53, "sys_fchownat", 5, 1, true);
    sys(registry, 270, "sys_process_vm_readv", 6, 1, true);
    sys(registry, 271, "sys_process_vm_writev", 6, 1, true);
    sys(registry, 273, "sys_membarrier", 3, 1, true);

    // -- Android-specific / bionic extras --
    sys(registry, 424, "sys_set_robust_list", 2, 1, true);
    sys(registry, 99, "sys_set_robust_list", 2, 1, true);
    sys(registry, 425, "sys_get_robust_list", 3, 1, false);
    sys(registry, 100, "sys_get_robust_list", 3, 1, false);
    sys(registry, 262, "sys_getcpu", 3, 1, false);
    sys(registry, 294, "sys_rseq", 4, 1, true);
}

/// Shorthand: register a syscall handler.
fn sys(reg: &mut CallOtherRegistry, nr: u32, name: &str, inputs: u32, outputs: u32, se: bool) {
    reg.register(CallOtherHandler {
        name: name.to_string(),
        opcode: nr,
        inputs,
        outputs,
        side_effects: se,
    });
}

// --- JNI catalogue -----------------------------------------------------------

/// Base opcode for JNI function entries.  Use `0x4000_0000` so they never
/// collide with real Linux syscall numbers (max ~450 on arm64).
pub const JNI_OPCODE_BASE: u32 = 0x4000_0000;

/// JNI function indices.  These are NOT pointer offsets into the JNIEnv table;
/// they are stable identifiers for the `callother_registry`.
pub mod jni_fn {
    pub const GET_VERSION: u32 = 0;
    pub const DEFINE_CLASS: u32 = 1;
    pub const FIND_CLASS: u32 = 2;
    pub const FROM_REFLECTED_METHOD: u32 = 3;
    pub const FROM_REFLECTED_FIELD: u32 = 4;
    pub const TO_REFLECTED_METHOD: u32 = 5;
    pub const GET_SUPERCLASS: u32 = 6;
    pub const IS_ASSIGNABLE_FROM: u32 = 7;
    pub const TO_REFLECTED_FIELD: u32 = 8;
    pub const THROW: u32 = 9;
    pub const THROW_NEW: u32 = 10;
    pub const EXCEPTION_OCCURRED: u32 = 11;
    pub const EXCEPTION_DESCRIBE: u32 = 12;
    pub const EXCEPTION_CLEAR: u32 = 13;
    pub const FATAL_ERROR: u32 = 14;
    pub const PUSH_LOCAL_FRAME: u32 = 15;
    pub const POP_LOCAL_FRAME: u32 = 16;
    pub const NEW_GLOBAL_REF: u32 = 17;
    pub const DELETE_GLOBAL_REF: u32 = 18;
    pub const DELETE_LOCAL_REF: u32 = 19;
    pub const IS_SAME_OBJECT: u32 = 20;
    pub const NEW_LOCAL_REF: u32 = 21;
    pub const ENSURE_LOCAL_CAPACITY: u32 = 22;
    pub const ALLOC_OBJECT: u32 = 23;
    pub const NEW_OBJECT: u32 = 24;
    pub const NEW_OBJECT_V: u32 = 25;
    pub const NEW_OBJECT_A: u32 = 26;
    pub const GET_OBJECT_CLASS: u32 = 27;
    pub const IS_INSTANCE_OF: u32 = 28;
    pub const GET_METHOD_ID: u32 = 29;
    pub const CALL_OBJECT_METHOD: u32 = 30;
    pub const CALL_OBJECT_METHOD_V: u32 = 31;
    pub const CALL_OBJECT_METHOD_A: u32 = 32;
    pub const CALL_BOOLEAN_METHOD: u32 = 33;
    pub const CALL_BOOLEAN_METHOD_V: u32 = 34;
    pub const CALL_BOOLEAN_METHOD_A: u32 = 35;
    pub const CALL_BYTE_METHOD: u32 = 36;
    pub const CALL_BYTE_METHOD_V: u32 = 37;
    pub const CALL_BYTE_METHOD_A: u32 = 38;
    pub const CALL_CHAR_METHOD: u32 = 39;
    pub const CALL_CHAR_METHOD_V: u32 = 40;
    pub const CALL_CHAR_METHOD_A: u32 = 41;
    pub const CALL_SHORT_METHOD: u32 = 42;
    pub const CALL_SHORT_METHOD_V: u32 = 43;
    pub const CALL_SHORT_METHOD_A: u32 = 44;
    pub const CALL_INT_METHOD: u32 = 45;
    pub const CALL_INT_METHOD_V: u32 = 46;
    pub const CALL_INT_METHOD_A: u32 = 47;
    pub const CALL_LONG_METHOD: u32 = 48;
    pub const CALL_LONG_METHOD_V: u32 = 49;
    pub const CALL_LONG_METHOD_A: u32 = 50;
    pub const CALL_FLOAT_METHOD: u32 = 51;
    pub const CALL_FLOAT_METHOD_V: u32 = 52;
    pub const CALL_FLOAT_METHOD_A: u32 = 53;
    pub const CALL_DOUBLE_METHOD: u32 = 54;
    pub const CALL_DOUBLE_METHOD_V: u32 = 55;
    pub const CALL_DOUBLE_METHOD_A: u32 = 56;
    pub const CALL_VOID_METHOD: u32 = 57;
    pub const CALL_VOID_METHOD_V: u32 = 58;
    pub const CALL_VOID_METHOD_A: u32 = 59;
    pub const CALL_NONVIRTUAL_OBJECT_METHOD: u32 = 60;
    pub const CALL_NONVIRTUAL_OBJECT_METHOD_V: u32 = 61;
    pub const CALL_NONVIRTUAL_OBJECT_METHOD_A: u32 = 62;
    pub const CALL_NONVIRTUAL_BOOLEAN_METHOD: u32 = 63;
    pub const CALL_NONVIRTUAL_BOOLEAN_METHOD_V: u32 = 64;
    pub const CALL_NONVIRTUAL_BOOLEAN_METHOD_A: u32 = 65;
    pub const CALL_NONVIRTUAL_BYTE_METHOD: u32 = 66;
    pub const CALL_NONVIRTUAL_BYTE_METHOD_V: u32 = 67;
    pub const CALL_NONVIRTUAL_BYTE_METHOD_A: u32 = 68;
    pub const CALL_NONVIRTUAL_CHAR_METHOD: u32 = 69;
    pub const CALL_NONVIRTUAL_CHAR_METHOD_V: u32 = 70;
    pub const CALL_NONVIRTUAL_CHAR_METHOD_A: u32 = 71;
    pub const CALL_NONVIRTUAL_SHORT_METHOD: u32 = 72;
    pub const CALL_NONVIRTUAL_SHORT_METHOD_V: u32 = 73;
    pub const CALL_NONVIRTUAL_SHORT_METHOD_A: u32 = 74;
    pub const CALL_NONVIRTUAL_INT_METHOD: u32 = 75;
    pub const CALL_NONVIRTUAL_INT_METHOD_V: u32 = 76;
    pub const CALL_NONVIRTUAL_INT_METHOD_A: u32 = 77;
    pub const CALL_NONVIRTUAL_LONG_METHOD: u32 = 78;
    pub const CALL_NONVIRTUAL_LONG_METHOD_V: u32 = 79;
    pub const CALL_NONVIRTUAL_LONG_METHOD_A: u32 = 80;
    pub const CALL_NONVIRTUAL_FLOAT_METHOD: u32 = 81;
    pub const CALL_NONVIRTUAL_FLOAT_METHOD_V: u32 = 82;
    pub const CALL_NONVIRTUAL_FLOAT_METHOD_A: u32 = 83;
    pub const CALL_NONVIRTUAL_DOUBLE_METHOD: u32 = 84;
    pub const CALL_NONVIRTUAL_DOUBLE_METHOD_V: u32 = 85;
    pub const CALL_NONVIRTUAL_DOUBLE_METHOD_A: u32 = 86;
    pub const CALL_NONVIRTUAL_VOID_METHOD: u32 = 87;
    pub const CALL_NONVIRTUAL_VOID_METHOD_V: u32 = 88;
    pub const CALL_NONVIRTUAL_VOID_METHOD_A: u32 = 89;
    pub const GET_FIELD_ID: u32 = 90;
    pub const GET_OBJECT_FIELD: u32 = 91;
    pub const GET_BOOLEAN_FIELD: u32 = 92;
    pub const GET_BYTE_FIELD: u32 = 93;
    pub const GET_CHAR_FIELD: u32 = 94;
    pub const GET_SHORT_FIELD: u32 = 95;
    pub const GET_INT_FIELD: u32 = 96;
    pub const GET_LONG_FIELD: u32 = 97;
    pub const GET_FLOAT_FIELD: u32 = 98;
    pub const GET_DOUBLE_FIELD: u32 = 99;
    pub const SET_OBJECT_FIELD: u32 = 100;
    pub const SET_BOOLEAN_FIELD: u32 = 101;
    pub const SET_BYTE_FIELD: u32 = 102;
    pub const SET_CHAR_FIELD: u32 = 103;
    pub const SET_SHORT_FIELD: u32 = 104;
    pub const SET_INT_FIELD: u32 = 105;
    pub const SET_LONG_FIELD: u32 = 106;
    pub const SET_FLOAT_FIELD: u32 = 107;
    pub const SET_DOUBLE_FIELD: u32 = 108;
    pub const GET_STATIC_METHOD_ID: u32 = 109;
    pub const CALL_STATIC_OBJECT_METHOD: u32 = 110;
    pub const CALL_STATIC_OBJECT_METHOD_V: u32 = 111;
    pub const CALL_STATIC_OBJECT_METHOD_A: u32 = 112;
    pub const CALL_STATIC_BOOLEAN_METHOD: u32 = 113;
    pub const CALL_STATIC_BOOLEAN_METHOD_V: u32 = 114;
    pub const CALL_STATIC_BOOLEAN_METHOD_A: u32 = 115;
    pub const CALL_STATIC_BYTE_METHOD: u32 = 116;
    pub const CALL_STATIC_BYTE_METHOD_V: u32 = 117;
    pub const CALL_STATIC_BYTE_METHOD_A: u32 = 118;
    pub const CALL_STATIC_CHAR_METHOD: u32 = 119;
    pub const CALL_STATIC_CHAR_METHOD_V: u32 = 120;
    pub const CALL_STATIC_CHAR_METHOD_A: u32 = 121;
    pub const CALL_STATIC_SHORT_METHOD: u32 = 122;
    pub const CALL_STATIC_SHORT_METHOD_V: u32 = 123;
    pub const CALL_STATIC_SHORT_METHOD_A: u32 = 124;
    pub const CALL_STATIC_INT_METHOD: u32 = 125;
    pub const CALL_STATIC_INT_METHOD_V: u32 = 126;
    pub const CALL_STATIC_INT_METHOD_A: u32 = 127;
    pub const CALL_STATIC_LONG_METHOD: u32 = 128;
    pub const CALL_STATIC_LONG_METHOD_V: u32 = 129;
    pub const CALL_STATIC_LONG_METHOD_A: u32 = 130;
    pub const CALL_STATIC_FLOAT_METHOD: u32 = 131;
    pub const CALL_STATIC_FLOAT_METHOD_V: u32 = 132;
    pub const CALL_STATIC_FLOAT_METHOD_A: u32 = 133;
    pub const CALL_STATIC_DOUBLE_METHOD: u32 = 134;
    pub const CALL_STATIC_DOUBLE_METHOD_V: u32 = 135;
    pub const CALL_STATIC_DOUBLE_METHOD_A: u32 = 136;
    pub const CALL_STATIC_VOID_METHOD: u32 = 137;
    pub const CALL_STATIC_VOID_METHOD_V: u32 = 138;
    pub const CALL_STATIC_VOID_METHOD_A: u32 = 139;
    pub const GET_STATIC_FIELD_ID: u32 = 140;
    pub const GET_STATIC_OBJECT_FIELD: u32 = 141;
    pub const GET_STATIC_BOOLEAN_FIELD: u32 = 142;
    pub const GET_STATIC_BYTE_FIELD: u32 = 143;
    pub const GET_STATIC_CHAR_FIELD: u32 = 144;
    pub const GET_STATIC_SHORT_FIELD: u32 = 145;
    pub const GET_STATIC_INT_FIELD: u32 = 146;
    pub const GET_STATIC_LONG_FIELD: u32 = 147;
    pub const GET_STATIC_FLOAT_FIELD: u32 = 148;
    pub const GET_STATIC_DOUBLE_FIELD: u32 = 149;
    pub const SET_STATIC_OBJECT_FIELD: u32 = 150;
    pub const SET_STATIC_BOOLEAN_FIELD: u32 = 151;
    pub const SET_STATIC_BYTE_FIELD: u32 = 152;
    pub const SET_STATIC_CHAR_FIELD: u32 = 153;
    pub const SET_STATIC_SHORT_FIELD: u32 = 154;
    pub const SET_STATIC_INT_FIELD: u32 = 155;
    pub const SET_STATIC_LONG_FIELD: u32 = 156;
    pub const SET_STATIC_FLOAT_FIELD: u32 = 157;
    pub const SET_STATIC_DOUBLE_FIELD: u32 = 158;
    pub const NEW_STRING: u32 = 159;
    pub const GET_STRING_LENGTH: u32 = 160;
    pub const GET_STRING_CHARS: u32 = 161;
    pub const RELEASE_STRING_CHARS: u32 = 162;
    pub const NEW_STRING_UTF: u32 = 163;
    pub const GET_STRING_UTF_LENGTH: u32 = 164;
    pub const GET_STRING_UTF_CHARS: u32 = 165;
    pub const RELEASE_STRING_UTF_CHARS: u32 = 166;
    pub const GET_ARRAY_LENGTH: u32 = 167;
    pub const NEW_OBJECT_ARRAY: u32 = 168;
    pub const GET_OBJECT_ARRAY_ELEMENT: u32 = 169;
    pub const SET_OBJECT_ARRAY_ELEMENT: u32 = 170;
    pub const NEW_BOOLEAN_ARRAY: u32 = 171;
    pub const NEW_BYTE_ARRAY: u32 = 172;
    pub const NEW_CHAR_ARRAY: u32 = 173;
    pub const NEW_SHORT_ARRAY: u32 = 174;
    pub const NEW_INT_ARRAY: u32 = 175;
    pub const NEW_LONG_ARRAY: u32 = 176;
    pub const NEW_FLOAT_ARRAY: u32 = 177;
    pub const NEW_DOUBLE_ARRAY: u32 = 178;
    pub const GET_BOOLEAN_ARRAY_ELEMENTS: u32 = 179;
    pub const GET_BYTE_ARRAY_ELEMENTS: u32 = 180;
    pub const GET_CHAR_ARRAY_ELEMENTS: u32 = 181;
    pub const GET_SHORT_ARRAY_ELEMENTS: u32 = 182;
    pub const GET_INT_ARRAY_ELEMENTS: u32 = 183;
    pub const GET_LONG_ARRAY_ELEMENTS: u32 = 184;
    pub const GET_FLOAT_ARRAY_ELEMENTS: u32 = 185;
    pub const GET_DOUBLE_ARRAY_ELEMENTS: u32 = 186;
    pub const RELEASE_BOOLEAN_ARRAY_ELEMENTS: u32 = 187;
    pub const RELEASE_BYTE_ARRAY_ELEMENTS: u32 = 188;
    pub const RELEASE_CHAR_ARRAY_ELEMENTS: u32 = 189;
    pub const RELEASE_SHORT_ARRAY_ELEMENTS: u32 = 190;
    pub const RELEASE_INT_ARRAY_ELEMENTS: u32 = 191;
    pub const RELEASE_LONG_ARRAY_ELEMENTS: u32 = 192;
    pub const RELEASE_FLOAT_ARRAY_ELEMENTS: u32 = 193;
    pub const RELEASE_DOUBLE_ARRAY_ELEMENTS: u32 = 194;
    pub const GET_BOOLEAN_ARRAY_REGION: u32 = 195;
    pub const GET_BYTE_ARRAY_REGION: u32 = 196;
    pub const GET_CHAR_ARRAY_REGION: u32 = 197;
    pub const GET_SHORT_ARRAY_REGION: u32 = 198;
    pub const GET_INT_ARRAY_REGION: u32 = 199;
    pub const GET_LONG_ARRAY_REGION: u32 = 200;
    pub const GET_FLOAT_ARRAY_REGION: u32 = 201;
    pub const GET_DOUBLE_ARRAY_REGION: u32 = 202;
    pub const SET_BOOLEAN_ARRAY_REGION: u32 = 203;
    pub const SET_BYTE_ARRAY_REGION: u32 = 204;
    pub const SET_CHAR_ARRAY_REGION: u32 = 205;
    pub const SET_SHORT_ARRAY_REGION: u32 = 206;
    pub const SET_INT_ARRAY_REGION: u32 = 207;
    pub const SET_LONG_ARRAY_REGION: u32 = 208;
    pub const SET_FLOAT_ARRAY_REGION: u32 = 209;
    pub const SET_DOUBLE_ARRAY_REGION: u32 = 210;
    pub const REGISTER_NATIVES: u32 = 211;
    pub const UNREGISTER_NATIVES: u32 = 212;
    pub const MONITOR_ENTER: u32 = 213;
    pub const MONITOR_EXIT: u32 = 214;
    pub const GET_JAVA_VM: u32 = 215;
    pub const GET_STRING_REGION: u32 = 216;
    pub const GET_STRING_UTF_REGION: u32 = 217;
    pub const GET_PRIMITIVE_ARRAY_CRITICAL: u32 = 218;
    pub const RELEASE_PRIMITIVE_ARRAY_CRITICAL: u32 = 219;
    pub const GET_STRING_CRITICAL: u32 = 220;
    pub const RELEASE_STRING_CRITICAL: u32 = 221;
    pub const NEW_WEAK_GLOBAL_REF: u32 = 222;
    pub const DELETE_WEAK_GLOBAL_REF: u32 = 223;
    pub const EXCEPTION_CHECK: u32 = 224;
    pub const NEW_DIRECT_BYTE_BUFFER: u32 = 225;
    pub const GET_DIRECT_BUFFER_ADDRESS: u32 = 226;
    pub const GET_DIRECT_BUFFER_CAPACITY: u32 = 227;
    pub const GET_OBJECT_REF_TYPE: u32 = 228;
}

/// Register common JNI function handlers.
///
/// Opcodes are `JNI_OPCODE_BASE + jni_fn::<NAME>`.
pub fn register_jni_handlers(registry: &mut CallOtherRegistry) {
    jni(
        registry,
        jni_fn::GET_VERSION,
        "JNI::GetVersion",
        1,
        1,
        false,
    );
    jni(registry, jni_fn::FIND_CLASS, "JNI::FindClass", 2, 1, true);
    jni(
        registry,
        jni_fn::GET_SUPERCLASS,
        "JNI::GetSuperclass",
        2,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::IS_ASSIGNABLE_FROM,
        "JNI::IsAssignableFrom",
        3,
        1,
        false,
    );
    jni(registry, jni_fn::THROW, "JNI::Throw", 2, 1, true);
    jni(registry, jni_fn::THROW_NEW, "JNI::ThrowNew", 3, 1, true);
    jni(
        registry,
        jni_fn::EXCEPTION_OCCURRED,
        "JNI::ExceptionOccurred",
        1,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::EXCEPTION_DESCRIBE,
        "JNI::ExceptionDescribe",
        1,
        0,
        true,
    );
    jni(
        registry,
        jni_fn::EXCEPTION_CLEAR,
        "JNI::ExceptionClear",
        1,
        0,
        true,
    );
    jni(registry, jni_fn::FATAL_ERROR, "JNI::FatalError", 2, 0, true);
    jni(
        registry,
        jni_fn::PUSH_LOCAL_FRAME,
        "JNI::PushLocalFrame",
        2,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::POP_LOCAL_FRAME,
        "JNI::PopLocalFrame",
        2,
        1,
        true,
    );

    jni(
        registry,
        jni_fn::NEW_GLOBAL_REF,
        "JNI::NewGlobalRef",
        2,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::DELETE_GLOBAL_REF,
        "JNI::DeleteGlobalRef",
        2,
        0,
        true,
    );
    jni(
        registry,
        jni_fn::DELETE_LOCAL_REF,
        "JNI::DeleteLocalRef",
        2,
        0,
        true,
    );
    jni(
        registry,
        jni_fn::IS_SAME_OBJECT,
        "JNI::IsSameObject",
        3,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::NEW_LOCAL_REF,
        "JNI::NewLocalRef",
        2,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::ENSURE_LOCAL_CAPACITY,
        "JNI::EnsureLocalCapacity",
        2,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::ALLOC_OBJECT,
        "JNI::AllocObject",
        2,
        1,
        true,
    );
    jni(registry, jni_fn::NEW_OBJECT, "JNI::NewObject", 4, 1, true);
    jni(
        registry,
        jni_fn::NEW_OBJECT_V,
        "JNI::NewObjectV",
        4,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::NEW_OBJECT_A,
        "JNI::NewObjectA",
        4,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::GET_OBJECT_CLASS,
        "JNI::GetObjectClass",
        2,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::IS_INSTANCE_OF,
        "JNI::IsInstanceOf",
        3,
        1,
        false,
    );

    jni(
        registry,
        jni_fn::GET_METHOD_ID,
        "JNI::GetMethodID",
        4,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::CALL_OBJECT_METHOD,
        "JNI::CallObjectMethod",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::CALL_BOOLEAN_METHOD,
        "JNI::CallBooleanMethod",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::CALL_BYTE_METHOD,
        "JNI::CallByteMethod",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::CALL_CHAR_METHOD,
        "JNI::CallCharMethod",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::CALL_SHORT_METHOD,
        "JNI::CallShortMethod",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::CALL_INT_METHOD,
        "JNI::CallIntMethod",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::CALL_LONG_METHOD,
        "JNI::CallLongMethod",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::CALL_FLOAT_METHOD,
        "JNI::CallFloatMethod",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::CALL_DOUBLE_METHOD,
        "JNI::CallDoubleMethod",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::CALL_VOID_METHOD,
        "JNI::CallVoidMethod",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::CALL_NONVIRTUAL_OBJECT_METHOD,
        "JNI::CallNonvirtualObjectMethod",
        4,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::CALL_NONVIRTUAL_INT_METHOD,
        "JNI::CallNonvirtualIntMethod",
        4,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::CALL_NONVIRTUAL_VOID_METHOD,
        "JNI::CallNonvirtualVoidMethod",
        4,
        0,
        true,
    );

    jni(
        registry,
        jni_fn::GET_FIELD_ID,
        "JNI::GetFieldID",
        4,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::GET_OBJECT_FIELD,
        "JNI::GetObjectField",
        3,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::GET_INT_FIELD,
        "JNI::GetIntField",
        3,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::GET_LONG_FIELD,
        "JNI::GetLongField",
        3,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::SET_OBJECT_FIELD,
        "JNI::SetObjectField",
        3,
        0,
        true,
    );
    jni(
        registry,
        jni_fn::SET_INT_FIELD,
        "JNI::SetIntField",
        4,
        0,
        true,
    );
    jni(
        registry,
        jni_fn::SET_LONG_FIELD,
        "JNI::SetLongField",
        4,
        0,
        true,
    );

    jni(
        registry,
        jni_fn::GET_STATIC_METHOD_ID,
        "JNI::GetStaticMethodID",
        4,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::CALL_STATIC_OBJECT_METHOD,
        "JNI::CallStaticObjectMethod",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::CALL_STATIC_INT_METHOD,
        "JNI::CallStaticIntMethod",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::CALL_STATIC_LONG_METHOD,
        "JNI::CallStaticLongMethod",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::CALL_STATIC_VOID_METHOD,
        "JNI::CallStaticVoidMethod",
        3,
        0,
        true,
    );

    jni(
        registry,
        jni_fn::GET_STATIC_FIELD_ID,
        "JNI::GetStaticFieldID",
        4,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::GET_STATIC_OBJECT_FIELD,
        "JNI::GetStaticObjectField",
        3,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::GET_STATIC_INT_FIELD,
        "JNI::GetStaticIntField",
        3,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::SET_STATIC_INT_FIELD,
        "JNI::SetStaticIntField",
        4,
        0,
        true,
    );

    jni(
        registry,
        jni_fn::NEW_STRING_UTF,
        "JNI::NewStringUTF",
        2,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::GET_STRING_UTF_CHARS,
        "JNI::GetStringUTFChars",
        3,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::RELEASE_STRING_UTF_CHARS,
        "JNI::ReleaseStringUTFChars",
        3,
        0,
        true,
    );
    jni(
        registry,
        jni_fn::GET_STRING_LENGTH,
        "JNI::GetStringLength",
        2,
        1,
        false,
    );
    jni(registry, jni_fn::NEW_STRING, "JNI::NewString", 3, 1, true);

    jni(
        registry,
        jni_fn::GET_ARRAY_LENGTH,
        "JNI::GetArrayLength",
        2,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::NEW_OBJECT_ARRAY,
        "JNI::NewObjectArray",
        4,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::GET_OBJECT_ARRAY_ELEMENT,
        "JNI::GetObjectArrayElement",
        3,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::SET_OBJECT_ARRAY_ELEMENT,
        "JNI::SetObjectArrayElement",
        4,
        0,
        true,
    );
    jni(
        registry,
        jni_fn::NEW_BYTE_ARRAY,
        "JNI::NewByteArray",
        2,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::NEW_INT_ARRAY,
        "JNI::NewIntArray",
        2,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::NEW_LONG_ARRAY,
        "JNI::NewLongArray",
        2,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::GET_BYTE_ARRAY_ELEMENTS,
        "JNI::GetByteArrayElements",
        3,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::RELEASE_BYTE_ARRAY_ELEMENTS,
        "JNI::ReleaseByteArrayElements",
        4,
        0,
        true,
    );
    jni(
        registry,
        jni_fn::GET_INT_ARRAY_ELEMENTS,
        "JNI::GetIntArrayElements",
        3,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::RELEASE_INT_ARRAY_ELEMENTS,
        "JNI::ReleaseIntArrayElements",
        4,
        0,
        true,
    );
    jni(
        registry,
        jni_fn::GET_BYTE_ARRAY_REGION,
        "JNI::GetByteArrayRegion",
        4,
        0,
        false,
    );
    jni(
        registry,
        jni_fn::SET_BYTE_ARRAY_REGION,
        "JNI::SetByteArrayRegion",
        4,
        0,
        true,
    );
    jni(
        registry,
        jni_fn::GET_PRIMITIVE_ARRAY_CRITICAL,
        "JNI::GetPrimitiveArrayCritical",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::RELEASE_PRIMITIVE_ARRAY_CRITICAL,
        "JNI::ReleasePrimitiveArrayCritical",
        4,
        0,
        true,
    );

    jni(
        registry,
        jni_fn::REGISTER_NATIVES,
        "JNI::RegisterNatives",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::UNREGISTER_NATIVES,
        "JNI::UnregisterNatives",
        2,
        1,
        true,
    );

    jni(
        registry,
        jni_fn::MONITOR_ENTER,
        "JNI::MonitorEnter",
        2,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::MONITOR_EXIT,
        "JNI::MonitorExit",
        2,
        1,
        true,
    );

    jni(registry, jni_fn::GET_JAVA_VM, "JNI::GetJavaVM", 2, 1, false);

    jni(
        registry,
        jni_fn::NEW_DIRECT_BYTE_BUFFER,
        "JNI::NewDirectByteBuffer",
        3,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::GET_DIRECT_BUFFER_ADDRESS,
        "JNI::GetDirectBufferAddress",
        2,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::GET_DIRECT_BUFFER_CAPACITY,
        "JNI::GetDirectBufferCapacity",
        2,
        1,
        false,
    );

    jni(
        registry,
        jni_fn::NEW_WEAK_GLOBAL_REF,
        "JNI::NewWeakGlobalRef",
        2,
        1,
        true,
    );
    jni(
        registry,
        jni_fn::DELETE_WEAK_GLOBAL_REF,
        "JNI::DeleteWeakGlobalRef",
        2,
        0,
        true,
    );
    jni(
        registry,
        jni_fn::EXCEPTION_CHECK,
        "JNI::ExceptionCheck",
        1,
        1,
        false,
    );
    jni(
        registry,
        jni_fn::GET_OBJECT_REF_TYPE,
        "JNI::GetObjectRefType",
        1,
        1,
        false,
    );
}

/// Shorthand: register a JNI handler.
fn jni(reg: &mut CallOtherRegistry, idx: u32, name: &str, inputs: u32, outputs: u32, se: bool) {
    reg.register(CallOtherHandler {
        name: name.to_string(),
        opcode: JNI_OPCODE_BASE + idx,
        inputs,
        outputs,
        side_effects: se,
    });
}

// --- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_mmap_lookup() {
        let reg = CallOtherRegistry::default();
        let h = reg.lookup(222).expect("sys_mmap should exist");
        assert_eq!(h.name, "sys_mmap");
        assert_eq!(h.inputs, 6);
        assert_eq!(h.outputs, 1);
        assert!(h.side_effects);
    }

    #[test]
    fn syscall_exit_no_output() {
        let reg = CallOtherRegistry::default();
        let h = reg.lookup(93).expect("sys_exit should exist");
        assert_eq!(h.name, "sys_exit");
        assert_eq!(h.outputs, 0);
        assert!(h.side_effects);
    }

    #[test]
    fn syscall_gettid_read_only() {
        let reg = CallOtherRegistry::default();
        let h = reg
            .lookup(171)
            .expect("sys_gettid should exist at opcode 171");
        assert_eq!(h.name, "sys_gettid");
        assert!(!h.side_effects);
    }

    #[test]
    fn jni_findclass_lookup() {
        let reg = CallOtherRegistry::default();
        let opcode = JNI_OPCODE_BASE + jni_fn::FIND_CLASS;
        let h = reg.lookup(opcode).expect("JNI::FindClass should exist");
        assert_eq!(h.name, "JNI::FindClass");
        assert_eq!(h.inputs, 2);
        assert_eq!(h.outputs, 1);
        assert!(h.side_effects);
    }

    #[test]
    fn jni_get_static_method_id() {
        let reg = CallOtherRegistry::default();
        let opcode = JNI_OPCODE_BASE + jni_fn::GET_STATIC_METHOD_ID;
        let h = reg
            .lookup(opcode)
            .expect("JNI::GetStaticMethodID should exist");
        assert_eq!(h.name, "JNI::GetStaticMethodID");
        assert_eq!(h.inputs, 4);
        assert!(!h.side_effects);
    }

    #[test]
    fn missing_opcode() {
        let reg = CallOtherRegistry::default();
        assert!(reg.lookup(9999).is_none());
        assert!(reg.lookup(JNI_OPCODE_BASE + 999).is_none());
    }

    #[test]
    fn empty_registry() {
        let reg = CallOtherRegistry::empty();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(reg.lookup(222).is_none());
    }

    #[test]
    fn default_registry_is_populated() {
        let reg = CallOtherRegistry::default();
        assert!(reg.len() > 50);
    }

    #[test]
    fn syscall_and_jni_namespaces_do_not_collide() {
        let reg = CallOtherRegistry::default();
        // syscalls live at their raw number
        let sys = reg.lookup(57).expect("close should exist");
        assert_eq!(sys.name, "sys_close");
        // JNI lives at base + index
        let jni = reg.lookup(JNI_OPCODE_BASE + jni_fn::FIND_CLASS);
        assert!(jni.is_some());
        // JNI_OPCODE_BASE - 1 has no entry (max ARM64 syscall ~450 << 0x4000_0000)
        assert!(reg.lookup(JNI_OPCODE_BASE - 1).is_none());
    }
}
