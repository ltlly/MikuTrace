//! Thread-local FIFO cache over [`raw_decode`]. Capacity matches Python's
//! `@lru_cache(maxsize=200000)`. FIFO instead of true LRU — simpler and
//! behaviorally equivalent on trace-walk workloads where every distinct PC
//! is decoded once per scan.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

use crate::disasm::decoder::{raw_decode, DecodedInsn};

const CAP: usize = 200_000;

struct Cache {
    /// 键为 `(pc, inst)` 元组。旧实现用 `(pc << 32) | inst` 打包成 u64，
    /// 会丢弃 PC 的高 32 位，导致 ARM64 高位地址（PAC/高位栈，如
    /// 0x1_0000_0000 以上）之间互相串缓存。
    map: HashMap<(u64, u32), DecodedInsn>,
    /// FIFO queue of keys in insertion order; oldest at front.
    order: VecDeque<(u64, u32)>,
}

impl Cache {
    fn new() -> Self {
        Self {
            map: HashMap::with_capacity(CAP),
            order: VecDeque::with_capacity(CAP),
        }
    }

    fn get_or_insert(&mut self, pc: u64, inst: u32) -> DecodedInsn {
        let key = (pc, inst);
        if let Some(v) = self.map.get(&key) {
            return v.clone();
        }
        let d = raw_decode(pc, inst);
        if self.map.len() >= CAP {
            // FIFO evict oldest.
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
        self.map.insert(key, d.clone());
        self.order.push_back(key);
        d
    }
}

thread_local! {
    static CACHE: RefCell<Cache> = RefCell::new(Cache::new());
}

/// Cached decode — looks up `(pc, inst)` in the per-thread FIFO buffer
/// (200k entries) and falls through to [`raw_decode`] on miss.
pub fn decode(pc: u64, inst: u32) -> DecodedInsn {
    CACHE.with(|c| c.borrow_mut().get_or_insert(pc, inst))
}
