//! Shared worker-count planning for CPU-heavy trace scans.

use std::sync::{Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
struct BuildGateState {
    active: usize,
}

/// Process-local gate; a per-trace file lock in AnalysisContext also covers
/// independent CLI processes.
#[derive(Debug, Default)]
pub struct BuildGate {
    state: Mutex<BuildGateState>,
    ready: Condvar,
}

#[derive(Debug)]
pub struct BuildGatePermit<'a> {
    gate: &'a BuildGate,
}

impl BuildGate {
    pub fn acquire(
        &self,
        maximum: usize,
        wait: Duration,
    ) -> Result<BuildGatePermit<'_>, BuildLimit> {
        let maximum = maximum.max(1);
        let deadline = Instant::now() + wait;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if state.active < maximum {
                state.active += 1;
                return Ok(BuildGatePermit { gate: self });
            }
            if wait.is_zero() || Instant::now() >= deadline {
                return Err(BuildLimit {
                    component: "concurrent_builds",
                    estimated_bytes: state.active.saturating_add(1),
                    budget_bytes: maximum,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let (next, timeout) = self
                .ready
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
            if timeout.timed_out() && state.active >= maximum {
                return Err(BuildLimit {
                    component: "concurrent_builds",
                    estimated_bytes: state.active.saturating_add(1),
                    budget_bytes: maximum,
                });
            }
        }
    }
}

impl Drop for BuildGatePermit<'_> {
    fn drop(&mut self) {
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active = state.active.saturating_sub(1);
        self.gate.ready.notify_one();
    }
}

static GLOBAL_BUILD_GATE: OnceLock<BuildGate> = OnceLock::new();

pub fn global_build_gate() -> &'static BuildGate {
    GLOBAL_BUILD_GATE.get_or_init(BuildGate::default)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildLimit {
    pub component: &'static str,
    pub estimated_bytes: usize,
    pub budget_bytes: usize,
}

pub fn check_memory_budget(
    component: &'static str,
    estimated_bytes: usize,
    budget_bytes: usize,
) -> Result<(), BuildLimit> {
    if estimated_bytes > budget_bytes {
        Err(BuildLimit {
            component,
            estimated_bytes,
            budget_bytes,
        })
    } else {
        Ok(())
    }
}

/// Planned worker count for a component scan over `records` trace records.
///
/// A component-specific env var such as `TRACEMIKU_INDEX_THREADS` wins over
/// the global `TRACEMIKU_ANALYSIS_THREADS`. Explicit env requests bypass the
/// default records-per-worker cap so users can force full-core startup scans
/// on mid-sized traces when latency matters more than thread overhead.
pub fn worker_count(
    records: usize,
    component_env: &str,
    parallel_min_records: usize,
    min_chunk_records: usize,
) -> usize {
    let requested =
        env_thread_count(component_env).or_else(|| env_thread_count("TRACEMIKU_ANALYSIS_THREADS"));
    let available = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    worker_count_with(
        records,
        requested,
        available,
        parallel_min_records,
        min_chunk_records,
    )
}

fn env_thread_count(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&v| v > 0)
}

fn worker_count_with(
    records: usize,
    requested: Option<usize>,
    available: usize,
    parallel_min_records: usize,
    min_chunk_records: usize,
) -> usize {
    if let Some(requested) = requested {
        return requested.min(available).min(records.max(1)).max(1);
    }
    if available <= 1 || records < parallel_min_records {
        return 1;
    }
    let chunk_cap = records.div_ceil(min_chunk_records).max(1);
    available.min(chunk_cap).max(1)
}

#[cfg(test)]
mod tests {
    use super::worker_count_with;

    #[test]
    fn default_count_is_capped_by_chunk_size() {
        assert_eq!(worker_count_with(469_639, None, 16, 250_000, 200_000), 3);
    }

    #[test]
    fn explicit_count_bypasses_chunk_cap() {
        assert_eq!(
            worker_count_with(469_639, Some(16), 16, 250_000, 200_000),
            16
        );
    }

    #[test]
    fn explicit_count_is_bounded_by_record_count() {
        assert_eq!(worker_count_with(4, Some(16), 16, 250_000, 200_000), 4);
    }

    #[test]
    fn explicit_count_is_capped_by_available_parallelism() {
        assert_eq!(worker_count_with(100_000, Some(1024), 4, 1, 1), 4);
    }

    #[test]
    fn memory_budget_reports_component_and_sizes() {
        let error = super::check_memory_budget("cfg", 101, 100).unwrap_err();
        assert_eq!(error.component, "cfg");
        assert_eq!(error.estimated_bytes, 101);
        assert_eq!(error.budget_bytes, 100);
        assert!(super::check_memory_budget("memshadow", 100, 100).is_ok());
    }

    #[test]
    fn build_gate_limits_and_releases_permits() {
        let gate = super::BuildGate::default();
        let first = gate.acquire(1, std::time::Duration::ZERO).unwrap();
        let error = gate.acquire(1, std::time::Duration::ZERO).unwrap_err();
        assert_eq!(error.component, "concurrent_builds");
        drop(first);
        let _second = gate.acquire(1, std::time::Duration::ZERO).unwrap();
    }

    #[test]
    fn default_count_keeps_small_traces_single_threaded() {
        assert_eq!(worker_count_with(20_000, None, 16, 250_000, 200_000), 1);
    }
}
