//! Shared worker-count planning for CPU-heavy trace scans.

use std::thread;

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
        return requested.min(records.max(1)).max(1);
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
    fn default_count_keeps_small_traces_single_threaded() {
        assert_eq!(worker_count_with(20_000, None, 16, 250_000, 200_000), 1);
    }
}
