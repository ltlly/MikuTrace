use std::path::PathBuf;
use std::sync::Arc;

use tracemiku_core::prelude::{Trace, TraceMeta};

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppStateInner>,
}

pub struct AppStateInner {
    pub trace_dir: PathBuf,
    pub meta: TraceMeta,
    /// Loaded eagerly at startup. Mmap is cheap (constant time); bumping it
    /// to lazy would add Mutex/RwLock complexity for no perf win.
    pub trace: Trace,
}

impl AppState {
    pub fn load(trace_dir: PathBuf) -> anyhow::Result<Self> {
        let meta = TraceMeta::load(&trace_dir)?;
        let trace = Trace::load(&trace_dir)?;
        Ok(Self {
            inner: Arc::new(AppStateInner {
                trace_dir,
                meta,
                trace,
            }),
        })
    }
}
