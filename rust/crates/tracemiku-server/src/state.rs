use std::path::PathBuf;
use std::sync::Arc;

use tracemiku_core::prelude::TraceMeta;

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppStateInner>,
}

pub struct AppStateInner {
    pub trace_dir: PathBuf,
    pub meta: TraceMeta,
}

impl AppState {
    pub fn load(trace_dir: PathBuf) -> anyhow::Result<Self> {
        let meta = TraceMeta::load(&trace_dir)?;
        Ok(Self {
            inner: Arc::new(AppStateInner { trace_dir, meta }),
        })
    }
}
