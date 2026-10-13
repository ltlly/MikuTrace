//! 采集到的进程分叉事件。

use serde::{Deserialize, Serialize};

use crate::analysis::context::AnalysisContext;

#[derive(Debug, Deserialize)]
pub struct ForkEventsQuery {
    pub status: Option<String>,
    pub is_fork_like: Option<bool>,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    1_000
}

const MAX_LIMIT: usize = 5_000;

#[derive(Debug, Serialize)]
pub struct ForkEventsResponse {
    pub count: usize,
    pub returned: usize,
    pub truncated: bool,
    pub events: Vec<serde_json::Value>,
}

pub fn fork_events(state: &AnalysisContext, q: ForkEventsQuery) -> ForkEventsResponse {
    let limit = q.limit.min(MAX_LIMIT);
    let mut count = 0usize;
    let mut events = Vec::new();
    for ev in state
        .inner
        .meta
        .fork_events
        .iter()
        .filter(|ev| match q.status.as_deref() {
            Some(status) => ev
                .get("attach_status")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s == status),
            None => true,
        })
        .filter(|ev| match q.is_fork_like {
            Some(want) => ev
                .get("is_fork_like")
                .and_then(|v| v.as_bool())
                .is_some_and(|v| v == want),
            None => true,
        })
    {
        count += 1;
        if events.len() < limit {
            events.push(ev.clone());
        }
    }
    let returned = events.len();
    ForkEventsResponse {
        count,
        returned,
        truncated: returned < count,
        events,
    }
}

impl Default for ForkEventsQuery {
    fn default() -> Self {
        Self {
            status: Default::default(),
            is_fork_like: Default::default(),
            limit: default_limit(),
        }
    }
}
