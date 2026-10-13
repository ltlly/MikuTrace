//! 根据调用与返回配对构建调用树。

use super::AnalysisError;
use serde::{Deserialize, Serialize};

use crate::prelude::CallNode;

use crate::analysis::context::AnalysisContext;

const DEFAULT_MAX_DEPTH: usize = 50;
const MAX_CALL_TREE_DEPTH: usize = 256;

#[derive(Debug, Deserialize, Default)]
pub struct CallTreeQuery {
    pub max_depth: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct CallTreeResponse {
    pub tree: CallNode,
}

fn effective_max_depth(raw: Option<usize>) -> usize {
    raw.unwrap_or(DEFAULT_MAX_DEPTH).min(MAX_CALL_TREE_DEPTH)
}

pub fn call_tree(
    state: &AnalysisContext,
    q: CallTreeQuery,
) -> Result<CallTreeResponse, AnalysisError> {
    let inner = state.inner.clone();
    let depth = effective_max_depth(q.max_depth);
    let tree = inner.call_tree_for_depth(depth);
    Ok(CallTreeResponse { tree })
}

#[cfg(test)]
mod tests {
    use super::{effective_max_depth, DEFAULT_MAX_DEPTH, MAX_CALL_TREE_DEPTH};

    #[test]
    fn effective_max_depth_caps_extreme_requests() {
        assert_eq!(effective_max_depth(None), DEFAULT_MAX_DEPTH);
        assert_eq!(effective_max_depth(Some(0)), 0);
        assert_eq!(effective_max_depth(Some(5)), 5);
        assert_eq!(effective_max_depth(Some(usize::MAX)), MAX_CALL_TREE_DEPTH);
    }
}
