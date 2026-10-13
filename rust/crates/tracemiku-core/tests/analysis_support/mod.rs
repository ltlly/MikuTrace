//! Synthetic-fixture adapter for typed core queries; no runtime transport.
#![allow(dead_code)]
use serde_json::Value;
use tracemiku_core::analysis::{self, AnalysisContext, AnalysisError, Query};

pub struct QueryResult(Result<Value, AnalysisError>);
impl QueryResult {
    pub fn error_code(&self) -> Option<&'static str> {
        self.0.as_ref().err().map(|e| e.code)
    }
    pub fn bytes(&self) -> Vec<u8> {
        let value = match &self.0 {
            Ok(v) => v.clone(),
            Err(e) => {
                serde_json::json!({"status":"error", "error":e.message, "code":e.code, "details":e.details})
            }
        };
        serde_json::to_vec(&value).unwrap()
    }
}
pub fn query(
    context: &AnalysisContext,
    query: impl AsRef<str>,
    payload: Option<Vec<u8>>,
) -> QueryResult {
    let result = (|| {
        let (name, fields) = query
            .as_ref()
            .split_once('?')
            .unwrap_or((query.as_ref(), ""));
        fn args<T: serde::de::DeserializeOwned>(fields: &str) -> Result<T, AnalysisError> {
            serde_urlencoded::from_str(fields).map_err(|e| AnalysisError::invalid(e.to_string()))
        }
        let request = if let Some(idx) = name.strip_prefix("record/") {
            Query::Record(
                idx.parse()
                    .map_err(|_| AnalysisError::invalid("invalid record index"))?,
            )
        } else {
            match name {
                "meta" => Query::Meta,
                "analysis-index" => Query::AnalysisIndex,
                "so-stats" => Query::SoStats(args(fields)?),
                "reg-at" => Query::RegAt(args(fields)?),
                "trace-replay" => Query::TraceReplay(args(fields)?),
                "coverage" => Query::Coverage(args(fields)?),
                "resolve" => Query::Resolve(args(fields)?),
                "indirect-targets" => Query::IndirectTargets(args(fields)?),
                "records" => Query::Records(args(fields)?),
                "search" => Query::Search(args(fields)?),
                "crypto-scan" => Query::CryptoScan,
                "crypto-analysis" => Query::CryptoAnalysis,
                "watchpoints" => Query::Watchpoints(args(fields)?),
                "hash-finalize-detect" => Query::HashFinalizeDetect(args(fields)?),
                "hash-input-search" => Query::HashInputSearch(
                    serde_json::from_slice(&payload.unwrap_or_default())
                        .map_err(|e| AnalysisError::invalid(e.to_string()))?,
                ),
                "diff-traces" => Query::DiffTraces(
                    serde_json::from_slice(&payload.unwrap_or_default())
                        .map_err(|e| AnalysisError::invalid(e.to_string()))?,
                ),
                "auto-phase-detect" => Query::AutoPhaseDetect(args(fields)?),
                "dep-graph" => Query::DepGraph(args(fields)?),
                "forward-dep-tree" => Query::ForwardDepTree(args(fields)?),
                "bfs-slice" => Query::BfsSlice(args(fields)?),
                "jni-events" => Query::JniEvents(args(fields)?),
                "jni-calls" => Query::JniCalls(args(fields)?),
                "jobj-history" => Query::JobjHistory(args(fields)?),
                "jni-strings" => Query::JniStrings(args(fields)?),
                "idxs-for-pc" => Query::IdxsForPc(args(fields)?),
                "idxs-for-block" => Query::IdxsForBlock(args(fields)?),
                "cfg" => Query::Cfg(args(fields)?),
                "block-for-pc" => Query::BlockForPc(args(fields)?),
                "block" => Query::Block(args(fields)?),
                "loops" => Query::Loops,
                "backtrace" => Query::Backtrace(args(fields)?),
                "call-chain" => Query::CallChain(args(fields)?),
                "call-tree" => Query::CallTree(args(fields)?),
                "fn-summary" => Query::FnSummary(args(fields)?),
                "functions" => Query::Functions,
                "fork-events" => Query::ForkEvents(args(fields)?),
                "ollvm-detect-vm" => Query::OllvmDetectVm(args(fields)?),
                "last-write-of-reg" => Query::LastWriteOfReg(args(fields)?),
                "next-use-of-reg" => Query::NextUseOfReg(args(fields)?),
                "reg-value-at" => Query::RegValueAt(args(fields)?),
                "forward-taint" => Query::ForwardTaint(args(fields)?),
                "backward-taint" => Query::BackwardTaint(args(fields)?),
                "data-chase" => Query::DataChase(args(fields)?),
                "reg-timeline" => Query::RegTimeline(args(fields)?),
                "mem-diff" => Query::MemDiff(args(fields)?),
                "mem-flow" => Query::MemFlow(args(fields)?),
                "strings" => Query::Strings(args(fields)?),
                "string-provenance" => Query::StringProvenance(args(fields)?),
                "mem-dump" => Query::MemDump(args(fields)?),
                "mem-export" => Query::MemExport(args(fields)?),
                "last-write-of-addr" => Query::LastWriteOfAddr(args(fields)?),
                "mem-writes-in-range" => Query::MemWritesInRange(args(fields)?),
                "idxs-touching-range" => Query::IdxsTouchingRange(args(fields)?),
                "idxs-touching-addr" => Query::IdxsTouchingAddr(args(fields)?),
                "find-mem-pattern" => Query::FindMemPattern(args(fields)?),
                _ => {
                    return Err(AnalysisError::invalid(format!(
                        "unknown fixture query: {name}"
                    )))
                }
            }
        };
        analysis::execute(context, request)
    })();
    QueryResult(result)
}
