//! 类型化分析请求。CLI 只负责构造参数，查询语义位于各分析模块。
use super::*;
use serde_json::Value;

#[derive(Debug)]
pub enum Query {
    CfgInspect(cfg::CfgInspectQuery),
    FunctionsInspect(functions::FunctionsQuery),
    BacktraceInspect(navigation::BacktraceInspectQuery),
    MemAccesses(mem_accesses::MemAccessesQuery),
    MemProvenance(mem_provenance::MemProvenanceQuery),
    Dependencies(dependency_query::DependencyQuery),
    JniInspect(jni_calls::JniInspectQuery),
    RegInspect(timeline_diff::RegInspectQuery),

    Meta,
    AnalysisIndex,
    SoStats(so_stats::SoStatsQuery),
    RegAt(reg_at::RegAtQuery),
    TraceReplay(trace_replay::ReplayQuery),
    Coverage(coverage::CoverageQuery),
    Resolve(resolve::ResolveQuery),
    IndirectTargets(indirect_targets::IndirectTargetsQuery),
    Records(records::RecordsQuery),
    Record(usize),
    Search(search::SearchQuery),
    CryptoAnalysis,
    IdxsForPc(idxs_for_pc::IdxsForPcQuery),
    IdxsForBlock(idxs_for_block::IdxsForBlockQuery),
    Cfg(cfg::CfgQuery),
    Block(navigation::PcQuery),
    Loops,
    Backtrace(navigation::BacktraceQuery),
    CallChain(navigation::CallChainQuery),
    CallTree(call_tree::CallTreeQuery),
    FnSummary(fn_summary::FnSummaryQuery),
    Functions,
    LastWriteOfReg(last_write_of_reg::LastWriteQuery),
    NextUseOfReg(next_use_of_reg::NextUseQuery),
    ForwardTaint(forward_taint::ForwardTaintQuery),
    BackwardTaint(backward_taint::BackwardTaintQuery),
    RegTimeline(timeline_diff::RegTimelineQuery),
    Strings(strings::StringsQuery),
    StringProvenance(string_provenance::StringProvenanceQuery),
    MemDump(mem_dump::MemDumpQuery),
    LastWriteOfAddr(memory_query::LastWriteOfAddrQuery),
    MemWritesInRange(memory_query::MemWritesInRangeQuery),
    IdxsTouchingRange(memory_query::TouchingRangeQuery),
    IdxsTouchingAddr(memory_query::TouchingAddrQuery),
    FindMemPattern(memory_query::FindMemPatternQuery),
}

pub fn execute(context: &AnalysisContext, query: Query) -> Result<Value, AnalysisError> {
    let value = match query {
        Query::CfgInspect(args) => serde_json::to_value(cfg::inspect(context, args)?),
        Query::FunctionsInspect(args) => serde_json::to_value(functions::inspect(context, args)?),
        Query::BacktraceInspect(args) => {
            serde_json::to_value(navigation::inspect_backtrace(context, args)?)
        }
        Query::MemAccesses(args) => {
            serde_json::to_value(mem_accesses::mem_accesses(context, args)?)
        }
        Query::MemProvenance(args) => {
            serde_json::to_value(mem_provenance::mem_provenance(context, args)?)
        }
        Query::Dependencies(args) => {
            serde_json::to_value(dependency_query::dependencies(context, args)?)
        }
        Query::JniInspect(args) => serde_json::to_value(jni_calls::inspect(context, args)?),
        Query::RegInspect(args) => {
            serde_json::to_value(timeline_diff::inspect_register(context, args)?)
        }

        Query::Meta => serde_json::to_value(meta::meta(context)),
        Query::AnalysisIndex => serde_json::to_value(analysis_index::analysis_index(context)?),
        Query::SoStats(args) => serde_json::to_value(so_stats::so_stats(context, args)?),
        Query::RegAt(args) => serde_json::to_value(reg_at::reg_at(context, args)?),
        Query::TraceReplay(args) => {
            serde_json::to_value(trace_replay::trace_replay(context, args)?)
        }
        Query::Coverage(args) => serde_json::to_value(coverage::coverage(context, args)?),
        Query::Resolve(args) => serde_json::to_value(resolve::resolve(context, args)?),
        Query::IndirectTargets(args) => {
            serde_json::to_value(indirect_targets::indirect_targets(context, args)?)
        }
        Query::Records(args) => serde_json::to_value(records::records(context, args)?),
        Query::Record(args) => serde_json::to_value(record::record(context, args)?),
        Query::Search(args) => serde_json::to_value(search::search(context, args)?),
        Query::CryptoAnalysis => serde_json::to_value(crypto_analysis::crypto_analysis(context)?),
        Query::IdxsForPc(args) => serde_json::to_value(idxs_for_pc::idxs_for_pc(context, args)?),
        Query::IdxsForBlock(args) => {
            serde_json::to_value(idxs_for_block::idxs_for_block(context, args)?)
        }
        Query::Cfg(args) => serde_json::to_value(cfg::cfg(context, args)?),
        Query::Block(args) => serde_json::to_value(navigation::block(context, args)?),
        Query::Loops => serde_json::to_value(navigation::loops(context)?),
        Query::Backtrace(args) => serde_json::to_value(navigation::backtrace(context, args)?),
        Query::CallChain(args) => serde_json::to_value(navigation::call_chain(context, args)?),
        Query::CallTree(args) => serde_json::to_value(call_tree::call_tree(context, args)?),
        Query::FnSummary(args) => serde_json::to_value(fn_summary::fn_summary(context, args)?),
        Query::Functions => serde_json::to_value(functions::functions(context)?),
        Query::LastWriteOfReg(args) => {
            serde_json::to_value(last_write_of_reg::last_write_of_reg(context, args))
        }
        Query::NextUseOfReg(args) => {
            serde_json::to_value(next_use_of_reg::next_use_of_reg(context, args))
        }
        Query::ForwardTaint(args) => {
            serde_json::to_value(forward_taint::forward_taint(context, args)?)
        }
        Query::BackwardTaint(args) => {
            serde_json::to_value(backward_taint::backward_taint(context, args)?)
        }
        Query::RegTimeline(args) => {
            serde_json::to_value(timeline_diff::reg_timeline(context, args)?)
        }
        Query::Strings(args) => serde_json::to_value(strings::strings(context, args)?),
        Query::StringProvenance(args) => {
            serde_json::to_value(string_provenance::string_provenance(context, args)?)
        }
        Query::MemDump(args) => serde_json::to_value(mem_dump::mem_dump(context, args)?),
        Query::LastWriteOfAddr(args) => {
            serde_json::to_value(memory_query::last_write_of_addr(context, args)?)
        }
        Query::MemWritesInRange(args) => {
            serde_json::to_value(memory_query::mem_writes_in_range(context, args)?)
        }
        Query::IdxsTouchingRange(args) => {
            serde_json::to_value(memory_query::idxs_touching_range(context, args)?)
        }
        Query::IdxsTouchingAddr(args) => {
            serde_json::to_value(memory_query::idxs_touching_addr(context, args)?)
        }
        Query::FindMemPattern(args) => {
            serde_json::to_value(memory_query::find_mem_pattern(context, args)?)
        }
    };
    value.map_err(|error| AnalysisError::internal(error.to_string()))
}
