use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn vm_backtree_value_on(
    analysis: &AnalysisContext,
    idx: usize,
    reg: Option<String>,
    depth: usize,
    max_nodes: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    frontier_with_next: bool,
    regs: String,
    profile: &VmProfile,
) -> anyhow::Result<serde_json::Value> {
    let mut queue = VecDeque::new();
    queue.push_back(TreeSeed {
        parent: None,
        depth: 0,
        idx,
        reg: reg.clone(),
        via: serde_json::json!({"kind": "root"}),
    });
    let mut seen = HashSet::new();
    let mut nodes = Vec::new();
    let mut truncated = false;
    while let Some(seed) = queue.pop_front() {
        if nodes.len() >= max_nodes {
            truncated = true;
            break;
        }
        let key = format!("{}:{}", seed.idx, seed.reg.as_deref().unwrap_or(""));
        if !seen.insert(key) {
            nodes.push(serde_json::json!({
                "id": nodes.len(),
                "parent": seed.parent,
                "depth": seed.depth,
                "idx": seed.idx,
                "reg": seed.reg,
                "via": seed.via,
                "status": "cycle",
            }));
            continue;
        }
        let backstep = vm_backstep_value_on(
            analysis,
            seed.idx,
            seed.reg.clone(),
            context,
            lookback,
            max_writes,
            regs.clone(),
            profile,
        )?;
        let node_id = nodes.len();
        let upstream_next = backstep
            .get("upstream")
            .and_then(|v| v.get("next"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let upstream_byte_nexts = upstream_byte_nexts_from_step(&backstep);
        let frontier_nexts = frontier_nexts_from_step(&backstep, profile);
        let enqueue_frontiers =
            frontier_with_next || upstream_next.get("idx").and_then(|v| v.as_u64()).is_none();
        nodes.push(compact_backtree_node(
            node_id,
            seed.parent,
            seed.depth,
            &seed.via,
            &backstep,
            &upstream_next,
            &upstream_byte_nexts,
            &frontier_nexts,
        ));
        if seed.depth >= depth {
            continue;
        }
        if let Some(next_seed) = tree_seed_from_next(
            node_id,
            seed.depth + 1,
            upstream_next.clone(),
            serde_json::json!({"kind": "upstream_next"}),
        ) {
            queue.push_back(next_seed);
        }
        for byte_next in upstream_byte_nexts {
            if same_tree_next(&upstream_next, &byte_next) {
                continue;
            }
            if let Some(next_seed) = tree_seed_from_next(
                node_id,
                seed.depth + 1,
                byte_next.clone(),
                serde_json::json!({
                    "kind": "upstream_byte",
                    "byte": byte_next,
                }),
            ) {
                queue.push_back(next_seed);
            }
        }
        if enqueue_frontiers {
            for frontier_next in frontier_nexts {
                if let Some(next_seed) = tree_seed_from_next(
                    node_id,
                    seed.depth + 1,
                    frontier_next.clone(),
                    serde_json::json!({
                        "kind": "frontier",
                        "frontier": frontier_next.get("frontier").cloned().unwrap_or(serde_json::Value::Null),
                    }),
                ) {
                    queue.push_back(next_seed);
                }
            }
        }
    }
    let highlights = vm_backtree_highlights(&nodes);
    Ok(serde_json::json!({
        "status": "ready",
        "start": {
            "idx": idx,
            "reg": reg,
        },
        "depth_requested": depth,
        "max_nodes": max_nodes,
        "frontier_with_next": frontier_with_next,
        "vm_profile": profile.to_json(),
        "nodes_returned": nodes.len(),
        "truncated": truncated || !queue.is_empty(),
        "highlights": highlights,
        "nodes": nodes,
    }))
}

pub(super) fn vm_backtree_summary(tree: &serde_json::Value) -> serde_json::Value {
    let nodes = tree
        .get("nodes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let formula_summary = index_tree_summary(tree);
    let interesting_formulas = formula_summary
        .get("interesting_formulas")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let semantic_formulas = formula_summary
        .get("semantic_formulas")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let bytecode_frontiers = nodes
        .iter()
        .filter(|node| {
            local_class(node) == Some("bytecode-read")
                && node
                    .get("frontier_nexts")
                    .and_then(|v| v.as_array())
                    .is_none_or(|items| items.is_empty())
        })
        .take(64)
        .map(compact_tree_node_summary)
        .collect::<Vec<_>>();
    let bytecode_operands = bytecode_frontiers
        .iter()
        .map(bytecode_operand_summary)
        .collect::<Vec<_>>();
    let small_byte_loads = nodes
        .iter()
        .filter(|node| {
            local_class(node) == Some("byte-load")
                && node_value_u64(node).is_some_and(|value| value <= 0xff)
        })
        .take(64)
        .map(compact_tree_node_summary)
        .collect::<Vec<_>>();
    let terminal_nodes = nodes
        .iter()
        .filter(|node| {
            node.get("status").and_then(|v| v.as_str()) == Some("cycle")
                || (node
                    .get("upstream")
                    .and_then(|v| v.get("status"))
                    .and_then(|v| v.as_str())
                    != Some("ready")
                    && node
                        .get("frontier_nexts")
                        .and_then(|v| v.as_array())
                        .is_none_or(|items| items.is_empty()))
        })
        .take(64)
        .map(compact_tree_node_summary)
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": tree.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": tree.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "depth_requested": tree.get("depth_requested").cloned().unwrap_or(serde_json::Value::Null),
        "max_nodes": tree.get("max_nodes").cloned().unwrap_or(serde_json::Value::Null),
        "frontier_with_next": tree.get("frontier_with_next").cloned().unwrap_or(serde_json::Value::Null),
        "nodes_returned": tree.get("nodes_returned").cloned().unwrap_or(serde_json::Value::Null),
        "truncated": tree.get("truncated").cloned().unwrap_or(serde_json::Value::Null),
        "highlights": {
            "word_loads": tree.pointer("/highlights/word_loads").cloned().unwrap_or_else(|| serde_json::json!([])),
            "table_lookups": tree.pointer("/highlights/table_lookups").cloned().unwrap_or_else(|| serde_json::json!([])),
            "interesting_formulas": interesting_formulas,
            "semantic_formulas": semantic_formulas,
        },
        "small_byte_loads": small_byte_loads,
        "bytecode_frontiers": bytecode_frontiers,
        "bytecode_operands": bytecode_operands,
        "terminal_nodes": terminal_nodes,
    })
}

pub(super) fn bytecode_operand_summary(node: &serde_json::Value) -> serde_json::Value {
    let producer_asm = node.pointer("/producer/asm").and_then(|v| v.as_str());
    serde_json::json!({
        "idx": node.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "depth": node.get("depth").cloned().unwrap_or(serde_json::Value::Null),
        "reg": node.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": node.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "offset": producer_asm.and_then(bytecode_offset_from_asm).map(|off| format!("{off:#x}")),
        "producer_asm": node.pointer("/producer/asm").cloned().unwrap_or(serde_json::Value::Null),
        "producer_addr": node.pointer("/producer/mem_addr").cloned().unwrap_or(serde_json::Value::Null),
        "consumer_asm": node.pointer("/consumer/asm").cloned().unwrap_or(serde_json::Value::Null),
        "consumer_class": node.pointer("/consumer/class").cloned().unwrap_or(serde_json::Value::Null),
    })
}

pub(super) fn bytecode_offset_from_asm(asm: &str) -> Option<u64> {
    let hash = asm.find('#')?;
    let tail = &asm[hash + 1..];
    let raw = tail
        .split(|c: char| c == ']' || c == ',' || c.is_whitespace())
        .next()
        .unwrap_or("")
        .trim();
    parse_u64_str(raw)
}

pub(super) fn local_class(node: &serde_json::Value) -> Option<&str> {
    node.pointer("/local_def/class").and_then(|v| v.as_str())
}

/// 节点 value 字段转 u64；数值解析统一走 cli_support::json_u64。
pub(super) fn node_value_u64(node: &serde_json::Value) -> Option<u64> {
    node.get("value").and_then(json_u64)
}

pub(super) fn compact_tree_node_summary(node: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": node.get("id").cloned().unwrap_or(serde_json::Value::Null),
        "parent": node.get("parent").cloned().unwrap_or(serde_json::Value::Null),
        "depth": node.get("depth").cloned().unwrap_or(serde_json::Value::Null),
        "idx": node.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": node.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": node.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "producer": {
            "asm": node.pointer("/local_def/asm").cloned().unwrap_or(serde_json::Value::Null),
            "class": node.pointer("/local_def/class").cloned().unwrap_or(serde_json::Value::Null),
            "func": node.pointer("/local_def/func").cloned().unwrap_or(serde_json::Value::Null),
            "pc": node.pointer("/local_def/pc").cloned().unwrap_or(serde_json::Value::Null),
            "mem_addr": node.pointer("/local_def/mem_addr").cloned().unwrap_or(serde_json::Value::Null),
            "formula": node.pointer("/local_def/formula").cloned().unwrap_or(serde_json::Value::Null),
        },
        "consumer": {
            "asm": node.pointer("/target/asm").cloned().unwrap_or(serde_json::Value::Null),
            "class": node.pointer("/target/class").cloned().unwrap_or(serde_json::Value::Null),
            "func": node.pointer("/target/func").cloned().unwrap_or(serde_json::Value::Null),
            "pc": node.pointer("/target/pc").cloned().unwrap_or(serde_json::Value::Null),
            "mem_addr": node.pointer("/target/mem_addr").cloned().unwrap_or(serde_json::Value::Null),
        },
        "upstream_status": node.pointer("/upstream/status").cloned().unwrap_or(serde_json::Value::Null),
        "via_kind": node.pointer("/via/kind").cloned().unwrap_or(serde_json::Value::Null),
    })
}
