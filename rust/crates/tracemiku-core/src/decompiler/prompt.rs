//! LLM prompt bundles for TraceIR decompilation.
//!
//! Directly mirrors `viewer/decompiler/llm_bundle.py`: build one request's
//! system prompt + user markdown. Model transport lives in tracemiku-server.

use serde::Serialize;

use crate::decompiler::ir::{FuncIR, TopIR};
use crate::decompiler::render::{render_func_md, render_summary_md};

pub const SYSTEM_PROMPT_DECOMPILE: &str = r#"You are a reverse engineering assistant specialized in ARM64 Android trace
decompilation. You receive a structured TraceIR describing what the binary
ACTUALLY EXECUTED on a real device — not what static analysis guesses.

Key trace semantics you can exploit:
- exec_count on each block tells you which paths were hot vs cold.
- Branch counts are observed (taken=N). 0 not-taken edges are dead in this
  run; do NOT generate dead code for opaque predicates.
- Loop iter counts are observed (iters=N).
- bl/blr targets are concretely resolved (callee_pc + name in calls section).
  No indirect-jump guessing needed.
- samples are first-execution register snapshots; useful for inferring types.
- This is ONE execution path; alternative inputs may take different branches.

Your output:
- Pure C pseudocode wrapped in a single ```c block.
- Reference observed values where they help understanding.
- Use readable identifier names; infer types from sample values + JNI/libc context.
- Where the trace does NOT determine semantics, comment that explicitly.
- Do NOT include OLLVM dispatcher boilerplate; output the LOGICAL control flow.
- Keep the function body under ~150 lines unless absolutely necessary.

Format expectation:
- A short prose paragraph of high-level semantics (3-6 sentences)
- Then ```c ... ``` with the pseudocode
- Then a brief note section listing assumptions / unknowns
"#;

pub const SYSTEM_PROMPT_DECOMPILE_ZH: &str = r#"你是 ARM64 Android trace 反编译助手. 输入是一份结构化 TraceIR,
描述二进制在真机上实际执行的轨迹 — 不是静态分析的猜测.

可利用的 trace 语义:
- 每个 block 的 exec_count 表明哪些路径热, 哪些冷
- 分支计数是真值 (taken=N). 0 not-taken 边在本次执行里就是死分支,
  **不要给 opaque predicate 编造 dead code**
- 循环迭代次数是实测值 (iters=N)
- bl/blr 目标已经解析 (calls 段有 callee_pc + name), **不需要猜间接跳转**
- samples 是首次执行时的寄存器快照, 适合推断类型
- 这是 *一条* 执行路径; 不同输入可能走不同分支

输出要求:
- C 伪代码必须放在 ```c 块里
- 适当引用观测值帮理解
- 变量名要可读, 从 sample 值 + JNI/libc 上下文推类型
- 不能从 trace 决定的部分明确注释说明, 不要瞎编
- 不要保留 OLLVM dispatcher 套路 — trace 已经摊平了, 输出**逻辑**控制流即可
- 函数体保持 150 行以内, 除非真的必要

格式:
- 先一段简短的高层语义说明 (3-6 句中文)
- 然后 ```c ... ``` 伪代码块
- 最后简短列出假设 / 未知项 (用中文 bullet)

整个回答用**中文**, 但代码本身用 C 语法 (注释也用中文).
"#;

pub const SYSTEM_PROMPT_SUMMARY: &str = r#"You are an ARM64 Android trace triage assistant. You receive a high-level
TraceIR summary listing function calls observed in one execution. Your job
is to identify which functions are likely the most interesting for a
reverse engineer to focus on.

Output format: bullet list. Each bullet:
  - <fn_id> `<name>` — one sentence why interesting

Pick at most 5 candidates. Be concrete; do not list every fn.
"#;

#[derive(Debug, Clone, Serialize)]
pub struct Bundle {
    pub system: String,
    pub user: String,
    pub fn_id: Option<String>,
    pub estimated_tokens: usize,
}

impl Bundle {
    pub fn chars(&self) -> usize {
        self.system.len() + self.user.len()
    }
}

fn est_tokens(s: &str) -> usize {
    std::cmp::max(1, s.len() / 4)
}

pub fn build_summary_prompt(top: &TopIR) -> Bundle {
    let md = render_summary_md(top);
    let user = format!(
        "Below is the trace summary. Pick the top-5 functions worth reverse-engineering \
         and explain why in one sentence each.\n\n{md}"
    );
    Bundle {
        system: SYSTEM_PROMPT_SUMMARY.to_string(),
        estimated_tokens: est_tokens(SYSTEM_PROMPT_SUMMARY) + est_tokens(&user),
        user,
        fn_id: None,
    }
}

pub fn build_fn_decompile_prompt(
    top: &TopIR,
    fn_: &FuncIR,
    tier: &str,
    lang: &str,
    max_user_chars: usize,
) -> Bundle {
    let mut rendered_fn = fn_.clone();
    let mut fn_md = render_func_md(&rendered_fn, tier);
    if fn_md.len() > max_user_chars {
        rendered_fn = truncate_fn_by_hot_blocks(fn_, max_user_chars / 2);
        fn_md = render_func_md(&rendered_fn, tier);
        fn_md.push_str(&format!(
            "\n\n> TRACE TRUNCATED: original had {} blocks; only the top {} by exec_count shown to fit token budget. Cold blocks dropped.\n",
            fn_.blocks.len(),
            rendered_fn.blocks.len()
        ));
    }

    let vm_context = vm_context_md(top);
    let user = format!(
        "Decompile this function from its execution trace. Output the logical C pseudocode for THIS execution path.\n\n{vm_context}{fn_md}"
    );
    let system = if lang == "zh" {
        SYSTEM_PROMPT_DECOMPILE_ZH
    } else {
        SYSTEM_PROMPT_DECOMPILE
    };
    Bundle {
        system: system.to_string(),
        estimated_tokens: est_tokens(system) + est_tokens(&user),
        user,
        fn_id: Some(fn_.id.clone()),
    }
}

fn vm_context_md(top: &TopIR) -> String {
    if top.vm_candidates.is_empty() {
        return String::new();
    }
    let summary = render_summary_md(top);
    let Some(start) = summary.find("## VM Candidates") else {
        return String::new();
    };
    let rest = &summary[start + 1..];
    let end = rest
        .find("\n## ")
        .map(|i| start + 1 + i)
        .unwrap_or(summary.len());
    format!("{}\n\n---\n\n", &summary[start..end])
}

fn truncate_fn_by_hot_blocks(fn_: &FuncIR, target_chars: usize) -> FuncIR {
    let mut blocks = fn_.blocks.clone();
    blocks.sort_by_key(|b| std::cmp::Reverse(b.exec_count));

    let mut kept = Vec::new();
    let mut accum = 0usize;
    for b in blocks {
        let approx = b.asm.len() + 200 + 60 * b.exits.len();
        if accum + approx > target_chars && !kept.is_empty() {
            break;
        }
        accum += approx;
        kept.push(b);
    }
    kept.sort_by_key(|b| b.pc);
    let mut out = fn_.clone();
    out.blocks = kept;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ir::{BlockIR, VmCandidateIR};

    #[test]
    fn build_fn_prompt_uses_english_by_default() {
        let top = TopIR::default();
        let fn_ = FuncIR {
            id: "F0".to_string(),
            name: "root".to_string(),
            blocks: vec![BlockIR {
                id: "B0".to_string(),
                pc: 0x1000,
                tier: "hot".to_string(),
                asm: "  0x1000: ret".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let b = build_fn_decompile_prompt(&top, &fn_, "hot", "en", 200_000);
        assert_eq!(b.fn_id.as_deref(), Some("F0"));
        assert!(b.system.contains("reverse engineering assistant"));
        assert!(b.user.contains("# F0 `root`"));
        assert!(b.estimated_tokens > 0);
    }

    #[test]
    fn build_fn_prompt_uses_chinese_prompt_when_requested() {
        let top = TopIR::default();
        let fn_ = FuncIR {
            id: "F0".to_string(),
            name: "root".to_string(),
            ..Default::default()
        };
        let b = build_fn_decompile_prompt(&top, &fn_, "summary", "zh", 200_000);
        assert!(b.system.contains("反编译助手"));
        assert!(b.system.contains("整个回答用"));
    }

    #[test]
    fn build_fn_prompt_includes_vm_context() {
        let top = TopIR {
            vm_candidates: vec![VmCandidateIR {
                dispatcher_pc: 0x1234,
                confidence: 1.0,
                reasons: vec!["indirect br/blr".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let fn_ = FuncIR {
            id: "F0".to_string(),
            name: "root".to_string(),
            ..Default::default()
        };
        let b = build_fn_decompile_prompt(&top, &fn_, "summary", "en", 200_000);
        assert!(b.user.contains("## VM Candidates"));
        assert!(b.user.contains("0x1234"));
    }

    #[test]
    fn build_fn_prompt_truncates_large_block_list() {
        let top = TopIR::default();
        let blocks: Vec<BlockIR> = (0..20u64)
            .map(|i| BlockIR {
                id: format!("B{i}"),
                pc: 0x1000 + i * 4,
                exec_count: i,
                tier: "hot".to_string(),
                asm: "  0x1000: nop\n".repeat(200),
                ..Default::default()
            })
            .collect();
        let fn_ = FuncIR {
            id: "F0".to_string(),
            name: "root".to_string(),
            blocks,
            ..Default::default()
        };
        let b = build_fn_decompile_prompt(&top, &fn_, "all", "en", 2_000);
        assert!(b.user.contains("TRACE TRUNCATED"));
    }
}
