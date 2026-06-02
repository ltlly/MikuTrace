//! Structured C-like tokens for decompiler output.
//!
//! Each token carries its text, semantic kind, and optional metadata
//! (variable identity, address, runtime value). The frontend renders
//! these directly without regex tokenization.

use serde::{Deserialize, Serialize};

/// Semantic kind of a C-like decompiler token.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CTokenKind {
    /// C keywords: if, else, while, for, return, goto, break, continue, switch, case, default
    Keyword,
    /// Type expressions: uint64_t, int32_t, void, struct, etc.
    Type,
    /// Named variables: x8_v1, arg_0, cs_x20, sp, fp
    Var,
    /// Numeric constants: 0x8bad, 42, -1
    Literal,
    /// String literals (rare in decompiler output)
    String,
    /// Operators: +, -, *, &, |, ^, ~, =, ==, !=, <, >, <<, >>, etc.
    Op,
    /// Punctuation: ; , { } ( ) [ ] :
    Punct,
    /// Function/call targets: sub_54fe8, memcpy, etc.
    Func,
    /// Goto labels: loc_6cc6503834
    Label,
    /// Struct field names
    Field,
    /// Comments: /* ... */
    Comment,
    /// Indentation and spacing
    Whitespace,
}

/// A single structured token in decompiler output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CToken {
    /// Display text of this token.
    pub text: std::string::String,
    /// Semantic kind — drives syntax highlighting and interaction.
    pub kind: CTokenKind,
    /// Variable identity for highlight-all-occurrences and rename.
    /// Present only for `Var` tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub var_id: Option<std::string::String>,
    /// Associated address (for jump-to-PC, xref). Present for `Func`, `Label`,
    /// and address-valued `Literal` tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<u64>,
    /// Runtime trace value (for hover display). Populated from TraceContext
    /// when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<i64>,
}

impl CToken {
    pub fn keyword(text: &str) -> Self {
        Self {
            text: text.into(),
            kind: CTokenKind::Keyword,
            var_id: None,
            addr: None,
            value: None,
        }
    }

    pub fn type_token(text: &str) -> Self {
        Self {
            text: text.into(),
            kind: CTokenKind::Type,
            var_id: None,
            addr: None,
            value: None,
        }
    }

    pub fn var(text: &str) -> Self {
        Self {
            text: text.clone().into(),
            kind: CTokenKind::Var,
            var_id: Some(text.into()),
            addr: None,
            value: None,
        }
    }

    pub fn literal(text: &str) -> Self {
        Self {
            text: text.into(),
            kind: CTokenKind::Literal,
            var_id: None,
            addr: None,
            value: None,
        }
    }

    pub fn literal_addr(text: &str, addr: u64) -> Self {
        Self {
            text: text.into(),
            kind: CTokenKind::Literal,
            var_id: None,
            addr: Some(addr),
            value: None,
        }
    }

    pub fn op(text: &str) -> Self {
        Self {
            text: text.into(),
            kind: CTokenKind::Op,
            var_id: None,
            addr: None,
            value: None,
        }
    }

    pub fn punct(text: &str) -> Self {
        Self {
            text: text.into(),
            kind: CTokenKind::Punct,
            var_id: None,
            addr: None,
            value: None,
        }
    }

    pub fn func(text: &str, addr: Option<u64>) -> Self {
        Self {
            text: text.into(),
            kind: CTokenKind::Func,
            var_id: None,
            addr,
            value: None,
        }
    }

    pub fn label(text: &str, addr: Option<u64>) -> Self {
        Self {
            text: text.into(),
            kind: CTokenKind::Label,
            var_id: None,
            addr,
            value: None,
        }
    }

    pub fn field(text: &str) -> Self {
        Self {
            text: text.into(),
            kind: CTokenKind::Field,
            var_id: None,
            addr: None,
            value: None,
        }
    }

    pub fn comment(text: &str) -> Self {
        Self {
            text: text.into(),
            kind: CTokenKind::Comment,
            var_id: None,
            addr: None,
            value: None,
        }
    }

    pub fn ws(text: &str) -> Self {
        Self {
            text: text.into(),
            kind: CTokenKind::Whitespace,
            var_id: None,
            addr: None,
            value: None,
        }
    }
}

/// Compact wire format for JSON transfer (minimizes payload size).
/// Maps to frontend `CToken` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CTokenWire {
    /// Token text
    pub t: std::string::String,
    /// Kind shorthand: kw, ty, var, lit, op, p, fn, lbl, fld, cmt, ws
    pub k: std::string::String,
    /// Variable identity (for var tokens)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v: Option<std::string::String>,
    /// Address (hex string, for func/label/addr-literal tokens)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a: Option<std::string::String>,
    /// Runtime value (hex string, for hover)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rv: Option<std::string::String>,
}

impl From<&CToken> for CTokenWire {
    fn from(t: &CToken) -> Self {
        Self {
            t: t.text.clone(),
            k: kind_short(t.kind).into(),
            v: t.var_id.clone(),
            a: t.addr.map(|a| format!("0x{a:x}")),
            rv: t.value.map(|v| format!("0x{:x}", v as u64)),
        }
    }
}

fn kind_short(k: CTokenKind) -> &'static str {
    match k {
        CTokenKind::Keyword => "kw",
        CTokenKind::Type => "ty",
        CTokenKind::Var => "var",
        CTokenKind::Literal => "lit",
        CTokenKind::String => "str",
        CTokenKind::Op => "op",
        CTokenKind::Punct => "p",
        CTokenKind::Func => "fn",
        CTokenKind::Label => "lbl",
        CTokenKind::Field => "fld",
        CTokenKind::Comment => "cmt",
        CTokenKind::Whitespace => "ws",
    }
}

/// A line of structured tokens with source PC for cursor sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CTokenLine {
    /// Tokens composing this line.
    pub tokens: Vec<CToken>,
    /// Source PC of the primary expression on this line (for trace cursor sync).
    pub pc: u64,
}

impl CTokenLine {
    pub fn new(tokens: Vec<CToken>, pc: u64) -> Self {
        Self { tokens, pc }
    }

    /// Convert to wire format.
    pub fn to_wire(&self) -> Vec<CTokenWire> {
        self.tokens.iter().map(CTokenWire::from).collect()
    }

    /// Join all token texts into a single string (for text-only fallback).
    pub fn to_text(&self) -> std::string::String {
        self.tokens.iter().map(|t| t.text.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format_compact() {
        let tok = CToken::var("x8_v1");
        let wire = CTokenWire::from(&tok);
        assert_eq!(wire.t, "x8_v1");
        assert_eq!(wire.k, "var");
        assert_eq!(wire.v, Some("x8_v1".into()));
        assert_eq!(wire.a, None);
        assert_eq!(wire.rv, None);
    }

    #[test]
    fn wire_format_literal_with_addr() {
        let tok = CToken::literal_addr("0x6cc6500fe8", 0x6cc6500fe8);
        let wire = CTokenWire::from(&tok);
        assert_eq!(wire.k, "lit");
        assert_eq!(wire.a, Some("0x6cc6500fe8".into()));
    }

    #[test]
    fn line_to_text() {
        let line = CTokenLine::new(
            vec![
                CToken::var("x8_v1"),
                CToken::ws(" "),
                CToken::op("="),
                CToken::ws(" "),
                CToken::literal("0x42"),
                CToken::punct(";"),
            ],
            0x1000,
        );
        assert_eq!(line.to_text(), "x8_v1 = 0x42;");
    }
}
