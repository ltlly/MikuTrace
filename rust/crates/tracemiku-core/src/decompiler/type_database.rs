//! User-defined type database.
//!
//! Stores typedefs, struct definitions, and enum definitions supplied by the
//! user (or imported from DWARF / symbol files).  Types can be resolved by
//! name and serialised to JSON for persistence across sessions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Core type representations
// ---------------------------------------------------------------------------

/// Primitive C type kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeKind {
    Void,
    Bool,
    Char,
    Short,
    Int,
    Long,
    LongLong,
    UChar,
    UShort,
    UInt,
    ULong,
    ULongLong,
    Float,
    Double,
    LongDouble,
    /// Size_t / pointer-sized unsigned integer.
    SizeT,
    /// ptrdiff_t / pointer-sized signed integer.
    PtrDiffT,
    /// Opaque / unknown primitive.
    Unknown,
}

impl TypeKind {
    /// Human-readable name of the primitive (e.g. `"int"`, `"char*"`).
    pub fn name(&self) -> &'static str {
        match self {
            TypeKind::Void => "void",
            TypeKind::Bool => "bool",
            TypeKind::Char => "char",
            TypeKind::Short => "short",
            TypeKind::Int => "int",
            TypeKind::Long => "long",
            TypeKind::LongLong => "long long",
            TypeKind::UChar => "unsigned char",
            TypeKind::UShort => "unsigned short",
            TypeKind::UInt => "unsigned int",
            TypeKind::ULong => "unsigned long",
            TypeKind::ULongLong => "unsigned long long",
            TypeKind::Float => "float",
            TypeKind::Double => "double",
            TypeKind::LongDouble => "long double",
            TypeKind::SizeT => "size_t",
            TypeKind::PtrDiffT => "ptrdiff_t",
            TypeKind::Unknown => "?",
        }
    }

    /// Approximate byte size of the primitive on a 64-bit (LP64) target.
    pub fn size_bytes(&self) -> usize {
        match self {
            TypeKind::Void => 0,
            TypeKind::Bool | TypeKind::Char | TypeKind::UChar => 1,
            TypeKind::Short | TypeKind::UShort => 2,
            TypeKind::Int | TypeKind::UInt | TypeKind::Float => 4,
            TypeKind::Long
            | TypeKind::ULong
            | TypeKind::Double
            | TypeKind::LongLong
            | TypeKind::ULongLong
            | TypeKind::SizeT
            | TypeKind::PtrDiffT => 8,
            TypeKind::LongDouble => 16,
            TypeKind::Unknown => 0,
        }
    }

    /// Try to look up a primitive from its C keyword name.
    pub fn from_keyword(s: &str) -> Option<TypeKind> {
        match s {
            "void" => Some(TypeKind::Void),
            "bool" | "_Bool" => Some(TypeKind::Bool),
            "char" => Some(TypeKind::Char),
            "short" => Some(TypeKind::Short),
            "int" => Some(TypeKind::Int),
            "long" => Some(TypeKind::Long),
            "long long" | "longlong" => Some(TypeKind::LongLong),
            "unsigned char" | "uchar" => Some(TypeKind::UChar),
            "unsigned short" | "ushort" => Some(TypeKind::UShort),
            "unsigned int" | "uint" | "unsigned" => Some(TypeKind::UInt),
            "unsigned long" | "ulong" => Some(TypeKind::ULong),
            "unsigned long long" | "ulonglong" | "unsigned longlong" => Some(TypeKind::ULongLong),
            "float" => Some(TypeKind::Float),
            "double" => Some(TypeKind::Double),
            "long double" | "longdouble" => Some(TypeKind::LongDouble),
            "size_t" => Some(TypeKind::SizeT),
            "ptrdiff_t" => Some(TypeKind::PtrDiffT),
            _ => None,
        }
    }
}

/// Recursive C type representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CType {
    /// A primitive scalar.
    Primitive(TypeKind),
    /// Pointer to another type (e.g. `int*`, `char**`).
    Pointer(Box<CType>),
    /// Fixed-size array (e.g. `int[16]`).
    Array(Box<CType>, usize),
    /// Named struct – the name is looked up in the database.
    #[serde(rename = "struct")]
    Struct(String),
    /// Named enum – the name is looked up in the database.
    #[serde(rename = "enum")]
    Enum(String),
    /// Function pointer: argument types and return type.
    FuncPtr(Vec<CType>, Box<CType>),
}

impl CType {
    /// Render the type back to a C-ish string.
    pub fn to_c_string(&self) -> String {
        match self {
            CType::Primitive(k) => k.name().to_string(),
            CType::Pointer(inner) => format!("{}*", inner.to_c_inner()),
            CType::Array(inner, len) => format!("{}[{}]", inner.to_c_string(), len),
            CType::Struct(name) => format!("struct {}", name),
            CType::Enum(name) => format!("enum {}", name),
            CType::FuncPtr(args, ret) => {
                let arg_strs: Vec<String> = args.iter().map(|a| a.to_c_string()).collect();
                format!("{} (*)({})", ret.to_c_string(), arg_strs.join(", "))
            }
        }
    }

    /// Wraps in parentheses when needed (only for function pointers
    /// which need disambiguation when used as the inner type of a pointer).
    fn to_c_inner(&self) -> String {
        match self {
            CType::FuncPtr(_, _) => format!("({})", self.to_c_string()),
            _ => self.to_c_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Struct / Enum definitions
// ---------------------------------------------------------------------------

/// A field within a struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructField {
    pub name: String,
    pub ty: CType,
    /// Byte offset of this field within the struct.
    pub offset: usize,
}

/// A struct definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<StructField>,
    /// Total size in bytes (may differ from the last field's end due to padding).
    pub size: usize,
}

impl StructDef {
    /// Look up a field by name.
    pub fn field(&self, name: &str) -> Option<&StructField> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Look up a field at a given byte offset (best-fit: the field whose range
    /// contains `offset`).
    pub fn field_at_offset(&self, offset: usize) -> Option<&StructField> {
        // The field whose range covers the offset.
        let mut best: Option<&StructField> = None;
        for f in &self.fields {
            let end = if best.is_none() { self.size } else { f.offset };
            if offset >= f.offset && offset < end {
                best = Some(f);
                break;
            }
        }
        best
    }
}

/// A variant within an enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumVariant {
    pub name: String,
    pub value: i64,
}

/// An enum definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumDef {
    pub name: String,
    pub variants: Vec<EnumVariant>,
}

impl EnumDef {
    /// Look up a variant by name.
    pub fn variant(&self, name: &str) -> Option<&EnumVariant> {
        self.variants.iter().find(|v| v.name == name)
    }

    /// Look up a variant by numeric value.
    pub fn variant_by_value(&self, value: i64) -> Option<&EnumVariant> {
        self.variants.iter().find(|v| v.value == value)
    }
}

// ---------------------------------------------------------------------------
// Type database
// ---------------------------------------------------------------------------

/// Persistent, user-extensible type database.
///
/// ```rust
/// use tracemiku_core::decompiler::type_database::{TypeDatabase, CType, TypeKind};
///
/// let mut db = TypeDatabase::new();
/// db.add_typedef("MyInt", CType::Primitive(TypeKind::Int));
/// assert_eq!(db.resolve_type("MyInt"), Some(CType::Primitive(TypeKind::Int)));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TypeDatabase {
    /// User-defined typedefs: alias name -> underlying C type.
    pub typedefs: HashMap<String, CType>,
    /// Named struct definitions.
    pub structs: HashMap<String, StructDef>,
    /// Named enum definitions.
    pub enums: HashMap<String, EnumDef>,
}

impl TypeDatabase {
    /// Create an empty type database.
    pub fn new() -> Self {
        Self {
            typedefs: HashMap::new(),
            structs: HashMap::new(),
            enums: HashMap::new(),
        }
    }

    // ------------------------------------------------------------------
    // Registration
    // ------------------------------------------------------------------

    /// Register a typedef alias.
    ///
    /// Returns `true` if a previous definition was replaced.
    pub fn add_typedef(&mut self, name: &str, ty: CType) -> bool {
        self.typedefs.insert(name.to_string(), ty).is_some()
    }

    /// Register a struct definition.
    ///
    /// Returns `true` if a previous definition was replaced.
    pub fn add_struct(&mut self, def: StructDef) -> bool {
        let name = def.name.clone();
        self.structs.insert(name, def).is_some()
    }

    /// Register an enum definition.
    ///
    /// Returns `true` if a previous definition was replaced.
    pub fn add_enum(&mut self, def: EnumDef) -> bool {
        let name = def.name.clone();
        self.enums.insert(name, def).is_some()
    }

    /// Register a struct from name and field list, computing offsets and size
    /// from field types.  Fields are packed sequentially; the caller should
    /// provide correctly-ordered fields.
    pub fn add_struct_fields(&mut self, name: &str, fields: Vec<(String, CType)>) -> bool {
        let mut offset = 0usize;
        let fields_with_offsets: Vec<StructField> = fields
            .into_iter()
            .map(|(fname, ty)| {
                let field = StructField {
                    name: fname,
                    ty,
                    offset,
                };
                offset += field.ty.size_bytes();
                // Align to the field's natural alignment.
                let align = field.ty.alignment();
                if align > 0 {
                    offset = (offset + align - 1) & !(align - 1);
                }
                field
            })
            .collect();
        let size = offset;
        let def = StructDef {
            name: name.to_string(),
            fields: fields_with_offsets,
            size,
        };
        self.add_struct(def)
    }

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    /// Resolve a named type (typedef, struct, or enum) to its `CType`.
    ///
    /// Follows typedef chains transitively.
    pub fn resolve_type(&self, name: &str) -> Option<CType> {
        // Check typedefs first.
        if let Some(ty) = self.typedefs.get(name) {
            return Some(self.resolve_typedef(ty));
        }
        // Check known structs – wrap in Struct(_) for structural use.
        if self.structs.contains_key(name) {
            return Some(CType::Struct(name.to_string()));
        }
        // Check known enums.
        if self.enums.contains_key(name) {
            return Some(CType::Enum(name.to_string()));
        }
        None
    }

    /// Resolve a typedef chain, following aliases that point to other
    /// typedefs / structs / enums registered in the database.
    fn resolve_typedef(&self, ty: &CType) -> CType {
        match ty {
            CType::Struct(name) | CType::Enum(name) => {
                // If `name` is itself a typedef, follow it.
                if let Some(underlying) = self.typedefs.get(name) {
                    return self.resolve_typedef(underlying);
                }
                ty.clone()
            }
            _ => ty.clone(),
        }
    }

    /// Get a struct definition by name.
    pub fn get_struct(&self, name: &str) -> Option<&StructDef> {
        self.structs.get(name)
    }

    /// Get an enum definition by name.
    pub fn get_enum(&self, name: &str) -> Option<&EnumDef> {
        self.enums.get(name)
    }

    // ------------------------------------------------------------------
    // Serialisation
    // ------------------------------------------------------------------

    /// Serialise the whole database to a JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialise the whole database from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Merge another database into this one, overwriting conflicts.
    pub fn merge(&mut self, other: &TypeDatabase) {
        for (k, v) in &other.typedefs {
            self.typedefs.insert(k.clone(), v.clone());
        }
        for (k, v) in &other.structs {
            self.structs.insert(k.clone(), v.clone());
        }
        for (k, v) in &other.enums {
            self.enums.insert(k.clone(), v.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// CType helpers (size / alignment)
// ---------------------------------------------------------------------------

impl CType {
    /// Approximate byte size.
    pub fn size_bytes(&self) -> usize {
        match self {
            CType::Primitive(k) => k.size_bytes(),
            CType::Pointer(_) => 8, // 64-bit pointer
            CType::Array(inner, len) => inner.size_bytes() * len,
            CType::Struct(name) => {
                // Without a database reference we cannot know — return 0.
                // Callers with access to TypeDatabase should use
                // `TypeDatabase::get_struct` instead.
                let _ = name;
                0
            }
            CType::Enum(_) => 4,       // enums are typically int-sized
            CType::FuncPtr(_, _) => 8, // function pointer
        }
    }

    /// Natural alignment in bytes.
    pub fn alignment(&self) -> usize {
        match self {
            CType::Primitive(k) => k.size_bytes().min(8), // typical cap
            CType::Pointer(_) => 8,
            CType::Array(inner, _) => inner.alignment(),
            CType::Struct(_) => 8, // structs align to largest member; default 8
            CType::Enum(_) => 4,
            CType::FuncPtr(_, _) => 8,
        }
    }
}

// ---------------------------------------------------------------------------
// C type parser
// ---------------------------------------------------------------------------

/// Error returned by `parse_c_type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CTypeParseError {
    UnexpectedToken(String),
    UnterminatedBracket,
    UnterminatedParen,
    EmptyInput,
    UnknownType(String),
}

impl std::fmt::Display for CTypeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CTypeParseError::UnexpectedToken(t) => write!(f, "unexpected token: {}", t),
            CTypeParseError::UnterminatedBracket => write!(f, "unterminated '['"),
            CTypeParseError::UnterminatedParen => write!(f, "unterminated '('"),
            CTypeParseError::EmptyInput => write!(f, "empty input"),
            CTypeParseError::UnknownType(s) => write!(f, "unknown type: {}", s),
        }
    }
}

/// Parse a C type expression string into a `CType`.
///
/// # Examples
///
/// ```rust
/// use tracemiku_core::decompiler::type_database::{parse_c_type, CType, TypeKind};
///
/// assert_eq!(parse_c_type("int").unwrap(), CType::Primitive(TypeKind::Int));
/// assert_eq!(
///     parse_c_type("char*").unwrap(),
///     CType::Pointer(Box::new(CType::Primitive(TypeKind::Char)))
/// );
/// assert_eq!(
///     parse_c_type("int[16]").unwrap(),
///     CType::Array(Box::new(CType::Primitive(TypeKind::Int)), 16)
/// );
/// assert_eq!(
///     parse_c_type("struct MyStruct*").unwrap(),
///     CType::Pointer(Box::new(CType::Struct("MyStruct".into())))
/// );
/// assert_eq!(
///     parse_c_type("void*").unwrap(),
///     CType::Pointer(Box::new(CType::Primitive(TypeKind::Void)))
/// );
/// ```
pub fn parse_c_type(input: &str) -> Result<CType, CTypeParseError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(CTypeParseError::EmptyInput);
    }
    let mut parser = Parser::new(input);
    parser.parse_type()
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn skip_ws(&mut self) {
        while let Some(ch) = self.peek() {
            if ch.is_whitespace() {
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    fn consume_token(&mut self) -> String {
        self.skip_ws();
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch.is_alphanumeric() || ch == '_' {
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
        self.input[start..self.pos].to_string()
    }

    fn consume_char(&mut self, expected: char) -> bool {
        self.skip_ws();
        if self.peek() == Some(expected) {
            self.pos += expected.len_utf8();
            true
        } else {
            false
        }
    }

    /// Parse a complete type expression.
    ///
    /// Grammar (simplified):
    ///   type_expr  = function_ptr | pointer_type | base_type suffix*
    ///   base_type  = "void" | "char" | "short" | "int" | "long" | "float" | "double"
    ///              | "unsigned" base_type
    ///              | "struct" IDENT
    ///              | "enum" IDENT
    ///              | IDENT                  // typedef
    ///   suffix     = "*" | "[" NUMBER? "]"  // pointer or array
    ///   pointer_type = base_type suffix* "*" suffix*
    ///   function_ptr = base_type "(*)" "(" arg_types ")"
    fn parse_type(&mut self) -> Result<CType, CTypeParseError> {
        let input = self.input.trim();
        // Special case: function pointer `ret (*)(args...)`
        if let Some(rest) = input.strip_suffix(')') {
            // Check if this looks like `... (*)(arglist)`
            if let Some(idx) = rest.find("(*)(") {
                let ret_part = &rest[..idx];
                let arg_part = &rest[idx + 4..];
                // Parse the return type from the base
                let mut sub = Parser::new(ret_part);
                let ret_ty = sub.parse_base_with_suffixes()?;
                // Parse argument list
                let args = if arg_part.is_empty() {
                    vec![]
                } else {
                    arg_part
                        .split(',')
                        .map(|s| parse_c_type(s.trim()))
                        .collect::<Result<Vec<_>, _>>()?
                };
                return Ok(CType::FuncPtr(args, Box::new(ret_ty)));
            }
        }
        self.parse_base_with_suffixes()
    }

    /// Parse a base type followed by pointer/array suffixes.
    fn parse_base_with_suffixes(&mut self) -> Result<CType, CTypeParseError> {
        let base = self.parse_base()?;
        self.parse_suffixes(base)
    }

    /// Parse the base (leaf) type.
    fn parse_base(&mut self) -> Result<CType, CTypeParseError> {
        self.skip_ws();
        let tok = self.consume_token();
        if tok.is_empty() {
            return Err(CTypeParseError::UnexpectedToken(
                self.input[self.pos..].to_string(),
            ));
        }

        match tok.as_str() {
            "unsigned" => {
                // "unsigned <base>" or bare "unsigned" = unsigned int
                self.skip_ws();
                let next = self.consume_token();
                if next.is_empty() {
                    // Bare "unsigned"
                    Ok(CType::Primitive(TypeKind::UInt))
                } else {
                    let combined = format!("unsigned {}", next);
                    TypeKind::from_keyword(&combined)
                        .map(CType::Primitive)
                        .ok_or(CTypeParseError::UnknownType(combined))
                }
            }
            "long" => {
                // "long long" or just "long"
                self.skip_ws();
                let next = self.consume_token();
                if next == "long" {
                    Ok(CType::Primitive(TypeKind::LongLong))
                } else if next == "double" {
                    Ok(CType::Primitive(TypeKind::LongDouble))
                } else if next.is_empty() {
                    Ok(CType::Primitive(TypeKind::Long))
                } else {
                    // Put back the token (e.g. "long *" -> long, then * parsed as suffix)
                    // Walk pos back by the token length.
                    let back = self.pos.saturating_sub(next.len());
                    let ws_back = back.saturating_sub(
                        self.input[..back]
                            .chars()
                            .rev()
                            .take_while(|c| c.is_whitespace())
                            .count(),
                    );
                    self.pos = ws_back;
                    Ok(CType::Primitive(TypeKind::Long))
                }
            }
            "struct" => {
                let name = self.consume_token();
                if name.is_empty() {
                    return Err(CTypeParseError::UnexpectedToken(
                        "expected struct name".to_string(),
                    ));
                }
                Ok(CType::Struct(name))
            }
            "enum" => {
                let name = self.consume_token();
                if name.is_empty() {
                    return Err(CTypeParseError::UnexpectedToken(
                        "expected enum name".to_string(),
                    ));
                }
                Ok(CType::Enum(name))
            }
            _ => {
                // Try as a known keyword first (int, char, void, etc.)
                if let Some(kind) = TypeKind::from_keyword(&tok) {
                    Ok(CType::Primitive(kind))
                } else {
                    // It is a typedef name — resolve later by caller.
                    // Store as Struct temporarily; TypeDatabase::resolve_type
                    // will follow typedef chains.
                    Ok(CType::Struct(tok))
                }
            }
        }
    }

    /// Consume trailing `*` and `[N]` suffixes, building the type inside-out.
    fn parse_suffixes(&mut self, mut ty: CType) -> Result<CType, CTypeParseError> {
        loop {
            self.skip_ws();
            match self.peek() {
                Some('*') => {
                    self.pos += '*'.len_utf8();
                    ty = CType::Pointer(Box::new(ty));
                }
                Some('[') => {
                    self.pos += '['.len_utf8();
                    let num_str = self.consume_token();
                    let len: usize = if num_str.is_empty() {
                        // `[]` – treat as 0 (unknown bound).
                        0
                    } else {
                        num_str.parse::<usize>().map_err(|_| {
                            CTypeParseError::UnexpectedToken(format!(
                                "invalid array size: {}",
                                num_str
                            ))
                        })?
                    };
                    if !self.consume_char(']') {
                        return Err(CTypeParseError::UnterminatedBracket);
                    }
                    ty = CType::Array(Box::new(ty), len);
                }
                _ => break,
            }
        }
        Ok(ty)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ----- C type parsing -----

    #[test]
    fn parse_primitive_int() {
        assert_eq!(
            parse_c_type("int").unwrap(),
            CType::Primitive(TypeKind::Int)
        );
    }

    #[test]
    fn parse_primitive_char() {
        assert_eq!(
            parse_c_type("char").unwrap(),
            CType::Primitive(TypeKind::Char)
        );
    }

    #[test]
    fn parse_primitive_void() {
        assert_eq!(
            parse_c_type("void").unwrap(),
            CType::Primitive(TypeKind::Void)
        );
    }

    #[test]
    fn parse_unsigned_int() {
        assert_eq!(
            parse_c_type("unsigned int").unwrap(),
            CType::Primitive(TypeKind::UInt)
        );
    }

    #[test]
    fn parse_bare_unsigned() {
        assert_eq!(
            parse_c_type("unsigned").unwrap(),
            CType::Primitive(TypeKind::UInt)
        );
    }

    #[test]
    fn parse_long_long() {
        assert_eq!(
            parse_c_type("long long").unwrap(),
            CType::Primitive(TypeKind::LongLong)
        );
    }

    #[test]
    fn parse_char_ptr() {
        assert_eq!(
            parse_c_type("char*").unwrap(),
            CType::Pointer(Box::new(CType::Primitive(TypeKind::Char)))
        );
    }

    #[test]
    fn parse_char_ptr_space() {
        assert_eq!(
            parse_c_type("char *").unwrap(),
            CType::Pointer(Box::new(CType::Primitive(TypeKind::Char)))
        );
    }

    #[test]
    fn parse_double_ptr() {
        assert_eq!(
            parse_c_type("int**").unwrap(),
            CType::Pointer(Box::new(CType::Pointer(Box::new(CType::Primitive(
                TypeKind::Int
            )))))
        );
    }

    #[test]
    fn parse_int_array() {
        assert_eq!(
            parse_c_type("int[16]").unwrap(),
            CType::Array(Box::new(CType::Primitive(TypeKind::Int)), 16)
        );
    }

    #[test]
    fn parse_struct_ptr() {
        assert_eq!(
            parse_c_type("struct MyStruct*").unwrap(),
            CType::Pointer(Box::new(CType::Struct("MyStruct".into())))
        );
    }

    #[test]
    fn parse_struct_no_ptr() {
        assert_eq!(
            parse_c_type("struct Foo").unwrap(),
            CType::Struct("Foo".into())
        );
    }

    #[test]
    fn parse_enum_() {
        assert_eq!(
            parse_c_type("enum Color").unwrap(),
            CType::Enum("Color".into())
        );
    }

    #[test]
    fn parse_void_ptr() {
        assert_eq!(
            parse_c_type("void*").unwrap(),
            CType::Pointer(Box::new(CType::Primitive(TypeKind::Void)))
        );
    }

    #[test]
    fn parse_func_ptr_void_int() {
        let ty = parse_c_type("void (*)(int, char*)").unwrap();
        match &ty {
            CType::FuncPtr(args, ret) => {
                assert_eq!(**ret, CType::Primitive(TypeKind::Void));
                assert_eq!(args.len(), 2);
                assert_eq!(args[0], CType::Primitive(TypeKind::Int));
                assert_eq!(
                    args[1],
                    CType::Pointer(Box::new(CType::Primitive(TypeKind::Char)))
                );
            }
            _ => panic!("expected FuncPtr, got {:?}", ty),
        }
    }

    #[test]
    fn parse_func_ptr_no_args() {
        let ty = parse_c_type("int (*)()").unwrap();
        match &ty {
            CType::FuncPtr(args, ret) => {
                assert_eq!(**ret, CType::Primitive(TypeKind::Int));
                assert!(args.is_empty());
            }
            _ => panic!("expected FuncPtr, got {:?}", ty),
        }
    }

    #[test]
    fn parse_func_ptr_returns_ptr() {
        let ty = parse_c_type("int* (*)(int, int)").unwrap();
        match &ty {
            CType::FuncPtr(args, ret) => {
                assert_eq!(
                    **ret,
                    CType::Pointer(Box::new(CType::Primitive(TypeKind::Int)))
                );
                assert_eq!(args.len(), 2);
            }
            _ => panic!("expected FuncPtr, got {:?}", ty),
        }
    }

    #[test]
    fn parse_float() {
        assert_eq!(
            parse_c_type("float").unwrap(),
            CType::Primitive(TypeKind::Float)
        );
    }

    #[test]
    fn parse_double() {
        assert_eq!(
            parse_c_type("double").unwrap(),
            CType::Primitive(TypeKind::Double)
        );
    }

    #[test]
    fn parse_size_t_alias() {
        // size_t is a keyword; will parse as Primitive(SizeT)
        assert_eq!(
            parse_c_type("size_t").unwrap(),
            CType::Primitive(TypeKind::SizeT)
        );
    }

    #[test]
    fn parse_unknown_typedef() {
        // Unregistered types are stored as Struct(name) so TypeDatabase
        // can resolve them later.
        assert_eq!(
            parse_c_type("MyCustomType").unwrap(),
            CType::Struct("MyCustomType".into())
        );
    }

    // ----- CType::to_c_string -----

    #[test]
    fn c_string_int() {
        assert_eq!(CType::Primitive(TypeKind::Int).to_c_string(), "int");
    }

    #[test]
    fn c_string_char_ptr() {
        let ty = CType::Pointer(Box::new(CType::Primitive(TypeKind::Char)));
        assert_eq!(ty.to_c_string(), "char*");
    }

    #[test]
    fn c_string_double_ptr() {
        let ty = CType::Pointer(Box::new(CType::Pointer(Box::new(CType::Primitive(
            TypeKind::Int,
        )))));
        assert_eq!(ty.to_c_string(), "int**");
    }

    #[test]
    fn c_string_array() {
        let ty = CType::Array(Box::new(CType::Primitive(TypeKind::Char)), 16);
        assert_eq!(ty.to_c_string(), "char[16]");
    }

    #[test]
    fn c_string_struct() {
        assert_eq!(CType::Struct("Foo".into()).to_c_string(), "struct Foo");
    }

    #[test]
    fn c_string_func_ptr() {
        let ty = CType::FuncPtr(
            vec![
                CType::Primitive(TypeKind::Int),
                CType::Primitive(TypeKind::Char),
            ],
            Box::new(CType::Primitive(TypeKind::Void)),
        );
        assert_eq!(ty.to_c_string(), "void (*)(int, char)");
    }

    // ----- TypeDatabase -----

    #[test]
    fn db_add_and_resolve_typedef() {
        let mut db = TypeDatabase::new();
        db.add_typedef("MyInt", CType::Primitive(TypeKind::Int));
        assert_eq!(
            db.resolve_type("MyInt"),
            Some(CType::Primitive(TypeKind::Int))
        );
    }

    #[test]
    fn db_add_struct() {
        let mut db = TypeDatabase::new();
        db.add_struct_fields(
            "Point",
            vec![
                ("x".into(), CType::Primitive(TypeKind::Int)),
                ("y".into(), CType::Primitive(TypeKind::Int)),
            ],
        );
        let s = db.get_struct("Point").unwrap();
        assert_eq!(s.fields.len(), 2);
        assert_eq!(s.fields[0].name, "x");
        assert_eq!(s.fields[0].offset, 0);
        assert_eq!(s.fields[1].name, "y");
        assert_eq!(s.fields[1].offset, 4);
        assert_eq!(s.size, 8);
    }

    #[test]
    fn db_add_enum() {
        let mut db = TypeDatabase::new();
        db.add_enum(EnumDef {
            name: "Color".into(),
            variants: vec![
                EnumVariant {
                    name: "Red".into(),
                    value: 0,
                },
                EnumVariant {
                    name: "Green".into(),
                    value: 1,
                },
                EnumVariant {
                    name: "Blue".into(),
                    value: 2,
                },
            ],
        });
        let e = db.get_enum("Color").unwrap();
        assert_eq!(e.variant_by_value(1).unwrap().name, "Green");
    }

    #[test]
    fn db_resolve_struct_as_type() {
        let mut db = TypeDatabase::new();
        db.add_struct(StructDef {
            name: "Node".into(),
            fields: vec![],
            size: 0,
        });
        assert_eq!(db.resolve_type("Node"), Some(CType::Struct("Node".into())));
    }

    #[test]
    fn db_resolve_enum_as_type() {
        let mut db = TypeDatabase::new();
        db.add_enum(EnumDef {
            name: "Status".into(),
            variants: vec![],
        });
        assert_eq!(
            db.resolve_type("Status"),
            Some(CType::Enum("Status".into()))
        );
    }

    #[test]
    fn db_typedef_chain() {
        let mut db = TypeDatabase::new();
        db.add_typedef("A", CType::Struct("B".into()));
        db.add_typedef("B", CType::Primitive(TypeKind::Int));
        // resolve_type("A") should follow A -> Struct("B"), then check
        // typedefs for "B" -> Primitive(Int).
        assert_eq!(db.resolve_type("A"), Some(CType::Primitive(TypeKind::Int)));
    }

    #[test]
    fn db_json_roundtrip() {
        let mut db = TypeDatabase::new();
        db.add_typedef("Handle", CType::Primitive(TypeKind::UInt));
        db.add_struct(StructDef {
            name: "Header".into(),
            fields: vec![StructField {
                name: "magic".into(),
                ty: CType::Primitive(TypeKind::UInt),
                offset: 0,
            }],
            size: 4,
        });
        let json = db.to_json().unwrap();
        let db2 = TypeDatabase::from_json(&json).unwrap();
        assert_eq!(db, db2);
    }

    // ----- TypeKind sizes (LP64) -----

    #[test]
    fn sizeof_primitives_lp64() {
        assert_eq!(TypeKind::Void.size_bytes(), 0);
        assert_eq!(TypeKind::Char.size_bytes(), 1);
        assert_eq!(TypeKind::Short.size_bytes(), 2);
        assert_eq!(TypeKind::Int.size_bytes(), 4);
        assert_eq!(TypeKind::Long.size_bytes(), 8);
        assert_eq!(TypeKind::LongLong.size_bytes(), 8);
        assert_eq!(TypeKind::Float.size_bytes(), 4);
        assert_eq!(TypeKind::Double.size_bytes(), 8);
        assert_eq!(TypeKind::SizeT.size_bytes(), 8);
        assert_eq!(TypeKind::PtrDiffT.size_bytes(), 8);
    }
}
