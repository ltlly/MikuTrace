// Simple C type expression parser — validates and normalises C type strings
// entered via the decompile panel's "set type" dialog (IDA Y key).
//
// Supports:
//   base types: void, char, short, int, long, float, double
//   modifiers:  signed, unsigned, const, volatile
//   stdint:     int8_t .. uint64_t, size_t, ssize_t, ptrdiff_t, etc.
//   pointers:   int*, char**, void***
//   structs:    struct Name, struct Name*
//   typedefs:   any identifier passed through

const C_BASE_TYPES = new Set([
  "void", "char", "short", "int", "long", "float", "double",
]);

const C_MODIFIERS = new Set([
  "signed", "unsigned", "const", "volatile",
]);

const C_STDINT_TYPES = new Set([
  "int8_t", "int16_t", "int32_t", "int64_t",
  "uint8_t", "uint16_t", "uint32_t", "uint64_t",
  "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t",
  "bool",
]);

export interface CTypeResult {
  valid: boolean;
  normalized: string;  // canonical form
  error?: string;
}

interface ParseState {
  input: string;
  pos: number;
}

function skipWS(s: ParseState) {
  while (s.pos < s.input.length && s.input[s.pos] === " ") s.pos++;
}

function peek(s: ParseState): string {
  return s.pos < s.input.length ? s.input[s.pos] : "";
}

function consume(s: ParseState): string {
  return s.input[s.pos++] ?? "";
}

function expectWord(s: ParseState, word: string): boolean {
  const start = s.pos;
  for (let i = 0; i < word.length; i++) {
    if (s.pos >= s.input.length || s.input[s.pos] !== word[i]) {
      s.pos = start;
      return false;
    }
    s.pos++;
  }
  return true;
}

function readIdentifier(s: ParseState): string {
  const start = s.pos;
  while (s.pos < s.input.length && /[a-zA-Z0-9_]/.test(s.input[s.pos])) {
    s.pos++;
  }
  return s.input.slice(start, s.pos);
}

function readNumber(s: ParseState): string {
  const start = s.pos;
  while (s.pos < s.input.length && /[0-9]/.test(s.input[s.pos])) {
    s.pos++;
  }
  return s.input.slice(start, s.pos);
}

/// Parse a C type expression. Returns { valid, normalized, error? }.
export function parseCType(input: string): CTypeResult {
  const trimmed = input.trim();
  if (!trimmed) return { valid: false, normalized: "", error: "empty type" };

  // Struct prefix
  let prefix = "";
  let base = "";
  const s: ParseState = { input: trimmed, pos: 0 };
  skipWS(s);

  // Struct?
  if (expectWord(s, "struct")) {
    skipWS(s);
    const name = readIdentifier(s);
    if (!name) return { valid: false, normalized: trimmed, error: "struct name required" };
    prefix = "struct";
    base = name;
  } else if (expectWord(s, "union")) {
    skipWS(s);
    const name = readIdentifier(s);
    if (!name) return { valid: false, normalized: trimmed, error: "union name required" };
    prefix = "union";
    base = name;
  } else if (expectWord(s, "enum")) {
    skipWS(s);
    const name = readIdentifier(s);
    if (!name) return { valid: false, normalized: trimmed, error: "enum name required" };
    prefix = "enum";
    base = name;
  } else {
    // Modifiers (signed, unsigned, const, volatile)
    const modifiers: string[] = [];
    while (s.pos < s.input.length) {
      skipWS(s);
      const word = readIdentifier(s);
      if (!word) break;
      if (C_MODIFIERS.has(word)) {
        modifiers.push(word);
        continue;
      }
      if (C_BASE_TYPES.has(word) || C_STDINT_TYPES.has(word)) {
        base = word;
        prefix = modifiers.join(" ");
        break;
      }
      // Unknown word — treat as typedef
      base = word;
      if (modifiers.length > 0) {
        return { valid: false, normalized: trimmed, error: `modifiers before typedef '${word}'` };
      }
      break;
    }
    // If we had modifiers but no base type, it's a modifier-as-type (e.g. "unsigned" = "unsigned int")
    if (modifiers.length > 0 && !base) {
      base = "int";
      prefix = modifiers.join(" ");
    }
    if (!base) {
      return { valid: false, normalized: trimmed, error: "no base type found" };
    }
    // Numeric-only or leading-digit identifiers are not valid types
    if (/^\d/.test(base)) {
      return { valid: false, normalized: trimmed, error: `'${base}' is not a valid type name` };
    }
  }

  // Pointer asterisks
  let ptrDepth = 0;
  while (s.pos < s.input.length) {
    skipWS(s);
    if (peek(s) === "*") {
      consume(s);
      ptrDepth++;
      // Check for const after *
      skipWS(s);
      expectWord(s, "const");
      continue;
    }
    break;
  }

  // Array brackets (e.g., int[10], char[])
  let arraySuffix = "";
  while (s.pos < s.input.length) {
    skipWS(s);
    if (peek(s) === "[") {
      consume(s);
      const size = readNumber(s);
      skipWS(s);
      if (peek(s) !== "]") {
        return { valid: false, normalized: trimmed, error: "unclosed array bracket" };
      }
      consume(s); // skip ]
      arraySuffix += size ? `[${size}]` : "[]";
      continue;
    }
    break;
  }

  skipWS(s);
  if (s.pos < s.input.length) {
    return { valid: false, normalized: trimmed, error: `unexpected '${peek(s)}' at position ${s.pos}` };
  }

  // Build normalised form
  let normalized = "";
  if (prefix === "struct" || prefix === "union" || prefix === "enum") {
    normalized = `${prefix} ${base}`;
  } else if (prefix) {
    normalized = `${prefix} ${base}`;
  } else {
    normalized = base;
  }
  for (let i = 0; i < ptrDepth; i++) {
    normalized += " *";
  }
  if (ptrDepth > 0) normalized = normalized.trim();
  normalized += arraySuffix;
  // Clean up double spaces
  normalized = normalized.replace(/\s+/g, " ").trim();

  return { valid: true, normalized };
}
