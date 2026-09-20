/**
 * Hallucinated Method Call detector
 *
 * AI models confidently invent methods that don't exist on the object/
 * library they're calling (`array.isEmpty()`, `Array.flatten()`,
 * `JSON.validate()`) -- code that reads plausibly but throws
 * `TypeError: X is not a function` at runtime. This is a real, AI-specific
 * defect class that classic SAST tools don't check for.
 *
 * This is intentionally separate from `sigHallucinatedAPI()` in scanner.ts
 * (Signal 46), which is a whole-file, line-unaware regex heuristic that
 * only feeds the calibrated AI%-likelihood ensemble -- it is not a security
 * finding and is left completely untouched. This module produces a real,
 * line-numbered `security: true` ScanIndicator instead, registered via
 * detectorRegistry.ts (see scanner.ts's `detectorRegistry.register(...)`
 * call), so it rides the existing violations/alerts/PR-comment pipeline.
 *
 * No AST/type parser exists anywhere in this codebase, so "does this
 * method really exist" can never be proven via type inference -- only via
 * hand-curated allowlists of real methods on a small set of stable
 * built-ins (same hand-curated-table convention as dependencyScan.ts's
 * NON_CVE_RISK_DB).
 *
 * Two tiers:
 *   Tier A -- allowlist check, but ONLY on unambiguous receivers (an array/
 *     string literal, a static namespace object like `Array.`/`JSON.`, or a
 *     variable whose most recent nearby assignment is unambiguously a
 *     constructor for that type). A bare `x.foo()` with no such evidence is
 *     explicitly out of scope -- a wrong flag is worse than a missed one.
 *   Tier B -- an expanded, hand-vetted regex blocklist of well-documented
 *     AI-hallucination idioms (the "...AndX" chained-method family), run
 *     per line so every hit carries a real line number (the existing
 *     scanner.ts signal only tests the whole file at once).
 *
 * JS/TS only for v1. Python is deferred: JS's `= []` literal-vs-variable
 * distinction doesn't transfer cleanly to Python's duck-typing culture,
 * where legitimate custom classes commonly implement `.get()`/`__len__`/
 * etc., making a "real dict/list methods" allowlist meaningfully more
 * false-positive-prone there.
 */

import type { ScanIndicator } from "./scanner";
import type { DetectorContext } from "./detectorRegistry";

const ID = "hallucinated-method-call";
const LABEL = "Hallucinated Method Call";

// ── Real-method allowlists ──────────────────────────────────────────────────
// Static (namespace-side, e.g. `Array.isArray(x)`) vs instance (receiver-side,
// e.g. `[].map(...)` / `arr.map(...)`) are kept separate since they're real,
// different method sets -- `Array.prototype.map` is not a static method, and
// `Array.isArray` is not an instance method.

const ARRAY_STATIC_METHODS = new Set(["isArray", "from", "of"]);
const ARRAY_INSTANCE_METHODS = new Set([
  "push", "pop", "shift", "unshift", "slice", "splice", "concat", "join", "reverse", "sort",
  "indexOf", "lastIndexOf", "includes", "find", "findIndex", "findLast", "findLastIndex",
  "filter", "map", "forEach", "reduce", "reduceRight", "some", "every", "flat", "flatMap",
  "fill", "copyWithin", "keys", "values", "entries", "at", "toString", "toLocaleString",
  "toReversed", "toSorted", "toSpliced", "with",
]);

const OBJECT_STATIC_METHODS = new Set([
  "keys", "values", "entries", "assign", "freeze", "isFrozen", "seal", "isSealed",
  "preventExtensions", "isExtensible", "create", "defineProperty", "defineProperties",
  "getOwnPropertyDescriptor", "getOwnPropertyDescriptors", "getOwnPropertyNames",
  "getOwnPropertySymbols", "getPrototypeOf", "setPrototypeOf", "is", "fromEntries", "groupBy",
]);
const OBJECT_INSTANCE_METHODS = new Set([
  "hasOwnProperty", "toString", "valueOf", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString",
]);

const STRING_STATIC_METHODS = new Set(["fromCharCode", "fromCodePoint", "raw"]);
const STRING_INSTANCE_METHODS = new Set([
  "charAt", "charCodeAt", "codePointAt", "concat", "includes", "endsWith", "indexOf",
  "lastIndexOf", "localeCompare", "match", "matchAll", "normalize", "padEnd", "padStart",
  "repeat", "replace", "replaceAll", "search", "slice", "split", "startsWith", "substring",
  "substr", "toLowerCase", "toUpperCase", "toLocaleLowerCase", "toLocaleUpperCase", "trim",
  "trimStart", "trimEnd", "toString", "valueOf", "at",
]);

const JSON_STATIC_METHODS = new Set(["parse", "stringify"]);

const MATH_STATIC_METHODS = new Set([
  "abs", "acos", "acosh", "asin", "asinh", "atan", "atan2", "atanh", "cbrt", "ceil", "clz32",
  "cos", "cosh", "exp", "expm1", "floor", "fround", "hypot", "imul", "log", "log10", "log1p",
  "log2", "max", "min", "pow", "random", "round", "sign", "sin", "sinh", "sqrt", "tan", "tanh", "trunc",
]);

const NUMBER_STATIC_METHODS = new Set(["isInteger", "isFinite", "isNaN", "isSafeInteger", "parseFloat", "parseInt"]);
const NUMBER_INSTANCE_METHODS = new Set(["toFixed", "toPrecision", "toExponential", "toString", "valueOf", "toLocaleString"]);

const STATIC_NAMESPACES: Record<string, Set<string>> = {
  Array: ARRAY_STATIC_METHODS,
  Object: OBJECT_STATIC_METHODS,
  JSON: JSON_STATIC_METHODS,
  Math: MATH_STATIC_METHODS,
  Number: NUMBER_STATIC_METHODS,
  String: STRING_STATIC_METHODS,
};

// ── Tier B: expanded, hand-vetted blocklist of hallucination idioms ────────
// Deliberately a fresh, distinct list from scanner.ts's HALLUCINATED_API_
// PATTERNS (Signal 46) -- that constant belongs to the calibrated AI%
// ensemble and must not be imported/touched here.

// Each pattern captures its receiver token (group 1, an identifier or
// `this`) so a mock-factory receiver can be suppressed the same way Tier A
// suppresses one -- almost every real call site has some identifier
// immediately before the dot, so this doesn't meaningfully narrow recall.
const TIER_B_PATTERNS: RegExp[] = [
  /\b(this|[A-Za-z_$][\w$]*)\s*\.\s*validateAnd(?:Save|Parse|Return|Process|Submit|Send|Throw)\s*\(/i,
  /\b(this|[A-Za-z_$][\w$]*)\s*\.\s*parseAnd(?:Validate|Return|Process|Save|Transform)\s*\(/i,
  /\b(this|[A-Za-z_$][\w$]*)\s*\.\s*fetchAnd(?:Update|Save|Return|Process|Store)\s*\(/i,
  /\b(this|[A-Za-z_$][\w$]*)\s*\.\s*getAnd(?:Set|Update|Return|Process|Validate)\s*\(/i,
  /\b(this|[A-Za-z_$][\w$]*)\s*\.\s*findOneAndValidate\s*\(/i,
  /\b(this|[A-Za-z_$][\w$]*)\s*\.\s*saveAndReturn\s*\(/i,
  /\b(this|[A-Za-z_$][\w$]*)\s*\.\s*updateAndRefresh\s*\(/i,
  /\b(this|[A-Za-z_$][\w$]*)\s*\.\s*deleteAndCleanup\s*\(/i,
  /\b(this|[A-Za-z_$][\w$]*)\s*\.\s*sanitizeAndEscape\s*\(/i,
  /\b(this|[A-Za-z_$][\w$]*)\s*\.\s*mergeAndDedupe\s*\(/i,
  /\b(this|[A-Za-z_$][\w$]*)\s*\.\s*toSnakeCase\s*\(/,
  /\b(this|[A-Za-z_$][\w$]*)\s*\.\s*toTitleCase\s*\(/,
  /\b(this|[A-Za-z_$][\w$]*)\s*\.\s*toCamelCaseDeep\s*\(/,
  /\b(this|[A-Za-z_$][\w$]*)\s*\.\s*deepClone\s*\(\s*\)/,
];

// ── Non-executable line filter ──────────────────────────────────────────────
// Intentionally a small, local copy of scanner.ts's isNonExecutableLine --
// duplicated rather than importing an unexported helper, to keep this module
// self-contained (same module-boundary convention as dependencyScan.ts/
// depAnalysis.ts, which don't reach into scanner.ts's internals either).

function isNonExecutableLine(line: string): boolean {
  const t = line.trim();
  return t.startsWith("//") || t.startsWith("#") || t.startsWith("*") || t.startsWith("/*");
}

// ── Guardrails ───────────────────────────────────────────────────────────────

// If the file itself defines/monkey-patches a method of this name anywhere
// (a real polyfill, a class that legitimately implements it), suppress
// flagging that method name for the whole file. Bounded quantifiers avoid
// ReDoS on large files; a shadow definition further than ~3000 chars into a
// single class body would be missed, which is an acceptable conservative
// trade-off (fewer false positives at the cost of rare false negatives).
const shadowCache = new Map<string, boolean>();
function hasLocalShadow(content: string, methodName: string): boolean {
  const key = methodName;
  const cached = shadowCache.get(key);
  if (cached !== undefined) return cached;
  const protoRe = new RegExp(`\\.prototype\\.${methodName}\\s*=`);
  const classRe = new RegExp(`class\\s+\\w+[^{]{0,200}\\{[^}]{0,3000}\\b${methodName}\\s*\\(`);
  const result = protoRe.test(content) || classRe.test(content);
  shadowCache.set(key, result);
  return result;
}

// Test doubles legitimately have "fake" methods -- don't flag a receiver
// whose nearby assignment looks like a mock/stub factory.
const MOCK_FACTORY_RE = /=\s*(?:jest\.fn\(|sinon\.|vi\.fn\(|\{[^}]{0,200}:\s*(?:jest\.fn|vi\.fn)\()/;

// Shared by both tiers: does `name`'s nearest assignment within a small
// backward window (same line + up to 3 non-blank lines above) look like a
// mock/stub factory? Used to suppress findings on test doubles, which
// legitimately implement "fake" methods on purpose.
function receiverLooksLikeMock(lines: string[], lineIdx: number, name: string): boolean {
  const nameRe = new RegExp(`\\b${name}\\s*(?::[^=]+)?=`);
  let seen = 0;
  for (let i = lineIdx; i >= 0 && seen < 4; i--) {
    const line = lines[i];
    if (line.trim().length === 0) continue;
    seen++;
    if (!nameRe.test(line)) continue;
    return MOCK_FACTORY_RE.test(line);
  }
  return false;
}

// Constructor evidence for a bare-identifier receiver, checked within a
// small backward window (same line + up to 3 non-blank lines above) --
// string/regex based, not real scope analysis, deliberately conservative.
const ARRAY_CTOR_RE = /=\s*(?:\[\s*\]|\[[^\]]{0,300}\]|Array\.from\(|Array\(|new\s+Array\()/;
const OBJECT_CTOR_RE = /=\s*(?:\{\s*\}|Object\.keys\(|Object\.values\(|Object\.entries\(|Object\.assign\()/;

type ReceiverKind = "array" | "object" | null;

function resolveIdentifierReceiver(lines: string[], lineIdx: number, name: string): ReceiverKind | "mock" {
  if (receiverLooksLikeMock(lines, lineIdx, name)) return "mock";
  const nameRe = new RegExp(`\\b${name}\\s*(?::[^=]+)?` + "=");
  let seen = 0;
  for (let i = lineIdx; i >= 0 && seen < 4; i--) {
    const line = lines[i];
    if (line.trim().length === 0) continue;
    seen++;
    if (!nameRe.test(line)) continue;
    if (ARRAY_CTOR_RE.test(line)) return "array";
    if (OBJECT_CTOR_RE.test(line)) return "object";
    return null; // assigned, but not to an unambiguous constructor -- stay out of scope
  }
  return null;
}

// ── Call-site extraction (Tier A) ───────────────────────────────────────────
// One receiver-capturing regex, classified in code rather than via several
// overlapping regexes -- array/string literals and bare identifiers are
// naturally disjoint (literals can't start with a word character), so a
// single alternation is unambiguous to parse per match.
const CALL_SITE_RE =
  /(\[[^[\]]{0,200}\]|"(?:[^"\\]|\\.){0,200}"|'(?:[^'\\]|\\.){0,200}'|`(?:[^`\\]|\\.){0,200}`|[A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*\(/g;

function tierAFindings(lines: string[], content: string): ScanIndicator[] {
  const out: ScanIndicator[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isNonExecutableLine(line)) continue;

    CALL_SITE_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = CALL_SITE_RE.exec(line))) {
      const receiver = m[1];
      const method = m[2];
      let realMethods: Set<string> | null = null;

      const first = receiver[0];
      if (first === "[") {
        realMethods = ARRAY_INSTANCE_METHODS;
      } else if (first === '"' || first === "'" || first === "`") {
        realMethods = STRING_INSTANCE_METHODS;
      } else if (Object.prototype.hasOwnProperty.call(STATIC_NAMESPACES, receiver)) {
        // Object.hasOwn/hasOwnProperty, not `in` -- `in` also matches
        // inherited Object.prototype property names (toString, valueOf,
        // constructor, hasOwnProperty itself, ...), so a receiver literally
        // named e.g. "toString" would look up Object.prototype.toString
        // (a function) instead of undefined, and the .has() call below
        // would throw since it's not a Set.
        realMethods = STATIC_NAMESPACES[receiver];
      } else {
        const kind = resolveIdentifierReceiver(lines, i, receiver);
        if (kind === "mock") continue;
        if (kind === "array") realMethods = ARRAY_INSTANCE_METHODS;
        else if (kind === "object") realMethods = OBJECT_INSTANCE_METHODS;
        else continue; // ambiguous receiver -- out of scope for Tier A
      }

      if (realMethods.has(method)) continue;
      if (hasLocalShadow(content, method)) continue;

      out.push({
        id: ID,
        label: LABEL,
        severity: "medium",
        line: i + 1,
        detail: `\`${receiver.length > 40 ? receiver.slice(0, 40) + "…" : receiver}.${method}()\` does not exist on this built-in type -- likely an AI-invented API that will throw \`TypeError\` at runtime.`,
        confidence: 72,
      });
    }
  }
  return out;
}

// ── Tier B: per-line blocklist ───────────────────────────────────────────────

function tierBFindings(lines: string[]): ScanIndicator[] {
  const out: ScanIndicator[] = [];
  const seen = new Set<number>();
  for (const re of TIER_B_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      if (seen.has(i)) continue;
      if (isNonExecutableLine(lines[i])) continue;
      const m = re.exec(lines[i]);
      if (!m) continue;
      const receiver = m[1];
      if (receiver !== "this" && receiverLooksLikeMock(lines, i, receiver)) continue;
      seen.add(i);
      out.push({
        id: ID,
        label: LABEL,
        severity: "medium",
        line: i + 1,
        detail: "Chained-method name matches a well-documented AI-hallucination pattern -- verify this method actually exists on the receiver before merging.",
        confidence: 58,
      });
    }
  }
  return out;
}

// ── Entry point (registered via detectorRegistry) ──────────────────────────

export function scanHallucinatedMethodCalls(ctx: DetectorContext): ScanIndicator[] {
  if (ctx.language !== "javascript" && ctx.language !== "typescript") return [];
  shadowCache.clear();
  return [...tierAFindings(ctx.lines, ctx.content), ...tierBFindings(ctx.lines)];
}
