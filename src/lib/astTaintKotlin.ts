/**
 * Real AST-based taint engine for Kotlin (Spring MVC / WebFlux, Ktor, Servlet) -- the eighth engine, mirroring
 * astTaintRuby.ts's structure and astTaintJava.ts's JVM vocabulary: sources, sinks, propagation, interprocedural
 * summaries, findings with source -> sink traces, cross-file parameter -> sink facts, and an object-level
 * authorization (BOLA) check. Shared semantics come from taint/taintCore.ts, taint/sanitizers.ts ("kt" table),
 * taint/sinkShape.ts and taint/principal.ts.
 *
 * Kotlin and Java share one cross-file fact namespace: facts are keyed `Class.method` exactly like
 * computeJavaMethodSinkFacts, and scanner.ts converges both languages together, so a Kotlin controller calling a
 * Java service (or the reverse) gets the same evidence as a same-language call.
 *
 * Parsing uses tree-sitter-wasms' tree-sitter-kotlin.wasm through the shared web-tree-sitter runtime. That grammar
 * has NO field names, so everything below reads children by type and position. Shapes confirmed by probing:
 *  - `a.b(c)` is call_expression[navigation_expression[a, navigation_suffix[b]], call_suffix[value_arguments]];
 *    a trailing lambda is call_suffix > annotated_lambda > lambda_literal; `f(x) { }` (Ktor's `get("/") { }`)
 *    nests the first call as the callee of the second.
 *  - Named arguments are value_argument[simple_identifier, <=>, expr]; spreads are spread_expression.
 *  - "a $b ${c}" is string_literal with interpolated_identifier / interpolated_expression children.
 *  - Parameter annotations are `parameter_modifiers` SIBLINGS preceding each `parameter`.
 *  - A top-level class's annotations that take arguments (`@RequestMapping("/api")`) can parse as an expression
 *    statement BEFORE the class_declaration rather than inside its `modifiers` -- classAnnotations reads both.
 *  - `null` is an unnamed token; jump_expression's keyword is its first token (return, return@x, throw, ...).
 *
 * Kotlin-specific modelling decisions:
 *  - Sources: Spring binding annotations (@RequestParam, @PathVariable, @RequestBody, ...) and JAX-RS ones; a
 *    parameter typed as a number/boolean/UUID/date carries only CONTROL (it can still pick WHICH record, so BOLA
 *    sees it, but it can't inject). Ktor `call.parameters` / `call.request.*` / `call.receive*()`; Servlet and
 *    WebFlux request getters, in call or Kotlin property form (`request.queryString`).
 *  - Scope functions and collection lambdas propagate: `x.let { it.trim() }`, `list.map { ... }`, `forEach`.
 *  - Receiver conversions (`x.toInt()`, `toLongOrNull()`) coerce; predicates (`isBlank()`, `startsWith`) yield an
 *    untainted result; an opaque call on an untainted receiver stays untainted -- the contract every engine keeps.
 *    Constructors carry their arguments (a DTO built from input holds that input).
 *  - Class properties written in one function and read in another are file-wide sticky state, re-walked to a fixed
 *    point (same as Java fields / Ruby ivars).
 *  - Spring view names: a @Controller handler returning a request-controlled view name is template injection
 *    (Thymeleaf view manipulation); `"redirect:" + x` is an open redirect.
 *  - A path construction whose result is only used for its file NAME (`File(x).name`, `Paths.get(x).fileName`) is
 *    not a traversal.
 *
 * Runs ADDITIVELY next to kotlinTaint.ts's line-based pass and the shared regex detectors (which remain the
 * fallback whenever the grammar is unavailable); a flow proven safe here vetoes their duplicate via SuppressedSink.
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { Parser, Language } = require("web-tree-sitter") as typeof import("web-tree-sitter");
import type { Node as SyntaxNode, Language as LanguageT, Parser as ParserT } from "web-tree-sitter";
import { ensureTreeSitterInit, rootIfShallowEnough } from "./treeSitterRuntime";
import {
  ALL, FIXED_POINT_CAP, SHADOW, SinkClass, applyClears, applySanitizer, applyGuards, buildBackwardTraceGeneric, classOf, cloneEnv,
  crossFileTrace, displayFnName, dropOnPathDuplicates, factStepsFromTrace, mergeSinkFacts, walkIfChain, walkLoop, walkSwitch, walkTry,
  wasCleared, type Branch, type Guard, type ParamSinkFact, type SuppressedSink, type TaintEnv, type TraceResolver, type TraceStep,
} from "./taint/taintCore";
import { sanitizerClears, NUMERIC_CLEARS } from "./taint/sanitizers";
import { assessSqlInjection, assessSsrfUrl, type UrlPart } from "./taint/sinkShape";
import { authzVerdict, classifyGuardName, isOwnerField, type AuthzKind } from "./taint/principal";
import { astTaintJavaLabel, astTaintJavaSeverity, type AstTaintJavaId } from "./astTaintJava";

declare const __non_webpack_require__: NodeJS.Require | undefined;
function nodeRequire(): NodeJS.Require {
  // eslint-disable-next-line no-undef
  return typeof __non_webpack_require__ !== "undefined" ? __non_webpack_require__ : require;
}

/** Same finding vocabulary as Java: Kotlin findings are JVM findings everywhere downstream. */
export type AstTaintKotlinId = AstTaintJavaId;

export interface AstTaintKotlinFinding {
  id:         AstTaintKotlinId;
  line:       number;
  detail:     string;
  sourceExpr: string;
  sinkExpr:   string;
  /** True when the finding exists only because an un-annotated entry-point parameter was treated as untrusted. */
  entryPointSeeded?: boolean;
  severityOverride?: "critical" | "high" | "medium";
  trace?: TraceStep[];
  calleeSink?: { file: string; line: number; sinkExpr: string; via: string[] };
}

export function astTaintKotlinSeverity(id: AstTaintKotlinId): "critical" | "high" | "medium" { return astTaintJavaSeverity(id); }
export function astTaintKotlinLabel(id: AstTaintKotlinId): string { return astTaintJavaLabel(id); }

// ── Parser lifecycle (warm-cache pattern, see astTaintCSharp.ts) ───────────────────────────────────────────

let langPromise: Promise<LanguageT> | null = null;
let parserPool: ParserT | null = null;

function initKotlinParser(): Promise<LanguageT> {
  if (!langPromise) {
    langPromise = (async () => {
      await ensureTreeSitterInit();
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const fs = require("fs") as typeof import("fs");
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const path = require("path") as typeof import("path");
      const webTreeSitterEntry = nodeRequire().resolve("web-tree-sitter");
      const nodeModulesDir = path.dirname(path.dirname(webTreeSitterEntry));
      const wasmPath = path.join(nodeModulesDir, "tree-sitter-wasms", "out", "tree-sitter-kotlin.wasm");
      const lang = await Language.load(new Uint8Array(fs.readFileSync(wasmPath)));
      const p = new Parser();
      p.setLanguage(lang);
      parserPool = p;
      console.log("[astTaintKotlin] Kotlin AST taint engine ready");
      return lang;
    })().catch(err => {
      console.error("[astTaintKotlin] WASM init failed -- Kotlin AST taint scanning disabled, regex detectors unaffected:", err);
      throw err;
    });
  }
  return langPromise;
}
if (!process.env.JEST_WORKER_ID) {
  void initKotlinParser().catch(() => { /* already logged above */ });
}

export function isKotlinParserReady(): boolean {
  return parserPool !== null;
}

export async function warmKotlinTaintEngine(): Promise<void> {
  await initKotlinParser().catch(() => { /* already logged; callers just proceed regex-only */ });
}

export function parseKotlinSourceSync(content: string, filePath: string): SyntaxNode | null {
  if (!parserPool) return null;
  try {
    return rootIfShallowEnough(parserPool.parse(content)?.rootNode, "astTaintKotlin", filePath);
  } catch (err) {
    console.error(`[astTaintKotlin] parse threw for ${filePath}:`, err);
    return null;
  }
}

// ── Enclosing-function lookup (reachability.ts / scanner.ts) ────────────────────────────────────────────────

export function findNodeAtRowKotlin(root: SyntaxNode, row: number): SyntaxNode {
  let node = root;
  for (;;) {
    const child = node.namedChildren.find(c => c && row >= c.startPosition.row && row <= c.endPosition.row);
    if (!child) return node;
    node = child;
  }
}

export function findEnclosingFunctionNameKotlin(node: SyntaxNode): string {
  for (let cur: SyntaxNode | null = node; cur; cur = cur.parent) {
    if (cur.type === "function_declaration") {
      const nameNode = childOfType(cur, "simple_identifier");
      if (nameNode) return nameNode.text;
    }
  }
  return "unknown";
}

// ── Tree helpers ───────────────────────────────────────────────────────────────────────────────────────────

const lineOf = (n: SyntaxNode) => n.startPosition.row + 1;
const named = (n: SyntaxNode | null | undefined): SyntaxNode[] => (n ? n.namedChildren.filter((c): c is SyntaxNode => !!c) : []);
const childOfType = (n: SyntaxNode | null | undefined, type: string): SyntaxNode | null => named(n).find(c => c.type === type) ?? null;
const childrenOfType = (n: SyntaxNode | null | undefined, type: string): SyntaxNode[] => named(n).filter(c => c.type === type);

function findAllNodes(root: SyntaxNode, type: string | ReadonlySet<string>, acc: SyntaxNode[] = []): SyntaxNode[] {
  if (typeof type === "string" ? root.type === type : type.has(root.type)) acc.push(root);
  for (const c of root.namedChildren) if (c) findAllNodes(c, type, acc);
  return acc;
}

/** First unnamed (token) child's type: an expression's operator (`==`, `+`, `!`, `+=`, `return`...). */
function operatorOf(n: SyntaxNode): string {
  for (let i = 0; i < n.childCount; i++) {
    const c = n.child(i);
    if (c && !c.isNamed) return c.type;
  }
  return "";
}

/** `x` / `a.b.c` / `Runtime.getRuntime().exec` (calls flattened) -> dotted text, or null for anything else. */
function calleeText(n: SyntaxNode | null): string | null {
  if (!n) return null;
  switch (n.type) {
    case "simple_identifier": case "this_expression": case "type_identifier": return n.text;
    case "navigation_expression": {
      const kids = named(n);
      const suffix = kids[kids.length - 1];
      const member = suffix?.type === "navigation_suffix" ? childOfType(suffix, "simple_identifier")?.text : null;
      const base = calleeText(kids[0] ?? null);
      return base !== null && member ? `${base}.${member}` : null;
    }
    case "call_expression": return calleeText(named(n)[0] ?? null);
    case "parenthesized_expression": return calleeText(named(n)[0] ?? null);
    default: return null;
  }
}

interface CallParts { name: string; recv: SyntaxNode | null; callee: SyntaxNode | null; suffix: SyntaxNode | null }
function callParts(call: SyntaxNode): CallParts {
  const kids = named(call);
  const callee = kids[0] ?? null;
  const suffix = kids.find(k => k.type === "call_suffix") ?? null;
  if (callee?.type === "simple_identifier") return { name: callee.text, recv: null, callee, suffix };
  if (callee?.type === "navigation_expression") {
    const nk = named(callee);
    const navSuffix = nk[nk.length - 1];
    const name = navSuffix?.type === "navigation_suffix" ? childOfType(navSuffix, "simple_identifier")?.text ?? "" : "";
    return { name, recv: nk[0] ?? null, callee, suffix };
  }
  return { name: "", recv: callee, callee, suffix };
}
/** The member a navigation_expression reads (`a.b` -> "b"). */
function memberOf(nav: SyntaxNode): string {
  const kids = named(nav);
  const s = kids[kids.length - 1];
  return s?.type === "navigation_suffix" ? childOfType(s, "simple_identifier")?.text ?? "" : "";
}

interface Arg { name: string | null; expr: SyntaxNode; spread: boolean }
function argsOf(call: SyntaxNode): Arg[] {
  const va = childOfType(childOfType(call, "call_suffix"), "value_arguments");
  return argsOfList(va);
}
function argsOfList(va: SyntaxNode | null): Arg[] {
  const out: Arg[] = [];
  for (const a of childrenOfType(va, "value_argument")) {
    const kids = named(a);
    if (kids.length === 0) continue;
    if (kids.length >= 2 && kids[0].type === "simple_identifier" && operatorOf(a) === "=") {
      out.push({ name: kids[0].text, expr: kids[kids.length - 1], spread: false });
    } else if (kids[kids.length - 1].type === "spread_expression") {
      const inner = named(kids[kids.length - 1])[0];
      if (inner) out.push({ name: null, expr: inner, spread: true });
    } else {
      out.push({ name: null, expr: kids[kids.length - 1], spread: false });
    }
  }
  return out;
}
const positionalArgs = (call: SyntaxNode): SyntaxNode[] => argsOf(call).filter(a => !a.name).map(a => a.expr);
const namedArg = (call: SyntaxNode, key: string): SyntaxNode | null => argsOf(call).find(a => a.name === key)?.expr ?? null;
function trailingLambda(call: SyntaxNode): SyntaxNode | null {
  const al = childOfType(childOfType(call, "call_suffix"), "annotated_lambda");
  return childOfType(al, "lambda_literal");
}

/** A string literal's text when it has no interpolation, else null. */
function stringValue(n: SyntaxNode | null | undefined): string | null {
  if (!n || n.type !== "string_literal") return null;
  const kids = named(n);
  if (kids.some(c => c.type !== "string_content" && c.type !== "escape_sequence" && c.type !== "character_escape_seq")) return null;
  return kids.map(c => c.text).join("");
}
const LITERAL_TYPES = new Set([
  "integer_literal", "real_literal", "boolean_literal", "character_literal", "long_literal", "hex_literal", "bin_literal",
  "unsigned_literal", "string_content", "callable_reference", "type_test", "label", "null", "line_comment", "multiline_comment",
]);
const isLiteral = (n: SyntaxNode) => stringValue(n) !== null || LITERAL_TYPES.has(n.type);

/** `String`, `List<String>?`, `org.x.User` -> its simple name with generics (`List<String>`), no nullability. */
function typeNameOf(n: SyntaxNode | null | undefined): string {
  if (!n) return "";
  return n.text.replace(/\?$/, "").replace(/^(?:[a-z_][\w]*\.)+/, "").trim();
}
const bareType = (t: string) => t.replace(/<.*$/, "").replace(/\?$/, "");

/** Annotation simple names in a `modifiers` / `parameter_modifiers` node (`@PathVariable("id")` -> "PathVariable"). */
function annotationNames(mods: SyntaxNode | null | undefined): string[] {
  const out: string[] = [];
  for (const a of findAllNodes(mods ?? null as unknown as SyntaxNode, "annotation")) {
    const t = childOfType(a, "user_type") ?? childOfType(childOfType(a, "constructor_invocation"), "user_type");
    const ids = t ? findAllNodes(t, "type_identifier") : [];
    const last = ids[ids.length - 1];
    if (last) out.push(last.text);
  }
  return out;
}
function annotationNodes(mods: SyntaxNode | null | undefined): SyntaxNode[] {
  return mods ? findAllNodes(mods, "annotation") : [];
}
const annotationName = (a: SyntaxNode) => {
  const t = childOfType(a, "user_type") ?? childOfType(childOfType(a, "constructor_invocation"), "user_type");
  const ids = t ? findAllNodes(t, "type_identifier") : [];
  return ids[ids.length - 1]?.text ?? "";
};

/** A class's annotations: its `modifiers`, plus annotation-only statements right before it (see module docblock). */
function classAnnotationNodes(cls: SyntaxNode): SyntaxNode[] {
  if (isRecoveredClass(cls)) {
    const out: SyntaxNode[] = [];
    for (let p = cls.parent; p?.type === "prefix_expression"; p = p.parent) out.push(...childrenOfType(p, "annotation"));
    return out;
  }
  const out = annotationNodes(childOfType(cls, "modifiers"));
  for (let prev = cls.previousNamedSibling; prev; prev = prev.previousNamedSibling) {
    if (prev.type !== "prefix_expression" && prev.type !== "annotation") break;
    const anns = findAllNodes(prev, "annotation");
    if (anns.length === 0) break;
    out.push(...anns);
    if (prev.endPosition.row < cls.startPosition.row - 1) break;
  }
  return out;
}

// ── Sources ────────────────────────────────────────────────────────────────────────────────────────────────

const SPRING_SOURCE_ANNOTATIONS = new Set([
  "PathVariable", "RequestParam", "RequestBody", "RequestHeader", "ModelAttribute", "CookieValue", "MatrixVariable", "RequestPart",
  "QueryParam", "PathParam", "FormParam", "HeaderParam", "CookieParam", "BeanParam", "MatrixParam",
]);
/** Parameter types that can't carry an injection payload -- still attacker-CHOSEN (which record), so CONTROL stays. */
const SAFE_SCALAR_TYPE_RE = /^(?:Int|Long|Short|Byte|Double|Float|Boolean|UInt|ULong|UUID|LocalDate|LocalDateTime|LocalTime|Instant|OffsetDateTime|ZonedDateTime|BigDecimal|BigInteger|Integer|Character|Char)$/;
const SERVLET_SOURCE_CALLS = new Set([
  "getParameter", "getHeader", "getParameterValues", "getQueryString", "getParameterMap", "getParameterNames",
  "getHeaders", "getCookies", "getRequestURI", "getRequestURL", "getPathInfo", "getReader", "getInputStream", "getPart",
  "getParts", "getRemoteUser",
  // WebFlux ServerRequest / ServerHttpRequest
  "queryParam", "queryParams", "pathVariable", "pathVariables", "formData", "multipartData", "bodyToMono", "bodyToFlux",
  "awaitBody", "awaitBodyOrNull", "awaitFormData", "awaitMultipartData",
]);
/** Kotlin property syntax for the same getters (`request.queryString`). */
const SERVLET_SOURCE_PROPS = new Set([
  "queryString", "requestURI", "requestURL", "pathInfo", "cookies", "inputStream", "reader", "parameterMap", "parameterNames",
  "headerNames", "queryParams", "headers", "uri", "body", "parts",
]);
const REQUEST_VAR_RE = /^(?:request|req|httpRequest|servletRequest|httpServletRequest|serverRequest)$/;
const REQUEST_TYPE_RE = /^(?:Http)?ServletRequest(?:Wrapper)?$|^WebRequest$|^NativeWebRequest$|^ServerHttpRequest$|^ServerRequest$/;
/** Ktor: `call.<member>` members that are what the client sent. */
const KTOR_INPUT_MEMBERS = new Set(["parameters", "request", "receive", "receiveText", "receiveParameters", "receiveMultipart", "receiveNullable", "receiveOrNull", "receiveChannel", "receiveStream"]);

// ── Propagation tables ─────────────────────────────────────────────────────────────────────────────────────

const RECEIVER_CLEARS: Record<string, number> = Object.fromEntries([
  "toInt", "toLong", "toShort", "toByte", "toDouble", "toFloat", "toIntOrNull", "toLongOrNull", "toShortOrNull", "toByteOrNull",
  "toDoubleOrNull", "toFloatOrNull", "toBigDecimal", "toBigDecimalOrNull", "toBigInteger", "toBigIntegerOrNull", "toBoolean",
  "toBooleanStrict", "toBooleanStrictOrNull", "toUInt", "toULong", "toUIntOrNull", "toULongOrNull", "roundToInt", "roundToLong",
].map(n => [n, NUMERIC_CLEARS]));
/** Methods whose result says nothing about the receiver's text (a size, a boolean, an index). */
const OPAQUE_RESULT_METHODS = new Set([
  "isEmpty", "isNotEmpty", "isBlank", "isNotBlank", "isNullOrEmpty", "isNullOrBlank", "contains", "containsKey", "containsValue",
  "startsWith", "endsWith", "equals", "equalsIgnoreCase", "contentEquals", "matches", "hashCode", "count", "compareTo", "any",
  "all", "none", "indexOf", "lastIndexOf", "isPresent", "isEmpty", "exists", "hasNext", "size", "length", "isDigit", "isLetter",
  "isLetterOrDigit", "isWhitespace", "isInitialized", "containsMatchIn", "toByteArray",
]);
const OPAQUE_PROPS = new Set(["size", "length", "indices", "lastIndex", "isEmpty", "isNotEmpty", "javaClass", "hashCode", "class"]);
/** Methods on a value whose ARGUMENTS also flow into the result. */
const ARG_FLOW_METHODS = new Set([
  "plus", "format", "replace", "replaceFirst", "replaceRange", "append", "appendLine", "insert", "concat", "copy", "resolve",
  "resolveSibling", "queryParam", "path", "pathSegment", "host", "scheme", "uri", "fromUriString", "fromHttpUrl", "port",
  "plusElement", "zip", "padStart", "padEnd", "replaceAll", "with", "withPath", "setPath", "addPathSegment", "addQueryParameter",
  "build", "buildAndExpand", "expand", "header", "body", "put", "putIfAbsent", "getOrDefault", "getOrElse", "orElse", "or",
]);
/** Methods that write their arguments INTO the receiver variable. */
const MUTATOR_METHODS = new Set(["append", "appendLine", "add", "addAll", "put", "putAll", "set", "insert", "push", "offer", "addFirst", "addLast", "plusAssign", "putIfAbsent", "setProperty"]);
/** Functions / constructors whose result carries their arguments. Uppercase constructors carry them by default. */
const PASSTHROUGH_CALLS = new Set([
  "String.format", "listOf", "mutableListOf", "arrayListOf", "arrayOf", "setOf", "mutableSetOf", "hashSetOf", "mapOf",
  "mutableMapOf", "hashMapOf", "linkedMapOf", "requireNotNull", "checkNotNull", "URI.create", "Paths.get", "Path.of",
  "URLDecoder.decode", "String.valueOf", "Objects.toString", "Objects.requireNonNull", "UriComponentsBuilder.fromHttpUrl",
  "UriComponentsBuilder.fromUriString", "MessageFormat.format", "StringBuilder", "buildString", "sequenceOf", "Optional.of",
  "Optional.ofNullable", "Base64.getDecoder.decode", "Base64.getUrlDecoder.decode", "Base64.getMimeDecoder.decode",
]);
const DECODER_RE = /(?:URLDecoder\.decode|getDecoder\.decode|getUrlDecoder\.decode|getMimeDecoder\.decode)$/;
/** Lambda-taking calls: what the result is. */
const RECEIVER_RESULT_LAMBDAS = new Set(["also", "apply", "takeIf", "takeUnless", "filter", "filterNot", "onEach", "sortedBy", "sortedByDescending", "distinctBy", "filterIndexed", "ifEmpty", "ifBlank"]);
const LAMBDA_RESULT_LAMBDAS = new Set(["let", "run", "map", "mapNotNull", "flatMap", "mapIndexed", "use", "fold", "reduce", "associate", "associateWith", "associateBy", "firstOrNull", "lastOrNull", "find", "mapValues", "mapKeys", "getOrElse", "ifEmpty", "ifBlank", "takeIf"]);
/** Lambda-taking calls whose lambda parameter is the receiver (or one of its elements). */
const ELEMENT_LAMBDAS = new Set([
  "let", "also", "takeIf", "takeUnless", "forEach", "forEachIndexed", "map", "mapNotNull", "flatMap", "mapIndexed", "filter",
  "filterNot", "onEach", "any", "all", "none", "first", "firstOrNull", "last", "lastOrNull", "find", "use", "sortedBy",
  "sortedByDescending", "distinctBy", "associate", "associateWith", "associateBy", "groupBy", "partition", "sumOf", "count",
  "mapValues", "mapKeys", "filterIndexed", "ifPresent", "subscribe", "doOnNext", "flatMapMany", "collect", "fold", "reduce",
]);
/** Receiver-is-`this` scope functions: inside the lambda, bare member names read the receiver. */
const THIS_SCOPE_LAMBDAS = new Set(["run", "apply", "with"]);

// ── Sink vocabulary ────────────────────────────────────────────────────────────────────────────────────────

const SQL_UNAMBIGUOUS = new Set([
  "executeQuery", "executeUpdate", "executeLargeUpdate", "prepareStatement", "prepareCall", "createQuery", "createNativeQuery",
  "createSQLQuery", "queryForObject", "queryForList", "queryForMap", "queryForRowSet", "queryForStream", "batchUpdate", "addBatch",
  "nativeQuery", "createUpdate", "resultQuery",
]);
/** Only on a database-looking receiver: these names are common elsewhere (`executor.execute`, `cache.update`). */
const SQL_GATED = new Set(["execute", "query", "update", "exec", "fetch", "sql", "select", "queryForInt", "queryForLong"]);
const DB_RECEIVER_RE = /jdbc|template|^stmt$|statement|^conn$|connection|^db$|database|session|entitymanager|^em$|sql|dsl|jooq|jdbi|handle|r2dbc|databaseclient|transaction|^tx$/i;
const DB_TYPE_RE = /^(?:JdbcTemplate|NamedParameterJdbcTemplate|JdbcOperations|Connection|Statement|PreparedStatement|EntityManager|Session|StatelessSession|DSLContext|Jdbi|Handle|DatabaseClient|R2dbcEntityTemplate|Database|Transaction|JdbcClient|SqlSession)$/;
const DSL_SQL_CALLS = new Set(["DSL.field", "DSL.condition", "DSL.table", "DSL.sql", "DSL.query", "DSL.resultQuery", "DSL.name", "DSL.unquotedName"]);
const SHELL_PROGRAMS = /^(?:(?:\/usr)?\/bin\/)?(?:sh|bash|zsh|dash|ksh)$|^(?:cmd|cmd\.exe|powershell|powershell\.exe|pwsh)$/i;
const SHELL_COMMAND_FLAGS = /^(?:-c|\/c|\/k|-command|-encodedcommand)$/i;
const LIST_BUILDERS = new Set(["arrayOf", "listOf", "mutableListOf", "arrayListOf", "Arrays.asList", "List.of"]);
const FILE_CTORS_ALL_ARGS = new Set(["File"]);
const FILE_CTORS_FIRST_ARG = new Set(["FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile", "PrintWriter", "FileSystemResource", "PathResource", "ZipFile", "JarFile"]);
const FILES_FIRST_ARG = new Set([
  "readString", "readAllBytes", "readAllLines", "write", "writeString", "newInputStream", "newOutputStream", "newBufferedReader",
  "newBufferedWriter", "delete", "deleteIfExists", "lines", "createFile", "createDirectories", "createDirectory", "list", "walk",
  "exists", "size", "readAttributes", "newByteChannel",
]);
/** `File(x).name` / `Paths.get(x).fileName`: only the last segment survives -- reading it is not a traversal. */
const NAME_ONLY_MEMBERS = new Set(["name", "fileName", "nameWithoutExtension", "extension", "getName", "getFileName"]);
const URL_READ_METHODS = new Set(["openConnection", "openStream", "readText", "readBytes", "getContent", "content"]);
const REST_TEMPLATE_METHODS = new Set(["getForObject", "getForEntity", "postForObject", "postForEntity", "exchange", "patchForObject", "postForLocation", "headForHeaders", "optionsForAllow"]);
const HTTP_CLIENT_METHODS = new Set(["get", "post", "put", "delete", "patch", "head", "options", "request", "prepareGet", "preparePost", "preparePut", "prepareDelete", "prepareRequest", "submitForm"]);
const HTTP_CLIENT_RECV_RE = /client|http|restTemplate|webClient|okHttp/i;
const HTTP_CLIENT_TYPE_RE = /^(?:HttpClient|OkHttpClient|RestTemplate|WebClient|RestClient|CloseableHttpClient)$/;
const HTTP_HEADER_NAME_RE = /^(?:X-[\w-]+|Content-[\w-]+|Location|Set-Cookie|Refresh|Link|Cache-Control|Access-Control-[\w-]+|Authorization|Cookie|Retry-After|WWW-Authenticate|Referer|Origin|Host)$/i;
const SECRET_NAME_RE = /secret|token|password|passwd|api_?key|apikey|hmac|signature|digest/i;
const HTML_TAG_RE = /(?<![\w\]>])<\/?[a-z][a-z0-9-]*(?:\s[^<>]*)?\/?>/;
const MAPPING_ANNOTATIONS = new Set(["GetMapping", "PostMapping", "PutMapping", "PatchMapping", "DeleteMapping", "RequestMapping"]);
const WRITE_VERB_ANNOTATIONS = new Set(["PostMapping", "PutMapping", "PatchMapping", "DeleteMapping"]);
const NON_ENTRY_FN_RE = /^(?:main|equals|hashCode|toString|compareTo|run|call|invoke|get\w*|set\w*|is\w*|close|apply|accept|test|component\d+|copy|onCreate\w*)$/;
const STRINGY_TYPE_RE = /^(?:String|CharSequence|StringBuilder|ByteArray|CharArray|List<String>|Set<String>|Collection<String>|Map<String,\s*(?:String|Any\??)>|Array<String>|InputStream|Reader)$/;

// ── Engine context ─────────────────────────────────────────────────────────────────────────────────────────

type Env = TaintEnv;
interface ParamShape { name: string; index: number; isRest: boolean; type: string; annotations: string[]; annotationNodes: SyntaxNode[] }
interface LocalFn {
  name: string;
  /** `Class.method` (Java-compatible, case preserved), `::name` for a top-level function, null for a local one. */
  key: string | null;
  className: string | null;
  classDecl: SyntaxNode | null;
  params: ParamShape[];
  body: SyntaxNode | null;
  decl: SyntaxNode;
  annotations: SyntaxNode[];
  isPrivate: boolean;
  /** Extension receiver type (`fun ApplicationCall.userId()`), or null. */
  receiverType: string | null;
}
type TaintMaskFn = (node: SyntaxNode, env: Env) => number;

interface EngineCtx {
  filePath: string;
  content: string;
  lines: string[];
  root: SyntaxNode;
  fns: Map<string, LocalFn>;
  propagating: Map<string, Map<number, number>>;
  intrinsic: Map<string, number>;
  seeded: Map<string, Map<number, number>>;
  suppressed?: SuppressedSink[];
  findings: AstTaintKotlinFinding[];
  seen: Set<string>;
  /** Class properties (constructor `val`s and body properties) by name. */
  fields: Set<string>;
  sticky: Map<string, number>;
  stickyDirty: boolean;
  /** variable/property/parameter -> declared or constructed type's simple name */
  varTypes: Map<string, string>;
  crossFileFacts?: ReadonlyMap<string, readonly ParamSinkFact[]>;
  localKeys: Set<string>;
  /** Set by the walker at each sink check: narrows a reported source to its tainted operand. */
  refine?: (source: SyntaxNode, cls: number) => SyntaxNode;
  /** The function being walked (main scan), for return-value sinks (view names, redirects, HTML bodies). */
  current: LocalFn | null;
}

function emit(
  ctx: EngineCtx, id: AstTaintKotlinId, node: SyntaxNode, sourceExpr: string, sinkExpr: string,
  detailOverride?: string, severityOverride?: "critical" | "high" | "medium",
) {
  const line = lineOf(node);
  const key = `${id}:${line}`;
  if (ctx.seen.has(key)) return;
  ctx.seen.add(key);
  ctx.findings.push({
    id, line, sinkExpr, sourceExpr, severityOverride,
    detail: detailOverride ?? `Tainted expression '${sourceExpr.slice(0, 80)}' flows into ${sinkExpr}(...) — real data-flow match, not a line-pattern guess`,
    trace: buildBackwardTraceGeneric(ctx.filePath, node, sourceExpr, sinkExpr, kotlinTraceResolver),
  });
}

// ── Taint mask ─────────────────────────────────────────────────────────────────────────────────────────────

const ZERO_TYPES = new Set([
  ...LITERAL_TYPES, "this_expression", "super_expression", "object_literal", "anonymous_function", "function_declaration",
  "class_declaration", "object_declaration", "equality_expression", "comparison_expression", "conjunction_expression",
  "disjunction_expression", "check_expression", "jump_expression", "type_arguments", "user_type", "nullable_type",
]);
const UNION_TYPES = new Set([
  "string_literal", "interpolated_expression", "parenthesized_expression", "additive_expression", "multiplicative_expression",
  "range_expression", "infix_expression", "elvis_expression", "spread_expression", "collection_literal", "postfix_expression",
  "value_argument", "value_arguments", "annotated_lambda",
]);

function isShadowed(name: string, env: Env, ctx: EngineCtx): boolean {
  return env.has(name) || ctx.fields.has(name);
}

function isRequestReceiver(recv: SyntaxNode | null, env: Env, ctx: EngineCtx): boolean {
  if (!recv || recv.type !== "simple_identifier") return false;
  const t = ctx.varTypes.get(recv.text);
  if (t) return REQUEST_TYPE_RE.test(bareType(t));
  return REQUEST_VAR_RE.test(recv.text) && !env.has(recv.text);
}

/** `call.parameters` / `call.request.queryParameters` / `call.receive<T>()` with `call` the Ktor ApplicationCall. */
function isKtorInput(node: SyntaxNode, env: Env): boolean {
  let cur: SyntaxNode | null = node;
  let first = "";
  while (cur && (cur.type === "navigation_expression" || cur.type === "call_expression" || cur.type === "indexing_expression")) {
    if (cur.type === "navigation_expression") first = memberOf(cur);
    cur = named(cur)[0] ?? null;
  }
  return !!cur && cur.type === "simple_identifier" && cur.text === "call" && !env.has("call") && KTOR_INPUT_MEMBERS.has(first);
}

function makeTaintMask(ctx: EngineCtx): TaintMaskFn {
  const ident = (name: string, env: Env): number => {
    if (env.has(name)) return env.get(name)!;
    if (ctx.fields.has(name)) return ctx.sticky.get(name) ?? 0;
    return 0;
  };

  const mask = (node: SyntaxNode, env: Env): number => {
    if (ZERO_TYPES.has(node.type)) return 0;
    switch (node.type) {
      case "simple_identifier": case "interpolated_identifier":
        return ident(node.text, env);
      case "navigation_expression": {
        if (isKtorInput(node, env)) return ALL;
        const member = memberOf(node);
        const recv = named(node)[0];
        if (!recv) return 0;
        if (recv.type === "callable_reference" || OPAQUE_PROPS.has(member)) return 0;
        if (recv.type === "this_expression") return ident(member, env);
        if (SERVLET_SOURCE_PROPS.has(member) && isRequestReceiver(recv, env, ctx)) return ALL;
        const rm = mask(recv, env);
        // File(x).name / Paths.get(x).fileName: only the last path segment is left
        if (NAME_ONLY_MEMBERS.has(member)) return applyClears(rm, SinkClass.PATH);
        return rm;
      }
      case "indexing_expression": {
        if (isKtorInput(node, env)) return ALL;
        const recv = named(node)[0];
        return recv ? mask(recv, env) : 0;
      }
      case "as_expression": {
        const v = named(node)[0];
        return v ? mask(v, env) : 0;
      }
      case "prefix_expression": {
        const op = operatorOf(node);
        if (op === "!") return 0;
        const kids = named(node);
        const v = kids[kids.length - 1];
        return v ? mask(v, env) : 0;
      }
      case "if_expression": {
        // each arm's value under the guards its condition proves (`if (s in ALLOWED) s else "id"`)
        const cond = named(node).find(k => k.type !== "control_structure_body");
        const guards = cond ? guardsOf(cond, ctx.root) : [];
        const bodies = childrenOfType(node, "control_structure_body");
        return bodies.reduce((m, b, i) => m | valueMask(b, guarded(env, guards.filter(g => g.holds === (i === 0 ? "true" : "false")))), 0);
      }
      case "when_expression": {
        const subject = childOfType(node, "when_subject");
        const subjectName = guardName(named(subject).find(k => k.type !== "variable_declaration"));
        return childrenOfType(node, "when_entry").reduce((m, e) => {
          const conds = childrenOfType(e, "when_condition");
          const literalArm = !!subjectName && conds.length > 0 && conds.every(c => whenConditionIsLiteral(c, ctx.root));
          const armEnv = literalArm ? guarded(env, [{ name: subjectName!, holds: "true" }]) : env;
          return m | valueMask(childOfType(e, "control_structure_body"), armEnv);
        }, 0);
      }
      case "try_expression": {
        const main = childOfType(node, "statements");
        const catches = childrenOfType(node, "catch_block").map(c => childOfType(c, "statements"));
        return [main, ...catches].reduce((m, s) => m | valueMask(s, env), 0);
      }
      case "statements": case "control_structure_body": case "function_body":
        return valueMask(node, env);
      case "lambda_literal":
        return 0;
      case "call_expression":
        return callMask(node, env);
      default:
        break;
    }
    if (UNION_TYPES.has(node.type)) return named(node).reduce((m, c) => m | mask(c, env), 0);
    return named(node).reduce((m, c) => m | mask(c, env), 0);
  };

  /** The value of a block = its last expression. */
  const valueMask = (node: SyntaxNode | null, env: Env): number => {
    if (!node) return 0;
    if (node.type !== "statements" && node.type !== "control_structure_body" && node.type !== "function_body") return mask(node, env);
    const kids = named(node).filter(n => !/comment$/.test(n.type));
    const last = kids[kids.length - 1];
    if (!last) return 0;
    return last.type === "statements" ? valueMask(last, env) : mask(last, env);
  };

  /** A lambda's result with its parameter (or `it`) bound to `paramMask`. */
  const lambdaValue = (lam: SyntaxNode, paramMask: number, env: Env): number => {
    const lenv = cloneEnv(env);
    for (const p of lambdaParamNames(lam)) lenv.set(p, paramMask);
    return valueMask(childOfType(lam, "statements"), lenv);
  };

  const callMask = (node: SyntaxNode, env: Env): number => {
    const { name, recv } = callParts(node);
    const ct = calleeText(node) ?? name;
    const args = argsOf(node);
    const argsMask = () => args.reduce((m, a) => m | mask(a.expr, env), 0);
    const lam = trailingLambda(node);

    if (isKtorInput(node, env)) return ALL;
    if (recv && SERVLET_SOURCE_CALLS.has(name) && isRequestReceiver(recv, env, ctx)) return ALL;

    if (recv) {
      const clears = RECEIVER_CLEARS[name];
      if (clears !== undefined) return applyClears(mask(recv, env), clears);
      if (OPAQUE_RESULT_METHODS.has(name) || /^(?:is|has|can)[A-Z]/.test(name)) return 0;
    }

    const sc = sanitizerClears("kt", ct, args.map(a => a.expr.text));
    if (sc !== null) {
      const data = args[0]?.expr ?? recv;
      return data ? applySanitizer(mask(data, env), sc) : 0;
    }

    // Same-file function: summary of what its parameters (and its own body) contribute to its return value.
    if (!recv || recv.type === "this_expression") {
      const local = ctx.fns.get(name);
      if (local && local.body) {
        let m = ctx.intrinsic.get(name) ?? 0;
        const prop = ctx.propagating.get(name);
        if (prop) for (const [i, surviving] of prop) for (const a of bindArgument(local, node, i)) m |= mask(a, env) & surviving;
        return m;
      }
    }

    if (lam) {
      const rm = recv ? mask(recv, env) : 0;
      if (name === "buildString" || name === "buildList") return appendedInside(lam, env);
      if (RECEIVER_RESULT_LAMBDAS.has(name) && !LAMBDA_RESULT_LAMBDAS.has(name)) return rm;
      if (LAMBDA_RESULT_LAMBDAS.has(name)) {
        const bound = name === "with" ? (args[0] ? mask(args[0].expr, env) : 0) : rm;
        return lambdaValue(lam, bound, env) | (name === "takeIf" || name === "ifEmpty" || name === "ifBlank" ? rm : 0);
      }
      if (name === "with" && args[0]) return lambdaValue(lam, mask(args[0].expr, env), env);
    }

    if (PASSTHROUGH_CALLS.has(ct) || (!recv && /^[A-Z]/.test(name))) {
      const m = argsMask();
      return DECODER_RE.test(ct) ? (m & ALL) | ((m >>> SHADOW) & ALL) : m;
    }
    if (recv) {
      const rm = mask(recv, env);
      if (DECODER_RE.test(ct)) { const m = rm | argsMask(); return (m & ALL) | ((m >>> SHADOW) & ALL); }
      return ARG_FLOW_METHODS.has(name) ? rm | argsMask() : rm;
    }
    return 0;
  };

  /** buildString { append(x) }: everything appended. */
  const appendedInside = (lam: SyntaxNode, env: Env): number => {
    let m = 0;
    for (const c of findAllNodes(lam, "call_expression")) {
      const { name, recv } = callParts(c);
      if (!recv && (name === "append" || name === "appendLine" || name === "add")) m |= argsOf(c).reduce((acc, a) => acc | mask(a.expr, env), 0);
    }
    return m;
  };

  return mask;
}

function lambdaParamNames(lam: SyntaxNode): string[] {
  const lp = childOfType(lam, "lambda_parameters");
  if (!lp) return ["it"];
  return findAllNodes(lp, "simple_identifier").filter(i => i.parent?.type === "variable_declaration").map(i => i.text);
}

/** The argument node(s) bound to parameter `index` of `fn` at a call site (positional, named, or vararg). */
function bindArgument(fn: LocalFn, call: SyntaxNode, index: number): SyntaxNode[] {
  const shape = fn.params.find(p => p.index === index);
  if (!shape) return [];
  const args = argsOf(call);
  const byName = args.find(a => a.name === shape.name);
  if (byName) return [byName.expr];
  const pos = args.filter(a => !a.name).map(a => a.expr);
  return shape.isRest ? pos.slice(index) : pos[index] ? [pos[index]] : [];
}

// ── Declarations ───────────────────────────────────────────────────────────────────────────────────────────

const CLASS_LIKE = new Set(["class_declaration", "object_declaration", "companion_object"]);
/** tree-sitter-kotlin's error recovery for an annotated class followed by another top-level declaration: no
 * class_declaration at all, but `infix_expression[class, Name, lambda_literal{members}]` inside the annotations'
 * prefix_expression(s). Recognised so its members keep their class (and its annotations). */
const isRecoveredClass = (n: SyntaxNode): boolean =>
  n.type === "infix_expression" && /^(?:class|object|interface)$/.test(named(n)[0]?.text ?? "") && named(n)[1]?.type === "simple_identifier";

function classNameOf(n: SyntaxNode): string | null {
  if (n.type === "companion_object") {
    for (let p = n.parent; p; p = p.parent) if (p.type === "class_declaration" || p.type === "object_declaration") return classNameOf(p);
    return null;
  }
  if (isRecoveredClass(n)) return named(n)[1].text;
  return childOfType(n, "type_identifier")?.text ?? null;
}
function enclosingClass(n: SyntaxNode): SyntaxNode | null {
  for (let p = n.parent; p; p = p.parent) {
    if (CLASS_LIKE.has(p.type) || isRecoveredClass(p)) return p;
    if (p.type === "function_declaration" || p.type === "object_literal") return null;   // a local / anonymous declaration
  }
  return null;
}
/** The class a member belongs to for keys: a companion's members are its outer class's statics. */
function ownerClassDecl(cls: SyntaxNode): SyntaxNode {
  if (cls.type !== "companion_object") return cls;
  for (let p = cls.parent; p; p = p.parent) if (p.type === "class_declaration" || p.type === "object_declaration") return p;
  return cls;
}

function paramShapesOf(fvp: SyntaxNode | null): ParamShape[] {
  const out: ParamShape[] = [];
  let pendingAnns: SyntaxNode[] = [];
  let pendingVararg = false;
  let index = 0;
  for (const c of named(fvp)) {
    if (c.type === "parameter_modifiers") {
      pendingAnns.push(...annotationNodes(c));
      if (findAllNodes(c, "parameter_modifier").some(m => m.text === "vararg")) pendingVararg = true;
      continue;
    }
    if (c.type !== "parameter") continue;
    const nm = childOfType(c, "simple_identifier")?.text;
    const typeNode = named(c).find(k => k.type !== "simple_identifier" && k.type !== "modifiers");
    if (nm) out.push({
      name: nm, index, isRest: pendingVararg, type: typeNameOf(typeNode),
      annotations: pendingAnns.map(annotationName), annotationNodes: pendingAnns,
    });
    index++;
    pendingAnns = [];
    pendingVararg = false;
  }
  return out;
}

function collectFns(root: SyntaxNode): LocalFn[] {
  const out: LocalFn[] = [];
  for (const decl of findAllNodes(root, "function_declaration")) {
    const kids = named(decl);
    const nameNode = kids.find(k => k.type === "simple_identifier");
    if (!nameNode) continue;
    const name = nameNode.text;
    const cls = enclosingClass(decl);
    const owner = cls ? ownerClassDecl(cls) : null;
    const className = owner ? classNameOf(owner) : null;
    const topLevel = decl.parent?.type === "source_file";
    const mods = childOfType(decl, "modifiers");
    const isPrivate = !!mods && findAllNodes(mods, "visibility_modifier").some(v => v.text === "private");
    // `fun Type.name()` -- an extension: a user_type before the name
    const nameIdx = kids.indexOf(nameNode);
    const recvType = kids.slice(0, nameIdx).find(k => k.type === "user_type" || k.type === "nullable_type");
    out.push({
      name, decl, className, classDecl: owner, isPrivate,
      key: className ? `${className}.${name}` : topLevel && !recvType ? `::${name}` : null,
      params: paramShapesOf(childOfType(decl, "function_value_parameters")),
      body: childOfType(decl, "function_body"),
      annotations: annotationNodes(mods),
      receiverType: recvType ? typeNameOf(recvType) : null,
    });
  }
  return out;
}

/** Constructor `val`/`var` parameters and body properties of every class in the file -> their types. */
function collectFields(root: SyntaxNode): Map<string, string> {
  const out = new Map<string, string>();
  for (const cp of findAllNodes(root, "class_parameter")) {
    if (!childOfType(cp, "binding_pattern_kind")) continue;
    const nm = childOfType(cp, "simple_identifier")?.text;
    const t = named(cp).find(k => k.type === "user_type" || k.type === "nullable_type");
    if (nm) out.set(nm, typeNameOf(t));
  }
  for (const body of findAllNodes(root, "class_body")) {
    for (const pd of childrenOfType(body, "property_declaration")) {
      const vd = childOfType(pd, "variable_declaration");
      const nm = childOfType(vd, "simple_identifier")?.text;
      const t = named(vd).find(k => k.type === "user_type" || k.type === "nullable_type");
      const init = propertyValue(pd);
      const ctorType = init?.type === "call_expression" ? constructedClass(init) : null;
      if (nm) out.set(nm, t ? typeNameOf(t) : ctorType ?? "");
    }
  }
  return out;
}

function classSupers(cls: SyntaxNode): string[] {
  return childrenOfType(cls, "delegation_specifier").map(d => {
    const t = childOfType(d, "user_type") ?? childOfType(childOfType(d, "constructor_invocation"), "user_type");
    return t ? bareType(typeNameOf(t)) : "";
  }).filter(Boolean);
}

/** A property_declaration's initializer (or null). */
function propertyValue(pd: SyntaxNode): SyntaxNode | null {
  const kids = named(pd);
  const at = kids.findIndex(k => k.type === "variable_declaration" || k.type === "multi_variable_declaration");
  if (at < 0) return null;
  return kids.slice(at + 1).find(k => !["getter", "setter", "property_delegate", "type_constraints"].includes(k.type)) ?? null;
}

/** `Foo(...)` (an uppercase callee with no receiver) -> "Foo". */
function constructedClass(n: SyntaxNode): string | null {
  if (n.type !== "call_expression") return null;
  const { name, recv } = callParts(n);
  return !recv && /^[A-Z]/.test(name) ? name : null;
}

// ── Guards ─────────────────────────────────────────────────────────────────────────────────────────────────

const unwrapParens = (n: SyntaxNode): SyntaxNode => {
  let cur = n;
  while (cur.type === "parenthesized_expression" && named(cur).length === 1) cur = named(cur)[0];
  return cur;
};
const invert = (g: Guard): Guard => ({ name: g.name, holds: g.holds === "true" ? "false" : "true" });
const guardName = (n: SyntaxNode | null | undefined): string | null => (n && n.type === "simple_identifier" ? n.text : null);
const NUMERIC_TYPE_RE = /^(?:Int|Long|Short|Byte|Double|Float|Number|UUID|Boolean)$/;
const DIGITS_REGEX_RE = /^"\^?(?:\\\\d|\[0-9\])[+*]\$?"$/;

function isLiteralCollection(n: SyntaxNode, root: SyntaxNode): boolean {
  if (n.type === "call_expression") {
    const { name, recv } = callParts(n);
    if (!recv && /^(?:setOf|listOf|arrayOf|hashSetOf|mutableSetOf|mutableListOf)$/.test(name)) {
      const a = positionalArgs(n);
      return a.length > 0 && a.every(isLiteral);
    }
    return false;
  }
  if (n.type === "simple_identifier" && /^[A-Z][A-Z0-9_]*$/.test(n.text)) {
    const decl = findAllNodes(root, "property_declaration").find(pd => childOfType(childOfType(pd, "variable_declaration"), "simple_identifier")?.text === n.text);
    const v = decl ? propertyValue(decl) : null;
    return !!v && isLiteralCollection(v, root);
  }
  return false;
}

/** Validation guards a condition proves. Narrow on purpose: a wrong guard hides a real finding. */
function guardsOf(cond: SyntaxNode, root: SyntaxNode): Guard[] {
  const c = unwrapParens(cond);
  if (c.type === "prefix_expression" && operatorOf(c) === "!") {
    const inner = named(c)[named(c).length - 1];
    return inner ? guardsOf(inner, root).map(invert) : [];
  }
  if (c.type === "conjunction_expression") return named(c).flatMap(k => guardsOf(k, root)).filter(g => g.holds === "true");
  if (c.type === "disjunction_expression") return named(c).flatMap(k => guardsOf(k, root)).filter(g => g.holds === "false");
  if (c.type === "equality_expression") {
    const [l, r] = named(c);
    const op = operatorOf(c);
    if (!l || !r || (op !== "==" && op !== "!=")) return [];
    const holds = op === "==" ? "true" : "false";
    if (guardName(l) && isLiteral(r) && r.type !== "null") return [{ name: guardName(l)!, holds }];
    if (guardName(r) && isLiteral(l)) return [{ name: guardName(r)!, holds }];
    return [];
  }
  if (c.type === "check_expression") {
    const [l, r] = named(c);
    const op = operatorOf(c);
    const n = guardName(l);
    if (!n) return [];
    if ((op === "in" || op === "!in") && r && isLiteralCollection(r, root)) return [{ name: n, holds: op === "in" ? "true" : "false" }];
    if ((op === "is" || op === "!is") && NUMERIC_TYPE_RE.test(c.text.split(/\s+/).pop() ?? "")) return [{ name: n, holds: op === "is" ? "true" : "false" }];
    return [];
  }
  if (c.type === "call_expression") {
    const { name, recv } = callParts(c);
    const args = positionalArgs(c);
    if (name === "contains" && recv && args[0] && isLiteralCollection(recv, root)) {
      const n = guardName(args[0]);
      return n ? [{ name: n, holds: "true" }] : [];
    }
    if (name === "matches" && recv && args[0] && DIGITS_REGEX_RE.test(args[0].text.replace(/^Regex\((.*)\)$/, "$1").replace(/\.toRegex\(\)$/, ""))) {
      const n = guardName(recv);
      return n ? [{ name: n, holds: "true" }] : [];
    }
    if (/^(?:all|none)$/.test(name) && recv && /^\{\s*it\.isDigit\(\)\s*\}$/.test(trailingLambda(c)?.text ?? "")) {
      const n = guardName(recv);
      return n && name === "all" ? [{ name: n, holds: "true" }] : [];
    }
  }
  return [];
}

/** `when (x) { "a", in ALLOWED, is Int -> ... }`: inside the arm, x is one of those literals / a number. */
function whenConditionIsLiteral(c: SyntaxNode, root: SyntaxNode): boolean {
  const k = named(c)[0];
  if (!k) return false;
  if (k.type === "range_test") { const coll = named(k)[0]; return operatorOf(k) === "in" && !!coll && isLiteralCollection(coll, root); }
  if (k.type === "type_test") return operatorOf(k) === "is" && NUMERIC_TYPE_RE.test(k.text.replace(/^is\s+/, ""));
  return isLiteral(k);
}

/** `env` with the guards that hold applied (a copy when there are any). */
function guarded(env: Env, guards: readonly Guard[]): Env {
  if (guards.length === 0) return env;
  const e = cloneEnv(env);
  applyGuards(e, guards.map(g => g.name));
  return e;
}

// ── Statement walker ───────────────────────────────────────────────────────────────────────────────────────

interface WalkOpts {
  descendLambdas: boolean;
  onReturn?: (expr: SyntaxNode | null, env: Env, mask: TaintMaskFn) => void;
}

/** Calls that never return (Kotlin's `error()`/`TODO()`, Spring/Ktor aborts). */
const TERMINATING_CALLS = new Set(["error", "TODO", "fail", "exitProcess", "throwError", "abort"]);

function jumpKeyword(n: SyntaxNode): string {
  return n.child(0)?.type ?? "";
}

function createWalker(ctx: EngineCtx, opts: WalkOpts) {
  const mask = makeTaintMask(ctx);
  const root = ctx.root;

  const walkSeq = (nodes: readonly SyntaxNode[], env: Env): boolean => {
    for (const c of nodes) if (walk(c, env)) return true;
    return false;
  };

  const branch = (cond: SyntaxNode | null, body: SyntaxNode | null): Branch => ({
    visitCond: (e) => { if (cond) walk(cond, e); },
    guards: () => (cond ? guardsOf(cond, root) : []),
    body: (e) => (body ? walk(body, e) : false),
  });

  const ifExpr = (node: SyntaxNode, env: Env): boolean => {
    const kids = named(node);
    const cond = kids.find(k => k.type !== "control_structure_body") ?? null;
    const bodies = childrenOfType(node, "control_structure_body");
    const branches: Branch[] = [branch(cond, bodies[0] ?? null)];
    if (bodies[1]) branches.push({ body: (e) => walk(bodies[1], e) });
    return walkIfChain(env, branches);
  };

  /** A lambda passed to a call: Kotlin lambdas read and write the enclosing scope and may run zero or more times. */
  const walkLambda = (lam: SyntaxNode, paramMask: number, env: Env) => {
    const params = lambdaParamNames(lam);
    const saved = new Map(params.map(p => [p, env.get(p)]));
    walkLoop(env, (e) => {
      for (const p of params) e.set(p, paramMask);
      const body = childOfType(lam, "statements");
      return body ? walk(body, e) : false;
    });
    for (const [k, v] of saved) { if (v === undefined) env.delete(k); else env.set(k, v); }
  };

  const assignTo = (target: SyntaxNode, value: number, env: Env, orInto: boolean) => {
    const set = (key: string, m: number) => env.set(key, orInto ? (env.get(key) ?? 0) | m : m);
    const setField = (name: string) => {
      const next = (ctx.sticky.get(name) ?? 0) | (value & ALL);
      if (next !== (ctx.sticky.get(name) ?? 0)) { ctx.sticky.set(name, next); ctx.stickyDirty = true; }
    };
    const kids = named(target);
    if (target.type === "simple_identifier") {
      if (!env.has(target.text) && ctx.fields.has(target.text)) setField(target.text);
      else set(target.text, value);
      return;
    }
    if (target.type === "directly_assignable_expression") {
      if (kids.length === 1) { assignTo(kids[0], value, env, orInto); return; }
      const base = kids[0];
      const suffix = kids[kids.length - 1];
      if (base?.type === "this_expression" && suffix?.type === "navigation_suffix") {
        const f = childOfType(suffix, "simple_identifier")?.text;
        if (f) { setField(f); env.delete(f); }
        return;
      }
      // obj.prop = x / arr[i] = x -- field-insensitive: the object now carries x
      if (base) assignTo(base, value, env, true);
      return;
    }
    if (target.type === "navigation_expression" || target.type === "indexing_expression") {
      const base = kids[0];
      if (base) assignTo(base, value, env, true);
    }
  };

  const declare = (pd: SyntaxNode, env: Env) => {
    const value = propertyValue(pd);
    if (value) walk(value, env);
    const m = value ? mask(value, env) : 0;
    const vd = childOfType(pd, "variable_declaration");
    const multi = childOfType(pd, "multi_variable_declaration");
    if (vd) {
      const nm = childOfType(vd, "simple_identifier")?.text;
      if (nm) {
        env.set(nm, m);
        const declared = named(vd).find(k => k.type === "user_type" || k.type === "nullable_type");
        const t = declared ? typeNameOf(declared) : value ? constructedClass(value) : null;
        if (t) ctx.varTypes.set(nm, t);
      }
    }
    if (multi) for (const v of childrenOfType(multi, "variable_declaration")) {
      const nm = childOfType(v, "simple_identifier")?.text;
      if (nm) env.set(nm, m);
    }
    if (value && vd) checkRedirectOrViewValue(value, env, ctx, mask, null);
  };

  const walk = (node: SyntaxNode, env: Env): boolean => {
    switch (node.type) {
      case "function_declaration": case "class_declaration": case "object_declaration": case "companion_object":
      case "anonymous_function": case "object_literal":
        return false;   // walked separately, each in its own scope
      case "lambda_literal":
        if (opts.descendLambdas) walkLambda(node, 0, cloneEnv(env));
        return false;
      case "statements": case "control_structure_body": case "function_body": case "parenthesized_expression":
        return walkSeq(named(node), env);
      case "property_declaration":
        declare(node, env);
        return false;
      case "assignment": {
        const kids = named(node);
        const target = kids[0], value = kids[kids.length - 1];
        if (!target || !value || target === value) return false;
        walk(value, env);
        const m = mask(value, env);
        const op = operatorOf(node);
        assignTo(target, m, env, op !== "=");
        checkPropertyWrite(target, value, m, env, ctx, mask, node);
        return false;
      }
      case "if_expression":
        return ifExpr(node, env);
      case "when_expression": {
        const subjectNode = childOfType(node, "when_subject");
        const subjectDecl = childOfType(subjectNode, "variable_declaration");
        const subjectExpr = named(subjectNode).find(k => k.type !== "variable_declaration") ?? null;
        if (subjectExpr) walk(subjectExpr, env);
        if (subjectDecl && subjectExpr) { const nm = childOfType(subjectDecl, "simple_identifier")?.text; if (nm) env.set(nm, mask(subjectExpr, env)); }
        const subjectName = subjectDecl ? childOfType(subjectDecl, "simple_identifier")?.text ?? null : guardName(subjectExpr);
        const entries = childrenOfType(node, "when_entry");
        if (!subjectNode) {
          // `when { a -> ...; b -> ... }` is an if/else-if chain
          return walkIfChain(env, entries.map(e => {
            const conds = childrenOfType(e, "when_condition");
            const body = childOfType(e, "control_structure_body");
            if (conds.length === 0) return { body: (en: Env) => (body ? walk(body, en) : false) };
            const cond = conds.length === 1 ? named(conds[0])[0] ?? null : null;
            return branch(cond, body);
          }));
        }
        return walkSwitch(env, entries.map(e => {
          const conds = childrenOfType(e, "when_condition");
          return {
            isDefault: conds.length === 0,
            pre: (en: Env) => {
              if (!subjectName || conds.length === 0) return;
              if (conds.every(c => whenConditionIsLiteral(c, root))) applyGuards(en, [subjectName]);
            },
            body: (en: Env) => { const b = childOfType(e, "control_structure_body"); return b ? walk(b, en) : false; },
          };
        }));
      }
      case "for_statement": {
        const kids = named(node);
        const body = childOfType(node, "control_structure_body");
        const decl = kids.find(k => k.type === "variable_declaration" || k.type === "multi_variable_declaration");
        const iter = kids.find(k => k !== decl && k !== body && k.type !== "annotation");
        if (iter) walk(iter, env);
        const im = iter ? mask(iter, env) : 0;
        const names = decl ? findAllNodes(decl, "simple_identifier").filter(i => i.parent?.type === "variable_declaration").map(i => i.text) : [];
        return walkLoop(env, (e) => { for (const n of names) e.set(n, im); return body ? walk(body, e) : false; });
      }
      case "while_statement": case "do_while_statement": {
        const body = childOfType(node, "control_structure_body");
        const cond = named(node).find(k => k !== body) ?? null;
        if (cond) walk(cond, env);
        return walkLoop(env, (e) => (body ? walk(body, e) : false));
      }
      case "try_expression": {
        const main = childOfType(node, "statements");
        const catches = childrenOfType(node, "catch_block");
        const fin = childOfType(childOfType(node, "finally_block"), "statements");
        return walkTry(
          env,
          (e) => (main ? walk(main, e) : false),
          catches.map(c => ({
            bind: [childOfType(c, "simple_identifier")?.text ?? ""].filter(Boolean),
            body: (e: Env) => { const b = childOfType(c, "statements"); return b ? walk(b, e) : false; },
          })),
          fin ? (e) => walk(fin, e) : undefined,
        );
      }
      case "jump_expression": {
        const kw = jumpKeyword(node);
        // The grammar sometimes closes a `return` early and leaves its value as the next statement on the same line.
        const next = node.nextNamedSibling;
        const value = named(node).find(k => k.type !== "label")
          ?? (next && (kw === "return" || kw === "throw") && next.startPosition.row === node.endPosition.row ? next : null);
        if (value) walk(value, env);
        if (kw === "return") {
          opts.onReturn?.(value, env, mask);
          if (value) checkReturnValue(value, env, ctx, mask);
        }
        return true;
      }
      default:
        break;
    }

    if (node.type === "call_expression") {
      const lam = trailingLambda(node);
      const { name, recv, callee } = callParts(node);
      // the callee chain (receiver + its own calls) and the arguments first
      if (callee && callee.type !== "simple_identifier") walk(callee, env);
      for (const a of argsOf(node)) walk(a.expr, env);
      checkCallSink(node, env, ctx, mask);
      seedLocalFn(node, env, ctx, mask);
      checkCrossFileCall(node, env, ctx, mask);
      if (recv && MUTATOR_METHODS.has(name)) {
        const am = argsOf(node).reduce((m, a) => m | mask(a.expr, env), 0);
        if (am) assignTo(recv, am, env, true);
      }
      // require(cond) / check(cond) throw unless cond holds: what follows runs only when it does
      if (!recv && (name === "require" || name === "check")) {
        const cond = positionalArgs(node)[0];
        if (cond) applyGuards(env, guardsOf(cond, root).filter(g => g.holds === "true").map(g => g.name));
      }
      if (lam) {
        const elementMask = recv && ELEMENT_LAMBDAS.has(name) ? mask(recv, env)
          : name === "with" ? positionalArgs(node).reduce((m, a) => m | mask(a, env), 0) : 0;
        if (THIS_SCOPE_LAMBDAS.has(name) || ELEMENT_LAMBDAS.has(name) || opts.descendLambdas) walkLambda(lam, elementMask, env);
      }
      return !recv && TERMINATING_CALLS.has(name);
    }

    if (node.type === "equality_expression") {
      for (const c of named(node)) walk(c, env);
      const [l, r] = named(node);
      if (l && r) checkTimingCompare(node, l, r, env, ctx, mask);
      return false;
    }
    if (node.type === "prefix_expression" && operatorOf(node) === "+" && insideUnsafeHtml(node)) {
      for (const c of named(node)) walk(c, env);
      const v = named(node)[0];
      if (v) fireOn(ctx, "xss", node, v, mask(v, env), "unsafe { +... }");
      return false;
    }

    for (const c of named(node)) walk(c, env);
    return false;
  };

  return { walk, mask };
}

// ── Sinks ──────────────────────────────────────────────────────────────────────────────────────────────────

/** The operand that actually carries the taint inside a composite value (a template part, one side of `+`). */
function culpritOf(src: SyntaxNode, cls: number, env: Env, mask: TaintMaskFn): SyntaxNode {
  const n = unwrapParens(src);
  if (n.type === "string_literal") {
    for (const c of named(n)) {
      if (c.type === "interpolated_identifier" && (mask(c, env) & cls)) return c;
      if (c.type === "interpolated_expression") { const inner = named(c)[0]; if (inner && (mask(inner, env) & cls)) return culpritOf(inner, cls, env, mask); }
    }
  }
  if (n.type === "additive_expression") {
    for (const side of named(n)) if (mask(side, env) & cls) return culpritOf(side, cls, env, mask);
  }
  return n;
}

function fireOn(ctx: EngineCtx, id: AstTaintKotlinId, at: SyntaxNode, source: SyntaxNode, m: number, sinkExpr: string, detail?: string): boolean {
  const cls = classOf(id);
  if (m & cls) {
    const culprit = ctx.refine ? ctx.refine(source, cls) : source;
    emit(ctx, id, at, culprit.text, sinkExpr, detail);
    return true;
  }
  if (wasCleared(m, cls)) ctx.suppressed?.push({ id, line: lineOf(at) });
  return false;
}

/** Most recent `val/var name = <expr>` or `name = <expr>` before `at` in the enclosing function (or file). */
function lastAssignment(name: string, at: SyntaxNode): SyntaxNode | null {
  let scope: SyntaxNode | null = enclosingScope(at);
  if (!scope) { scope = at; while (scope.parent) scope = scope.parent; }
  let best: SyntaxNode | null = null;
  const visit = (n: SyntaxNode) => {
    if (n.startIndex >= at.startIndex) return;
    if (n !== scope && n.type === "function_declaration") return;
    if (n.type === "property_declaration" && childOfType(childOfType(n, "variable_declaration"), "simple_identifier")?.text === name) best = propertyValue(n);
    if (n.type === "assignment" && named(n)[0]?.text === name && operatorOf(n) === "=") best = named(n)[named(n).length - 1] ?? null;
    for (const c of named(n)) visit(c);
  };
  visit(scope);
  return best;
}
const resolveVar = (n: SyntaxNode): SyntaxNode => (n.type === "simple_identifier" ? lastAssignment(n.text, n) ?? n : n);

/** A Kotlin string expression as literal text and opaque value parts (templates, `+`, URI(...) wrappers). */
function decomposeString(node: SyntaxNode, depth = 0): UrlPart<SyntaxNode>[] {
  const n = unwrapParens(node);
  if (n.type === "string_literal") {
    return named(n).map(c => c.type === "string_content" || c.type === "escape_sequence" || c.type === "character_escape_seq"
      ? { kind: "literal" as const, text: c.text }
      : c.type === "interpolated_expression" && named(c)[0] ? { kind: "opaque" as const, node: named(c)[0] } : { kind: "opaque" as const, node: c });
  }
  if (n.type === "additive_expression" && operatorOf(n) === "+") {
    const [l, r] = named(n);
    if (l && r) return [...decomposeString(l, depth), ...decomposeString(r, depth)];
  }
  if (n.type === "call_expression") {
    const ct = calleeText(n);
    if (ct === "URI" || ct === "URI.create" || ct === "URL" || ct === "Uri.parse") { const a = positionalArgs(n)[0]; if (a) return decomposeString(a, depth); }
  }
  if (n.type === "simple_identifier" && depth < 3) {
    const v = lastAssignment(n.text, n);
    if (v) return decomposeString(v, depth + 1);
  }
  return [{ kind: "opaque", node: n }];
}

function isDbReceiver(recv: SyntaxNode | null, ctx: EngineCtx): boolean {
  if (!recv) return false;
  const t = recv.type === "simple_identifier" ? ctx.varTypes.get(recv.text) : undefined;
  if (t && DB_TYPE_RE.test(bareType(t))) return true;
  const text = calleeText(recv) ?? "";
  const last = text.split(".").pop() ?? "";
  return DB_RECEIVER_RE.test(last) || /TransactionManager\.current$|getConnection$|connection$/.test(text);
}

function isHttpClientReceiver(recv: SyntaxNode | null, ctx: EngineCtx): boolean {
  if (!recv) return false;
  if (recv.type === "simple_identifier") {
    const t = ctx.varTypes.get(recv.text);
    if (t) return HTTP_CLIENT_TYPE_RE.test(bareType(t));
    return HTTP_CLIENT_RECV_RE.test(recv.text);
  }
  const ct = calleeText(recv) ?? "";
  return /^(?:HttpClient|OkHttpClient|WebClient|RestClient)\b/.test(ct) || /(?:client|http)$/i.test(ct.split(".").pop() ?? "");
}

/** The elements of `arrayOf(...)` / `listOf(...)` (resolving one variable hop), or null. */
function listElements(n: SyntaxNode): SyntaxNode[] | null {
  const v = resolveVar(n);
  if (v.type !== "call_expression") return null;
  return LIST_BUILDERS.has(calleeText(v) ?? "") ? positionalArgs(v) : null;
}

/** A process argv: a tainted program, or an element after a shell + `-c`, is command injection; any other tainted
 * element is at most argument injection (it can start with `-`), and not even that after a literal `--`. */
function checkArgv(ctx: EngineCtx, at: SyntaxNode, elems: SyntaxNode[], env: Env, mask: TaintMaskFn, sink: string) {
  if (elems.length === 0) return;
  if (elems.length === 1) { fireOn(ctx, "command-injection", at, elems[0], mask(elems[0], env), sink); return; }
  const lit = elems.map(e => stringValue(e));
  fireOn(ctx, "command-injection", at, elems[0], mask(elems[0], env), sink);
  const shellAt = lit[0] !== null && SHELL_PROGRAMS.test(lit[0] ?? "") ? lit.findIndex((s, i) => i > 0 && s !== null && SHELL_COMMAND_FLAGS.test(s)) : -1;
  if (shellAt > 0) {
    for (const e of elems.slice(shellAt + 1)) if (fireOn(ctx, "command-injection", at, e, mask(e, env), sink)) break;
    return;
  }
  const endOfOptions = lit.findIndex((s, i) => i > 0 && s === "--");
  for (let i = 1; i < elems.length; i++) {
    if (endOfOptions >= 0 && i > endOfOptions) break;
    const m = mask(elems[i], env);
    if (m & ALL) { emit(ctx, "argument-injection", at, elems[i].text, sink, `Request input '${elems[i].text.slice(0, 60)}' is passed as an argument to ${sink} — no shell runs, but a value starting with '-' becomes an option; put '--' before it or validate it`); break; }
  }
}

/** Is the call/constructor's result used only for its last path segment (`File(x).name`)? */
function onlyNameUsed(node: SyntaxNode): boolean {
  const p = node.parent;
  return !!p && p.type === "navigation_expression" && named(p)[0]?.id === node.id && NAME_ONLY_MEMBERS.has(memberOf(p));
}

function checkSsrfArg(ctx: EngineCtx, at: SyntaxNode, arg: SyntaxNode, env: Env, mask: TaintMaskFn, sink: string) {
  const verdict = assessSsrfUrl(decomposeString(arg), n => mask(n, env));
  if (verdict.verdict === "vulnerable") emit(ctx, "ssrf", at, (verdict.culprit ?? arg).text, sink);
  else if (verdict.verdict === "no-taint") fireOn(ctx, "ssrf", at, arg, mask(arg, env), sink);
  else ctx.suppressed?.push({ id: "ssrf", line: lineOf(at) });
}

function checkRedirectTarget(ctx: EngineCtx, at: SyntaxNode, arg: SyntaxNode, env: Env, mask: TaintMaskFn, sink: string, parts?: UrlPart<SyntaxNode>[]) {
  const verdict = assessSsrfUrl(parts ?? decomposeString(arg), n => mask(n, env));
  if (verdict.verdict === "safe") { ctx.suppressed?.push({ id: "open-redirect", line: lineOf(at) }); return; }
  const culprit = verdict.verdict === "vulnerable" ? verdict.culprit ?? arg : arg;
  fireOn(ctx, "open-redirect", at, culprit, verdict.verdict === "vulnerable" ? ALL : mask(arg, env), sink);
}

function insideLambdaOf(node: SyntaxNode, test: (call: SyntaxNode) => boolean): boolean {
  for (let p = node.parent; p; p = p.parent) {
    if (p.type === "function_declaration") return false;
    if (p.type === "lambda_literal") {
      const call = p.parent?.parent?.parent;   // lambda_literal < annotated_lambda < call_suffix < call_expression
      if (call?.type === "call_expression" && test(call)) return true;
    }
  }
  return false;
}
const insideUnsafeHtml = (n: SyntaxNode) => insideLambdaOf(n, c => callParts(c).name === "unsafe");

function checkCallSink(node: SyntaxNode, env: Env, ctx: EngineCtx, mask: TaintMaskFn) {
  ctx.refine = (src, cls) => culpritOf(src, cls, env, mask);
  const { name, recv } = callParts(node);
  const ct = calleeText(node) ?? name;
  const args = argsOf(node);
  const pos = args.filter(a => !a.name).map(a => a.expr);
  const arg0 = namedArg(node, "sql") ?? pos[0];
  const ctor = !recv && /^[A-Z]/.test(name) ? name : null;
  const recvType = recv?.type === "simple_identifier" ? bareType(ctx.varTypes.get(recv.text) ?? "") : "";
  const recvText = recv ? calleeText(recv) ?? recv.text : "";

  // ── SQL ──
  const sqlCall = (recv && (SQL_UNAMBIGUOUS.has(name) || (SQL_GATED.has(name) && isDbReceiver(recv, ctx))))
    || DSL_SQL_CALLS.has(ct)
    || (!recv && name === "exec" && insideLambdaOf(node, c => /^(?:transaction|newSuspendedTransaction|suspendedTransactionAsync)$/.test(callParts(c).name)));
  if (sqlCall && arg0) {
    const verdict = assessSqlInjection(decomposeString(arg0), n => mask(n, env));
    if (verdict.verdict === "vulnerable" && verdict.escaped) {
      emit(ctx, "sql-injection", node, verdict.culprit!.text, ct, `Escaped value '${verdict.culprit!.text}' is placed outside a quoted SQL string literal — string-escaping only protects a value inside quotes`);
    } else {
      fireOn(ctx, "sql-injection", node, arg0, mask(arg0, env), ct);
    }
  }

  // ── Command ──
  if (name === "exec" && recv && (/getRuntime$/.test(recvText) || recvType === "Runtime")) {
    const a = pos[0];
    if (a) {
      const elems = listElements(a);
      if (elems) checkArgv(ctx, node, elems, env, mask, "Runtime.exec");
      else fireOn(ctx, "command-injection", node, a, mask(a, env), "Runtime.exec");
    }
  }
  if (ctor === "ProcessBuilder" || (recv && name === "command" && (/ProcessBuilder/.test(recvText) || recvType === "ProcessBuilder" || /ProcessExecutor/.test(recvText)))) {
    const elems = pos.length === 1 ? listElements(pos[0]) ?? pos : pos;
    checkArgv(ctx, node, elems, env, mask, ctor ? "ProcessBuilder" : `${recvText}.command`);
  }
  if (ct === "CommandLine.parse" && pos[0]) fireOn(ctx, "command-injection", node, pos[0], mask(pos[0], env), ct);

  // ── Path ──
  if (ctor && (FILE_CTORS_ALL_ARGS.has(ctor) || FILE_CTORS_FIRST_ARG.has(ctor)) && !onlyNameUsed(node)) {
    const targets = FILE_CTORS_ALL_ARGS.has(ctor) ? pos : pos.slice(0, 1);
    for (const a of targets) if (fireOn(ctx, "path-traversal", node, a, mask(a, env), ctor)) break;
  }
  if ((ct === "Paths.get" || ct === "Path.of" || ct === "File.createTempFile") && !onlyNameUsed(node)) {
    for (const a of pos) if (fireOn(ctx, "path-traversal", node, a, mask(a, env), ct)) break;
  }
  if (recvText === "Files" && (FILES_FIRST_ARG.has(name) || name === "copy" || name === "move")) {
    const sourceIsStream = name === "copy" && !!pos[0] && /InputStream|inputStream|^(?:input|stream|ins)$/.test(pos[0].text);
    const targets = name === "copy" || name === "move" ? (sourceIsStream ? pos.slice(1, 2) : pos.slice(0, 2)) : pos.slice(0, 1);
    for (const a of targets) if (fireOn(ctx, "path-traversal", node, a, mask(a, env), `Files.${name}`)) break;
  }
  if (recv && (name === "resolve" || name === "resolveSibling") && pos[0] && !onlyNameUsed(node) &&
      (/^(?:Path|File)$/.test(recvType) || /(?:Paths\.get|Path\.of|toPath)$/.test(recvText))) {
    fireOn(ctx, "path-traversal", node, pos[0], mask(pos[0], env), `Path.${name}`);
  }
  if ((ct === "ResourceUtils.getFile" || (recv && name === "getResource" && /resourceLoader|loader|context/i.test(recvText))) && pos[0]) {
    fireOn(ctx, "path-traversal", node, pos[0], mask(pos[0], env), ct);
  }
  if (recv && name === "respondFile" && isKtorCallReceiver(recv, env)) {
    const a = pos[1] ?? pos[0];
    if (a && !(pos.length === 1 && a.type === "call_expression" && constructedClass(a) === "File")) fireOn(ctx, "path-traversal", node, a, mask(a, env), "call.respondFile");
  }

  // ── SSRF ──
  if (recv && REST_TEMPLATE_METHODS.has(name) && pos[0]) checkSsrfArg(ctx, node, pos[0], env, mask, `RestTemplate.${name}`);
  if (recv && URL_READ_METHODS.has(name)) {
    // URL(x).readText() / URI(x).toURL().openConnection() / a URL held in a variable
    let base: SyntaxNode | null = recv;
    if (base.type === "call_expression" && callParts(base).name === "toURL") base = callParts(base).recv;
    if (base?.type === "simple_identifier") base = resolveVar(base);
    if (base?.type === "call_expression" && /^(?:URL|URI|URI\.create)$/.test(calleeText(base) ?? "")) {
      const a = positionalArgs(base)[0];
      if (a) checkSsrfArg(ctx, node, a, env, mask, `URL.${name}`);
    } else if (recv.type === "simple_identifier" && /^(?:URL|URI)$/.test(recvType)) {
      fireOn(ctx, "ssrf", node, recv, mask(recv, env), `URL.${name}`);
    }
  }
  if (recv && name === "uri" && pos[0] && (/webclient|client|HttpRequest|newBuilder/i.test(recvText) || /\.(?:get|post|put|delete|patch|head|method)$/.test(recvText))) {
    checkSsrfArg(ctx, node, pos[0], env, mask, `${recvText.split(".")[0]}.uri`);
  }
  if (recv && (name === "url" || name === "baseUrl") && pos[0] && /Builder|builder|WebClient|RestClient/.test(recvText)) checkSsrfArg(ctx, node, pos[0], env, mask, `${name}`);
  if (!recv && name === "url" && pos[0] && insideLambdaOf(node, c => HTTP_CLIENT_METHODS.has(callParts(c).name) && isHttpClientReceiver(callParts(c).recv, ctx))) {
    checkSsrfArg(ctx, node, pos[0], env, mask, "client.request { url(...) }");
  }
  if (recv && HTTP_CLIENT_METHODS.has(name) && isHttpClientReceiver(recv, ctx) && !REST_TEMPLATE_METHODS.has(name)) {
    const a = namedArg(node, "urlString") ?? pos[0];
    if (a && a.type !== "lambda_literal") checkSsrfArg(ctx, node, a, env, mask, `${recvText}.${name}`);
  }
  if (["WebClient.create", "HttpRequest.newBuilder", "Jsoup.connect", "InetAddress.getByName", "InetAddress.getAllByName", "Fuel.get", "Fuel.post", "Fuel.put", "Fuel.delete"].includes(ct) && pos[0]) {
    checkSsrfArg(ctx, node, pos[0], env, mask, ct);
  }
  if (recv && /^http(?:Get|Post|Put|Delete|Patch|Head)$/.test(name)) checkSsrfArg(ctx, node, recv, env, mask, `.${name}()`);
  if (ctor === "Socket" && pos[0]) fireOn(ctx, "ssrf", node, pos[0], mask(pos[0], env), "Socket");

  // ── Redirect ──
  if (recv && name === "sendRedirect" && pos[0]) checkRedirectTarget(ctx, node, pos[0], env, mask, "sendRedirect");
  if (recv && name === "respondRedirect" && (namedArg(node, "url") ?? pos[0])) checkRedirectTarget(ctx, node, (namedArg(node, "url") ?? pos[0])!, env, mask, "call.respondRedirect");
  if (ctor === "RedirectView" && pos[0]) checkRedirectTarget(ctx, node, pos[0], env, mask, "RedirectView");
  if (recv && name === "location" && pos[0]) checkRedirectTarget(ctx, node, pos[0], env, mask, "ResponseEntity.location");
  if (ctor === "ModelAndView" && pos[0]) checkRedirectOrViewValue(pos[0], env, ctx, mask, node);

  // ── Headers ──
  if (recv && (name === "setHeader" || name === "addHeader") && pos.length >= 2) {
    if (/^location$/i.test(stringValue(pos[0]) ?? "")) checkRedirectTarget(ctx, node, pos[1], env, mask, `${name}("Location")`);
    else fireOn(ctx, "header-injection", node, pos[1], mask(pos[1], env) | (mask(pos[0], env) & ALL), name);
  } else if (recv && (name === "header" || name === "set" || name === "add" || name === "append") && pos.length >= 2) {
    const key = stringValue(pos[0]);
    if (key && /^location$/i.test(key)) checkRedirectTarget(ctx, node, pos[1], env, mask, `${name}("Location")`);
    else if (key && HTTP_HEADER_NAME_RE.test(key)) fireOn(ctx, "header-injection", node, pos[1], mask(pos[1], env), `${name}("${key}")`);
  }

  // ── Deserialization ──
  if (recv && (name === "readObject" || name === "readUnshared") && (/ObjectInputStream/.test(recvText) || recvType === "ObjectInputStream" || /ObjectInputStream\(/.test(recv.text))) {
    fireOn(ctx, "insecure-deserialization", node, recv, mask(recv, env), "ObjectInputStream.readObject");
  }
  if (recv && name === "fromXML" && pos[0]) fireOn(ctx, "insecure-deserialization", node, pos[0], mask(pos[0], env), "XStream.fromXML");
  if (recv && /^(?:load|loadAs|loadAll)$/.test(name) && pos[0] && (recvType === "Yaml" || /^Yaml\(/.test(recv.text))) {
    fireOn(ctx, "insecure-deserialization", node, pos[0], mask(pos[0], env), "Yaml.load");
  }
  if ((ct === "SerializationUtils.deserialize") && pos[0]) fireOn(ctx, "insecure-deserialization", node, pos[0], mask(pos[0], env), ct);
  if (recv && name === "readValue" && pos[0] && /enableDefaultTyping|activateDefaultTyping|JsonTypeInfo\.Id\.CLASS/.test(ctx.content)) {
    fireOn(ctx, "insecure-deserialization", node, pos[0], mask(pos[0], env), "ObjectMapper.readValue (default typing)");
  }

  // ── XSS ──
  if (recv && /^(?:print|println|write|append|printf|format)$/.test(name) && pos[0] &&
      (/(?:response|resp|res)\.(?:writer|getWriter|outputStream)$/.test(recvText) || /^(?:out|writer|pw|printWriter)$/.test(recvText))) {
    fireOn(ctx, "xss", node, pos[0], mask(pos[0], env), `${recvText}.${name}`);
  }
  if (recv && name === "respondText" && isKtorCallReceiver(recv, env)) {
    const text = namedArg(node, "text") ?? pos[0];
    if (text && /Html/.test(node.text)) fireOn(ctx, "xss", node, text, mask(text, env), "call.respondText(HTML)");
  }
  if (recv && name === "body" && pos[0] && (/TEXT_HTML|text\/html/.test(recvText + node.text) || htmlLiteralWithTaint(pos[0], env, mask))) {
    fireOn(ctx, "xss", node, pos[0], mask(pos[0], env), "ResponseEntity.body (HTML)");
  }
  if (!recv && name === "raw" && pos[0] && insideUnsafeHtml(node)) fireOn(ctx, "xss", node, pos[0], mask(pos[0], env), "unsafe { raw(...) }");

  // ── LDAP / XPath / NoSQL ──
  if (recv && name === "search" && pos.length >= 2 && (/DirContext|LdapContext|LdapTemplate/.test(recvType) || /ctx|context|ldap/i.test(recvText))) {
    fireOn(ctx, "ldap-injection", node, pos[1], mask(pos[1], env), "search");
  }
  if (recv && name === "filter" && pos[0] && /LdapQueryBuilder|query\(\)/.test(recv.text)) fireOn(ctx, "ldap-injection", node, pos[0], mask(pos[0], env), "LdapQuery.filter");
  if (recv && (name === "evaluate" || name === "compile") && pos[0] && (recvType === "XPath" || /xpath|newXPath/i.test(recvText))) {
    fireOn(ctx, "xpath-injection", node, pos[0], mask(pos[0], env), `XPath.${name}`);
  }
  if ((ctor === "BasicQuery" || ctor === "BasicDBObject" || ct === "Document.parse" || ct === "BasicDBObject.parse" || ct === "BsonDocument.parse") && pos[0]) {
    fireOn(ctx, "nosql-injection", node, pos[0], mask(pos[0], env), ct);
  }

  // ── Template injection ──
  if (/(?:^|\.)evaluate$/.test(ct) && /^(?:Velocity|velocityEngine|engine|ve)/.test(ct) && pos[3]) fireOn(ctx, "ssti", node, pos[3], mask(pos[3], env), "Velocity.evaluate");
  if (ctor === "Template" && pos[1]) fireOn(ctx, "ssti", node, pos[1], mask(pos[1], env), "freemarker.Template");
  if (recv && name === "process" && pos[0] && /templateEngine|TemplateEngine/.test(recvType + recvText) && stringValue(pos[0]) === null) {
    fireOn(ctx, "ssti", node, pos[0], mask(pos[0], env), "TemplateEngine.process");
  }
  if (recv && name === "getLiteralTemplate" && pos[0]) fireOn(ctx, "ssti", node, pos[0], mask(pos[0], env), "Pebble.getLiteralTemplate");

  // ── Code execution ──
  if (recv && name === "eval" && pos[0] && (recvType === "ScriptEngine" || /engine|script|nashorn|getEngineByName/i.test(recvText))) fireOn(ctx, "eval-exec", node, pos[0], mask(pos[0], env), "ScriptEngine.eval");
  if (recv && name === "parseExpression" && pos[0]) fireOn(ctx, "eval-exec", node, pos[0], mask(pos[0], env), "SpEL parseExpression");
  if ((ct === "Class.forName" || (recv && name === "loadClass")) && pos[0]) fireOn(ctx, "eval-exec", node, pos[0], mask(pos[0], env), ct);
  if (recv && (name === "getMethod" || name === "getDeclaredMethod") && pos[0]) fireOn(ctx, "eval-exec", node, pos[0], mask(pos[0], env), name);
  if (((recv && name === "evaluate" && /GroovyShell/.test(recv.text + recvType)) || ct === "Eval.me" || ct === "MVEL.eval" || ct === "Ognl.getValue") && pos[0]) {
    fireOn(ctx, "eval-exec", node, pos[0], mask(pos[0], env), ct);
  }

  // ── Mass assignment (reflective field write chosen by the request) ──
  if (recv && (name === "getField" || name === "getDeclaredField") && pos[0]) fireOn(ctx, "mass-assignment", node, pos[0], mask(pos[0], env), name);

  // ── ReDoS ──
  const regexArg = ctor === "Regex" ? pos[0] : ct === "Pattern.compile" || ct === "Pattern.matches" ? pos[0]
    : recv && (name === "toRegex" || name === "toPattern") ? recv
    : recv && name === "matches" && pos[0] && pos[0].type !== "call_expression" ? pos[0] : null;
  if (regexArg) {
    const escaped = regexArg.type === "call_expression" && /^(?:Regex\.escape|Pattern\.quote)$/.test(calleeText(regexArg) ?? "");
    const m = mask(regexArg, env);
    if (!escaped && (m & ALL)) emit(ctx, "redos", node, regexArg.text, ct);
  }

  // ── Timing attack (a.equals(b) / a.contentEquals(b)) ──
  if (recv && (name === "equals" || name === "contentEquals" || name === "equalsIgnoreCase") && pos[0] && pos.length === 1) {
    checkTimingCompare(node, recv, pos[0], env, ctx, mask);
  }

  // ── Weak digest ──
  if (ct === "MessageDigest.getInstance" && /^(?:MD5|MD2|MD4|SHA-?1)$/i.test(stringValue(pos[0]) ?? "")) {
    emit(ctx, "weak-crypto", node, stringValue(pos[0]) ?? "", "MessageDigest.getInstance", `MessageDigest.getInstance("${stringValue(pos[0])}") is a broken/weak hash — use SHA-256+ (and a slow KDF such as bcrypt/Argon2 for passwords)`);
  }

  // ── JWT accepted without a signature ──
  if (recv && /^(?:parseClaimsJwt|parsePlaintextJwt|parseUnsecuredClaims|parseUnsecuredContent)$/.test(name)) {
    emit(ctx, "jwt-none-alg", node, pos[0]?.text ?? "token", name, `${name}() accepts tokens with NO signature (alg: none) — use parseSignedClaims/parseClaimsJws with a verification key`);
  }
  if (recv && name === "unsecured" && /Jwts\.parser/.test(recvText)) {
    emit(ctx, "jwt-none-alg", node, "token", "Jwts.parser().unsecured()", "The JWT parser is configured to accept unsigned tokens (alg: none) — remove .unsecured()");
  }
  if (ct === "JWT.decode" && pos[0] && !/\.verify\s*\(|JWT\.require\s*\(/.test(ctx.content)) {
    emit(ctx, "jwt-none-alg", node, pos[0].text, "JWT.decode", "JWT.decode() only parses the token; nothing in this file verifies its signature (JWT.require(...).build().verify(...)) — its claims are attacker-controlled");
  }
}

function isKtorCallReceiver(recv: SyntaxNode, env: Env): boolean {
  return recv.type === "simple_identifier" && recv.text === "call" && !env.has("call");
}

function htmlLiteralWithTaint(arg: SyntaxNode, env: Env, mask: TaintMaskFn): boolean {
  const parts = decomposeString(arg);
  const literal = parts.filter(p => p.kind === "literal").map(p => (p as { text: string }).text).join("");
  return HTML_TAG_RE.test(literal) && parts.some(p => p.kind === "opaque" && (mask(p.node, env) & SinkClass.XSS));
}

/** `headers.location = URI(x)` / `response.contentType = x` style property writes. */
function checkPropertyWrite(target: SyntaxNode, value: SyntaxNode, m: number, env: Env, ctx: EngineCtx, mask: TaintMaskFn, at: SyntaxNode) {
  const kids = named(target);
  const suffix = kids[kids.length - 1];
  if (target.type !== "directly_assignable_expression" || !suffix) return;
  if (suffix.type === "navigation_suffix" && childOfType(suffix, "simple_identifier")?.text === "location") {
    checkRedirectTarget(ctx, at, value, env, mask, "headers.location");
    return;
  }
  // headers["X-Foo"] = x / response.headers["Location"] = x
  if (suffix.type === "indexing_suffix" && /headers?$/i.test(kids[0]?.text ?? "")) {
    const key = stringValue(named(suffix)[0]);
    if (key && /^location$/i.test(key)) checkRedirectTarget(ctx, at, value, env, mask, "headers[Location]");
    else { ctx.refine = (src, cls) => culpritOf(src, cls, env, mask); fireOn(ctx, "header-injection", at, value, m, `headers[${key ?? "?"}]`); }
  }
}

/** A string that becomes a Spring view: `redirect:` + x is an open redirect, any other request-chosen view name is
 * template injection (Thymeleaf view manipulation). `at` = where to report (null: only when it's a returned value). */
function checkRedirectOrViewValue(value: SyntaxNode, env: Env, ctx: EngineCtx, mask: TaintMaskFn, at: SyntaxNode | null) {
  const parts = decomposeString(value);
  const first = parts[0];
  if (first?.kind === "literal" && /^redirect:/.test(first.text)) {
    const rest: UrlPart<SyntaxNode>[] = [{ kind: "literal", text: first.text.replace(/^redirect:/, "") }, ...parts.slice(1)];
    if (rest.some(p => p.kind === "opaque")) checkRedirectTarget(ctx, at ?? value, value, env, mask, "\"redirect:\" view", rest);
    return;
  }
  if (at && at.type === "call_expression") {
    // new ModelAndView(viewName): a request-chosen view name is resolved as a template expression
    const m = parts.reduce((acc, p) => acc | (p.kind === "opaque" ? mask(p.node, env) : 0), 0);
    if (parts.some(p => p.kind === "opaque")) { ctx.refine = (src, cls) => culpritOf(src, cls, env, mask); fireOn(ctx, "ssti", at, value, m, "ModelAndView(view name)"); }
  }
}

/** A handler's returned value: view names, redirects, and HTML bodies of @ResponseBody handlers. */
function checkReturnValue(value: SyntaxNode, env: Env, ctx: EngineCtx, mask: TaintMaskFn) {
  const fn = ctx.current;
  if (!fn || !isHandler(fn)) return;
  ctx.refine = (src, cls) => culpritOf(src, cls, env, mask);
  const parts = decomposeString(value);
  const first = parts[0];
  if (first?.kind === "literal" && /^(?:redirect|forward):/.test(first.text)) {
    if (/^redirect:/.test(first.text)) checkRedirectOrViewValue(value, env, ctx, mask, value);
    return;
  }
  if (returnsBody(fn)) {
    if (htmlLiteralWithTaint(value, env, mask) || fn.annotations.some(a => /produces\s*=.*html/i.test(a.text))) {
      fireOn(ctx, "xss", value, value, mask(value, env), `${fn.name}() response body (HTML)`);
    }
    return;
  }
  // @Controller handler returning a String: the value is a VIEW NAME, resolved by the template engine
  if (/^String\??$/.test(returnTypeOf(fn)) || parts.some(p => p.kind === "literal")) {
    fireOn(ctx, "ssti", value, value, mask(value, env), `${fn.name}() view name`,
      `Request input '${value.text.slice(0, 60)}' decides the view name ${fn.name}() returns — Spring resolves it as a template expression (Thymeleaf view manipulation); map input to fixed view names`);
  }
}

function returnTypeOf(fn: LocalFn): string {
  const kids = named(fn.decl);
  const params = kids.findIndex(k => k.type === "function_value_parameters");
  const t = kids.slice(params + 1).find(k => k.type === "user_type" || k.type === "nullable_type");
  return t ? typeNameOf(t) : "";
}
function isHandler(fn: LocalFn): boolean {
  return fn.annotations.some(a => MAPPING_ANNOTATIONS.has(annotationName(a)));
}
/** @RestController class or @ResponseBody handler: the return value is the HTTP body, not a view name. */
function returnsBody(fn: LocalFn): boolean {
  if (fn.annotations.some(a => annotationName(a) === "ResponseBody")) return true;
  if (!fn.classDecl) return true;
  const anns = classAnnotationNodes(fn.classDecl).map(annotationName);
  return anns.includes("RestController") || anns.includes("ResponseBody") || !anns.includes("Controller");
}

function checkTimingCompare(node: SyntaxNode, l: SyntaxNode, r: SyntaxNode, env: Env, ctx: EngineCtx, mask: TaintMaskFn) {
  const nameOf = (n: SyntaxNode): string => n.type === "simple_identifier" ? n.text : n.type === "navigation_expression" ? memberOf(n)
    : n.type === "call_expression" ? callParts(n).name : "";
  for (const [secret, other] of [[l, r], [r, l]] as const) {
    const nm = nameOf(secret);
    if (nm && SECRET_NAME_RE.test(nm) && !isLiteral(other) && other.type !== "null" && (mask(other, env) & ALL) && !(mask(secret, env) & ALL)) {
      emit(ctx, "timing-attack", node, other.text, nm, `'${other.text.slice(0, 60)}' is compared to ${nm} with ==/equals — use MessageDigest.isEqual (constant time)`);
      return;
    }
  }
}

// ── Same-file helpers (re-walk with seeded parameters) ────────────────────────────────────────────────────

function seedLocalFn(node: SyntaxNode, env: Env, ctx: EngineCtx, mask: TaintMaskFn) {
  const { name, recv } = callParts(node);
  if (recv && recv.type !== "this_expression") return;
  const callee = ctx.fns.get(name);
  if (!callee?.body) return;
  const tainted = new Map<number, number>();
  for (const p of callee.params) {
    const m = bindArgument(callee, node, p.index).reduce((acc, a) => acc | (mask(a, env) & ALL), 0);
    if (m) tainted.set(p.index, m);
  }
  if (tainted.size === 0) return;
  const existing = ctx.seeded.get(callee.name) ?? new Map<number, number>();
  for (const [i, m] of tainted) existing.set(i, (existing.get(i) ?? 0) | m);
  ctx.seeded.set(callee.name, existing);
}

// ── Cross-file calls (facts from other files' methods, Kotlin or Java) ────────────────────────────────────

function callKeys(node: SyntaxNode, env: Env, ctx: EngineCtx): string[] {
  const { name, recv } = callParts(node);
  if (!name) return [];
  if (!recv) return ctx.fns.has(name) || env.has(name) ? [] : [`::${name}`];
  if (recv.type === "simple_identifier") {
    const t = ctx.varTypes.get(recv.text);
    if (t) return [`${bareType(t)}.${name}`];
    if (/^[A-Z]/.test(recv.text) && !env.has(recv.text)) return [`${recv.text}.${name}`];
    return [];
  }
  if (recv.type === "call_expression") {
    const c = constructedClass(recv);
    return c ? [`${c}.${name}`] : [];
  }
  if (recv.type === "navigation_expression") {
    const ct = calleeText(recv);
    return ct && /^[A-Z]/.test(ct.split(".").pop() ?? "") ? [`${ct.split(".").pop()}.${name}`] : [];
  }
  return [];
}

function checkCrossFileCall(node: SyntaxNode, env: Env, ctx: EngineCtx, mask: TaintMaskFn) {
  if (!ctx.crossFileFacts?.size) return;
  const key = callKeys(node, env, ctx).find(k => ctx.crossFileFacts!.has(k));
  if (!key || ctx.localKeys.has(key)) return;
  const facts = ctx.crossFileFacts.get(key)!;
  const args = argsOf(node);
  const pos = args.filter(a => !a.name).map(a => a.expr);
  const line = lineOf(node);
  for (const fact of facts) {
    const bound = fact.isRest ? pos.slice(fact.index) : pos[fact.index] ? [pos[fact.index]] : [];
    for (const a of bound) {
      const m = mask(a, env);
      if (!(m & fact.sinkClass)) { if (wasCleared(m, fact.sinkClass)) ctx.suppressed?.push({ id: fact.id, line }); continue; }
      const dedup = `${fact.id}:${line}`;
      if (ctx.seen.has(dedup)) break;
      ctx.seen.add(dedup);
      const display = displayFnName(key.replace(/^::/, ""));
      const via = fact.via.length > 1 ? ` (${fact.via.map(displayFnName).join(" -> ")})` : "";
      const source = culpritOf(a, fact.sinkClass, env, mask).text;
      const callerTrace = buildBackwardTraceGeneric(ctx.filePath, node, source, display, kotlinTraceResolver);
      callerTrace[callerTrace.length - 1] = { ...callerTrace[callerTrace.length - 1], snippet: `${display}(...)` };
      ctx.findings.push({
        id: fact.id as AstTaintKotlinId, line, sourceExpr: source, sinkExpr: `${display}() -> ${fact.sinkExpr}`,
        detail: `Tainted expression '${source.slice(0, 80)}' is passed to ${display}(...), which reaches ${fact.sinkExpr}(...) at ${fact.file}:${fact.line} [crosses file boundary${via}] — real data-flow match across files, not a line-pattern guess`,
        trace: crossFileTrace(callerTrace, display, fact),
        calleeSink: { file: fact.file, line: fact.line, sinkExpr: fact.sinkExpr, via: fact.via },
      });
      break;
    }
  }
}

// ── Trace resolver ─────────────────────────────────────────────────────────────────────────────────────────

function enclosingScope(node: SyntaxNode): SyntaxNode | null {
  for (let cur = node.parent; cur; cur = cur.parent) if (cur.type === "function_declaration" || cur.type === "anonymous_function") return cur;
  return null;
}
function assignmentsIn(scope: SyntaxNode): Array<{ name: string; position: number; rhsText: string; line: number }> {
  const out: Array<{ name: string; position: number; rhsText: string; line: number }> = [];
  const visit = (n: SyntaxNode) => {
    if (n !== scope && n.type === "function_declaration") return;
    if (n.type === "property_declaration") {
      const nm = childOfType(childOfType(n, "variable_declaration"), "simple_identifier")?.text;
      const v = propertyValue(n);
      if (nm && v) out.push({ name: nm, position: n.startIndex, rhsText: v.text, line: lineOf(v) });
    }
    if (n.type === "assignment") {
      const kids = named(n);
      const t = kids[0], v = kids[kids.length - 1];
      if (t && v && t !== v && named(t).length === 1 && named(t)[0].type === "simple_identifier") out.push({ name: named(t)[0].text, position: n.startIndex, rhsText: v.text, line: lineOf(v) });
    }
    for (const c of named(n)) visit(c);
  };
  visit(scope);
  return out;
}
const kotlinTraceResolver: TraceResolver<SyntaxNode> = {
  enclosingScope, assignmentsIn,
  fileScope: n => { let c = n; while (c.parent) c = c.parent; return c; },
  position: n => n.startIndex, line: lineOf, text: n => n.text,
};

// ── Interprocedural summaries ─────────────────────────────────────────────────────────────────────────────

/** Is `fn`'s body an expression (`fun f(x) = ...`) rather than a block? */
function expressionBody(fn: LocalFn): SyntaxNode | null {
  const kids = named(fn.body);
  return kids.length === 1 && kids[0].type !== "statements" && fn.body?.text.trimStart().startsWith("=") ? kids[0] : null;
}

function returnMask(fn: LocalFn, ctx: EngineCtx, seed: ParamShape | null): number {
  if (!fn.body) return 0;
  let surviving = 0;
  const walker = createWalker({ ...ctx, findings: [], seen: new Set(), suppressed: undefined, seeded: new Map(), stickyDirty: false, sticky: new Map(ctx.sticky), current: null },
    { descendLambdas: false, onReturn: (expr, env, mask) => { if (expr) surviving |= mask(expr, env); } });
  const env: Env = new Map();
  for (const p of fn.params) env.set(p.name, seed && p.index === seed.index ? ALL : 0);
  const expr = expressionBody(fn);
  walker.walk(fn.body, env);
  if (expr) surviving |= walker.mask(expr, env);
  return surviving & ALL;
}

function buildSummaries(ctx: EngineCtx): void {
  for (let round = 0; round < FIXED_POINT_CAP; round++) {
    let changed = false;
    for (const [name, f] of ctx.fns) {
      const intrinsic = returnMask(f, ctx, null);
      if ((intrinsic | (ctx.intrinsic.get(name) ?? 0)) !== (ctx.intrinsic.get(name) ?? 0)) { ctx.intrinsic.set(name, (ctx.intrinsic.get(name) ?? 0) | intrinsic); changed = true; }
      const prop = new Map(ctx.propagating.get(name) ?? []);
      let grew = false;
      for (const p of f.params) {
        const r = returnMask(f, ctx, p) & ~intrinsic;
        const next = (prop.get(p.index) ?? 0) | r;
        if (r && next !== (prop.get(p.index) ?? 0)) { prop.set(p.index, next); grew = true; }
      }
      if (grew) { ctx.propagating.set(name, prop); changed = true; }
    }
    if (!changed) break;
  }
}

// ── BOLA (object-level authorization) ─────────────────────────────────────────────────────────────────────

const RESOURCE_ID_NAME_RE = /^(?:id|ID|pk|.*_id|.*Id)$/;
const BOLA_LOOKUP = new Set(["findById", "getById", "getOne", "getReferenceById", "findByIdOrNull", "findByIdOrThrow"]);
const BOLA_WRITE = new Set(["deleteById", "delete", "save", "saveAndFlush"]);
const PRINCIPAL_TEXT_RE = /getPrincipal|principal|authentication|SecurityContextHolder|currentUser|getCurrentUser|\bme\b|\.getName\s*\(/i;
const SPEL_ID_VS_PRINCIPAL_RE = /#(\w+)\s*(?:==|\.equals\()\s*authentication\.(?:principal\.)?(?:name|id)\b/;
const SPEL_PRINCIPAL_VS_ID_RE = /authentication\.(?:principal\.)?(?:name|id)\s*==\s*#(\w+)\b/;

function annotationEvidence(anns: SyntaxNode[], ids: Set<string>): Set<AuthzKind> {
  const ev = new Set<AuthzKind>();
  for (const a of anns) {
    const nm = annotationName(a);
    if (nm === "Secured" || nm === "RolesAllowed") { ev.add("role"); continue; }
    if (nm !== "PreAuthorize" && nm !== "PostAuthorize") continue;
    const expr = stringValue(findAllNodes(a, "string_literal")[0]) ?? "";
    if (!expr) { ev.add("role"); continue; }
    for (const re of [SPEL_ID_VS_PRINCIPAL_RE, SPEL_PRINCIPAL_VS_ID_RE]) { const m = re.exec(expr); if (m && ids.has(m[1])) ev.add("ownership"); }
    for (const m of expr.matchAll(/(?:@|\b)([\w.]+)\s*\(([^)]*)\)/g)) {
      const kind = classifyGuardName(m[1].split(".").pop() ?? "");
      if (!kind) continue;
      ev.add(kind === "role" && [...ids].some(id => new RegExp(`#${id}\\b`).test(m[2])) ? "ownership" : kind);
    }
    if (ev.size === 0) ev.add("role");
  }
  return ev;
}

const idsIn = (n: SyntaxNode, ids: Set<string>): boolean => findAllNodes(n, new Set(["simple_identifier", "interpolated_identifier"])).some(i => ids.has(i.text));
const principalIn = (n: SyntaxNode, principals: Set<string>): boolean =>
  findAllNodes(n, "simple_identifier").some(i => principals.has(i.text)) || PRINCIPAL_TEXT_RE.test(n.text);

/** Ownership / role evidence a condition proves on its `holds` side. */
function conditionEvidence(cond: SyntaxNode, ids: Set<string>, principals: Set<string>, record: SyntaxNode | null): Array<{ holds: "true" | "false"; kind: AuthzKind }> {
  const c = unwrapParens(cond);
  if (c.type === "prefix_expression" && operatorOf(c) === "!") {
    const inner = named(c)[named(c).length - 1];
    return inner ? conditionEvidence(inner, ids, principals, record).map(e => ({ ...e, holds: e.holds === "true" ? "false" : "true" })) : [];
  }
  if (c.type === "conjunction_expression") return named(c).flatMap(k => conditionEvidence(k, ids, principals, record)).filter(e => e.holds === "true");
  if (c.type === "disjunction_expression") return named(c).flatMap(k => conditionEvidence(k, ids, principals, record)).filter(e => e.holds === "false");
  const compares = (l: SyntaxNode, r: SyntaxNode): boolean => {
    const subject = (n: SyntaxNode) => idsIn(n, ids) || (!!record && n.text.split(/[.?!]/)[0] === record.text && isOwnerField(n.text.split(".").pop() ?? ""));
    return (subject(l) && principalIn(r, principals)) || (subject(r) && principalIn(l, principals));
  };
  if (c.type === "equality_expression") {
    const [l, r] = named(c);
    const op = operatorOf(c);
    if (l && r && compares(l, r)) return [{ holds: op === "==" || op === "===" ? "true" : "false", kind: "ownership" }];
    return [];
  }
  if (c.type === "call_expression") {
    const { name, recv } = callParts(c);
    const pos = positionalArgs(c);
    if (name === "equals" && recv && pos[0] && compares(recv, pos[0])) return [{ holds: "true", kind: "ownership" }];
    if (name === "equals" && pos.length === 2 && compares(pos[0], pos[1])) return [{ holds: "true", kind: "ownership" }];
    const kind = classifyGuardName(name);
    if (kind) return [{ holds: "true", kind: kind === "role" && pos.some(p => idsIn(p, ids)) ? "ownership" : kind }];
  }
  return [];
}

function terminates(body: SyntaxNode | null | undefined): boolean {
  if (!body) return false;
  const stmts = body.type === "control_structure_body" ? named(body) : [body];
  const last = (stmts.length === 1 && stmts[0].type === "statements" ? named(stmts[0]) : stmts).slice(-1)[0];
  if (!last) return false;
  if (last.type === "jump_expression") return /^(?:return|throw)/.test(jumpKeyword(last));
  return last.type === "call_expression" && !callParts(last).recv && TERMINATING_CALLS.has(callParts(last).name);
}

/** Does an ownership/role check dominate `sink`, or check the loaded `record` between source offsets `from` and `to`
 * (after a lookup: anywhere later; before a write of that record: between its load and the write)? */
function dominatingEvidence(
  sink: SyntaxNode, body: SyntaxNode, ids: Set<string>, principals: Set<string>, record: SyntaxNode | null, from: number, to: number,
): AuthzKind | null {
  let found: AuthzKind | null = null;
  const note = (k: AuthzKind) => { if (k === "ownership" || !found) found = k; };
  const consider = (evs: Array<{ holds: "true" | "false"; kind: AuthzKind }>, holds: "true" | "false") => {
    const m = evs.filter(e => e.holds === holds);
    if (m.length) note(m.some(e => e.kind === "ownership") ? "ownership" : "role");
  };
  // enclosing if arms
  for (let cur: SyntaxNode | null = sink; cur && cur.id !== body.id; cur = cur.parent) {
    const p = cur.parent;
    if (p?.type === "if_expression" && cur.type === "control_structure_body") {
      const cond = named(p)[0];
      const bodies = childrenOfType(p, "control_structure_body");
      if (cond) consider(conditionEvidence(cond, ids, principals, null), bodies[0]?.id === cur.id ? "true" : "false");
    }
  }
  // preceding guard clauses in every enclosing statement list: if (...) throw / require(...) / check(...)
  const guardClause = (stmt: SyntaxNode, rec: SyntaxNode | null) => {
    if (stmt.type === "if_expression") {
      const cond = named(stmt)[0];
      const bodies = childrenOfType(stmt, "control_structure_body");
      if (!cond) return;
      const evs = conditionEvidence(cond, ids, principals, rec);
      if (terminates(bodies[0])) consider(evs, "false");
      if (bodies[1] && terminates(bodies[1])) consider(evs, "true");
    }
    if (stmt.type === "call_expression" && /^(?:require|check|assert)$/.test(callParts(stmt).name) && !callParts(stmt).recv) {
      const a = positionalArgs(stmt)[0];
      if (a) consider(conditionEvidence(a, ids, principals, rec), "true");
    }
  };
  for (let cur: SyntaxNode | null = sink; cur && cur.id !== body.parent?.id; cur = cur.parent) {
    const p = cur.parent;
    if (p?.type !== "statements") continue;
    for (const s of named(p)) {
      if (s.startIndex >= cur.startIndex) break;
      guardClause(s, null);
    }
  }
  // a check on the loaded record: `if (order.ownerId != me.id) throw ...`
  if (record) {
    for (const list of findAllNodes(body, "statements")) for (const s of named(list)) if (s.startIndex > from && s.startIndex < to) guardClause(s, record);
  }
  return found;
}

function collectBola(fn: LocalFn, ctx: EngineCtx) {
  if (!fn.body || !isHandler(fn)) return;
  const ids = new Set(fn.params.filter(p => (p.annotations.includes("PathVariable") || p.annotations.includes("RequestParam")) && RESOURCE_ID_NAME_RE.test(p.name)).map(p => p.name));
  if (ids.size === 0) return;
  const principals = new Set(fn.params.filter(p => p.annotations.includes("AuthenticationPrincipal") || /Principal|Authentication|UserDetails|Jwt$/.test(bareType(p.type))).map(p => p.name));
  const classAnns = fn.classDecl ? classAnnotationNodes(fn.classDecl) : [];
  const baseEvidence = annotationEvidence([...fn.annotations, ...classAnns], ids);
  const verb = fn.annotations.map(annotationName);
  const write = verb.some(v => WRITE_VERB_ANNOTATIONS.has(v));
  const read = verb.includes("GetMapping");
  for (const call of findAllNodes(fn.body, "call_expression")) {
    const { name, recv } = callParts(call);
    if (!recv || !(BOLA_LOOKUP.has(name) || BOLA_WRITE.has(name))) continue;
    const a = positionalArgs(call)[0];
    if (!a) continue;
    const viaLocal = a.type === "simple_identifier" ? lastAssignment(a.text, a) : null;
    if (!idsIn(a, ids) && !(viaLocal && idsIn(viaLocal, ids))) continue;
    // The record involved: what a lookup loads (`val order = repo.findById(id)...`, checked anywhere after it), or the
    // record a write saves when it was loaded by the request id (checked between that load and the write).
    let record: SyntaxNode | null = null;
    let from = call.endIndex, to = Number.MAX_SAFE_INTEGER;
    if (BOLA_LOOKUP.has(name)) {
      for (let p = call.parent; p && p.id !== fn.body.id; p = p.parent) {
        if (p.type === "property_declaration") { record = childOfType(childOfType(p, "variable_declaration"), "simple_identifier"); break; }
      }
    } else if (a.type === "simple_identifier" && viaLocal && findAllNodes(viaLocal, "call_expression").some(c => BOLA_LOOKUP.has(callParts(c).name))) {
      record = a; from = viaLocal.endIndex; to = call.startIndex;
    }
    const ev = new Set(baseEvidence);
    const dom = dominatingEvidence(call, fn.body, ids, principals, record, from, to);
    if (dom) ev.add(dom);
    if (findAllNodes(fn.body, "call_expression").some(c => /^(?:authorize|checkPermission|checkAccess|assertOwner|verifyOwner|requireOwner|ensureOwner)$/.test(callParts(c).name))) ev.add("ownership");
    const verdict = authzVerdict(ev);
    if (verdict === "proven") continue;
    const roleOnly = verdict === "role-only";
    const sinkExpr = `${calleeText(recv) ?? recv.text}.${name}`;
    emit(ctx, "bola-missing-ownership-check", call, a.text, sinkExpr,
      roleOnly
        ? `Resource identifier '${a.text}' reaches ${sinkExpr}(...) behind a role/permission check, but nothing establishes that the caller owns THIS object — a role limits who can reach the endpoint, not which objects they may read or change`
        : `Resource identifier '${a.text}' from the request reaches ${sinkExpr}(...) in ${fn.name}() with no ownership check — scope the lookup to the caller (findByIdAndOwnerId) or compare the record's owner to the authenticated principal`,
      roleOnly || (read && !write) ? "medium" : "high");
  }
}

// ── Entry points ──────────────────────────────────────────────────────────────────────────────────────────

function makeCtx(content: string, filePath: string, root: SyntaxNode, suppressed?: SuppressedSink[],
  crossFileFacts?: ReadonlyMap<string, readonly ParamSinkFact[]>): EngineCtx {
  const all = collectFns(root);
  const fns = new Map<string, LocalFn>();
  for (const f of all) if (!fns.has(f.name)) fns.set(f.name, f);
  const fieldTypes = collectFields(root);
  const varTypes = new Map<string, string>();
  for (const [n, t] of fieldTypes) if (t) varTypes.set(n, t);
  for (const f of all) for (const p of f.params) if (!varTypes.has(p.name) && p.type) varTypes.set(p.name, p.type);
  const ctx: EngineCtx = {
    filePath, content, lines: content.split("\n"), root, fns, propagating: new Map(), intrinsic: new Map(), seeded: new Map(),
    suppressed, findings: [], seen: new Set(), fields: new Set(fieldTypes.keys()), sticky: new Map(), stickyDirty: false, varTypes,
    crossFileFacts, localKeys: new Set(all.map(f => f.key).filter((k): k is string => !!k)), current: null,
  };
  buildSummaries(ctx);
  return ctx;
}

const walkMain = (node: SyntaxNode, env: Env, ctx: EngineCtx) => createWalker(ctx, { descendLambdas: true }).walk(node, env);

/** Parameter masks at a function's entry: request-bound parameters are sources. */
function entryEnv(fn: LocalFn, seedEntryPoints: boolean): Env {
  const env: Env = new Map();
  for (const p of fn.params) {
    let m = 0;
    if (p.annotations.some(a => SPRING_SOURCE_ANNOTATIONS.has(a))) m = SAFE_SCALAR_TYPE_RE.test(bareType(p.type)) ? applyClears(ALL, NUMERIC_CLEARS) : ALL;
    else if (seedEntryPoints && p.annotations.length === 0 && STRINGY_TYPE_RE.test(p.type.replace(/\s+/g, " "))) m = ALL;
    env.set(p.name, m);
  }
  return env;
}

function runScan(ctx: EngineCtx, withEntryPoints: boolean): AstTaintKotlinFinding[] {
  // which functions does this file call? the rest are entry points (handlers/library API without annotations)
  const called = new Set<string>();
  for (const c of findAllNodes(ctx.root, "call_expression")) called.add(callParts(c).name);
  const isEntry = (f: LocalFn) => withEntryPoints && !!f.body && !f.isPrivate && !called.has(f.name) && !NON_ENTRY_FN_RE.test(f.name)
    && !f.params.some(p => p.annotations.some(a => SPRING_SOURCE_ANNOTATIONS.has(a)));

  const walkAll = (withBola: boolean) => {
    for (const [, f] of ctx.fns) {
      if (!f.body) continue;
      ctx.current = f;
      const env = entryEnv(f, isEntry(f));
      walkMain(f.body, env, ctx);
      const expr = expressionBody(f);
      if (expr) checkReturnValue(expr, env, ctx, makeTaintMask(ctx));
      if (withBola) collectBola(f, ctx);
    }
    ctx.current = null;
  };
  // class property initializers and init blocks write fields
  for (const body of findAllNodes(ctx.root, "class_body")) {
    for (const s of named(body)) {
      if (s.type === "anonymous_initializer") walkMain(s, new Map(), ctx);
      if (s.type === "property_declaration") {
        const nm = childOfType(childOfType(s, "variable_declaration"), "simple_identifier")?.text;
        const v = propertyValue(s);
        if (nm && v) { const m = makeTaintMask(ctx)(v, new Map()); if (m) ctx.sticky.set(nm, (ctx.sticky.get(nm) ?? 0) | (m & ALL)); }
      }
    }
  }
  walkAll(true);
  for (let round = 0; round < FIXED_POINT_CAP && ctx.stickyDirty; round++) {
    ctx.stickyDirty = false;
    walkAll(false);
  }
  // top-level script statements (.kts) -- function bodies were walked above
  for (const child of named(ctx.root)) {
    if (["function_declaration", "class_declaration", "object_declaration", "property_declaration", "import_list", "package_header", "import_header"].includes(child.type)) continue;
    walkMain(child, new Map(), ctx);
  }
  drainSeeded(ctx);

  // A hand-rolled JWT payload decode in a file that never verifies a signature (Java parity)
  if (!/\bJwts\b|SignedJWT|JWSVerifier|io\.jsonwebtoken|com\.auth0|nimbusds|\.verify\(/.test(ctx.content)) {
    for (const [, f] of ctx.fns) {
      if (!f.body) continue;
      const text = f.body.text;
      if (/\.split\(\s*"(?:\\\\\.|\.)"\s*\)/.test(text) && /Base64/.test(text)) {
        emit(ctx, "jwt-none-alg", f.body, "token", "manual JWT decode",
          "JWT payload is base64-decoded by hand and the file never verifies a signature — claims (role, sub, ...) are attacker-controlled; use a JWT library's verify()");
      }
    }
  }
  return ctx.findings;
}

function drainSeeded(ctx: EngineCtx) {
  const walked = new Set<string>();
  for (let round = 0; round < FIXED_POINT_CAP; round++) {
    let changed = false;
    for (const [name, idx] of Array.from(ctx.seeded.entries())) {
      const f = ctx.fns.get(name);
      if (!f?.body) continue;
      const sig = `${name}:${[...idx].sort((a, b) => a[0] - b[0]).map(([i, v]) => `${i}=${v}`).join(",")}`;
      if (walked.has(sig)) continue;
      walked.add(sig);
      changed = true;
      const env: Env = new Map();
      for (const p of f.params) env.set(p.name, idx.get(p.index) ?? 0);
      const prev = ctx.current;
      ctx.current = f;
      walkMain(f.body, env, ctx);
      ctx.current = prev;
    }
    if (!changed) break;
  }
}

export interface KotlinScanOptions {
  /** Also treat un-annotated String parameters of public functions nothing in the file calls as untrusted input;
   * findings that exist ONLY because of this come back with `entryPointSeeded: true`. */
  entryPoints?: boolean;
  crossFileFacts?: ReadonlyMap<string, readonly ParamSinkFact[]>;
}

export function scanAstTaintKotlin(
  content: string, filePath: string, root: SyntaxNode, suppressedOut?: SuppressedSink[], opts?: KotlinScanOptions,
): AstTaintKotlinFinding[] {
  try {
    const strict = runScan(makeCtx(content, filePath, root, suppressedOut, opts?.crossFileFacts), false);
    if (!opts?.entryPoints) return strict;
    const relaxed = runScan(makeCtx(content, filePath, root, suppressedOut, opts.crossFileFacts), true);
    const have = new Set(strict.map(f => `${f.id}:${f.line}`));
    return [...strict, ...relaxed.filter(f => !have.has(`${f.id}:${f.line}`)).map(f => ({ ...f, entryPointSeeded: true }))];
  } catch (err) {
    console.error(`[astTaintKotlin] threw scanning ${filePath}:`, err);
    return [];
  }
}

/** Findings that are not "this argument reaches that sink" -- a caller doesn't re-raise them. */
const NON_FLOW_IDS: ReadonlySet<string> = new Set(["bola-missing-ownership-check", "timing-attack", "jwt-none-alg", "weak-crypto"]);

/**
 * Parameter -> sink facts for every non-private function in one file, keyed `Class.method` (and each supertype's
 * `Super.method`, so a call through an interface resolves) exactly like computeJavaMethodSinkFacts -- the two
 * languages share one namespace -- plus `::name` for top-level functions. Computed with the scan's own sink logic,
 * each parameter walked alone, diffed against an unseeded baseline.
 */
export function computeKotlinMethodSinkFacts(
  content: string, filePath: string, root: SyntaxNode, incoming: ReadonlyMap<string, readonly ParamSinkFact[]>,
): Map<string, ParamSinkFact[]> {
  const out = new Map<string, ParamSinkFact[]>();
  try {
    const ctx = makeCtx(content, filePath, root, undefined, incoming);
    const all = collectFns(root);
    const ranges = all.map(f => ({ name: f.name, start: f.decl.startPosition.row + 1, end: f.decl.endPosition.row + 1 }));
    const run = (f: LocalFn, env: Env): AstTaintKotlinFinding[] => {
      ctx.findings = []; ctx.seen = new Set(); ctx.seeded = new Map();
      ctx.current = f;
      walkMain(f.body!, env, ctx);
      drainSeeded(ctx);
      ctx.current = null;
      return ctx.findings;
    };
    for (const f of all) {
      if (!f.key || !f.body || f.isPrivate || f.params.length === 0) continue;
      const baseline = new Set(run(f, new Map(f.params.map(p => [p.name, 0]))).map(x => `${x.id}:${x.line}`));
      const label = f.key.replace(/^::/, "");
      const facts: ParamSinkFact[] = [];
      for (const p of f.params) {
        const env: Env = new Map(f.params.map(q => [q.name, q.index === p.index ? ALL : 0]));
        for (const x of dropOnPathDuplicates(run(f, env))) {
          if (baseline.has(`${x.id}:${x.line}`) || NON_FLOW_IDS.has(x.id)) continue;
          const where = x.calleeSink;
          mergeSinkFacts(facts, [{
            index: p.index, isRest: p.isRest, id: x.id, sinkClass: classOf(x.id),
            sinkExpr: where?.sinkExpr ?? x.sinkExpr, file: where?.file ?? filePath, line: where?.line ?? x.line,
            via: [label, ...(where?.via ?? [])],
            steps: x.trace?.length ? factStepsFromTrace(x.trace, label, filePath, f.decl.startPosition.row + 1, p.name,
              { fnEnd: f.decl.endPosition.row + 1, functions: ranges, lines: ctx.lines }) : undefined,
          }]);
        }
      }
      if (facts.length === 0) continue;
      const owners = f.key.startsWith("::") ? [f.key] : [f.key, ...(f.classDecl ? classSupers(f.classDecl).map(s => `${s}.${f.name}`) : [])];
      for (const k of owners) {
        const list = out.get(k) ?? [];
        mergeSinkFacts(list, facts);
        out.set(k, list);
      }
    }
  } catch (err) {
    console.error(`[astTaintKotlin] threw computing method sink facts for ${filePath}:`, err);
  }
  return out;
}
