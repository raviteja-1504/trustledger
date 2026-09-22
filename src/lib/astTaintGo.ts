/**
 * Real AST-based taint engine for Go — Phase 4 of the multi-language OWASP
 * Top 10 hardening effort (see astTaint.ts for Phase 1/JS-TS and
 * astTaintPython.ts for Phase 2/Python, whose five-stage architecture --
 * sources, sinks, propagation, interprocedural, findings -- this file
 * mirrors using web-tree-sitter + tree-sitter-wasms' prebuilt
 * tree-sitter-go.wasm grammar, same as Python's Phase 2 engine).
 *
 * Same warm-cache contract as astTaintPython.ts: WASM instantiation is
 * genuinely async, but analyzeFile()/runScan() in scanner.ts are used
 * synchronously from ~90 call sites -- this module fires WASM init at
 * import time and exposes a synchronous parse function that returns null
 * until the parser is warm. Production awaits warmGoTaintEngine() from
 * src/instrumentation.ts; a cold serverless instance that misses the
 * warm-up window gets regex-only results for that one request, never a
 * crash or a wrong answer.
 *
 * Runs ADDITIVELY alongside every existing Go regex/named-taint detector in
 * scanner.ts (extractTaintedVars' Go branch, findNamedTaintCommandInjectionGo,
 * findNamedTaintIDORGo, findSSRFGoNewRequest, etc.) -- none of those are
 * touched, removed, or replaced. Reuses existing finding ids (sql-injection,
 * command-injection, ssrf, path-traversal, open-redirect,
 * insecure-deserialization, idor), all already wired through cweMap.ts, so
 * no new UI wiring is needed.
 *
 * Deliberately scoped to real data-flow (source-reaches-sink) questions
 * only. Explicitly EXCLUDED, matching astTaintJava.ts's own precedent of
 * leaving "hardening-absence" checks to the regex layer: insecure-randomness,
 * weak-crypto, cookie-no-httponly/cookie-no-secure, pii-in-logs. None of
 * those ask "does tainted input reach a sink" -- they ask "is a hardening
 * flag set/absent" -- and the existing regex detectors for them
 * (findInsecureRandomnessGoFunc, the http.Cookie{} struct-literal branch,
 * etc.) are the structurally right tool, unchanged by this phase.
 *
 * Also deliberately excluded this phase (see the approved plan for the
 * reasoning): cross-file taint (same-file only, matching Python/Java) and
 * sanitizer/de-taint recognition (same "nothing ever de-taints" model as
 * every other engine here -- makeIsTaintedGo's combinators are all
 * `||`/`.some()`).
 *
 * The IDOR check is a deliberate AST-taint + line-window-context hybrid,
 * not pure AST: whether a nearby line contains an ownership-check keyword
 * is reused as-is from scanner.ts's IDOR_AUTH_CHECK_NEARBY_RE (passed in by
 * the caller), consistent with astTaintJava.ts's own BOLA detector mixing a
 * structural AST fact (a tainted id reaching a lookup sink) with a
 * non-AST suppression check (annotation/keyword presence) -- "is there an
 * ownership check nearby" is not a fact a parser alone can answer.
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { Parser, Language } = require("web-tree-sitter") as typeof import("web-tree-sitter");
import type { Node as SyntaxNode, Language as LanguageT, Parser as ParserT } from "web-tree-sitter";
import { ensureTreeSitterInit } from "./treeSitterRuntime";
import {
  ALL, SHADOW, applyClears, applyGuards, buildBackwardTraceGeneric, classOf, cloneEnv, guardedNames, walkIfChain, walkLoop, walkSwitch, wasCleared,
  type Branch, type Guard, type SuppressedSink, type TaintEnv, type TraceResolver, type TraceStep,
} from "./taint/taintCore";
import { sanitizerClears } from "./taint/sanitizers";

// See astTaintPython.ts's identical helper for why: require.resolve(...)
// from inside webpack-bundled code doesn't do real filesystem resolution,
// even for an externalized package -- it returns webpack's internal
// numeric module id instead of a path. __non_webpack_require__ escapes
// that, giving a real on-disk path to read raw .wasm bytes from.
declare const __non_webpack_require__: NodeJS.Require | undefined;
function nodeRequire(): NodeJS.Require {
  // eslint-disable-next-line no-undef
  return typeof __non_webpack_require__ !== "undefined" ? __non_webpack_require__ : require;
}

export type AstTaintGoId =
  | "sql-injection" | "command-injection" | "ssrf" | "path-traversal"
  | "open-redirect" | "insecure-deserialization" | "idor"
  | "xss" | "header-injection" | "redos" | "ssti" | "eval-exec" | "mass-assignment" | "nosql-injection"
  | "ldap-injection" | "xpath-injection" | "timing-attack" | "jwt-none-alg" | "weak-crypto";

export interface AstTaintGoFinding {
  id:         AstTaintGoId;
  line:       number;
  detail:     string;
  sourceExpr: string;
  sinkExpr:   string;
  // Source -> sink trace (best-effort, see taintCore.ts's TraceStep/buildBackwardTraceGeneric docblocks).
  trace?: TraceStep[];
}

// ── Parser lifecycle (warm-cache pattern -- see astTaintPython.ts's docblock) ──

let langPromise: Promise<LanguageT> | null = null;
let parserPool: ParserT | null = null;

function initGoParser(): Promise<LanguageT> {
  if (!langPromise) {
    langPromise = (async () => {
      // Never call Parser.init() directly here -- see treeSitterRuntime.ts's
      // docblock for the concurrent-init race this sidesteps.
      await ensureTreeSitterInit();
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const fs = require("fs") as typeof import("fs");
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const path = require("path") as typeof import("path");
      const webTreeSitterEntry = nodeRequire().resolve("web-tree-sitter");
      const nodeModulesDir = path.dirname(path.dirname(webTreeSitterEntry));
      const wasmPath = path.join(nodeModulesDir, "tree-sitter-wasms", "out", "tree-sitter-go.wasm");
      const lang = await Language.load(new Uint8Array(fs.readFileSync(wasmPath)));
      const p = new Parser();
      p.setLanguage(lang);
      parserPool = p;
      console.log("[astTaintGo] Go AST taint engine ready");
      return lang;
    })().catch(err => {
      console.error("[astTaintGo] WASM init failed -- Go AST taint scanning disabled, regex detectors unaffected:", err);
      throw err;
    });
  }
  return langPromise;
}
// Fire at module import time, skipped under Jest for the same reason
// astTaintPython.ts skips it: dozens of unrelated test files transitively
// import this module via scanner.ts, none of which await this promise.
// astTaintGo.test.ts calls warmGoTaintEngine() explicitly in beforeAll instead.
if (!process.env.JEST_WORKER_ID) {
  void initGoParser().catch(() => { /* already logged above */ });
}

export function isGoParserReady(): boolean {
  return parserPool !== null;
}

/** Awaits WASM readiness. Call from instrumentation.ts (prod) or a test beforeAll. */
export async function warmGoTaintEngine(): Promise<void> {
  await initGoParser().catch(() => { /* already logged; callers just proceed regex-only */ });
}

export function parseGoSourceSync(content: string, filePath: string): SyntaxNode | null {
  if (!parserPool) return null;
  try {
    return parserPool.parse(content)?.rootNode ?? null;
  } catch (err) {
    console.error(`[astTaintGo] parse threw for ${filePath}:`, err);
    return null;
  }
}

// ── Enclosing-function lookup (shared with reachability.ts's resolver) ──────

/** Deepest tree-sitter node whose source range spans 0-based row `row`. */
export function findNodeAtRowGo(root: SyntaxNode, row: number): SyntaxNode {
  let node = root;
  for (;;) {
    const child = node.namedChildren.find(c => c && row >= c.startPosition.row && row <= c.endPosition.row);
    if (!child) return node;
    node = child;
  }
}

/**
 * Walks up to the nearest enclosing function_declaration (a package-level
 * `func foo(...)`) or method_declaration (a receiver method,
 * `func (s *Server) foo(...)`) and reads its `name` field -- present on
 * both node types, confirmed directly against the pinned tree-sitter-go
 * grammar (method_declaration's name field returns a field_identifier
 * rather than an identifier, but .text works identically either way).
 * Matches callGraph.ts's regex-based tryMatchFunc() naming convention
 * closely enough for reachability.ts's name-based lookup to work for both
 * shapes -- unlike Python's resolver, this is NOT restricted to
 * column-0/module-level: Go has no separate "class method" concept the way
 * Python does, so there's no equivalent ambiguity to guard against.
 */
export function findEnclosingFunctionNameGo(node: SyntaxNode): string {
  let cur: SyntaxNode | null = node;
  while (cur) {
    if (cur.type === "function_declaration" || cur.type === "method_declaration") {
      const nameNode = cur.childForFieldName("name");
      if (nameNode) return nameNode.text;
    }
    cur = cur.parent;
  }
  return "unknown";
}

// ── Taint sources ─────────────────────────────────────────────────────────
// Call-shaped, not property-shaped like JS/Python -- Go's idiom is
// r.URL.Query().Get("id"), not a bare attribute access. Matches the exact
// source vocabulary scanner.ts's TAINT_SOURCES/extractTaintedVars Go branch
// already covers, so this engine matches, never narrows, existing recall.

const GIN_ECHO_FIBER_METHODS = new Set(["Param", "Params", "Query", "QueryParam", "PostForm"]);

/** Resolves a selector_expression/identifier chain to dotted text, e.g.
 * `r.URL.Query` -> "r.URL.Query". Mirrors calleeText/calleeTextPy exactly. */
function calleeTextGo(node: SyntaxNode): string | null {
  if (node.type === "identifier" || node.type === "field_identifier") return node.text;
  if (node.type === "selector_expression") {
    const operand = node.childForFieldName("operand");
    const field = node.childForFieldName("field");
    if (!operand || !field) return null;
    const base = calleeTextGo(operand);
    return base ? `${base}.${field.text}` : null;
  }
  return null;
}

function argListOfGo(call: SyntaxNode): SyntaxNode[] {
  const args = call.childForFieldName("arguments");
  if (!args) return [];
  return args.namedChildren.filter((n): n is SyntaxNode => !!n);
}

// r.URL.Query().Get(...) / r.Header.Get(...) embed a CALL in the middle of
// their own selector chain (`.Query()` returns a url.Values, `.Get` is then
// called on THAT) -- calleeTextGo structurally can't resolve through a call
// node, so these are recognized by matching the call's own raw source text
// directly instead. The request variable is any parameter typed *http.Request
// (collected per scan into goSourceCallRe), not only one literally named `r`.
const GIN_ECHO_FIBER_SOURCE_METHODS = new Set([
  "Param", "Params", "Query", "QueryParam", "QueryParams", "PostForm", "PostFormArray", "DefaultQuery", "DefaultPostForm",
  "GetHeader", "Cookie", "FormValue", "FormParams", "GetRawData", "Body",
]);

function isTaintSourceExprGo(node: SyntaxNode): boolean {
  if (node.type === "call_expression") {
    if (goSourceCallRe.test(node.text)) return true;
    const fn = node.childForFieldName("function");
    const text = fn ? calleeTextGo(fn) : null;
    if (!text) return /^mux\.Vars\s*\(/.test(node.text);
    // chi.URLParam(r, "id")
    if (text === "chi.URLParam" || text.endsWith(".URLParam")) return true;
    if (text === "mux.Vars") return true;
    // gin/echo/fiber: c.Param("id") / c.Query("id") / c.QueryParam("id") / c.PostForm("id")
    if (text.startsWith("c.")) {
      const method = text.slice(2);
      if (GIN_ECHO_FIBER_SOURCE_METHODS.has(method) || GIN_ECHO_FIBER_METHODS.has(method)) return true;
    }
    return false;
  }
  if (node.type === "selector_expression") return goSourceSelectorRe.test(node.text.replace(/\s+/g, ""));
  if (node.type === "index_expression") {
    const operand = node.childForFieldName("operand");
    // mux.Vars(r)["id"] -- operand is itself a call_expression, not a
    // resolvable dotted name; check that shape directly via raw text too
    // (same embedded-call reason as the call sources above).
    if (operand?.type === "call_expression" && /^mux\.Vars\s*\(/.test(operand.text)) return true;
    // r.Header["X-Name"]
    const text = operand ? calleeTextGo(operand) : null;
    if (text === "r.Header" || text?.endsWith(".Header")) return true;
    return false;
  }
  return false;
}

// ── Sink dispatch table ──────────────────────────────────────────────────
// sql-injection and idor are handled as separate, independent checks (see
// scanAstTaintGo below), not through this table -- a single .QueryRow(...)
// call can legitimately be BOTH a sql-injection candidate (if its QUERY
// STRING argument, args[0], is tainted -- built via concatenation/Sprintf)
// AND an idor candidate (if its bind-parameter id argument is tainted with
// no ownership check nearby) -- two different questions about two different
// arguments of the same call, not mutually exclusive categories a single
// dispatch table entry could represent.

interface SinkMatch { id: AstTaintGoId; sinkExpr: string; args: SyntaxNode[] }

// ── Go recall helpers (sources, passthroughs, scope, sinks) ──────────────────

interface GoScanCtx {
  writerVars: Set<string>;      // parameters typed http.ResponseWriter
  pluginVars: Set<string>;      // variables assigned from plugin.Open(...)
  gobVars: Set<string>;         // variables assigned from gob.NewDecoder(...)
  htmlEscapers: Set<string>;    // local funcs that replace "<" with an entity
  sensitiveStructs: Set<string>;   // struct types with role/admin-like fields
  varStructTypes: Map<string, string>; // variable -> declared struct type name
}
const emptyGoCtx = (): GoScanCtx => ({
  writerVars: new Set(["w"]), pluginVars: new Set(), gobVars: new Set(), htmlEscapers: new Set(),
  sensitiveStructs: new Set(), varStructTypes: new Map(),
});
// Per-scan facts. Scans are synchronous, so a module-level slot set at scan start is safe.
let goCtx: GoScanCtx = emptyGoCtx();
let goSourceCallRe = /^(?:r|req|request|c\.Request)\.(?:URL\.Query\(\)|(?:Header\.(?:Get|Values)|FormValue|PostFormValue|Cookie|Referer|UserAgent|BasicAuth|PathValue)\s*\()/;
let goSourceSelectorRe = /^(?:r|req|request|c\.Request)\.(?:URL\.(?:Path|RawQuery|RawPath|Fragment)|Form|PostForm|MultipartForm|Body|Host|RequestURI|Header|Trailer)$/;
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
function setGoRequestVars(names: Iterable<string>): void {
  const alt = ["r", "req", "request", ...names].map(escapeRe).join("|");
  goSourceCallRe = new RegExp(`^(?:${alt}|c\\.Request)\\.(?:URL\\.Query\\(\\)|(?:Header\\.(?:Get|Values)|FormValue|PostFormValue|Cookie|Referer|UserAgent|BasicAuth|PathValue)\\s*\\()`);
  goSourceSelectorRe = new RegExp(`^(?:${alt}|c\\.Request)\\.(?:URL\\.(?:Path|RawQuery|RawPath|Fragment)|Form|PostForm|MultipartForm|Body|Host|RequestURI|Header|Trailer)$`);
}

// Stdlib/utility calls whose RESULT carries the taint of their arguments (string, path, URL, JSON and
// container plumbing that neither validates nor neutralizes anything). Opaque calls stay untainted.
const GO_PASSTHROUGH = new Set([
  "strings.TrimSpace", "strings.Trim", "strings.TrimLeft", "strings.TrimRight", "strings.TrimPrefix", "strings.TrimSuffix",
  "strings.TrimFunc", "strings.ToLower", "strings.ToUpper", "strings.ToTitle", "strings.Title", "strings.Replace",
  "strings.ReplaceAll", "strings.Join", "strings.Split", "strings.SplitN", "strings.SplitAfter", "strings.Fields",
  "strings.Repeat", "strings.Map", "strings.NewReader", "strings.Clone",
  "bytes.TrimSpace", "bytes.Trim", "bytes.ToLower", "bytes.ToUpper", "bytes.ReplaceAll", "bytes.NewBuffer",
  "bytes.NewBufferString", "bytes.NewReader", "bytes.Join", "bytes.Split",
  "fmt.Errorf", "url.QueryUnescape", "url.PathUnescape", "url.Parse", "url.ParseRequestURI", "url.JoinPath",
  "filepath.Join", "filepath.Clean", "filepath.Abs", "filepath.Dir", "filepath.ToSlash", "filepath.FromSlash", "filepath.Rel",
  "path.Join", "path.Clean", "path.Dir", "json.Marshal", "json.MarshalIndent", "json.NewDecoder", "xml.NewDecoder",
  "gob.NewDecoder", "yaml.NewDecoder", "io.ReadAll", "ioutil.ReadAll", "bufio.NewReader", "bufio.NewScanner",
  "html.UnescapeString", "hex.DecodeString", "hex.EncodeToString", "strconv.Quote", "template.HTML", "template.JS",
  "template.JSStr", "template.URL", "template.CSS", "template.HTMLAttr", "textwrap.Dedent",
]);
const GO_DECODERS = new Set(["url.QueryUnescape", "url.PathUnescape", "html.UnescapeString", "hex.DecodeString"]);
const GO_BASE64_RE = /(?:^|\.)base64\.\w+\.(?:DecodeString|EncodeToString)$|(?:^|\.)base64\.(?:StdEncoding|URLEncoding|RawStdEncoding|RawURLEncoding)\.(?:DecodeString|EncodeToString)$/;
// Methods whose result also includes their ARGUMENTS (replacement text) and container mutators.
const GO_ARG_CARRYING_METHODS = new Set(["Replace", "ReplaceAll", "Join", "Sprintf", "Format"]);
const GO_MUTATORS = new Set(["WriteString", "Write", "WriteByte", "WriteRune", "Add", "Set", "Push", "Store", "Put", "Insert", "Append", "Enqueue"]);
const GO_BUILTIN_METHOD_NAMES = new Set([
  "Get", "Set", "Add", "Del", "Write", "WriteString", "Read", "Close", "Query", "Exec", "Execute", "Encode", "Decode",
  "String", "Error", "Join", "Split", "Replace", "Sprintf", "Format", "Lookup", "Open", "Run", "Do", "Next", "Scan",
]);

/** Root identifier of a selector/index/paren/star/address expression (`a.b[c].d` -> a). */
function rootIdentGo(n: SyntaxNode | null | undefined): SyntaxNode | null {
  let cur: SyntaxNode | null | undefined = n;
  while (cur) {
    if (cur.type === "identifier") return cur;
    if (cur.type === "selector_expression" || cur.type === "index_expression") cur = cur.childForFieldName("operand");
    else if (cur.type === "parenthesized_expression" || cur.type === "unary_expression" || cur.type === "slice_expression") cur = cur.namedChildren[0] ?? null;
    else if (cur.type === "call_expression") cur = cur.childForFieldName("function");
    else return null;
  }
  return null;
}

const localNamesCacheGo = new WeakMap<SyntaxNode, Set<string>>();
/** Names bound inside a function (params, :=, var, range, type-switch alias). Nested function bodies excluded. */
function localNamesOfGo(fn: SyntaxNode): Set<string> {
  const cached = localNamesCacheGo.get(fn);
  if (cached) return cached;
  const names = new Set<string>(paramNamesOfGo(fn));
  const body = fn.childForFieldName("body");
  const visit = (n: SyntaxNode) => {
    if (n.type === "func_literal") { for (const p of paramNamesOfGo(n)) names.add(p); }
    if (n.type === "short_var_declaration") {
      for (const id of identifiersOf(n.childForFieldName("left") ?? n)) names.add(id.text);
    } else if (n.type === "var_spec") {
      for (const nm of n.childrenForFieldName("name")) if (nm) names.add(nm.text);
    } else if (n.type === "range_clause") {
      for (const id of identifiersOf(n.childForFieldName("left") ?? n)) names.add(id.text);
    } else if (n.type === "type_switch_statement") {
      for (const id of identifiersOf(n.childForFieldName("alias") ?? n)) names.add(id.text);
    }
    for (const c of n.namedChildren) if (c) visit(c);
  };
  if (body) visit(body);
  localNamesCacheGo.set(fn, names);
  return names;
}

/** Is identifier `id` bound by an enclosing function (a parameter or local) rather than at package level? */
function isLocalNameGo(id: SyntaxNode): boolean {
  for (let cur: SyntaxNode | null = id.parent; cur; cur = cur.parent) {
    if ((cur.type === "function_declaration" || cur.type === "method_declaration" || cur.type === "func_literal") &&
        localNamesOfGo(cur).has(id.text)) return true;
  }
  return false;
}
function enclosingFnGo(n: SyntaxNode): SyntaxNode | null {
  for (let cur: SyntaxNode | null = n.parent; cur; cur = cur.parent) {
    if (cur.type === "function_declaration" || cur.type === "method_declaration" || cur.type === "func_literal") return cur;
  }
  return null;
}
/** Is `id` a PARAMETER of an enclosing function (a callback the caller supplied)? */
function isParamOfEnclosingFnGo(id: SyntaxNode): boolean {
  for (let cur: SyntaxNode | null = id.parent; cur; cur = cur.parent) {
    if ((cur.type === "function_declaration" || cur.type === "method_declaration" || cur.type === "func_literal") &&
        paramNamesOfGo(cur).includes(id.text)) return true;
  }
  return false;
}

/** The out-parameter a decode-style call fills (`json.Unmarshal(data, &v)`, `dec.Decode(&v)`, `c.ShouldBindJSON(&v)`). */
function findOutParamGo(call: SyntaxNode, env: TaintEnv, mask: (n: SyntaxNode, e: TaintEnv) => number): { root: string; mask: number } | null {
  const fn = call.childForFieldName("function");
  if (!fn) return null;
  const args = argListOfGo(call);
  const text = calleeTextGo(fn);
  const rootOf = (a: SyntaxNode | undefined) => rootIdentGo(a)?.text ?? null;
  if (text && /^(?:json|xml|yaml|toml|msgpack)\.Unmarshal$/.test(text) && args[1]) {
    const m = mask(args[0], env);
    const r = rootOf(args[1]);
    return r && (m & ALL) ? { root: r, mask: m } : null;
  }
  if (fn.type === "selector_expression") {
    const field = fn.childForFieldName("field")?.text ?? "";
    const operand = fn.childForFieldName("operand");
    if (field === "Decode" && args[0] && operand) {
      const m = mask(operand, env);
      const r = rootOf(args[0]);
      return r && (m & ALL) ? { root: r, mask: m } : null;
    }
    if (/^(?:ShouldBind\w*|Bind\w*|BodyParser|QueryParser|ParamsParser|ReqHeaderParser)$/.test(field) && args[0] && /^(?:c|ctx|context)$/.test(operand?.text ?? "")) {
      const r = rootOf(args[0]);
      return r ? { root: r, mask: ALL } : null;
    }
  }
  return null;
}

const NOSQL_TAILS_GO = new Set(["FindOne", "Find", "UpdateOne", "UpdateMany", "DeleteOne", "DeleteMany", "Aggregate", "CountDocuments", "ReplaceOne", "FindOneAndUpdate", "FindOneAndDelete", "FindOneAndReplace"]);
const NOSQL_RECEIVER_RE_GO = /coll|mongo|\bdb\b|users?\b|orders?\b|accounts?\b|store|repo/i;
const FS_SINKS_GO = new Set([
  "Open", "Create", "OpenFile", "ReadFile", "WriteFile", "Remove", "RemoveAll", "Mkdir", "MkdirAll", "Rename", "Stat",
  "Lstat", "ReadDir", "Chmod", "Chdir", "Truncate", "Symlink", "Link", "Chown",
]);
const TEMPLATE_PARSE_RE_GO = /^(?:text\/)?template\.(?:New|Must)\b[\s\S]*\.(?:Parse|ParseFiles|ParseGlob)$/;
const SENSITIVE_FIELD_RE_GO = /^(?:role|roles|admin|is_?admin|permissions?|privileges?|scope|scopes|is_?staff|superuser|is_?superuser|groups?)$/i;
const SECRET_NAME_RE_GO = /^(?:[A-Za-z_]*(?:secret|token|password|passwd|apikey|api_key|hmac|signature)[A-Za-z_0-9]*)$/i;

function matchSinkGo(call: SyntaxNode): SinkMatch | null {
  const fnNode = call.childForFieldName("function");
  if (!fnNode) return null;
  const rawText = fnNode.text.replace(/\s+/g, "");
  const text = calleeTextGo(fnNode) ?? rawText;
  const parts = text.split(".");
  const head = parts[0];
  const tail = parts[parts.length - 1];
  const args = argListOfGo(call);
  const receiverText = parts.slice(0, -1).join(".");

  if (text === "exec.Command" || text === "exec.CommandContext") {
    return { id: "command-injection", sinkExpr: text, args };
  }
  if (text === "http.Get" || text === "http.Post" || text === "http.Head" || text === "http.PostForm" ||
      (["Get", "Post", "Head", "PostForm"].includes(tail) && /(?:^|\.)(?:client|Client|httpClient|http\.DefaultClient)$/.test(receiverText)) ||
      /^net\.(?:Dial|DialTimeout|DialTCP|DialUDP)$/.test(text)) {
    return { id: "ssrf", sinkExpr: text, args: /^net\./.test(text) ? args.slice(1, 2) : args };
  }
  if ((head === "os" && FS_SINKS_GO.has(tail)) || (head === "ioutil" && (tail === "ReadFile" || tail === "WriteFile" || tail === "ReadDir")) ||
      /^filepath\.Walk(?:Dir)?$/.test(text) || text === "os.DirFS") {
    return { id: "path-traversal", sinkExpr: text, args: args.slice(0, 1).length ? args.slice(0, 1) : args };
  }
  if (text === "filepath.Join") {
    return { id: "path-traversal", sinkExpr: text, args };
  }
  if (text === "http.ServeFile" && args[2]) return { id: "path-traversal", sinkExpr: text, args: [args[2]] };
  if (text === "http.Redirect") {
    // http.Redirect(w, r, target, code) -- target is the 3rd positional arg.
    return args[2] ? { id: "open-redirect", sinkExpr: text, args: [args[2]] } : null;
  }
  if (tail === "Redirect" && /^(?:c|ctx)$/.test(receiverText) && args.length > 0) {
    return { id: "open-redirect", sinkExpr: text, args: [args[args.length - 1]] };
  }
  // XSS: writes to the response body
  if (/^fmt\.Fprint(?:f|ln)?$/.test(text) && args[0] && (goCtx.writerVars.has(args[0].text) || /^(?:c\.Writer|resp|res|rw)$/.test(args[0].text))) {
    return { id: "xss", sinkExpr: text, args: args.slice(1) };
  }
  if (text === "io.WriteString" && args[0] && goCtx.writerVars.has(args[0].text) && args[1]) return { id: "xss", sinkExpr: text, args: [args[1]] };
  if ((tail === "Write" || tail === "WriteString") && (goCtx.writerVars.has(receiverText) || receiverText === "c.Writer")) {
    return { id: "xss", sinkExpr: text, args };
  }
  if ((tail === "String" || tail === "HTML" || tail === "SendString" || tail === "Send") && /^(?:c|ctx)$/.test(receiverText) && args.length > 0) {
    return { id: "xss", sinkExpr: text, args: args.slice(-1) };
  }
  if (/^template\.(?:HTML|JS|JSStr|URL|CSS|HTMLAttr)$/.test(text) && args[0]) return { id: "xss", sinkExpr: text, args: [args[0]] };
  // HTTP header injection
  if (/^(?:[\w.]+)\.Header\(\)\.(?:Set|Add)$/.test(rawText) || /^(?:c|ctx)\.(?:Header|SetHeader|Set)$/.test(text)) {
    if (args.length >= 2) return { id: "header-injection", sinkExpr: text, args };
  }
  // SSRF via raw text (client.Do is handled elsewhere)
  // SQL entry points
  if (["QueryContext", "ExecContext", "QueryRowContext", "PrepareContext"].includes(tail) && args[1]) {
    return { id: "sql-injection", sinkExpr: text, args: [args[1]] };
  }
  if (["Prepare", "Raw", "Rebind", "Queryx", "QueryRowx", "MustExec", "NamedExec", "NamedQuery"].includes(tail) && args[0] && parts.length > 1) {
    return { id: "sql-injection", sinkExpr: text, args: [args[0]] };
  }
  if ((tail === "Select" || tail === "Get") && args.length >= 2 && /(?:^|\.)(?:db|tx|DB|sqlx)$/.test(receiverText)) {
    return { id: "sql-injection", sinkExpr: text, args: [args[1]] };
  }
  // user-controlled regular expression
  if (/^regexp\.(?:MustCompile|Compile|MatchString|Match|MustCompilePOSIX|CompilePOSIX)$/.test(text) && args[0]) {
    return { id: "redos", sinkExpr: text, args: [args[0]] };
  }
  // template text controlled by the caller
  if (TEMPLATE_PARSE_RE_GO.test(rawText) && args[0]) return { id: "ssti", sinkExpr: text, args: [args[0]] };
  // dynamic code / reflection
  if (text === "plugin.Open" && args[0]) return { id: "eval-exec", sinkExpr: text, args: [args[0]] };
  if (tail === "Lookup" && goCtx.pluginVars.has(receiverText) && args[0]) return { id: "eval-exec", sinkExpr: text, args: [args[0]] };
  if (tail === "MethodByName" && args[0]) return { id: "eval-exec", sinkExpr: text, args: [args[0]] };
  if ((tail === "RunString" || tail === "Eval") && args[0] && parts.length > 1) return { id: "eval-exec", sinkExpr: text, args: [args[0]] };
  if (tail === "FieldByName" && args[0]) return { id: "mass-assignment", sinkExpr: text, args: [args[0]] };
  // NoSQL (mongo-style) with an operator-capable filter document
  if (parts.length > 1 && NOSQL_TAILS_GO.has(tail) && NOSQL_RECEIVER_RE_GO.test(receiverText) && args.length > 0) {
    return { id: "nosql-injection", sinkExpr: text, args: args.slice(-1) };
  }
  // LDAP
  if (text === "ldap.NewSearchRequest" && args.length >= 7) return { id: "ldap-injection", sinkExpr: text, args: [args[6]] };
  if (parts.length === 1 && /^(?:ldap_?[sS]earch|search_?[lL]dap|ldapQuery|LDAPSearch|ldapFind)$/.test(tail) && args[0]) {
    return { id: "ldap-injection", sinkExpr: text, args: [args[0]] };
  }
  // XPath
  if (/^(?:xpath\.(?:Compile|MustCompile)|xmlquery\.(?:Find|FindOne)|htmlquery\.(?:Find|FindOne))$/.test(text)) {
    const expr = /^xpath\./.test(text) ? args[0] : args[1];
    if (expr) return { id: "xpath-injection", sinkExpr: text, args: [expr] };
  }
  if (parts.length === 1 && /^(?:xpath_?[qQ]uery|select_?[xX][pP]ath|evaluate_?[xX][pP]ath|run_?[xX][pP]ath|xpathSearch)$/.test(tail) && args[0]) {
    return { id: "xpath-injection", sinkExpr: text, args: [args[0]] };
  }
  return null;
}

// String shapes: a `+` chain / Sprintf that builds SQL, LDAP or XPath text around an untrusted operand.
const SQL_START_RE_GO = /^\s*(?:select|insert|update|delete|with|call|exec(?:ute)?|merge|replace)\b/i;
const LDAP_SHAPE_RE_GO = /\(\s*[&|!]?\s*(?:\(\s*)?[\w.-]+\s*(?:=|~=|>=|<=)\s*$/;
const XPATH_SHAPE_RE_GO = /\/\/?[\w*@.:-]+(?:\/[\w*@.:()-]+)*\[[^\]]*=\s*['"]?$/;
const SCRIPT_CONTEXT_RE_GO = /<script\b[^>]*>(?:(?!<\/script>)[\s\S])*$/i;
// Inside a still-open tag with a bare `attr=` right at the end and no quote before the hole --
// HTML-escaping doesn't add the missing quotes an unquoted attribute value needs (see astTaint.ts's
// identical JS/TS check's own docblock for the full reasoning).
const UNQUOTED_ATTR_CONTEXT_RE_GO = /<[a-zA-Z][-\w]*(?:\s+[-\w]+(?:=(?:"[^"]*"|'[^']*'|[^\s>]*))?)*\s+[-\w]+=\s*$/;

function goStringLiteralValue(n: SyntaxNode): string | null {
  if (n.type === "interpreted_string_literal") return n.text.slice(1, -1);
  if (n.type === "raw_string_literal") return n.text.slice(1, -1);
  if (n.type === "parenthesized_expression" && n.namedChildren[0]) return goStringLiteralValue(n.namedChildren[0]);
  return null;
}
/** Flatten a `a + b + c` chain into its operands, or null when it is not a pure `+` chain. */
function concatOperandsGo(n: SyntaxNode): SyntaxNode[] | null {
  if (n.type !== "binary_expression" || n.childForFieldName("operator")?.type !== "+") return null;
  const l = n.childForFieldName("left");
  const r = n.childForFieldName("right");
  if (!l || !r) return null;
  const left = l.type === "binary_expression" ? concatOperandsGo(l) : [l];
  return left ? [...left, r] : null;
}

function findAllNodesGo(root: SyntaxNode, type: string, acc: SyntaxNode[] = []): SyntaxNode[] {
  if (root.type === type) acc.push(root);
  for (const c of root.namedChildren) if (c) findAllNodesGo(c, type, acc);
  return acc;
}

/** SQL injection is a QUERY-TEXT question, not an any-argument one: only
 * args[0] (the query string) is checked -- a tainted bind-parameter value
 * (args[1+], the normal, safe use of parameterization) is never itself
 * "sql-injection", it's what the separate idor check below cares about. */
function matchSqlInjectionGo(call: SyntaxNode): SinkMatch | null {
  const fnNode = call.childForFieldName("function");
  const text = fnNode ? calleeTextGo(fnNode) : null;
  if (!text) return null;
  const tail = text.split(".").pop();
  if (tail !== "Query" && tail !== "QueryRow" && tail !== "Exec") return null;
  const args = argListOfGo(call);
  return args[0] ? { id: "sql-injection", sinkExpr: text, args: [args[0]] } : null;
}

/** Mirrors GO_IDOR_SINK_RE's three shapes (db.QueryRow/.First/.Where),
 * checking only the LAST argument (the id-like bind parameter), independent
 * of matchSqlInjectionGo's args[0]-only check above. */
function matchIdorGo(call: SyntaxNode): SinkMatch | null {
  const fnNode = call.childForFieldName("function");
  const text = fnNode ? calleeTextGo(fnNode) : null;
  if (!text) return null;
  const tail = text.split(".").pop();
  if (tail !== "QueryRow" && tail !== "First" && tail !== "Where") return null;
  const args = argListOfGo(call);
  const last = args[args.length - 1];
  return last ? { id: "idor", sinkExpr: text, args: [last] } : null;
}

// ── Authorization analysis (Decision 4) ─────────────────────────────────
// Real structural check mirroring astTaintJava.ts's collectBolaFindings,
// ADDED alongside (not replacing) the existing idorAuthCheckNearby regex
// callback below -- both must fail to suppress for an idor finding to fire,
// so this can only ever REDUCE false positives further, never introduce
// new ones, and needs zero scanner.ts wiring changes (the callback stays
// exactly as-is). Dominance-aware: the comparison must precede the sink and
// put it on the continuing path (see ownershipDominatesGo), not merely exist
// somewhere in the enclosing function.

/** Gin/Echo/Fiber principal-lookup vocabulary -- the same specific tokens
 * IDOR_AUTH_CHECK_NEARBY_RE (scanner.ts) already matches as line text
 * (`c.MustGet(...)`, `c.GetString("user"/"userId"/"userID"/"uid")`), now
 * matched structurally against a real call_expression instead. */
function isPrincipalShapedGo(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const fn = node.childForFieldName("function");
  const text = fn ? calleeTextGo(fn) : null;
  if (!text) return false;
  if (text.endsWith(".MustGet")) return true;
  if (text.endsWith(".GetString")) {
    const raw = argListOfGo(node)[0]?.text ?? "";
    return /^["'](?:user|userId|userID|user_id|uid)["']$/i.test(raw);
  }
  return false;
}

const GO_FUNCTION_NODES = new Set(["function_declaration", "method_declaration", "func_literal"]);

function findEnclosingFunctionNodeGo(node: SyntaxNode): SyntaxNode | null {
  let cur: SyntaxNode | null = node;
  while (cur) {
    if (GO_FUNCTION_NODES.has(cur.type)) return cur;
    cur = cur.parent;
  }
  return null;
}

// Calls that never return -- an arm ending in one cannot continue.
const TERMINATING_CALLS_GO = new Set([
  "panic", "os.Exit", "log.Fatal", "log.Fatalf", "log.Fatalln", "log.Panic", "log.Panicf", "log.Panicln",
]);

/** True when control cannot fall out of the end of `n` (return / panic-like
 * call, a block containing one, or an if whose every arm does). */
function statementTerminatesGo(n: SyntaxNode | null): boolean {
  if (!n) return false;
  if (n.type === "return_statement") return true;
  if (n.type === "expression_statement") {
    const call = n.namedChildren[0];
    if (call?.type === "call_expression") {
      const fn = call.childForFieldName("function");
      const text = fn ? calleeTextGo(fn) : null;
      return !!text && TERMINATING_CALLS_GO.has(text);
    }
    return false;
  }
  if (n.type === "block") return n.namedChildren.some(c => statementTerminatesGo(c));
  if (n.type === "if_statement") {
    const alt = n.childForFieldName("alternative");
    return !!alt && statementTerminatesGo(n.childForFieldName("consequence")) && statementTerminatesGo(alt);
  }
  return false;
}

type SideGo = "true" | "false";

/** Which side(s) of `cond` establish that `id` is compared equal to the
 * authenticated principal (`==` holds on the true side, `!=` on the false
 * side; `!`/`&&`/`||` compose like validation guards do). An identifier
 * condition (`isOwner`) resolves ONE hop to its last preceding assignment. */
function ownershipSidesGo(cond: SyntaxNode, id: string, fnBody: SyntaxNode, resolve = true): SideGo[] {
  const isId = (n: SyntaxNode | null) => !!n && n.type === "identifier" && n.text === id;
  const flip = (s: SideGo): SideGo => (s === "true" ? "false" : "true");
  switch (cond.type) {
    case "parenthesized_expression": {
      const inner = cond.namedChildren[0];
      return inner ? ownershipSidesGo(inner, id, fnBody, resolve) : [];
    }
    case "unary_expression": {
      if (cond.child(0)?.type !== "!") return [];
      const inner = cond.namedChildren[0];
      return inner ? ownershipSidesGo(inner, id, fnBody, resolve).map(flip) : [];
    }
    case "binary_expression": {
      const op = cond.childForFieldName("operator")?.type;
      const l = cond.childForFieldName("left");
      const r = cond.childForFieldName("right");
      if (!l || !r) return [];
      if (op === "==" || op === "!=") {
        const hit = (isId(l) && isPrincipalShapedGo(r)) || (isId(r) && isPrincipalShapedGo(l));
        return hit ? [op === "==" ? "true" : "false"] : [];
      }
      if (op === "&&") return [...ownershipSidesGo(l, id, fnBody, resolve), ...ownershipSidesGo(r, id, fnBody, resolve)].filter(s => s === "true");
      if (op === "||") return [...ownershipSidesGo(l, id, fnBody, resolve), ...ownershipSidesGo(r, id, fnBody, resolve)].filter(s => s === "false");
      return [];
    }
    case "call_expression": {
      const fn = cond.childForFieldName("function");
      if (fn?.type === "selector_expression" && fn.childForFieldName("field")?.text === "Equal") {
        const operand = fn.childForFieldName("operand");
        const arg0 = argListOfGo(cond)[0] ?? null;
        if ((isId(operand) && arg0 && isPrincipalShapedGo(arg0)) || (isId(arg0) && operand && isPrincipalShapedGo(operand))) return ["true"];
      }
      return [];
    }
    case "identifier": {
      if (!resolve) return [];
      let best: SyntaxNode | null = null;
      const visit = (n: SyntaxNode) => {
        if ((n.type === "short_var_declaration" || n.type === "assignment_statement") && n.endIndex <= cond.startIndex) {
          const left = n.childForFieldName("left");
          const right = n.childForFieldName("right");
          const ids = left ? left.namedChildren.filter(c => !!c) : [];
          if (ids.length === 1 && ids[0]!.text === cond.text && right?.namedChildren.length === 1) {
            if (!best || n.endIndex > best.endIndex) best = right.namedChildren[0]!;
          }
        }
        for (const c of n.namedChildren) if (c) visit(c);
      };
      visit(fnBody);
      return best ? ownershipSidesGo(best, id, fnBody, false) : [];
    }
    default:
      return [];
  }
}

/**
 * Does an ownership comparison for `id` DOMINATE `sink`? It must (a) sit in
 * an if condition that precedes the sink in source order and (b) put the
 * sink on the continuing path: the sink is in the arm where the comparison
 * establishes ownership, or the arm where it does not always terminates and
 * the sink comes after the whole if. A comparison that is unused, follows
 * the lookup, or guards a different branch no longer suppresses.
 */
function ownershipDominatesGo(sink: SyntaxNode, id: string, fnBody: SyntaxNode): boolean {
  const contains = (outer: SyntaxNode | null, inner: SyntaxNode) =>
    !!outer && outer.startIndex <= inner.startIndex && inner.endIndex <= outer.endIndex;
  let found = false;
  const visit = (n: SyntaxNode) => {
    if (found) return;
    if (n.type === "if_statement") {
      const cond = n.childForFieldName("condition");
      const cons = n.childForFieldName("consequence");
      const alt = n.childForFieldName("alternative");
      if (cond && cond.endIndex <= sink.startIndex) {
        const sides = ownershipSidesGo(cond, id, fnBody);
        const afterIf = sink.startIndex >= n.endIndex && contains(n.parent, sink);
        if (sides.includes("true") && (contains(cons, sink) || (afterIf && statementTerminatesGo(alt)))) found = true;
        if (sides.includes("false") && (contains(alt, sink) || (afterIf && statementTerminatesGo(cons)))) found = true;
      }
    }
    if (!found) for (const c of n.namedChildren) if (c) visit(c);
  };
  visit(fnBody);
  return found;
}

/** Only meaningful when the tainted resource-id expression fed to the sink
 * is itself a bare identifier -- a compound expression (a selector, a call)
 * has no single name a separate comparison elsewhere could reference by,
 * same "bare identifier only" scoping astTaintJava.ts's bareIdentifierOf
 * uses for its own one-hop backward check. */
function structuralOwnershipCheckSuppressesGo(sinkNode: SyntaxNode, resourceIdExpr: SyntaxNode): boolean {
  if (resourceIdExpr.type !== "identifier") return false;
  const enclosingFn = findEnclosingFunctionNodeGo(sinkNode);
  const fnBody = enclosingFn?.childForFieldName("body");
  if (!fnBody) return false;
  return ownershipDominatesGo(sinkNode, resourceIdExpr.text, fnBody);
}

// ── Taint environment / propagation ─────────────────────────────────────────
// Flat, OR-shaped, no de-tainting -- same explicit design as astTaint.ts /
// astTaintPython.ts / astTaintJava.ts. Nothing in makeIsTaintedGo ever
// clears a taint flag once set.

type Env = TaintEnv;
// fn name -> (param index -> sink classes that survive to its return value)
type PropagatingGo = Map<string, Map<number, number>>;
interface ParamShape { name: string; index: number }
interface LocalFn { paramShapes: ParamShape[]; body: SyntaxNode }

function paramShapesOfGo(fn: SyntaxNode): ParamShape[] {
  const params = fn.childForFieldName("parameters");
  if (!params) return [];
  const shapes: ParamShape[] = [];
  let index = 0;
  for (const p of params.namedChildren) {
    if (!p || (p.type !== "parameter_declaration" && p.type !== "variadic_parameter_declaration")) continue;
    // `a, b string` is ONE declaration binding two parameters; an unnamed
    // parameter (`func(string)`) still occupies a position.
    const names = p.childrenForFieldName("name").filter((n): n is SyntaxNode => !!n);
    if (names.length === 0) { index++; continue; }
    for (const nm of names) shapes.push({ name: nm.text, index: index++ });
  }
  return shapes;
}

/** fmt.Sprintf / fmt.Errorf / fmt.Sprint -- any %-placeholder arg's taint
 * propagates to the call's own result, a generic "known formatting
 * function" passthrough (not sink-specific -- the SQL-injection sink match
 * happens separately, at whatever call wraps this one). */
function isFormatCall(text: string): boolean {
  return text === "fmt.Sprintf" || text === "fmt.Errorf" || text === "fmt.Sprint" || text === "fmt.Sprintln";
}

// ── Sanitizer/de-taint recognition ──────────────────────────────────────
// Sanitizers live in taint/sanitizers.ts, keyed by the sink classes each one
// actually neutralizes. strconv.Atoi/ParseInt/ParseFloat/ParseBool used to be
// deliberately taint-PRESERVING here (so an IDOR check on the converted id
// still fired); they now clear every INJECTION class (a %d into SQL is not
// injectable) while keeping the CONTROL bit, which is exactly what the IDOR
// check asks for -- no special case needed at the IDOR site beyond its class.

function makeTaintMaskGo(localFns: Map<string, LocalFn>, propagating: PropagatingGo, sticky?: Map<string, number>) {
  let fnValueDepth = 0;
  const orArgs = (args: SyntaxNode[], env: Env): number =>
    args.reduce((m, a) => (a.type === "func_literal" ? m : m | taintMask(a, env)), 0);

  const callMask = (node: SyntaxNode, env: Env): number => {
    const fn = node.childForFieldName("function");
    const args = argListOfGo(node);
    const text = fn ? calleeTextGo(fn) : null;
    if (text) {
      // Known sanitizer: the argument's taint passes THROUGH minus only the
      // classes it neutralizes. Checked BEFORE the format-call passthrough
      // and every other taint-increasing branch below, so a sanitized value
      // can't be re-tainted by one of them in this same call.
      const clears = sanitizerClears("go", text);
      if (clears !== null) return args[0] ? applyClears(taintMask(args[0], env), clears) : 0;
      // a local function that replaces "<" with an HTML entity is structurally an escaper
      if (goCtx.htmlEscapers.has(text)) return args[0] ? applyClears(taintMask(args[0], env), classOf("xss")) : 0;
      if (isFormatCall(text)) return args.reduce((m, a) => m | taintMask(a, env), 0);
      // Curated stdlib passthroughs; a decoder re-taints what an earlier encoder cleared.
      if (GO_PASSTHROUGH.has(text) || GO_BASE64_RE.test(text)) {
        const m = orArgs(args, env);
        return GO_DECODERS.has(text) || /DecodeString$/.test(text) ? (m & ALL) | ((m >>> SHADOW) & ALL) : m;
      }
    }
    // builtins and type conversions: string(x), []byte(x), append(a, b...), copy
    if (fn?.type === "identifier" && (fn.text === "string" || fn.text === "append" || fn.text === "copy") && !localFns.has(fn.text)) {
      return args.reduce((m, a) => m | taintMask(a, env), 0);
    }
    if (fn && fn.type !== "identifier" && fn.type !== "selector_expression" && fn.type !== "func_literal" &&
        fn.type !== "call_expression" && fn.type !== "parenthesized_expression") {
      return orArgs(args, env); // `[]byte(x)` and other conversions
    }
    // A call to a local function known to propagate taint from SPECIFIC
    // params to its return value (see computeReturnTaintPropagatingGo),
    // limited to the classes that survive the callee's own body. Also resolves
    // `obj.method(x)` to a local method by name.
    const fnName = fn?.type === "identifier" ? fn.text
      : fn?.type === "selector_expression" && !GO_BUILTIN_METHOD_NAMES.has(fn.childForFieldName("field")?.text ?? "")
        ? fn.childForFieldName("field")?.text ?? null : null;
    if (fnName) {
      const propIdx = propagating.get(fnName);
      if (propIdx) {
        const callee = localFns.get(fnName);
        const shapes = callee?.paramShapes ?? [];
        let m = 0;
        for (const [i, surviving] of propIdx) {
          if (shapes[i] !== undefined && args[i] !== undefined) m |= taintMask(args[i], env) & surviving;
        }
        if (m) return m;
      }
    }
    // calling a value: an IIFE / `f()()` / a closure held in a variable returns what it captured;
    // calling a callback PARAMETER is (recall-biased) as tainted as what it is called with
    if (fn && (fn.type === "call_expression" || fn.type === "func_literal" || fn.type === "parenthesized_expression")) {
      const inner = fn.type === "parenthesized_expression" ? fn.namedChildren[0] : fn;
      if (inner) return taintMask(inner, env);
    }
    if (fn?.type === "identifier" && !propagating.has(fn.text)) {
      if (isParamOfEnclosingFnGo(fn)) return orArgs(args, env);
      const held = env.get(fn.text) ?? 0;
      if (held) return held;
    }
    // Passthrough method call on an already-tainted receiver
    // (dec.Decode(), strings.TrimSpace(x) via selector on a tainted var); a few methods
    // (Replacer.Replace) also carry their arguments.
    if (fn?.type === "selector_expression") {
      const operand = fn.childForFieldName("operand");
      const field = fn.childForFieldName("field")?.text ?? "";
      const recv = operand ? taintMask(operand, env) : 0;
      return recv | (GO_ARG_CARRYING_METHODS.has(field) ? orArgs(args, env) : 0);
    }
    return 0;
  };

  const taintMask = (node: SyntaxNode, env: Env): number => {
    if (isTaintSourceExprGo(node)) return ALL;
    if (node.type === "identifier") {
      let m = env.get(node.text) ?? 0;
      const st = sticky?.get(node.text);
      if (st && !isLocalNameGo(node)) m |= st;
      // a bare object also carries the fields written onto it (`u.host = h; u`)
      const prefix = node.text + ".";
      for (const [k, v] of env) if (v && k.startsWith(prefix)) m |= v;
      return m;
    }
    if (node.type === "binary_expression") {
      const op = node.childForFieldName("operator")?.type;
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if (op === "+" && left && right) return taintMask(left, env) | taintMask(right, env);
      return 0;
    }
    if (node.type === "call_expression") return callMask(node, env);
    if (node.type === "index_expression" || node.type === "slice_expression" || node.type === "type_assertion_expression" ||
        node.type === "type_conversion_expression") {
      const operand = node.childForFieldName("operand") ?? node.namedChildren[0];
      return operand ? taintMask(operand, env) : 0;
    }
    // Field-sensitive read: a bare selector like `user.Name` ORs the full
    // dotted-path composite key (set by the selector-expression assignment
    // handling in `walk`'s short_var_decl/assignment_statement branch below)
    // with the operand's own mask -- pure recall gain. The ROOT identifier
    // contributes only its own mask so field sensitivity survives.
    if (node.type === "selector_expression") {
      const path = calleeTextGo(node);
      const operand = node.childForFieldName("operand");
      const opMask = operand?.type === "identifier"
        ? (env.get(operand.text) ?? 0) | (sticky && !isLocalNameGo(operand) ? (sticky.get(operand.text) ?? 0) : 0)
        : operand ? taintMask(operand, env) : 0;
      return (path ? (env.get(path) ?? 0) : 0) | opMask;
    }
    if (node.type === "unary_expression" || node.type === "variadic_argument") {
      const operand = node.namedChildren[0];
      return operand ? taintMask(operand, env) : 0;
    }
    if (node.type === "parenthesized_expression") {
      const inner = node.namedChildren[0];
      return inner ? taintMask(inner, env) : 0;
    }
    if (node.type === "literal_element") {
      const inner = node.namedChildren[0];
      return inner ? taintMask(inner, env) : 0;
    }
    if (node.type === "composite_literal") {
      const body = node.childForFieldName("body");
      if (!body) return 0;
      return body.namedChildren.reduce((m: number, el) => {
        if (!el) return m;
        if (el.type === "keyed_element") return el.namedChildren[1] ? m | taintMask(el.namedChildren[1], env) : m;
        return m | taintMask(el, env); // unkeyed literal element (slice/array literal entries)
      }, 0);
    }
    // A function VALUE carries whatever it captured: `func() string { return v }` returns v when called.
    // Bounded (shallow) so nested literals stay cheap.
    if (node.type === "func_literal") {
      if (fnValueDepth >= 2) return 0;
      const body = node.childForFieldName("body");
      if (!body) return 0;
      const lenv = cloneEnv(env);
      for (const p of paramNamesOfGo(node)) lenv.set(p, 0);
      let m = 0;
      fnValueDepth++;
      try {
        createWalkerGo({
          localFns, propagating, root: node.tree.rootNode, descendFunctions: false,
          onReturn: (e, en, mk) => { m |= mk(e, en); },
        }).walk(body, lenv);
      } finally { fnValueDepth--; }
      return m;
    }
    return 0;
  };
  return taintMask;
}

type TaintMaskFnGo = ReturnType<typeof makeTaintMaskGo>;

/**
 * For each of `fn`'s parameters INDEPENDENTLY, does `fn`'s return value
 * become tainted? Returns the set of propagating parameter INDICES, not a
 * per-function boolean -- identical reasoning to computeReturnTaintPropagating
 * (astTaint.ts) / computeReturnTaintPropagatingPy (astTaintPython.ts): sound
 * because makeIsTaintedGo is purely OR-shaped, so seeding a superset of
 * params can only ever taint a superset of what seeding a subset taints.
 * Go's multi-value returns (`return a, b`) are checked as "any returned
 * expression tainted" -- conservative, matches this engine's recall-biased
 * philosophy elsewhere.
 *
 * Nested calls inside `fn`'s own body are resolved using whatever
 * `isTaintedFn` the caller passes in (Decision 3) -- no longer hardcoded to
 * a fresh empty-map evaluator internally. See buildPropagatingMapGo below,
 * which threads a bounded, round-capped view of the file's own in-progress
 * propagating map instead.
 */
function computeReturnTaintPropagatingGo(
  fn: LocalFn, localFns: Map<string, LocalFn>, propagating: PropagatingGo, root: SyntaxNode,
): Map<number, number> {
  // param index -> sink classes that still survive to the return value
  const propagatingIdx = new Map<number, number>();
  for (const shape of fn.paramShapes) {
    let surviving = 0;
    const walker = createWalkerGo({
      localFns, propagating, root, descendFunctions: false,
      // Go's multi-value returns (`return a, b`): any returned expression counts.
      onReturn: (expr, env, mask) => { surviving |= mask(expr, env); },
    });
    const env: Env = new Map();
    env.set(shape.name, ALL);
    walker.walk(fn.body, env);
    // Low bits only: the shadow half is per-scan bookkeeping, not a summary.
    surviving &= ALL;
    if (surviving) propagatingIdx.set(shape.index, surviving);
  }
  return propagatingIdx;
}

// Caps every bounded fixed-point loop below (same-file propagating-map
// convergence and the call-site-seeding worklist) -- named and shared for
// the same reason astTaint.ts's own MAX_PROPAGATION_ROUNDS is, and matching
// its value exactly.
const MAX_PROPAGATION_ROUNDS = 3;

/**
 * Builds the same-file propagating-param map via a bounded fixed-point
 * iteration instead of one pass with every nested call opaque (Decision 3),
 * mirroring astTaint.ts's/astTaintPython.ts's/astTaintJava.ts's own
 * buildPropagatingMap. Sound without extra cycle-breaking machinery because
 * propagation is monotonic (each round only ever ADDS indices, never
 * removes one, and every function's index set is bounded by its own
 * parameter count) -- convergence is never in doubt, the round cap only
 * bounds worst-case cost on a large file's call graph.
 */
function buildPropagatingMapGo(localFns: Map<string, LocalFn>, root: SyntaxNode): PropagatingGo {
  const propagating: PropagatingGo = new Map();
  for (let round = 0; round < MAX_PROPAGATION_ROUNDS; round++) {
    let changed = false;
    for (const [name, fn] of localFns) {
      const found = computeReturnTaintPropagatingGo(fn, localFns, propagating, root);
      // Monotonic merge (only ever adds a parameter or adds surviving classes).
      const merged = new Map(propagating.get(name) ?? []);
      let grew = false;
      for (const [idx, m] of found) {
        const next = (merged.get(idx) ?? 0) | m;
        if (next !== (merged.get(idx) ?? 0)) { merged.set(idx, next); grew = true; }
      }
      if (grew) { propagating.set(name, merged); changed = true; }
    }
    if (!changed) break;
  }
  return propagating;
}

function sourceLabelGo(node: SyntaxNode): string {
  return node.text.replace(/\s+/g, " ").slice(0, 60);
}

function collectLocalFunctionsGo(root: SyntaxNode): Map<string, LocalFn> {
  const fns = new Map<string, LocalFn>();
  const visit = (node: SyntaxNode) => {
    if (node.type === "function_declaration" || node.type === "method_declaration") {
      const name = node.childForFieldName("name")?.text;
      const body = node.childForFieldName("body");
      if (name && body) fns.set(name, { paramShapes: paramShapesOfGo(node), body });
    }
    for (const c of node.namedChildren) if (c) visit(c);
  };
  visit(root);
  return fns;
}

const SEVERITY: Record<AstTaintGoId, "critical" | "high" | "medium"> = {
  "sql-injection": "critical", "command-injection": "critical", "ssrf": "critical",
  "path-traversal": "critical", "insecure-deserialization": "critical",
  "open-redirect": "medium", "idor": "medium",
  "xss": "critical", "header-injection": "high", "redos": "high", "ssti": "critical", "eval-exec": "critical",
  "mass-assignment": "high", "nosql-injection": "critical", "ldap-injection": "critical", "xpath-injection": "critical",
  "timing-attack": "medium", "jwt-none-alg": "critical", "weak-crypto": "high",
};
const LABEL: Record<AstTaintGoId, string> = {
  "sql-injection": "SQL Injection", "command-injection": "Command Injection",
  "ssrf": "Server-Side Request Forgery", "path-traversal": "Path Traversal",
  "insecure-deserialization": "Insecure Deserialization",
  "open-redirect": "Open Redirect", "idor": "Insecure Direct Object Reference",
  "xss": "Reflected XSS", "header-injection": "HTTP Header Injection", "redos": "ReDoS — Regex DoS",
  "ssti": "Server-Side Template Injection", "eval-exec": "Arbitrary Code Execution", "mass-assignment": "Mass Assignment",
  "nosql-injection": "NoSQL Injection", "ldap-injection": "LDAP Injection", "xpath-injection": "XPath Injection",
  "timing-attack": "Timing Attack", "jwt-none-alg": "JWT Signature Not Verified", "weak-crypto": "Weak Cryptography",
};

/** Unwraps short_var_declaration/assignment_statement's left/right fields,
 * both of which the grammar ALWAYS wraps in an expression_list -- even for
 * a single identifier on the left (confirmed directly: `x := ...` produces
 * `left: (expression_list (identifier))`, never a bare identifier field). */
function identifiersOf(exprList: SyntaxNode): SyntaxNode[] {
  return exprList.namedChildren.filter((n): n is SyntaxNode => !!n && n.type === "identifier");
}

/** Assignment LHS targets (Decision 1, write side): identifier OR
 * selector_expression (`obj.field`, confirmed directly: `user.Name = x`
 * parses as `left: (expression_list (selector_expression ...))`, not an
 * identifier -- previously entirely invisible to identifiersOf, so
 * `user.Name = x` silently updated no env entry at all). Any other LHS
 * shape (index_expression, etc.) stays unrecognized/untracked, same as
 * before -- scoped to static dotted-property access only. */
function assignmentTargetsOfGo(exprList: SyntaxNode): SyntaxNode[] {
  return exprList.namedChildren.filter((n): n is SyntaxNode =>
    !!n && (n.type === "identifier" || n.type === "selector_expression"));
}

/** Env lookup key for an assignment target: plain text for an identifier,
 * the full dotted path (calleeTextGo) for a selector_expression -- the same
 * key shape the new field-sensitive read case in makeIsTaintedGo checks. */
function assignmentKeyOfGo(target: SyntaxNode): string | null {
  return target.type === "identifier" ? target.text : calleeTextGo(target);
}

// ── Narrow validation guards ────────────────────────────────────────────────
// Same policy as the other engines: only unambiguous proofs that a bare
// identifier is safe -- literal equality, literal-collection membership
// (`slices.Contains`, or the `_, ok := allowed[x]` map idiom), strict numeric
// parses (`_, err := strconv.Atoi(x)` then `err != nil`). NOT recognized:
// regex matches, prefix checks, custom validators.

/** A name bound by a validating statement, resolved when it shows up in a condition. */
interface ValidationAliasGo { target: string; kind: "ok" | "err" }

const STRICT_PARSE_CALLS_GO = new Set(["strconv.Atoi", "strconv.ParseInt", "strconv.ParseUint", "strconv.ParseFloat", "strconv.ParseBool"]);
const NUMERIC_TYPES_GO = new Set([
  "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64",
  "float32", "float64", "bool",
]);

function isLiteralGo(n: SyntaxNode): boolean {
  if (n.type === "literal_element") return !!n.namedChildren[0] && isLiteralGo(n.namedChildren[0]);
  if (n.type === "parenthesized_expression") return !!n.namedChildren[0] && isLiteralGo(n.namedChildren[0]);
  return ["interpreted_string_literal", "raw_string_literal", "int_literal", "float_literal", "rune_literal"].includes(n.type);
}

/** `[]string{"a","b"}` / `map[string]bool{"a": true}` (all keys/elements literal), or an
 * identifier EVERY binding of which, file-wide, is such a literal (a name that is
 * ever rebound to something else is not trusted). */
function isLiteralCollectionGo(n: SyntaxNode, root: SyntaxNode, depth = 0): boolean {
  if (n.type === "composite_literal") {
    const body = n.childForFieldName("body");
    if (!body) return false;
    const els = body.namedChildren.filter((c): c is SyntaxNode => !!c);
    return els.length > 0 && els.every(el => {
      if (el.type === "keyed_element") return !!el.namedChildren[0] && isLiteralGo(el.namedChildren[0]);
      return isLiteralGo(el);
    });
  }
  if (n.type === "identifier" && depth === 0) {
    const bindings: SyntaxNode[] = [];
    let opaque = false;
    const visit = (x: SyntaxNode) => {
      if (x.type === "var_spec") {
        const names = x.childrenForFieldName("name").filter(c => !!c);
        const value = x.childForFieldName("value");
        if (names.some(nm => nm!.text === n.text)) {
          if (names.length === 1 && value?.namedChildren.length === 1) bindings.push(value.namedChildren[0]!);
          else opaque = true;
        }
      } else if (x.type === "short_var_declaration" || x.type === "assignment_statement") {
        const left = x.childForFieldName("left");
        const right = x.childForFieldName("right");
        const ids = left?.namedChildren.filter(c => !!c) ?? [];
        if (ids.some(i => i!.type === "identifier" && i!.text === n.text)) {
          if (ids.length === 1 && right?.namedChildren.length === 1) bindings.push(right.namedChildren[0]!);
          else opaque = true;
        }
      }
      for (const c of x.namedChildren) if (c) visit(c);
    };
    visit(root);
    return !opaque && bindings.length > 0 && bindings.every(b => isLiteralCollectionGo(b, root, 1));
  }
  return false;
}

function invertGo(g: Guard): Guard {
  return { name: g.name, holds: g.holds === "true" ? "false" : "true" };
}

function guardsOfConditionGo(cond: SyntaxNode, root: SyntaxNode, aliases: ReadonlyMap<string, ValidationAliasGo>): Guard[] {
  switch (cond.type) {
    case "parenthesized_expression": {
      const inner = cond.namedChildren[0];
      return inner ? guardsOfConditionGo(inner, root, aliases) : [];
    }
    case "unary_expression": {
      if (cond.child(0)?.type !== "!") return [];
      const inner = cond.namedChildren[0];
      return inner ? guardsOfConditionGo(inner, root, aliases).map(invertGo) : [];
    }
    case "identifier": {
      const a = aliases.get(cond.text);
      // `_, ok := allowed[x]; if ok {` -- x is a member of a literal allowlist
      return a?.kind === "ok" ? [{ name: a.target, holds: "true" }] : [];
    }
    case "binary_expression": {
      const op = cond.childForFieldName("operator")?.type;
      const l = cond.childForFieldName("left");
      const r = cond.childForFieldName("right");
      if (!l || !r) return [];
      if (op === "&&") return [...guardsOfConditionGo(l, root, aliases), ...guardsOfConditionGo(r, root, aliases)].filter(g => g.holds === "true");
      if (op === "||") return [...guardsOfConditionGo(l, root, aliases), ...guardsOfConditionGo(r, root, aliases)].filter(g => g.holds === "false");
      if (op === "==" || op === "!=") {
        const holdsWhenEqual: "true" | "false" = op === "==" ? "true" : "false";
        if (l.type === "identifier" && isLiteralGo(r)) return [{ name: l.text, holds: holdsWhenEqual }];
        if (r.type === "identifier" && isLiteralGo(l)) return [{ name: r.text, holds: holdsWhenEqual }];
        // `err == nil` / `err != nil` after `_, err := strconv.Atoi(x)`
        if (l.type === "identifier" && r.type === "nil") {
          const a = aliases.get(l.text);
          if (a?.kind === "err") return [{ name: a.target, holds: op === "==" ? "true" : "false" }];
        }
      }
      return [];
    }
    case "call_expression": {
      const fn = cond.childForFieldName("function");
      const text = fn ? calleeTextGo(fn) : null;
      const args = argListOfGo(cond);
      if (text === "slices.Contains" && args.length === 2 && args[1].type === "identifier" && isLiteralCollectionGo(args[0], root)) {
        return [{ name: args[1].text, holds: "true" }];
      }
      return [];
    }
    default:
      return [];
  }
}

// ── Path-sensitive statement walk ───────────────────────────────────────────
// One walker serves the interprocedural summary builder (no sink checks, no
// nested functions, collects return masks) and the main scan (sink checks,
// nested functions walked on a cloned env). Branches walk each arm on a CLONE
// of the env and join with may-taint OR (shared combinators in
// taint/taintCore.ts); an arm ending in return/panic is dropped from the
// join, and code after a terminating statement is dead and not walked.

interface WalkHooksGo {
  localFns: Map<string, LocalFn>;
  propagating: PropagatingGo;
  root: SyntaxNode;
  /** Sink checks / call-site seeding for one call_expression, with the env at that point. */
  onCall?: (node: SyntaxNode, env: Env, taintMask: TaintMaskFnGo) => void;
  /** Called for each returned value, with the env on that path. */
  onReturn?: (expr: SyntaxNode, env: Env, taintMask: TaintMaskFnGo) => void;
  /** Walk nested function bodies (main scan) or ignore them (summaries). */
  descendFunctions: boolean;
  /** Package-level container memory shared across functions (main scan only). */
  sticky?: Map<string, number>;
  /** Called for every visited node with the env at that point (string shapes, comparisons, mutation recording). */
  onNode?: (node: SyntaxNode, env: Env, taintMask: TaintMaskFnGo) => void;
}

function paramNamesOfGo(fn: SyntaxNode): string[] {
  const names: string[] = [];
  for (const list of [fn.childForFieldName("receiver"), fn.childForFieldName("parameters")]) {
    if (!list) continue;
    for (const p of list.namedChildren) {
      if (!p || (p.type !== "parameter_declaration" && p.type !== "variadic_parameter_declaration")) continue;
      for (const nm of p.childrenForFieldName("name")) if (nm) names.push(nm.text);
    }
  }
  return names;
}

function createWalkerGo(h: WalkHooksGo) {
  const taintMask = makeTaintMaskGo(h.localFns, h.propagating, h.sticky);
  // >0 while walking an immediately-invoked / go / defer literal in the CURRENT scope (its returns are not ours)
  let inline = 0;
  // Names bound by a validating statement (`_, ok := allowed[x]`), per function.
  let aliases = new Map<string, ValidationAliasGo>();

  const walkStmts = (nodes: readonly (SyntaxNode | null)[], env: Env): boolean => {
    for (const c of nodes) if (c && walk(c, env)) return true; // dead code after a terminator is not walked
    return false;
  };

  const walkFunction = (fn: SyntaxNode, env: Env) => {
    const body = fn.childForFieldName("body");
    if (!body) return;
    // A nested function sees captured outer variables (cloned env); its own
    // parameters shadow same-named outer ones and start untainted.
    const fenv = cloneEnv(env);
    for (const p of paramNamesOfGo(fn)) fenv.set(p, 0);
    const saved = aliases;
    aliases = new Map();
    walk(body, fenv);
    aliases = saved;
  };

  const rememberAliases = (names: readonly SyntaxNode[], rightVals: readonly SyntaxNode[]) => {
    for (const n of names) aliases.delete(n.text);
    if (names.length !== 2 || rightVals.length !== 1) return;
    const rhs = rightVals[0];
    const okName = names[1].text;
    if (rhs.type === "index_expression") {
      const operand = rhs.childForFieldName("operand");
      const index = rhs.childForFieldName("index");
      if (operand && index?.type === "identifier" && isLiteralCollectionGo(operand, h.root)) {
        aliases.set(okName, { target: index.text, kind: "ok" });
      }
    } else if (rhs.type === "call_expression") {
      const fn = rhs.childForFieldName("function");
      const text = fn ? calleeTextGo(fn) : null;
      const arg0 = argListOfGo(rhs)[0];
      if (text && STRICT_PARSE_CALLS_GO.has(text) && arg0?.type === "identifier") {
        aliases.set(okName, { target: arg0.text, kind: "err" });
      }
    }
  };

  /** Bind `targets` (env keys, null = unrecognized/blank) from `rightVals`; `compound` ORs with the existing value. */
  const bind = (targets: readonly (string | null)[], rightVals: readonly SyntaxNode[], env: Env, compound: boolean) => {
    const put = (key: string | null, mask: number) => {
      if (key) env.set(key, compound ? mask | (env.get(key) ?? 0) : mask);
    };
    if (targets.length > 0 && rightVals.length === 1) {
      // Single RHS value (possibly Go's multi-return form binding N LHS
      // targets to one call's multiple return values) -- only the FIRST
      // target is marked tainted, never trailing ones (by strong Go
      // convention those are `err`/`ok`, not real data).
      put(targets[0], taintMask(rightVals[0], env));
    } else {
      // Positional 1:1 multi-assignment (`a, b = x, y`) -- assign independently.
      targets.forEach((key, i) => { if (rightVals[i]) put(key, taintMask(rightVals[i], env)); });
    }
  };

  const walk = (node: SyntaxNode, env: Env): boolean => {
    switch (node.type) {
      case "function_declaration":
      case "method_declaration":
      case "func_literal":
        if (h.descendFunctions) walkFunction(node, env);
        return false;

      case "source_file":
      case "block":
        return walkStmts(node.namedChildren, env);

      case "expression_statement": {
        for (const c of node.namedChildren) if (c) walk(c, env);
        return statementTerminatesGo(node);
      }

      case "if_statement": {
        const branches: Branch[] = [];
        let cur: SyntaxNode | null = node;
        while (cur && cur.type === "if_statement") {
          const init = cur.childForFieldName("initializer");
          const cond = cur.childForFieldName("condition");
          const cons = cur.childForFieldName("consequence");
          branches.push({
            visitCond: (e) => { if (init) walk(init, e); if (cond) walk(cond, e); },
            guards: () => (cond ? guardsOfConditionGo(cond, h.root, aliases) : []),
            body: (e) => (cons ? walk(cons, e) : false),
          });
          const alt: SyntaxNode | null = cur.childForFieldName("alternative");
          if (alt && alt.type !== "if_statement") {
            branches.push({ body: (e) => walk(alt, e) });
            cur = null;
          } else {
            cur = alt;
          }
        }
        return walkIfChain(env, branches);
      }

      case "for_statement": {
        const body = node.childForFieldName("body");
        const head = node.namedChildren.find(c => !!c && c.id !== body?.id) ?? null;
        if (head?.type === "range_clause") {
          const right = head.childForFieldName("right");
          if (right) walk(right, env);
          const rmask = right ? taintMask(right, env) : 0;
          const targets = (head.childForFieldName("left")?.namedChildren ?? []).filter((c): c is SyntaxNode => !!c && c.type === "identifier");
          // Two targets = (index/key, value): the value carries the element's taint.
          const carrier = targets.length === 2 ? [targets[1]] : targets;
          for (const t of targets) env.set(t.text, 0);
          for (const t of carrier) if (t.text !== "_") env.set(t.text, rmask);
          return walkLoop(env, (e) => (body ? walk(body, e) : false));
        }
        let update: SyntaxNode | null = null;
        if (head?.type === "for_clause") {
          const init = head.childForFieldName("initializer");
          const cond = head.childForFieldName("condition");
          update = head.childForFieldName("update");
          if (init) walk(init, env);
          if (cond) walk(cond, env);
        } else if (head) {
          walk(head, env);
        }
        return walkLoop(env, (e) => {
          const t = body ? walk(body, e) : false;
          if (!t && update) walk(update, e);
          return t;
        });
      }

      case "expression_switch_statement": {
        const init = node.childForFieldName("initializer");
        if (init) walk(init, env);
        const value = node.childForFieldName("value");
        if (value) walk(value, env);
        const subject = value?.type === "identifier" ? value.text : null;
        const clauses = node.namedChildren.filter(c => c?.type === "expression_case" || c?.type === "default_case");
        return walkSwitch(env, clauses.map(cl => {
          const caseValue = cl!.childForFieldName("value");
          const values = (caseValue?.namedChildren ?? []).filter((c): c is SyntaxNode => !!c);
          const stmts = cl!.namedChildren.filter(c => !!c && c.id !== caseValue?.id);
          return {
            isDefault: cl!.type === "default_case",
            pre: (e: Env) => {
              // `switch x { case "a", "b": ... }` -- inside, x IS one of the literals.
              if (subject && values.length > 0 && values.every(isLiteralGo)) applyGuards(e, [subject]);
              // tagless `switch { case x == "a": ... }` -- each case is a condition.
              if (!value) for (const v of values) applyGuards(e, guardedNames(guardsOfConditionGo(v, h.root, aliases), "true"));
            },
            body: (e: Env) => walkStmts(stmts, e),
          };
        }));
      }

      case "type_switch_statement": {
        const init = node.childForFieldName("initializer");
        if (init) walk(init, env);
        const value = node.childForFieldName("value");
        if (value) walk(value, env);
        const subject = value?.type === "identifier" ? value.text : null;
        const aliasNames = (node.childForFieldName("alias")?.namedChildren ?? []).filter((c): c is SyntaxNode => !!c).map(c => c.text);
        const vmask = value ? taintMask(value, env) : 0;
        for (const a of aliasNames) env.set(a, vmask);
        const clauses = node.namedChildren.filter(c => c?.type === "type_case" || c?.type === "default_case");
        return walkSwitch(env, clauses.map(cl => {
          const types = cl!.childrenForFieldName("type").filter((c): c is SyntaxNode => !!c);
          const typeIds = new Set(types.map(t => t.id));
          const stmts = cl!.namedChildren.filter(c => !!c && !typeIds.has(c.id));
          return {
            isDefault: cl!.type === "default_case",
            // `case int, float64:` -- a strict numeric/bool type check
            pre: (e: Env) => {
              if (types.length > 0 && types.every(t => NUMERIC_TYPES_GO.has(t.text))) applyGuards(e, subject ? [subject, ...aliasNames] : aliasNames);
            },
            body: (e: Env) => walkStmts(stmts, e),
          };
        }));
      }

      case "select_statement": {
        const clauses = node.namedChildren.filter(c => c?.type === "communication_case" || c?.type === "default_case");
        return walkSwitch(env, clauses.map(cl => {
          const comm = cl!.childForFieldName("communication");
          const stmts = cl!.namedChildren.filter(c => !!c && c.id !== comm?.id);
          return {
            isDefault: cl!.type === "default_case",
            pre: (e: Env) => { if (comm) walk(comm, e); },
            body: (e: Env) => walkStmts(stmts, e),
          };
        }));
      }

      case "return_statement": {
        for (const c of node.namedChildren) if (c) walk(c, env);
        const child = node.namedChildren[0];
        const values = child?.type === "expression_list" ? child.namedChildren : child ? [child] : [];
        if (inline === 0) for (const v of values) if (v) h.onReturn?.(v, env, taintMask);
        return true;
      }

      default:
        break;
    }

    if (node.type === "short_var_declaration" || node.type === "assignment_statement") {
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if (left && right) {
        const op = node.text.slice(left.endIndex - node.startIndex, right.startIndex - node.startIndex).trim();
        const targets = assignmentTargetsOfGo(left);
        rememberAliases(identifiersOf(left), right.namedChildren.filter((n): n is SyntaxNode => !!n));
        bind(targets.map(assignmentKeyOfGo), right.namedChildren.filter((n): n is SyntaxNode => !!n), env,
          op !== "=" && op !== ":=");
        // `m[k] = v`: the container now holds the value (additive: a write never de-taints)
        const rightList = right.namedChildren.filter((n): n is SyntaxNode => !!n);
        left.namedChildren.forEach((t, i) => {
          if (t?.type !== "index_expression") return;
          const root = rootIdentGo(t);
          const rv = rightList[i] ?? rightList[0];
          if (root && rv) env.set(root.text, (env.get(root.text) ?? 0) | taintMask(rv, env));
        });
      }
    }

    // `ch <- v`: the channel now carries the value
    if (node.type === "send_statement") {
      const root = rootIdentGo(node.childForFieldName("channel"));
      const val = node.childForFieldName("value");
      if (root && val) env.set(root.text, (env.get(root.text) ?? 0) | taintMask(val, env));
    }

    // `var q = "SELECT ... " + id`
    if (node.type === "var_spec") {
      const names = node.childrenForFieldName("name").filter((n): n is SyntaxNode => !!n);
      const value = node.childForFieldName("value");
      if (names.length > 0 && value) {
        rememberAliases(names, value.namedChildren.filter((n): n is SyntaxNode => !!n));
        bind(names.map(n => n.text), value.namedChildren.filter((n): n is SyntaxNode => !!n), env, false);
      }
    }

    if (node.type === "call_expression") {
      const fnNode = node.childForFieldName("function");
      const callArgs = argListOfGo(node);
      // An immediately-invoked / go / defer function literal runs in THIS scope: its writes flow out.
      if (fnNode?.type === "func_literal") {
        for (const a of callArgs) walk(a, env);
        const argMasks = callArgs.map(a => taintMask(a, env));
        const body = fnNode.childForFieldName("body");
        if (body) {
          const names = paramNamesOfGo(fnNode);
          const saved = names.map(n => env.get(n));
          names.forEach((n, i) => env.set(n, argMasks[i] ?? 0));
          inline++;
          walk(body, env);
          inline--;
          names.forEach((n, i) => { const sv = saved[i]; if (sv === undefined) env.delete(n); else env.set(n, sv); });
        }
        h.onNode?.(node, env, taintMask);
        return false;
      }
      h.onCall?.(node, env, taintMask);
      // `dec.Decode(&v)` / `json.Unmarshal(data, &v)` / `c.ShouldBindJSON(&v)`: the out-parameter now holds the input
      const out = findOutParamGo(node, env, taintMask);
      if (out) env.set(out.root, (env.get(out.root) ?? 0) | out.mask);
      // `b.WriteString(x)` / `fmt.Fprint(&b, x)`: the receiver / buffer now holds the arguments
      if (fnNode?.type === "selector_expression" && GO_MUTATORS.has(fnNode.childForFieldName("field")?.text ?? "")) {
        const root = rootIdentGo(fnNode.childForFieldName("operand"));
        if (root && !goCtx.writerVars.has(root.text)) env.set(root.text, (env.get(root.text) ?? 0) | callArgs.reduce((m, a) => m | taintMask(a, env), 0));
      }
      if (fnNode && /^fmt\.Fprint(?:f|ln)?$/.test(calleeTextGo(fnNode) ?? "") && callArgs[0]) {
        const root = rootIdentGo(callArgs[0]);
        if (root && !goCtx.writerVars.has(root.text)) env.set(root.text, (env.get(root.text) ?? 0) | callArgs.slice(1).reduce((m, a) => m | taintMask(a, env), 0));
      }
    }
    h.onNode?.(node, env, taintMask);

    for (const c of node.namedChildren) if (c) walk(c, env);
    return false;
  };

  return { walk, taintMask };
}

/**
 * Walks the whole tree once: tracks taint through env, seeds tainted
 * parameters into same-file callees on tainted call sites (one hop, mirrors
 * Phase 1/2/3), and matches sink call expressions against a tainted
 * argument (or, for insecure-deserialization, a tainted receiver).
 */
export function scanAstTaintGo(
  content: string, filePath: string, presparsed?: SyntaxNode | null,
  idorAuthCheckNearby?: (line: number) => boolean,
  // Sinks whose argument was tainted for the sink's class but positively
  // cleared by a sanitizer (see astTaint.ts) -- lets scanner.ts drop the
  // regex layer's duplicate for a flow this engine proved safe.
  suppressedOut?: SuppressedSink[],
): AstTaintGoFinding[] {
  try {
    const root = presparsed ?? parseGoSourceSync(content, filePath);
    if (!root) return [];

    // Per-scan facts: request/writer variables, escapers, plugin/gob variables, structs with role-like fields.
    goCtx = emptyGoCtx();
    const requestVars: string[] = [];
    const findDecls = (n: SyntaxNode) => {
      if (n.type === "parameter_declaration") {
        const type = n.childForFieldName("type")?.text ?? "";
        const names = n.childrenForFieldName("name").filter((x): x is SyntaxNode => !!x).map(x => x.text);
        if (/http\.Request$/.test(type)) requestVars.push(...names);
        if (/http\.ResponseWriter$/.test(type)) for (const nm of names) goCtx.writerVars.add(nm);
      } else if (n.type === "short_var_declaration") {
        const rhs = n.childForFieldName("right")?.text ?? "";
        const ids = identifiersOf(n.childForFieldName("left") ?? n);
        if (/^plugin\.Open\(/.test(rhs) && ids[0]) goCtx.pluginVars.add(ids[0].text);
        if (/gob\.NewDecoder\(/.test(rhs) && ids[0]) goCtx.gobVars.add(ids[0].text);
        const composite = /^&?([A-Za-z_]\w*)\{/.exec(rhs) ?? /^new\(([A-Za-z_]\w*)\)/.exec(rhs);
        if (composite && ids[0]) goCtx.varStructTypes.set(ids[0].text, composite[1]);
      } else if (n.type === "var_spec") {
        const nm = n.childrenForFieldName("name")[0];
        const t = n.childForFieldName("type");
        if (nm && t?.type === "type_identifier") goCtx.varStructTypes.set(nm.text, t.text);
      } else if (n.type === "type_spec") {
        const nm = n.childForFieldName("name")?.text;
        const st = n.childForFieldName("type");
        if (nm && st?.type === "struct_type") {
          for (const fd of findAllNodesGo(st, "field_declaration")) {
            const tag = fd.childForFieldName("tag")?.text ?? "";
            if (/json:"-"/.test(tag)) continue;
            for (const f of fd.childrenForFieldName("name")) if (f && SENSITIVE_FIELD_RE_GO.test(f.text)) goCtx.sensitiveStructs.add(nm);
          }
        }
      } else if (n.type === "function_declaration") {
        const name = n.childForFieldName("name")?.text;
        const body = n.childForFieldName("body");
        if (name && body) {
          const lits = new Set(findAllNodesGo(body, "interpreted_string_literal").map(l => l.text));
          if (lits.has('"<"') && (lits.has('"&lt;"') || lits.has('"&#60;"') || lits.has('"&#x3C;"'))) goCtx.htmlEscapers.add(name);
        }
      }
      for (const c of n.namedChildren) if (c) findDecls(c);
    };
    findDecls(root);
    setGoRequestVars(requestVars);

    const localFns = collectLocalFunctionsGo(root);
    const propagating = buildPropagatingMapGo(localFns, root);

    // Package-level container memory: taint appended/stored into a package-level slice/map by one handler is
    // visible to every handler that reads it back (stored XSS, second-order SQL).
    const sticky = new Map<string, number>();
    let stickyDirty = false;
    const modulePkgNames = new Set<string>();
    for (const st of root.namedChildren) {
      if (st?.type !== "var_declaration") continue;
      for (const vs of findAllNodesGo(st, "var_spec")) for (const nm of vs.childrenForFieldName("name")) if (nm) modulePkgNames.add(nm.text);
    }

    const findings: AstTaintGoFinding[] = [];
    const seen = new Set<string>();
    const lineOf = (node: SyntaxNode): number => node.startPosition.row + 1;

    // Source -> sink trace (see taintCore.ts's buildBackwardTraceGeneric docblock). No cross-file
    // support here (Go's is explicitly out of scope -- see crossFile.ts's own docblock), so this
    // resolver has no crossFileHop and the slice always stays inside this one file.
    const traceResolver: TraceResolver<SyntaxNode> = {
      enclosingScope: findEnclosingFunctionNodeGo,
      position: n => n.startIndex,
      line: lineOf,
      text: n => n.text,
      assignmentsIn: (scope) => {
        const out: Array<{ name: string; position: number; rhsText: string; line: number }> = [];
        const visit = (n: SyntaxNode) => {
          if (n !== scope && GO_FUNCTION_NODES.has(n.type)) return; // a nested closure's own assignments aren't this scope's
          if (n.type === "short_var_declaration" || n.type === "assignment_statement") {
            // `left`/`right` are expression_list nodes (even for a single target -- confirmed via
            // assignmentTargetsOfGo's own identical unwrap elsewhere in this file); only the
            // single-target `x := expr` / `x = expr` shape is worth resolving here (a multi-value
            // `a, b := f()` has no one RHS expression per name to point at).
            const left = n.childForFieldName("left");
            const right = n.childForFieldName("right");
            const lTarget = left?.namedChildren.length === 1 ? left.namedChildren[0] : null;
            const rExpr = right?.namedChildren.length === 1 ? right.namedChildren[0] : null;
            if (lTarget?.type === "identifier" && rExpr) out.push({ name: lTarget.text, position: n.startIndex, rhsText: rExpr.text, line: lineOf(rExpr) });
          }
          for (const c of n.namedChildren) if (c) visit(c);
        };
        visit(scope);
        return out;
      },
    };

    const emit = (id: AstTaintGoId, node: SyntaxNode, sourceExpr: string, sinkExpr: string, detailOverride?: string) => {
      const line = lineOf(node);
      const key = `${id}:${line}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({
        id, line, sinkExpr, sourceExpr,
        detail: detailOverride ?? `Tainted expression '${sourceExpr}' flows into ${sinkExpr}(...) — real data-flow match, not a line-pattern guess`,
        trace: buildBackwardTraceGeneric(filePath, node, sourceExpr, sinkExpr, traceResolver),
      });
    };

    // fn name -> (tainted param index -> classes tainted at the call site)
    const seededParams = new Map<string, Map<number, number>>();

    // First argument tainted for `id`'s class, if any. When none is but one
    // was tainted-then-positively-cleared, records a suppression instead
    // (for the regex-layer veto).
    const sinkHit = (
      node: SyntaxNode, args: readonly SyntaxNode[], id: AstTaintGoId | "idor",
      env: Env, taintMask: TaintMaskFnGo,
    ): SyntaxNode | undefined => {
      const cls = classOf(id);
      let cleared = false;
      for (const a of args) {
        const m = taintMask(a, env);
        if (m & cls) return a;
        if (wasCleared(m, cls)) cleared = true;
      }
      if (cleared) suppressedOut?.push({ id, line: lineOf(node) });
      return undefined;
    };

    // Sink checks and same-file call-site seeding for one call_expression, with
    // the env at that point. Statement structure, branching, assignments and
    // nested functions are the shared walker's job (createWalkerGo).
    const onCall = (node: SyntaxNode, env: Env, taintMask: TaintMaskFnGo) => {
      const fn = node.childForFieldName("function");
      const args = argListOfGo(node);

      const match = matchSinkGo(node);
      if (match) {
        const taintedArg = sinkHit(node, match.args, match.id, env, taintMask);
        if (taintedArg) emit(match.id, node, sourceLabelGo(taintedArg), match.sinkExpr);
      }

      const sqlMatch = matchSqlInjectionGo(node);
      if (sqlMatch) {
        const hit = sinkHit(node, [sqlMatch.args[0]], "sql-injection", env, taintMask);
        if (hit) emit("sql-injection", node, sourceLabelGo(sqlMatch.args[0]), sqlMatch.sinkExpr);
      }

      // IDOR asks "is this id attacker-CONTROLLED", not "is it injectable":
      // classOf("idor") is the CONTROL bit, which numeric coercion
      // (strconv.Atoi(c.Param("id"))) deliberately does not clear.
      const idorMatch = matchIdorGo(node);
      if (idorMatch && sinkHit(node, [idorMatch.args[0]], "idor", env, taintMask)) {
        const suppressed = (idorAuthCheckNearby?.(lineOf(node)) ?? false) ||
          structuralOwnershipCheckSuppressesGo(node, idorMatch.args[0]);
        if (!suppressed) emit("idor", node, sourceLabelGo(idorMatch.args[0]), idorMatch.sinkExpr);
      }

      const fnTextAll = fn ? calleeTextGo(fn) : null;
      // weak digests / ciphers (not taint-based)
      if (fnTextAll && /^(?:md5\.(?:Sum|New)|sha1\.(?:Sum|New)|des\.NewCipher|des\.NewTripleDESCipher|rc4\.NewCipher)$/.test(fnTextAll)) {
        emit("weak-crypto", node, fnTextAll, fnTextAll,
          `${fnTextAll} is a broken/weak primitive — use SHA-256+ (and bcrypt/argon2 for passwords) or AES-GCM`);
      }
      // decoding a request into a struct that has role/admin-like fields: the client chooses them
      const outParam = findOutParamGo(node, env, taintMask);
      if (outParam) {
        const typeName = goCtx.varStructTypes.get(outParam.root);
        if (typeName && goCtx.sensitiveStructs.has(typeName)) {
          emit("mass-assignment", node, outParam.root, fnTextAll ?? "Decode",
            `Request data is decoded straight into '${outParam.root}' (${typeName}), which has role/admin-like fields — the client can set them; decode into a DTO with only the allowed fields`);
        }
      }
      // fmt.Sprintf("SELECT ... '%s'", x) and friends: string shapes built around untrusted operands
      const isFprintf = fnTextAll === "fmt.Fprintf";
      if (fnTextAll && (isFormatCall(fnTextAll) || isFprintf)) {
        const base = isFprintf ? 1 : 0; // Fprintf(w, format, args...)
        const fmtArg = args[base];
        const lit = fmtArg ? goStringLiteralValue(fmtArg) : null;
        if (lit !== null) {
          const segs = lit.split(/%[-+# 0-9.*]*[a-zA-Z]/);
          const parts: Array<{ lit?: string; expr?: SyntaxNode }> = [];
          segs.forEach((seg, i) => {
            parts.push({ lit: seg });
            if (i < segs.length - 1) parts.push(args[base + 1 + i] ? { expr: args[base + 1 + i] } : { lit: "" });
          });
          checkShapes(node, parts, env, taintMask);
        }
      }

      // dec.Decode(...) -- receiver-tainted, not arg-tainted: fires if
      // `dec` itself is tainted (built from gob.NewDecoder(r.Body) or
      // similar via the propagation rule right below), args are irrelevant.
      if (fn?.type === "selector_expression" && fn.childForFieldName("field")?.text === "Decode") {
        const operand = fn.childForFieldName("operand");
        if (operand && (/gob\.NewDecoder\(/.test(operand.text) || goCtx.gobVars.has(operand.text)) &&
            sinkHit(node, [operand], "insecure-deserialization", env, taintMask)) {
          emit("insecure-deserialization", node, sourceLabelGo(operand), calleeTextGo(fn) ?? "Decode");
        }
      }

      // gob.NewDecoder(EXPR) -- taints the assignment target if EXPR ends
      // in .Body/.Conn (an untrusted stream). The enclosing
      // short_var_declaration/assignment_statement's OWN top-level handling
      // (above, in this same walk call) already ran and set this target
      // to `false` via isTainted(gob.NewDecoder(...), env) -- which can
      // never recognize this call as tainted, since gob.NewDecoder isn't a
      // recognized source/format-call/local-propagating-fn/tainted-receiver
      // shape. This deeper, later visit (recursing into the RHS) corrects
      // that to `true` once we're structurally certain the source stream
      // is untrusted -- runs after and intentionally overwrites the
      // outer pass's `false`, not a race.
      if (fn) {
        const fnText = calleeTextGo(fn);
        if (fnText === "gob.NewDecoder" && args[0]) {
          const argText = calleeTextGo(args[0]) ?? "";
          if (argText.endsWith(".Body") || argText.endsWith(".Conn")) {
            const parent = node.parent?.type === "expression_list" ? node.parent.parent : node.parent;
            if (parent && (parent.type === "short_var_declaration" || parent.type === "assignment_statement")) {
              const left = parent.childForFieldName("left");
              const ids = left ? identifiersOf(left) : [];
              if (ids[0]) env.set(ids[0].text, ALL);
            }
          }
        }
        // http.NewRequest(method, url, body) / NewRequestWithContext(ctx,
        // method, url, body) -- same "correct the outer pass's false"
        // pattern as gob.NewDecoder above: taints the assignment target
        // if the URL argument is tainted, so the later client.Do(req)
        // sink (via matchSinkGo's passthrough-on-tainted-receiver, since
        // .Do's own function selector's operand `client` isn't itself
        // tainted -- `req`, its ARGUMENT, is) resolves correctly. client.Do
        // is matched generically below via the same receiver-tainted
        // shape as Decode, since neither is arg-tainted in the usual sense.
        if ((fnText === "http.NewRequest" || fnText === "http.NewRequestWithContext") && args.length > 0) {
          const urlArg = fnText === "http.NewRequestWithContext" ? args[2] : args[1];
          const urlMask = urlArg ? taintMask(urlArg, env) : 0;
          if (urlArg && (urlMask & ALL)) {
            const parent = node.parent?.type === "expression_list" ? node.parent.parent : node.parent;
            if (parent && (parent.type === "short_var_declaration" || parent.type === "assignment_statement")) {
              const left = parent.childForFieldName("left");
              const ids = left ? identifiersOf(left) : [];
              if (ids[0]) env.set(ids[0].text, urlMask);
            }
          }
        }
      }

      // client.Do(req) -- ssrf sink where the DANGER is the receiver's
      // (`client`'s) call target, but the actual taint lives on the
      // ARGUMENT (`req`), not the receiver itself -- the inverse shape
      // from Decode's receiver-tainted check above.
      if (fn?.type === "selector_expression" && fn.childForFieldName("field")?.text === "Do" && args[0]) {
        if (sinkHit(node, [args[0]], "ssrf", env, taintMask)) emit("ssrf", node, sourceLabelGo(args[0]), calleeTextGo(fn) ?? "Do");
      }

      // Same-file interprocedural seeding (one hop) -- mirrors
      // astTaint.ts/astTaintPython.ts exactly.
      const seedField = fn?.type === "selector_expression" ? fn.childForFieldName("field")?.text ?? null : null;
      const seedName = fn?.type === "identifier" ? fn.text : seedField && !GO_BUILTIN_METHOD_NAMES.has(seedField) ? seedField : null;
      if (seedName && localFns.has(seedName)) {
        const fnName = seedName;
        const localFn = localFns.get(fnName)!;
        const taintedIdx = new Map<number, number>();
        args.forEach((arg, i) => {
          const m = taintMask(arg, env) & ALL;
          if (!m) return;
          if (localFn.paramShapes.some(s => s.index === i)) taintedIdx.set(i, (taintedIdx.get(i) ?? 0) | m);
        });
        if (taintedIdx.size > 0) {
          const existing = seededParams.get(fnName) ?? new Map<number, number>();
          for (const [i, m] of taintedIdx) existing.set(i, (existing.get(i) ?? 0) | m);
          seededParams.set(fnName, existing);
        }
      }
    };

    /** A string built around an untrusted operand: SQL / LDAP / XPath text, or an escaped value inside <script>. */
    const checkShapes = (
      node: SyntaxNode, parts: Array<{ lit?: string; expr?: SyntaxNode }>, env: Env, mask: TaintMaskFnGo,
    ) => {
      let prefix = "";
      for (const p of parts) {
        if (p.lit !== undefined) { prefix += p.lit; continue; }
        const m = mask(p.expr!, env);
        const src = sourceLabelGo(p.expr!);
        if ((m & classOf("sql-injection")) && SQL_START_RE_GO.test(prefix)) {
          emit("sql-injection", node, src, "SQL string construction",
            `Untrusted '${src}' is concatenated into a SQL statement — use bind parameters (db.Query(query, args...))`);
        }
        if ((m & classOf("ldap-injection")) && LDAP_SHAPE_RE_GO.test(prefix)) {
          emit("ldap-injection", node, src, "LDAP filter construction",
            `Untrusted '${src}' is concatenated into an LDAP filter — escape it with ldap.EscapeFilter`);
        }
        if ((m & classOf("xpath-injection")) && XPATH_SHAPE_RE_GO.test(prefix)) {
          emit("xpath-injection", node, src, "XPath expression construction",
            `Untrusted '${src}' is concatenated into an XPath expression — use parameterized XPath`);
        }
        if (wasCleared(m, classOf("xss")) && SCRIPT_CONTEXT_RE_GO.test(prefix)) {
          emit("xss", node, src, "HTML string",
            `HTML-escaped value '${src}' is placed inside a <script> block — HTML escaping does not neutralize JavaScript string context`);
        }
        if (wasCleared(m, classOf("xss")) && UNQUOTED_ATTR_CONTEXT_RE_GO.test(prefix)) {
          emit("xss", node, src, "HTML string",
            `HTML-escaped value '${src}' is interpolated into an UNQUOTED HTML attribute — HTML escaping doesn't add the missing quotes, so a space still starts a new attribute (e.g. ' onmouseover=alert(1)')`);
        }
        prefix += "\u0000";
      }
    };

    const goNameOf = (n: SyntaxNode): string | null =>
      n.type === "identifier" ? n.text : n.type === "selector_expression" ? n.childForFieldName("field")?.text ?? null : null;

    const recordSticky = (n: SyntaxNode, env: Env, mask: TaintMaskFnGo) => {
      const pairs: Array<{ target: SyntaxNode; m: number }> = [];
      if (n.type === "assignment_statement") {
        const left = n.childForFieldName("left");
        const right = n.childForFieldName("right");
        const rightList = right?.namedChildren.filter((x): x is SyntaxNode => !!x) ?? [];
        left?.namedChildren.forEach((t, i) => {
          const root = t ? rootIdentGo(t) : null;
          const rv = rightList[i] ?? rightList[0];
          if (root && rv) pairs.push({ target: root, m: mask(rv, env) });
        });
      } else if (n.type === "send_statement") {
        const root = rootIdentGo(n.childForFieldName("channel"));
        const val = n.childForFieldName("value");
        if (root && val) pairs.push({ target: root, m: mask(val, env) });
      } else if (n.type === "call_expression") {
        const f = n.childForFieldName("function");
        if (f?.type === "selector_expression" && GO_MUTATORS.has(f.childForFieldName("field")?.text ?? "")) {
          const root = rootIdentGo(f.childForFieldName("operand"));
          if (root) pairs.push({ target: root, m: argListOfGo(n).reduce((acc, a) => acc | mask(a, env), 0) });
        }
      }
      for (const { target, m } of pairs) {
        if (!(m & ALL) || !modulePkgNames.has(target.text) || isLocalNameGo(target) || !enclosingFnGo(target)) continue;
        const next = (sticky.get(target.text) ?? 0) | (m & ALL);
        if (next !== (sticky.get(target.text) ?? 0)) { sticky.set(target.text, next); stickyDirty = true; }
      }
    };

    const onNode = (n: SyntaxNode, env: Env, mask: TaintMaskFnGo) => {
      if (n.type === "binary_expression") {
        const operands = concatOperandsGo(n);
        if (operands) {
          checkShapes(n, operands.map(o => { const lit = goStringLiteralValue(o); return lit !== null ? { lit } : { expr: o }; }), env, mask);
        }
        // secret == untrusted: a non-constant-time comparison is a timing oracle
        const op = n.childForFieldName("operator")?.type;
        const l = n.childForFieldName("left");
        const r = n.childForFieldName("right");
        if ((op === "==" || op === "!=") && l && r) {
          for (const [secretSide, other] of [[l, r], [r, l]] as const) {
            const name = goNameOf(secretSide);
            if (!name || !SECRET_NAME_RE_GO.test(name) || isLiteralGo(other)) continue;
            if (mask(other, env) & ALL) {
              emit("timing-attack", n, sourceLabelGo(other), "==",
                `Secret '${sourceLabelGo(secretSide)}' is compared to attacker-supplied '${sourceLabelGo(other)}' with == — use subtle.ConstantTimeCompare`);
              break;
            }
          }
        }
      }
      if (n.type === "assignment_statement") {
        const left = n.childForFieldName("left")?.namedChildren[0];
        const right = n.childForFieldName("right")?.namedChildren[0];
        const idx = left?.type === "index_expression" ? left.childForFieldName("index") : null;
        if (idx?.type === "identifier" && right?.type === "identifier") {
          for (let cur: SyntaxNode | null = n.parent; cur && cur.type !== "function_declaration" && cur.type !== "method_declaration" && cur.type !== "func_literal"; cur = cur.parent) {
            if (cur.type !== "for_statement") continue;
            const rc = cur.namedChildren.find(c => c?.type === "range_clause");
            const names = rc ? identifiersOf(rc.childForFieldName("left") ?? rc).map(x => x.text) : [];
            const iter = rc?.childForFieldName("right");
            if (rc && iter && names.includes(idx.text) && names.includes(right.text) && (mask(iter, env) & ALL)) {
              emit("mass-assignment", n, sourceLabelGo(iter), "map merge",
                `Every entry of the attacker-controlled map '${sourceLabelGo(iter)}' is copied onto the target — the client decides which keys (role, admin, ...) get set; copy an explicit allowlist`);
              break;
            }
          }
        }
      }
      if (n.type === "assignment_statement" || n.type === "send_statement" || n.type === "call_expression") recordSticky(n, env, mask);
    };

    const walker = createWalkerGo({ localFns, propagating, root, descendFunctions: true, onCall, onNode, sticky });

    walker.walk(root, new Map());
    // A container written by a handler declared AFTER the one that reads it: walk again with what the first
    // pass learned (findings dedupe by id+line).
    for (let i = 0; i < 2 && stickyDirty; i++) {
      stickyDirty = false;
      walker.walk(root, new Map());
    }

    // Second pass, bounded worklist (Decision 3): re-walk any local function
    // whose params were seeded tainted by a call site above, so sinks inside
    // the callee are reachable. Re-walking can itself seed FURTHER functions
    // (or grow an already-seeded function's own index set) via the same
    // seeding logic above, which is exactly how a second/third hop (A calls
    // B calls C) gets discovered -- explicitly capped at
    // MAX_PROPAGATION_ROUNDS instead of relying on live-Map-iteration order
    // for its multi-hop convergence, mirroring astTaint.ts's/
    // astTaintPython.ts's/astTaintJava.ts's own bounded worklists.
    // `walkedSignatures` skips re-walking a function with a seed set
    // identical to one already walked, while still allowing a re-walk once
    // that function's seed set has genuinely grown.
    const walkedSignatures = new Set<string>();
    for (let round = 0; round < MAX_PROPAGATION_ROUNDS; round++) {
      const toWalk = Array.from(seededParams.entries());
      let changed = false;
      for (const [fnName, idxSet] of toWalk) {
        const fn = localFns.get(fnName);
        if (!fn) continue;
        const signature = `${fnName}:${[...idxSet].sort((a, b) => a[0] - b[0]).map(([i, m]) => `${i}=${m}`).join(",")}`;
        if (walkedSignatures.has(signature)) continue;
        walkedSignatures.add(signature);
        changed = true;
        const env: Env = new Map();
        for (const [idx, m] of idxSet) {
          const shape = fn.paramShapes.find(s => s.index === idx);
          if (shape) env.set(shape.name, m);
        }
        walker.walk(fn.body, env);
      }
      if (!changed) break;
    }

    // A hand-rolled JWT payload decode in a file that never verifies a signature
    if (!/golang-jwt|dgrijalva\/jwt-go|go-jose|jwt\.Parse|jwt\.Verify|lestrrat/.test(content)) {
      for (const fnDecl of findAllNodesGo(root, "function_declaration")) {
        const t = fnDecl.text;
        if (/strings\.Split\([\s\S]*?"\."\s*\)/.test(t) && /base64\.\w+\.DecodeString/.test(t) && /json\.Unmarshal/.test(t)) {
          emit("jwt-none-alg", fnDecl.childForFieldName("name") ?? fnDecl, "token", "manual JWT decode",
            "JWT payload is base64-decoded and JSON-parsed by hand and the file never verifies a signature — claims (role, sub, ...) are attacker-controlled; verify with a JWT library");
        }
      }
    }

    return findings;
  } catch (err) {
    console.error(`[astTaintGo] threw scanning ${filePath}:`, err);
    return [];
  }
}

export function astTaintGoSeverity(id: AstTaintGoId): "critical" | "high" | "medium" {
  return SEVERITY[id];
}
export function astTaintGoLabel(id: AstTaintGoId): string {
  return LABEL[id];
}
