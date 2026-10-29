/**
 * Real AST-based taint engine for Rust (Actix Web, Axum, Rocket) -- the ninth engine, mirroring astTaintRuby.ts /
 * astTaintKotlin.ts: sources, sinks, propagation, interprocedural summaries, findings with source -> sink traces,
 * cross-file parameter -> sink facts, and an object-level authorization (BOLA) check on writes. Shared semantics
 * come from taint/taintCore.ts, taint/sanitizers.ts ("rs" table), taint/sinkShape.ts and taint/principal.ts.
 *
 * Parsing uses tree-sitter-wasms' tree-sitter-rust.wasm (field names available). Shapes confirmed by probing:
 *  - Method calls are call_expression{function: field_expression{value, field}, arguments}; turbofish wraps the
 *    callee in generic_function; path calls (`sqlx::query(x)`, `Command::new(x)`) have a scoped_identifier callee.
 *  - MACRO ARGUMENTS ARE NOT PARSED: `format!("..{}", x)` is macro_invocation{macro, token_tree} with raw tokens.
 *    Since nearly all Rust string building goes through format!, the arguments are re-parsed here as a call's
 *    argument list (macroArgs), plus Rust 2021's inline captures (`format!("{name}")`) -- see formatParts.
 *  - Extractor patterns destructure in the parameter list: `Path(id): Path<i64>`, `Json(body): Json<Req>`.
 *  - `let Some(x) = y else { return ... };` (let-else) carries an `alternative` block; match arm guards are a
 *    `condition` field inside match_pattern.
 *
 * Rust-specific modelling decisions:
 *  - Sources are request extractors by TYPE (Path/Query/Json/Form/RawQuery/HeaderMap/TypedHeader/Bytes/Multipart,
 *    actix `web::*`), the request object's accessors (`req.match_info()`, `req.headers()`, `req.uri()`), and
 *    Rocket's route-bound parameters (`#[get("/<name>")]`). A `String`/`Bytes` parameter is the request body only
 *    in a handler. Scalar extractors (`Path<i64>`, `Path<Uuid>`) carry only CONTROL: still the record a caller
 *    picked (BOLA), but not an injection payload.
 *  - `x.parse::<T>()` / `x as i64` / `let n: u32 = ...` coerce; `.file_name()` keeps only the last path segment;
 *    `.canonicalize()` followed by `starts_with(base)` is a path guard.
 *  - Command: Rust's `Command` never runs a shell itself, so a tainted PROGRAM, or an argument after an explicit
 *    `sh -c`, is command injection; any other tainted argument is argument injection (not after `--`).
 *  - The `regex` crate is linear-time, so a request-built pattern is only reported for `fancy_regex` (backtracking).
 *  - http's HeaderValue rejects CR/LF, so header injection is not modelled.
 *
 * Runs ADDITIVELY next to the regex detectors in scanner.ts (the fallback when the grammar is unavailable); a flow
 * this engine proves safe vetoes their duplicate via SuppressedSink.
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { Parser, Language } = require("web-tree-sitter") as typeof import("web-tree-sitter");
import type { Node as SyntaxNode, Language as LanguageT, Parser as ParserT, Tree } from "web-tree-sitter";
import { ensureTreeSitterInit, rootIfShallowEnough, treeTooDeep } from "./treeSitterRuntime";
import {
  ALL, FIXED_POINT_CAP, INJECTION, SinkClass, applyClears, applySanitizer, applyGuards, applyGuardSet, buildBackwardTraceGeneric, classOf, cloneEnv,
  crossFileTrace, displayFnName, dropOnPathDuplicates, factStepsFromTrace, mergeSinkFacts, walkIfChain, walkLoop, walkSwitch,
  wasCleared, type Branch, type Guard, type ParamSinkFact, type SuppressedSink, type TaintEnv, type TraceResolver, type TraceStep,
} from "./taint/taintCore";
import { sanitizerClears, NUMERIC_CLEARS } from "./taint/sanitizers";
import { anchoredPatternClears } from "./taint/charClass";
import { assessSqlInjection, assessSsrfUrl, type UrlPart } from "./taint/sinkShape";
import { authzVerdict, classifyGuardName, isOwnerField, type AuthzKind } from "./taint/principal";

declare const __non_webpack_require__: NodeJS.Require | undefined;
function nodeRequire(): NodeJS.Require {
  // eslint-disable-next-line no-undef
  return typeof __non_webpack_require__ !== "undefined" ? __non_webpack_require__ : require;
}

export type AstTaintRustId =
  | "sql-injection" | "command-injection" | "argument-injection" | "path-traversal" | "ssrf" | "open-redirect" | "xss"
  | "ssti" | "eval-exec" | "redos" | "nosql-injection" | "ldap-injection" | "timing-attack" | "jwt-none-alg" | "weak-crypto"
  | "bola-missing-ownership-check" | "mass-assignment" | "insecure-deserialization" | "xpath-injection" | "header-injection";

export interface AstTaintRustFinding {
  id:         AstTaintRustId;
  line:       number;
  detail:     string;
  sourceExpr: string;
  sinkExpr:   string;
  entryPointSeeded?: boolean;
  severityOverride?: "critical" | "high" | "medium";
  trace?: TraceStep[];
  calleeSink?: { file: string; line: number; sinkExpr: string; via: string[] };
}

const SEVERITY: Record<AstTaintRustId, "critical" | "high" | "medium"> = {
  "sql-injection": "critical", "command-injection": "critical", "argument-injection": "high", "path-traversal": "critical",
  "ssrf": "critical", "open-redirect": "medium", "xss": "high", "ssti": "critical", "eval-exec": "critical", "redos": "high",
  "nosql-injection": "critical", "ldap-injection": "critical", "timing-attack": "medium", "jwt-none-alg": "critical",
  "weak-crypto": "high", "bola-missing-ownership-check": "high",
  // No gadget-chain RCE in Rust's serde: attacker-sized allocations / panics (DoS), so high rather than critical.
  "mass-assignment": "high", "insecure-deserialization": "high", "xpath-injection": "critical", "header-injection": "high",
};
const LABEL: Record<AstTaintRustId, string> = {
  "sql-injection": "SQL Injection", "command-injection": "Command Injection", "argument-injection": "Argument Injection",
  "path-traversal": "Path Traversal", "ssrf": "Server-Side Request Forgery", "open-redirect": "Open Redirect",
  "xss": "Cross-Site Scripting (XSS)", "ssti": "Server-Side Template Injection", "eval-exec": "Arbitrary Code Execution",
  "redos": "ReDoS — Regex DoS", "nosql-injection": "NoSQL Injection", "ldap-injection": "LDAP Injection",
  "timing-attack": "Timing Attack", "jwt-none-alg": "JWT Signature Not Verified", "weak-crypto": "Weak Cryptography",
  "bola-missing-ownership-check": "Broken Object Level Authorization (AST-verified)",
  "mass-assignment": "Mass Assignment", "insecure-deserialization": "Insecure Deserialization",
  "xpath-injection": "XPath Injection", "header-injection": "HTTP Header Injection",
};
export function astTaintRustSeverity(id: AstTaintRustId): "critical" | "high" | "medium" { return SEVERITY[id]; }
export function astTaintRustLabel(id: AstTaintRustId): string { return LABEL[id]; }

// ── Parser lifecycle (warm-cache pattern, see astTaintCSharp.ts) ───────────────────────────────────────────

let langPromise: Promise<LanguageT> | null = null;
let parserPool: ParserT | null = null;

function initRustParser(): Promise<LanguageT> {
  if (!langPromise) {
    langPromise = (async () => {
      await ensureTreeSitterInit();
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const fs = require("fs") as typeof import("fs");
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const path = require("path") as typeof import("path");
      const webTreeSitterEntry = nodeRequire().resolve("web-tree-sitter");
      const nodeModulesDir = path.dirname(path.dirname(webTreeSitterEntry));
      const wasmPath = path.join(nodeModulesDir, "tree-sitter-wasms", "out", "tree-sitter-rust.wasm");
      const lang = await Language.load(new Uint8Array(fs.readFileSync(wasmPath)));
      const p = new Parser();
      p.setLanguage(lang);
      parserPool = p;
      console.log("[astTaintRust] Rust AST taint engine ready");
      return lang;
    })().catch(err => {
      console.error("[astTaintRust] WASM init failed -- Rust AST taint scanning disabled, regex detectors unaffected:", err);
      throw err;
    });
  }
  return langPromise;
}
if (!process.env.JEST_WORKER_ID) {
  void initRustParser().catch(() => { /* already logged above */ });
}

export function isRustParserReady(): boolean {
  return parserPool !== null;
}

export async function warmRustTaintEngine(): Promise<void> {
  await initRustParser().catch(() => { /* already logged; callers just proceed regex-only */ });
}

export function parseRustSourceSync(content: string, filePath: string): SyntaxNode | null {
  if (!parserPool) return null;
  try {
    return rootIfShallowEnough(parserPool.parse(content)?.rootNode, "astTaintRust", filePath);
  } catch (err) {
    console.error(`[astTaintRust] parse threw for ${filePath}:`, err);
    return null;
  }
}

// ── Enclosing-function lookup (reachability.ts / scanner.ts) ────────────────────────────────────────────────

export function findNodeAtRowRust(root: SyntaxNode, row: number): SyntaxNode {
  let node = root;
  for (;;) {
    const child = node.namedChildren.find(c => c && row >= c.startPosition.row && row <= c.endPosition.row);
    if (!child) return node;
    node = child;
  }
}

export function findEnclosingFunctionNameRust(node: SyntaxNode): string {
  for (let cur: SyntaxNode | null = node; cur; cur = cur.parent) {
    if (cur.type === "function_item") {
      const nameNode = cur.childForFieldName("name");
      if (nameNode) return nameNode.text;
    }
  }
  return "unknown";
}

// ── Tree helpers ───────────────────────────────────────────────────────────────────────────────────────────

/** Re-parsed macro argument trees -> the source row their text starts on (see macroArgs). */
const reparsedRowBase = new WeakMap<object, number>();
const lineOf = (n: SyntaxNode) => n.startPosition.row + 1 + (reparsedRowBase.get(n.tree) ?? 0);
const named = (n: SyntaxNode | null | undefined): SyntaxNode[] => (n ? n.namedChildren.filter((c): c is SyntaxNode => !!c) : []);
const field = (n: SyntaxNode | null | undefined, f: string): SyntaxNode | null => n?.childForFieldName(f) ?? null;

function findAllNodes(root: SyntaxNode, type: string | ReadonlySet<string>, acc: SyntaxNode[] = []): SyntaxNode[] {
  if (typeof type === "string" ? root.type === type : type.has(root.type)) acc.push(root);
  for (const c of root.namedChildren) if (c) findAllNodes(c, type, acc);
  return acc;
}
function operatorOf(n: SyntaxNode): string {
  return n.childForFieldName("operator")?.type ?? (() => {
    for (let i = 0; i < n.childCount; i++) { const c = n.child(i); if (c && !c.isNamed) return c.type; }
    return "";
  })();
}

/** `a::b::c` / `x` / `self` -> path text; null for anything else. */
function pathText(n: SyntaxNode | null): string | null {
  if (!n) return null;
  switch (n.type) {
    case "identifier": case "self": case "crate": case "super": case "type_identifier": case "metavariable": return n.text;
    case "scoped_identifier": case "scoped_type_identifier": {
      const p = pathText(field(n, "path"));
      const nm = field(n, "name")?.text;
      return nm ? (p ? `${p}::${nm}` : nm) : null;
    }
    case "generic_function": return pathText(field(n, "function"));
    default: return null;
  }
}

interface CallParts { name: string; recv: SyntaxNode | null; path: string | null; fnNode: SyntaxNode | null }
/** A call's method name and receiver (`x.m()`), or its path (`a::b::f()` / `f()`). */
function callParts(call: SyntaxNode): CallParts {
  let fn = field(call, "function");
  if (fn?.type === "generic_function") fn = field(fn, "function");
  if (fn?.type === "field_expression") return { name: field(fn, "field")?.text ?? "", recv: field(fn, "value"), path: null, fnNode: fn };
  const path = pathText(fn);
  return { name: path ? path.split("::").pop()! : "", recv: null, path, fnNode: fn };
}
const argNodes = (call: SyntaxNode): SyntaxNode[] => named(field(call, "arguments")).filter(n => !/comment$/.test(n.type));

/** `a.b.c()` chains flattened to text (`req.headers.get`), for receiver tests. */
function chainText(n: SyntaxNode | null): string {
  if (!n) return "";
  switch (n.type) {
    case "call_expression": {
      const { name, recv, path } = callParts(n);
      return recv ? `${chainText(recv)}.${name}` : path ?? "";
    }
    case "field_expression": return `${chainText(field(n, "value"))}.${field(n, "field")?.text ?? ""}`;
    case "reference_expression": case "try_expression": case "await_expression": case "parenthesized_expression":
      return chainText(field(n, "value") ?? named(n)[0] ?? null);
    default: return pathText(n) ?? n.text.slice(0, 40);
  }
}

function stringValue(n: SyntaxNode | null | undefined): string | null {
  if (!n) return null;
  if (n.type === "string_literal") return n.text.slice(1, -1);
  if (n.type === "raw_string_literal") return n.text.replace(/^r#*"/, "").replace(/"#*$/, "");
  return null;
}
const LITERAL_TYPES = new Set([
  "string_literal", "raw_string_literal", "char_literal", "integer_literal", "float_literal", "boolean_literal", "unit_expression",
  "line_comment", "block_comment", "string_content", "escape_sequence",
]);
const isLiteral = (n: SyntaxNode): boolean => LITERAL_TYPES.has(n.type) || (n.type === "reference_expression" && !!named(n)[0] && isLiteral(named(n)[0]));

/** Peel `&T`, `&mut T`, `Option<T>`, `Arc<T>`, `Box<dyn T>`, `web::Data<T>`, `State<T>`, `impl T` -> T's last segment. */
function coreType(t: SyntaxNode | null): string {
  if (!t) return "";
  switch (t.type) {
    case "reference_type": case "pointer_type": return coreType(field(t, "type"));
    case "abstract_type": case "dynamic_type": return coreType(field(t, "trait") ?? named(t)[0] ?? null);
    case "generic_type": {
      const outer = (pathText(field(t, "type")) ?? "").split("::").pop() ?? "";
      if (/^(?:Arc|Rc|Box|Option|Data|State|Extension|Mutex|RwLock|Cow|Pin)$/.test(outer)) return coreType(named(field(t, "type_arguments"))[0] ?? null);
      return outer;
    }
    default: return (pathText(t) ?? t.text).split("::").pop() ?? "";
  }
}
/** The extractor wrapper's own name (`web::Query<T>` -> "Query", `Path<i64>` -> "Path"), or "". */
function outerType(t: SyntaxNode | null): string {
  if (!t) return "";
  if (t.type === "reference_type") return outerType(field(t, "type"));
  if (t.type === "generic_type") return (pathText(field(t, "type")) ?? "").split("::").pop() ?? "";
  return (pathText(t) ?? t.text).split("::").pop() ?? "";
}
const typeArg = (t: SyntaxNode | null): SyntaxNode | null => (t?.type === "generic_type" ? named(field(t, "type_arguments"))[0] ?? null : null);

// ── Sources ────────────────────────────────────────────────────────────────────────────────────────────────

/** Extractor types whose contents are what the client sent. */
const EXTRACTOR_TYPES = new Set([
  "Path", "Query", "Json", "Form", "RawQuery", "HeaderMap", "TypedHeader", "Bytes", "Multipart", "Payload", "RawForm",
  "OriginalUri", "Uri", "Host", "RawPathParams", "Cookies", "CookieJar", "MsgPack", "Protobuf", "Xml", "QsQuery", "WithRejection",
  "ValidatedJson", "ValidatedQuery", "LenientForm",
]);
/** Scalar payloads: attacker-chosen (CONTROL) but not an injection vector. */
const SCALAR_TYPE_RE = /^(?:i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize|f32|f64|bool|Uuid|NaiveDate|NaiveDateTime|DateTime|ObjectId)$/;
const REQUEST_TYPES = new Set(["HttpRequest", "Request", "ServiceRequest", "Parts", "RequestHead"]);
const REQUEST_INPUT_METHODS = new Set([
  "match_info", "query_string", "headers", "uri", "path", "cookie", "cookies", "connection_info", "head", "body", "into_body",
  "url", "query", "param", "params", "header", "get_header", "body_string", "body_json", "body_bytes", "query_pairs",
  // tonic (gRPC): the message is `request.into_inner()` / `get_ref()`; metadata is the client's headers.
  "into_inner", "get_ref", "get_mut", "metadata", "into_parts",
  // lambda_http's RequestExt
  "payload", "query_string_parameters", "path_parameters", "query_string_parameters_ref", "path_parameters_ref", "raw_http_path",
]);
const REQUEST_INPUT_HELPER_RE = /^(?:query|header|param|form|cookie|path_param)_(?:get|value|param|str|string|opt)$/;

/** The argument is (or is bound to) SQL text: `&query` where `let query = format!("SELECT ... {}", x)`. */
function sqlTextNearby(arg: SyntaxNode, at: SyntaxNode): boolean {
  const base = arg.type === "reference_expression" ? named(arg)[0] : arg;
  if (!base) return false;
  if (/\b(?:SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b/i.test(base.text)) return true;
  if (base.type !== "identifier") return false;
  let fn: SyntaxNode | null = at.parent;
  while (fn && fn.type !== "function_item" && fn.type !== "closure_expression") fn = fn.parent;
  return !!fn && new RegExp(`let\\s+(?:mut\\s+)?${base.text}\\b[^;]*?\\b(?:SELECT|INSERT\\s+INTO|UPDATE\\s+\\w+\\s+SET|DELETE\\s+FROM)\\b`, "is").test(fn.text);
}

/** warp filters whose output is what the client sent; a handler fed by them (`.and_then(handler)`) gets it as params. */
const WARP_INPUT_RE = /warp::(?:path::param|path::tail|path::full|query|body::json|body::form|body::bytes|body::stream|header|cookie|filters::query|multipart::form|ws)\b|warp::path!/;
/** Fields that let a client grant themselves something when a request body is saved as-is. */
const PRIVILEGED_FIELD_RE = /^(?:role|roles|is_admin|admin|is_superuser|superuser|is_staff|staff|permissions?|scopes?|privileges?|group|groups|owner_id|account_id|tenant_id|org_id|organization_id|balance|credits?|price|plan|tier|is_verified|verified|email_verified|approved|is_active|active|status|password_hash|hashed_password)$/;
const ROUTE_ATTRS = /^(?:get|post|put|delete|patch|head|options|route|routes|handler|debug_handler|connect|trace)$/;

// ── Propagation tables ─────────────────────────────────────────────────────────────────────────────────────

const RECEIVER_CLEARS: Record<string, number> = {
  len: NUMERIC_CLEARS, count: NUMERIC_CLEARS,
};
const OPAQUE_RESULT_METHODS = new Set([
  "len", "is_empty", "contains", "contains_key", "starts_with", "ends_with", "eq", "ne", "is_some", "is_none", "is_ok", "is_err",
  "cmp", "partial_cmp", "any", "all", "count", "is_match", "exists", "is_file", "is_dir", "hash", "matches", "position",
  "is_ascii", "is_char_boundary", "chars_count", "capacity", "find_iter_count", "is_alphanumeric",
]);
/** Methods whose ARGUMENTS also flow into the result. */
const ARG_FLOW_METHODS = new Set([
  "push_str", "push", "extend", "insert", "replace", "replacen", "unwrap_or", "or", "chain", "join", "with_file_name",
  "with_extension", "concat", "append", "add", "set_path", "set_query", "set_host", "query", "header", "body", "uri", "url",
  "path", "or_else", "unwrap_or_else", "map_or", "extend_from_slice", "zip", "and",
]);
const MUTATOR_METHODS = new Set(["push_str", "push", "extend", "insert", "append", "extend_from_slice", "write_str", "write_all", "push_front", "push_back", "set_path", "set_query", "set_host"]);
/** Path calls whose result carries their arguments. Uppercase-first single identifiers (Some, Ok, tuple structs) too. */
const PASSTHROUGH_PATHS = new Set([
  "String::from", "PathBuf::from", "Path::new", "OsString::from", "OsStr::new", "Url::parse", "Url::join", "Uri::from_str",
  "Uri::try_from", "Cow::from", "Box::new", "Arc::new", "Rc::new", "urlencoding::decode", "percent_decode_str",
  "percent_encoding::percent_decode_str", "base64::decode", "serde_json::from_str", "serde_json::from_slice",
  "serde_json::from_value", "serde_urlencoded::from_str", "serde_qs::from_str", "toml::from_str", "serde_yaml::from_str",
  "String::from_utf8", "String::from_utf8_lossy", "str::from_utf8", "std::str::from_utf8", "Vec::from", "Document::from",
  "bson::to_document", "Value::from", "STANDARD.decode", "general_purpose::STANDARD.decode",
]);
const DECODER_RE = /(?:urlencoding::decode|percent_decode_str|base64::decode|\.decode)$/;
/** Iterator / Option / Result adaptors: the closure parameter is the receiver's element(s). */
const ELEMENT_CLOSURES = new Set([
  "map", "and_then", "for_each", "filter_map", "flat_map", "inspect", "map_or", "map_or_else", "filter", "find", "take_while",
  "skip_while", "fold", "try_for_each", "try_fold", "any", "all", "position", "find_map", "map_err", "unwrap_or_else", "then",
  "or_else", "ok_or_else", "zip_with",
]);
const RECEIVER_RESULT_CLOSURES = new Set(["filter", "inspect", "take_while", "skip_while", "or_else", "unwrap_or_else"]);

// ── Sink vocabulary ────────────────────────────────────────────────────────────────────────────────────────

const SQLX_FNS = /(?:^|::)(?:query|query_as|query_scalar|query_with|query_as_with|query_scalar_with|raw_sql)$/;
const DIESEL_SQL_FNS = /(?:^|::)(?:sql_query|sql)$/;
const DB_METHODS = new Set([
  "execute", "execute_batch", "query", "query_one", "query_opt", "query_row", "query_map", "prepare", "prepare_cached",
  "batch_execute", "simple_query", "query_raw", "query_drop", "query_first", "query_iter", "exec", "exec_drop", "exec_first",
  "exec_iter", "execute_unprepared", "query_all", "query_one_raw",
]);
const DB_RECEIVER_RE = /^(?:conn|connection|db|database|client|pool|tx|txn|transaction|pg|mysql|sqlite|store|session)$|(?:conn|connection|db|pool|client|tx)$/i;
const DB_TYPE_RE = /^(?:Connection|Transaction|Client|Pool|PgPool|MySqlPool|SqlitePool|PgConnection|SqliteConnection|MySqlConnection|PooledConn|Conn|DatabaseConnection|DbConn|Object)$/;
const SHELL_PROGRAMS = /^(?:(?:\/usr)?\/bin\/)?(?:sh|bash|zsh|dash|ksh)$|^(?:cmd|cmd\.exe|powershell|powershell\.exe|pwsh)$/i;
/** Programs whose options only change how their own arguments are echoed back: an injected option is harmless. */
const OPTION_SAFE_PROGRAMS = /^(?:(?:\/usr)?\/bin\/)?(?:echo|basename|dirname|true|false)$/;
const SHELL_COMMAND_FLAGS = /^(?:-c|\/c|\/C|\/k|-command|-Command|-encodedcommand)$/;
const FS_FIRST_ARG = /(?:^|::)(?:File::open|File::create|File::create_new|fs::read|fs::read_to_string|fs::write|fs::remove_file|fs::remove_dir|fs::remove_dir_all|fs::create_dir|fs::create_dir_all|fs::read_dir|fs::metadata|fs::symlink_metadata|fs::set_permissions|fs::read_link|NamedFile::open|NamedFile::open_async|ServeFile::new|ServeDir::new|NamedFile::new|File::options)$/;
const FS_TWO_ARGS = /(?:^|::)fs::(?:copy|rename|hard_link|soft_link|symlink)$/;
const HTTP_FREE_FNS = /^(?:reqwest::get|reqwest::blocking::get|ureq::get|ureq::post|ureq::put|ureq::delete|ureq::request|surf::get|surf::post|isahc::get|isahc::post|attohttpc::get|attohttpc::post|minreq::get|minreq::post|TcpStream::connect|UdpSocket::connect|tokio::net::TcpStream::connect)$/;
const HTTP_CLIENT_METHODS = new Set(["get", "post", "put", "delete", "patch", "head", "request"]);
const HTTP_CLIENT_TYPE_RE = /^(?:Client|ClientWithMiddleware|Agent|HttpClient)$/;
const REDIRECT_FNS = /(?:^|::)Redirect::(?:to|temporary|permanent|see_other|found|moved)$/;
const SECRET_NAME_RE = /secret|token|password|passwd|api_?key|apikey|hmac|signature|digest/i;
const HTML_TAG_RE = /(?<![\w\]>])<\/?[a-z][a-z0-9-]*(?:\s[^<>]*)?\/?>/;
const NON_ENTRY_FN_RE = /^(?:main|new|default|fmt|from|into|clone|eq|hash|drop|deref|try_from|from_str|as_ref|borrow|build|run|call|next|poll|serialize|deserialize|visit_\w+|test_\w+)$/;
const NAME_ONLY_METHODS = new Set(["file_name", "file_stem", "extension"]);

// ── Engine context ─────────────────────────────────────────────────────────────────────────────────────────

type Env = TaintEnv;
interface ParamShape { name: string; index: number; type: SyntaxNode | null; names: string[]; pattern: SyntaxNode | null }
interface LocalFn {
  name: string;
  key: string | null;
  /** extra keys a cross-file caller may use (the implemented trait's `Trait.method`) */
  altKeys: string[];
  implType: string | null;
  hasSelf: boolean;
  params: ParamShape[];
  body: SyntaxNode | null;
  decl: SyntaxNode;
  attrs: SyntaxNode[];
  isPub: boolean;
}
type TaintMaskFn = (node: SyntaxNode, env: Env) => number;

interface CmdState { program: SyntaxNode | null; args: SyntaxNode[] }

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
  findings: AstTaintRustFinding[];
  seen: Set<string>;
  varTypes: Map<string, string>;
  /** `Struct.field` -> field's core type (same-file structs) */
  structFields: Map<string, string>;
  /** imported name -> its full path (`find` -> `crate::services::user::find`) */
  imports: Map<string, string>;
  /** Command builders held in variables */
  cmdVars: Map<string, CmdState>;
  crossFileFacts?: ReadonlyMap<string, readonly ParamSinkFact[]>;
  localKeys: Set<string>;
  refine?: (source: SyntaxNode, cls: number) => SyntaxNode;
  current: LocalFn | null;
  moduleName: string;
  /** Functions a warp filter chain hands its extracted values to (`.and_then(handler)`), by name. */
  warpHandlers: Set<string>;
  /** Request-body variable -> the struct it was deserialized into (mass assignment). */
  bodyTypes: Map<string, string>;
}

/** A warp handler's shared state, injected by the app rather than sent by the client. */
const WARP_STATE_NAME_RE = /^(?:state|app|pool|db|database|config|cfg|store|ctx|client|clients|sender|tx|repo|repository|service|svc|cache)$/;
const WARP_STATE_TYPE_RE = /(?:Db|Database|Pool|Store|Config|State|Client|Clients|Sender|Repo|Repository|Service|Cache|Context)$/;

/** Extractors that deserialize the whole request body into a struct. */
const BODY_EXTRACTORS = new Set(["Json", "Form", "ValidatedJson", "LenientForm", "MsgPack", "Protobuf", "Xml", "WithRejection"]);

/**
 * warp handlers: a named function passed to `.and_then(f)` / `.map(f)` / `.then(f)` of a filter chain that extracts
 * request data (WARP_INPUT_RE, in the chain itself or in the variable it was built in). Their parameters are those
 * extracted values, so they are sources -- warp has no extractor types or route attributes to recognise them by.
 */
function warpHandlersOf(root: SyntaxNode, content: string, fns: ReadonlyMap<string, LocalFn>): Set<string> {
  const out = new Set<string>();
  if (!/\bwarp::/.test(content)) return out;
  const filterVars = new Set<string>();
  for (const l of findAllNodes(root, "let_declaration")) {
    const p = field(l, "pattern"), v = field(l, "value");
    if (p?.type === "identifier" && v && WARP_INPUT_RE.test(v.text)) filterVars.add(p.text);
  }
  for (const c of findAllNodes(root, "call_expression")) {
    const { name, recv } = callParts(c);
    if (!recv || !/^(?:and_then|map|then)$/.test(name)) continue;
    const a = argNodes(c)[0];
    if (a?.type !== "identifier" || !fns.has(a.text)) continue;
    const chain = recv.text;
    if (WARP_INPUT_RE.test(chain) || [...filterVars].some(v => new RegExp(`\\b${v}\\b`).test(chain))) out.add(a.text);
  }
  return out;
}

function emit(
  ctx: EngineCtx, id: AstTaintRustId, node: SyntaxNode, sourceExpr: string, sinkExpr: string,
  detailOverride?: string, severityOverride?: "critical" | "high" | "medium",
) {
  const line = lineOf(node);
  const key = `${id}:${line}`;
  if (ctx.seen.has(key)) return;
  ctx.seen.add(key);
  ctx.findings.push({
    id, line, sinkExpr, sourceExpr, severityOverride,
    detail: detailOverride ?? `Tainted expression '${sourceExpr.slice(0, 80)}' flows into ${sinkExpr}(...) — real data-flow match, not a line-pattern guess`,
    trace: buildBackwardTraceGeneric(ctx.filePath, node, sourceExpr, sinkExpr, rustTraceResolver),
  });
}

// ── Macros ─────────────────────────────────────────────────────────────────────────────────────────────────

/** Re-parsed macro arguments, kept alive with their trees (a node is only valid while its tree is). Keyed by the
 * macro's position and text: the same source re-parsed yields new node objects for the same macro. */
const macroCacheById = new Map<string, { args: SyntaxNode[]; captures: Map<string, SyntaxNode>; tree: Tree | null }>();

const macroName = (m: SyntaxNode) => (pathText(field(m, "macro")) ?? "").split("::").pop() ?? "";
const FORMAT_MACROS = new Set(["format", "format_args", "write", "writeln", "print", "println", "eprint", "eprintln", "panic", "concat", "anyhow", "bail", "ensure", "error", "warn", "info", "debug", "trace", "assert", "assert_eq", "assert_ne", "todo", "unimplemented", "unreachable", "expect"]);

/**
 * A macro's arguments as expressions: the token tree re-parsed as a call's argument list, plus a synthetic argument
 * per inline format capture (`format!("{name}")` reads `name`). Falls back to the identifier tokens when the
 * arguments aren't expression-shaped (`json!({...})`, `vec![x; n]`).
 */
function macroArgs(m: SyntaxNode): { args: SyntaxNode[]; captures: Map<string, SyntaxNode> } {
  const key = `${m.startIndex}:${m.endIndex}:${m.text.length}:${m.tree.rootNode.startIndex}:${m.text.slice(0, 80)}`;
  const hit = macroCacheById.get(key);
  if (hit) return hit;
  const tt = named(m).find(c => c.type === "token_tree");
  const empty = { args: [] as SyntaxNode[], captures: new Map<string, SyntaxNode>(), tree: null };
  if (!tt || !parserPool) return empty;
  const inner = tt.text.slice(1, -1);
  const first = named(tt)[0];
  const fmt = FORMAT_MACROS.has(macroName(m)) ? stringValue(first ?? null) : null;
  const captured = fmt ? [...new Set([...fmt.matchAll(/\{([A-Za-z_]\w*)(?::[^}]*)?\}/g)].map(x => x[1]))] : [];
  const src = `fn __tl() { __tl(${inner}${captured.length ? `, ${captured.join(", ")}` : ""}); }`;
  let tree: Tree | null = null;
  try { tree = parserPool.parse(src); } catch { tree = null; }
  if (tree && treeTooDeep(tree.rootNode)) tree = null;
  const call = tree ? findAllNodes(tree.rootNode, "call_expression")[0] : null;
  if (!tree || !call || tree.rootNode.hasError) {
    // not expression-shaped: every identifier token is a value it may carry
    const ids = findAllNodes(tt, "identifier");
    const res = { args: ids, captures: new Map<string, SyntaxNode>(), tree: null };
    macroCacheById.set(key, res);
    return res;
  }
  const all = argNodes(call);
  reparsedRowBase.set(tree, tt.startPosition.row);
  const args = all.slice(0, all.length - captured.length);
  const captures = new Map(captured.map((nm, i) => [nm, all[args.length + i]]));
  const res = { args, captures, tree };
  macroCacheById.set(key, res);
  if (macroCacheById.size > 5000) macroCacheById.clear();
  return res;
}

/**
 * `format!("'{}'", s.replace('\'', "'\\''"))`: the POSIX single-quote idiom (close the quote, an escaped quote,
 * reopen) -- the result is one shell word whatever s holds.
 */
function isPosixShellQuote(m: SyntaxNode): boolean {
  const parts = formatParts(m);
  if (!parts || parts.length !== 3 || parts[0].kind !== "literal" || parts[2].kind !== "literal" || parts[1].kind !== "opaque") return false;
  if (parts[0].text !== "'" || parts[2].text !== "'") return false;
  const inner = unwrapExpr(parts[1].node);
  if (inner.type !== "call_expression") return false;
  const { name } = callParts(inner);
  const [from, to] = argNodes(inner);
  return name === "replace" && charOrStringValue(from ?? null) === "'" && stringValue(to ?? null) === String.raw`'\\''`;
}

/** format!-family: the format string's literal text and the value parts, in output order. */
function formatParts(m: SyntaxNode): UrlPart<SyntaxNode>[] | null {
  const { args, captures } = macroArgs(m);
  const fmt = stringValue(args[0] ?? null);
  if (fmt === null) return null;
  const rest = args.slice(1);
  const namedArgs = new Map<string, SyntaxNode>();
  const positional: SyntaxNode[] = [];
  for (const a of rest) {
    if (a.type === "assignment_expression" && field(a, "left")?.type === "identifier") namedArgs.set(field(a, "left")!.text, field(a, "right")!);
    else positional.push(a);
  }
  const parts: UrlPart<SyntaxNode>[] = [];
  let next = 0;
  const re = /\{\{|\}\}|\{([^{}]*)\}/g;
  let last = 0;
  for (let mm = re.exec(fmt); mm; mm = re.exec(fmt)) {
    if (mm.index > last) parts.push({ kind: "literal", text: fmt.slice(last, mm.index) });
    last = mm.index + mm[0].length;
    if (mm[0] === "{{" || mm[0] === "}}") { parts.push({ kind: "literal", text: mm[0][0] }); continue; }
    const spec = (mm[1] ?? "").split(":")[0];
    const arg = spec === "" ? positional[next++] : /^\d+$/.test(spec) ? positional[Number(spec)] : namedArgs.get(spec) ?? captures.get(spec);
    if (arg) parts.push({ kind: "opaque", node: arg });
  }
  if (last < fmt.length) parts.push({ kind: "literal", text: fmt.slice(last) });
  return parts;
}

// ── Taint mask ─────────────────────────────────────────────────────────────────────────────────────────────

const ZERO_TYPES = new Set([
  ...LITERAL_TYPES, "closure_expression", "function_item", "struct_item", "impl_item", "use_declaration", "self", "crate",
  "range_expression_literal", "type_identifier", "primitive_type", "attribute_item", "return_expression", "break_expression",
  "continue_expression", "macro_definition",
]);

function makeTaintMask(ctx: EngineCtx): TaintMaskFn {
  const mask = (node: SyntaxNode, env: Env): number => {
    if (ZERO_TYPES.has(node.type)) return 0;
    switch (node.type) {
      case "identifier": return (env.get(node.text) ?? 0) | keyedUnion(env, node.text);
      case "field_expression": {
        const v = field(node, "value");
        return v ? mask(v, env) : 0;
      }
      case "reference_expression": case "try_expression": case "await_expression": case "parenthesized_expression": {
        const v = field(node, "value") ?? named(node)[0];
        return v ? mask(v, env) : 0;
      }
      case "unary_expression": {
        if (operatorOf(node) === "!") return 0;
        const v = named(node)[0];
        return v ? mask(v, env) : 0;
      }
      case "type_cast_expression": {
        const t = field(node, "type");
        const v = field(node, "value");
        const m = v ? mask(v, env) : 0;
        return t && /^(?:primitive_type)$/.test(t.type) && t.text !== "str" ? applyClears(m, NUMERIC_CLEARS) : m;
      }
      case "binary_expression": {
        const op = operatorOf(node);
        if (/^(?:==|!=|<|>|<=|>=|&&|\|\|)$/.test(op)) return 0;
        return (mask(field(node, "left")!, env)) | (mask(field(node, "right")!, env));
      }
      case "index_expression": {
        const element = vecElementAt(node);
        if (element !== undefined) return element ? mask(element, env) : 0;
        const v = named(node)[0]; return v ? mask(v, env) : 0;
      }
      case "if_expression": {
        const cond = field(node, "condition");
        const cons = field(node, "consequence"), alt = field(node, "alternative");
        // `if 7 * 6 > 40 { a } else { b }`: only the arm a constant condition picks
        const cv = cond && cond.type !== "let_condition" ? constValueRs(cond) : NOT_CONST_RS;
        if (typeof cv === "boolean") return cv ? valueMask(cons, env) : alt ? valueMask(alt, env) : 0;
        const guards = cond ? guardsOf(cond, ctx) : [];
        return valueMask(cons, guarded(env, guards.filter(g => g.holds === "true")))
          | (alt ? valueMask(alt, guarded(env, guards.filter(g => g.holds === "false"))) : 0);
      }
      case "else_clause": return valueMask(named(node)[0] ?? null, env);
      case "match_expression": {
        const subject = field(node, "value");
        const sm = subject ? mask(subject, env) : 0;
        const subjectName = subject ? guardName(subject) : null;
        return named(field(node, "body")).filter(a => a.type === "match_arm").reduce((m, arm) => {
          const pat = field(arm, "pattern");
          const aenv = cloneEnv(env);
          bindPattern(pat, sm, aenv);
          if (subjectName && pat && patternIsLiteral(pat)) applyGuards(aenv, [subjectName]);
          return m | valueMask(field(arm, "value"), aenv);
        }, 0);
      }
      case "block": case "unsafe_block": case "async_block": case "loop_expression": return valueMask(node, env);
      case "struct_expression": return named(field(node, "body")).reduce((m, f) => m | (f.type === "shorthand_field_initializer" ? mask(named(f)[0]!, env) : field(f, "value") ? mask(field(f, "value")!, env) : f.type === "base_field_initializer" ? mask(named(f)[0]!, env) : 0), 0);
      case "macro_invocation": return macroMask(node, env);
      case "call_expression": return callMask(node, env);
      default: break;
    }
    return named(node).reduce((m, c) => m | mask(c, env), 0);
  };

  /** A block's value = its tail expression (no trailing semicolon). */
  const valueMask = (node: SyntaxNode | null, env: Env): number => {
    if (!node) return 0;
    if (node.type !== "block" && node.type !== "unsafe_block" && node.type !== "async_block") return mask(node, env);
    const kids = named(node).filter(k => !/comment$/.test(k.type));
    const last = kids[kids.length - 1];
    if (!last || last.type === "expression_statement" || last.type === "let_declaration" || last.type === "empty_statement") {
      // `loop { break x }` / tail-less block: nothing flows out
      return 0;
    }
    return mask(last, env);
  };

  const closureValue = (cl: SyntaxNode, paramMask: number, env: Env): number => {
    const cenv = cloneEnv(env);
    for (const p of closureParams(cl)) cenv.set(p, paramMask);
    return valueMask(field(cl, "body"), cenv);
  };

  const macroMask = (m: SyntaxNode, env: Env): number => {
    const name = macroName(m);
    if (/^(?:query|query_as|query_scalar|query_file|query_as_unchecked)$/.test(name) && /sqlx/.test(m.text.split("!")[0])) return 0;
    if (name === "matches" || name === "assert" || name === "debug_assert") return 0;
    const { args, captures } = macroArgs(m);
    const valueArgs = FORMAT_MACROS.has(name) && (name === "write" || name === "writeln") ? args.slice(1) : args;
    let out = valueArgs.reduce((acc, a) => acc | mask(a.type === "assignment_expression" ? field(a, "right")! : a, env), 0);
    for (const c of captures.values()) out |= mask(c, env);
    // doc! { "k": v } -- a string value can't become a query operator; a whole request document still can
    if (name === "doc" || name === "bson") out = applyClears(out, SinkClass.NOSQL);
    if (name === "format" && isPosixShellQuote(m)) out = applyClears(out, SinkClass.CMD);
    return out;
  };

  const callMask = (node: SyntaxNode, env: Env): number => {
    const { name, recv, path } = callParts(node);
    const args = argNodes(node);
    const argsMask = () => args.reduce((m, a) => m | mask(a, env), 0);
    const fullPath = path ? resolvePath(path, ctx) : null;

    // request accessors: req.headers() / req.match_info() / request.uri()
    // an app's own request type read through `query_get` / `header_value` / `form_param`-style helpers too
    if (recv && (REQUEST_INPUT_METHODS.has(name) || REQUEST_INPUT_HELPER_RE.test(name)) && isRequestValue(recv, env, ctx)) return ALL;
    // m.get("k") on a map written under literal keys: what was stored under "k" (plus the map itself), not its other keys
    if (recv && /^(?:get|get_mut|remove)$/.test(name)) {
      const kc = literalKeyCall(node);
      if (kc && hasKeyedSlots(env, kc.map)) return (env.get(keySlot(kc.map, kc.key)) ?? 0) | (env.get(kc.map) ?? 0);
    }

    if (recv) {
      if (name === "parse") {
        // x.parse::<i64>() / let n: u32 = x.parse()? -- parsed to a typed value
        const turbofish = field(node, "function")?.type === "generic_function" ? named(field(field(node, "function"), "type_arguments"))[0]?.text ?? "" : "";
        const target = turbofish || letTypeOf(node);
        const rm = mask(recv, env);
        return !target || /^(?:i\d+|u\d+|isize|usize|f\d+|bool|char|Uuid|IpAddr|Ipv4Addr|Ipv6Addr|SocketAddr|NaiveDate|NaiveDateTime|DateTime.*)$/.test(target) ? applyClears(rm, NUMERIC_CLEARS) : rm;
      }
      if (NAME_ONLY_METHODS.has(name)) return applyClears(mask(recv, env), SinkClass.PATH);
      if (RECEIVER_CLEARS[name] !== undefined) return applyClears(mask(recv, env), RECEIVER_CLEARS[name]);
      if (OPAQUE_RESULT_METHODS.has(name) || /^is_/.test(name)) return 0;
    }

    if (fullPath) {
      const sc = sanitizerClears("rs", lastTwo(fullPath), args.map(a => a.text)) ?? sanitizerClears("rs", fullPath, args.map(a => a.text));
      if (sc !== null) { const a = args[0]; return a ? applySanitizer(mask(a, env), sc) : 0; }
    }

    // Same-file function / method: return-value summary.
    const local = (!recv || recv.type === "self") ? ctx.fns.get(name) : null;
    if (local?.body && (!path || !path.includes("::") || path.startsWith("Self::") || path.startsWith("self::"))) {
      let m = ctx.intrinsic.get(name) ?? 0;
      const prop = ctx.propagating.get(name);
      if (prop) for (const [i, surviving] of prop) { const a = args[i]; if (a) m |= mask(a, env) & surviving; }
      return m;
    }

    if (recv) {
      const closure = args.find(a => a.type === "closure_expression");
      const rm = mask(recv, env);
      if (closure && ELEMENT_CLOSURES.has(name)) {
        if (RECEIVER_RESULT_CLOSURES.has(name)) return rm;
        return closureValue(closure, rm, env) | (name === "map_or" || name === "map_or_else" ? args.filter(a => a !== closure).reduce((m, a) => m | mask(a, env), 0) : 0);
      }
      if (DECODER_RE.test(`${chainText(recv)}.${name}`) && name === "decode") { const m = rm | argsMask(); return (m & ALL) | ((m >>> 16) & ALL); }
      return ARG_FLOW_METHODS.has(name) ? rm | argsMask() : rm;
    }

    if (fullPath && (PASSTHROUGH_PATHS.has(lastTwo(fullPath)) || PASSTHROUGH_PATHS.has(fullPath))) {
      const m = argsMask();
      return DECODER_RE.test(fullPath) ? (m & ALL) | ((m >>> 16) & ALL) : m;
    }
    // tuple structs / enum variants: Some(x), Ok(x), Html(x), Wrapper(x)
    if (path && /^[A-Z]/.test(path.split("::").pop() ?? "")) return argsMask();
    return 0;
  };

  return mask;
}

function lastTwo(path: string): string {
  const segs = path.split("::");
  return segs.slice(-2).join("::");
}
/** `find` -> its imported full path; `Self::x` stays. */
function resolvePath(path: string, ctx: EngineCtx): string {
  const segs = path.split("::");
  const head = ctx.imports.get(segs[0]);
  return head ? [head, ...segs.slice(1)].join("::") : path;
}
/** `let n: u32 = <node>?` -- the declared type of the let this expression initializes, or "". */
function letTypeOf(n: SyntaxNode): string {
  let cur: SyntaxNode | null = n;
  while (cur?.parent && /^(?:try_expression|call_expression|field_expression|await_expression)$/.test(cur.parent.type)) {
    if (cur.parent.type === "call_expression" && field(cur.parent, "function")?.type === "field_expression" && !/^(?:unwrap|expect|unwrap_or|unwrap_or_default)$/.test(callParts(cur.parent).name)) return "";
    cur = cur.parent;
  }
  const p = cur?.parent;
  return p?.type === "let_declaration" ? field(p, "type")?.text ?? "" : "";
}

function isRequestValue(recv: SyntaxNode, env: Env, ctx: EngineCtx): boolean {
  const base = recv.type === "reference_expression" ? named(recv)[0] : recv;
  if (base?.type !== "identifier") return false;
  const t = ctx.varTypes.get(base.text);
  // an app's own request wrapper (`ApiRequest`, `BenchmarkRequest`) read through the same accessor names
  return !!t && (REQUEST_TYPES.has(t) || /^[A-Z]\w*Request$/.test(t)) && !env.has(`!shadow:${base.text}`);
}

function closureParams(cl: SyntaxNode): string[] {
  return findAllNodes(field(cl, "parameters") ?? cl, "identifier").filter(i => i.parent?.type !== "type_identifier" && !isTypePosition(i)).map(i => i.text);
}
const isTypePosition = (i: SyntaxNode) => i.parent?.type === "scoped_type_identifier" || i.parent?.type === "generic_type" || (i.parent?.type === "tuple_struct_pattern" && field(i.parent, "type")?.id === i.id);

/** Bind every name a pattern introduces (`x`, `Some(x)`, `(a, b)`, `Point { x, y }`, `ref mut x`) to `m`. */
function bindPattern(pat: SyntaxNode | null, m: number, env: Env) {
  if (!pat) return;
  for (const i of findAllNodes(pat, "identifier")) {
    if (isTypePosition(i)) continue;
    if (i.parent?.type === "match_pattern" && field(i.parent, "condition") && field(i.parent, "condition")!.startIndex <= i.startIndex) continue;
    if (field(pat, "condition") && i.startIndex >= field(pat, "condition")!.startIndex) continue;
    if (/^[A-Z]/.test(i.text) && i.parent?.type === "match_pattern") continue;   // a constant / unit variant, not a binding
    env.set(i.text, m);
  }
}
function patternIsLiteral(pat: SyntaxNode): boolean {
  const kids = named(pat).filter(k => k.type !== "condition" && field(pat, "condition")?.id !== k.id);
  if (kids.length === 0) return false;
  return kids.every(k => k.type === "or_pattern" ? named(k).every(isLiteral) : isLiteral(k));
}

/** The argument node bound to parameter `index` (self excluded) at a call. */
const bindArgument = (call: SyntaxNode, index: number): SyntaxNode | null => argNodes(call)[index] ?? null;

// ── Declarations ───────────────────────────────────────────────────────────────────────────────────────────

function attributesOf(fn: SyntaxNode): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  for (let p = fn.previousNamedSibling; p && p.type === "attribute_item"; p = p.previousNamedSibling) out.push(p);
  return out;
}
const attrName = (a: SyntaxNode) => (pathText(named(named(a)[0] ?? null)[0] ?? null) ?? named(named(a)[0])[0]?.text ?? "").split("::").pop() ?? "";

function paramShapesOf(params: SyntaxNode | null): { shapes: ParamShape[]; hasSelf: boolean } {
  const shapes: ParamShape[] = [];
  let hasSelf = false;
  let index = 0;
  for (const p of named(params)) {
    if (p.type === "self_parameter") { hasSelf = true; continue; }
    if (p.type !== "parameter") continue;
    const pat = field(p, "pattern");
    const names = pat ? findAllNodes(pat, "identifier").filter(i => !isTypePosition(i) && !(i.parent?.type === "tuple_struct_pattern" && field(i.parent, "type")?.id === i.id)).map(i => i.text) : [];
    shapes.push({ name: names[0] ?? `_${index}`, index, type: field(p, "type"), names, pattern: pat });
    index++;
  }
  return { shapes, hasSelf };
}

function moduleNameOf(filePath: string): string {
  const parts = filePath.replace(/\\/g, "/").split("/");
  const file = (parts.pop() ?? "").replace(/\.rs$/, "");
  if (file === "mod") return parts.pop() ?? "crate";
  if (file === "lib" || file === "main") return "crate";
  return file;
}

function collectFns(root: SyntaxNode, moduleName: string): LocalFn[] {
  const out: LocalFn[] = [];
  for (const decl of findAllNodes(root, "function_item")) {
    const name = field(decl, "name")?.text;
    if (!name) continue;
    let impl: SyntaxNode | null = null;
    for (let p = decl.parent; p; p = p.parent) {
      if (p.type === "impl_item" || p.type === "trait_item") { impl = p; break; }
      if (p.type === "function_item") break;
    }
    const { shapes, hasSelf } = paramShapesOf(field(decl, "parameters"));
    const implType = impl?.type === "impl_item" ? coreType(field(impl, "type")) : null;
    const trait = impl?.type === "impl_item" ? coreType(field(impl, "trait")) : "";
    const nested = !impl && decl.parent?.type !== "source_file" && decl.parent?.type !== "declaration_list";
    const key = nested ? null : implType ? `${implType}${hasSelf ? "." : "::"}${name}` : `${moduleName}::${name}`;
    out.push({
      name, decl, implType, hasSelf, params: shapes, body: field(decl, "body"), attrs: attributesOf(decl),
      isPub: named(decl).some(c => c.type === "visibility_modifier") || !!trait,
      key, altKeys: trait && key ? [`${trait}${hasSelf ? "." : "::"}${name}`] : [],
    });
  }
  return out;
}

function collectImports(root: SyntaxNode): Map<string, string> {
  const out = new Map<string, string>();
  const visit = (n: SyntaxNode, prefix: string) => {
    switch (n.type) {
      case "scoped_identifier": case "identifier": case "self": { const t = pathText(n); if (t) out.set(t.split("::").pop()!, prefix ? `${prefix}::${t}` : t); break; }
      case "use_as_clause": { const p = pathText(field(n, "path")); const a = field(n, "alias")?.text; if (p && a) out.set(a, prefix ? `${prefix}::${p}` : p); break; }
      case "scoped_use_list": { const p = pathText(field(n, "path")); const list = field(n, "list"); for (const c of named(list)) visit(c, [prefix, p].filter(Boolean).join("::")); break; }
      case "use_list": for (const c of named(n)) visit(c, prefix); break;
      default: break;
    }
  };
  for (const u of findAllNodes(root, "use_declaration")) { const a = field(u, "argument"); if (a) visit(a, ""); }
  return out;
}

function collectStructFields(root: SyntaxNode): Map<string, string> {
  const out = new Map<string, string>();
  for (const s of findAllNodes(root, "struct_item")) {
    const sn = field(s, "name")?.text;
    if (!sn) continue;
    for (const f of findAllNodes(s, "field_declaration")) {
      const fn = field(f, "name")?.text;
      if (fn) out.set(`${sn}.${fn}`, coreType(field(f, "type")));
    }
  }
  return out;
}

// ── Guards ─────────────────────────────────────────────────────────────────────────────────────────────────

const unwrapExpr = (n: SyntaxNode): SyntaxNode => {
  let cur = n;
  while ((cur.type === "parenthesized_expression" || cur.type === "reference_expression") && named(cur).length >= 1) cur = field(cur, "value") ?? named(cur)[0];
  return cur;
};
/** The variable a guard is about: `x`, `&x`, `x.as_str()`, `x.trim()`, `*x`. */
function guardName(n: SyntaxNode): string | null {
  const c = unwrapExpr(n);
  if (c.type === "identifier") return c.text;
  if (c.type === "unary_expression" && operatorOf(c) === "*") { const v = named(c)[0]; return v ? guardName(v) : null; }
  if (c.type === "call_expression") {
    const { name, recv } = callParts(c);
    if (recv && /^(?:as_str|as_ref|trim|as_deref|to_string|to_owned|to_lowercase|deref|borrow)$/.test(name)) return guardName(recv);
  }
  return null;
}
const invert = (g: Guard): Guard => ({ ...g, holds: g.holds === "true" ? "false" : "true" });

function isLiteralCollection(n: SyntaxNode, ctx: EngineCtx): boolean {
  const c = unwrapExpr(n);
  if (c.type === "array_expression") return named(c).length > 0 && named(c).every(isLiteral);
  if (c.type === "macro_invocation" && macroName(c) === "vec") return macroArgs(c).args.length > 0 && macroArgs(c).args.every(isLiteral);
  if (c.type === "identifier" && /^[A-Z][A-Z0-9_]*$/.test(c.text)) {
    const decl = findAllNodes(ctx.root, new Set(["const_item", "static_item"])).find(d => field(d, "name")?.text === c.text);
    const v = decl ? field(decl, "value") : null;
    return !!v && isLiteralCollection(v, ctx);
  }
  // `let allowed = ["a", "b"];` -- a local bound once to a literal list
  if (c.type === "identifier") {
    const def = lastAssignment(c.text, c);
    return !!def && def.type !== "identifier" && isLiteralCollection(def, ctx);
  }
  return false;
}

/**
 * The classes a "this sequence is not in the value" check makes safe: without `..` a path can't climb out of its
 * directory; without a quote the value can't close a quoted SQL/XPath string literal; without `<` it can't open a
 * tag. Null for any other substring -- it proves nothing.
 */
function substringGuardClears(sub: string): number | null {
  let clears = 0;
  if (sub.includes("..")) clears |= SinkClass.PATH;
  if (sub.includes("'") || sub.includes('"')) clears |= SinkClass.SQL | SinkClass.XPATH;
  if (sub.includes("<")) clears |= SinkClass.XSS;
  return clears || null;
}
/** `'x'` / `'\''` / `"x"` -> its character(s). */
function charOrStringValue(n: SyntaxNode | null | undefined): string | null {
  if (!n) return null;
  if (n.type === "char_literal") return n.text.slice(1, -1).replace(/^\\(.)$/, "$1");
  return stringValue(n);
}

/**
 * `x.chars().all(|c| c.is_alphanumeric() || c == '_')`: what the allowed alphabet rules out. Every injection class,
 * except that a `-` in it still lets the value be an option (CMD stays: argument injection), and `/` or `\` still
 * lets it be a nested path.
 */
function charAllowlistClears(closure: string): number {
  const extras = [...closure.matchAll(/==\s*'(\\.|[^'])'/g)].map(m => m[1].replace(/^\\/, ""));
  let clears = INJECTION;
  if (extras.includes("-")) clears &= ~SinkClass.CMD;
  if (extras.includes("/") || extras.includes("\\")) clears &= ~SinkClass.PATH;
  return clears;
}

/** A guard on a helper's parameter that holds only when the caller's argument was itself canonicalized. */
const CANON_PARAM = (name: string) => `\u0000canon:${name}`;

type ConstRs = number | boolean | string;
const NOT_CONST_RS: unique symbol = Symbol("not-const");
/** Compile-time value of a literal expression (`7 * 6 > 40`, `"a" == "b"`, `!true`), else NOT_CONST_RS. */
function constValueRs(n: SyntaxNode | null, depth = 0): ConstRs | typeof NOT_CONST_RS {
  if (!n || depth > 8) return NOT_CONST_RS;
  switch (n.type) {
    case "integer_literal": { const v = Number(n.text.replace(/_/g, "").replace(/(?:[iu](?:8|16|32|64|128|size))$/, "")); return Number.isFinite(v) ? v : NOT_CONST_RS; }
    case "boolean_literal": return n.text === "true";
    case "string_literal": return stringValue(n) ?? NOT_CONST_RS;
    case "parenthesized_expression": return constValueRs(named(n)[0] ?? null, depth + 1);
    case "unary_expression": {
      const v = constValueRs(named(n)[0] ?? null, depth + 1);
      const op = operatorOf(n);
      if (op === "!" && typeof v === "boolean") return !v;
      if (op === "-" && typeof v === "number") return -v;
      return NOT_CONST_RS;
    }
    case "binary_expression": {
      const op = operatorOf(n);
      const a = constValueRs(field(n, "left"), depth + 1);
      if (a === NOT_CONST_RS) return a;
      if (op === "&&" && typeof a === "boolean") return a ? constValueRs(field(n, "right"), depth + 1) : false;
      if (op === "||" && typeof a === "boolean") return a ? true : constValueRs(field(n, "right"), depth + 1);
      const b = constValueRs(field(n, "right"), depth + 1);
      if (b === NOT_CONST_RS) return b;
      if (op === "==") return a === b;
      if (op === "!=") return a !== b;
      if (typeof a === "number" && typeof b === "number") {
        switch (op) {
          case "+": return a + b; case "-": return a - b; case "*": return a * b;
          case "/": return b === 0 ? NOT_CONST_RS : Math.trunc(a / b);
          case "%": return b === 0 ? NOT_CONST_RS : a % b;
          case "<": return a < b; case ">": return a > b; case "<=": return a <= b; case ">=": return a >= b;
        }
      }
      return NOT_CONST_RS;
    }
    default: return NOT_CONST_RS;
  }
}

/** The local a `.insert(k, v)` / `.get(k)` call is keyed on, with its literal key; null otherwise. */
function literalKeyCall(call: SyntaxNode): { map: string; key: string } | null {
  const { recv } = callParts(call);
  const k = argNodes(call)[0];
  const base = recv ? unwrapExpr(recv) : null;
  const key = k ? stringValue(unwrapExpr(k)) ?? (unwrapExpr(k).type === "integer_literal" ? unwrapExpr(k).text : null) : null;
  return base?.type === "identifier" && key !== null ? { map: base.text, key } : null;
}
const keySlot = (map: string, key: string) => `${map}[${JSON.stringify(key)}]`;
/** Set once a map has a literal-key slot, so whole-map reads only scan the env for maps that have them. */
const KEYED_MARK = (map: string) => `\u0000keyed:${map}`;
/** Everything stored in a map under literal keys (what a whole-map read carries). */
function keyedUnion(env: Env, map: string): number {
  if (!env.has(KEYED_MARK(map))) return 0;
  const prefix = `${map}[`;
  let m = 0;
  for (const [k, v] of env) if (k.startsWith(prefix)) m |= v;
  return m;
}
function hasKeyedSlots(env: Env, map: string): boolean {
  return env.has(KEYED_MARK(map));
}

/**
 * `v[k]` (literal k) for a Vec built in straight-line code in the same block: `let mut v = vec![...]`, then only
 * `v.push(x)` / `v.insert(i, x)` / `v.remove(i)` / `v.pop()` statements before the read. The element expression
 * at k, null when k is out of range, undefined when the contents can't be followed this way.
 */
function vecElementAt(index: SyntaxNode): SyntaxNode | null | undefined {
  const [value, idx] = named(index);
  if (value?.type !== "identifier" || idx?.type !== "integer_literal") return undefined;
  const k = Number(idx.text.replace(/_/g, ""));
  let stmt: SyntaxNode | null = index;
  while (stmt?.parent && stmt.parent.type !== "block") stmt = stmt.parent;
  const block = stmt?.parent;
  if (!stmt || !block) return undefined;
  const name = value.text;
  const mentions = new RegExp(`\\b${name}\\b`);
  let seq: SyntaxNode[] | null = null;
  for (const st of named(block)) {
    if (st.id === stmt.id) break;
    if (!mentions.test(st.text)) continue;
    if (st.type === "let_declaration" && field(st, "pattern")?.text.replace(/^mut\s+/, "") === name) {
      const v = field(st, "value");
      if (!v || v.type !== "macro_invocation" || macroName(v) !== "vec") return undefined;
      seq = [...macroArgs(v).args];
      if (/;/.test(named(v).find(c => c.type === "token_tree")?.text ?? "")) return undefined;   // vec![x; n]
      continue;
    }
    const e = st.type === "expression_statement" ? named(st)[0] : null;
    if (!seq || e?.type !== "call_expression") return undefined;
    const { name: method, recv } = callParts(e);
    if (!recv || unwrapExpr(recv).text !== name) return undefined;
    const args = argNodes(e);
    const intArg = (n: SyntaxNode | undefined) => (n?.type === "integer_literal" ? Number(n.text.replace(/_/g, "")) : null);
    if (method === "push" && args.length === 1) seq.push(args[0]);
    else if (method === "insert" && args.length === 2 && intArg(args[0]) !== null) seq.splice(intArg(args[0])!, 0, args[1]);
    else if (method === "pop" && args.length === 0) seq.pop();
    else if (method === "remove" && args.length === 1 && intArg(args[0]) !== null) seq.splice(intArg(args[0])!, 1);
    else return undefined;
  }
  if (!seq) return undefined;
  return k >= 0 && k < seq.length ? seq[k] : null;
}

function guardsOf(cond: SyntaxNode, ctx: EngineCtx, depth = 0): Guard[] {
  const c = unwrapExpr(cond);
  if (depth > 4) return [];
  if (c.type === "unary_expression" && operatorOf(c) === "!") { const v = named(c)[0]; return v ? guardsOf(v, ctx, depth + 1).map(invert) : []; }
  // `let ok = x.chars().all(..); if !ok { return }` -- a boolean local bound to a check
  if (c.type === "identifier") {
    const def = lastAssignment(c.text, c);
    return def && def.type !== "identifier" ? guardsOf(def, ctx, depth + 1) : [];
  }
  if (c.type === "binary_expression") {
    const op = operatorOf(c);
    const l = field(c, "left"), r = field(c, "right");
    if (!l || !r) return [];
    if (op === "&&") return [...guardsOf(l, ctx, depth + 1), ...guardsOf(r, ctx, depth + 1)].filter(g => g.holds === "true");
    if (op === "||") return [...guardsOf(l, ctx, depth + 1), ...guardsOf(r, ctx, depth + 1)].filter(g => g.holds === "false");
    if (op === "==" || op === "!=") {
      const holds = op === "==" ? "true" : "false";
      const ln = guardName(l), rn = guardName(r);
      if (ln && isLiteral(unwrapExpr(r))) return [{ name: ln, holds }];
      if (rn && isLiteral(unwrapExpr(l))) return [{ name: rn, holds }];
    }
    return [];
  }
  if (c.type === "macro_invocation" && macroName(c) === "matches") {
    const { args } = macroArgs(c);
    // matches!(x, "a" | "b") -- the second argument is a pattern; re-parsed as an expression it is `"a" | "b"`
    const n = args[0] ? guardName(args[0]) : null;
    const pat = args[1];
    const lits = pat ? findAllNodes(pat, new Set(["string_literal", "integer_literal", "char_literal"])) : [];
    return n && pat && lits.length > 0 && !findAllNodes(pat, "identifier").length ? [{ name: n, holds: "true" }] : [];
  }
  if (c.type === "call_expression") {
    const { name, recv } = callParts(c);
    const args = argNodes(c);
    if (name === "contains" && recv && args[0] && isLiteralCollection(recv, ctx)) { const n = guardName(args[0]); return n ? [{ name: n, holds: "true" }] : []; }
    // x.contains("..") / x.contains('\'') -- when false, x lacks that sequence
    if (name === "contains" && recv && args[0]) {
      const sub = charOrStringValue(unwrapExpr(args[0]));
      const clears = sub !== null ? substringGuardClears(sub) : null;
      const n = guardName(recv);
      return n && clears ? [{ name: n, holds: "false", clears }] : [];
    }
    // x.chars().all(|c| c.is_ascii_digit())
    if (name === "all" && recv?.type === "call_expression" && callParts(recv).name === "chars" && /is_ascii_(?:digit|alphanumeric|hexdigit)|is_numeric|is_alphanumeric/.test(args[0]?.text ?? "")) {
      const n = callParts(recv).recv ? guardName(callParts(recv).recv!) : null;
      return n ? [{ name: n, holds: "true", clears: charAllowlistClears(args[0]?.text ?? "") }] : [];
    }
    // p.strip_prefix(&base).is_err() after p = ...canonicalize() -- false when p is inside base
    if ((name === "is_err" || name === "is_ok") && recv?.type === "call_expression" && callParts(recv).name === "strip_prefix") {
      const inner = callParts(recv).recv;
      const n = inner ? guardName(inner) : null;
      const def = n ? lastAssignment(n, c) : null;
      return n && def && /canonicalize|normalize|clean/.test(def.text) ? [{ name: n, holds: name === "is_ok" ? "true" : "false" }] : [];
    }
    // a same-file boolean helper: `fn is_safe(s: &str) -> bool { !s.contains("..") && ... }`
    if (!recv && ctx.fns.get(name)?.body && depth < 3) {
      const fn = ctx.fns.get(name)!;
      const kids = named(fn.body).filter(k => !/comment$/.test(k.type));
      const tail = kids[kids.length - 1];
      if (!tail || tail.type === "expression_statement" || tail.type === "let_declaration") return [];
      const out: Guard[] = [];
      for (const g of guardsOf(tail, ctx, depth + 1)) {
        const canon = g.name.startsWith(CANON_PARAM(""));
        const pname = canon ? g.name.slice(CANON_PARAM("").length) : g.name;
        const p = fn.params.find(q => q.name === pname);
        const a = p ? args[p.index] : undefined;
        const an = a ? guardName(a) : null;
        if (!an) continue;
        if (canon) { const def = lastAssignment(an, c); if (!def || !/canonicalize|normalize|clean/.test(def.text)) continue; }
        out.push({ ...g, name: an });
      }
      return out;
    }
    // x.parse::<i64>().is_ok()
    if (name === "is_ok" && recv?.type === "call_expression" && callParts(recv).name === "parse") {
      const n = callParts(recv).recv ? guardName(callParts(recv).recv!) : null;
      return n ? [{ name: n, holds: "true" }] : [];
    }
    // RE.is_match(&x) with an anchored character-class pattern
    if (name === "is_match" && recv && args[0]) {
      const n = guardName(args[0]);
      const pattern = regexLiteralOf(recv, ctx);
      // an anchored alphabet (`^[a-z0-9_-]+$`); a `-` in it still lets the value be an option
      const clears = pattern ? anchoredPatternClears(pattern) : null;
      return n && clears ? [{ name: n, holds: "true", clears }] : [];
    }
    // p.starts_with(&base) after p = base.join(x).canonicalize()?
    if (name === "starts_with" && recv) {
      const n = guardName(recv);
      const def = n ? lastAssignment(n, c) : null;
      if (n && !def && ctx.fns.get(findEnclosingFunctionNameRust(c))?.params.some(p => p.name === n)) return [{ name: CANON_PARAM(n), holds: "true" }];
      return n && def && /canonicalize|normalize|clean/.test(def.text) ? [{ name: n, holds: "true" }] : [];
    }
  }
  return [];
}
function regexLiteralOf(recv: SyntaxNode, ctx: EngineCtx): string | null {
  const lit = (n: SyntaxNode | null): string | null => {
    if (!n) return null;
    const s = findAllNodes(n, new Set(["string_literal", "raw_string_literal"]))[0];
    return s ? stringValue(s) : null;
  };
  const base = unwrapExpr(recv);
  if (base.type === "identifier") {
    const decl = findAllNodes(ctx.root, new Set(["const_item", "static_item", "let_declaration"])).find(d => (field(d, "name") ?? field(d, "pattern"))?.text === base.text);
    return lit(decl ? field(decl, "value") : null);
  }
  return lit(base);
}
function guarded(env: Env, guards: readonly Guard[]): Env {
  if (guards.length === 0) return env;
  const e = cloneEnv(env);
  applyGuardSet(e, guards, guards[0].holds);
  return e;
}

// ── Statement walker ───────────────────────────────────────────────────────────────────────────────────────

interface WalkOpts {
  descendClosures: boolean;
  onReturn?: (expr: SyntaxNode | null, env: Env, mask: TaintMaskFn) => void;
}
const TERMINATING_MACROS = new Set(["panic", "unreachable", "todo", "unimplemented", "bail"]);

function createWalker(ctx: EngineCtx, opts: WalkOpts) {
  const mask = makeTaintMask(ctx);

  const walkSeq = (nodes: readonly SyntaxNode[], env: Env): boolean => {
    for (const c of nodes) if (walk(c, env)) return true;
    return false;
  };

  /** `if cond` / `if let P = v` / let chains: guards and pattern bindings for the then-arm. */
  const condBranch = (cond: SyntaxNode | null, body: SyntaxNode | null): Branch => ({
    visitCond: (e) => {
      if (!cond) return;
      for (const lc of cond.type === "let_condition" ? [cond] : findAllNodes(cond, "let_condition")) {
        const v = field(lc, "value");
        if (v) walk(v, e);
      }
      if (cond.type !== "let_condition") walk(cond, e);
    },
    guards: () => (cond && cond.type !== "let_condition" ? guardsOf(cond, ctx) : []),
    body: (e) => {
      if (cond) for (const lc of cond.type === "let_condition" ? [cond] : findAllNodes(cond, "let_condition")) {
        const v = field(lc, "value");
        bindPattern(field(lc, "pattern"), v ? mask(v, e) : 0, e);
      }
      return body ? walk(body, e) : false;
    },
  });

  const ifExpr = (node: SyntaxNode, env: Env): boolean => {
    const branches: Branch[] = [];
    let cur: SyntaxNode | null = node;
    while (cur) {
      const cond = field(cur, "condition");
      const cv = cond && cond.type !== "let_condition" ? constValueRs(cond) : NOT_CONST_RS;
      if (cv === true) {
        // a constant-true condition: its arm is the only one that runs (earlier arms already joined in)
        const cons = field(cur, "consequence");
        branches.push({ body: (e) => (cons ? walk(cons, e) : false) });
        break;
      }
      if (cv === false) {
        const alt: SyntaxNode | null = field(cur, "alternative");
        const inner: SyntaxNode | null = alt ? named(alt)[0] ?? null : null;
        if (!inner) break;
        if (inner.type === "if_expression") { cur = inner; continue; }
        branches.push({ body: (e) => walk(inner, e) });
        break;
      }
      branches.push(condBranch(cond, field(cur, "consequence")));
      const alt: SyntaxNode | null = field(cur, "alternative");
      const inner: SyntaxNode | null = alt ? named(alt)[0] ?? null : null;
      if (!inner) break;
      if (inner.type === "if_expression") { cur = inner; continue; }
      branches.push({ body: (e) => walk(inner, e) });
      break;
    }
    return walkIfChain(env, branches);
  };

  const walkClosure = (cl: SyntaxNode, paramMask: number, env: Env) => {
    const params = closureParams(cl);
    const saved = new Map(params.map(p => [p, env.get(p)]));
    walkLoop(env, (e) => {
      for (const p of params) e.set(p, paramMask);
      const body = field(cl, "body");
      if (body) walk(body, e);
      return false;
    });
    for (const [k, v] of saved) { if (v === undefined) env.delete(k); else env.set(k, v); }
  };

  const assignTo = (left: SyntaxNode, m: number, env: Env, orInto: boolean) => {
    const target = unwrapExpr(left);
    if (target.type === "identifier") { env.set(target.text, orInto ? (env.get(target.text) ?? 0) | m : m); return; }
    if (target.type === "field_expression" || target.type === "index_expression") {
      // s.field = x / v[i] = x -- field-insensitive: the base now carries x
      let base: SyntaxNode | null = target;
      while (base && (base.type === "field_expression" || base.type === "index_expression")) base = field(base, "value") ?? named(base)[0] ?? null;
      if (base?.type === "identifier") env.set(base.text, (env.get(base.text) ?? 0) | m);
      return;
    }
    if (target.type === "unary_expression") { const v = named(target)[0]; if (v) assignTo(v, m, env, orInto); }
  };

  const walk = (node: SyntaxNode, env: Env): boolean => {
    switch (node.type) {
      case "function_item": case "struct_item": case "impl_item": case "trait_item": case "mod_item": case "enum_item":
      case "use_declaration": case "attribute_item": case "const_item": case "static_item": case "macro_definition":
        return false;
      case "closure_expression":
        if (opts.descendClosures) walkClosure(node, 0, cloneEnv(env));
        return false;
      case "block": case "unsafe_block": case "async_block": case "expression_statement": case "parenthesized_expression":
        return walkSeq(named(node), env);
      case "let_declaration": {
        const value = field(node, "value");
        if (value) walk(value, env);
        let m = value ? mask(value, env) : 0;
        const t = field(node, "type");
        if (t && t.type === "primitive_type" && t.text !== "str") m = applyClears(m, NUMERIC_CLEARS);
        const pat = field(node, "pattern");
        bindPattern(pat, m, env);
        if (pat?.type === "identifier") {
          const declared = t ? coreType(t) : value ? constructedType(value) : null;
          if (declared) ctx.varTypes.set(pat.text, declared);
          if (value) trackCommand(pat.text, value, ctx);
        }
        const alt = field(node, "alternative");
        if (alt) walkIfChain(env, [{ body: (e) => walk(alt, e) }]);
        return false;
      }
      case "assignment_expression": case "compound_assignment_expr": {
        const r = field(node, "right"), l = field(node, "left");
        if (r) walk(r, env);
        if (l && r) assignTo(l, mask(r, env), env, node.type === "compound_assignment_expr");
        return false;
      }
      case "if_expression":
        return ifExpr(node, env);
      case "match_expression": {
        const subject = field(node, "value");
        if (subject) walk(subject, env);
        const sm = subject ? mask(subject, env) : 0;
        const subjectName = subject ? guardName(subject) : null;
        const arms = named(field(node, "body")).filter(a => a.type === "match_arm");
        return walkSwitch(env, arms.map(arm => {
          const pat = field(arm, "pattern");
          return {
            isDefault: !!pat && /^_$/.test(pat.text.trim()),
            pre: (e: Env) => {
              bindPattern(pat, sm, e);
              if (subjectName && pat && patternIsLiteral(pat)) applyGuards(e, [subjectName]);
              const guard = pat ? field(pat, "condition") : null;
              if (guard) { walk(guard, e); applyGuardSet(e, guardsOf(guard, ctx), "true"); }
            },
            body: (e: Env) => { const v = field(arm, "value"); return v ? walk(v, e) : false; },
          };
        }));
      }
      case "for_expression": {
        const value = field(node, "value");
        if (value) walk(value, env);
        const vm = value ? mask(value, env) : 0;
        const pat = field(node, "pattern");
        const body = field(node, "body");
        return walkLoop(env, (e) => { bindPattern(pat, vm, e); return body ? walk(body, e) : false; });
      }
      case "while_expression": {
        const cond = field(node, "condition");
        const body = field(node, "body");
        if (cond) walk(cond, env);
        return walkLoop(env, (e) => {
          if (cond) for (const lc of cond.type === "let_condition" ? [cond] : findAllNodes(cond, "let_condition")) bindPattern(field(lc, "pattern"), field(lc, "value") ? mask(field(lc, "value")!, e) : 0, e);
          return body ? walk(body, e) : false;
        });
      }
      case "loop_expression": {
        const body = field(node, "body");
        walkLoop(env, (e) => (body ? walk(body, e) : false));
        return false;
      }
      case "return_expression": {
        const v = named(node)[0] ?? null;
        if (v) walk(v, env);
        opts.onReturn?.(v, env, mask);
        return true;
      }
      case "break_expression": case "continue_expression":
        for (const c of named(node)) walk(c, env);
        return true;
      case "macro_invocation": {
        const name = macroName(node);
        const { args, captures } = macroArgs(node);
        for (const a of args) walk(a, env);
        void captures;
        checkMacroSink(node, env, ctx, mask);
        if (name === "write" || name === "writeln") {
          const target = args[0];
          if (target) assignTo(target, args.slice(1).reduce((m, a) => m | mask(a, env), 0) | [...macroArgs(node).captures.values()].reduce((m, a) => m | mask(a, env), 0), env, true);
        }
        if (name === "ensure" && args[0]) applyGuardSet(env, guardsOf(args[0], ctx), "true");
        return TERMINATING_MACROS.has(name);
      }
      case "call_expression": {
        const { name, recv, fnNode } = callParts(node);
        if (recv) walk(recv, env);
        else if (fnNode && fnNode.type !== "identifier" && fnNode.type !== "scoped_identifier") walk(fnNode, env);
        for (const a of argNodes(node)) if (a.type !== "closure_expression") walk(a, env);
        checkCallSink(node, env, ctx, mask);
        seedLocalFn(node, env, ctx, mask);
        checkCrossFileCall(node, env, ctx, mask);
        const kc = recv && name === "insert" && argNodes(node).length === 2 ? literalKeyCall(node) : null;
        if (kc) {
          // m.insert("k", v): the value lives under its own key
          const slot = keySlot(kc.map, kc.key);
          env.set(slot, (env.get(slot) ?? 0) | mask(argNodes(node)[1], env));
          env.set(KEYED_MARK(kc.map), 0);
        } else if (recv && MUTATOR_METHODS.has(name)) {
          const am = argNodes(node).reduce((m, a) => m | mask(a, env), 0);
          if (am) assignTo(recv, am, env, true);
        }
        if (recv && (name === "arg" || name === "args") && unwrapExpr(recv).type === "identifier") appendCommandArgs(unwrapExpr(recv).text, node, ctx);
        for (const cl of argNodes(node).filter(a => a.type === "closure_expression")) {
          walkClosure(cl, recv && ELEMENT_CLOSURES.has(name) ? mask(recv, env) : 0, env);
        }
        return false;
      }
      default:
        break;
    }
    if (node.type === "binary_expression" && /^(?:==|!=)$/.test(operatorOf(node))) {
      for (const c of named(node)) walk(c, env);
      const l = field(node, "left"), r = field(node, "right");
      if (l && r) checkTimingCompare(node, l, r, env, ctx, mask);
      return false;
    }
    for (const c of named(node)) walk(c, env);
    return false;
  };

  return { walk, mask };
}

/** `Client::new()` -> "Client"; `reqwest::Client::builder()...build()?` -> "Client"; `Command::new(..)` -> "Command". */
function constructedType(v: SyntaxNode): string | null {
  let cur: SyntaxNode | null = unwrapExpr(v);
  while (cur && (cur.type === "try_expression" || cur.type === "await_expression")) cur = named(cur)[0] ?? null;
  while (cur?.type === "call_expression" && callParts(cur).recv) cur = callParts(cur).recv;
  if (cur?.type === "call_expression") {
    const p = callParts(cur).path;
    const segs = p?.split("::") ?? [];
    if (segs.length >= 2 && /^[A-Z]/.test(segs[segs.length - 2])) return segs[segs.length - 2];
  }
  if (cur?.type === "struct_expression") return coreType(field(cur, "name"));
  return null;
}

// ── Command builders ───────────────────────────────────────────────────────────────────────────────────────

/** The program + literal-or-not arguments of a `Command` chain, following one variable hop. */
function commandChain(n: SyntaxNode, ctx: EngineCtx): CmdState | null {
  const args: SyntaxNode[] = [];
  let cur: SyntaxNode | null = unwrapExpr(n);
  while (cur?.type === "call_expression") {
    const { name, recv, path } = callParts(cur);
    if (path && /(?:^|::)Command::new$/.test(path)) return { program: argNodes(cur)[0] ?? null, args: args.reverse() };
    if (!recv) return null;
    if (name === "arg") { const a = argNodes(cur)[0]; if (a) args.push(a); }
    else if (name === "args") { const a = argNodes(cur)[0]; if (a) args.push(...listElements(a).reverse()); }
    cur = unwrapExpr(recv);
  }
  if (cur?.type === "identifier") {
    const st = ctx.cmdVars.get(cur.text);
    if (st) return { program: st.program, args: [...st.args, ...args.reverse()] };
  }
  return null;
}
function trackCommand(name: string, value: SyntaxNode, ctx: EngineCtx) {
  const st = commandChain(value, ctx);
  if (st) ctx.cmdVars.set(name, st);
}
function appendCommandArgs(name: string, call: SyntaxNode, ctx: EngineCtx) {
  const st = ctx.cmdVars.get(name);
  if (!st) return;
  const { name: m } = callParts(call);
  const a = argNodes(call)[0];
  if (!a) return;
  if (m === "arg") st.args.push(a);
  else st.args.push(...listElements(a));
}
function listElements(n: SyntaxNode): SyntaxNode[] {
  const c = unwrapExpr(n);
  if (c.type === "array_expression") return named(c);
  if (c.type === "macro_invocation" && macroName(c) === "vec") return macroArgs(c).args;
  return [c];
}

// ── Sinks ──────────────────────────────────────────────────────────────────────────────────────────────────

/** The operand carrying the taint inside a composite value (a format! argument, one side of `+`). */
function culpritOf(src: SyntaxNode, cls: number, env: Env, mask: TaintMaskFn): SyntaxNode {
  const n = unwrapExpr(src);
  if (n.type === "macro_invocation") {
    const parts = formatParts(n);
    for (const p of parts ?? []) if (p.kind === "opaque" && (mask(p.node, env) & cls)) return culpritOf(p.node, cls, env, mask);
  }
  if (n.type === "binary_expression" && operatorOf(n) === "+") {
    for (const side of [field(n, "left"), field(n, "right")]) if (side && (mask(side, env) & cls)) return culpritOf(side, cls, env, mask);
  }
  return n;
}

function fireOn(ctx: EngineCtx, id: AstTaintRustId, at: SyntaxNode, source: SyntaxNode, m: number, sinkExpr: string, detail?: string): boolean {
  const cls = classOf(id);
  if (m & cls) {
    const culprit = ctx.refine ? ctx.refine(source, cls) : source;
    emit(ctx, id, at, culprit.text, sinkExpr, detail);
    return true;
  }
  if (wasCleared(m, cls)) ctx.suppressed?.push({ id, line: lineOf(at) });
  return false;
}

function lastAssignment(name: string, at: SyntaxNode): SyntaxNode | null {
  let scope: SyntaxNode | null = enclosingScope(at);
  if (!scope) { scope = at; while (scope.parent) scope = scope.parent; }
  let best: SyntaxNode | null = null;
  const visit = (n: SyntaxNode) => {
    if (n.startIndex >= at.startIndex) return;
    if (n !== scope && n.type === "function_item") return;
    if (n.type === "let_declaration" && field(n, "pattern")?.type === "identifier" && field(n, "pattern")!.text === name) best = field(n, "value");
    if (n.type === "assignment_expression" && field(n, "left")?.text === name) best = field(n, "right");
    for (const c of named(n)) visit(c);
  };
  visit(scope);
  return best;
}

/** A Rust string expression as literal text and value parts (format!, `+`, `&`, `.as_str()`, one variable hop). */
function decomposeString(node: SyntaxNode, depth = 0): UrlPart<SyntaxNode>[] {
  const n = unwrapExpr(node);
  const lit = stringValue(n);
  if (lit !== null) return [{ kind: "literal", text: lit }];
  if (n.type === "macro_invocation") { const p = formatParts(n); if (p) return p; }
  if (n.type === "binary_expression" && operatorOf(n) === "+") {
    const l = field(n, "left"), r = field(n, "right");
    if (l && r) return [...decomposeString(l, depth), ...decomposeString(r, depth)];
  }
  if (n.type === "call_expression") {
    const { name, recv, path } = callParts(n);
    if (recv && /^(?:as_str|to_string|to_owned|as_ref|clone|into|unwrap)$/.test(name)) return decomposeString(recv, depth);
    if (path && /(?:^|::)(?:String::from|Url::parse|Uri::from_str|Uri::try_from|Path::new|PathBuf::from)$/.test(path)) { const a = argNodes(n)[0]; if (a) return decomposeString(a, depth); }
  }
  if (n.type === "try_expression") return decomposeString(named(n)[0]!, depth);
  if (n.type === "identifier" && depth < 3) {
    const v = lastAssignment(n.text, n);
    if (v) return decomposeString(v, depth + 1);
  }
  return [{ kind: "opaque", node: n }];
}

function isDbReceiver(recv: SyntaxNode, ctx: EngineCtx): boolean {
  const base = unwrapExpr(recv);
  const text = chainText(base);
  const last = text.split(/[.:]/).pop() ?? "";
  if (base.type === "identifier") {
    const t = ctx.varTypes.get(base.text);
    if (t && DB_TYPE_RE.test(t)) return true;
  }
  return DB_RECEIVER_RE.test(last) || /(?:get_ref|lock|get|acquire|begin|transaction|conn|connection)$/.test(last) && /db|pool|conn|tx/i.test(text);
}

function isHttpClient(recv: SyntaxNode, ctx: EngineCtx): boolean {
  const base = unwrapExpr(recv);
  if (base.type === "identifier") {
    const t = ctx.varTypes.get(base.text);
    if (t) return HTTP_CLIENT_TYPE_RE.test(t);
    return /client|http|agent/i.test(base.text);
  }
  const t = chainText(base);
  return /(?:reqwest::)?Client::new$|Client::builder.*\.build|client$|http$/i.test(t);
}

function checkSsrfArg(ctx: EngineCtx, at: SyntaxNode, arg: SyntaxNode, env: Env, mask: TaintMaskFn, sink: string) {
  const verdict = assessSsrfUrl(decomposeString(arg), n => mask(n, env));
  if (verdict.verdict === "vulnerable") emit(ctx, "ssrf", at, culpritOf(verdict.culprit ?? arg, SinkClass.SSRF, env, mask).text, sink);
  else if (verdict.verdict === "no-taint") fireOn(ctx, "ssrf", at, arg, mask(arg, env), sink);
  else ctx.suppressed?.push({ id: "ssrf", line: lineOf(at) });
}
function checkRedirect(ctx: EngineCtx, at: SyntaxNode, arg: SyntaxNode, env: Env, mask: TaintMaskFn, sink: string) {
  const verdict = assessSsrfUrl(decomposeString(arg), n => mask(n, env));
  if (verdict.verdict === "safe") { ctx.suppressed?.push({ id: "open-redirect", line: lineOf(at) }); return; }
  fireOn(ctx, "open-redirect", at, verdict.verdict === "vulnerable" ? verdict.culprit ?? arg : arg, verdict.verdict === "vulnerable" ? ALL : mask(arg, env), sink);
}
function checkSql(ctx: EngineCtx, at: SyntaxNode, arg: SyntaxNode, env: Env, mask: TaintMaskFn, sink: string) {
  const verdict = assessSqlInjection(decomposeString(arg), n => mask(n, env));
  if (verdict.verdict === "vulnerable" && verdict.escaped) {
    emit(ctx, "sql-injection", at, verdict.culprit!.text, sink, `Escaped value '${verdict.culprit!.text}' is placed outside a quoted SQL string literal — string-escaping only protects a value inside quotes`);
  } else {
    fireOn(ctx, "sql-injection", at, arg, mask(arg, env), sink);
  }
}

/** Does the response chain this call ends declare HTML (`content_type("text/html")`, `ContentType::html()`)? */
const HTML_CHAIN_RE = /text\/html|ContentType::html|mime::TEXT_HTML|TEXT_HTML/;

function checkCallSink(node: SyntaxNode, env: Env, ctx: EngineCtx, mask: TaintMaskFn) {
  ctx.refine = (src, cls) => culpritOf(src, cls, env, mask);
  const { name, recv, path } = callParts(node);
  const args = argNodes(node);
  const full = path ? resolvePath(path, ctx) : "";
  const two = full ? lastTwo(full) : "";
  const recvText = recv ? chainText(recv) : "";

  // ── SQL ──
  if (full && (SQLX_FNS.test(full) && /sqlx/.test(full + ctx.content.slice(0, 4000)) || /QueryBuilder::new$/.test(full))) {
    if (args[0]) checkSql(ctx, node, args[0], env, mask, two || full);
  }
  if (full && DIESEL_SQL_FNS.test(full) && /diesel/.test(full + ctx.content.slice(0, 4000)) && args[0]) checkSql(ctx, node, args[0], env, mask, two || full);
  if (full && /(?:^|::)Statement::from_string$/.test(full) && args[1]) checkSql(ctx, node, args[1], env, mask, "Statement::from_string");
  if (recv && DB_METHODS.has(name) && args[0] && isDbReceiver(recv, ctx)) checkSql(ctx, node, args[0], env, mask, `${recvText.split(".").pop()}.${name}`);
  // a store's own query helper (`db.query_users(&sql)`): SQL when the argument is SQL text built in this function
  else if (recv && /^(?:query|execute|exec|run)_\w+$/.test(name) && args[0] && isDbReceiver(recv, ctx) && sqlTextNearby(args[0], node)) {
    checkSql(ctx, node, args[0], env, mask, `${recvText.split(".").pop()}.${name}`);
  }
  if (recv && name === "push" && args[0] && /QueryBuilder/.test(ctx.varTypes.get(unwrapExpr(recv).text) ?? chainText(recv))) checkSql(ctx, node, args[0], env, mask, "QueryBuilder.push");

  // ── Command ──
  if (full && /(?:^|::)Command::new$/.test(full) && args[0]) {
    fireOn(ctx, "command-injection", node, args[0], mask(args[0], env), "Command::new");
  }
  if (recv && (name === "arg" || name === "args") && args[0]) {
    const chain = commandChain(node, ctx);
    if (chain) {
      const program = chain.program ? stringValue(chain.program) : null;
      const lits = chain.args.map(a => stringValue(a));
      const shellAt = program !== null && SHELL_PROGRAMS.test(program) ? lits.findIndex(s => s !== null && SHELL_COMMAND_FLAGS.test(s)) : -1;
      const endOfOptions = lits.findIndex(s => s === "--");
      const added = name === "arg" ? [args[0]] : listElements(args[0]);
      for (const a of added) {
        const idx = chain.args.findIndex(x => x.id === a.id && x.tree === a.tree);
        const pos = idx >= 0 ? idx : chain.args.length;
        if (shellAt >= 0 && pos > shellAt) { if (fireOn(ctx, "command-injection", node, a, mask(a, env), `${program} -c`)) break; continue; }
        if (endOfOptions >= 0 && pos > endOfOptions) continue;
        if (program !== null && OPTION_SAFE_PROGRAMS.test(program)) continue;
        const m = mask(a, env);
        // attacker-chosen AND still able to start with "-" (a number, an allowlisted word or a "-"-free alphabet can not)
        if ((m & SinkClass.CONTROL) && (m & SinkClass.CMD)) { emit(ctx, "argument-injection", node, culpritOf(a, ALL, env, mask).text, "Command.arg", `Request input '${a.text.slice(0, 60)}' is passed as an argument to ${program ?? "a command"} — no shell runs, but a value starting with '-' becomes an option; put "--" before it or validate it`); break; }
      }
    }
  }

  // ── Path ──
  if (full && FS_FIRST_ARG.test(full) && args[0]) fireOn(ctx, "path-traversal", node, args[0], mask(args[0], env), two);
  if (full && FS_TWO_ARGS.test(full)) for (const a of args.slice(0, 2)) if (fireOn(ctx, "path-traversal", node, a, mask(a, env), two)) break;
  if (recv && name === "open" && args[0] && /OpenOptions/.test(recvText)) fireOn(ctx, "path-traversal", node, args[0], mask(args[0], env), "OpenOptions.open");

  // ── SSRF ──
  if (full && HTTP_FREE_FNS.test(full.replace(/^std::net::/, "")) && args[0]) checkSsrfArg(ctx, node, args[0], env, mask, full);
  if (recv && HTTP_CLIENT_METHODS.has(name) && isHttpClient(recv, ctx)) {
    const urlArg = name === "request" ? args[1] : args[0];
    if (urlArg) checkSsrfArg(ctx, node, urlArg, env, mask, `${recvText}.${name}`);
  }
  if (recv && name === "uri" && args[0] && /Request::builder|Request::get|Request::post|builder\(\)/.test(recv.text)) checkSsrfArg(ctx, node, args[0], env, mask, "Request::builder().uri");

  // ── Redirect ──
  if (full && REDIRECT_FNS.test(full) && args[0]) checkRedirect(ctx, node, args[0], env, mask, two);
  if (recv && /^(?:append_header|insert_header|header)$/.test(name) && args.length >= 1) {
    const tuple = args.length === 1 && unwrapExpr(args[0]).type === "tuple_expression" ? named(unwrapExpr(args[0])) : args;
    const [k, v] = tuple;
    if (k && v && (/LOCATION$/.test(k.text) || /^location$/i.test(stringValue(k) ?? ""))) checkRedirect(ctx, node, v, env, mask, `${name}(LOCATION)`);
  }

  // ── XSS ──
  if (!recv && path && /^(?:Html|RawHtml)$/.test(path.split("::").pop() ?? "") && args[0]) {
    fireOn(ctx, "xss", node, args[0], mask(args[0], env), path.split("::").pop()!);
  }
  if (recv && name === "body" && args[0] && (HTML_CHAIN_RE.test(recv.text) || htmlLiteralWithTaint(args[0], env, mask))) {
    fireOn(ctx, "xss", node, args[0], mask(args[0], env), "response.body (HTML)");
  }

  if (!recv && path && /(?:^|::)PreEscaped$/.test(path) && args[0]) fireOn(ctx, "xss", node, args[0], mask(args[0], env), "maud::PreEscaped");

  // ── More SQL builders: sea-query custom expressions, sea-orm raw statements ──
  if (full && /(?:^|::)(?:Expr|SimpleExpr)::(?:cust|cust_with_values|cust_with_exprs|Custom)$/.test(full) && args[0]) checkSql(ctx, node, args[0], env, mask, two);
  if (full && /(?:^|::)Statement::from_sql_and_values$/.test(full) && args[1]) checkSql(ctx, node, args[1], env, mask, "Statement::from_sql_and_values");

  // ── More command runners: subprocess, duct ──
  if (full && /(?:^|::)Exec::shell$/.test(full) && args[0]) fireOn(ctx, "command-injection", node, args[0], mask(args[0], env), "subprocess::Exec::shell");
  if (full && /(?:^|::)Exec::cmd$/.test(full) && args[0]) fireOn(ctx, "command-injection", node, args[0], mask(args[0], env), "subprocess::Exec::cmd");
  if (full && /(?:^|::)duct::cmd$/.test(full) && args[0]) fireOn(ctx, "command-injection", node, args[0], mask(args[0], env), "duct::cmd");
  if (full && /(?:^|::)duct_sh::sh_dangerous$/.test(full) && args[0]) fireOn(ctx, "command-injection", node, args[0], mask(args[0], env), "duct_sh::sh_dangerous");

  // ── Insecure deserialization: unbounded bincode (allocation bombs), pickle ──
  if (full && /(?:^|::)bincode::(?:deserialize|deserialize_from|decode_from_slice|decode_from_std_read)$/.test(full) && args[0] && !/with_limit|limit::</.test(ctx.content)) {
    fireOn(ctx, "insecure-deserialization", node, args[0], mask(args[0], env), two,
      `Request bytes '${args[0].text.slice(0, 60)}' are decoded by ${two} with no size limit — a forged length prefix allocates gigabytes; use bincode::options().with_limit(...) (or config::standard().with_limit::<N>())`);
  }
  if (full && /(?:^|::)serde_pickle::(?:from_slice|from_reader|value_from_slice|value_from_reader)$/.test(full) && args[0]) {
    fireOn(ctx, "insecure-deserialization", node, args[0], mask(args[0], env), two);
  }

  // ── XPath ──
  if (full && /(?:^|::)evaluate_xpath$/.test(full) && args[1] && /sxd_xpath/.test(ctx.content)) fireOn(ctx, "xpath-injection", node, args[1], mask(args[1], env), "sxd_xpath::evaluate_xpath");
  if (recv && name === "build" && args[0] && /sxd_xpath/.test(ctx.content) && /Factory/.test(ctx.varTypes.get(unwrapExpr(recv).text) ?? recvText)) {
    fireOn(ctx, "xpath-injection", node, args[0], mask(args[0], env), "xpath Factory.build");
  }
  if (recv && /^(?:evaluate|findnodes|findvalues|node_evaluate)$/.test(name) && args[0] && /libxml/.test(ctx.content) &&
      (name !== "evaluate" || /ctx|context|xpath/i.test(recvText + (ctx.varTypes.get(unwrapExpr(recv).text) ?? "")))) {
    fireOn(ctx, "xpath-injection", node, args[0], mask(args[0], env), `libxml .${name}`);
  }

  // ── Header injection: only the unchecked constructors skip the CR/LF validation ──
  if (full && /(?:^|::)HeaderValue::(?:from_maybe_shared_unchecked|from_bytes_unchecked|from_shared_unchecked)$/.test(full) && args[0]) {
    fireOn(ctx, "header-injection", node, args[0], mask(args[0], env), two,
      `Request input '${args[0].text.slice(0, 60)}' becomes a header value through ${two}, which skips the CR/LF check — use HeaderValue::from_str`);
  }

  // ── Mass assignment ──
  checkMassAssignment(node, name, recv, full, args, env, ctx, mask);

  // ── Template injection ──
  if (full && /(?:^|::)Tera::one_off$/.test(full) && args[0]) fireOn(ctx, "ssti", node, args[0], mask(args[0], env), "Tera::one_off");
  if (recv && /^(?:render_str|render_template|template_from_str)$/.test(name) && args[0]) fireOn(ctx, "ssti", node, args[0], mask(args[0], env), `.${name}`);
  if (recv && /^(?:add_raw_template|register_template_string|add_template|add_template_owned)$/.test(name) && args[1]) fireOn(ctx, "ssti", node, args[1], mask(args[1], env), `.${name}`);

  // ── Code execution ──
  if (recv && /^(?:eval|eval_expression|run|compile|eval_with_scope|run_with_scope|compile_expression)$/.test(name) && args[0] &&
      (/^(?:Engine|Context|Lua|JsRuntime)$/.test(ctx.varTypes.get(unwrapExpr(recv).text) ?? "") || /engine|rhai|lua|js|script|runtime|context/i.test(recvText))) {
    const src = name.endsWith("_with_scope") ? args[1] ?? args[0] : args[0];
    fireOn(ctx, "eval-exec", node, src, mask(src, env), `${recvText}.${name}`);
  }
  if (recv && name === "load" && args[0] && /lua/i.test(recvText)) fireOn(ctx, "eval-exec", node, args[0], mask(args[0], env), "Lua.load");
  if (recv && name === "execute_script" && args[1]) fireOn(ctx, "eval-exec", node, args[1], mask(args[1], env), "JsRuntime.execute_script");

  // ── ReDoS (backtracking engine only) ──
  if (full && /fancy_regex::Regex::new$|^fancy_regex::Regex::new/.test(full) && args[0]) {
    const m = mask(args[0], env);
    if (m & ALL) emit(ctx, "redos", node, culpritOf(args[0], ALL, env, mask).text, "fancy_regex::Regex::new");
  }

  // ── NoSQL ──
  if (recv && /^(?:find|find_one|delete_one|delete_many|update_one|update_many|count_documents|find_one_and_update|find_one_and_delete|aggregate)$/.test(name) && args[0] &&
      /collection|coll|users|db/i.test(recvText)) {
    fireOn(ctx, "nosql-injection", node, args[0], mask(args[0], env), `${recvText}.${name}`);
  }

  // ── LDAP ──
  if (recv && name === "search" && args.length >= 3 && /ldap/i.test(recvText)) fireOn(ctx, "ldap-injection", node, args[2], mask(args[2], env), "ldap.search");

  // ── Timing attack ──
  if (recv && name === "eq" && args[0]) checkTimingCompare(node, recv, args[0], env, ctx, mask);

  // ── Weak digest ──
  if (full && /(?:^|::)(?:md5::compute|Md5::new|Md5::digest|Sha1::new|Sha1::digest|md5::Md5::new|sha1::Sha1::new)$/.test(full)) {
    emit(ctx, "weak-crypto", node, two, two, `${two} is a broken/weak hash — use SHA-256+ (and argon2/bcrypt for passwords)`);
  }

  // ── JWT accepted without its signature ──
  if ((recv && name === "insecure_disable_signature_validation") || (full && /(?:^|::)(?:dangerous_insecure_decode|dangerous_insecure_decode_with_validation|insecure_decode)$/.test(full))) {
    emit(ctx, "jwt-none-alg", node, "token", name, "The JWT's signature is not verified (insecure_disable_signature_validation / insecure decode) — its claims are attacker-controlled; decode with a key and Validation");
  }
}

/**
 * Privileged fields a client can set on a struct deserialized from the request: the field names PRIVILEGED_FIELD_RE
 * lists, minus those serde never reads (`#[serde(skip)]`, `skip_deserializing`).
 */
function privilegedFields(structName: string, ctx: EngineCtx): string[] {
  const s = findAllNodes(ctx.root, "struct_item").find(x => field(x, "name")?.text === structName);
  const list = s ? named(s).find(c => c.type === "field_declaration_list") : null;
  if (!list) return [];
  const out: string[] = [];
  let skipped = false;
  for (const c of named(list)) {
    if (c.type === "attribute_item") { if (/serde\s*\([^)]*\bskip(?:_deserializing)?\b/.test(c.text)) skipped = true; continue; }
    if (c.type !== "field_declaration") continue;
    const fname = field(c, "name")?.text ?? "";
    if (!skipped && PRIVILEGED_FIELD_RE.test(fname)) out.push(fname);
    skipped = false;
  }
  return out;
}

/**
 * Mass assignment: the deserialized request body written to the database as-is -- diesel
 * `insert_into(t).values(&body)` / `update(t).set(&body)`, sea-orm `ActiveModel::from_json(json)` /
 * `.set_from_json(json)`. For a typed body it fires only when the struct carries a privileged field.
 */
function checkMassAssignment(node: SyntaxNode, name: string, recv: SyntaxNode | null, full: string, args: SyntaxNode[], env: Env, ctx: EngineCtx, mask: TaintMaskFn) {
  const arg = args[0];
  if (!arg || !(mask(arg, env) & ALL)) return;
  const dieselWrite = recv && ((name === "values" && /\b(?:insert_into|replace_into|insert_or_ignore_into)\s*\(/.test(recv.text))
    || (name === "set" && /\bupdate\s*\(/.test(recv.text) && /diesel/.test(ctx.content)));
  if (dieselWrite) {
    // the value must BE the deserialized body (an extractor, or `let b: T = serde_json::from_str(..)`), not a
    // struct the handler built from it -- that one sets its privileged fields itself
    const deserialized = (i: SyntaxNode) => {
      const v = lastAssignment(i.text, i);
      return !!v && ctx.varTypes.has(i.text) && /serde_json::from_(?:str|slice|value|reader)\b/.test(v.text);
    };
    const id = findAllNodes(arg, "identifier").find(i => ctx.bodyTypes.has(i.text) || deserialized(i));
    const t = id ? ctx.bodyTypes.get(id.text) ?? ctx.varTypes.get(id.text)! : "";
    const fields = t ? privilegedFields(t, ctx) : [];
    if (fields.length) {
      emit(ctx, "mass-assignment", node, arg.text, `diesel .${name}()`,
        `The request body '${arg.text.slice(0, 60)}' (${t}) is written with .${name}() as-is — the client can set ${fields.join(", ")}; deserialize into a struct without those fields, or set them server-side`);
    }
    return;
  }
  const seaOrm = (full && /(?:^|::)ActiveModel::from_json$/.test(full)) || (recv && name === "set_from_json");
  if (seaOrm) {
    emit(ctx, "mass-assignment", node, arg.text, name,
      `Request JSON '${arg.text.slice(0, 60)}' sets every column of the ActiveModel through ${name} — the client can set privileged columns (role, owner, ...); copy only the fields it may change`);
  }
}

/** Macro-level sinks: doc! with $where, sqlx raw macros are safe (checked at compile time). */
function checkMacroSink(node: SyntaxNode, env: Env, ctx: EngineCtx, mask: TaintMaskFn) {
  const name = macroName(node);
  if (name === "doc" && /"\$where"/.test(node.text)) {
    const m = findAllNodes(node, "identifier").reduce((acc, i) => acc | mask(i, env), 0);
    if (m & ALL) emit(ctx, "nosql-injection", node, node.text.slice(0, 60), "doc! { \"$where\": ... }", "Request input is placed in a MongoDB $where clause — it runs as JavaScript on the server; use query operators instead");
  }
  // maud: `html! { (PreEscaped(body)) }` -- the macro body is a token tree, so the call is matched by its tokens
  if (name === "html" && /\bPreEscaped\s*\(/.test(node.text)) {
    const ids = findAllNodes(node, "identifier");
    for (let i = 0; i < ids.length; i++) {
      if (ids[i].text !== "PreEscaped") continue;
      const tt = ids[i].nextSibling;
      if (!tt || tt.type !== "token_tree") continue;
      const m = findAllNodes(tt, "identifier").reduce((acc, x) => acc | mask(x, env), 0);
      if (fireOn(ctx, "xss", node, tt, m, "maud::PreEscaped")) break;
    }
  }
}

function htmlLiteralWithTaint(arg: SyntaxNode, env: Env, mask: TaintMaskFn): boolean {
  const parts = decomposeString(arg);
  const literal = parts.filter(p => p.kind === "literal").map(p => (p as { text: string }).text).join("");
  return HTML_TAG_RE.test(literal) && parts.some(p => p.kind === "opaque" && (mask(p.node, env) & SinkClass.XSS));
}

function checkTimingCompare(node: SyntaxNode, l: SyntaxNode, r: SyntaxNode, env: Env, ctx: EngineCtx, mask: TaintMaskFn) {
  const nameOf = (n: SyntaxNode): string => {
    const c = unwrapExpr(n);
    return c.type === "identifier" ? c.text : c.type === "field_expression" ? field(c, "field")?.text ?? ""
      : c.type === "call_expression" ? (callParts(c).recv ? nameOf(callParts(c).recv!) : callParts(c).name) : "";
  };
  for (const [secret, other] of [[l, r], [r, l]] as const) {
    const nm = nameOf(secret);
    if (nm && SECRET_NAME_RE.test(nm) && !isLiteral(unwrapExpr(other)) && (mask(other, env) & ALL) && !(mask(secret, env) & ALL)) {
      emit(ctx, "timing-attack", node, other.text, nm, `'${other.text.slice(0, 60)}' is compared to ${nm} with == — use a constant-time comparison (subtle::ConstantTimeEq / constant_time_eq)`);
      return;
    }
  }
}

// ── Same-file helpers (re-walk with seeded parameters) ────────────────────────────────────────────────────

function seedLocalFn(node: SyntaxNode, env: Env, ctx: EngineCtx, mask: TaintMaskFn) {
  const { name, recv, path } = callParts(node);
  if (recv && recv.type !== "self") return;
  if (path && path.includes("::") && !/^(?:Self|self)::/.test(path)) return;
  const callee = ctx.fns.get(name);
  if (!callee?.body) return;
  const tainted = new Map<number, number>();
  for (const p of callee.params) {
    const a = bindArgument(node, p.index);
    const m = a ? mask(a, env) & ALL : 0;
    if (m) tainted.set(p.index, m);
  }
  if (tainted.size === 0) return;
  const existing = ctx.seeded.get(callee.name) ?? new Map<number, number>();
  for (const [i, m] of tainted) existing.set(i, (existing.get(i) ?? 0) | m);
  ctx.seeded.set(callee.name, existing);
}

// ── Cross-file calls ──────────────────────────────────────────────────────────────────────────────────────

/** The type a receiver expression has: a typed local/param, `self.field`, `state.field` of a same-file struct. */
function typeOfExpr(n: SyntaxNode, ctx: EngineCtx): string | null {
  const c = unwrapExpr(n);
  if (c.type === "identifier") return ctx.varTypes.get(c.text) ?? null;
  if (c.type === "field_expression") {
    const base = field(c, "value");
    const f = field(c, "field")?.text;
    const bt = base?.type === "self" ? ctx.current?.implType ?? null : base ? typeOfExpr(base, ctx) : null;
    return bt && f ? ctx.structFields.get(`${bt}.${f}`) ?? null : null;
  }
  if (c.type === "call_expression") {
    const { name, recv } = callParts(c);
    if (recv && /^(?:clone|as_ref|get_ref|into_inner|lock|read|write|unwrap|deref)$/.test(name)) return typeOfExpr(recv, ctx);
  }
  return null;
}

function callKeys(node: SyntaxNode, env: Env, ctx: EngineCtx): string[] {
  const { name, recv, path } = callParts(node);
  if (!name) return [];
  if (recv) {
    if (recv.type === "self") return [];
    const t = typeOfExpr(recv, ctx);
    return t ? [`${t}.${name}`] : [];
  }
  if (!path) return [];
  const segs = resolvePath(path, ctx).split("::");
  // `find(x)` resolves only through a `use` import (a bare name with no import is local or a prelude function)
  if (segs.length === 1 || env.has(name)) return [];
  return [`${segs[segs.length - 2]}::${name}`];
}

function checkCrossFileCall(node: SyntaxNode, env: Env, ctx: EngineCtx, mask: TaintMaskFn) {
  if (!ctx.crossFileFacts?.size) return;
  const key = callKeys(node, env, ctx).find(k => ctx.crossFileFacts!.has(k));
  if (!key || ctx.localKeys.has(key)) return;
  const facts = ctx.crossFileFacts.get(key)!;
  const args = argNodes(node);
  const line = lineOf(node);
  for (const fact of facts) {
    const bound = fact.isRest ? args.slice(fact.index) : args[fact.index] ? [args[fact.index]] : [];
    for (const a of bound) {
      const m = mask(a, env);
      if (!(m & fact.sinkClass)) { if (wasCleared(m, fact.sinkClass)) ctx.suppressed?.push({ id: fact.id, line }); continue; }
      const dedup = `${fact.id}:${line}`;
      if (ctx.seen.has(dedup)) break;
      ctx.seen.add(dedup);
      const display = displayFnName(key);
      const via = fact.via.length > 1 ? ` (${fact.via.map(displayFnName).join(" -> ")})` : "";
      const source = culpritOf(a, fact.sinkClass, env, mask).text;
      const callerTrace = buildBackwardTraceGeneric(ctx.filePath, node, source, display, rustTraceResolver);
      callerTrace[callerTrace.length - 1] = { ...callerTrace[callerTrace.length - 1], snippet: `${display}(...)` };
      ctx.findings.push({
        id: fact.id as AstTaintRustId, line, sourceExpr: source, sinkExpr: `${display}() -> ${fact.sinkExpr}`,
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
  for (let cur = node.parent; cur; cur = cur.parent) if (cur.type === "function_item" || cur.type === "closure_expression") return cur;
  return null;
}
function assignmentsIn(scope: SyntaxNode): Array<{ name: string; position: number; rhsText: string; line: number }> {
  const out: Array<{ name: string; position: number; rhsText: string; line: number }> = [];
  const visit = (n: SyntaxNode) => {
    if (n !== scope && n.type === "function_item") return;
    if (n.type === "let_declaration") {
      const p = field(n, "pattern"), v = field(n, "value");
      if (p && v) for (const i of findAllNodes(p, "identifier")) if (!isTypePosition(i)) out.push({ name: i.text, position: n.startIndex, rhsText: v.text, line: lineOf(v) });
    }
    if (n.type === "assignment_expression" || n.type === "compound_assignment_expr") {
      const l = field(n, "left"), r = field(n, "right");
      if (l?.type === "identifier" && r) out.push({ name: l.text, position: n.startIndex, rhsText: r.text, line: lineOf(r) });
    }
    for (const c of named(n)) visit(c);
  };
  visit(scope);
  return out;
}
const rustTraceResolver: TraceResolver<SyntaxNode> = {
  enclosingScope, assignmentsIn,
  fileScope: n => { let c = n; while (c.parent) c = c.parent; return c; },
  position: n => n.startIndex, line: lineOf, text: n => n.text,
};

// ── Interprocedural summaries ─────────────────────────────────────────────────────────────────────────────

function returnMask(fn: LocalFn, ctx: EngineCtx, seed: ParamShape | null): number {
  if (!fn.body) return 0;
  let surviving = 0;
  const walker = createWalker({ ...ctx, findings: [], seen: new Set(), suppressed: undefined, seeded: new Map(), cmdVars: new Map(), current: null },
    { descendClosures: false, onReturn: (expr, env, mask) => { if (expr) surviving |= mask(expr, env); } });
  const env: Env = new Map();
  for (const p of fn.params) for (const n of p.names) env.set(n, seed && p.index === seed.index ? ALL : 0);
  const terminated = walker.walk(fn.body, env);
  if (!terminated) surviving |= walker.mask(fn.body, env);
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

// ── Handlers and their sources ────────────────────────────────────────────────────────────────────────────

function routeAttr(fn: LocalFn): SyntaxNode | null {
  return fn.attrs.find(a => ROUTE_ATTRS.test(attrName(a))) ?? null;
}
function isHandler(fn: LocalFn): boolean {
  return !!routeAttr(fn) || fn.params.some(p => EXTRACTOR_TYPES.has(outerType(p.type)) || REQUEST_TYPES.has(coreType(p.type)));
}
/** Rocket: names bound by the route (`#[get("/<name>?<q>")]`). */
function rocketParams(fn: LocalFn): Set<string> {
  const a = routeAttr(fn);
  const lit = a ? findAllNodes(a, "string_literal")[0] : null;
  const route = lit ? stringValue(lit) ?? "" : "";
  return new Set([...route.matchAll(/<([A-Za-z_]\w*)(?:\.\.)?>/g)].map(m => m[1]));
}

/** Parameter masks at a function's entry. */
function entryEnv(fn: LocalFn, seedEntryPoints: boolean, ctx: EngineCtx): Env {
  const env: Env = new Map();
  const handler = isHandler(fn);
  const rocket = rocketParams(fn);
  for (const p of fn.params) {
    const outer = outerType(p.type);
    const core = coreType(p.type);
    let m = 0;
    if (EXTRACTOR_TYPES.has(outer)) {
      const inner = typeArg(p.type);
      const scalar = inner && (SCALAR_TYPE_RE.test(coreType(inner)) || (inner.type === "tuple_type" && named(inner).every(t => SCALAR_TYPE_RE.test(coreType(t)))));
      m = scalar ? applyClears(ALL, NUMERIC_CLEARS) : ALL;
    } else if (rocket.has(p.name)) {
      m = SCALAR_TYPE_RE.test(core) ? applyClears(ALL, NUMERIC_CLEARS) : ALL;
    } else if (handler && /^(?:String|Bytes|Vec)$/.test(core) && !p.names.some(n => /^(?:state|app|pool|db|config|cfg)$/.test(n))) {
      m = ALL;   // the request body as a String / Bytes extractor
    } else if (ctx.warpHandlers.has(fn.name) && !WARP_STATE_NAME_RE.test(p.name) && !WARP_STATE_TYPE_RE.test(core) && !DB_TYPE_RE.test(core)) {
      // warp hands a handler the values its filters extracted -- except shared state injected with `warp::any().map(...)`
      m = SCALAR_TYPE_RE.test(core) ? applyClears(ALL, NUMERIC_CLEARS) : ALL;
    } else if (seedEntryPoints && /^(?:str|String)$/.test(core)) {
      m = ALL;
    }
    for (const n of p.names) env.set(n, m);
    if (core && (p.pattern?.type === "identifier" || p.names.length === 1)) ctx.varTypes.set(p.name, core);
  }
  return env;
}

// ── BOLA (writes by a request-chosen id, no ownership evidence) ───────────────────────────────────────────

const ID_NAME_RE = /^(?:id|pk|uuid|.*_id|.*Id)$/;
const OWNER_COLUMN_RE = /\b(?:user_id|owner_id|author_id|account_id|tenant_id|org_id|organization_id|created_by|owner|creator_id)\b/i;
const PRINCIPAL_TYPE_RE = /User|Claims|Identity|Session|Principal|Auth|CurrentUser|Jwt|Token/;

function collectBola(fn: LocalFn, ctx: EngineCtx) {
  if (!fn.body || !isHandler(fn)) return;
  const rocket = rocketParams(fn);
  const ids = new Set<string>();
  for (const p of fn.params) {
    if (outerType(p.type) === "Path" || rocket.has(p.name)) for (const n of p.names) if (ID_NAME_RE.test(n) || p.names.length === 1) ids.add(n);
  }
  if (ids.size === 0) return;
  const principals = new Set(fn.params.filter(p => !EXTRACTOR_TYPES.has(outerType(p.type)) || outerType(p.type) === "Extension").filter(p => PRINCIPAL_TYPE_RE.test(coreType(p.type))).flatMap(p => p.names));
  const body = fn.body;
  const mentionsId = (n: SyntaxNode) => findAllNodes(n, "identifier").some(i => ids.has(i.text)) || macroIdents(n).some(i => ids.has(i));
  const mentionsPrincipal = (t: string) => [...principals].some(p => new RegExp(`\\b${p}\\b`).test(t)) || /\bclaims\b|\bcurrent_user\b|\bsub\b|\bsession\b/.test(t);

  // ownership / role evidence anywhere in the handler: an owner field compared to the principal, an owner column
  // filter, or a guard call judged by name
  let evidence: AuthzKind | null = null;
  for (const b of findAllNodes(body, "binary_expression")) {
    if (!/^(?:==|!=)$/.test(operatorOf(b))) continue;
    const l = field(b, "left"), r = field(b, "right");
    if (!l || !r) continue;
    const owner = (n: SyntaxNode) => isOwnerField(n.text.split(".").pop()?.replace(/\(\)$/, "") ?? "") || OWNER_COLUMN_RE.test(n.text);
    if ((owner(l) && mentionsPrincipal(r.text)) || (owner(r) && mentionsPrincipal(l.text))) evidence = "ownership";
  }
  for (const c of findAllNodes(body, "call_expression")) {
    const k = classifyGuardName(callParts(c).name);
    if (k === "ownership" || (k === "role" && evidence === null)) evidence = k === "role" && argNodes(c).some(mentionsId) ? "ownership" : k;
    if (callParts(c).name === "filter" && OWNER_COLUMN_RE.test(c.text) && mentionsPrincipal(c.text)) evidence = "ownership";
  }
  if (evidence === "ownership") return;

  const report = (at: SyntaxNode, src: string, sink: string) => {
    const roleOnly = authzVerdict(new Set(evidence ? [evidence] : [])) === "role-only";
    emit(ctx, "bola-missing-ownership-check", at, src, sink,
      roleOnly
        ? `Resource identifier '${src}' selects the record ${sink} modifies behind a role check only — nothing establishes that the caller owns THIS record`
        : `Resource identifier '${src}' from the path selects the record ${sink} modifies, with no ownership check — add the owner to the WHERE clause (AND user_id = $n) or compare the record's owner to the authenticated user`,
      roleOnly ? "medium" : "high");
  };

  // raw SQL writes: UPDATE/DELETE ... WHERE id = $1 bound to the path id, no owner column
  for (const c of [...findAllNodes(body, "call_expression"), ...findAllNodes(body, "macro_invocation")]) {
    const sqlNode = c.type === "macro_invocation" ? macroArgs(c).args[0] : argNodes(c)[0];
    const sql = sqlNode ? stringValue(sqlNode) : null;
    if (!sql || !/^\s*(?:update|delete)\b/i.test(sql) || OWNER_COLUMN_RE.test(sql)) continue;
    // the statement and its binds: this call and the chain built on it (`.bind(id)`), or the macro's arguments
    let chainTop: SyntaxNode = c;
    while (chainTop.parent && /^(?:field_expression|call_expression|await_expression|try_expression)$/.test(chainTop.parent.type)) chainTop = chainTop.parent;
    if (!mentionsId(chainTop)) continue;
    report(c, [...ids].find(i => chainTop.text.includes(i)) ?? [...ids][0], sql.trim().split(/\s+/).slice(0, 3).join(" "));
  }
  // ORM writes: diesel::delete(t.find(id)) / diesel::update(t.find(id)) / Entity::delete_by_id(id)
  for (const c of findAllNodes(body, "call_expression")) {
    const { name, path, recv } = callParts(c);
    const full = path ? resolvePath(path, ctx) : "";
    const target = argNodes(c)[0];
    if (full && /(?:^|::)diesel::(?:delete|update)$|^(?:delete|update)$/.test(lastTwo(full)) && target && /\.find\(|\.filter\(/.test(target.text) && mentionsId(target) && !OWNER_COLUMN_RE.test(target.text)) {
      report(c, [...ids].find(i => target.text.includes(i)) ?? "id", `diesel::${name}`);
    }
    if (/^(?:delete_by_id|update_by_id)$/.test(name) && target && mentionsId(target) && (path || recv)) report(c, target.text, `${(path ?? chainText(recv)).split("::").slice(-2, -1)[0] ?? "Entity"}::${name}`);
  }
}
function macroIdents(n: SyntaxNode): string[] {
  return findAllNodes(n, "macro_invocation").flatMap(m => macroArgs(m).args.flatMap(a => findAllNodes(a, "identifier").map(i => i.text)));
}

// ── Entry points ──────────────────────────────────────────────────────────────────────────────────────────

function makeCtx(content: string, filePath: string, root: SyntaxNode, suppressed?: SuppressedSink[],
  crossFileFacts?: ReadonlyMap<string, readonly ParamSinkFact[]>): EngineCtx {
  const moduleName = moduleNameOf(filePath);
  const all = collectFns(root, moduleName);
  const fns = new Map<string, LocalFn>();
  for (const f of all) if (!fns.has(f.name)) fns.set(f.name, f);
  const ctx: EngineCtx = {
    filePath, content, lines: content.split("\n"), root, fns, propagating: new Map(), intrinsic: new Map(), seeded: new Map(),
    suppressed, findings: [], seen: new Set(), varTypes: new Map(), structFields: collectStructFields(root),
    imports: collectImports(root), cmdVars: new Map(), crossFileFacts,
    localKeys: new Set(all.flatMap(f => [f.key, ...f.altKeys]).filter((k): k is string => !!k)), current: null, moduleName,
    warpHandlers: warpHandlersOf(root, content, fns), bodyTypes: new Map(),
  };
  // `svc: Arc<UserService>` and `State(svc): State<Arc<UserService>>` both type svc as UserService
  for (const f of all) for (const p of f.params) { const t = coreType(p.type); if (t && (p.pattern?.type === "identifier" || p.names.length === 1) && !ctx.varTypes.has(p.name)) ctx.varTypes.set(p.name, t); }
  // The struct a request body was deserialized into: `Json(user): Json<NewUser>`, `form: web::Form<Signup>`, or a warp
  // handler's `body: NewUser` -- what mass assignment checks for privileged fields.
  for (const f of all) for (const p of f.params) {
    const inner = BODY_EXTRACTORS.has(outerType(p.type)) ? typeArg(p.type) : ctx.warpHandlers.has(f.name) ? p.type : null;
    const t = inner ? coreType(inner) : "";
    if (t && p.names.length === 1) ctx.bodyTypes.set(p.names[0], t);
  }
  buildSummaries(ctx);
  return ctx;
}

const walkMain = (node: SyntaxNode, env: Env, ctx: EngineCtx) => createWalker(ctx, { descendClosures: true }).walk(node, env);

function runScan(ctx: EngineCtx, withEntryPoints: boolean): AstTaintRustFinding[] {
  const called = new Set<string>();
  for (const c of findAllNodes(ctx.root, "call_expression")) called.add(callParts(c).name);
  // Every name used anywhere except where a function declares itself: a private function passed as a value
  // (`.map(helper)`, `get(handler)`) is being called by this file's own code, with this file's own data.
  const referenced = new Set<string>();
  for (const n of findAllNodes(ctx.root, "identifier")) {
    const p = n.parent;
    if (p?.type === "function_item" && p.childForFieldName("name")?.id === n.id) continue;
    referenced.add(n.text);
  }
  // Entry points: a `pub` function nothing in the file calls (library API), AND a private one nothing in the file
  // calls or refers to. A Rust module is its file, so an unreferenced private function is reached from a child
  // module (`super::f`), a test or a macro -- the compiler flags it as dead code otherwise. Only public functions
  // used to count, so `fn run_tool(user_value: &str)` building a shell command was never analysed with its input.
  const isEntry = (f: LocalFn) => withEntryPoints && !!f.body && !called.has(f.name) && (f.isPub || !referenced.has(f.name))
    && !NON_ENTRY_FN_RE.test(f.name) && !isHandler(f)
    && !f.attrs.some(a => /^(?:test|tokio::test|cfg)$/.test(attrName(a)));
  for (const [, f] of ctx.fns) {
    if (!f.body) continue;
    ctx.current = f;
    ctx.cmdVars = new Map();
    walkMain(f.body, entryEnv(f, isEntry(f), ctx), ctx);
    collectBola(f, ctx);
  }
  ctx.current = null;
  drainSeeded(ctx);

  // A hand-rolled JWT payload decode in a file that never verifies a signature (Java parity)
  if (!/jsonwebtoken|jwt_simple|josekit|\bdecode::<|\.verify\(/.test(ctx.content)) {
    for (const [, f] of ctx.fns) {
      const text = f.body?.text ?? "";
      if (/\.split\(\s*['"]\.['"]\s*\)/.test(text) && /base64|BASE64|URL_SAFE/.test(text) && /claims|payload|sub\b|role/i.test(text)) {
        emit(ctx, "jwt-none-alg", f.body!, "token", "manual JWT decode",
          "JWT payload is base64-decoded by hand and the file never verifies a signature — claims (role, sub, ...) are attacker-controlled; use a JWT library's verified decode");
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
      for (const p of f.params) for (const n of p.names) env.set(n, idx.get(p.index) ?? 0);
      const prev = ctx.current;
      ctx.current = f;
      ctx.cmdVars = new Map();
      walkMain(f.body, env, ctx);
      ctx.current = prev;
    }
    if (!changed) break;
  }
}

export interface RustScanOptions {
  /** Also treat `&str`/`String` parameters of functions nothing in the file calls (public), or calls or refers to
   * (private), as untrusted input;
   * findings that exist ONLY because of this come back with `entryPointSeeded: true`. */
  entryPoints?: boolean;
  crossFileFacts?: ReadonlyMap<string, readonly ParamSinkFact[]>;
}

export function scanAstTaintRust(
  content: string, filePath: string, root: SyntaxNode, suppressedOut?: SuppressedSink[], opts?: RustScanOptions,
): AstTaintRustFinding[] {
  try {
    const strict = runScan(makeCtx(content, filePath, root, suppressedOut, opts?.crossFileFacts), false);
    if (!opts?.entryPoints) return strict;
    const relaxed = runScan(makeCtx(content, filePath, root, suppressedOut, opts.crossFileFacts), true);
    const have = new Set(strict.map(f => `${f.id}:${f.line}`));
    return [...strict, ...relaxed.filter(f => !have.has(`${f.id}:${f.line}`)).map(f => ({ ...f, entryPointSeeded: true }))];
  } catch (err) {
    console.error(`[astTaintRust] threw scanning ${filePath}:`, err);
    return [];
  }
}

const NON_FLOW_IDS: ReadonlySet<string> = new Set(["bola-missing-ownership-check", "timing-attack", "jwt-none-alg", "weak-crypto"]);

/**
 * Parameter -> sink facts for every public function in one file (self excluded from indices), keyed
 * `Type.method` (methods), `Type::assoc` (associated functions), `Trait.method` (trait impls, so a call through
 * `&dyn Trait` / `impl Trait` / `Arc<dyn Trait>` resolves) and `module::fn` (free functions, module = file stem;
 * `mod.rs` -> its directory, `lib.rs`/`main.rs` -> "crate").
 */
export function computeRustFnSinkFacts(
  content: string, filePath: string, root: SyntaxNode, incoming: ReadonlyMap<string, readonly ParamSinkFact[]>,
): Map<string, ParamSinkFact[]> {
  const out = new Map<string, ParamSinkFact[]>();
  try {
    const ctx = makeCtx(content, filePath, root, undefined, incoming);
    const all = collectFns(root, ctx.moduleName);
    const ranges = all.map(f => ({ name: f.name, start: f.decl.startPosition.row + 1, end: f.decl.endPosition.row + 1 }));
    const run = (f: LocalFn, env: Env): AstTaintRustFinding[] => {
      ctx.findings = []; ctx.seen = new Set(); ctx.seeded = new Map(); ctx.cmdVars = new Map();
      ctx.current = f;
      walkMain(f.body!, env, ctx);
      drainSeeded(ctx);
      ctx.current = null;
      return ctx.findings;
    };
    for (const f of all) {
      if (!f.key || !f.body || !f.isPub || f.params.length === 0) continue;
      const zero = () => { const e: Env = new Map(); for (const p of f.params) for (const n of p.names) e.set(n, 0); return e; };
      const baseline = new Set(run(f, zero()).map(x => `${x.id}:${x.line}`));
      const label = f.key;
      const facts: ParamSinkFact[] = [];
      for (const p of f.params) {
        const env = zero();
        for (const n of p.names) env.set(n, ALL);
        for (const x of dropOnPathDuplicates(run(f, env))) {
          if (baseline.has(`${x.id}:${x.line}`) || NON_FLOW_IDS.has(x.id)) continue;
          const where = x.calleeSink;
          mergeSinkFacts(facts, [{
            index: p.index, isRest: false, id: x.id, sinkClass: classOf(x.id),
            sinkExpr: where?.sinkExpr ?? x.sinkExpr, file: where?.file ?? filePath, line: where?.line ?? x.line,
            via: [label, ...(where?.via ?? [])],
            steps: x.trace?.length ? factStepsFromTrace(x.trace, label, filePath, f.decl.startPosition.row + 1, p.name,
              { fnEnd: f.decl.endPosition.row + 1, functions: ranges, lines: ctx.lines }) : undefined,
          }]);
        }
      }
      if (facts.length === 0) continue;
      for (const k of [f.key, ...f.altKeys]) {
        const list = out.get(k) ?? [];
        mergeSinkFacts(list, facts);
        out.set(k, list);
      }
    }
  } catch (err) {
    console.error(`[astTaintRust] threw computing fn sink facts for ${filePath}:`, err);
  }
  return out;
}
