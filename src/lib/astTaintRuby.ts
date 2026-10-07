/**
 * Real AST-based taint engine for Ruby (Rails, Sinatra, Grape) -- the seventh engine, mirroring the five-stage
 * architecture of astTaintPHP.ts / astTaintGo.ts / astTaintCSharp.ts: sources, sinks, propagation,
 * interprocedural summaries, findings (with source -> sink traces), plus cross-file parameter -> sink facts and an
 * object-level authorization (BOLA) check. Shared semantics come from taint/taintCore.ts (sink-class masks,
 * shadow bits for the regex-layer veto, path-sensitive combinators), taint/sanitizers.ts ("rb" table),
 * taint/sinkShape.ts (SSRF / SQL position analysis) and taint/principal.ts (authorization vocabulary).
 *
 * Parsing uses tree-sitter-wasms' prebuilt tree-sitter-ruby.wasm through the shared web-tree-sitter runtime
 * (treeSitterRuntime.ts). Grammar shapes below were confirmed by direct probing, not assumed:
 *  - Every call is one `call` node {receiver?, method, arguments?, block?}, with or without parentheses
 *    (`redirect_to target` and `redirect_to(target)` are the same shape); a call with neither receiver nor
 *    arguments is indistinguishable from a local variable read (`identifier`), so identifiers fall back to a
 *    same-file zero-argument method's summary (the Rails `user_params` strong-parameters idiom).
 *  - `params[:id]` is `element_reference {object, index...}`; `"a #{b}"`, backticks (`subshell`), regex literals
 *    and symbols carry `interpolation` children; single-quoted strings never interpolate.
 *  - A heredoc's body is NOT inside the expression that opens it: `q = <<~SQL` holds a `heredoc_beginning`
 *    and the body is a later sibling `heredoc_body` -- paired here by order (see heredocBodies).
 *  - `if`/`unless` (+ `elsif`/`else`), modifier forms (`return unless ok`), `case`/`when`, `while`/`until`/`for`,
 *    `begin`/`rescue`/`else`/`ensure` (also directly in a method body), ternary `conditional`, blocks
 *    (`do_block`/`block` with `block_parameters`) and `lambda`.
 *
 * Ruby-specific modelling decisions:
 *  - Sources are request input: `params` (Rails, Sinatra, Grape), `cookies[...]` (not `cookies.signed`/
 *    `.encrypted`), `request.params/query_parameters/body/headers/...`. A method parameter or local named
 *    `params` shadows the source (a service object taking a `params` hash is not a controller).
 *  - Ruby's sanitizers are as often methods ON the value (`x.to_i`, `x.shellescape`) as functions of it
 *    (`Shellwords.escape(x)`), so receiver conversions are modelled here; function-style ones are in
 *    sanitizers.ts. A predicate (`x.present?`) or size (`x.length`) yields an untainted result.
 *  - Method calls on a tainted value stay tainted (`params[:q].strip.downcase`), exactly like PHP's
 *    receiver passthrough; an OPAQUE call on an untainted receiver stays untainted (`User.find(id)` returns a
 *    record, not the id) -- the same contract every engine keeps.
 *  - Implicit return: a method's value is its last expression; summaries take both that and every `return`.
 *  - Instance variables persist between a controller's actions/filters (`before_action :set_user` assigns
 *    `@user` that `show` reads), so they are file-wide sticky state, re-walked to a fixed point like PHP's
 *    `global`.
 *  - Rails' safe query forms stay clean by construction: hash conditions (`where(name: x)`), placeholders
 *    (`where("a = ?", x)`, `where(["a = ?", x])`), and `connection.quote`/`sanitize_sql*`.
 *  - BOLA is reported only where an unscoped lookup by a request-controlled id is followed by a WRITE to the
 *    record (or happens in an update/destroy/edit action) with no ownership or authorization evidence --
 *    unscoped reads of possibly-public records (`Post.find(params[:id])` in `show`) are deliberately not flagged.
 *
 * Runs ADDITIVELY next to the Ruby regex/named-taint detectors in scanner.ts and rubyTaint.ts (which remain the
 * fallback whenever this engine's grammar is unavailable); a flow this engine positively proves safe vetoes their
 * duplicate via SuppressedSink. Out of scope, as for every engine: ERB/Haml/Slim templates (views), metaprogrammed
 * methods (define_method), monkey-patching, and dynamic `send` targets beyond flagging them.
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

declare const __non_webpack_require__: NodeJS.Require | undefined;
function nodeRequire(): NodeJS.Require {
  // eslint-disable-next-line no-undef
  return typeof __non_webpack_require__ !== "undefined" ? __non_webpack_require__ : require;
}

export type AstTaintRubyId =
  | "sql-injection" | "command-injection" | "xss" | "ssrf" | "path-traversal" | "open-redirect"
  | "insecure-deserialization" | "eval-exec" | "ssti" | "mass-assignment" | "header-injection" | "redos"
  | "bola-missing-ownership-check" | "timing-attack" | "jwt-none-alg";

export interface AstTaintRubyFinding {
  id:         AstTaintRubyId;
  line:       number;
  detail:     string;
  sourceExpr: string;
  sinkExpr:   string;
  severityOverride?: "critical" | "high" | "medium";
  trace?: TraceStep[];
  /** Set when the sink is inside a method defined in another file: where it really is. */
  calleeSink?: { file: string; line: number; sinkExpr: string; via: string[] };
}

// ── Parser lifecycle (warm-cache pattern, see astTaintCSharp.ts) ───────────────────────────────────────────

let langPromise: Promise<LanguageT> | null = null;
let parserPool: ParserT | null = null;

function initRubyParser(): Promise<LanguageT> {
  if (!langPromise) {
    langPromise = (async () => {
      await ensureTreeSitterInit();
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const fs = require("fs") as typeof import("fs");
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const path = require("path") as typeof import("path");
      const webTreeSitterEntry = nodeRequire().resolve("web-tree-sitter");
      const nodeModulesDir = path.dirname(path.dirname(webTreeSitterEntry));
      const wasmPath = path.join(nodeModulesDir, "tree-sitter-wasms", "out", "tree-sitter-ruby.wasm");
      const lang = await Language.load(new Uint8Array(fs.readFileSync(wasmPath)));
      const p = new Parser();
      p.setLanguage(lang);
      parserPool = p;
      console.log("[astTaintRuby] Ruby AST taint engine ready");
      return lang;
    })().catch(err => {
      console.error("[astTaintRuby] WASM init failed -- Ruby AST taint scanning disabled, regex detectors unaffected:", err);
      throw err;
    });
  }
  return langPromise;
}
if (!process.env.JEST_WORKER_ID) {
  void initRubyParser().catch(() => { /* already logged above */ });
}

export function isRubyParserReady(): boolean {
  return parserPool !== null;
}

export async function warmRubyTaintEngine(): Promise<void> {
  await initRubyParser().catch(() => { /* already logged; callers just proceed regex-only */ });
}

export function parseRubySourceSync(content: string, filePath: string): SyntaxNode | null {
  if (!parserPool) return null;
  try {
    return rootIfShallowEnough(parserPool.parse(content)?.rootNode, "astTaintRuby", filePath);
  } catch (err) {
    console.error(`[astTaintRuby] parse threw for ${filePath}:`, err);
    return null;
  }
}

// ── Enclosing-method lookup (reachability.ts / scanner.ts) ──────────────────────────────────────────────────

export function findNodeAtRowRuby(root: SyntaxNode, row: number): SyntaxNode {
  let node = root;
  for (;;) {
    const child = node.namedChildren.find(c => c && row >= c.startPosition.row && row <= c.endPosition.row);
    if (!child) return node;
    node = child;
  }
}

export function findEnclosingFunctionNameRuby(node: SyntaxNode): string {
  for (let cur: SyntaxNode | null = node; cur; cur = cur.parent) {
    if (cur.type === "method" || cur.type === "singleton_method") {
      const nameNode = cur.childForFieldName("name");
      if (nameNode) return nameNode.text;
    }
  }
  return "unknown";
}

// ── Tree helpers ───────────────────────────────────────────────────────────────────────────────────────────

const lineOf = (n: SyntaxNode) => n.startPosition.row + 1;
const named = (n: SyntaxNode | null | undefined): SyntaxNode[] => (n ? n.namedChildren.filter((c): c is SyntaxNode => !!c) : []);

function findAllNodes(root: SyntaxNode, type: string | ReadonlySet<string>, acc: SyntaxNode[] = []): SyntaxNode[] {
  if (typeof type === "string" ? root.type === type : type.has(root.type)) acc.push(root);
  for (const c of root.namedChildren) if (c) findAllNodes(c, type, acc);
  return acc;
}

const methodNameOf = (call: SyntaxNode) => call.childForFieldName("method")?.text ?? "";
const receiverOf = (call: SyntaxNode) => call.childForFieldName("receiver");

/** `User`, `Net::HTTP`, `params.require`, `self.class.qux` -> dotted text with `::` kept; null when the receiver chain
 * has a part that isn't a name (a literal, an index). */
function calleeTextRuby(node: SyntaxNode | null): string | null {
  if (!node) return null;
  switch (node.type) {
    case "identifier": case "constant": case "instance_variable": case "self":
      return node.text;
    case "scope_resolution": {
      const scope = node.childForFieldName("scope");
      const name = node.childForFieldName("name")?.text;
      if (!name) return null;
      const s = scope ? calleeTextRuby(scope) : "";
      return s === null ? null : `${s}::${name}`;
    }
    case "call": {
      const m = methodNameOf(node);
      const r = receiverOf(node);
      if (!r) return m || null;
      const rt = calleeTextRuby(r);
      return rt === null ? null : `${rt}.${m}`;
    }
    default:
      return null;
  }
}

/** All arguments of a call as written (positional expressions, `pair`s of keyword arguments, splats). */
function argsOf(call: SyntaxNode): SyntaxNode[] {
  return named(call.childForFieldName("arguments")).filter(n => n.type !== "block_argument" && n.type !== "comment");
}
/** Positional arguments only (not `key: value` keyword pairs). */
const positionalArgs = (call: SyntaxNode) => argsOf(call).filter(a => a.type !== "pair");
/** The value of keyword argument `key:` (`url: x`, `inline: x`), or null. */
function keywordArg(call: SyntaxNode, key: string): SyntaxNode | null {
  for (const a of argsOf(call)) {
    if (a.type !== "pair") continue;
    const k = a.childForFieldName("key");
    const kt = k?.type === "hash_key_symbol" ? k.text : k?.type === "simple_symbol" ? k.text.slice(1) : null;
    if (kt === key) return a.childForFieldName("value");
  }
  return null;
}
const pairKeyText = (p: SyntaxNode): string | null => {
  const k = p.childForFieldName("key");
  return k?.type === "hash_key_symbol" ? k.text : k?.type === "simple_symbol" ? k.text.slice(1) : k?.type === "string" ? stringValue(k) : null;
};

/** A string/symbol literal's text when it has no interpolation, else null. */
function stringValue(n: SyntaxNode): string | null {
  if (n.type === "simple_symbol") return n.text.slice(1);
  if (n.type !== "string" && n.type !== "delimited_symbol" && n.type !== "bare_string") return null;
  const kids = named(n);
  if (kids.some(c => c.type !== "string_content" && c.type !== "escape_sequence")) return null;
  return kids.map(c => c.text).join("");
}
const isLiteral = (n: SyntaxNode) =>
  stringValue(n) !== null || ["integer", "float", "true", "false", "nil", "simple_symbol", "rational", "complex"].includes(n.type);

/** The binary operator token (`==`, `+`, `<<`, `&&`, `and`...). */
const operatorOf = (bin: SyntaxNode) => bin.childForFieldName("operator")?.type ?? bin.child(1)?.type ?? "";

const COMPARISON_OPS = new Set(["==", "!=", "===", "<", ">", "<=", ">=", "<=>", "=~", "!~", "eql?", "equal?"]);

// ── Sources ────────────────────────────────────────────────────────────────────────────────────────────────

/** `request.<x>` members that carry what the client sent. */
const REQUEST_INPUT_MEMBERS = new Set([
  "params", "query_parameters", "request_parameters", "path_parameters", "parameters", "GET", "POST",
  "body", "raw_post", "headers", "env", "referer", "referrer", "url", "original_url", "fullpath", "original_fullpath",
  "path", "query_string", "host", "host_with_port", "user_agent", "cookies", "content_type", "accept",
]);
const PARAMS_SOURCE = "params";
const COOKIES_SOURCE = "cookies";

// ── Propagation tables ─────────────────────────────────────────────────────────────────────────────────────

/** Receiver conversions: `x.to_i` makes x a number; `x.shellescape` a safe shell token; `x.to_sym` (as a column
 * name) can't carry SQL. */
const RECEIVER_CLEARS: Record<string, number> = {
  to_i: NUMERIC_CLEARS, to_f: NUMERIC_CLEARS, to_r: NUMERIC_CLEARS, to_c: NUMERIC_CLEARS, to_d: NUMERIC_CLEARS, round: NUMERIC_CLEARS,
  abs: NUMERIC_CLEARS, floor: NUMERIC_CLEARS, ceil: NUMERIC_CLEARS,
  shellescape: SinkClass.CMD, to_sym: SinkClass.SQL,
};
/** Methods whose result says nothing about the receiver's text (a size, an id, a boolean). */
const OPAQUE_RESULT_METHODS = new Set([
  "size", "length", "count", "bytesize", "hash", "object_id", "class", "frozen?", "nil?", "empty?", "blank?", "present?",
  "any?", "none?", "zero?", "positive?", "negative?", "valid?", "persisted?", "new_record?", "key?", "has_key?",
  "include?", "start_with?", "end_with?", "match?", "is_a?", "kind_of?", "instance_of?", "respond_to?",
]);
/** Methods on a value whose ARGUMENTS also flow into the result (`a.concat(b)`, `s.gsub(x, y)`, `h.merge(other)`). */
const ARG_FLOW_METHODS = new Set([
  "concat", "prepend", "insert", "sub", "gsub", "sub!", "gsub!", "replace", "merge", "merge!", "update", "reverse_merge",
  "deep_merge", "push", "append", "unshift", "<<", "+", "join", "format", "%", "center", "ljust", "rjust", "zip", "product",
]);
/** Methods that write their arguments INTO the receiver variable (`q << x`, `parts.push(x)`, `h.merge!(x)`). */
const MUTATOR_METHODS = new Set(["<<", "concat", "prepend", "insert", "push", "append", "unshift", "merge!", "update", "replace", "store", "[]="]);
/** Functions / constructors whose result carries their arguments' taint (string, URI, path and JSON plumbing). */
const PASSTHROUGH_CALLS = new Set([
  "format", "sprintf", "String", "Array", "Hash", "URI", "URI.parse", "URI.join", "URI::HTTP.build", "URI::HTTPS.build",
  "File.join", "File.expand_path", "File.absolute_path", "File.realpath", "Pathname.new", "Pathname", "Rails.root.join",
  "Base64.decode64", "Base64.strict_decode64", "Base64.urlsafe_decode64", "Base64.encode64", "Base64.strict_encode64",
  "CGI.unescape", "URI.decode_www_form_component", "Rack::Utils.unescape", "JSON.parse", "JSON.generate", "Oj.dump",
  "ActiveSupport::JSON.decode", "declared", "OpenStruct.new", "Struct.new", "Kernel.format", "Kernel.sprintf",
]);
/** Decoders re-taint what an encoder cleared (an encode/decode round trip undoes the encoding). */
const DECODER_CALLS = new Set(["Base64.decode64", "Base64.strict_decode64", "Base64.urlsafe_decode64", "CGI.unescape", "URI.decode_www_form_component", "Rack::Utils.unescape"]);
/** Block-taking iterators whose block parameters are the receiver's elements. */
const ITERATOR_METHODS = new Set([
  "each", "each_with_index", "each_with_object", "map", "flat_map", "collect", "select", "filter", "reject", "find", "detect",
  "each_pair", "each_key", "each_value", "map!", "select!", "reject!", "filter_map", "group_by", "partition", "sort_by",
  "min_by", "max_by", "sum", "each_slice", "each_cons", "inject", "reduce", "tap", "then", "yield_self", "each_line", "each_char",
]);

// ── Sink tables ────────────────────────────────────────────────────────────────────────────────────────────

/** ActiveRecord / relation query methods whose first argument may be raw SQL. */
const AR_SQL_METHODS = new Set([
  "where", "not", "or", "rewhere", "order", "reorder", "group", "having", "pluck", "joins", "left_joins", "left_outer_joins",
  "from", "select", "lock", "calculate", "count", "sum", "average", "minimum", "maximum", "exists?", "find_by", "find_by!",
  "update_all", "delete_all", "destroy_all", "delete_by", "destroy_by", "find_or_create_by", "find_or_initialize_by",
  "distinct_on", "reselect", "in_order_of", "extending",
]);
/** Methods that take a complete SQL statement as their first argument, on any receiver (models, connections, Sequel). */
const RAW_SQL_METHODS = new Set([
  "find_by_sql", "count_by_sql", "execute", "exec_query", "exec_update", "exec_delete", "exec_insert", "select_all",
  "select_one", "select_value", "select_values", "select_rows", "insert_all", "query", "fetch", "run", "exec",
]);
const SHELL_FUNCTIONS = new Set(["system", "exec", "spawn", "`"]);
const SHELL_CALLS = new Set([
  "Kernel.system", "Kernel.exec", "Kernel.spawn", "Process.spawn", "IO.popen", "Open3.capture2", "Open3.capture2e",
  "Open3.capture3", "Open3.popen2", "Open3.popen2e", "Open3.popen3", "Open3.pipeline", "Open3.pipeline_r", "Open3.pipeline_w",
  "Open3.pipeline_rw", "PTY.spawn", "Kernel.open",
]);
const FILE_CALL_RE = /^(?:::)?(?:File|IO|Dir|FileUtils)\.\w+[?!]?$/;
const FILE_SAFE_METHODS = new Set(["basename", "extname", "dirname", "join", "expand_path", "absolute_path", "split", "fnmatch", "fnmatch?", "path", "pwd", "home", "tmpdir"]);
const PATH_RECEIVER_SINKS = new Set(["read", "binread", "readlines", "write", "binwrite", "open", "each_line", "delete", "unlink", "rmtree", "children", "entries", "opendir"]);
const SSRF_CALL_RE = /^(?:::)?(?:Net::HTTP\.(?:get|get_response|get_print|post|post_form|start|new)|URI\.open|(?:HTTParty|Faraday|RestClient|Excon|HTTP|Typhoeus|HTTPX|Curl)\.(?:get|post|put|patch|delete|head|options|request|new|follow|via|stream_get)|RestClient::Request\.(?:execute|new)|Typhoeus::Request\.new|Faraday::Connection\.new|OpenURI\.open_uri)$/;
const DESERIAL_CALL_RE = /^(?:::)?(?:Marshal\.(?:load|restore)|YAML\.(?:load|unsafe_load|load_file|unsafe_load_file|load_stream)|Psych\.(?:load|unsafe_load|load_stream)|Oj\.(?:load|object_load)|JSON\.load|Ox\.load)$/;
const SSTI_CALL_RE = /^(?:::)?(?:ERB\.new|Erubi::Engine\.new|Erubis::Eruby\.new|Haml::Engine\.new|Haml::Template\.new|Slim::Template\.new|Tilt::\w+\.new|Mustache\.render)$/;
const REFLECTION_METHODS = new Set(["send", "public_send", "__send__", "try", "try!", "instance_variable_get", "instance_variable_set", "method", "public_method", "const_get", "class_variable_get", "class_variable_set"]);
const EVAL_FUNCTIONS = new Set(["eval", "instance_eval", "class_eval", "module_eval", "binding.eval", "Kernel.eval", "require", "load", "require_relative", "autoload"]);
/** Model writes that accept an attributes hash. */
const MASS_ASSIGN_METHODS = new Set([
  "new", "create", "create!", "build", "update", "update!", "assign_attributes", "attributes=", "update_attributes",
  "update_attributes!", "insert", "insert!", "upsert", "find_or_create_by", "find_or_create_by!", "first_or_create",
  "first_or_create!", "find_or_initialize_by", "first_or_initialize", "update_columns",
]);
/** permit(...) keys that let a user change who they are or what they may do. */
const PRIVILEGED_ATTR_RE = /^(?:admin|is_admin|role|roles|role_id|superuser|is_superuser|staff|permissions?|account_id|user_id|owner_id|organization_id|tenant_id|verified|approved|banned|confirmed_at|password_digest)$/;
const SECRET_NAME_RE = /secret|token|password|passwd|api_?key|hmac|signature|digest/i;

const SEVERITY: Record<AstTaintRubyId, "critical" | "high" | "medium"> = {
  "sql-injection": "critical", "command-injection": "critical", "xss": "high", "ssrf": "critical", "path-traversal": "critical",
  "open-redirect": "medium", "insecure-deserialization": "critical", "eval-exec": "critical", "ssti": "critical",
  "mass-assignment": "high", "header-injection": "high", "redos": "high", "bola-missing-ownership-check": "high",
  "timing-attack": "medium", "jwt-none-alg": "critical",
};
const LABEL: Record<AstTaintRubyId, string> = {
  "sql-injection": "SQL Injection", "command-injection": "Command Injection", "xss": "Cross-Site Scripting (XSS)",
  "ssrf": "Server-Side Request Forgery", "path-traversal": "Path Traversal", "open-redirect": "Open Redirect",
  "insecure-deserialization": "Insecure Deserialization", "eval-exec": "Code Execution / Unsafe Reflection",
  "ssti": "Server-Side Template Injection", "mass-assignment": "Mass Assignment", "header-injection": "HTTP Header Injection",
  "redos": "ReDoS — Regex DoS", "bola-missing-ownership-check": "Broken Object Level Authorization (AST-verified)",
  "timing-attack": "Timing Attack", "jwt-none-alg": "JWT Signature Not Verified",
};

export function astTaintRubySeverity(id: AstTaintRubyId): "critical" | "high" | "medium" { return SEVERITY[id]; }
export function astTaintRubyLabel(id: AstTaintRubyId): string { return LABEL[id]; }

// ── Engine context ─────────────────────────────────────────────────────────────────────────────────────────

type Env = TaintEnv;
interface ParamShape { name: string; index: number; isRest: boolean; keyword: boolean }
interface LocalMethod {
  name: string;
  /** `Class#name` (instance) or `Class.name` (singleton / scope), lower-cased; null outside a class. */
  key: string | null;
  className: string | null;
  singleton: boolean;
  params: ParamShape[];
  body: SyntaxNode | null;
  decl: SyntaxNode;
}
type TaintMaskFn = (node: SyntaxNode, env: Env) => number;

interface EngineCtx {
  filePath: string;
  lines: string[];
  root: SyntaxNode;
  /** Same-file methods by bare name (first declared wins on a collision). */
  methods: Map<string, LocalMethod>;
  /** name -> (param index -> classes surviving to the return value) */
  propagating: Map<string, Map<number, number>>;
  /** name -> classes the return value carries regardless of arguments (it reads params itself: `user_params`) */
  intrinsic: Map<string, number>;
  seeded: Map<string, Map<number, number>>;
  suppressed?: SuppressedSink[];
  findings: AstTaintRubyFinding[];
  seen: Set<string>;
  /** Instance variables written anywhere in the file (controller filters/actions share them). */
  sticky: Map<string, number>;
  stickyDirty: boolean;
  /** local variable -> class it was constructed from (`svc = Billing::Charge.new(...)`) */
  varTypes: Map<string, string>;
  /** heredoc_beginning id -> its heredoc_body */
  heredocs: Map<number, SyntaxNode>;
  /** Lower-cased `Class.method` / `Class#method` -> facts of methods in other files (and this one). */
  crossFileFacts?: ReadonlyMap<string, readonly ParamSinkFact[]>;
  /** Lower-cased keys of methods declared in this file. */
  localKeys: Set<string>;
  /** Variables holding an unrestricted params hash (permit! / to_unsafe_h / privileged permit). */
  unsafeParamVars: Set<string>;
  /** Set by the walker at each sink check (it holds the env): narrows a reported source to its tainted operand. */
  refine?: (source: SyntaxNode, cls: number) => SyntaxNode;
}

function emit(
  ctx: EngineCtx, id: AstTaintRubyId, node: SyntaxNode, sourceExpr: string, sinkExpr: string,
  detailOverride?: string, severityOverride?: "critical" | "high" | "medium",
) {
  const line = lineOf(node);
  const key = `${id}:${line}`;
  if (ctx.seen.has(key)) return;
  ctx.seen.add(key);
  ctx.findings.push({
    id, line, sinkExpr, sourceExpr, severityOverride,
    detail: detailOverride ?? `Tainted expression '${sourceExpr.slice(0, 80)}' flows into ${sinkExpr}(...) — real data-flow match, not a line-pattern guess`,
    trace: buildBackwardTraceGeneric(ctx.filePath, node, sourceExpr, sinkExpr, rubyTraceResolver),
  });
}

/** Pair every `heredoc_beginning` with its body: bodies follow their openers, in the same order. */
function heredocBodies(root: SyntaxNode): Map<number, SyntaxNode> {
  const begins = findAllNodes(root, "heredoc_beginning").sort((a, b) => a.startIndex - b.startIndex);
  const bodies = findAllNodes(root, "heredoc_body").sort((a, b) => a.startIndex - b.startIndex);
  const out = new Map<number, SyntaxNode>();
  let j = 0;
  for (const b of begins) {
    while (j < bodies.length && bodies[j].startIndex < b.startIndex) j++;
    if (j < bodies.length) out.set(b.id, bodies[j++]);
  }
  return out;
}

// ── Taint mask ─────────────────────────────────────────────────────────────────────────────────────────────

const LITERAL_TYPES = new Set([
  "integer", "float", "true", "false", "nil", "simple_symbol", "hash_key_symbol", "constant", "self", "comment",
  "string_content", "escape_sequence", "rational", "complex", "character", "heredoc_content", "heredoc_end", "regex_content",
]);
const INTERPOLATING_TYPES = new Set(["string", "subshell", "regex", "delimited_symbol", "heredoc_body", "interpolation", "bare_string", "string_array", "symbol_array", "bare_symbol"]);
const AGGREGATE_TYPES = new Set(["array", "hash", "pair", "splat_argument", "hash_splat_argument", "argument_list", "range", "parenthesized_statements", "element_reference_index"]);

function makeTaintMask(ctx: EngineCtx): TaintMaskFn {
  const mask = (node: SyntaxNode, env: Env): number => {
    if (LITERAL_TYPES.has(node.type)) return 0;
    switch (node.type) {
      case "identifier": {
        const name = node.text;
        if (env.has(name)) return env.get(name)!;
        if (name === PARAMS_SOURCE) return ALL;
        // A same-file method called with no arguments looks exactly like a variable read (`user_params`).
        const m = ctx.methods.get(name);
        if (m && m.params.filter(p => !p.keyword).length === 0) return ctx.intrinsic.get(name) ?? 0;
        return 0;
      }
      case "instance_variable":
        return (env.get(node.text) ?? 0) | (ctx.sticky.get(node.text) ?? 0);
      case "class_variable": case "global_variable":
        return env.get(node.text) ?? 0;
      case "heredoc_beginning": {
        const body = ctx.heredocs.get(node.id);
        return body ? mask(body, env) : 0;
      }
      case "element_reference": {
        const obj = node.childForFieldName("object");
        if (!obj) return 0;
        if (obj.type === "identifier" && obj.text === COOKIES_SOURCE && !env.has(COOKIES_SOURCE)) return ALL;
        return mask(obj, env);
      }
      case "binary": {
        const op = operatorOf(node);
        if (COMPARISON_OPS.has(op)) return 0;
        const l = node.childForFieldName("left"), r = node.childForFieldName("right");
        return (l ? mask(l, env) : 0) | (r ? mask(r, env) : 0);
      }
      case "unary": {
        const op = node.child(0)?.type ?? "";
        if (op === "!" || op === "not" || op === "defined?") return 0;
        return named(node).reduce((m, c) => m | mask(c, env), 0);
      }
      case "conditional": {
        const c = node.childForFieldName("consequence"), a = node.childForFieldName("alternative");
        return (c ? mask(c, env) : 0) | (a ? mask(a, env) : 0);
      }
      case "if": case "unless": case "case": case "begin": case "then": case "else": case "elsif": case "when":
      case "body_statement": case "do": case "ensure": case "rescue": case "block_body":
        return valueMask(node, env);
      case "assignment": case "operator_assignment": {
        const r = node.childForFieldName("right");
        return r ? mask(r, env) : 0;
      }
      case "lambda": case "block": case "do_block": case "method": case "singleton_method": case "class": case "module":
        return 0;
      case "call":
        return callMask(node, env);
      default:
        break;
    }
    if (INTERPOLATING_TYPES.has(node.type) || AGGREGATE_TYPES.has(node.type)) {
      return named(node).reduce((m, c) => m | mask(c, env), 0);
    }
    return named(node).reduce((m, c) => m | mask(c, env), 0);
  };

  /** The value of a statement sequence / branch construct = its last expression (per arm). */
  const valueMask = (node: SyntaxNode, env: Env): number => {
    switch (node.type) {
      case "if": case "unless": case "elsif": {
        const c = node.childForFieldName("consequence"), a = node.childForFieldName("alternative");
        return (c ? valueMask(c, env) : 0) | (a ? valueMask(a, env) : 0);
      }
      case "case":
        return named(node).filter(n => n.type === "when" || n.type === "else").reduce((m, w) => m | valueMask(w, env), 0);
      case "when": {
        const body = node.childForFieldName("body");
        return body ? valueMask(body, env) : 0;
      }
      default: {
        const kids = named(node).filter(n => n.type !== "comment" && n.type !== "rescue" && n.type !== "ensure" && n.type !== "heredoc_body");
        const last = kids[kids.length - 1];
        return last ? mask(last, env) : 0;
      }
    }
  };

  const callMask = (node: SyntaxNode, env: Env): number => {
    const name = methodNameOf(node);
    const recv = receiverOf(node);
    const callee = calleeTextRuby(node) ?? name;
    const args = argsOf(node);
    const argsMask = () => args.reduce((m, a) => m | mask(a, env), 0);

    // request.<input>
    if (recv?.type === "identifier" && recv.text === "request" && !env.has("request") && REQUEST_INPUT_MEMBERS.has(name)) return ALL;
    // cookies.signed / cookies.encrypted are tamper-proof: what the server itself set.
    if (recv?.type === "identifier" && recv.text === COOKIES_SOURCE && !env.has(COOKIES_SOURCE)) {
      return name === "signed" || name === "encrypted" ? 0 : ALL;
    }

    if (recv) {
      // x.to_i / x.shellescape / x.to_sym
      const clears = RECEIVER_CLEARS[name];
      // to_sym / numeric conversions change what the value IS (safe in any position); shellescape is an escaper.
      if (clears !== undefined) return (name === "shellescape" ? applySanitizer : applyClears)(mask(recv, env), clears);
      if (OPAQUE_RESULT_METHODS.has(name) || (name.endsWith("?") && !ARG_FLOW_METHODS.has(name))) return 0;
    }

    // Function-style sanitizers (sanitizers.ts "rb"): ERB::Util.html_escape(x), Shellwords.escape(x), Integer(x)...
    const sc = sanitizerClears("rb", callee, args.map(a => a.text));
    if (sc !== null) {
      // connection.quote returns a complete quoted literal: safe in any position, unlike an escaper.
      const complete = /\.quote$|sanitize_sql/.test(callee);
      const data = recv && /\.quote(?:_string)?$/.test(callee) ? args[0] : (args[0] ?? recv);
      return data ? (complete ? applyClears : applySanitizer)(mask(data, env), sc) : 0;
    }

    // Same-file method: summary of what its parameters (and its own body) contribute to its return value.
    if (!recv || recv.type === "self") {
      const local = ctx.methods.get(name);
      if (local) {
        let m = ctx.intrinsic.get(name) ?? 0;
        const prop = ctx.propagating.get(name);
        if (prop) for (const [i, surviving] of prop) {
          const bound = bindArgument(local, node, i);
          for (const a of bound) m |= mask(a, env) & surviving;
        }
        return m;
      }
    }

    if (PASSTHROUGH_CALLS.has(callee)) {
      const m = argsMask();
      return DECODER_CALLS.has(callee) ? (m & ALL) | ((m >>> SHADOW) & ALL) : m;
    }
    if (recv) {
      const rm = mask(recv, env);
      return ARG_FLOW_METHODS.has(name) ? rm | argsMask() : rm;
    }
    return 0;
  };

  return mask;
}

/** The argument node(s) bound to parameter `index` of `method` at a call site (positional, rest, or keyword). */
function bindArgument(method: LocalMethod, call: SyntaxNode, index: number): SyntaxNode[] {
  const shape = method.params.find(p => p.index === index);
  if (!shape) return [];
  if (shape.keyword) {
    const v = keywordArg(call, shape.name);
    return v ? [v] : [];
  }
  const pos = positionalArgs(call);
  const posIndex = method.params.filter(p => !p.keyword && p.index < index).length;
  return shape.isRest ? pos.slice(posIndex) : pos[posIndex] ? [pos[posIndex]] : [];
}

// ── Method collection ──────────────────────────────────────────────────────────────────────────────────────

function enclosingClassName(n: SyntaxNode): string | null {
  const parts: string[] = [];
  for (let cur = n.parent; cur; cur = cur.parent) {
    if (cur.type === "class" || cur.type === "module") {
      const nm = cur.childForFieldName("name");
      if (nm) parts.unshift(nm.text);
    }
  }
  return parts.length ? parts.join("::") : null;
}

function paramShapesOf(params: SyntaxNode | null): ParamShape[] {
  const out: ParamShape[] = [];
  let index = 0;
  for (const p of named(params)) {
    switch (p.type) {
      case "identifier":
        out.push({ name: p.text, index: index++, isRest: false, keyword: false }); break;
      case "optional_parameter":
        out.push({ name: p.childForFieldName("name")?.text ?? "", index: index++, isRest: false, keyword: false }); break;
      case "splat_parameter": {
        const nm = p.childForFieldName("name")?.text;
        if (nm) out.push({ name: nm, index: index, isRest: true, keyword: false });
        index++;
        break;
      }
      case "keyword_parameter":
        out.push({ name: p.childForFieldName("name")?.text ?? "", index: index++, isRest: false, keyword: true }); break;
      default:
        index++;   // block / hash-splat / destructuring parameters carry no tracked binding
    }
  }
  return out.filter(s => s.name);
}

/** `scope :by_name, ->(n) { where("name = '#{n}'") }` defines a class method: model it as one. */
function scopeAsMethod(call: SyntaxNode, className: string | null): LocalMethod | null {
  if (methodNameOf(call) !== "scope" || receiverOf(call)) return null;
  const [nameArg, body] = positionalArgs(call);
  const name = nameArg ? stringValue(nameArg) : null;
  if (!name || !body || body.type !== "lambda") return null;
  return {
    name, key: className ? `${className}.${name}`.toLowerCase() : null, className, singleton: true,
    params: paramShapesOf(body.childForFieldName("parameters")),
    body: body.childForFieldName("body"), decl: call,
  };
}

function collectMethods(root: SyntaxNode): LocalMethod[] {
  const out: LocalMethod[] = [];
  for (const decl of findAllNodes(root, new Set(["method", "singleton_method"]))) {
    const name = decl.childForFieldName("name")?.text;
    if (!name) continue;
    const className = enclosingClassName(decl);
    const singleton = decl.type === "singleton_method" || insideClassSelfBlock(decl);
    out.push({
      name, className, singleton, decl,
      key: className ? `${className}${singleton ? "." : "#"}${name}`.toLowerCase() : null,
      params: paramShapesOf(decl.childForFieldName("parameters")),
      body: decl.childForFieldName("body"),
    });
  }
  for (const call of findAllNodes(root, "call")) {
    const s = scopeAsMethod(call, enclosingClassName(call));
    if (s) out.push(s);
  }
  return out;
}
/** `class << self ... def x ... end ... end` */
function insideClassSelfBlock(decl: SyntaxNode): boolean {
  for (let cur = decl.parent; cur; cur = cur.parent) {
    if (cur.type === "singleton_class") return true;
    if (cur.type === "class" || cur.type === "module") return false;
  }
  return false;
}

// ── Guards ─────────────────────────────────────────────────────────────────────────────────────────────────

const unwrapParens = (n: SyntaxNode): SyntaxNode => {
  let cur = n;
  while (cur.type === "parenthesized_statements" && named(cur).length === 1) cur = named(cur)[0];
  return cur;
};
const invert = (g: Guard): Guard => ({ name: g.name, holds: g.holds === "true" ? "false" : "true" });
const guardName = (n: SyntaxNode | null): string | null =>
  n && (n.type === "identifier" || n.type === "instance_variable") ? n.text : null;

/** A literal collection (`%w[a b]`, `["a", "b"]`, a frozen constant of literals) -- allow-list membership checks. */
function isLiteralCollection(n: SyntaxNode, root: SyntaxNode): boolean {
  if (n.type === "string_array" || n.type === "symbol_array") return true;
  if (n.type === "array") return named(n).length > 0 && named(n).every(isLiteral);
  if (n.type === "constant") {
    const asg = findAllNodes(root, "assignment").find(a => a.childForFieldName("left")?.text === n.text);
    let v = asg?.childForFieldName("right") ?? null;
    if (v?.type === "call" && methodNameOf(v) === "freeze") v = receiverOf(v);
    return !!v && isLiteralCollection(v, root);
  }
  if (n.type === "call" && methodNameOf(n) === "freeze") { const r = receiverOf(n); return !!r && isLiteralCollection(r, root); }
  return false;
}

/** Validation guards a condition proves (true side). Narrow on purpose: a wrong guard hides a real finding. */
function guardsOf(cond: SyntaxNode, root: SyntaxNode): Guard[] {
  const c = unwrapParens(cond);
  if (c.type === "unary" && (c.child(0)?.type === "!" || c.child(0)?.type === "not")) {
    const inner = named(c)[0];
    return inner ? guardsOf(inner, root).map(invert) : [];
  }
  if (c.type === "binary") {
    const op = operatorOf(c);
    const l = c.childForFieldName("left"), r = c.childForFieldName("right");
    if (!l || !r) return [];
    if (op === "&&" || op === "and") return [...guardsOf(l, root), ...guardsOf(r, root)].filter(g => g.holds === "true");
    if (op === "||" || op === "or") return [...guardsOf(l, root), ...guardsOf(r, root)].filter(g => g.holds === "false");
    if (op === "==" || op === "!=") {
      const holds = op === "==" ? "true" : "false";
      const ln = guardName(l), rn = guardName(r);
      if (ln && isLiteral(r)) return [{ name: ln, holds }];
      if (rn && isLiteral(l)) return [{ name: rn, holds }];
    }
    // x =~ /\A\d+\z/  -- an anchored digits-only pattern
    if (op === "=~" && /^\/\\A(?:\\d|\[0-9\])[+*](?:\\z|\\Z)\/$/.test(r.text)) {
      const ln = guardName(l);
      if (ln) return [{ name: ln, holds: "true" }];
    }
    return [];
  }
  if (c.type === "call") {
    const name = methodNameOf(c);
    const recv = receiverOf(c);
    const args = positionalArgs(c);
    // ALLOWED.include?(x) / %w[a b].include?(x)
    if ((name === "include?" || name === "member?") && recv && args[0] && isLiteralCollection(recv, root)) {
      const n = guardName(args[0]);
      return n ? [{ name: n, holds: "true" }] : [];
    }
    // x.in?(%w[a b])
    if (name === "in?" && recv && args[0] && isLiteralCollection(args[0], root)) {
      const n = guardName(recv);
      return n ? [{ name: n, holds: "true" }] : [];
    }
    // x.is_a?(Integer) / Integer === x
    if ((name === "is_a?" || name === "kind_of?" || name === "instance_of?") && recv && /^(?:Integer|Numeric|Float)$/.test(args[0]?.text ?? "")) {
      const n = guardName(recv);
      return n ? [{ name: n, holds: "true" }] : [];
    }
    // x.match?(/\A\d+\z/)
    if (name === "match?" && recv && args[0] && /^\/\\A(?:\\d|\[0-9\])[+*](?:\\z|\\Z)\/$/.test(args[0].text)) {
      const n = guardName(recv);
      return n ? [{ name: n, holds: "true" }] : [];
    }
  }
  return [];
}

// ── Statement walker ───────────────────────────────────────────────────────────────────────────────────────

interface WalkOpts {
  /** Walk lambda bodies (main scan) or not (summaries). Blocks are always walked: they run inline. */
  descendLambdas: boolean;
  onReturn?: (expr: SyntaxNode | null, env: Env, mask: TaintMaskFn) => void;
}

const TERMINATING_CALLS = new Set(["raise", "fail", "exit", "exit!", "abort", "throw", "head", "render_404", "not_found!", "forbidden!", "error!", "halt"]);
const NAMED_SCOPES = new Set(["method", "singleton_method"]);
const ANY_SCOPES = new Set(["method", "singleton_method", "lambda", "block", "do_block"]);

function statementTerminates(n: SyntaxNode | null | undefined): boolean {
  if (!n) return false;
  if (n.type === "return" || n.type === "break" || n.type === "next" || n.type === "redo" || n.type === "retry") return true;
  if (n.type === "call" && !receiverOf(n) && TERMINATING_CALLS.has(methodNameOf(n))) return true;
  // `head :forbidden and return` / `redirect_to x and return`
  if (n.type === "binary" && (operatorOf(n) === "and" || operatorOf(n) === "&&")) return statementTerminates(n.childForFieldName("right"));
  return false;
}

function createWalker(ctx: EngineCtx, opts: WalkOpts) {
  const mask = makeTaintMask(ctx);
  const root = ctx.root;

  const walkSeq = (nodes: readonly SyntaxNode[], env: Env): boolean => {
    for (const c of nodes) if (walk(c, env)) return true;
    return false;
  };

  const branch = (cond: SyntaxNode | null, body: SyntaxNode | null, negated: boolean): Branch => ({
    visitCond: (e) => { if (cond) walk(cond, e); },
    guards: () => (cond ? guardsOf(cond, root).map(g => (negated ? invert(g) : g)) : []),
    body: (e) => (body ? walk(body, e) : false),
  });

  /** if / unless / elsif chain. */
  const ifChain = (node: SyntaxNode, env: Env): boolean => {
    const branches: Branch[] = [];
    let cur: SyntaxNode | null = node;
    let negated = node.type === "unless";
    while (cur) {
      branches.push(branch(cur.childForFieldName("condition"), cur.childForFieldName("consequence"), negated));
      const alt: SyntaxNode | null = cur.childForFieldName("alternative");
      if (!alt) break;
      if (alt.type === "elsif") { cur = alt; negated = false; continue; }
      branches.push({ body: (e) => walk(alt, e) });
      break;
    }
    return walkIfChain(env, branches);
  };

  /** Walk a block body: its parameters are the receiver's elements for an iterator, else untainted; Ruby
   * blocks read and write the enclosing scope's variables, and may run zero or more times. */
  const walkBlock = (block: SyntaxNode, elementMask: number, env: Env) => {
    const params = findAllNodes(block.childForFieldName("parameters") ?? block, "identifier")
      .filter(id => id.parent?.type === "block_parameters" || id.parent?.type === "destructured_parameter" || id.parent?.type === "lambda_parameters");
    const saved = new Map(params.map(p => [p.text, env.get(p.text)]));
    walkLoop(env, (e) => {
      for (const p of params) e.set(p.text, elementMask);
      const body = block.childForFieldName("body");
      return body ? walk(body, e) : false;
    });
    for (const [k, v] of saved) { if (v === undefined) env.delete(k); else env.set(k, v); }
  };

  /** begin ... rescue => e ... else ... ensure ... end (also a method body with those clauses). */
  const walkBeginLike = (node: SyntaxNode, env: Env): boolean => {
    const stmts = named(node);
    const rescues = stmts.filter(s => s.type === "rescue");
    const ensureC = stmts.find(s => s.type === "ensure");
    const elseC = stmts.find(s => s.type === "else");
    const main = stmts.filter(s => s.type !== "rescue" && s.type !== "ensure" && s.type !== "else");
    return walkTry(
      env,
      (e) => walkSeq(main, e) || (elseC ? walk(elseC, e) : false),
      rescues.map(r => ({
        bind: findAllNodes(r.childForFieldName("variable") ?? r, "identifier").filter(i => i.parent?.type === "exception_variable").map(i => i.text),
        body: (e: Env) => { const b = r.childForFieldName("body"); return b ? walk(b, e) : false; },
      })),
      ensureC ? (e) => walk(ensureC, e) : undefined,
    );
  };

  const assign = (left: SyntaxNode | null, value: number, env: Env, orInto: boolean) => {
    if (!left) return;
    const set = (key: string, m: number) => env.set(key, orInto ? (env.get(key) ?? 0) | m : m);
    switch (left.type) {
      case "identifier": case "class_variable": case "global_variable":
        set(left.text, value); break;
      case "instance_variable": {
        set(left.text, value);
        const next = (ctx.sticky.get(left.text) ?? 0) | (value & ALL);
        if (next !== (ctx.sticky.get(left.text) ?? 0)) { ctx.sticky.set(left.text, next); ctx.stickyDirty = true; }
        break;
      }
      case "element_reference": {   // h[:k] = x  -- the read side resolves to the object
        const obj = left.childForFieldName("object");
        if (obj) assign(obj, value, env, true);
        break;
      }
      case "call": {   // obj.attr = x  -- field-insensitive: the object now carries x
        const r = receiverOf(left);
        if (r) assign(r, value, env, true);
        break;
      }
      case "left_assignment_list": case "destructured_left_assignment": case "rest_assignment":
        for (const c of named(left)) assign(c, value, env, orInto);
        break;
      default:
        break;
    }
  };

  const walk = (node: SyntaxNode, env: Env): boolean => {
    switch (node.type) {
      case "method": case "singleton_method": case "class": case "module": case "singleton_class":
        return false;   // walked separately, each in its own scope
      case "lambda":
        if (opts.descendLambdas) {
          const lenv = cloneEnv(env);
          for (const p of paramShapesOf(node.childForFieldName("parameters"))) lenv.set(p.name, 0);
          const body = node.childForFieldName("body");
          if (body) walk(body, lenv);
        }
        return false;
      case "body_statement": case "begin":
        // A method body can carry its own rescue/else/ensure clauses, exactly like an explicit begin block.
        if (node.type === "begin" || named(node).some(n => n.type === "rescue" || n.type === "ensure")) return walkBeginLike(node, env);
        return walkSeq(named(node), env);
      case "program": case "then": case "else": case "do": case "block_body": case "parenthesized_statements": case "ensure":
        return walkSeq(named(node), env);
      case "if": case "unless":
        return ifChain(node, env);
      case "if_modifier": case "unless_modifier": {
        const cond = node.childForFieldName("condition");
        const body = node.childForFieldName("body");
        return walkIfChain(env, [branch(cond, body, node.type === "unless_modifier")]);
      }
      case "conditional": {
        const cond = node.childForFieldName("condition");
        const cons = node.childForFieldName("consequence");
        const alt = node.childForFieldName("alternative");
        walkIfChain(env, [
          { ...branch(cond, null, false), body: (e) => { if (cons) walk(cons, e); return false; } },
          { body: (e) => { if (alt) walk(alt, e); return false; } },
        ]);
        return false;
      }
      case "while": case "until": case "while_modifier": case "until_modifier": {
        const cond = node.childForFieldName("condition");
        if (cond) walk(cond, env);
        const body = node.childForFieldName("body");
        return walkLoop(env, (e) => (body ? walk(body, e) : false));
      }
      case "for": {
        const value = node.childForFieldName("value");
        if (value) walk(value, env);
        const vm = value ? mask(value, env) : 0;
        const pattern = node.childForFieldName("pattern");
        const body = node.childForFieldName("body");
        return walkLoop(env, (e) => { if (pattern) assign(pattern, vm, e, false); return body ? walk(body, e) : false; });
      }
      case "case": {
        const subject = node.childForFieldName("value");
        if (subject) walk(subject, env);
        const subjectName = subject ? guardName(subject) : null;
        const clauses = named(node).filter(c => c.type === "when" || c.type === "else");
        return walkSwitch(env, clauses.map(cl => ({
          isDefault: cl.type === "else",
          pre: (e: Env) => {
            if (cl.type !== "when" || !subjectName) return;
            const pats = cl.childrenForFieldName("pattern").filter((p): p is SyntaxNode => !!p).map(p => named(p)[0] ?? p);
            // when "a", "b"  /  when Integer  -- inside, the subject is one of those literals / a number
            if (pats.length > 0 && pats.every(p => isLiteral(p) || /^(?:Integer|Numeric|Float)$/.test(p.text))) applyGuards(e, [subjectName]);
          },
          body: (e: Env) => {
            const b = cl.type === "when" ? cl.childForFieldName("body") : cl;
            return b ? walk(b, e) : false;
          },
        })));
      }
      case "return": {
        for (const c of named(node)) walk(c, env);
        const v = named(node)[0];
        opts.onReturn?.(v ? (v.type === "argument_list" ? named(v)[0] ?? null : v) : null, env, mask);
        return true;
      }
      case "break": case "next": case "redo": case "retry":
        for (const c of named(node)) walk(c, env);
        return true;
      default:
        break;
    }

    if (node.type === "assignment") {
      const right = node.childForFieldName("right");
      if (right) walk(right, env);
      const left = node.childForFieldName("left");
      const m = right ? mask(right, env) : 0;
      assign(left, m, env, false);
      if (left?.type === "identifier" && right) {
        trackUnsafeParams(left.text, right, ctx);
        const t = constructedClass(right);
        if (t) ctx.varTypes.set(left.text, t);
      }
      if (left?.type === "element_reference") { ctx.refine = (src, cls) => culpritOf(src, cls, env, mask, ctx); checkHeaderWrite(left, right, m, ctx, node); }
      return false;
    }
    if (node.type === "operator_assignment") {
      const right = node.childForFieldName("right");
      if (right) walk(right, env);
      assign(node.childForFieldName("left"), right ? mask(right, env) : 0, env, true);
      return false;
    }

    if (node.type === "call") {
      const block = node.childForFieldName("block");
      for (const c of named(node)) if (c.id !== block?.id) walk(c, env);
      checkCallSink(node, env, ctx, mask);
      seedLocalMethod(node, env, ctx, mask);
      checkCrossFileCall(node, env, ctx, mask);
      // q << x / parts.push(x): the receiver variable now holds x too
      const recv = receiverOf(node);
      const name = methodNameOf(node);
      if (recv && MUTATOR_METHODS.has(name)) {
        const am = argsOf(node).reduce((m, a) => m | mask(a, env), 0);
        if (am) assign(recv, am, env, true);
      }
      if (block) {
        const elementMask = recv && ITERATOR_METHODS.has(name) ? mask(recv, env) : 0;
        walkBlock(block, elementMask, env);
      }
      return statementTerminates(node);
    }

    if (node.type === "binary") {
      const op = operatorOf(node);
      const l = node.childForFieldName("left"), r = node.childForFieldName("right");
      if (l) walk(l, env);
      if (op === "<<" && l && r) {   // buffer << x
        walk(r, env);
        assign(l, mask(r, env), env, true);
        return false;
      }
      if (r) walk(r, env);
      if ((op === "==" || op === "!=") && l && r) checkTimingCompare(node, l, r, env, ctx, mask);
      return statementTerminates(node);
    }

    if (node.type === "subshell") {
      for (const c of named(node)) walk(c, env);
      ctx.refine = (src, cls) => culpritOf(src, cls, env, mask, ctx);
      fireOn(ctx, "command-injection", node, node, mask(node, env), "`backticks`");
      return false;
    }
    if (node.type === "regex") {
      for (const c of named(node)) walk(c, env);
      if (named(node).some(c => c.type === "interpolation")) {
        const m = mask(node, env);
        if (m & ALL) emit(ctx, "redos", node, node.text, "regex literal");
      }
      return false;
    }

    for (const c of named(node)) walk(c, env);
    return statementTerminates(node);
  };

  return { walk, mask };
}

// ── Sinks ──────────────────────────────────────────────────────────────────────────────────────────────────

/** The operand that actually carries the taint inside a composite value -- a `#{...}` inside a string or heredoc,
 * one side of a `+` -- so a finding (and its trace) names `name`, not the whole SQL text. */
function culpritOf(src: SyntaxNode, cls: number, env: Env, mask: TaintMaskFn, ctx: EngineCtx): SyntaxNode {
  const n = unwrapParens(src);
  if (n.type === "heredoc_beginning") { const b = ctx.heredocs.get(n.id); return b ? culpritOf(b, cls, env, mask, ctx) : n; }
  if (INTERPOLATING_TYPES.has(n.type) && n.type !== "interpolation") {
    for (const c of named(n)) {
      if (c.type !== "interpolation") continue;
      const inner = named(c)[0];
      if (inner && (mask(inner, env) & cls)) return culpritOf(inner, cls, env, mask, ctx);
    }
  }
  if (n.type === "binary" && !COMPARISON_OPS.has(operatorOf(n))) {
    for (const side of [n.childForFieldName("left"), n.childForFieldName("right")]) {
      if (side && (mask(side, env) & cls)) return culpritOf(side, cls, env, mask, ctx);
    }
  }
  return n;
}

/** Report `id` when `m` carries its class; record the regex-layer veto when it was positively cleared. */
function fireOn(ctx: EngineCtx, id: AstTaintRubyId, at: SyntaxNode, source: SyntaxNode, m: number, sinkExpr: string, detail?: string): boolean {
  const cls = classOf(id);
  if (m & cls) {
    const culprit = ctx.refine ? ctx.refine(source, cls) : source;
    emit(ctx, id, at, culprit.text, sinkExpr, detail);
    return true;
  }
  if (wasCleared(m, cls)) ctx.suppressed?.push({ id, line: lineOf(at) });
  return false;
}

/** A Ruby string expression as literal text and opaque value parts ("..." with interpolation, +, heredocs). */
function decomposeString(node: SyntaxNode, ctx: EngineCtx): UrlPart<SyntaxNode>[] {
  const n = unwrapParens(node);
  if (n.type === "heredoc_beginning") { const b = ctx.heredocs.get(n.id); return b ? decomposeString(b, ctx) : [{ kind: "opaque", node: n }]; }
  if (n.type === "string" || n.type === "heredoc_body") {
    return named(n).filter(c => c.type !== "heredoc_end").map(c =>
      c.type === "string_content" || c.type === "heredoc_content" || c.type === "escape_sequence" ? { kind: "literal" as const, text: c.text } : { kind: "opaque" as const, node: c });
  }
  if (n.type === "binary" && operatorOf(n) === "+") {
    const l = n.childForFieldName("left"), r = n.childForFieldName("right");
    if (l && r) return [...decomposeString(l, ctx), ...decomposeString(r, ctx)];
  }
  if (n.type === "call" && !receiverOf(n) && methodNameOf(n) === "URI") { const a = positionalArgs(n)[0]; if (a) return decomposeString(a, ctx); }
  if (n.type === "call" && calleeTextRuby(n) === "URI.parse") { const a = positionalArgs(n)[0]; if (a) return decomposeString(a, ctx); }
  return [{ kind: "opaque", node: n }];
}

/** Most recent `name = <expr>` before `at` in the enclosing method (or file). */
function lastAssignment(name: string, at: SyntaxNode): SyntaxNode | null {
  let scope: SyntaxNode | null = enclosingScope(at);
  if (!scope) { scope = at; while (scope.parent) scope = scope.parent; }
  let best: SyntaxNode | null = null;
  const visit = (n: SyntaxNode) => {
    if (n.startIndex >= at.startIndex) return;
    if (n !== scope && NAMED_SCOPES.has(n.type)) return;
    if (n.type === "assignment" && n.childForFieldName("left")?.text === name) best = n.childForFieldName("right");
    for (const c of named(n)) visit(c);
  };
  visit(scope);
  return best;
}
const resolveVar = (n: SyntaxNode): SyntaxNode => (n.type === "identifier" ? lastAssignment(n.text, n) ?? n : n);

/** A SQL argument in Rails' safe forms: keyword-hash / hash conditions, or a placeholder template with no
 * interpolation (`"name = ?"`, `["name = ?", x]`). Returns the node that actually holds SQL text, or null if none. */
function sqlTextArg(call: SyntaxNode): SyntaxNode | null {
  const pos = positionalArgs(call);
  let first = pos[0] ?? null;
  if (!first) return null;                                   // where(name: x) -- only keyword pairs
  if (first.type === "hash") return null;                    // where({ name: x })
  if (first.type === "array") first = named(first)[0] ?? null; // where(["name = ?", x])
  return first;
}

function checkCallSink(node: SyntaxNode, env: Env, ctx: EngineCtx, mask: TaintMaskFn) {
  ctx.refine = (src, cls) => culpritOf(src, cls, env, mask, ctx);
  const name = methodNameOf(node);
  const recv = receiverOf(node);
  const callee = calleeTextRuby(node) ?? name;
  const pos = positionalArgs(node);
  const sinkName = callee.replace(/^::/, "");

  // ── SQL ──
  // Unambiguous relation methods count on any receiver; names Enumerable also has (count, sum, select, find_by...)
  // only on a chain rooted at a model class or already using a relation method; raw-SQL executors only on a
  // database-looking receiver (or a model class, for find_by_sql) -- `job.execute(x)` is not a query.
  const sqlReceiver = !!recv && recv.type !== "array" && recv.type !== "string" && recv.type !== "hash";
  const relationCall = sqlReceiver && (UNAMBIGUOUS_SQL_METHODS.has(name) || (AR_SQL_METHODS.has(name) && isActiveRecordChain(recv!)));
  const rawCall = sqlReceiver && RAW_SQL_METHODS.has(name)
    && (looksLikeDbReceiver(recv, ctx) || ((name === "find_by_sql" || name === "count_by_sql") && isActiveRecordChain(recv!)));
  if (relationCall || rawCall || (!recv && (name === "find_by_sql" || name === "where" || name === "order"))
      || callee === "Sequel.lit" || callee === "Arel.sql") {
    const sqlNode = sqlTextArg(node);
    if (sqlNode) {
      const m = mask(sqlNode, env);
      const parts = decomposeString(resolveVar(sqlNode), ctx);
      const verdict = assessSqlInjection(parts, n => mask(n, env));
      if (verdict.verdict === "vulnerable" && verdict.escaped) {
        emit(ctx, "sql-injection", node, verdict.culprit!.text, sinkName, `Escaped value '${verdict.culprit!.text}' is placed outside a quoted SQL string literal — string-escaping only protects a value inside quotes`);
      } else {
        fireOn(ctx, "sql-injection", node, sqlNode, m, sinkName);
      }
    }
  }
  // DB["SELECT ... #{x}"] (Sequel) is an element reference, handled in checkElementSql below.

  // ── Command ──
  if ((!recv && (SHELL_FUNCTIONS.has(name) || name === "open")) || SHELL_CALLS.has(callee)) {
    const args = pos.filter(a => a.type !== "hash");     // an env hash first: system({"A"=>"b"}, cmd)
    const first = args[0];
    if (first) {
      const literalProgram = stringValue(first);
      const viaShell = literalProgram !== null && /^(?:\/bin\/)?(?:sh|bash|zsh|dash)$/.test(literalProgram) && stringValue(args[1] ?? first) === "-c";
      if (viaShell) {
        for (const a of args.slice(2)) if (fireOn(ctx, "command-injection", node, a, mask(a, env), sinkName)) break;
      } else if (args.length === 1 || literalProgram === null) {
        // a single string runs through the shell; Kernel#open with "|cmd" runs a command too
        fireOn(ctx, "command-injection", node, first, mask(first, env), sinkName);
      }
      // system("ls", dir) -- argv form, no shell: not command injection
    }
  }

  // ── Path ──
  if (FILE_CALL_RE.test(callee) && !FILE_SAFE_METHODS.has(name)) {
    const targets = /\.(?:rename|symlink|link|copy|cp|mv|copy_file|cp_r|ln_s)$/.test(callee) ? pos : pos.slice(0, 1);
    for (const a of targets) if (fireOn(ctx, "path-traversal", node, a, mask(a, env), sinkName)) break;
  }
  if (!recv && (name === "send_file" || name === "send_data_file")) {
    const a = pos[0];
    if (a) fireOn(ctx, "path-traversal", node, a, mask(a, env), name);
  }
  if (!recv && name === "render") {
    // render params[:page] / render file: x / render template: x -- a request-chosen file or template
    const target = keywordArg(node, "file") ?? keywordArg(node, "template") ?? keywordArg(node, "partial") ?? (pos[0] && pos[0].type !== "hash" ? pos[0] : null);
    if (target) fireOn(ctx, "path-traversal", node, target, mask(target, env), "render");
    const inline = keywordArg(node, "inline");
    if (inline) fireOn(ctx, "ssti", node, inline, mask(inline, env), "render inline:");
  }
  if (recv && PATH_RECEIVER_SINKS.has(name)) {
    // Rails.root.join(x).read / Pathname.new(x).write(...)
    const base = calleeTextRuby(recv);
    if (recv.type === "call" && base && /(?:^|\.)(?:Rails\.root\.join|Pathname\.new|Pathname)$/.test(base.replace(/^::/, ""))) {
      fireOn(ctx, "path-traversal", node, recv, mask(recv, env), `${base}.${name}`);
    }
  }

  // ── SSRF ──
  if (SSRF_CALL_RE.test(callee)) {
    const urlArg = keywordArg(node, "url") ?? pos[0];
    if (urlArg) {
      const parts = decomposeString(resolveVar(urlArg), ctx);
      const verdict = assessSsrfUrl(parts, n => mask(n, env));
      if (verdict.verdict === "vulnerable") emit(ctx, "ssrf", node, (verdict.culprit ?? urlArg).text, sinkName);
      else if (verdict.verdict === "no-taint") fireOn(ctx, "ssrf", node, urlArg, mask(urlArg, env), sinkName);
      else ctx.suppressed?.push({ id: "ssrf", line: lineOf(node) });
    }
  }

  // ── Redirect ──
  if (!recv && (name === "redirect_to" || name === "redirect")) {
    const explicitlyInternal = keywordArg(node, "allow_other_host")?.type === "false";
    const first = pos[0];
    const pairs = argsOf(node).filter(a => a.type === "pair" && !/^(?:status|notice|alert|flash|allow_other_host|turbolinks)$/.test(pairKeyText(a) ?? ""));
    const target = first ?? (pairs.length ? pairs[0] : null);
    if (target && !explicitlyInternal) {
      const parts = decomposeString(resolveVar(target), ctx);
      const verdict = assessSsrfUrl(parts, n => mask(n, env));     // same host-position rule: a fixed host is internal
      const m = first ? mask(first, env) : pairs.reduce((acc, p) => acc | mask(p, env), 0);
      if (verdict.verdict === "safe") ctx.suppressed?.push({ id: "open-redirect", line: lineOf(node) });
      else fireOn(ctx, "open-redirect", node, target, m, name);
    }
  }

  // ── Deserialization ──
  if (DESERIAL_CALL_RE.test(callee)) {
    const a = pos[0];
    const safeMode = /^(?:Oj\.load)$/.test(sinkName) && /^:(?:strict|compat|null|json|rails)$/.test(keywordArg(node, "mode")?.text ?? "");
    if (a && !safeMode) fireOn(ctx, "insecure-deserialization", node, a, mask(a, env), sinkName);
  }

  // ── Code execution / reflection ──
  if ((!recv && EVAL_FUNCTIONS.has(name)) || EVAL_FUNCTIONS.has(sinkName)) {
    const a = pos[0];
    if (a) fireOn(ctx, "eval-exec", node, a, mask(a, env), sinkName);
  }
  if (recv && REFLECTION_METHODS.has(name)) {
    const a = pos[0];
    if (a) fireOn(ctx, "eval-exec", node, a, mask(a, env), `.${name}`, `Request input '${a.text.slice(0, 60)}' picks which method/constant runs (.${name}) — map input to an explicit allow-list`);
  }
  if (recv && (name === "constantize" || name === "safe_constantize")) {
    fireOn(ctx, "eval-exec", node, recv, mask(recv, env), `.${name}`, `Request input '${recv.text.slice(0, 60)}' is turned into a class (.${name}) — map input to an explicit allow-list of classes`);
  }

  // ── XSS ──
  if (recv && (name === "html_safe" || name === "safe_concat")) {
    const src = name === "html_safe" ? recv : pos[0];
    if (src) fireOn(ctx, "xss", node, src, mask(src, env), `.${name}`, `Request input '${src.text.slice(0, 60)}' is marked HTML-safe and rendered unescaped — leave it escaped or sanitize it`);
  }
  if (!recv && (name === "raw")) {
    const a = pos[0];
    if (a) fireOn(ctx, "xss", node, a, mask(a, env), "raw");
  }
  if (!recv && name === "link_to" && pos[1]) {
    // link_to "x", params[:url] -- a `javascript:` URL runs on click
    const parts = decomposeString(resolveVar(pos[1]), ctx);
    const startsLiteral = parts[0]?.kind === "literal" && /^(?:https?:\/\/|\/)/.test(parts[0].text);
    if (!startsLiteral) fireOn(ctx, "xss", node, pos[1], mask(pos[1], env), "link_to", `Request input '${pos[1].text.slice(0, 60)}' is used as a link target — a javascript: URL runs on click; only allow http(s) or relative URLs`);
  }

  // ── Template injection ──
  if (SSTI_CALL_RE.test(callee)) {
    const a = pos[0];
    if (a) fireOn(ctx, "ssti", node, a, mask(a, env), sinkName);
  }

  // ── ReDoS ──
  if (callee === "Regexp.new" || callee === "Regexp.compile") {
    const a = pos[0];
    const escaped = a?.type === "call" && /^Regexp\.(?:escape|quote)$/.test(calleeTextRuby(a) ?? "");
    if (a && !escaped) { const m = mask(a, env); if (m & ALL) emit(ctx, "redos", node, a.text, sinkName); }
  }

  // ── Mass assignment ──
  if (recv && MASS_ASSIGN_METHODS.has(name)) {
    const a = pos[0];
    if (a && isUnsafeParams(a, ctx)) emit(ctx, "mass-assignment", node, a.text, `${sinkName}`,
      `Unrestricted request parameters ('${a.text.slice(0, 60)}') are written to the model — permit only the attributes users may set (no permit!/to_unsafe_h, no role/admin/owner keys)`);
  }

  // ── JWT without verification ──
  if (callee === "JWT.decode") {
    const verify = pos[2];
    const algos = keywordArg(node, "algorithm") ?? keywordArg(node, "algorithms");
    if (verify?.type === "false" || /["']none["']/i.test(algos?.text ?? "")) emit(ctx, "jwt-none-alg", node, pos[0]?.text ?? "token", "JWT.decode",
      "JWT.decode is called without verifying the signature (verification disabled, or the none algorithm allowed) — anyone can forge the token");
  }
}

/** Relation methods with no Enumerable/Array namesake. */
const UNAMBIGUOUS_SQL_METHODS = new Set([
  "where", "rewhere", "order", "reorder", "having", "joins", "left_joins", "left_outer_joins", "update_all", "delete_all",
  "destroy_all", "delete_by", "destroy_by", "find_by_sql", "count_by_sql", "find_or_create_by", "find_or_initialize_by", "reselect", "in_order_of",
]);
/** A receiver chain rooted at a model class (`User`, `Admin::User`) or already a relation (`...where(...)...`). */
function isActiveRecordChain(recv: SyntaxNode): boolean {
  let cur: SyntaxNode | null = recv;
  while (cur?.type === "call") {
    if (UNAMBIGUOUS_SQL_METHODS.has(methodNameOf(cur)) || /^(?:all|unscoped|includes|preload|eager_load|limit|offset|distinct|none)$/.test(methodNameOf(cur))) return true;
    cur = receiverOf(cur);
  }
  return !!cur && (cur.type === "constant" || cur.type === "scope_resolution");
}

function looksLikeDbReceiver(recv: SyntaxNode | null, ctx: EngineCtx): boolean {
  if (!recv) return false;
  const t = (calleeTextRuby(recv) ?? recv.text).toLowerCase();
  if (/\b(?:connection|conn|db|database|pg|mysql|client|sequel|sqlite|redshift|dataset)\b|activerecord|connection$/.test(t)) return true;
  const type = recv.type === "identifier" ? ctx.varTypes.get(recv.text) : undefined;
  return !!type && /^(?:PG|Mysql2|SQLite3|Sequel|ActiveRecord)/.test(type);
}

/** response.headers["X"] = x  /  headers["Location"] = x */
function checkHeaderWrite(left: SyntaxNode, right: SyntaxNode | null, m: number, ctx: EngineCtx, at: SyntaxNode) {
  const obj = left.childForFieldName("object");
  const objText = obj ? calleeTextRuby(obj) : null;
  if (!right || !objText || !/^(?:response\.headers|headers|response\.header)$/.test(objText)) return;
  const keyNode = named(left).find(c => c.id !== obj?.id);
  const key = keyNode ? stringValue(keyNode) : null;
  if (key && /^location$/i.test(key)) fireOn(ctx, "open-redirect", at, right, m, "Location header");
  else fireOn(ctx, "header-injection", at, right, m, `${objText}[]`);
}

function checkTimingCompare(node: SyntaxNode, l: SyntaxNode, r: SyntaxNode, env: Env, ctx: EngineCtx, mask: TaintMaskFn) {
  const nameOf = (n: SyntaxNode) => (n.type === "identifier" || n.type === "instance_variable" || n.type === "constant" ? n.text
    : n.type === "call" ? methodNameOf(n) : n.type === "element_reference" ? (named(n)[1] ? stringValue(named(n)[1]!) ?? "" : "") : "");
  for (const [secret, other] of [[l, r], [r, l]] as const) {
    const nm = nameOf(secret);
    if (nm && SECRET_NAME_RE.test(nm) && !isLiteral(other) && (mask(other, env) & ALL) && !(mask(secret, env) & ALL)) {
      emit(ctx, "timing-attack", node, other.text, nm, `'${other.text.slice(0, 60)}' is compared to ${nm} with == — use ActiveSupport::SecurityUtils.secure_compare (constant-time)`);
      return;
    }
  }
}

// ── Mass assignment tracking ───────────────────────────────────────────────────────────────────────────────

// No trailing \b: `permit!` ends in a non-word character, so a word boundary after it never matches at the end.
const UNSAFE_PARAMS_RE = /\.(?:permit!|to_unsafe_h(?:ash)?\b)/;
function permitsPrivileged(text: string): boolean {
  for (const m of text.matchAll(/\.permit\s*\(([^)]*)\)/g)) {
    for (const sym of m[1].matchAll(/:(\w+)|(\w+):/g)) if (PRIVILEGED_ATTR_RE.test(sym[1] ?? sym[2])) return true;
  }
  return false;
}
function trackUnsafeParams(name: string, right: SyntaxNode, ctx: EngineCtx) {
  if (isUnsafeParams(right, ctx)) ctx.unsafeParamVars.add(name);
}
function isUnsafeParams(n: SyntaxNode, ctx: EngineCtx): boolean {
  const t = n.text;
  if (/\bparams\b/.test(t) && (UNSAFE_PARAMS_RE.test(t) || permitsPrivileged(t))) return true;
  if (/^params$|^params\[:?\w+\]$/.test(t)) return false;   // Rails raises ForbiddenAttributesError for these
  if (n.type === "identifier") {
    if (ctx.unsafeParamVars.has(n.text)) return true;
    const m = ctx.methods.get(n.text);   // user_params -> a permit-all strong-params call
    if (m?.body && m.params.length === 0) return /\bparams\b/.test(m.body.text) && (UNSAFE_PARAMS_RE.test(m.body.text) || permitsPrivileged(m.body.text));
  }
  return false;
}

/** `X.new(...)` / `X.call(...)` -> "X" (for receiver-type resolution of later `svc.method(...)` calls). */
function constructedClass(right: SyntaxNode): string | null {
  if (right.type !== "call" || methodNameOf(right) !== "new") return null;
  const r = receiverOf(right);
  return r && (r.type === "constant" || r.type === "scope_resolution") ? r.text.replace(/^::/, "") : null;
}

// ── Same-file helpers (re-walk with seeded parameters) ────────────────────────────────────────────────────

function seedLocalMethod(node: SyntaxNode, env: Env, ctx: EngineCtx, mask: TaintMaskFn) {
  const recv = receiverOf(node);
  if (recv && recv.type !== "self") return;
  const callee = ctx.methods.get(methodNameOf(node));
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

// ── Cross-file calls (facts from other files' methods) ────────────────────────────────────────────────────

/** Fact keys a call site may resolve to (in source case -- lowercase before lookup), most specific first: `Billing::Charge.call`, `charge.call`, `Charge#call` via
 * `Charge.new(...).call` or a variable typed by `x = Charge.new`. */
function callKeys(node: SyntaxNode, ctx: EngineCtx): string[] {
  const name = methodNameOf(node);
  const recv = receiverOf(node);
  if (!recv) return [];
  const keys: string[] = [];
  const cls = (t: string) => { const c = t.replace(/^::/, ""); keys.push(c); const last = c.split("::").pop()!; if (last !== c) keys.push(last); };
  if (recv.type === "constant" || recv.type === "scope_resolution") {
    const before = keys.length; cls(recv.text);
    for (let i = before; i < keys.length; i++) keys[i] = `${keys[i]}.${name}`;
  } else if (recv.type === "call" && methodNameOf(recv) === "new") {
    const t = constructedClass(recv);
    if (t) { const before = keys.length; cls(t); for (let i = before; i < keys.length; i++) keys[i] = `${keys[i]}#${name}`; }
  } else if (recv.type === "identifier" && ctx.varTypes.has(recv.text)) {
    const before = keys.length; cls(ctx.varTypes.get(recv.text)!);
    for (let i = before; i < keys.length; i++) keys[i] = `${keys[i]}#${name}`;
  }
  return keys;
}

function checkCrossFileCall(node: SyntaxNode, env: Env, ctx: EngineCtx, mask: TaintMaskFn) {
  if (!ctx.crossFileFacts?.size) return;
  // `Klass.new(x)` resolves to `klass.new` like any class method: the constructor's facts (initialize stores x; a later method sinks it)
  const keys = callKeys(node, ctx);
  const shown = keys.find(k => ctx.crossFileFacts!.has(k.toLowerCase()));
  const key = shown?.toLowerCase();
  if (!shown || !key || ctx.localKeys.has(key)) return;
  const facts = ctx.crossFileFacts.get(key)!;
  const pos = positionalArgs(node);
  const line = lineOf(node);
  for (const fact of facts) {
    const bound = fact.isRest ? pos.slice(fact.index) : pos[fact.index] ? [pos[fact.index]] : [];
    for (const a of bound) {
      const m = mask(a, env);
      if (!(m & fact.sinkClass)) { if (wasCleared(m, fact.sinkClass)) ctx.suppressed?.push({ id: fact.id, line }); continue; }
      const dedup = `${fact.id}:${line}`;
      if (ctx.seen.has(dedup)) break;
      ctx.seen.add(dedup);
      const display = displayFnName(shown);
      const via = fact.via.length > 1 ? ` (${fact.via.map(displayFnName).join(" -> ")})` : "";
      const callerTrace = buildBackwardTraceGeneric(ctx.filePath, node, a.text, display, rubyTraceResolver);
      callerTrace[callerTrace.length - 1] = { ...callerTrace[callerTrace.length - 1], snippet: `${display}(...)` };
      ctx.findings.push({
        id: fact.id as AstTaintRubyId, line, sourceExpr: a.text, sinkExpr: `${display}() -> ${fact.sinkExpr}`,
        detail: `Tainted expression '${a.text.slice(0, 80)}' is passed to ${display}(...), which reaches ${fact.sinkExpr}(...) at ${fact.file}:${fact.line} [crosses file boundary${via}] — real data-flow match across files, not a line-pattern guess`,
        trace: crossFileTrace(callerTrace, display, fact),
        calleeSink: { file: fact.file, line: fact.line, sinkExpr: fact.sinkExpr, via: fact.via },
      });
      break;
    }
  }
}

// ── Trace resolver ─────────────────────────────────────────────────────────────────────────────────────────

function enclosingScope(node: SyntaxNode): SyntaxNode | null {
  for (let cur = node.parent; cur; cur = cur.parent) if (NAMED_SCOPES.has(cur.type) || cur.type === "lambda") return cur;
  return null;
}
function assignmentsIn(scope: SyntaxNode): Array<{ name: string; position: number; rhsText: string; line: number }> {
  const out: Array<{ name: string; position: number; rhsText: string; line: number }> = [];
  const visit = (n: SyntaxNode) => {
    if (n !== scope && NAMED_SCOPES.has(n.type)) return;
    if (n.type === "assignment" || n.type === "operator_assignment") {
      const l = n.childForFieldName("left"), r = n.childForFieldName("right");
      if (l && r && (l.type === "identifier" || l.type === "instance_variable")) out.push({ name: l.text, position: n.startIndex, rhsText: r.text, line: lineOf(r) });
    }
    for (const c of named(n)) visit(c);
  };
  visit(scope);
  return out;
}
const rubyTraceResolver: TraceResolver<SyntaxNode> = {
  enclosingScope, assignmentsIn,
  fileScope: n => { let c = n; while (c.parent) c = c.parent; return c; },
  position: n => n.startIndex, line: lineOf, text: n => n.text,
};

// ── Interprocedural summaries ─────────────────────────────────────────────────────────────────────────────

/** Classes a method's return value carries: with parameter `seed` tainted (or none, for its intrinsic sources). */
function returnMask(method: LocalMethod, ctx: EngineCtx, seed: ParamShape | null): number {
  if (!method.body) return 0;
  let surviving = 0;
  const walker = createWalker({ ...ctx, findings: [], seen: new Set(), suppressed: undefined, seeded: new Map(), stickyDirty: false, sticky: new Map(ctx.sticky) },
    { descendLambdas: false, onReturn: (expr, env, mask) => { if (expr) surviving |= mask(expr, env); } });
  const env: Env = new Map();
  for (const p of method.params) env.set(p.name, seed && p.index === seed.index ? ALL : 0);
  const terminated = walker.walk(method.body, env);
  if (!terminated) surviving |= walker.mask(method.body, env);   // implicit return: the last expression's value
  return surviving & ALL;
}

function buildSummaries(ctx: EngineCtx): void {
  for (let round = 0; round < FIXED_POINT_CAP; round++) {
    let changed = false;
    for (const [name, m] of ctx.methods) {
      const intrinsic = returnMask(m, ctx, null);
      if ((intrinsic | (ctx.intrinsic.get(name) ?? 0)) !== (ctx.intrinsic.get(name) ?? 0)) { ctx.intrinsic.set(name, (ctx.intrinsic.get(name) ?? 0) | intrinsic); changed = true; }
      const prop = new Map(ctx.propagating.get(name) ?? []);
      let grew = false;
      for (const p of m.params) {
        const r = returnMask(m, ctx, p) & ~intrinsic;
        const next = (prop.get(p.index) ?? 0) | r;
        if (r && next !== (prop.get(p.index) ?? 0)) { prop.set(p.index, next); grew = true; }
      }
      if (grew) { ctx.propagating.set(name, prop); changed = true; }
    }
    if (!changed) break;
  }
}

// ── BOLA (object-level authorization) ─────────────────────────────────────────────────────────────────────

const LOOKUP_METHODS = new Set(["find", "find_by", "find_by!", "find_by_id", "find_by_id!", "where", "find_or_initialize_by"]);
const WRITE_ON_RECORD = /\.(?:update|update!|update_attribute|update_attributes|update_column|update_columns|destroy|destroy!|delete|save|save!|toggle!|increment!|decrement!|touch|archive!?|cancel!?|approve!?|publish!?)\b|\.\w+\s*=[^=]/;
const WRITE_ACTIONS = /^(?:update|destroy|delete|edit|archive|cancel|approve|publish|transfer|remove|toggle|reset|change|set_\w+|close)/;
const AUTHZ_CALLS = /\b(?:authorize!?|authorize_resource|policy_scope|can\?|cannot\?|load_and_authorize_resource|authorize_action_for|verify_authorized|require_owner|ensure_owner|check_owner|correct_user|owned_by\?|belongs_to_user\?)\b/;
const PRINCIPAL_RE = /\bcurrent_(?:user|account|member|admin|tenant|organization|org)\b|\bCurrent\.(?:user|account|tenant)\b|\bwarden\.user\b/;

/** Class-level evidence: `before_action :correct_user` / `load_and_authorize_resource` / CanCan / Pundit. */
function classAuthEvidence(classNode: SyntaxNode | null, actionName: string): Set<AuthzKind> {
  const ev = new Set<AuthzKind>();
  if (!classNode) return ev;
  // `load_and_authorize_resource` with no arguments parses as a bare identifier in the class body, not a call.
  for (const id of named(classNode.childForFieldName("body"))) {
    if (id.type === "identifier" && /^(?:load_and_authorize_resource|authorize_resource)$/.test(id.text)) ev.add("ownership");
  }
  for (const call of findAllNodes(classNode, "call")) {
    if (enclosingScope(call)) continue;   // class body only
    const m = methodNameOf(call);
    if (m === "load_and_authorize_resource" || m === "authorize_resource") { ev.add("ownership"); continue; }
    if (m !== "before_action" && m !== "before_filter" && m !== "prepend_before_action") continue;
    const only = keywordArg(call, "only"), except = keywordArg(call, "except");
    const applies = (!only || new RegExp(`:${actionName}\\b|["']${actionName}["']`).test(only.text)) && (!except || !new RegExp(`:${actionName}\\b`).test(except.text));
    if (!applies) continue;
    for (const a of positionalArgs(call)) {
      const nm = stringValue(a);
      const kind = nm ? classifyGuardName(nm) : null;
      if (kind) ev.add(kind);
    }
  }
  return ev;
}

function collectBola(method: LocalMethod, ctx: EngineCtx, mask: TaintMaskFn) {
  if (!method.body || method.singleton) return;
  const classNode = (() => { for (let c = method.decl.parent; c; c = c.parent) if (c.type === "class") return c; return null; })();
  const className = classNode?.childForFieldName("name")?.text ?? "";
  if (!/Controller$/.test(className) || /^Admin::|::Admin::|Admin\w*Controller$/.test(method.className ?? "")) return;
  const bodyText = method.body.text;
  if (AUTHZ_CALLS.test(bodyText)) return;
  const evidence = classAuthEvidence(classNode, method.name);
  if (authzVerdict(evidence) === "proven") return;

  const env: Env = new Map();
  for (const p of method.params) env.set(p.name, 0);
  for (const call of findAllNodes(method.body, "call")) {
    const name = methodNameOf(call);
    const recv = receiverOf(call);
    if (!LOOKUP_METHODS.has(name) || !recv) continue;
    // scoped to the principal: current_user.posts.find(id) / Post.where(user: current_user).find(id)
    if (PRINCIPAL_RE.test(recv.text)) continue;
    if (recv.type !== "constant" && recv.type !== "scope_resolution" && !(recv.type === "call" && /^(?:unscoped|all|includes|joins|preload)$/.test(methodNameOf(recv)))) continue;
    // find(params[:id]) / find_by(id: params[:id]) -- the id the caller chose (CONTROL survives to_i)
    const idArg = name === "find" || name === "find_by_id" || name === "find_by_id!" ? positionalArgs(call)[0]
      : keywordArg(call, "id") ?? keywordArg(call, "uuid") ?? keywordArg(call, "slug");
    if (!idArg || !(mask(idArg, env) & SinkClass.CONTROL)) continue;
    // ownership expressed in the query itself
    if (argsOf(call).some(a => a.type === "pair" && isOwnerField(pairKeyText(a) ?? ""))) continue;
    // ownership checked on the loaded record later: @post.user == current_user / post.user_id == current_user.id
    const after = ctx.lines.slice(lineOf(call) - 1, method.body.endPosition.row + 1).join("\n");
    if (PRINCIPAL_RE.test(after) && /(?:==|!=|eql\?)/.test(after) && /\b(?:user|owner|author|account|creator)(?:_id)?\b/.test(after)) continue;
    const writes = WRITE_ACTIONS.test(method.name) || WRITE_ON_RECORD.test(ctx.lines.slice(lineOf(call), method.body.endPosition.row + 1).join("\n"));
    if (!writes) continue;   // an unscoped READ may be of a public record -- not reported (see module docblock)
    const roleOnly = evidence.has("role");
    emit(ctx, "bola-missing-ownership-check", call, idArg.text, `${recv.text}.${name}`,
      `${className}#${method.name} loads ${recv.text} by a request-supplied id (${idArg.text.slice(0, 40)}) and modifies it without checking it belongs to the current user${roleOnly ? " (a role check limits who calls this, not which records they may change)" : ""} — scope the lookup (current_user.${recv.text.toLowerCase()}s.find(...)) or authorize it (Pundit/CanCan)`,
      roleOnly ? "medium" : "high");
  }
}

// ── Entry points ──────────────────────────────────────────────────────────────────────────────────────────

function makeCtx(content: string, filePath: string, root: SyntaxNode, suppressed?: SuppressedSink[],
  crossFileFacts?: ReadonlyMap<string, readonly ParamSinkFact[]>): EngineCtx {
  const all = collectMethods(root);
  const methods = new Map<string, LocalMethod>();
  for (const m of all) if (!methods.has(m.name)) methods.set(m.name, m);
  const ctx: EngineCtx = {
    filePath, lines: content.split("\n"), root, methods, propagating: new Map(), intrinsic: new Map(), seeded: new Map(),
    suppressed, findings: [], seen: new Set(), sticky: new Map(), stickyDirty: false, varTypes: new Map(),
    heredocs: heredocBodies(root), crossFileFacts, localKeys: new Set(all.map(m => m.key).filter((k): k is string => !!k)),
    unsafeParamVars: new Set(),
  };
  buildSummaries(ctx);
  return ctx;
}

const walkMain = (node: SyntaxNode, env: Env, ctx: EngineCtx) => createWalker(ctx, { descendLambdas: true }).walk(node, env);

function scanMethods(ctx: EngineCtx, structural: boolean) {
  for (const [, m] of ctx.methods) {
    if (!m.body) continue;
    const env: Env = new Map();
    for (const p of m.params) env.set(p.name, 0);   // parameters shadow sources (a `params` argument is not request input)
    walkMain(m.body, env, ctx);
    if (structural) collectBola(m, ctx, makeTaintMask(ctx));
  }
}

function drainSeeded(ctx: EngineCtx) {
  const walked = new Set<string>();
  for (let round = 0; round < FIXED_POINT_CAP; round++) {
    let changed = false;
    for (const [name, idx] of Array.from(ctx.seeded.entries())) {
      const m = ctx.methods.get(name);
      if (!m?.body) continue;
      const sig = `${name}:${[...idx].sort((a, b) => a[0] - b[0]).map(([i, v]) => `${i}=${v}`).join(",")}`;
      if (walked.has(sig)) continue;
      walked.add(sig);
      changed = true;
      const env: Env = new Map();
      for (const p of m.params) env.set(p.name, idx.get(p.index) ?? 0);
      walkMain(m.body, env, ctx);
    }
    if (!changed) break;
  }
}

export function scanAstTaintRuby(
  content: string, filePath: string, root: SyntaxNode, suppressedOut?: SuppressedSink[],
  crossFileFacts?: ReadonlyMap<string, readonly ParamSinkFact[]>,
): AstTaintRubyFinding[] {
  try {
    const ctx = makeCtx(content, filePath, root, suppressedOut, crossFileFacts);
    scanMethods(ctx, true);
    // Instance variables one action/filter writes are read by another: re-walk until they stop growing.
    for (let round = 0; round < FIXED_POINT_CAP && ctx.stickyDirty; round++) {
      ctx.stickyDirty = false;
      scanMethods(ctx, false);
    }
    // Top-level script code (Sinatra routes, rake tasks): `get "/x" do ... end` blocks are calls with blocks.
    const topEnv: Env = new Map();
    for (const child of named(root)) {
      if (child.type === "class" || child.type === "module" || child.type === "method" || child.type === "singleton_method") {
        // class bodies can hold Sinatra routes too (class App < Sinatra::Base; get "/" do ... end)
        if (child.type === "class" || child.type === "module") {
          for (const inner of named(child.childForFieldName("body"))) if (inner.type === "call") walkMain(inner, new Map(), ctx);
        }
        continue;
      }
      walkMain(child, topEnv, ctx);
    }
    drainSeeded(ctx);
    return ctx.findings;
  } catch (err) {
    console.error(`[astTaintRuby] threw scanning ${filePath}:`, err);
    return [];
  }
}

/** Findings that are not "this argument reaches that sink" -- a caller doesn't re-raise them. */
const NON_FLOW_IDS: ReadonlySet<string> = new Set(["bola-missing-ownership-check", "timing-attack", "jwt-none-alg", "mass-assignment"]);

/**
 * Parameter -> sink facts for every method in one file, keyed by lower-cased `Class.method` (singleton methods
 * and scopes) / `Class#method` (instance methods), plus `Class.new` for a constructor whose arguments are stored
 * in instance variables that another instance method sinks (the service-object idiom `Charge.new(x).call`).
 * Computed with the scan's own sink logic, each parameter walked alone, diffed against an unseeded baseline.
 */
export function computeRubyMethodSinkFacts(
  content: string, filePath: string, root: SyntaxNode, incoming: ReadonlyMap<string, readonly ParamSinkFact[]>,
): Map<string, ParamSinkFact[]> {
  const out = new Map<string, ParamSinkFact[]>();
  try {
    const ctx = makeCtx(content, filePath, root, undefined, incoming);
    const all = collectMethods(root);
    const ranges = all.map(m => ({ name: m.name, start: m.decl.startPosition.row + 1, end: m.decl.endPosition.row + 1 }));
    const run = (body: SyntaxNode, env: Env, stickySeed?: Map<string, number>): AstTaintRubyFinding[] => {
      ctx.findings = []; ctx.seen = new Set(); ctx.seeded = new Map();
      ctx.sticky = new Map(stickySeed ?? []);
      walkMain(body, env, ctx);
      drainSeeded(ctx);
      return ctx.findings;
    };
    const factsFor = (m: LocalMethod, findings: AstTaintRubyFinding[], baseline: Set<string>, p: ParamShape, label: string, viaPrefix: string[]): ParamSinkFact[] => {
      const facts: ParamSinkFact[] = [];
      for (const f of dropOnPathDuplicates(findings)) {
        if (baseline.has(`${f.id}:${f.line}`) || NON_FLOW_IDS.has(f.id)) continue;
        const where = f.calleeSink;
        mergeSinkFacts(facts, [{
          index: p.index, isRest: p.isRest, id: f.id, sinkClass: classOf(f.id),
          sinkExpr: where?.sinkExpr ?? f.sinkExpr, file: where?.file ?? filePath, line: where?.line ?? f.line,
          via: [...viaPrefix, ...(where?.via ?? [])],
          steps: f.trace?.length ? factStepsFromTrace(f.trace, label, filePath, m.decl.startPosition.row + 1, p.name,
            { fnEnd: m.decl.endPosition.row + 1, functions: ranges, lines: ctx.lines }) : undefined,
        }]);
      }
      return facts;
    };
    const add = (key: string, facts: ParamSinkFact[]) => {
      const list = out.get(key) ?? [];
      mergeSinkFacts(list, facts);
      out.set(key, list);
    };

    for (const m of all) {
      if (!m.key || !m.body) continue;
      if (!out.has(m.key)) out.set(m.key, []);   // listed even with no facts: callers know it is user code
      const positional = m.params.filter(p => !p.keyword);
      if (positional.length === 0) continue;
      const env0: Env = new Map(m.params.map(p => [p.name, 0]));
      const baseline = new Set(run(m.body, env0).map(f => `${f.id}:${f.line}`));
      const label = `${m.className ?? ""}${m.singleton ? "." : "#"}${m.name}`;
      const facts: ParamSinkFact[] = [];
      for (const p of positional) {
        const env: Env = new Map(m.params.map(q => [q.name, q.index === p.index ? ALL : 0]));
        mergeSinkFacts(facts, factsFor(m, run(m.body, env), baseline, p, label, [label]));
      }
      if (facts.length) add(m.key, facts);
    }

    // Constructors: initialize(x) stores x in @ivars; any instance method of the same class that sinks them.
    for (const init of all.filter(m => m.name === "initialize" && m.className && m.body)) {
      const siblings = all.filter(m => m.className === init.className && !m.singleton && m.name !== "initialize" && m.body);
      if (siblings.length === 0) continue;
      const label = `${init.className}.new`;
      const facts: ParamSinkFact[] = [];
      for (const p of init.params.filter(q => !q.keyword)) {
        // which ivars does this parameter reach?
        ctx.sticky = new Map();
        const env: Env = new Map(init.params.map(q => [q.name, q.index === p.index ? ALL : 0]));
        ctx.findings = []; ctx.seen = new Set();
        walkMain(init.body!, env, ctx);
        const ivars = new Map([...ctx.sticky].filter(([, v]) => v & ALL));
        if (ivars.size === 0) continue;
        for (const s of siblings) {
          const baseline = new Set(run(s.body!, new Map(s.params.map(q => [q.name, 0]))).map(f => `${f.id}:${f.line}`));
          const found = run(s.body!, new Map(s.params.map(q => [q.name, 0])), ivars);
          mergeSinkFacts(facts, factsFor(s, found, baseline, p, `${init.className}#${s.name}`, [label, `${init.className}#${s.name}`]));
        }
      }
      if (facts.length) add(`${init.className}.new`.toLowerCase(), facts);
    }
  } catch (err) {
    console.error(`[astTaintRuby] threw computing method sink facts for ${filePath}:`, err);
  }
  return out;
}
