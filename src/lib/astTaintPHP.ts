/**
 * Real AST-based taint engine for PHP — sixth and final language in this
 * multi-phase effort (see astTaint.ts for JS/TS, astTaintPython.ts for
 * Python, astTaintJava.ts for Java, astTaintGo.ts for Go, astTaintCSharp.ts
 * for C#, whose five-stage architecture -- sources, sinks, propagation,
 * interprocedural, findings -- this file mirrors).
 *
 * Parsing mechanics mirror astTaintGo.ts's/astTaintCSharp.ts's web-tree-sitter
 * warm-cache pattern, using tree-sitter-wasms' prebuilt tree-sitter-php.wasm
 * grammar (already bundled in this repo's existing dependency -- no new
 * package needed, confirmed the same way C#'s grammar was).
 *
 * The taint-walker shape follows Go's/Python's/C#'s recursive descent, NOT
 * Java's flat fold -- confirmed by direct empirical probing of the real
 * grammar: a fluent chain like `db()->query($sql)->fetch()` nests
 * RECURSIVELY (the outer `member_call_expression`'s receiver is itself
 * another `member_call_expression`), the same shape astTaintGo.ts/
 * astTaintCSharp.ts already recurse through. Unlike every other language
 * handled so far, PHP has THREE distinct call-expression node types instead
 * of one generic "invocation with a callee expression" shape --
 * `function_call_expression` (bare `foo(...)`), `member_call_expression`
 * (`$obj->method(...)`), and `scoped_call_expression` (`Class::method(...)`)
 * -- each carrying its own `name` field for the function/method being
 * called directly, confirmed via direct probing, not assumed.
 *
 * Several real, PHP-specific adaptations from the Java/C# template,
 * reasoned through directly rather than copied blind:
 *  - PHP has no separate variable-declaration statement -- `$x = $y;` is
 *    the SAME `assignment_expression` node whether `$x` is a brand-new
 *    local or a re-assignment (PHP variables are not statically declared).
 *    So, unlike every other engine here, there is no separate
 *    local-declaration-statement handler; assignment_expression alone
 *    covers both.
 *  - PHP has no parameter-attribute source convention the way Spring's
 *    @PathVariable/ASP.NET's [FromQuery] do -- taint instead originates
 *    UNIFORMLY from superglobal access ($_GET/$_POST/etc) anywhere in the
 *    walk, including inside an assignment's right-hand side, so no
 *    per-function param-seeding step is needed at all (a genuine
 *    simplification versus Java's/C#'s SPRING_SOURCE_ANNOTATIONS-seeded
 *    environment).
 *  - The BOLA/authorization detector's isEndpoint/resourceId/suppression
 *    signals can't be attribute-based (no [Authorize]/@PreAuthorize
 *    equivalent without cross-referencing a separate routes file, out of
 *    scope) -- resourceId params are identified by NAME convention
 *    (id/userId/user_id), matching the SAME breadth the existing
 *    findNamedTaintIDORPHP regex detector already accepts (not gated on
 *    any "is this a route handler" class/attribute signal either, so this
 *    doesn't regress recall versus the regex baseline), and suppression is
 *    detected structurally via a real call to Auth::check()/auth()->check()/
 *    auth()->user() found anywhere in the method body, rather than an
 *    annotation.
 *  - Severity tiering (read vs write) uses a name-convention heuristic
 *    (get/show/index/view/find -> read; everything else, including unknown
 *    names -> write, the conservative default when unsure) since PHP
 *    methods have no HTTP-verb attribute to read directly.
 *
 * Runs ADDITIVELY alongside every existing PHP regex/named-taint detector
 * in scanner.ts (findNamedTaintDeserializationPHP, findDeserializationPHPWrapped,
 * findPHPPharDeserialization, findSQLInjectionPHPInterpolated,
 * findSQLInjectionPHPMultilineBuild, findNamedTaintCommandInjectionPHP,
 * findNamedTaintPathTraversalPHP, findPHPFileInclusion, findNamedTaintSSRFPHP,
 * findNamedTaintXSSPHP, findNamedTaintIDORPHP, findPHPMissingSessionGuard)
 * -- none of those are touched, removed, or replaced. Reuses existing
 * finding ids (sql-injection, command-injection, xss, ssrf, path-traversal,
 * open-redirect, insecure-deserialization, file-inclusion,
 * bola-missing-ownership-check), all already wired through cweMap.ts/
 * sarif.ts/githubComment.ts, so no new UI wiring is needed.
 *
 * Deliberately excludes, matching every prior engine's own precedent:
 * hardening-absence checks (php-missing-session-guard stays regex-only,
 * it's a "no nearby guard" question, not a data-flow one), Laravel Blade /
 * WordPress mixed HTML+PHP template parsing (this engine parses plain .php
 * only), branch/CFG-aware authorization analysis, cross-file propagation,
 * and modeling a framework-less top-level script's superglobal access as
 * an implicit whole-file entry point (a genuinely different reachability
 * shape than every other language's function-centric one -- accepted,
 * documented gap, not silently missed).
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { Parser, Language } = require("web-tree-sitter") as typeof import("web-tree-sitter");
import type { Node as SyntaxNode, Language as LanguageT, Parser as ParserT } from "web-tree-sitter";
import { ensureTreeSitterInit } from "./treeSitterRuntime";
import {
  ALL, SHADOW, applyClears, applyGuards, classOf, cloneEnv, walkIfChain, walkLoop, walkSwitch, walkTry, wasCleared,
  type Branch, type Guard, type SuppressedSink, type TaintEnv,
} from "./taint/taintCore";
import { sanitizerClears, NUMERIC_CLEARS } from "./taint/sanitizers";

declare const __non_webpack_require__: NodeJS.Require | undefined;
function nodeRequire(): NodeJS.Require {
  // eslint-disable-next-line no-undef
  return typeof __non_webpack_require__ !== "undefined" ? __non_webpack_require__ : require;
}

export type AstTaintPHPId =
  | "sql-injection" | "command-injection" | "xss" | "ssrf" | "path-traversal"
  | "open-redirect" | "insecure-deserialization" | "file-inclusion"
  | "bola-missing-ownership-check" | "header-injection" | "ldap-injection"
  | "nosql-injection" | "xpath-injection"
  | "eval-exec" | "ssti" | "mass-assignment" | "redos" | "timing-attack" | "jwt-none-alg";

export interface AstTaintPHPFinding {
  id:         AstTaintPHPId;
  line:       number;
  detail:     string;
  sourceExpr: string;
  sinkExpr:   string;
  severityOverride?: "critical" | "high" | "medium";
}

// ── Parser lifecycle (warm-cache pattern -- see astTaintCSharp.ts's identical docblock) ──

let langPromise: Promise<LanguageT> | null = null;
let parserPool: ParserT | null = null;

function initPhpParser(): Promise<LanguageT> {
  if (!langPromise) {
    langPromise = (async () => {
      await ensureTreeSitterInit();
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const fs = require("fs") as typeof import("fs");
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const path = require("path") as typeof import("path");
      const webTreeSitterEntry = nodeRequire().resolve("web-tree-sitter");
      const nodeModulesDir = path.dirname(path.dirname(webTreeSitterEntry));
      const wasmPath = path.join(nodeModulesDir, "tree-sitter-wasms", "out", "tree-sitter-php.wasm");
      const lang = await Language.load(new Uint8Array(fs.readFileSync(wasmPath)));
      const p = new Parser();
      p.setLanguage(lang);
      parserPool = p;
      console.log("[astTaintPHP] PHP AST taint engine ready");
      return lang;
    })().catch(err => {
      console.error("[astTaintPHP] WASM init failed -- PHP AST taint scanning disabled, regex detectors unaffected:", err);
      throw err;
    });
  }
  return langPromise;
}
if (!process.env.JEST_WORKER_ID) {
  void initPhpParser().catch(() => { /* already logged above */ });
}

export function isPhpParserReady(): boolean {
  return parserPool !== null;
}

export async function warmPhpTaintEngine(): Promise<void> {
  await initPhpParser().catch(() => { /* already logged; callers just proceed regex-only */ });
}

export function parsePhpSourceSync(content: string, filePath: string): SyntaxNode | null {
  if (!parserPool) return null;
  try {
    return parserPool.parse(content)?.rootNode ?? null;
  } catch (err) {
    console.error(`[astTaintPHP] parse threw for ${filePath}:`, err);
    return null;
  }
}

// ── Enclosing-function lookup (shared with reachability.ts's resolver) ──────

export function findNodeAtRowPHP(root: SyntaxNode, row: number): SyntaxNode {
  let node = root;
  for (;;) {
    const child = node.namedChildren.find(c => c && row >= c.startPosition.row && row <= c.endPosition.row);
    if (!child) return node;
    node = child;
  }
}

export function findEnclosingFunctionNamePHP(node: SyntaxNode): string {
  let cur: SyntaxNode | null = node;
  while (cur) {
    if (cur.type === "function_definition" || cur.type === "method_declaration") {
      const nameNode = cur.childForFieldName("name");
      if (nameNode) return nameNode.text;
    }
    cur = cur.parent;
  }
  return "unknown";
}

// ── CST helpers ──────────────────────────────────────────────────────────

/** The bare identifier inside a `$name` variable_name node, without the
 * sigil -- e.g. for `$id`, returns "id". */
function variableBareName(node: SyntaxNode): string | null {
  const nameNode = node.namedChildren.find(c => c && c.type === "name");
  return nameNode ? nameNode.text : null;
}

/** Resolves a member-access/scoped-call/call chain to dotted text, e.g.
 * `$user->profile` -> "user.profile", `Database::find` -> "Database.find".
 * Recursive, matching this file's own docblock on why (confirmed directly
 * that PHP's call chains nest, unlike Java's flat primarySuffix array). */
function calleeTextPHP(node: SyntaxNode): string | null {
  if (node.type === "name") return node.text;
  if (node.type === "variable_name") return variableBareName(node);
  if (node.type === "member_access_expression" || node.type === "member_call_expression" || node.type === "scoped_call_expression") {
    const base = node.namedChildren[0];
    const nameField = node.childForFieldName("name");
    if (!base || !nameField) return null;
    const baseText = calleeTextPHP(base);
    return baseText ? `${baseText}.${nameField.text}` : null;
  }
  return null;
}

/** `argument` nodes wrap the real expression as their single named child,
 * no field name -- confirmed directly. Unwraps one level, matching every
 * other engine's argListOf* convention. `arguments` itself is a named
 * FIELD on function_call_expression/member_call_expression/
 * scoped_call_expression, but confirmed directly NOT field-named on
 * object_creation_expression (`new X(...)`) -- the positional fallback
 * below covers that case too, rather than needing a second helper. */
function argListOfPHP(call: SyntaxNode): SyntaxNode[] {
  const args = call.childForFieldName("arguments")
    ?? call.namedChildren.find((c): c is SyntaxNode => !!c && c.type === "arguments");
  if (!args) return [];
  return args.namedChildren
    .filter((n): n is SyntaxNode => !!n && n.type === "argument")
    .map(a => a.namedChildren[0])
    .filter((n): n is SyntaxNode => !!n);
}

function findAllNodes(root: SyntaxNode, type: string, acc: SyntaxNode[] = []): SyntaxNode[] {
  if (root.type === type) acc.push(root);
  for (const c of root.namedChildren) if (c) findAllNodes(c, type, acc);
  return acc;
}

function lineOf(node: SyntaxNode): number {
  return node.startPosition.row + 1;
}

const PHP_SCRIPT_CONTEXT_RE = /<script\b[^>]*>(?:(?!<\/script>)[\s\S])*$/i;

/** A PHP string literal's value (plain `'...'` or a non-interpolated `"..."`), or null. */
function phpStringValue(n: SyntaxNode): string | null {
  if (n.type === "string") return n.namedChildren.filter(c => c?.type === "string_content").map(c => c!.text).join("");
  if (n.type === "encapsed_string" && n.namedChildren.every(c => !!c && (c.type === "string_content" || c.type === "escape_sequence"))) {
    return n.namedChildren.map(c => c!.text).join("");
  }
  return null;
}
/** Flatten a `a . b . c` concatenation chain into its operands, or null when it is not a pure `.` chain. */
function phpConcatOperands(n: SyntaxNode): SyntaxNode[] | null {
  if (n.type !== "binary_expression" || n.childForFieldName("operator")?.type !== ".") return null;
  const l = n.childForFieldName("left");
  const r = n.childForFieldName("right");
  if (!l || !r) return null;
  const left = l.type === "binary_expression" && l.childForFieldName("operator")?.type === "." ? phpConcatOperands(l) : [l];
  return left ? [...left, r] : null;
}

// ── Taint sources ────────────────────────────────────────────────────────

const SUPERGLOBAL_NAMES = new Set(["_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER"]);
// Laravel: $request->input(...)/->query(...)/->get(...)/->all(...) -- the
// receiver's own variable name isn't checked (matches any receiver by
// method-name tail, same permissive-by-design posture the sanitizer tables
// across every engine already use), since a typed `Request $request`
// parameter has no attribute this engine can reliably read without
// re-probing a parameter type-hint field shape that wasn't confirmed.
const LARAVEL_REQUEST_METHODS = new Set(["input", "query", "all", "post", "get"]);

// Set into env by \`extract($tainted)\` -- see makeTaintMaskPHP's variable_name case. An impossible PHP
// variable name, so it can never collide with a real one.
const PHP_WILDCARD_VAR = "\\u0000wildcard";

// Static/utility functions whose RESULT carries the taint of their arguments (string/array plumbing that
// neither validates nor neutralizes anything). Opaque calls stay untainted, exactly as before.
const PHP_PASSTHROUGH = new Set([
  "trim", "ltrim", "rtrim", "strtolower", "strtoupper", "mb_strtolower", "mb_strtoupper", "ucfirst", "lcfirst",
  "ucwords", "nl2br", "addslashes", "stripslashes", "wordwrap", "str_pad", "str_repeat", "number_format",
  "substr", "mb_substr", "sprintf", "vsprintf", "str_replace", "str_ireplace", "preg_replace", "preg_replace_callback",
  "implode", "join", "explode", "array_merge", "array_merge_recursive", "array_combine", "array_values", "array_keys",
  "array_map", "array_filter", "array_slice", "array_unique", "array_reverse", "array_pad",
  "json_encode", "json_decode", "serialize", "realpath", "dirname", "pathinfo",
  "base64_encode", "base64_decode", "bin2hex", "hex2bin", "htmlspecialchars_decode", "html_entity_decode",
  "urldecode", "rawurldecode",
]);
// Decoders re-taint what a sanitizer cleared (encode-then-decode round trip) -- SHADOW-bit retaint,
// matching every other engine's identical decoder table.
const PHP_DECODERS = new Set(["urldecode", "rawurldecode", "base64_decode", "html_entity_decode", "htmlspecialchars_decode"]);
const PHP_SECRET_NAME_RE = /secret|token|password|passwd|apikey|api_key|hmac|signature/i;

function isTaintSourceExprPHP(node: SyntaxNode): boolean {
  if (node.type !== "subscript_expression") return false;
  const base = node.namedChildren[0];
  if (!base || base.type !== "variable_name") return false;
  const varName = variableBareName(base);
  return !!varName && SUPERGLOBAL_NAMES.has(varName);
}

// ── Sanitizer/de-taint recognition ──────────────────────────────────────
// Now lives in taint/sanitizers.ts, keyed by the sink classes each one
// actually neutralizes (htmlspecialchars clears XSS, not SQL/command/path),
// with filter_var depending on its filter constant and method-style
// sanitizers limited to the real ones (mysqli->real_escape_string,
// PDO->quote) instead of matching any `->htmlspecialchars`. Numeric CASTS --
// `(int)$x` -- are modeled in makeTaintMaskPHP below.
const PHP_NUMERIC_CAST_TYPES = new Set(["int", "integer", "float", "double", "bool", "boolean"]);

// ── Sink dispatch tables ─────────────────────────────────────────────────

const SEVERITY: Record<AstTaintPHPId, "critical" | "high" | "medium"> = {
  "sql-injection": "critical", "command-injection": "critical", "xss": "critical",
  "ssrf": "critical", "path-traversal": "critical", "insecure-deserialization": "critical",
  "file-inclusion": "critical", "open-redirect": "medium",
  "bola-missing-ownership-check": "high",
  "header-injection": "critical", "ldap-injection": "critical",
  "nosql-injection": "critical", "xpath-injection": "critical",
  "eval-exec": "critical", "ssti": "critical", "mass-assignment": "high", "redos": "high",
  "timing-attack": "medium", "jwt-none-alg": "critical",
};
const LABEL: Record<AstTaintPHPId, string> = {
  "sql-injection": "SQL Injection", "command-injection": "Command Injection", "xss": "Reflected XSS",
  "ssrf": "Server-Side Request Forgery", "path-traversal": "Path Traversal",
  "insecure-deserialization": "Insecure Deserialization", "file-inclusion": "PHP File Inclusion",
  "open-redirect": "Open Redirect",
  "bola-missing-ownership-check": "Broken Object Level Authorization (AST-verified)",
  "header-injection": "HTTP Header Injection", "ldap-injection": "LDAP Injection",
  "nosql-injection": "NoSQL Injection", "xpath-injection": "XPath Injection",
  "eval-exec": "Arbitrary Code Execution", "ssti": "Server-Side Template Injection",
  "mass-assignment": "Mass Assignment", "redos": "ReDoS — Regex DoS", "timing-attack": "Timing Attack",
  "jwt-none-alg": "JWT Signature Not Verified",
};

// ── Taint environment / propagation ─────────────────────────────────────

type Env = TaintEnv;
// function name -> (param index -> sink classes that survive to its return value)
type PropagatingPHP = Map<string, Map<number, number>>;
interface ParamShape { name: string; index: number }
interface LocalFunction {
  name: string;
  paramShapes: ParamShape[];
  resourceIdParamNames: Set<string>;
  authMeta: FuncAuthMeta;
  body: SyntaxNode | null;
}

interface EngineCtx {
  content: string;
  lines: string[];
  localFunctions: Map<string, LocalFunction>;
  propagatingParams: PropagatingPHP;
  // function name -> (tainted param index -> classes tainted at the call site)
  seededParams: Map<string, Map<number, number>>;
  // Sinks whose argument was tainted for the sink's class but positively
  // cleared by a sanitizer (see astTaint.ts) -- lets scanner.ts drop the
  // regex layer's duplicate for a flow this engine proved safe.
  suppressed?: SuppressedSink[];
  findings: AstTaintPHPFinding[];
  seen: Set<string>;
  // $var = new ClassName(...) -- variable-to-class-name tracking, mirroring
  // astTaintCSharp.ts's ctx.varTypes exactly. Used only to disambiguate a
  // same-named method call between an unrelated receiver type and a real
  // SQL driver (e.g. DOMXPath::query() vs a DB driver's ->query()) -- see
  // checkMemberCallSink's SQL_CALL_TAILS branch.
  varTypes: Map<string, string>;
  // File root -- lets guards resolve a literal-array variable/constant declared elsewhere in the file.
  root?: SyntaxNode;
  // `global $x;` memory: a variable one function writes and another reads via `global`, visible across
  // the whole file (second-order flows) -- mirrors astTaintCSharp.ts's ctx.sticky exactly.
  globalNames: Set<string>;
  sticky: Map<string, number>;
  stickyDirty: boolean;
  recordSticky: boolean;
}

function emit(
  ctx: EngineCtx, id: AstTaintPHPId, node: SyntaxNode, sourceExpr: string, sinkExpr: string,
  severityOverride?: "critical" | "high" | "medium",
) {
  const line = lineOf(node);
  const key = `${id}:${line}`;
  if (ctx.seen.has(key)) return;
  ctx.seen.add(key);
  ctx.findings.push({
    id, line, sinkExpr, sourceExpr, severityOverride,
    detail: `Tainted expression '${sourceExpr}' flows into ${sinkExpr}(...) — real data-flow match, not a line-pattern guess`,
  });
}

type TaintMaskFnPHP = (node: SyntaxNode, env: Env) => number;

function makeTaintMaskPHP(ctx: EngineCtx): TaintMaskFnPHP {
  const taintMask = (node: SyntaxNode, env: Env): number => {
    if (isTaintSourceExprPHP(node)) return ALL;
    if (node.type === "variable_name") {
      const varName = variableBareName(node);
      // a bare superglobal (`foreach ($_POST as $k => $v)`) is attacker-controlled as a whole
      if (varName && SUPERGLOBAL_NAMES.has(varName)) return ALL;
      if (!varName) return 0;
      const bound = env.get(varName);
      // extract($tainted) makes every subsequently-read, not-otherwise-bound local variable
      // attacker-controlled -- see the assignment where PHP_WILDCARD_VAR is set.
      return bound !== undefined ? bound : (env.get(PHP_WILDCARD_VAR) ?? 0);
    }
    if (node.type === "name") return 0;
    if (node.type === "argument") {
      const inner = node.namedChildren[0];
      return inner ? taintMask(inner, env) : 0;
    }
    if (node.type === "cast_expression") {
      // (int)$x / (float)$x / (bool)$x -- a numeric cast neutralizes every
      // injection class (was silently taint-PRESERVING through the generic
      // fallback while intval($x) cleared, an inconsistency within this one
      // engine). Any other cast ((string)$x, (array)$x) passes through.
      const typeNode = node.childForFieldName("type") ?? node.namedChildren[0];
      const valueNode = node.childForFieldName("value") ?? node.namedChildren[node.namedChildren.length - 1];
      const inner = valueNode ? taintMask(valueNode, env) : 0;
      return typeNode && PHP_NUMERIC_CAST_TYPES.has(typeNode.text.trim().toLowerCase()) ? applyClears(inner, NUMERIC_CLEARS) : inner;
    }
    if (node.type === "binary_expression") {
      const op = node.childForFieldName("operator")?.type;
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if ((op === "." || op === "+" || op === "??") && left && right) return taintMask(left, env) | taintMask(right, env);
      return 0;
    }
    if (node.type === "conditional_expression") {
      // `c ? a : b` -- the condition steers control and is NOT part of the value;
      // the short form `c ?: b` yields c itself when truthy, so it carries.
      const cond = node.childForFieldName("condition");
      const cons = node.childForFieldName("body");
      const alt = node.childForFieldName("alternative");
      return (cons ? taintMask(cons, env) : cond ? taintMask(cond, env) : 0) | (alt ? taintMask(alt, env) : 0);
    }
    if (node.type === "match_expression") {
      // value = union of the arm results; the subject is not part of the value
      let m = 0;
      const block = node.childForFieldName("body");
      for (const arm of block?.namedChildren ?? []) {
        const result = arm?.childForFieldName("return_expression");
        if (result) m |= taintMask(result, env);
      }
      return m;
    }
    if (node.type === "member_access_expression") {
      // Field-sensitive read: OR the full dotted path composite key (set by
      // the assignment write-side below) with the base's own mask -- pure
      // recall gain, never removes a class the fallback alone would find.
      const path = calleeTextPHP(node);
      const base = node.namedChildren[0];
      return (path ? (env.get(path) ?? 0) : 0) | (base ? taintMask(base, env) : 0);
    }
    if (node.type === "object_creation_expression") {
      return argListOfPHP(node).reduce((m, a) => m | taintMask(a, env), 0);
    }
    if (node.type === "function_call_expression") {
      const fnNode = node.childForFieldName("function");
      const fnName = fnNode?.type === "name" ? fnNode.text : null;
      const args = argListOfPHP(node);
      if (fnName) {
        // Known sanitizer: the argument's taint passes THROUGH minus only
        // the classes it neutralizes (filter_var depends on its constant).
        const clears = sanitizerClears("php", fnName, args.map(a => a.text));
        if (clears !== null) return args[0] ? applyClears(taintMask(args[0], env), clears) : 0;
      }
      // filter_input(...) -- itself a source call, regardless of args.
      if (fnName === "filter_input") return ALL;
      // file_get_contents("php://input") -- reads the raw request body, attacker-controlled
      // regardless of args being a literal string.
      if (fnName === "file_get_contents" && /php:\/\/input/i.test(args[0]?.text ?? "")) return ALL;
      if (fnName) {
        const propIdx = ctx.propagatingParams.get(fnName);
        if (propIdx) {
          const callee = ctx.localFunctions.get(fnName);
          const shapes = callee?.paramShapes ?? [];
          let m = 0;
          for (const [i, surviving] of propIdx) {
            if (shapes[i] !== undefined && args[i] !== undefined) m |= taintMask(args[i], env) & surviving;
          }
          if (m) return m;
        }
      }
      // Curated string/array/JSON plumbing: the result carries its arguments' taint.
      if (fnName && PHP_PASSTHROUGH.has(fnName)) {
        const m = args.reduce((acc, a) => acc | taintMask(a, env), 0);
        return PHP_DECODERS.has(fnName) ? (m & ALL) | ((m >>> SHADOW) & ALL) : m;
      }
      // \`$fn(...)\` -- calling a variable as a function: its result depends on what the variable
      // itself holds (a closure captured from tainted data) and on what it is called with.
      if (!fnName && fnNode?.type === "variable_name") {
        const nm = variableBareName(fnNode);
        return args.reduce((m, a) => m | taintMask(a, env), nm ? (env.get(nm) ?? 0) : 0);
      }
      return 0;
    }
    if (node.type === "member_call_expression") {
      const methodName = node.childForFieldName("name")?.text;
      if (methodName) {
        const args = argListOfPHP(node);
        const clears = sanitizerClears("php", calleeTextPHP(node) ?? methodName, args.map(a => a.text));
        if (clears !== null) return args[0] ? applyClears(taintMask(args[0], env), clears) : 0;
      }
      if (methodName && LARAVEL_REQUEST_METHODS.has(methodName)) return ALL;
      // Generic passthrough: a method call on an already-tainted receiver
      // stays tainted (e.g. $dirty->trim()).
      const receiver = node.namedChildren[0];
      if (receiver) return taintMask(receiver, env);
      return 0;
    }
    // Generic fallback -- recurse into every named child and OR-combine.
    // Confirmed directly (via probing "...{$id}..." encapsed_string
    // interpolation) that a bare `variable_name` interpolated into a
    // double-quoted string is a DIRECT named child, not wrapped in any
    // interpolation-specific node -- so this alone reaches it without a
    // special case, the same conclusion astTaintCSharp.ts's own docblock
    // reached for its own $"...{x}..." equivalent.
    let m = 0;
    for (const child of node.namedChildren) if (child) m |= taintMask(child, env);
    return m;
  };
  return taintMask;
}

/**
 * For each of `fn`'s parameters INDEPENDENTLY, does `fn`'s return value
 * become tainted? Returns the set of propagating parameter INDICES --
 * identical reasoning to every other engine's computeReturnTaintPropagating*.
 */
function computeReturnTaintPropagatingPHP(fn: LocalFunction, ctx: EngineCtx): Map<number, number> {
  // param index -> sink classes that still survive to the return value
  const propagatingIdx = new Map<number, number>();
  if (!fn.body) return propagatingIdx;
  for (const shape of fn.paramShapes) {
    let surviving = 0;
    // Path-sensitive: the mask is taken at EACH return with the env on that
    // path; a return inside a closure is not this function's. Sink checks run
    // against a throwaway ctx copy.
    const walker = createWalkerPHP({ ...ctx, findings: [], seen: new Set(), suppressed: undefined, seededParams: new Map() },
      { descendFunctions: false, onReturn: (expr, env, mask) => { surviving |= mask(expr, env); } });
    const env: Env = new Map();
    env.set(shape.name, ALL);
    walker.walk(fn.body, env);
    // Low bits only: the shadow half is per-scan bookkeeping, not a summary.
    surviving &= ALL;
    if (surviving) propagatingIdx.set(shape.index, surviving);
  }
  return propagatingIdx;
}

const MAX_PROPAGATION_ROUNDS = 3;

function buildPropagatingMapPHP(localFunctions: Map<string, LocalFunction>, baseCtx: EngineCtx): PropagatingPHP {
  const propagating: PropagatingPHP = new Map();
  for (let round = 0; round < MAX_PROPAGATION_ROUNDS; round++) {
    let changed = false;
    const roundCtx: EngineCtx = { ...baseCtx, propagatingParams: propagating };
    for (const [name, fn] of localFunctions) {
      const found = computeReturnTaintPropagatingPHP(fn, roundCtx);
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

function seedLocalFunctionParams(calleeName: string, args: SyntaxNode[], env: Env, ctx: EngineCtx) {
  const callee = ctx.localFunctions.get(calleeName);
  if (!callee) return;
  const taintMask = makeTaintMaskPHP(ctx);
  const taintedIdx = new Map<number, number>();
  args.forEach((arg, i) => {
    const m = taintMask(arg, env) & ALL;
    if (!m) return;
    if (callee.paramShapes.some(s => s.index === i)) taintedIdx.set(i, (taintedIdx.get(i) ?? 0) | m);
  });
  if (taintedIdx.size === 0) return;
  const existing = ctx.seededParams.get(calleeName) ?? new Map<number, number>();
  for (const [i, m] of taintedIdx) existing.set(i, (existing.get(i) ?? 0) | m);
  ctx.seededParams.set(calleeName, existing);
}

// ── Function/method collection ───────────────────────────────────────────

// Broadened from an exact 5-name set to also catch any snake_case "_id" or
// camelCase "Id" suffix (accountId, order_id, ...) -- the exact set missed
// real, common resource-id param names entirely. No `/i` flag: a
// case-insensitive `.*id` would also match ordinary words ending in those
// two letters (valid, avoid, grid); requiring either the underscore or the
// capital "I" keeps those safely excluded.
const RESOURCE_ID_PARAM_RE = /^(?:id|ID|.*_id|.*Id)$/;
const READ_NAME_RE = /^(?:get|show|index|view|find|list|search)/i;
const AUTH_SUPPRESS_CALL_RE = /^(?:Auth\.check|Auth\.user|auth\.check|auth\.user)$/;

interface FuncAuthMeta {
  hasResourceIdParam: boolean;
  verbTier: "read" | "write";
  suppressedByAuthCheck: boolean;
}

function paramShapesOf(paramList: SyntaxNode | undefined): ParamShape[] {
  const shapes: ParamShape[] = [];
  if (!paramList) return shapes;
  let index = 0;
  for (const param of paramList.namedChildren) {
    if (!param || (param.type !== "simple_parameter" && param.type !== "variadic_parameter")) { continue; }
    const nameField = param.childForFieldName("name");
    const varName = nameField?.type === "variable_name" ? variableBareName(nameField) : null;
    if (varName) shapes.push({ name: varName, index });
    index++;
  }
  return shapes;
}

function extractFuncInfo(decl: SyntaxNode): LocalFunction | null {
  const nameNode = decl.childForFieldName("name");
  if (!nameNode) return null;
  const paramList = decl.childForFieldName("parameters") ?? undefined;
  const paramShapes = paramShapesOf(paramList);
  const resourceIdParamNames = new Set(paramShapes.filter(s => RESOURCE_ID_PARAM_RE.test(s.name)).map(s => s.name));
  const verbTier: "read" | "write" = READ_NAME_RE.test(nameNode.text) ? "read" : "write";
  const body = decl.childForFieldName("body") ?? null;
  const suppressedByAuthCheck = body
    ? findAllNodes(body, "member_call_expression").some(mc => {
      const text = calleeTextPHP(mc);
      return !!text && AUTH_SUPPRESS_CALL_RE.test(text);
    }) || findAllNodes(body, "scoped_call_expression").some(sc => {
      const text = calleeTextPHP(sc);
      return !!text && AUTH_SUPPRESS_CALL_RE.test(text);
    })
    : false;
  return {
    name: nameNode.text, paramShapes, resourceIdParamNames, body,
    authMeta: { hasResourceIdParam: resourceIdParamNames.size > 0, verbTier, suppressedByAuthCheck },
  };
}

function collectLocalFunctions(root: SyntaxNode): Map<string, LocalFunction> {
  const functions = new Map<string, LocalFunction>();
  for (const decl of [...findAllNodes(root, "function_definition"), ...findAllNodes(root, "method_declaration")]) {
    const info = extractFuncInfo(decl);
    if (!info) continue;
    // Same bug class as astTaintCSharp.ts's collectLocalMethods (already
    // fixed there): two different classes/functions in the same file can
    // share a bare name, and a flat overwrite would silently lose whichever
    // one was declared first to whichever is declared last, regardless of
    // which one actually matters. PHP has no C#-style isEndpoint signal to
    // arbitrate by, so the simplest safe policy is first-declared-wins.
    if (functions.has(info.name)) continue;
    functions.set(info.name, info);
  }
  return functions;
}

/** Every variable name that appears in a `global $x;` declaration anywhere in the file. */
function collectGlobalNamesPHP(root: SyntaxNode): Set<string> {
  return new Set(findAllNodes(root, "global_declaration").flatMap(g => variableNamesIn(g)));
}

/** Record taint written into a `global`-shared variable (visible to every function). Main scan only. */
function recordGlobalStickyPHP(name: string | null, mask: number, ctx: EngineCtx): void {
  if (!name || !ctx.recordSticky || !(mask & ALL) || !ctx.globalNames.has(name)) return;
  const next = (ctx.sticky.get(name) ?? 0) | (mask & ALL);
  if (next !== (ctx.sticky.get(name) ?? 0)) { ctx.sticky.set(name, next); ctx.stickyDirty = true; }
}

// ── Sink checks ──────────────────────────────────────────────────────────

const SQL_CALL_TAILS = new Set(["query", "exec", "prepare"]);
const SQL_FUNCTIONS = new Set(["mysqli_query", "mysql_query", "pg_query"]);
const CMD_FUNCTIONS = new Set(["shell_exec", "system", "passthru", "popen", "proc_open", "exec"]);
// MongoDB-driver-shaped array-query calls. Deliberately overlaps with
// BOLA_LOOKUP_TAILS's own "find"/"get" entries below -- the two checks run
// independently per call site, so a single call can legitimately produce
// both a bola-missing-ownership-check AND a nosql-injection finding; not a
// conflict.
const NOSQL_CALL_TAILS = new Set(["find", "findOne", "findMany", "updateOne", "deleteOne", "remove"]);

function checkFunctionCallSink(node: SyntaxNode, ctx: EngineCtx, taintMask: TaintMaskFnPHP, env: Env) {
  const fnNode = node.childForFieldName("function");
  const fnName = fnNode?.type === "name" ? fnNode.text : null;
  if (!fnName) return;
  const args = argListOfPHP(node);
  const argMasks = args.map(a => taintMask(a, env));
  const combined = argMasks.reduce((m, x) => m | x, 0);
  // Any bit (taint OR shadow): a value that was tainted and then sanitized
  // must still reach fire() so the suppression gets recorded.
  const firstIdx = argMasks.findIndex(m => m !== 0);
  if (firstIdx < 0) return;
  const sourceExpr = args[firstIdx].text;
  // Each sink is gated on ITS OWN class (htmlspecialchars no longer hides a
  // SQL/command/path sink); tainted-then-positively-cleared records a
  // suppression instead (regex-layer veto).
  const fire = (id: AstTaintPHPId, mask: number = combined, source: string = sourceExpr) => {
    const cls = classOf(id);
    if (mask & cls) emit(ctx, id, node, source, fnName);
    else if (wasCleared(mask, cls)) ctx.suppressed?.push({ id, line: lineOf(node) });
  };

  if (SQL_FUNCTIONS.has(fnName)) {
    fire("sql-injection");
  } else if (CMD_FUNCTIONS.has(fnName)) {
    fire("command-injection");
  } else if (fnName === "unserialize") {
    fire("insecure-deserialization");
  } else if (fnName === "include" || fnName === "require" || fnName === "include_once" || fnName === "require_once") {
    // Dead in practice -- confirmed directly that plain `include $x;` is a
    // distinct language-construct node (include_expression), never a
    // function_call_expression -- kept as a harmless defensive fallback
    // only, matching checkIncludeExpressionSink below for the real path.
    fire("file-inclusion");
  } else if (fnName === "fopen" || fnName === "file_get_contents" || fnName === "readfile") {
    fire("path-traversal");
  } else if (fnName === "header") {
    // header("Location: " . $tainted) is open-redirect; header("X-Anything:
    // " . $tainted) for any other header name is header-injection -- same
    // call, discriminated purely by the literal string prefix (read
    // directly off the tainted arg's raw .text, since that's the whole
    // concatenation expression here, e.g. `"Location: " . $next`).
    fire(/^["']?\s*Location\s*:/i.test(sourceExpr) ? "open-redirect" : "header-injection");
  } else if (fnName === "ldap_search") {
    // ldap_search($link, $base_dn, $filter) -- confirmed 3-arg positional
    // signature; the filter is args[2], not just "any tainted arg" (the
    // $link/$base_dn args could themselves be tainted in a contrived case
    // without that being the real vulnerability).
    if (args.length >= 3) fire("ldap-injection", argMasks[2], args[2].text);
  } else if (fnName === "eval") {
    fire("eval-exec");
  } else if (fnName === "curl_init") {
    if (args[0]) fire("ssrf", argMasks[0], args[0].text);
  } else if ((fnName === "preg_match" || fnName === "preg_match_all" || fnName === "preg_replace" || fnName === "preg_replace_callback" || fnName === "preg_split")
             && args[0] && (argMasks[0] & ALL)) {
    // The PATTERN itself (not the subject/data being matched) is attacker-controlled.
    fire("redos", argMasks[0], args[0].text);
  } else if (fnName === "curl_setopt") {
    // curl_setopt($ch, CURLOPT_URL, $tainted) -- always a bare function
    // call in PHP, never a method call (confirmed: no OOP cURL wrapper in
    // the standard library). args[0] is the handle, args[1] the CURLOPT_*
    // constant, args[2] the value -- a tainted match anywhere in args is
    // close enough given this engine's established "accept some
    // imprecision" posture.
    fire("ssrf");
  }
}

// `include`/`require` are actual language constructs in PHP's grammar
// (`include_expression`/`require_expression`), not function calls -- a
// real, confirmed structural difference from every other sink in this
// table, handled separately.
function checkIncludeExpressionSink(node: SyntaxNode, ctx: EngineCtx, taintMask: TaintMaskFnPHP, env: Env) {
  const target = node.namedChildren[0];
  if (!target) return;
  const m = taintMask(target, env);
  const cls = classOf("file-inclusion");
  if (m & cls) emit(ctx, "file-inclusion", node, target.text, node.type);
  else if (wasCleared(m, cls)) ctx.suppressed?.push({ id: "file-inclusion", line: lineOf(node) });
}

function checkMemberCallSink(node: SyntaxNode, ctx: EngineCtx, taintMask: TaintMaskFnPHP, env: Env) {
  const methodName = node.childForFieldName("name")?.text;
  if (!methodName) return;
  const args = argListOfPHP(node);
  const argMasks = args.map(a => taintMask(a, env));
  const combined = argMasks.reduce((m, x) => m | x, 0);
  const firstIdx = argMasks.findIndex(m => m !== 0);
  if (firstIdx < 0) return;
  const sourceExpr = args[firstIdx].text;
  const fire = (id: AstTaintPHPId, sink: string = methodName) => {
    const cls = classOf(id);
    if (combined & cls) emit(ctx, id, node, sourceExpr, sink);
    else if (wasCleared(combined, cls)) ctx.suppressed?.push({ id, line: lineOf(node) });
  };
  if (SQL_CALL_TAILS.has(methodName)) {
    // Receiver-type-aware discrimination (mirrors astTaintCSharp.ts's
    // ctx.varTypes-based checkCallSink) -- ->query()/->exec()/->prepare()
    // is only really SQL injection when the receiver isn't something else
    // entirely that happens to share the method name, e.g. DOMXPath::query().
    const receiver = node.namedChildren[0];
    const receiverName = receiver?.type === "variable_name" ? variableBareName(receiver) : null;
    if (methodName === "query" && receiverName && ctx.varTypes.get(receiverName) === "DOMXPath") {
      fire("xpath-injection");
    } else {
      fire("sql-injection");
    }
  } else if (NOSQL_CALL_TAILS.has(methodName)) {
    fire("nosql-injection");
  } else if (methodName === "createTemplate" || methodName === "renderString" || methodName === "fetchFromString") {
    fire("ssti");
  } else if (methodName === "setopt") {
    // curl_setopt($ch, CURLOPT_URL, $tainted) -- args[0] is the handle,
    // args[1] the CURLOPT_* constant, args[2] the value; a tainted MATCH
    // anywhere in args is close enough given this engine's "accept some
    // imprecision" posture (matches every other engine's loose arg-tainted
    // checks elsewhere).
    fire("ssrf", "curl_setopt");
  }
}

/** The body of the function/method lexically enclosing \`node\`, or null (top-level code). */
function enclosingFunctionBodyPHP(node: SyntaxNode): SyntaxNode | null {
  for (let cur: SyntaxNode | null = node.parent; cur; cur = cur.parent) {
    if (cur.type === "function_definition" || cur.type === "method_declaration") return cur.childForFieldName("body") ?? null;
  }
  return null;
}

/** Was \`varName\` EVER assigned directly from a superglobal (\`$fn = $_POST['x'];\`) somewhere in \`body\`,
 * and NEVER assigned a closure/callable elsewhere? Deliberately narrow (favors precision): a callback
 * parameter that is simply CALLED, never itself assigned, doesn't match this at all (no false positive on
 * \`$cb($v)\` inside a normal higher-order helper) -- only a variable that's DEMONSTRABLY been overwritten
 * with raw request data, the real "attacker chooses which function runs" shape. */
function isEverAssignedFromSourcePHP(body: SyntaxNode | null, varName: string): boolean {
  if (!body) return false;
  let fromSource = false;
  let everCallable = false;
  for (const assign of findAllNodes(body, "assignment_expression")) {
    const left = assign.childForFieldName("left");
    if (left?.type !== "variable_name" || variableBareName(left) !== varName) continue;
    const right = assign.childForFieldName("right");
    if (!right) continue;
    if (right.type === "anonymous_function_creation_expression" || right.type === "arrow_function") { everCallable = true; continue; }
    if (isTaintSourceExprPHP(right)) { fromSource = true; continue; }
    if (right.type === "variable_name") {
      const nm = variableBareName(right);
      if (nm && SUPERGLOBAL_NAMES.has(nm)) fromSource = true;
    }
  }
  return fromSource && !everCallable;
}

/** \`$fn(...)\` where \`$fn\` itself holds an attacker-chosen function NAME (not a stored closure/callback --
 * see isEverAssignedFromSourcePHP's own docblock for why those are excluded). */
function checkDynamicCallSink(node: SyntaxNode, fnNode: SyntaxNode, ctx: EngineCtx, taintMask: TaintMaskFnPHP, env: Env) {
  const varName = variableBareName(fnNode);
  if (!varName) return;
  const m = taintMask(fnNode, env);
  if (!(m & ALL)) return;
  if (!isEverAssignedFromSourcePHP(enclosingFunctionBodyPHP(node), varName)) return;
  emit(ctx, "eval-exec", node, fnNode.text, "dynamic function call");
}

// ── Narrow validation guards ────────────────────────────────────────────────
// Same policy as every other engine: only unambiguous proofs that a bare
// variable is safe -- literal equality, membership in a literal array
// (`in_array`, `isset($allowed[$x])`), strict numeric checks (`is_numeric`,
// `ctype_digit`, `is_int`). NOT recognized: regex matches (`preg_match`),
// prefix checks, custom validators. PHP's LOOSE comparison (`==`, non-strict
// `in_array`, `switch`) treats a non-numeric string as equal to 0 on PHP < 8,
// so only STRING literals count for loose comparisons; strict comparisons
// (`===`, `!==`, `in_array(..., true)`, `match`) accept any literal.

const NUMERIC_CHECK_FUNCTIONS_PHP = new Set(["is_numeric", "ctype_digit", "is_int", "is_integer", "is_long", "is_float", "is_double", "is_bool"]);
const TERMINATING_CALLS_PHP = new Set(["die", "exit", "abort", "wp_die"]);

function isStringLiteralPHP(n: SyntaxNode): boolean {
  if (n.type === "string") return true;
  // a double-quoted string with no interpolation
  return n.type === "encapsed_string" && n.namedChildren.every(c => !!c && (c.type === "string_content" || c.type === "escape_sequence"));
}

function isLiteralPHP(n: SyntaxNode): boolean {
  if (n.type === "parenthesized_expression") return !!n.namedChildren[0] && isLiteralPHP(n.namedChildren[0]);
  return isStringLiteralPHP(n) || n.type === "integer" || n.type === "float" || n.type === "boolean";
}

/** Every element a literal (string-only when `stringsOnly`, for LOOSE membership); `keys` checks array keys instead of values. */
function literalArrayPHP(n: SyntaxNode, opts: { keys?: boolean; stringsOnly?: boolean }): boolean {
  if (n.type !== "array_creation_expression") return false;
  const inits = n.namedChildren.filter((c): c is SyntaxNode => !!c && c.type === "array_element_initializer");
  if (inits.length === 0 || inits.length !== n.namedChildren.length) return false;
  const okLit = (x: SyntaxNode | null | undefined) => !!x && (opts.stringsOnly ? isStringLiteralPHP(x) : isLiteralPHP(x));
  return inits.every(i => {
    const parts = i.namedChildren.filter((c): c is SyntaxNode => !!c);
    if (opts.keys) return parts.length === 2 && okLit(parts[0]);
    return parts.length === 1 && okLit(parts[0]);
  });
}

/** A literal array node, or a `$var` / CONSTANT EVERY binding of which, file-wide, is one. */
function isLiteralArrayRefPHP(
  n: SyntaxNode, root: SyntaxNode | undefined, opts: { keys?: boolean; stringsOnly?: boolean },
): boolean {
  if (n.type === "array_creation_expression") return literalArrayPHP(n, opts);
  if (!root) return false;
  const isVar = n.type === "variable_name";
  const wanted = isVar ? variableBareName(n) : n.type === "name" ? n.text : null;
  if (!wanted) return false;
  const bindings: SyntaxNode[] = [];
  let opaque = false;
  const visit = (x: SyntaxNode) => {
    if (isVar && x.type === "assignment_expression") {
      const left = x.childForFieldName("left");
      const right = x.childForFieldName("right");
      if (left?.type === "variable_name" && variableBareName(left) === wanted) { if (right) bindings.push(right); else opaque = true; }
      // `$allowed[] = $x` / `$allowed[k] = ...` mutates the array
      if (left?.type === "subscript_expression") {
        const base = left.namedChildren[0];
        if (base?.type === "variable_name" && variableBareName(base) === wanted) opaque = true;
      }
    } else if (isVar && x.type === "augmented_assignment_expression") {
      const left = x.childForFieldName("left");
      if (left?.type === "variable_name" && variableBareName(left) === wanted) opaque = true;
    } else if (!isVar && x.type === "const_element") {
      const nm = x.namedChildren[0];
      const val = x.namedChildren[1];
      if (nm?.text === wanted) { if (val) bindings.push(val); else opaque = true; }
    }
    for (const c of x.namedChildren) if (c) visit(c);
  };
  visit(root);
  return !opaque && bindings.length > 0 && bindings.every(b => b.type === "array_creation_expression" && literalArrayPHP(b, opts));
}

function invertPHP(g: Guard): Guard {
  return { name: g.name, holds: g.holds === "true" ? "false" : "true" };
}

function guardsOfConditionPHP(cond: SyntaxNode, root: SyntaxNode | undefined): Guard[] {
  switch (cond.type) {
    case "parenthesized_expression": {
      const inner = cond.namedChildren[0];
      return inner ? guardsOfConditionPHP(inner, root) : [];
    }
    case "unary_op_expression": {
      if (cond.child(0)?.type !== "!") return [];
      const inner = cond.childForFieldName("argument") ?? cond.namedChildren[0];
      return inner ? guardsOfConditionPHP(inner, root).map(invertPHP) : [];
    }
    case "binary_expression": {
      const op = cond.childForFieldName("operator")?.type;
      const l = cond.childForFieldName("left");
      const r = cond.childForFieldName("right");
      if (!l || !r) return [];
      if (op === "&&" || op === "and") return [...guardsOfConditionPHP(l, root), ...guardsOfConditionPHP(r, root)].filter(g => g.holds === "true");
      if (op === "||" || op === "or") return [...guardsOfConditionPHP(l, root), ...guardsOfConditionPHP(r, root)].filter(g => g.holds === "false");
      const strict = op === "===" || op === "!==";
      const loose = op === "==" || op === "!=";
      if (strict || loose) {
        const holdsWhenEqual: "true" | "false" = op === "===" || op === "==" ? "true" : "false";
        const litOk = (n: SyntaxNode) => (strict ? isLiteralPHP(n) : isStringLiteralPHP(n));
        const lName = l.type === "variable_name" ? variableBareName(l) : null;
        const rName = r.type === "variable_name" ? variableBareName(r) : null;
        if (lName && litOk(r)) return [{ name: lName, holds: holdsWhenEqual }];
        if (rName && litOk(l)) return [{ name: rName, holds: holdsWhenEqual }];
      }
      return [];
    }
    case "function_call_expression": {
      const fnNode = cond.childForFieldName("function");
      const fnName = fnNode?.type === "name" ? fnNode.text.toLowerCase() : null;
      const args = argListOfPHP(cond);
      if (!fnName || args.length === 0) return [];
      const a0 = args[0].type === "variable_name" ? variableBareName(args[0]) : null;
      if (NUMERIC_CHECK_FUNCTIONS_PHP.has(fnName) && a0) return [{ name: a0, holds: "true" }];
      // in_array($x, ["a","b"], true) -- loose (no/false 3rd arg) needs string-only elements
      if (fnName === "in_array" && a0 && args.length >= 2) {
        const strict = args[2]?.type === "boolean" && args[2].text.toLowerCase() === "true";
        if (isLiteralArrayRefPHP(args[1], root, { stringsOnly: !strict })) return [{ name: a0, holds: "true" }];
      }
      // array_key_exists($x, $allowedMap) / isset($allowedMap[$x])
      if (fnName === "array_key_exists" && a0 && args.length === 2 && isLiteralArrayRefPHP(args[1], root, { keys: true, stringsOnly: true })) {
        return [{ name: a0, holds: "true" }];
      }
      if (fnName === "isset" && args.length === 1 && args[0].type === "subscript_expression") {
        const [base, idx] = args[0].namedChildren;
        if (base && idx?.type === "variable_name" && isLiteralArrayRefPHP(base, root, { keys: true, stringsOnly: true })) {
          const idxName = variableBareName(idx);
          if (idxName) return [{ name: idxName, holds: "true" }];
        }
      }
      return [];
    }
    default:
      return [];
  }
}

// ── Path-sensitive statement walk ───────────────────────────────────────────
// One walker serves the interprocedural summary builder (no closures,
// collects return masks) and the main scan (sink checks, closures walked in
// their own scope). Branches walk each arm on a CLONE of the env and join with
// may-taint OR (shared combinators in taint/taintCore.ts); an arm ending in
// return/throw/exit is dropped from the join, and code after a terminating
// statement is dead and not walked.

interface WalkOptsPHP {
  /** Walk closure / arrow-function bodies (main scan) or ignore them (summaries). */
  descendFunctions: boolean;
  /** Called for each `return expr`, with the env on that path. */
  onReturn?: (expr: SyntaxNode, env: Env, taintMask: TaintMaskFnPHP) => void;
}

function statementTerminatesPHP(n: SyntaxNode | null | undefined): boolean {
  if (!n) return false;
  if (n.type === "return_statement" || n.type === "exit_statement") return true;
  if (n.type === "expression_statement") {
    const e = n.namedChildren[0];
    if (e?.type === "throw_expression") return true;
    if (e?.type === "function_call_expression") {
      const fnNode = e.childForFieldName("function");
      return fnNode?.type === "name" && TERMINATING_CALLS_PHP.has(fnNode.text.toLowerCase());
    }
    return false;
  }
  if (n.type === "compound_statement" || n.type === "colon_block") return n.namedChildren.some(c => statementTerminatesPHP(c));
  if (n.type === "if_statement") {
    const body = n.childForFieldName("body");
    const alts = n.childrenForFieldName("alternative").filter((c): c is SyntaxNode => !!c);
    const hasElse = alts.some(a => a.type === "else_clause");
    return hasElse && statementTerminatesPHP(body) && alts.every(a => statementTerminatesPHP(a.childForFieldName("body")));
  }
  return false;
}

function variableNamesIn(n: SyntaxNode | null | undefined): string[] {
  if (!n) return [];
  return findAllNodes(n, "variable_name").map(v => variableBareName(v)).filter((v): v is string => !!v);
}

function paramNamesOfPHP(fn: SyntaxNode): string[] {
  const params = fn.childForFieldName("parameters");
  if (!params) return [];
  const names: string[] = [];
  for (const p of params.namedChildren) {
    const nm = p?.childForFieldName("name");
    if (nm?.type === "variable_name") { const b = variableBareName(nm); if (b) names.push(b); }
  }
  return names;
}

const NAMED_FUNCTION_NODES_PHP = new Set(["function_definition", "method_declaration"]);

function createWalkerPHP(ctx: EngineCtx, opts: WalkOptsPHP) {
  const taintMask = makeTaintMaskPHP(ctx);
  const root = ctx.root;

  const walkStmts = (nodes: readonly (SyntaxNode | null)[], env: Env): boolean => {
    for (const c of nodes) if (c && walk(c, env)) return true; // dead code after a terminator is not walked
    return false;
  };

  const walkClosure = (fn: SyntaxNode, env: Env) => {
    const body = fn.childForFieldName("body");
    if (!body) return;
    let fenv: Env;
    if (fn.type === "arrow_function") {
      fenv = cloneEnv(env); // `fn` captures the enclosing scope by value
    } else {
      // A `function () use ($x)` closure sees ONLY its `use` variables.
      fenv = new Map();
      const use = fn.namedChildren.find(c => c?.type === "anonymous_function_use_clause");
      for (const name of variableNamesIn(use)) if (env.has(name)) fenv.set(name, env.get(name)!);
    }
    for (const p of paramNamesOfPHP(fn)) fenv.set(p, 0);
    walk(body, fenv);
  };

  /** Bind every variable in an assignment/foreach target from `mask`. */
  const bindTargets = (target: SyntaxNode, mask: number, env: Env) => {
    for (const name of variableNamesIn(target)) env.set(name, mask);
  };

  const walk = (node: SyntaxNode, env: Env): boolean => {
    switch (node.type) {
      // Named functions/methods are walked separately, each in a fresh scope.
      case "function_definition":
      case "method_declaration":
      case "class_declaration":
        return false;

      case "anonymous_function_creation_expression":
      case "arrow_function":
        if (opts.descendFunctions) walkClosure(node, env);
        return false;

      case "program":
      case "compound_statement":
      case "colon_block":
        return walkStmts(node.namedChildren, env);

      case "if_statement": {
        const branches: Branch[] = [];
        const cond = node.childForFieldName("condition");
        const body = node.childForFieldName("body");
        branches.push({
          visitCond: (e) => { if (cond) walk(cond, e); },
          guards: () => (cond ? guardsOfConditionPHP(cond, root) : []),
          body: (e) => (body ? walk(body, e) : false),
        });
        for (const alt of node.childrenForFieldName("alternative")) {
          if (!alt) continue;
          const abody = alt.childForFieldName("body");
          if (alt.type === "else_if_clause") {
            const acond = alt.childForFieldName("condition");
            branches.push({
              visitCond: (e) => { if (acond) walk(acond, e); },
              guards: () => (acond ? guardsOfConditionPHP(acond, root) : []),
              body: (e) => (abody ? walk(abody, e) : false),
            });
          } else if (alt.type === "else_clause") {
            branches.push({ body: (e) => (abody ? walk(abody, e) : false) });
          }
        }
        return walkIfChain(env, branches);
      }

      case "conditional_expression": {
        // `c ? a : b` -- arms are walked on cloned envs with the condition's guards
        const cond = node.childForFieldName("condition");
        const cons = node.childForFieldName("body");
        const alt = node.childForFieldName("alternative");
        walkIfChain(env, [
          {
            visitCond: (e) => { if (cond) walk(cond, e); },
            guards: () => (cond ? guardsOfConditionPHP(cond, root) : []),
            body: (e) => { if (cons) walk(cons, e); return false; },
          },
          { body: (e) => { if (alt) walk(alt, e); return false; } },
        ]);
        return false;
      }

      case "foreach_statement": {
        const named = node.namedChildren.filter((c): c is SyntaxNode => !!c);
        const subject = named[0];
        const body = node.childForFieldName("body");
        const target = named.find((c, i) => i > 0 && c.id !== body?.id) ?? null;
        if (subject) walk(subject, env);
        const rmask = subject ? taintMask(subject, env) : 0;
        if (target) bindTargets(target, rmask, env);
        // `foreach ($s as $k => $v) { $t[$k] = $v; }` -- every entry of a tainted array is copied
        // into another one wholesale (an attacker can set keys the API never meant to expose).
        if ((rmask & ALL) && body) {
          const isPair = target?.type === "pair";
          const keyName = isPair && target!.namedChildren[0]?.type === "variable_name" ? variableBareName(target!.namedChildren[0]) : null;
          const valName = isPair
            ? (target!.namedChildren[1]?.type === "variable_name" ? variableBareName(target!.namedChildren[1]) : null)
            : (target?.type === "variable_name" ? variableBareName(target) : null);
          if (keyName && valName) {
            for (const asg of findAllNodes(body, "assignment_expression")) {
              const l = asg.childForFieldName("left");
              const r = asg.childForFieldName("right");
              if (l?.type !== "subscript_expression" || r?.type !== "variable_name" || variableBareName(r) !== valName) continue;
              const idx = l.namedChildren[1];
              if (idx?.type === "variable_name" && variableBareName(idx) === keyName && l.namedChildren[0]?.type === "variable_name") {
                emit(ctx, "mass-assignment", asg, subject?.text ?? "", "array merge");
              }
            }
          }
        }
        return walkLoop(env, (e) => (body ? walk(body, e) : false));
      }

      case "for_statement": {
        for (const f of ["initialize", "condition"]) for (const c of node.childrenForFieldName(f)) if (c) walk(c, env);
        const body = node.childForFieldName("body");
        const updates = node.childrenForFieldName("update");
        return walkLoop(env, (e) => {
          const t = body ? walk(body, e) : false;
          if (!t) for (const u of updates) if (u) walk(u, e);
          return t;
        });
      }

      case "while_statement": {
        const cond = node.childForFieldName("condition");
        if (cond) walk(cond, env);
        const body = node.childForFieldName("body");
        return walkLoop(env, (e) => (body ? walk(body, e) : false));
      }

      case "do_statement": {
        const body = node.childForFieldName("body");
        const cond = node.childForFieldName("condition");
        const term = walkLoop(env, (e) => (body ? walk(body, e) : false));
        if (cond) walk(cond, env);
        return term;
      }

      case "try_statement": {
        const body = node.childForFieldName("body");
        const finallyC = node.namedChildren.find(c => c?.type === "finally_clause");
        const catches = node.namedChildren
          .filter(c => c?.type === "catch_clause")
          .map(c => {
            const nm = c!.childForFieldName("name");
            const bind = nm ? variableNamesIn(nm) : [];
            const cbody = c!.childForFieldName("body");
            return { bind, body: (e: Env) => (cbody ? walk(cbody, e) : false) };
          });
        return walkTry(
          env,
          (e) => (body ? walk(body, e) : false),
          catches,
          finallyC ? (e) => { const fb = finallyC.childForFieldName("body"); return fb ? walk(fb, e) : false; } : undefined,
        );
      }

      case "switch_statement": {
        const cond = node.childForFieldName("condition");
        if (cond) walk(cond, env);
        const inner = cond?.type === "parenthesized_expression" ? cond.namedChildren[0] : cond;
        const subject = inner?.type === "variable_name" ? variableBareName(inner) : null;
        const clauses = (node.childForFieldName("body") ?? node).namedChildren
          .filter(c => c?.type === "case_statement" || c?.type === "default_statement");
        return walkSwitch(env, clauses.map(cl => {
          const value = cl!.childForFieldName("value");
          const stmts = cl!.namedChildren.filter(c => !!c && c.id !== value?.id);
          return {
            isDefault: cl!.type === "default_statement",
            // `case "a":` (loose comparison: string literals only) -- inside, the subject IS that literal.
            pre: (e: Env) => { if (subject && value && isStringLiteralPHP(value)) applyGuards(e, [subject]); },
            body: (e: Env) => walkStmts(stmts, e),
          };
        }));
      }

      case "match_expression": {
        const cond = node.childForFieldName("condition");
        if (cond) walk(cond, env);
        const inner = cond?.type === "parenthesized_expression" ? cond.namedChildren[0] : cond;
        const subject = inner?.type === "variable_name" ? variableBareName(inner) : null;
        const arms = (node.childForFieldName("body") ?? node).namedChildren
          .filter(c => c?.type === "match_conditional_expression" || c?.type === "match_default_expression");
        walkSwitch(env, arms.map(arm => {
          const conds = (arm!.childForFieldName("conditional_expressions")?.namedChildren ?? []).filter((c): c is SyntaxNode => !!c);
          const result = arm!.childForFieldName("return_expression");
          return {
            isDefault: arm!.type === "match_default_expression",
            // `match` uses strict identity: inside an arm of literals the subject IS one of them.
            pre: (e: Env) => { if (subject && conds.length > 0 && conds.every(isLiteralPHP)) applyGuards(e, [subject]); },
            body: (e: Env) => { if (result) walk(result, e); return false; },
          };
        }));
        return false;
      }

      case "return_statement": {
        for (const c of node.namedChildren) if (c) walk(c, env);
        const v = node.namedChildren[0];
        if (v) opts.onReturn?.(v, env, taintMask);
        return true;
      }

      case "exit_statement":
        for (const c of node.namedChildren) if (c) walk(c, env);
        return true;

      case "yield_expression": {
        for (const c of node.namedChildren) if (c) walk(c, env);
        opts.onReturn?.(node, env, taintMask);
        return false;
      }

      case "expression_statement": {
        for (const c of node.namedChildren) if (c) walk(c, env);
        return statementTerminatesPHP(node);
      }

      default:
        break;
    }

    if (node.type === "assignment_expression") {
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      const mask = right ? taintMask(right, env) : 0;
      if (left?.type === "variable_name") {
        const varName = variableBareName(left);
        if (varName) {
          env.set(varName, mask);
          recordGlobalStickyPHP(varName, mask, ctx);
          // $var = new ClassName(...) -- class-name tracking (see
          // EngineCtx.varTypes's own docblock). className extraction reuses
          // the exact same technique collectBolaFindings' own
          // object_creation_expression loop already uses below.
          if (right?.type === "object_creation_expression") {
            const classNameNode = right.namedChildren.find(c => c && c.type === "name");
            if (classNameNode) ctx.varTypes.set(varName, classNameNode.text);
          }
        }
      } else if (left?.type === "member_access_expression") {
        const key = calleeTextPHP(left);
        if (key) env.set(key, mask);
        // \`$obj->$name = $value;\` -- the property NAME itself (not just the value) is attacker-controlled,
        // letting a request pick which field to overwrite (role, isAdmin, ...).
        const nameField = left.childForFieldName("name");
        if (nameField && nameField.type !== "name") {
          const nm = taintMask(nameField, env);
          if (nm & ALL) emit(ctx, "mass-assignment", node, nameField.text, "dynamic property assignment");
          else if (wasCleared(nm, ALL)) ctx.suppressed?.push({ id: "mass-assignment", line: lineOf(node) });
        }
      } else if (left?.type === "list_literal" || left?.type === "array_creation_expression") {
        // [$a, $b] = f() / list($a, $b) = f() -- every target receives the value's taint
        bindTargets(left, mask, env);
      } else if (left?.type === "subscript_expression") {
        // $arr['k'] = tainted -- the read side (`$arr['k']`) resolves to the base variable, so OR into it
        const base = left.namedChildren[0];
        const baseName = base?.type === "variable_name" ? variableBareName(base) : null;
        if (baseName) {
          const next = (env.get(baseName) ?? 0) | mask;
          env.set(baseName, next);
          recordGlobalStickyPHP(baseName, next, ctx);
        }
      }
    }

    // `$x .= y` / `$x += y` / `$x ??= y` keep whatever taint $x already had (OR), unlike plain `=`.
    if (node.type === "augmented_assignment_expression") {
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      const mask = right ? taintMask(right, env) : 0;
      if (left?.type === "variable_name") {
        const varName = variableBareName(left);
        if (varName) env.set(varName, mask | (env.get(varName) ?? 0));
      } else if (left?.type === "member_access_expression") {
        const key = calleeTextPHP(left);
        if (key) env.set(key, mask | (env.get(key) ?? 0));
      } else if (left?.type === "subscript_expression") {
        const base = left.namedChildren[0];
        const baseName = base?.type === "variable_name" ? variableBareName(base) : null;
        if (baseName) env.set(baseName, (env.get(baseName) ?? 0) | mask);
      }
    }

    if (node.type === "global_declaration") {
      // `global $c;` -- pulls in whatever another function has already written to the shared variable.
      for (const name of variableNamesIn(node)) env.set(name, (env.get(name) ?? 0) | (ctx.sticky.get(name) ?? 0));
    }

    if (node.type === "binary_expression") {
      const op = node.childForFieldName("operator")?.type;
      if (op === "." && node.parent?.type !== "binary_expression") {
        // A `.`-concatenation chain being built: an HTML-encoded value placed inside a <script> block
        // is still XSS (HTML encoding doesn't neutralize JavaScript string context).
        const operands = phpConcatOperands(node);
        if (operands) {
          let prefix = "";
          for (const o of operands) {
            const lit = phpStringValue(o);
            if (lit !== null) { prefix += lit; continue; }
            const m = taintMask(o, env);
            if (wasCleared(m, classOf("xss")) && PHP_SCRIPT_CONTEXT_RE.test(prefix)) {
              emit(ctx, "xss", node, o.text, "HTML string");
            }
            prefix += "";
          }
        }
      }
      if (op === "==" || op === "===" || op === "!=" || op === "!==") {
        const l = node.childForFieldName("left");
        const r = node.childForFieldName("right");
        const nameOf = (n: SyntaxNode | null) => (n?.type === "name" ? n.text : n?.type === "variable_name" ? variableBareName(n) : undefined);
        for (const [secret, other] of [[l, r], [r, l]] as const) {
          const nm = nameOf(secret);
          if (secret && other && nm && PHP_SECRET_NAME_RE.test(nm) && !isLiteralPHP(other)
              && (taintMask(other, env) & ALL) && !(taintMask(secret, env) & ALL)) {
            emit(ctx, "timing-attack", node, other.text, nm);
            break;
          }
        }
      }
    }

    if (node.type === "echo_statement" || node.type === "print_statement") {
      const cls = classOf("xss");
      let cleared = false;
      for (const child of node.namedChildren) {
        if (!child) continue;
        const m = taintMask(child, env);
        if (m & cls) {
          emit(ctx, "xss", node, child.text, node.type === "echo_statement" ? "echo" : "print");
          cleared = false;
          break;
        }
        if (wasCleared(m, cls)) cleared = true;
      }
      if (cleared) ctx.suppressed?.push({ id: "xss", line: lineOf(node) });
    }

    if (node.type === "function_call_expression") {
      checkFunctionCallSink(node, ctx, taintMask, env);
      const fnNode = node.childForFieldName("function");
      if (fnNode?.type === "name") {
        if (ctx.localFunctions.has(fnNode.text)) seedLocalFunctionParams(fnNode.text, argListOfPHP(node), env, ctx);
        if (fnNode.text === "extract") {
          const args = argListOfPHP(node);
          if (args[0] && (taintMask(args[0], env) & ALL)) env.set(PHP_WILDCARD_VAR, ALL);
        }
      } else if (fnNode?.type === "variable_name") {
        checkDynamicCallSink(node, fnNode, ctx, taintMask, env);
      }
    }
    if (node.type === "member_call_expression") {
      checkMemberCallSink(node, ctx, taintMask, env);
      const methodName = node.childForFieldName("name")?.text;
      if (methodName && ctx.localFunctions.has(methodName)) {
        seedLocalFunctionParams(methodName, argListOfPHP(node), env, ctx);
      }
    }
    if (node.type === "include_expression" || node.type === "require_expression"
        || node.type === "include_once_expression" || node.type === "require_once_expression") {
      checkIncludeExpressionSink(node, ctx, taintMask, env);
    }

    for (const child of node.namedChildren) if (child) walk(child, env);
    return false;
  };

  return { walk, taintMask };
}

/** Main-scan entry: walks one function body / top-level statement (or a seeded re-walk) with sink checks and call-site seeding. */
function walkForDeclarationsAndSinks(node: SyntaxNode, env: Env, ctx: EngineCtx): boolean {
  return createWalkerPHP(ctx, { descendFunctions: true }).walk(node, env);
}

// ── BOLA: sink shapes, ownership-comparison detection, per-function emission ──

// "where" deliberately NOT included here -- Laravel's `->where('column',
// $value)` is a 2-arg shape whose resource-id reference is in args[1], not
// args[0] (a real, confirmed difference from `->find($id)`'s single-arg
// shape) -- handled as its own special case below instead, since folding
// it into this generic "check args[0]" set would silently miss every real
// `->where('id', $id)` call.
const BOLA_LOOKUP_TAILS = new Set(["find", "findOrFail", "first", "get"]);
// Matched against a node's raw .text, which for a PHP superglobal/variable
// INCLUDES the $ sigil (e.g. "$_SESSION['user_id']", not "_SESSION[...]")
// -- confirmed directly (a test using this regex without the optional `\$`
// failed against real parsed text before this was added).
const PRINCIPAL_NAME_RE = /^(?:\$_SESSION\b|Auth::|auth\(\))/;

interface BolaSinkCandidate { node: SyntaxNode; sourceExpr: string; sinkExpr: string; idNames: Set<string> }

function isPrincipalShaped(text: string): boolean {
  return PRINCIPAL_NAME_RE.test(text);
}

// Resolves the most recent assignment (source-order-last among those
// preceding `beforeNode`) right-hand side for a bare variable name -- a small,
// bounded ONE-HOP lookback (not general taint propagation), used only to
// let the SQL_CALL_TAILS BOLA branch below see through an opaque
// intermediate variable like `$sql` back to whatever built it. Consistent
// with this engine's existing "second-hop" precision philosophy elsewhere
// (extractTaintedVars' own documented one-hop propagation in scanner.ts).
function resolveRecentAssignmentRHS(bodyNodes: SyntaxNode[], varName: string, beforeNode: SyntaxNode): SyntaxNode | null {
  let found: SyntaxNode | null = null;
  let foundIndex = -1;
  for (const body of bodyNodes) {
    for (const assign of findAllNodes(body, "assignment_expression")) {
      // Only assignments that PRECEDE the call being resolved -- a variable
      // like $sql is routinely reassigned many times in one script, and the
      // last assignment in the whole file is not the one this call sees.
      if (assign.startIndex >= beforeNode.startIndex) continue;
      const left = assign.childForFieldName("left");
      if (left?.type === "variable_name" && variableBareName(left) === varName && assign.startIndex > foundIndex) {
        found = assign.childForFieldName("right") ?? found;
        foundIndex = assign.startIndex;
      }
    }
  }
  return found;
}

/** Does `left`/`right` compare a resource id (one of `ids`) with the authenticated principal? */
function ownershipComparisonPHP(left: SyntaxNode, right: SyntaxNode, ids: Set<string>): boolean {
  const lIsRes = variableNamesIn(left).some(id => ids.has(id));
  const rIsRes = variableNamesIn(right).some(id => ids.has(id));
  return (lIsRes && isPrincipalShaped(right.text)) || (isPrincipalShaped(left.text) && rIsRes);
}

type SidePHP = "true" | "false";

/** Which side(s) of `cond` establish that a resource id in `ids` equals the
 * authenticated principal (`==`/`===` hold on the true side, `!=`/`!==` on
 * the false side; `!`/`&&`/`||` compose like validation guards do). A bare
 * `$isOwner` variable resolves ONE hop to its most recent assignment. */
function ownershipSidesPHP(cond: SyntaxNode, ids: Set<string>, bodyNodes: SyntaxNode[], resolve = true): SidePHP[] {
  const flip = (s: SidePHP): SidePHP => (s === "true" ? "false" : "true");
  switch (cond.type) {
    case "parenthesized_expression": {
      const inner = cond.namedChildren[0];
      return inner ? ownershipSidesPHP(inner, ids, bodyNodes, resolve) : [];
    }
    case "unary_op_expression": {
      if (cond.child(0)?.type !== "!") return [];
      const inner = cond.childForFieldName("argument") ?? cond.namedChildren[0];
      return inner ? ownershipSidesPHP(inner, ids, bodyNodes, resolve).map(flip) : [];
    }
    case "binary_expression": {
      const op = cond.childForFieldName("operator")?.type;
      const l = cond.childForFieldName("left");
      const r = cond.childForFieldName("right");
      if (!l || !r) return [];
      if (op === "==" || op === "===") return ownershipComparisonPHP(l, r, ids) ? ["true"] : [];
      if (op === "!=" || op === "!==") return ownershipComparisonPHP(l, r, ids) ? ["false"] : [];
      if (op === "&&" || op === "and") return [...ownershipSidesPHP(l, ids, bodyNodes, resolve), ...ownershipSidesPHP(r, ids, bodyNodes, resolve)].filter(s => s === "true");
      if (op === "||" || op === "or") return [...ownershipSidesPHP(l, ids, bodyNodes, resolve), ...ownershipSidesPHP(r, ids, bodyNodes, resolve)].filter(s => s === "false");
      return [];
    }
    case "variable_name": {
      if (!resolve) return [];
      const name = variableBareName(cond);
      const rhs = name ? resolveRecentAssignmentRHS(bodyNodes, name, cond) : null;
      return rhs ? ownershipSidesPHP(rhs, ids, bodyNodes, false) : [];
    }
    default:
      return [];
  }
}

/**
 * Does an ownership comparison DOMINATE `sink`? It must (a) sit in an if
 * condition (or ternary, or `abort_if`/`abort_unless`) that precedes the sink
 * in source order and (b) put the sink on the continuing path: the sink is in
 * the arm where the comparison establishes ownership, or the other arm always
 * terminates (return/throw/exit/die/abort) and the sink comes after the whole
 * if. A comparison that is unused, follows the lookup, or guards a different
 * branch no longer suppresses.
 */
function ownershipDominatesPHP(sink: SyntaxNode, ids: Set<string>, bodyNodes: SyntaxNode[]): boolean {
  const contains = (outer: SyntaxNode | null, inner: SyntaxNode) =>
    !!outer && outer.startIndex <= inner.startIndex && inner.endIndex <= outer.endIndex;
  let found = false;
  const visit = (n: SyntaxNode) => {
    if (found) return;
    if (n.type === "if_statement") {
      const cond = n.childForFieldName("condition");
      const body = n.childForFieldName("body");
      const alts = n.childrenForFieldName("alternative").filter((c): c is SyntaxNode => !!c);
      const afterIf = sink.startIndex >= n.endIndex && contains(n.parent, sink);
      if (cond && cond.endIndex <= sink.startIndex) {
        const sides = ownershipSidesPHP(cond, ids, bodyNodes);
        const inAlts = alts.some(a => contains(a, sink));
        const altsAllTerminate = alts.some(a => a.type === "else_clause") && alts.every(a => statementTerminatesPHP(a.childForFieldName("body")));
        if (sides.includes("true") && (contains(body, sink) || (afterIf && altsAllTerminate))) found = true;
        if (sides.includes("false") && (inAlts || (afterIf && statementTerminatesPHP(body)))) found = true;
      }
    } else if (n.type === "else_if_clause") {
      const cond = n.childForFieldName("condition");
      const body = n.childForFieldName("body");
      if (cond && cond.endIndex <= sink.startIndex) {
        const sides = ownershipSidesPHP(cond, ids, bodyNodes);
        if (sides.includes("true") && contains(body, sink)) found = true;
      }
    } else if (n.type === "conditional_expression") {
      const cond = n.childForFieldName("condition");
      if (cond && cond.endIndex <= sink.startIndex) {
        const sides = ownershipSidesPHP(cond, ids, bodyNodes);
        if (sides.includes("true") && contains(n.childForFieldName("body"), sink)) found = true;
        if (sides.includes("false") && contains(n.childForFieldName("alternative"), sink)) found = true;
      }
    } else if (n.type === "expression_statement") {
      // abort_if($id != Auth::id(), 403); abort_unless($id == Auth::id(), 403);
      const call = n.namedChildren[0];
      const fnNode = call?.type === "function_call_expression" ? call.childForFieldName("function") : null;
      const fnName = fnNode?.type === "name" ? fnNode.text.toLowerCase() : "";
      const isIf = fnName === "abort_if" || fnName === "throw_if";
      const isUnless = fnName === "abort_unless" || fnName === "throw_unless";
      if ((isIf || isUnless) && call && n.endIndex <= sink.startIndex && contains(n.parent, sink)) {
        const cond = argListOfPHP(call)[0];
        if (cond) {
          const sides = ownershipSidesPHP(cond, ids, bodyNodes);
          // abort_if(c) aborts when c is true, so what follows runs with c false
          if (sides.includes(isIf ? "false" : "true")) found = true;
        }
      }
    }
    if (!found) for (const c of n.namedChildren) if (c) visit(c);
  };
  for (const b of bodyNodes) visit(b);
  return found;
}

// Takes an array of body-ish nodes (a single function/method body, OR the
// scattered top-level statement siblings of a framework-less PHP script --
// see this function's two call sites in scanAstTaintPHP) rather than a
// single LocalFunction, so the same logic covers both without duplicating
// it. Top-level script code has no LocalFunction wrapper to hang a body
// off of at all -- collectBolaFindings used to be structurally uncallable
// for it for that reason alone, confirmed directly, not any other gating
// logic inside this function.
//
// Candidates are collected first, then each is emitted unless an ownership
// comparison for ITS resource id dominates it (ownershipDominatesPHP) -- not
// merely "a comparison exists somewhere in the function".
function collectBolaFindings(
  bodyNodes: SyntaxNode[], resourceIdParamNames: Set<string>, authMeta: FuncAuthMeta, ctx: EngineCtx,
) {
  if (bodyNodes.length === 0) return;
  if (!authMeta.hasResourceIdParam) return;
  if (authMeta.suppressedByAuthCheck) return;

  const candidates: BolaSinkCandidate[] = [];
  const idsIn = (n: SyntaxNode | null | undefined): Set<string> =>
    new Set(variableNamesIn(n).filter(id => resourceIdParamNames.has(id)));

  const memberAndScopedCalls = bodyNodes.flatMap(b =>
    [...findAllNodes(b, "member_call_expression"), ...findAllNodes(b, "scoped_call_expression")]);
  for (const shape of memberAndScopedCalls) {
    const methodName = shape.childForFieldName("name")?.text;
    if (!methodName) continue;
    const args = argListOfPHP(shape);
    if (methodName === "where" && args.length >= 2) {
      // Laravel: ->where('column', $value) / ::where('column', $value) --
      // the collected candidate is the where() call itself (a scoped
      // query), regardless of whatever ->get()/->first()/->delete() the
      // chain ends with -- that final call isn't where the resource id
      // actually appears.
      const idNames = idsIn(args[1]);
      if (idNames.size > 0) {
        candidates.push({ node: shape, sourceExpr: args[1].text, sinkExpr: calleeTextPHP(shape) ?? methodName, idNames });
      }
      continue;
    }
    if (SQL_CALL_TAILS.has(methodName) && args.length > 0) {
      // Raw-SQL-string sink (->query()/->exec()/->prepare()) -- a
      // materially different real-world shape from Laravel's ORM lookup
      // verbs above (`$sql = "SELECT ... '$accountId'"; $conn->query($sql);`
      // -- the resource id never appears as the call's own argument, only
      // inside whatever built the $sql string on an earlier line).
      const directNames = variableNamesIn(args[0]);
      let sourceExprText = args[0].text;
      let idNames = idsIn(args[0]);
      if (idNames.size === 0 && directNames.length === 1) {
        const rhs = resolveRecentAssignmentRHS(bodyNodes, directNames[0], shape);
        if (rhs) {
          const rhsIds = idsIn(rhs);
          if (rhsIds.size > 0) { idNames = rhsIds; sourceExprText = rhs.text; }
        }
      }
      if (idNames.size > 0) candidates.push({ node: shape, sourceExpr: sourceExprText, sinkExpr: calleeTextPHP(shape) ?? methodName, idNames });
      continue;
    }
    if (!BOLA_LOOKUP_TAILS.has(methodName) || args.length === 0) continue;
    const idNames = idsIn(args[0]);
    if (idNames.size > 0) {
      candidates.push({ node: shape, sourceExpr: args[0].text, sinkExpr: calleeTextPHP(shape) ?? methodName, idNames });
    }
  }
  for (const oc of bodyNodes.flatMap(b => findAllNodes(b, "object_creation_expression"))) {
    const classNameNode = oc.namedChildren.find(c => c && c.type === "name");
    if (!classNameNode) continue;
    const args = argListOfPHP(oc);
    if (args.length === 0) continue;
    const idNames = idsIn(args[0]);
    if (idNames.size > 0) {
      candidates.push({ node: oc, sourceExpr: args[0].text, sinkExpr: `new ${classNameNode.text}`, idNames });
    }
  }

  const severity: "medium" | "high" = authMeta.verbTier === "read" ? "medium" : "high";
  for (const c of candidates) {
    if (ownershipDominatesPHP(c.node, c.idNames, bodyNodes)) continue;
    emit(ctx, "bola-missing-ownership-check", c.node, c.sourceExpr, c.sinkExpr, severity);
  }
}

// ── Structural per-function checks ──────────────────────────────────────────

const JWT_DECODE_RE_PHP = /base64_decode|base64url_decode/;
const JWT_VERIFY_RE_PHP = /hash_hmac|hash_equals|JWT::decode|Firebase.{0,3}JWT|openssl_verify/;

/** Hand-rolled JWT parsing: split the token on '.', base64-decode the payload, trust the claims -- with
 * no signature check anywhere in sight. Same structural (not data-flow) shape as every other engine's
 * identical check. */
function checkHandRolledJwtPHP(bodyNodes: SyntaxNode[], ctx: EngineCtx) {
  for (const body of bodyNodes) {
    const text = body.text;
    if (!/explode\s*\(\s*["']\.["']/.test(text) || !JWT_DECODE_RE_PHP.test(text) || JWT_VERIFY_RE_PHP.test(text)) continue;
    const decode = findAllNodes(body, "function_call_expression").find(n => {
      const fnNode = n.childForFieldName("function");
      return fnNode?.type === "name" && JWT_DECODE_RE_PHP.test(fnNode.text);
    });
    if (!decode) continue;
    emit(ctx, "jwt-none-alg", decode, "bearer token", "manual JWT decode");
  }
}

// ── Entry point ──────────────────────────────────────────────────────────

export function scanAstTaintPHP(
  content: string, filePath: string, root: SyntaxNode,
  // Sinks whose argument was tainted for the sink's class but positively
  // cleared by a sanitizer -- see EngineCtx.suppressed.
  suppressedOut?: SuppressedSink[],
): AstTaintPHPFinding[] {
  try {
    const lines = content.split("\n");
    const localFunctions = collectLocalFunctions(root);
    const ctx: EngineCtx = {
      content, lines, localFunctions, propagatingParams: new Map(), seededParams: new Map(),
      findings: [], seen: new Set(), varTypes: new Map(), root, suppressed: suppressedOut,
      globalNames: collectGlobalNamesPHP(root), sticky: new Map(), stickyDirty: false, recordSticky: false,
    };

    const propagating = buildPropagatingMapPHP(localFunctions, ctx);
    for (const [name, idx] of propagating) ctx.propagatingParams.set(name, idx);

    ctx.recordSticky = true;
    const scanFunctions = (structural: boolean) => {
      for (const [, fn] of localFunctions) {
        if (!fn.body) continue;
        const env: Env = new Map();
        walkForDeclarationsAndSinks(fn.body, env, ctx);
        if (structural) {
          collectBolaFindings([fn.body], fn.resourceIdParamNames, fn.authMeta, ctx);
          checkHandRolledJwtPHP([fn.body], ctx);
        }
      }
    };
    scanFunctions(true);
    // `global $x;` memory one function writes is visible to another: re-walk until it stops growing.
    for (let round = 0; round < 2 && ctx.stickyDirty; round++) {
      ctx.stickyDirty = false;
      scanFunctions(false);
    }

    // Also walk top-level (non-function) statements once, so a superglobal
    // -> sink flow in framework-less script code (outside any function) is
    // still caught by the sink checks themselves -- reachability for this
    // code stays the documented, accepted "unreachable"/default gap (see
    // this module's own docblock), but the FINDING itself isn't silently
    // dropped just because it's not inside a named function.
    const topLevelEnv: Env = new Map();
    const topLevelChildren: SyntaxNode[] = [];
    // Deliberately NOT pruning code after a top-level `exit;`/`die;`/`return;`:
    // framework-less scripts (and vulnerable-by-design samples) routinely
    // concatenate independent snippets, and treating everything after the
    // first bare `exit;` as dead silently dropped six real findings on a
    // benchmark file. Inside function bodies the pruning stays.
    for (const child of root.namedChildren) {
      if (child && child.type !== "function_definition" && child.type !== "class_declaration") {
        walkForDeclarationsAndSinks(child, topLevelEnv, ctx);
        topLevelChildren.push(child);
      }
    }

    // BOLA for top-level script code -- same rationale as the sink-check
    // walk above (framework-less script code shouldn't be silently
    // excluded just because it has no enclosing function). resourceIdParamNames
    // here comes from a top-level variable assigned DIRECTLY from a
    // superglobal whose name matches RESOURCE_ID_PARAM_RE, the closest
    // top-level analog to a function's own resource-id-shaped parameter.
    // verbTier defaults to "read" (medium severity) -- there's no function
    // name here to signal read/write intent from, and a conservative
    // default avoids over-alarming on top-level code. suppressedByAuthCheck
    // reuses the exact same AUTH_SUPPRESS_CALL_RE scan extractFuncInfo
    // already does for a real function body.
    const topLevelResourceIdParamNames = new Set<string>();
    for (const child of topLevelChildren) {
      for (const assign of findAllNodes(child, "assignment_expression")) {
        const left = assign.childForFieldName("left");
        const right = assign.childForFieldName("right");
        if (left?.type !== "variable_name" || !right) continue;
        const varName = variableBareName(left);
        if (varName && RESOURCE_ID_PARAM_RE.test(varName) && isTaintSourceExprPHP(right)) {
          topLevelResourceIdParamNames.add(varName);
        }
      }
    }
    const topLevelSuppressedByAuthCheck = topLevelChildren.some(child =>
      findAllNodes(child, "member_call_expression").some(mc => {
        const text = calleeTextPHP(mc);
        return !!text && AUTH_SUPPRESS_CALL_RE.test(text);
      }) || findAllNodes(child, "scoped_call_expression").some(sc => {
        const text = calleeTextPHP(sc);
        return !!text && AUTH_SUPPRESS_CALL_RE.test(text);
      }));
    collectBolaFindings(topLevelChildren, topLevelResourceIdParamNames, {
      hasResourceIdParam: topLevelResourceIdParamNames.size > 0,
      verbTier: "read",
      suppressedByAuthCheck: topLevelSuppressedByAuthCheck,
    }, ctx);

    // Second pass, bounded worklist -- see astTaintCSharp.ts's/astTaintJava.ts's
    // own identical worklist for the full reasoning.
    const walkedSignatures = new Set<string>();
    for (let round = 0; round < MAX_PROPAGATION_ROUNDS; round++) {
      const toWalk = Array.from(ctx.seededParams.entries());
      let changed = false;
      for (const [fnName, idxSet] of toWalk) {
        const fn = localFunctions.get(fnName);
        if (!fn?.body) continue;
        const signature = `${fnName}:${[...idxSet].sort((a, b) => a[0] - b[0]).map(([i, m]) => `${i}=${m}`).join(",")}`;
        if (walkedSignatures.has(signature)) continue;
        walkedSignatures.add(signature);
        changed = true;
        const env: Env = new Map();
        for (const [idx, m] of idxSet) {
          const shape = fn.paramShapes[idx];
          if (shape) env.set(shape.name, m);
        }
        walkForDeclarationsAndSinks(fn.body, env, ctx);
      }
      if (!changed) break;
    }

    void filePath;
    return ctx.findings;
  } catch (err) {
    console.error(`[astTaintPHP] threw scanning ${filePath}:`, err);
    return [];
  }
}

export function astTaintPHPSeverity(id: AstTaintPHPId): "critical" | "high" | "medium" {
  return SEVERITY[id];
}
export function astTaintPHPLabel(id: AstTaintPHPId): string {
  return LABEL[id];
}
