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
import { ALL, applyClears, classOf, wasCleared, type SuppressedSink, type TaintEnv } from "./taint/taintCore";
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
  | "nosql-injection" | "xpath-injection";

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

// ── Taint sources ────────────────────────────────────────────────────────

const SUPERGLOBAL_NAMES = new Set(["_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER"]);
// Laravel: $request->input(...)/->query(...)/->get(...)/->all(...) -- the
// receiver's own variable name isn't checked (matches any receiver by
// method-name tail, same permissive-by-design posture the sanitizer tables
// across every engine already use), since a typed `Request $request`
// parameter has no attribute this engine can reliably read without
// re-probing a parameter type-hint field shape that wasn't confirmed.
const LARAVEL_REQUEST_METHODS = new Set(["input", "query", "all", "post", "get"]);

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
};
const LABEL: Record<AstTaintPHPId, string> = {
  "sql-injection": "SQL Injection", "command-injection": "Command Injection", "xss": "Reflected XSS",
  "ssrf": "Server-Side Request Forgery", "path-traversal": "Path Traversal",
  "insecure-deserialization": "Insecure Deserialization", "file-inclusion": "PHP File Inclusion",
  "open-redirect": "Open Redirect",
  "bola-missing-ownership-check": "Broken Object Level Authorization (AST-verified)",
  "header-injection": "HTTP Header Injection", "ldap-injection": "LDAP Injection",
  "nosql-injection": "NoSQL Injection", "xpath-injection": "XPath Injection",
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
      return varName ? (env.get(varName) ?? 0) : 0;
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
      if ((op === "." || op === "+") && left && right) return taintMask(left, env) | taintMask(right, env);
      return 0;
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
  const taintMask = makeTaintMaskPHP(ctx);
  const returnExprs = findAllNodes(fn.body, "return_statement")
    .map(ret => ret.namedChildren[0])
    .filter((e): e is SyntaxNode => !!e);
  for (const shape of fn.paramShapes) {
    const env: Env = new Map();
    env.set(shape.name, ALL);
    // Low bits only: the shadow half is per-scan bookkeeping, not a summary.
    const surviving = returnExprs.reduce((m, expr) => m | taintMask(expr, env), 0) & ALL;
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
  } else if (methodName === "setopt") {
    // curl_setopt($ch, CURLOPT_URL, $tainted) -- args[0] is the handle,
    // args[1] the CURLOPT_* constant, args[2] the value; a tainted MATCH
    // anywhere in args is close enough given this engine's "accept some
    // imprecision" posture (matches every other engine's loose arg-tainted
    // checks elsewhere).
    fire("ssrf", "curl_setopt");
  }
}

// ── Statement-level walk ─────────────────────────────────────────────────

function walkForDeclarationsAndSinks(node: SyntaxNode, env: Env, ctx: EngineCtx) {
  const taintMask = makeTaintMaskPHP(ctx);

  // No separate declaration statement in PHP -- see this module's own
  // docblock for why assignment_expression alone covers both first-use and
  // re-assignment.
  if (node.type === "assignment_expression") {
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    const mask = right ? taintMask(right, env) : 0;
    if (left?.type === "variable_name") {
      const varName = variableBareName(left);
      if (varName) {
        env.set(varName, mask);
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
    if (fnNode?.type === "name" && ctx.localFunctions.has(fnNode.text)) {
      seedLocalFunctionParams(fnNode.text, argListOfPHP(node), env, ctx);
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

  for (const child of node.namedChildren) {
    if (child) walkForDeclarationsAndSinks(child, env, ctx);
  }
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

interface BolaSinkCandidate { node: SyntaxNode; sourceExpr: string; sinkExpr: string }

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

// Takes an array of body-ish nodes (a single function/method body, OR the
// scattered top-level statement siblings of a framework-less PHP script --
// see this function's two call sites in scanAstTaintPHP) rather than a
// single LocalFunction, so the same logic covers both without duplicating
// it. Top-level script code has no LocalFunction wrapper to hang a body
// off of at all -- collectBolaFindings used to be structurally uncallable
// for it for that reason alone, confirmed directly, not any other gating
// logic inside this function.
function collectBolaFindings(
  bodyNodes: SyntaxNode[], resourceIdParamNames: Set<string>, authMeta: FuncAuthMeta, ctx: EngineCtx,
) {
  if (bodyNodes.length === 0) return;
  if (!authMeta.hasResourceIdParam) return;
  if (authMeta.suppressedByAuthCheck) return;

  const candidates: BolaSinkCandidate[] = [];
  let hasOwnershipComparison = false;

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
      const argIds = findAllNodes(args[1], "variable_name").map(n => variableBareName(n)).filter((n): n is string => !!n);
      if (argIds.some(id => resourceIdParamNames.has(id))) {
        candidates.push({ node: shape, sourceExpr: args[1].text, sinkExpr: calleeTextPHP(shape) ?? methodName });
      }
      continue;
    }
    if (SQL_CALL_TAILS.has(methodName) && args.length > 0) {
      // Raw-SQL-string sink (->query()/->exec()/->prepare()) -- a
      // materially different real-world shape from Laravel's ORM lookup
      // verbs above (`$sql = "SELECT ... '$accountId'"; $conn->query($sql);`
      // -- the resource id never appears as the call's own argument, only
      // inside whatever built the $sql string on an earlier line).
      const directIds = findAllNodes(args[0], "variable_name").map(n => variableBareName(n)).filter((n): n is string => !!n);
      let sourceExprText = args[0].text;
      let matched = directIds.some(id => resourceIdParamNames.has(id));
      if (!matched && directIds.length === 1) {
        const rhs = resolveRecentAssignmentRHS(bodyNodes, directIds[0], shape);
        if (rhs) {
          const rhsIds = findAllNodes(rhs, "variable_name").map(n => variableBareName(n)).filter((n): n is string => !!n);
          if (rhsIds.some(id => resourceIdParamNames.has(id))) { matched = true; sourceExprText = rhs.text; }
        }
      }
      if (matched) candidates.push({ node: shape, sourceExpr: sourceExprText, sinkExpr: calleeTextPHP(shape) ?? methodName });
      continue;
    }
    if (!BOLA_LOOKUP_TAILS.has(methodName) || args.length === 0) continue;
    const argIds = findAllNodes(args[0], "variable_name").map(n => variableBareName(n)).filter((n): n is string => !!n);
    if (argIds.some(id => resourceIdParamNames.has(id))) {
      candidates.push({ node: shape, sourceExpr: args[0].text, sinkExpr: calleeTextPHP(shape) ?? methodName });
    }
  }
  for (const oc of bodyNodes.flatMap(b => findAllNodes(b, "object_creation_expression"))) {
    const classNameNode = oc.namedChildren.find(c => c && c.type === "name");
    if (!classNameNode) continue;
    const args = argListOfPHP(oc);
    if (args.length === 0) continue;
    const argIds = findAllNodes(args[0], "variable_name").map(n => variableBareName(n)).filter((n): n is string => !!n);
    if (argIds.some(id => resourceIdParamNames.has(id))) {
      candidates.push({ node: oc, sourceExpr: args[0].text, sinkExpr: `new ${classNameNode.text}` });
    }
  }
  for (const bin of bodyNodes.flatMap(b => findAllNodes(b, "binary_expression"))) {
    const op = bin.childForFieldName("operator")?.type;
    if (op !== "==" && op !== "===" && op !== "!=" && op !== "!==") continue;
    const left = bin.childForFieldName("left");
    const right = bin.childForFieldName("right");
    if (!left || !right) continue;
    const lIds = new Set(findAllNodes(left, "variable_name").map(n => variableBareName(n)).filter((n): n is string => !!n));
    const rIds = new Set(findAllNodes(right, "variable_name").map(n => variableBareName(n)).filter((n): n is string => !!n));
    const lIsRes = [...lIds].some(id => resourceIdParamNames.has(id));
    const rIsRes = [...rIds].some(id => resourceIdParamNames.has(id));
    const lIsPrin = isPrincipalShaped(left.text);
    const rIsPrin = isPrincipalShaped(right.text);
    if ((lIsRes && rIsPrin) || (lIsPrin && rIsRes)) hasOwnershipComparison = true;
  }

  if (!hasOwnershipComparison) {
    const severity: "medium" | "high" = authMeta.verbTier === "read" ? "medium" : "high";
    for (const c of candidates) emit(ctx, "bola-missing-ownership-check", c.node, c.sourceExpr, c.sinkExpr, severity);
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
      findings: [], seen: new Set(), varTypes: new Map(), suppressed: suppressedOut,
    };

    const propagating = buildPropagatingMapPHP(localFunctions, ctx);
    for (const [name, idx] of propagating) ctx.propagatingParams.set(name, idx);

    for (const [, fn] of localFunctions) {
      if (!fn.body) continue;
      const env: Env = new Map();
      walkForDeclarationsAndSinks(fn.body, env, ctx);
      collectBolaFindings([fn.body], fn.resourceIdParamNames, fn.authMeta, ctx);
    }

    // Also walk top-level (non-function) statements once, so a superglobal
    // -> sink flow in framework-less script code (outside any function) is
    // still caught by the sink checks themselves -- reachability for this
    // code stays the documented, accepted "unreachable"/default gap (see
    // this module's own docblock), but the FINDING itself isn't silently
    // dropped just because it's not inside a named function.
    const topLevelEnv: Env = new Map();
    const topLevelChildren: SyntaxNode[] = [];
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
