/**
 * Real AST-based taint engine for C# — parity phase, closing the last gap
 * among this codebase's 5 scanned OOP/scripting languages (see astTaint.ts
 * for JS/TS, astTaintPython.ts for Python, astTaintJava.ts for Java,
 * astTaintGo.ts for Go, whose five-stage architecture -- sources, sinks,
 * propagation, interprocedural, findings -- this file mirrors).
 *
 * Two templates, deliberately split, confirmed by direct empirical probing
 * of tree-sitter-c-sharp's real grammar (not assumed):
 *  - PARSING MECHANICS follow astTaintGo.ts: web-tree-sitter +
 *    tree-sitter-wasms' prebuilt tree-sitter-c_sharp.wasm grammar (already
 *    bundled in this repo's existing tree-sitter-wasms dependency -- no new
 *    package needed), the same async warm-cache contract.
 *  - The TAINT-WALKER SHAPE also follows Go's/Python's recursive-descent
 *    design, NOT Java's flat primarySuffix fold -- confirmed directly: a
 *    C# fluent chain like `db.Query(sql).Execute()` nests RECURSIVELY
 *    (`invocation_expression -> function: member_access_expression ->
 *    expression: invocation_expression -> ...`), the same shape
 *    astTaintGo.ts's calleeTextGo/isTainted already recurse through, unlike
 *    Chevrotain's flat primarySuffix array Java's walkPrimaryChain exists
 *    specifically to fold over.
 *  - SOURCE/SINK/AUTHORIZATION VOCABULARY follows astTaintJava.ts: C# is an
 *    attribute-driven ASP.NET Core OOP language, the closest match to
 *    Java's annotation-driven Spring vocabulary ([FromRoute]/[FromQuery]/
 *    [FromBody]/[FromHeader] mirror @PathVariable/@RequestParam/
 *    @RequestBody/@RequestHeader; [HttpGet]/[HttpPost]/etc mirror
 *    @GetMapping/@PostMapping/etc; [Authorize]/[AllowAnonymous] mirror
 *    @PreAuthorize/@Secured/@RolesAllowed).
 *
 * Built directly to this session's CURRENT target state (not the earlier,
 * less-capable shape the first four engines originally shipped with, later
 * upgraded) -- field-sensitive taint, sanitizer/de-taint recognition,
 * bounded (MAX_PROPAGATION_ROUNDS = 3) same-file interprocedural
 * propagation, and a structural BOLA/authorization detector are all here
 * from the start.
 *
 * Runs ADDITIVELY alongside every existing C# regex/named-taint detector in
 * scanner.ts (findInsecureDeserializationCSharp(JsonNet),
 * findNamedTaintPathTraversalCSharp, findNamedTaintSSRFCSharp/
 * findSSRFCSharpNewRequest, findNamedTaintXSSCSharp, findNamedTaintIDORCSharp,
 * findXXECSharp, findInsecureFileUploadCSharp, findSQLInjectionCSharpTainted,
 * etc.) -- none of those are touched, removed, or replaced. Reuses existing
 * finding ids (sql-injection, command-injection, xss, ssrf, path-traversal,
 * open-redirect, insecure-deserialization, ldap-injection, xpath-injection,
 * bola-missing-ownership-check), all already wired through cweMap.ts/
 * sarif.ts/githubComment.ts (confirmed zero csharp-specific logic needed in
 * any of the three -- all purely id-keyed), so no new UI wiring is needed.
 *
 * Deliberately excludes, matching every prior engine's own precedent of
 * leaving "hardening-absence" checks to the regex layer: weak-crypto,
 * insecure-randomness, cookie security, verbose errors. Also out of scope
 * this phase: Razor (.cshtml) template-syntax parsing (tree-sitter-c_sharp
 * parses C#, not Razor's mixed HTML/C# syntax -- .cshtml stays on its
 * existing regex coverage), branch/CFG-aware authorization analysis (the
 * same accepted gap astTaintJava.ts's own BOLA detector documents), and
 * cross-file propagation (same-file only, matching every other engine here).
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { Parser, Language } = require("web-tree-sitter") as typeof import("web-tree-sitter");
import type { Node as SyntaxNode, Language as LanguageT, Parser as ParserT } from "web-tree-sitter";
import { ensureTreeSitterInit } from "./treeSitterRuntime";

// See astTaintPython.ts's/astTaintGo.ts's identical helper for why:
// require.resolve(...) from inside webpack-bundled code doesn't do real
// filesystem resolution, even for an externalized package -- it returns
// webpack's internal numeric module id instead of a path.
// __non_webpack_require__ escapes that, giving a real on-disk path to read
// raw .wasm bytes from.
declare const __non_webpack_require__: NodeJS.Require | undefined;
function nodeRequire(): NodeJS.Require {
  // eslint-disable-next-line no-undef
  return typeof __non_webpack_require__ !== "undefined" ? __non_webpack_require__ : require;
}

export type AstTaintCSharpId =
  | "sql-injection" | "command-injection" | "xss" | "ssrf" | "path-traversal"
  | "open-redirect" | "insecure-deserialization" | "ldap-injection" | "xpath-injection"
  | "bola-missing-ownership-check";

export interface AstTaintCSharpFinding {
  id:         AstTaintCSharpId;
  line:       number;
  detail:     string;
  sourceExpr: string;
  sinkExpr:   string;
  // Only set for bola-missing-ownership-check (read vs write endpoint
  // severity) -- every other id keeps using the constant SEVERITY table.
  severityOverride?: "critical" | "high" | "medium";
}

// ── Parser lifecycle (warm-cache pattern -- see astTaintGo.ts's identical docblock) ──

let langPromise: Promise<LanguageT> | null = null;
let parserPool: ParserT | null = null;

function initCSharpParser(): Promise<LanguageT> {
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
      // Note the underscore, not a hyphen -- confirmed directly against the
      // actual bundled filename in tree-sitter-wasms/out/.
      const wasmPath = path.join(nodeModulesDir, "tree-sitter-wasms", "out", "tree-sitter-c_sharp.wasm");
      const lang = await Language.load(new Uint8Array(fs.readFileSync(wasmPath)));
      const p = new Parser();
      p.setLanguage(lang);
      parserPool = p;
      console.log("[astTaintCSharp] C# AST taint engine ready");
      return lang;
    })().catch(err => {
      console.error("[astTaintCSharp] WASM init failed -- C# AST taint scanning disabled, regex detectors unaffected:", err);
      throw err;
    });
  }
  return langPromise;
}
// Fire at module import time, skipped under Jest for the same reason
// astTaintGo.ts/astTaintPython.ts skip it: dozens of unrelated test files
// transitively import this module via scanner.ts, none of which await this
// promise. astTaintCSharp.test.ts calls warmCSharpTaintEngine() explicitly
// in beforeAll instead.
if (!process.env.JEST_WORKER_ID) {
  void initCSharpParser().catch(() => { /* already logged above */ });
}

export function isCSharpParserReady(): boolean {
  return parserPool !== null;
}

/** Awaits WASM readiness. Call from instrumentation.ts (prod) or a test beforeAll. */
export async function warmCSharpTaintEngine(): Promise<void> {
  await initCSharpParser().catch(() => { /* already logged; callers just proceed regex-only */ });
}

export function parseCSharpSourceSync(content: string, filePath: string): SyntaxNode | null {
  if (!parserPool) return null;
  try {
    return parserPool.parse(content)?.rootNode ?? null;
  } catch (err) {
    console.error(`[astTaintCSharp] parse threw for ${filePath}:`, err);
    return null;
  }
}

// ── Enclosing-method lookup (shared with reachability.ts's resolver) ────────

/** Deepest tree-sitter node whose source range spans 0-based row `row`. */
export function findNodeAtRowCSharp(root: SyntaxNode, row: number): SyntaxNode {
  let node = root;
  for (;;) {
    const child = node.namedChildren.find(c => c && row >= c.startPosition.row && row <= c.endPosition.row);
    if (!child) return node;
    node = child;
  }
}

export function findEnclosingFunctionNameCSharp(node: SyntaxNode): string {
  let cur: SyntaxNode | null = node;
  while (cur) {
    if (cur.type === "method_declaration") {
      const nameNode = cur.childForFieldName("name");
      if (nameNode) return nameNode.text;
    }
    cur = cur.parent;
  }
  return "unknown";
}

// ── CST helpers ──────────────────────────────────────────────────────────

/** Resolves a member_access_expression/identifier chain to dotted text, e.g.
 * `Request.Query` -> "Request.Query". Recursive, NOT a flat fold -- see this
 * module's own docblock for why C#'s grammar nests this way (confirmed
 * directly), unlike Java's flat primarySuffix array. Mirrors calleeTextGo/
 * calleeText exactly. */
function calleeTextCSharp(node: SyntaxNode): string | null {
  if (node.type === "identifier") return node.text;
  if (node.type === "member_access_expression") {
    const expr = node.childForFieldName("expression");
    const name = node.childForFieldName("name");
    if (!expr || !name) return null;
    const base = calleeTextCSharp(expr);
    return base ? `${base}.${name.text}` : null;
  }
  return null;
}

function argListOfCSharp(call: SyntaxNode): SyntaxNode[] {
  const args = call.childForFieldName("arguments");
  if (!args) return [];
  // `argument` nodes wrap the real expression (confirmed: `argument ->
  // identifier`/`string_literal`/etc as a single named child, no field
  // name) -- unwrap one level so callers see the real expression directly,
  // matching every other engine's argListOf* convention.
  return args.namedChildren
    .filter((n): n is SyntaxNode => !!n && n.type === "argument")
    .map(a => a.namedChildren[0])
    .filter((n): n is SyntaxNode => !!n);
}

/** Every `modifier` node under `node` (public/private/static/async/etc) --
 * confirmed these are plain positional children, not exposed under any
 * named field, for BOTH class_declaration and method_declaration. */
function modifiersOf(node: SyntaxNode): string[] {
  return node.namedChildren.filter((c): c is SyntaxNode => !!c && c.type === "modifier").map(c => c.text);
}

/** Attribute names from an `attribute_list`-bearing node (method_declaration
 * OR parameter -- confirmed identical shape for both, unlike Java where
 * method vs. parameter modifiers are different CST productions). */
function attributeNamesOf(node: SyntaxNode): string[] {
  const names: string[] = [];
  for (const list of node.namedChildren) {
    if (!list || list.type !== "attribute_list") continue;
    for (const attr of list.namedChildren) {
      if (!attr || attr.type !== "attribute") continue;
      const name = attr.childForFieldName("name");
      if (name) names.push(name.text);
    }
  }
  return names;
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

const ASP_SOURCE_ATTRIBUTES = new Set(["FromRoute", "FromQuery", "FromBody", "FromHeader", "FromForm"]);
// ASP.NET Core binds a simple-type action-method parameter from the route
// template or query string IMPLICITLY, by convention, with no [From*]
// attribute at all -- `GetUser(int id)` is exactly as attacker-controlled
// as `GetUser([FromRoute] int id)`. Used only to gate implicit-binding
// taint seeding (extractMethodInfo below), never as a general "is this
// type safe" check -- a complex type with no attribute is NOT covered by
// this convention and is deliberately left untainted (out of scope, see
// astTaintCSharp.ts's own docblock).
const CSHARP_SIMPLE_TYPE_RE = /^(?:string|int|long|short|byte|bool|double|float|decimal|char|Guid|DateTime|byte\[\])\??$/;
// Raw HttpContext/HttpRequest access -- the ASP.NET Core Servlet-API analog.
const RAW_SOURCE_MEMBER_TAILS = new Set(["Query", "Form", "Headers", "Cookies", "QueryString"]);

function isTaintSourceExprCSharp(node: SyntaxNode): boolean {
  if (node.type === "member_access_expression") {
    const text = calleeTextCSharp(node);
    if (!text) return false;
    const tail = text.split(".").pop() ?? "";
    // Request.QueryString (bare, no indexer) -- the other three
    // (Query/Form/Headers/Cookies) are always indexed, handled below.
    return tail === "QueryString" && /(?:^|\.)Request\.QueryString$/.test(text);
  }
  if (node.type === "element_access_expression") {
    const expr = node.childForFieldName("expression") ?? node.namedChildren[0];
    const text = expr ? calleeTextCSharp(expr) : null;
    if (!text) return false;
    const tail = text.split(".").pop() ?? "";
    return RAW_SOURCE_MEMBER_TAILS.has(tail) && /(?:^|\.)Request\./.test(text + ".");
  }
  return false;
}

// ── Sanitizer/de-taint recognition ──────────────────────────────────────
// Matched by method-name TAIL (any receiver), same permissive-by-design
// posture as every other engine's sanitizer table.
const CSHARP_SANITIZER_TAILS = new Set([
  "HtmlEncode", "UrlEncode", "JavaScriptStringEncode", "Encode",
]);

// ── Sink dispatch table ──────────────────────────────────────────────────

const SEVERITY: Record<AstTaintCSharpId, "critical" | "high" | "medium"> = {
  "sql-injection": "critical", "command-injection": "critical", "xss": "critical",
  "ssrf": "critical", "path-traversal": "critical", "insecure-deserialization": "critical",
  "ldap-injection": "critical", "xpath-injection": "critical", "open-redirect": "medium",
  // Fallback only -- collectBolaFindings always passes a severityOverride
  // (medium for read endpoints, high for write/unknown).
  "bola-missing-ownership-check": "high",
};
const LABEL: Record<AstTaintCSharpId, string> = {
  "sql-injection": "SQL Injection", "command-injection": "Command Injection", "xss": "Reflected XSS",
  "ssrf": "Server-Side Request Forgery", "path-traversal": "Path Traversal",
  "insecure-deserialization": "Insecure Deserialization", "ldap-injection": "LDAP Injection",
  "xpath-injection": "XPath Injection", "open-redirect": "Open Redirect",
  "bola-missing-ownership-check": "Broken Object Level Authorization (AST-verified)",
};

// ── Taint environment / propagation ─────────────────────────────────────
// Flat, OR-shaped, no de-tainting (aside from the sanitizer table above) --
// same explicit design as every other engine here.

type Env = Map<string, boolean>;
type VarTypes = Map<string, string>;
interface ParamShape { name: string; index: number }
interface LocalMethod {
  name: string;
  paramShapes: ParamShape[];
  sourceParamNames: Set<string>;      // [FromRoute]/[FromQuery]/[FromBody]/[FromHeader]/[FromForm]
  resourceIdParamNames: Set<string>;  // [FromRoute]/[FromQuery] subset -- "which resource" (BOLA)
  authMeta: MethodAuthMeta;
  body: SyntaxNode | null;
}

interface EngineCtx {
  content: string;
  lines: string[];
  localMethods: Map<string, LocalMethod>;
  propagatingParams: Map<string, Set<number>>;
  seededParams: Map<string, Set<number>>;
  varTypes: VarTypes;
  findings: AstTaintCSharpFinding[];
  seen: Set<string>;
}

function emit(
  ctx: EngineCtx, id: AstTaintCSharpId, node: SyntaxNode, sourceExpr: string, sinkExpr: string,
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

function makeIsTaintedCSharp(ctx: EngineCtx): (node: SyntaxNode, env: Env) => boolean {
  const isTainted = (node: SyntaxNode, env: Env): boolean => {
    if (isTaintSourceExprCSharp(node)) return true;
    if (node.type === "identifier") return env.get(node.text) === true;
    if (node.type === "argument") {
      const inner = node.namedChildren[0];
      return inner ? isTainted(inner, env) : false;
    }
    if (node.type === "parenthesized_expression") {
      const inner = node.namedChildren[0];
      return inner ? isTainted(inner, env) : false;
    }
    if (node.type === "binary_expression") {
      const op = node.childForFieldName("operator")?.type;
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if (op === "+" && left && right) return isTainted(left, env) || isTainted(right, env);
      return false;
    }
    if (node.type === "member_access_expression") {
      // Field-sensitive read: the full dotted path composite key FIRST
      // (set by the assignment write-side below), falling back to the
      // root/operand's own taint -- pure recall gain, never removes a
      // `true` result the fallback alone would find.
      const path = calleeTextCSharp(node);
      if (path && env.get(path) === true) return true;
      const expr = node.childForFieldName("expression");
      return expr ? isTainted(expr, env) : false;
    }
    if (node.type === "element_access_expression") {
      const expr = node.childForFieldName("expression") ?? node.namedChildren[0];
      return expr ? isTainted(expr, env) : false;
    }
    if (node.type === "object_creation_expression") {
      // A constructor call is tainted if ANY of its arguments are --
      // deliberately the baseline rule from the start (unlike astTaintGo.ts,
      // which needed a later correction pass for the http.NewRequest
      // two-step pattern specifically because it lacked this as a default).
      const args = argListOfCSharp(node);
      return args.some(a => isTainted(a, env));
    }
    if (node.type === "invocation_expression") {
      const fn = node.childForFieldName("function");
      const args = argListOfCSharp(node);
      const text = fn ? calleeTextCSharp(fn) : null;
      const tail = text?.split(".").pop() ?? (fn?.type === "identifier" ? fn.text : undefined);
      // Sanitizer calls de-taint at this point, checked BEFORE the
      // propagating-fn/passthrough checks below, so a sanitized value can't
      // be re-tainted by one of them in this same call.
      if (tail && CSHARP_SANITIZER_TAILS.has(tail)) return false;
      // Same-file interprocedural, bounded (see buildPropagatingMapCSharp).
      if (fn?.type === "identifier") {
        const propIdx = ctx.propagatingParams.get(fn.text);
        if (propIdx) {
          const callee = ctx.localMethods.get(fn.text);
          const shapes = callee?.paramShapes ?? [];
          const matched = [...propIdx].some(i => shapes[i] !== undefined && args[i] !== undefined && isTainted(args[i], env));
          if (matched) return true;
        }
      }
      // Generic passthrough: a method call on an already-tainted receiver
      // stays tainted (e.g. dirty.Trim(), dirty.ToLower()).
      if (fn?.type === "member_access_expression") {
        const expr = fn.childForFieldName("expression");
        if (expr && isTainted(expr, env)) return true;
      }
      return false;
    }
    if (node.type === "interpolation") {
      const inner = node.namedChildren[0];
      return inner ? isTainted(inner, env) : false;
    }
    // Generic fallback -- recurse into every named child and OR-combine.
    // Confirmed directly (via probing $"...{x}..." interpolated strings)
    // that this alone correctly reaches an interpolation's inner
    // expression without any interpolated_string_expression-specific case.
    for (const child of node.namedChildren) {
      if (child && isTainted(child, env)) return true;
    }
    return false;
  };
  return isTainted;
}

/**
 * For each of `method`'s parameters INDEPENDENTLY, does `method`'s return
 * value become tainted? Returns the set of propagating parameter INDICES --
 * identical reasoning to every other engine's computeReturnTaintPropagating*.
 * Nested calls are resolved using `ctx` AS GIVEN (not a forced-empty
 * shallow copy) -- boundedness comes entirely from buildPropagatingMapCSharp's
 * round cap below, mirroring the other four engines' current (already-
 * upgraded) design, not their original one-shot shape.
 */
function computeReturnTaintPropagatingCSharp(method: LocalMethod, ctx: EngineCtx): Set<number> {
  const propagatingIdx = new Set<number>();
  if (!method.body) return propagatingIdx;
  const isTainted = makeIsTaintedCSharp(ctx);
  const returnExprs = findAllNodes(method.body, "return_statement")
    .map(ret => ret.namedChildren[0])
    .filter((e): e is SyntaxNode => !!e);
  for (const shape of method.paramShapes) {
    const env: Env = new Map();
    env.set(shape.name, true);
    if (returnExprs.some(expr => isTainted(expr, env))) propagatingIdx.add(shape.index);
  }
  return propagatingIdx;
}

const MAX_PROPAGATION_ROUNDS = 3;

function buildPropagatingMapCSharp(localMethods: Map<string, LocalMethod>, baseCtx: EngineCtx): Map<string, Set<number>> {
  const propagating = new Map<string, Set<number>>();
  for (let round = 0; round < MAX_PROPAGATION_ROUNDS; round++) {
    let changed = false;
    const roundCtx: EngineCtx = { ...baseCtx, propagatingParams: propagating };
    for (const [name, method] of localMethods) {
      const idx = computeReturnTaintPropagatingCSharp(method, roundCtx);
      const existingSize = propagating.get(name)?.size ?? 0;
      if (idx.size > existingSize) {
        propagating.set(name, idx);
        changed = true;
      }
    }
    if (!changed) break;
  }
  return propagating;
}

/** Seeds ctx.seededParams from a call site whose arguments are tainted --
 * consumed by scanAstTaintCSharp's bounded second pass so a sink INSIDE a
 * local method's own body (not just its return) becomes reachable. */
function seedLocalMethodParams(calleeName: string, args: SyntaxNode[], env: Env, ctx: EngineCtx) {
  const callee = ctx.localMethods.get(calleeName);
  if (!callee) return;
  const isTainted = makeIsTaintedCSharp(ctx);
  const taintedIdx = new Set<number>();
  args.forEach((arg, i) => {
    if (!isTainted(arg, env)) return;
    if (callee.paramShapes.some(s => s.index === i)) taintedIdx.add(i);
  });
  if (taintedIdx.size === 0) return;
  const existing = ctx.seededParams.get(calleeName) ?? new Set<number>();
  taintedIdx.forEach(i => existing.add(i));
  ctx.seededParams.set(calleeName, existing);
}

// ── BOLA: authorization metadata extraction ─────────────────────────────

const HTTP_VERB_ATTRIBUTES: Record<string, "read" | "write"> = {
  HttpGet: "read", HttpPost: "write", HttpPut: "write", HttpDelete: "write", HttpPatch: "write",
};
const AUTH_SUPPRESS_ATTRIBUTES = new Set(["Authorize"]);

interface MethodAuthMeta {
  isEndpoint: boolean;
  verbTier: "read" | "write" | "unknown";
  suppressedByAuthAnnotation: boolean;
}

function extractMethodAuthMeta(attrNames: string[]): MethodAuthMeta {
  let isEndpoint = false;
  let verbTier: MethodAuthMeta["verbTier"] = "unknown";
  for (const name of attrNames) {
    if (name in HTTP_VERB_ATTRIBUTES) { isEndpoint = true; verbTier = HTTP_VERB_ATTRIBUTES[name]; }
    if (name === "Route") isEndpoint = true;
  }
  const suppressedByAuthAnnotation = attrNames.some(n => AUTH_SUPPRESS_ATTRIBUTES.has(n));
  return { isEndpoint, verbTier, suppressedByAuthAnnotation };
}

function extractMethodInfo(methodDecl: SyntaxNode): LocalMethod | null {
  const nameNode = methodDecl.childForFieldName("name");
  if (!nameNode) return null;
  // Computed BEFORE the param loop (moved up from its original position
  // after it) so implicit-binding seeding below can gate on
  // authMeta.isEndpoint -- authMeta itself never depended on the params.
  const attrNames = attributeNamesOf(methodDecl);
  const authMeta = extractMethodAuthMeta(attrNames);
  const paramList = methodDecl.childForFieldName("parameters");
  const paramShapes: ParamShape[] = [];
  const sourceParamNames = new Set<string>();
  const resourceIdParamNames = new Set<string>();
  if (paramList) {
    let index = 0;
    for (const param of paramList.namedChildren) {
      if (!param || param.type !== "parameter") continue;
      const pName = param.childForFieldName("name");
      if (!pName) { index++; continue; }
      paramShapes.push({ name: pName.text, index });
      const attrs = attributeNamesOf(param);
      const hasExplicitSource = attrs.some(a => ASP_SOURCE_ATTRIBUTES.has(a));
      if (hasExplicitSource) sourceParamNames.add(pName.text);
      if (attrs.includes("FromRoute") || attrs.includes("FromQuery")) resourceIdParamNames.add(pName.text);
      // Implicit ASP.NET Core model binding (see CSHARP_SIMPLE_TYPE_RE's
      // docblock): only applies to a genuinely unattributed simple-type
      // param of a real controller action (authMeta.isEndpoint) -- a
      // private helper method's params are never HTTP-bound at all, so
      // this deliberately does NOT apply file-wide.
      if (!hasExplicitSource && attrs.length === 0 && authMeta.isEndpoint) {
        const typeText = param.childForFieldName("type")?.text;
        if (typeText && CSHARP_SIMPLE_TYPE_RE.test(typeText)) {
          sourceParamNames.add(pName.text);
          resourceIdParamNames.add(pName.text);
        }
      }
      index++;
    }
  }
  const body = methodDecl.childForFieldName("body");
  return { name: nameNode.text, paramShapes, sourceParamNames, resourceIdParamNames, authMeta, body: body ?? null };
}

function collectLocalMethods(root: SyntaxNode): Map<string, LocalMethod> {
  const methods = new Map<string, LocalMethod>();
  for (const decl of findAllNodes(root, "method_declaration")) {
    const info = extractMethodInfo(decl);
    if (!info) continue;
    // Two different classes in the same file can legitimately declare a
    // method with the same bare name -- e.g. a controller action colliding
    // with an unrelated static helper's method of the same name
    // (ChangeEmail/Transfer/DisableMfa/Deserialize/DeleteUser all collide
    // with a same-named Database.*/BinaryHelper.* stub in a real OWASP
    // benchmark file this phase was built against). Since interprocedural
    // resolution elsewhere in this engine keys callees by bare name (the
    // same same-file-scope precedent every other engine here uses), a
    // flat overwrite silently lost the REAL entry-point method's body to
    // whichever same-named declaration happened to appear LATER in the
    // file, regardless of which one actually mattered -- confirmed via a
    // real re-scan (BinaryHelper.Deserialize's own empty/null-bodied stub
    // overwrote the controller's Deserialize action, silently dropping
    // its insecure-deserialization finding). Prefer an already-recorded
    // entry-point method over a later non-entry-point same-named one;
    // only let a later declaration replace an earlier one when the later
    // one is itself an endpoint and the earlier one wasn't. Two
    // same-named ENDPOINT methods in different classes (not present in
    // that benchmark) is an accepted, undetected residual edge case, same
    // "flat file-wide namespace" tradeoff already documented elsewhere.
    const existing = methods.get(info.name);
    if (existing && existing.authMeta.isEndpoint && !info.authMeta.isEndpoint) continue;
    methods.set(info.name, info);
  }
  return methods;
}

// ── Sink checks ──────────────────────────────────────────────────────────

const FS_PATH_ROOTS = new Set(["Path", "File", "Directory"]);

function checkCallSink(
  fn: SyntaxNode, args: SyntaxNode[], node: SyntaxNode, env: Env, ctx: EngineCtx, isTainted: (n: SyntaxNode, e: Env) => boolean,
) {
  const text = calleeTextCSharp(fn);
  if (!text) return;
  const parts = text.split(".");
  const tail = parts[parts.length - 1];
  const rootVar = parts[0];
  const taintedArg = args.find(a => isTainted(a, env));
  const sourceExpr = taintedArg ? taintedArg.text : text;

  // sql-injection: EF Core raw-SQL calls (arg-tainted) and ADO.NET
  // SqlCommand receiver-tainted (tracked via env at the SqlCommand-typed
  // local declaration site, mirroring astTaintJava.ts's ObjectInputStream
  // readObject pattern).
  if ((tail === "FromSqlRaw" || tail === "ExecuteSqlRaw") && taintedArg) {
    emit(ctx, "sql-injection", node, sourceExpr, text);
  } else if ((tail === "ExecuteReader" || tail === "ExecuteNonQuery" || tail === "ExecuteScalar")
             && ctx.varTypes.get(rootVar) === "SqlCommand" && env.get(rootVar) === true) {
    emit(ctx, "sql-injection", node, rootVar, text);
  } else if (tail === "Start" && rootVar === "Process" && taintedArg) {
    emit(ctx, "command-injection", node, sourceExpr, text);
  } else if (tail === "Raw" && rootVar === "Html" && taintedArg) {
    emit(ctx, "xss", node, sourceExpr, text);
  } else if (tail === "Write" && rootVar === "Response" && taintedArg) {
    emit(ctx, "xss", node, sourceExpr, text);
  } else if (tail === "Content" && taintedArg) {
    // ControllerBase.Content(html, contentType) -- ASP.NET Core's
    // return-raw-HTML helper. Bare call (no rootVar prefix beyond
    // "Content" itself), tainted-arg-gated like every sink here; the
    // common real shape is a concatenated HTML string, already resolved
    // by isTainted's recursive binary_expression walk.
    emit(ctx, "xss", node, sourceExpr, text);
  } else if ((tail === "GetAsync" || tail === "PostAsync" || tail === "PutAsync" || tail === "DeleteAsync" || tail === "SendAsync"
              || tail === "GetStringAsync" || tail === "GetByteArrayAsync" || tail === "GetStreamAsync"
              || tail === "PostAsJsonAsync" || tail === "PutAsJsonAsync") && taintedArg) {
    emit(ctx, "ssrf", node, sourceExpr, text);
  } else if (tail === "Combine" && rootVar === "Path" && taintedArg) {
    emit(ctx, "path-traversal", node, sourceExpr, text);
  } else if (FS_PATH_ROOTS.has(rootVar) && ["ReadAllText", "WriteAllText", "Open", "Create", "Delete", "ReadAllBytes", "WriteAllBytes"].includes(tail) && taintedArg) {
    emit(ctx, "path-traversal", node, sourceExpr, text);
  } else if (tail === "PhysicalFile" && taintedArg) {
    // ControllerBase.PhysicalFile(path, contentType) -- ASP.NET Core's
    // file-serving helper, a distinct sink shape from the System.IO.File/
    // Path static-class checks above (this is an instance-method call
    // with no meaningful rootVar of its own).
    emit(ctx, "path-traversal", node, sourceExpr, text);
  } else if (tail === "Deserialize" && taintedArg) {
    emit(ctx, "insecure-deserialization", node, sourceExpr, text);
  } else if ((tail === "Redirect" || tail === "RedirectPermanent") && taintedArg) {
    emit(ctx, "open-redirect", node, sourceExpr, text);
  } else if ((tail === "Compile" && rootVar === "XPathExpression") || (tail === "SelectNodes" || tail === "SelectSingleNode")) {
    if (taintedArg) emit(ctx, "xpath-injection", node, sourceExpr, text);
  } else if (/ldap/i.test(rootVar) && /^(?:Search|FindOne|FindAll)$/i.test(tail) && taintedArg) {
    // Call-shaped LDAP sink -- a custom helper (LdapHelper.Search(filter),
    // Ldap.FindOne(...)), distinct from the DirectorySearcher.Filter
    // property-assignment shape handled structurally in
    // walkForDeclarationsAndSinks below. Real System.DirectoryServices
    // code has no fixed "Search" method name to allowlist exactly, so
    // this is a rootVar-name heuristic (same reasoning as the BOLA
    // lookup-name broadening below) rather than a class allowlist.
    emit(ctx, "ldap-injection", node, sourceExpr, text);
  }
}

/** `new ClassName(taintedArg)` -- the constructor-call-itself-is-the-sink
 * shape, mirroring astTaintGo.ts's checkNewExpressionSink. */
function checkNewExpressionSink(node: SyntaxNode, env: Env, ctx: EngineCtx, isTainted: (n: SyntaxNode, e: Env) => boolean) {
  const typeNode = node.childForFieldName("type");
  const className = typeNode?.type === "identifier" ? typeNode.text : null;
  if (!className) return;
  const args = argListOfCSharp(node);
  const taintedArg = args.find(a => isTainted(a, env));
  if (!taintedArg) return;
  if (className === "ProcessStartInfo") emit(ctx, "command-injection", node, taintedArg.text, "new ProcessStartInfo");
}

// ── Statement-level walk (declarations + assignments + sink-visiting) ────

function walkForDeclarationsAndSinks(node: SyntaxNode, env: Env, ctx: EngineCtx) {
  const isTainted = makeIsTaintedCSharp(ctx);

  if (node.type === "local_declaration_statement") {
    const varDecl = node.namedChildren.find(c => c && c.type === "variable_declaration");
    const typeNode = varDecl?.childForFieldName("type");
    const declaredTypeSimpleName = typeNode && typeNode.type === "identifier" ? typeNode.text : undefined;
    for (const declarator of varDecl?.namedChildren.filter(c => c && c.type === "variable_declarator") ?? []) {
      if (!declarator) continue;
      const nameTok = declarator.namedChildren.find(c => c && c.type === "identifier");
      if (!nameTok) continue;
      const equalsClause = declarator.namedChildren.find(c => c && c.type === "equals_value_clause");
      const initExpr = equalsClause?.namedChildren[0];
      const tainted = initExpr ? isTainted(initExpr, env) : false;
      env.set(nameTok.text, tainted);
      // `var cmd = new SqlCommand(sql);` -- declaredTypeSimpleName is
      // undefined for `var` (implicit_type), so the receiver-typed sink
      // check (SqlCommand.ExecuteReader) needs the type inferred from the
      // initializer's own constructor instead, when there is one.
      const inferredTypeName = declaredTypeSimpleName
        ?? (initExpr?.type === "object_creation_expression" ? initExpr.childForFieldName("type")?.text : undefined);
      if (inferredTypeName) ctx.varTypes.set(nameTok.text, inferredTypeName);
    }
  }

  // Assignment: `x = expr;` or `obj.Field = expr;`. Restricted to the
  // plain `=` operator only (not `+=`/`-=`/etc) -- a compound assignment
  // would need env.get(key) OR'd into the new value to stay additive-only,
  // which isn't implemented here; left unhandled (falls through to the
  // generic recursion below) rather than risk incorrectly de-tainting an
  // already-tainted target.
  if (node.type === "assignment_expression") {
    const opNode = node.namedChildren.find(c => c && c.type === "assignment_operator");
    if (opNode?.text === "=") {
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      const tainted = right ? isTainted(right, env) : false;
      if (left?.type === "identifier") {
        env.set(left.text, tainted);
      } else if (left?.type === "member_access_expression") {
        const key = calleeTextCSharp(left);
        if (key) {
          env.set(key, tainted);
          // Structural sink: `xxx.Filter = tainted` (System.DirectoryServices
          // DirectorySearcher.Filter) -- an assignment-target-IS-the-sink
          // shape, since the vulnerable API here is a property setter, not
          // a method call.
          if (key.endsWith(".Filter") && tainted) emit(ctx, "ldap-injection", node, right!.text, key);
        }
      }
    }
  }

  if (node.type === "invocation_expression") {
    const fn = node.childForFieldName("function");
    const args = argListOfCSharp(node);
    if (fn) {
      checkCallSink(fn, args, node, env, ctx, isTainted);
      if (fn.type === "identifier" && ctx.localMethods.has(fn.text)) {
        seedLocalMethodParams(fn.text, args, env, ctx);
      }
    }
  }
  if (node.type === "object_creation_expression") {
    checkNewExpressionSink(node, env, ctx, isTainted);
  }

  for (const child of node.namedChildren) {
    if (child) walkForDeclarationsAndSinks(child, env, ctx);
  }
}

// ── BOLA: sink shapes, ownership-comparison detection, per-method emission ──

const BOLA_LOOKUP_METHODS = new Set(["Find", "FirstOrDefault", "SingleOrDefault", "First", "Single", "QueryFirstOrDefault", "QuerySingleOrDefault"]);
const BOLA_WRITE_METHODS = new Set(["Remove", "Delete", "Update"]);
// Real-world repo/service classes (Database.GetUserById, UserRepo.FindById,
// ...) vary far more than EF/Dapper's fixed vocabulary above -- same
// reasoning already used for PHP's BOLA detector (name-convention
// heuristic, since a fixed allowlist can't cover every custom data-access
// class). Kept SEPARATE from the exact sets above (not merged in) so the
// exact-match sets stay the higher-precision, always-checked-first path.
const BOLA_LOOKUP_NAME_RE = /^Get\w*By(?:Id|Guid)?$/i;
const BOLA_WRITE_NAME_RE = /^(?:Delete|Remove|Update)\w*$/i;
const PRINCIPAL_NAME_RE = /^(?:User|HttpContext\.User)(?:\.|$)/;

interface BolaSinkCandidate { node: SyntaxNode; sourceExpr: string; sinkExpr: string }

function isPrincipalShaped(text: string): boolean {
  return PRINCIPAL_NAME_RE.test(text);
}

function checkBolaSinkCandidate(
  fn: SyntaxNode, args: SyntaxNode[], node: SyntaxNode, resourceIdParamNames: Set<string>, candidates: BolaSinkCandidate[],
) {
  const text = calleeTextCSharp(fn);
  if (!text || args.length === 0) return;
  const tail = text.split(".").pop() ?? text;
  const isKnownLookup = BOLA_LOOKUP_METHODS.has(tail) || BOLA_WRITE_METHODS.has(tail);
  const isNamedLookup = BOLA_LOOKUP_NAME_RE.test(tail) || BOLA_WRITE_NAME_RE.test(tail);
  if (!isKnownLookup && !isNamedLookup) return;
  const arg0 = args[0];
  const argIds = findAllNodes(arg0, "identifier").map(n => n.text);
  if (argIds.some(id => resourceIdParamNames.has(id))) {
    candidates.push({ node, sourceExpr: arg0.text, sinkExpr: text });
  }
}

/** `new ClassName(id)` -- reuses argReferencesResourceId-equivalent logic
 * directly inline (single-hop, arg is a bare resource-id identifier). */
function checkBolaConstructorSinkCandidate(node: SyntaxNode, resourceIdParamNames: Set<string>, candidates: BolaSinkCandidate[]) {
  const typeNode = node.childForFieldName("type");
  const className = typeNode?.type === "identifier" ? typeNode.text : null;
  if (!className) return;
  const args = argListOfCSharp(node);
  if (args.length === 0) return;
  const argIds = findAllNodes(args[0], "identifier").map(n => n.text);
  if (argIds.some(id => resourceIdParamNames.has(id))) {
    candidates.push({ node, sourceExpr: args[0].text, sinkExpr: `new ${className}` });
  }
}

function comparisonSuppresses(leftNode: SyntaxNode, rightNode: SyntaxNode, resourceIdParamNames: Set<string>): boolean {
  const lIds = new Set(findAllNodes(leftNode, "identifier").map(n => n.text));
  const rIds = new Set(findAllNodes(rightNode, "identifier").map(n => n.text));
  const lIsRes = [...lIds].some(id => resourceIdParamNames.has(id));
  const rIsRes = [...rIds].some(id => resourceIdParamNames.has(id));
  const lIsPrin = isPrincipalShaped(leftNode.text);
  const rIsPrin = isPrincipalShaped(rightNode.text);
  return (lIsRes && rIsPrin) || (lIsPrin && rIsRes);
}

/**
 * Per-method post-check, not per-call-site -- mirrors astTaintJava.ts's
 * collectBolaFindings exactly: candidate sinks are collected but not
 * emitted until a full body walk confirms no suppressing ownership
 * comparison exists anywhere in the method. Purely structural (no env/
 * taint), same posture as Java's version and the same documented,
 * accepted gap (an inverted `if (!x.Equals(y))` guard still incorrectly
 * suppresses -- branch/CFG-aware analysis is out of scope, see this
 * module's own docblock).
 */
function collectBolaFindings(method: LocalMethod, ctx: EngineCtx) {
  if (!method.body) return;
  if (!method.authMeta.isEndpoint) return;
  if (method.authMeta.suppressedByAuthAnnotation) return;
  if (method.resourceIdParamNames.size === 0) return;

  const candidates: BolaSinkCandidate[] = [];
  let hasOwnershipComparison = false;

  for (const inv of findAllNodes(method.body, "invocation_expression")) {
    const fn = inv.childForFieldName("function");
    if (!fn) continue;
    const args = argListOfCSharp(inv);
    checkBolaSinkCandidate(fn, args, inv, method.resourceIdParamNames, candidates);
    const tail = calleeTextCSharp(fn)?.split(".").pop();
    if (tail === "Equals" && args[0]) {
      const receiver = fn.type === "member_access_expression" ? fn.childForFieldName("expression") : null;
      if (receiver && comparisonSuppresses(receiver, args[0], method.resourceIdParamNames)) hasOwnershipComparison = true;
    }
  }
  for (const oc of findAllNodes(method.body, "object_creation_expression")) {
    checkBolaConstructorSinkCandidate(oc, method.resourceIdParamNames, candidates);
  }
  for (const bin of findAllNodes(method.body, "binary_expression")) {
    const op = bin.childForFieldName("operator")?.type;
    if (op !== "==" && op !== "!=") continue;
    const left = bin.childForFieldName("left");
    const right = bin.childForFieldName("right");
    if (left && right && comparisonSuppresses(left, right, method.resourceIdParamNames)) hasOwnershipComparison = true;
  }

  if (!hasOwnershipComparison) {
    const severity: "medium" | "high" = method.authMeta.verbTier === "read" ? "medium" : "high";
    for (const c of candidates) emit(ctx, "bola-missing-ownership-check", c.node, c.sourceExpr, c.sinkExpr, severity);
  }
}

// ── Entry point ──────────────────────────────────────────────────────────

export function scanAstTaintCSharp(content: string, filePath: string, root: SyntaxNode): AstTaintCSharpFinding[] {
  try {
    const lines = content.split("\n");
    const localMethods = collectLocalMethods(root);
    const ctx: EngineCtx = {
      content, lines, localMethods, propagatingParams: new Map(), seededParams: new Map(),
      varTypes: new Map(), findings: [], seen: new Set(),
    };

    const propagating = buildPropagatingMapCSharp(localMethods, ctx);
    for (const [name, idx] of propagating) ctx.propagatingParams.set(name, idx);

    for (const [, method] of localMethods) {
      if (!method.body) continue;
      const env: Env = new Map();
      method.sourceParamNames.forEach(p => env.set(p, true));
      walkForDeclarationsAndSinks(method.body, env, ctx);
      collectBolaFindings(method, ctx);
    }

    // Second pass, bounded worklist -- see astTaintJava.ts's/astTaint.ts's
    // own identical worklist for the full reasoning (multi-hop convergence,
    // explicitly capped, not an accidental side effect of Map iteration).
    const walkedSignatures = new Set<string>();
    for (let round = 0; round < MAX_PROPAGATION_ROUNDS; round++) {
      const toWalk = Array.from(ctx.seededParams.entries());
      let changed = false;
      for (const [methodName, idxSet] of toWalk) {
        const method = localMethods.get(methodName);
        if (!method?.body) continue;
        const signature = `${methodName}:${[...idxSet].sort((a, b) => a - b).join(",")}`;
        if (walkedSignatures.has(signature)) continue;
        walkedSignatures.add(signature);
        changed = true;
        const env: Env = new Map();
        for (const idx of idxSet) {
          const shape = method.paramShapes[idx];
          if (shape) env.set(shape.name, true);
        }
        walkForDeclarationsAndSinks(method.body, env, ctx);
      }
      if (!changed) break;
    }

    void filePath;
    return ctx.findings;
  } catch (err) {
    console.error(`[astTaintCSharp] threw scanning ${filePath}:`, err);
    return [];
  }
}

export function astTaintCSharpSeverity(id: AstTaintCSharpId): "critical" | "high" | "medium" {
  return SEVERITY[id];
}
export function astTaintCSharpLabel(id: AstTaintCSharpId): string {
  return LABEL[id];
}
