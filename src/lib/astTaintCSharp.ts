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
import {
  ALL, applyClears, applyGuards, classOf, cloneEnv, walkIfChain, walkLoop, walkSwitch, walkTry, wasCleared,
  type Branch, type Guard, type SuppressedSink, type TaintEnv,
} from "./taint/taintCore";
import { sanitizerClears, NUMERIC_CLEARS } from "./taint/sanitizers";

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
  if (node.type === "identifier" || node.type === "predefined_type") return node.text;
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
// Now lives in taint/sanitizers.ts, keyed by the sink classes each one
// actually neutralizes (HtmlEncode clears XSS, not SQL/command/path); the
// bare `Encode` tail is receiver-aware there (only the web encoders count).
// Numeric CASTS -- `(int)x` -- are modeled in makeTaintMaskCSharp below.
const CSHARP_NUMERIC_CAST_TYPES = new Set([
  "int", "long", "short", "byte", "sbyte", "uint", "ulong", "ushort", "double", "float", "decimal", "bool",
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

type Env = TaintEnv;
// method name -> (param index -> sink classes that survive to its return value)
type PropagatingCS = Map<string, Map<number, number>>;
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
  propagatingParams: PropagatingCS;
  // method name -> (tainted param index -> classes tainted at the call site)
  seededParams: Map<string, Map<number, number>>;
  varTypes: VarTypes;
  // File root -- lets guards resolve a literal-collection identifier declared elsewhere in the file.
  root?: SyntaxNode;
  findings: AstTaintCSharpFinding[];
  seen: Set<string>;
  // Sinks whose argument was tainted for the sink's class but positively
  // cleared by a sanitizer (see astTaint.ts) -- lets scanner.ts drop the
  // regex layer's duplicate for a flow this engine proved safe.
  suppressed?: SuppressedSink[];
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

type TaintMaskFnCS = (node: SyntaxNode, env: Env) => number;

function makeTaintMaskCSharp(ctx: EngineCtx): TaintMaskFnCS {
  const taintMask = (node: SyntaxNode, env: Env): number => {
    if (isTaintSourceExprCSharp(node)) return ALL;
    if (node.type === "identifier") return env.get(node.text) ?? 0;
    if (node.type === "argument" || node.type === "parenthesized_expression" || node.type === "interpolation") {
      const inner = node.namedChildren[0];
      return inner ? taintMask(inner, env) : 0;
    }
    if (node.type === "cast_expression") {
      // (int)x / (long)x / (bool)x -- a numeric cast neutralizes every
      // injection class (was silently taint-PRESERVING through the generic
      // fallback while int.Parse(x) cleared, an inconsistency within this
      // one engine). Any other cast ((string)x, (MyType)x) passes through.
      const typeNode = node.childForFieldName("type") ?? node.namedChildren[0];
      const valueNode = node.childForFieldName("value") ?? node.namedChildren[node.namedChildren.length - 1];
      const inner = valueNode ? taintMask(valueNode, env) : 0;
      return typeNode && CSHARP_NUMERIC_CAST_TYPES.has(typeNode.text) ? applyClears(inner, NUMERIC_CLEARS) : inner;
    }
    if (node.type === "binary_expression") {
      const op = node.childForFieldName("operator")?.type;
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if ((op === "+" || op === "??") && left && right) return taintMask(left, env) | taintMask(right, env);
      return 0;
    }
    if (node.type === "conditional_expression") {
      // the condition steers control, it does not flow into the value
      const cons = node.childForFieldName("consequence");
      const alt = node.childForFieldName("alternative");
      return (cons ? taintMask(cons, env) : 0) | (alt ? taintMask(alt, env) : 0);
    }
    if (node.type === "switch_expression") {
      // value = union of the arm results; the subject is not part of the value
      let m = 0;
      for (const arm of node.namedChildren) {
        if (arm?.type !== "switch_expression_arm") continue;
        const result = arm.namedChildren[arm.namedChildren.length - 1];
        if (result) m |= taintMask(result, env);
      }
      return m;
    }
    if (node.type === "member_access_expression") {
      // Field-sensitive read: OR the full dotted path composite key (set by
      // the assignment write-side below) with the root/operand's own mask --
      // pure recall gain, never removes a class the fallback alone finds.
      const path = calleeTextCSharp(node);
      const expr = node.childForFieldName("expression");
      return (path ? (env.get(path) ?? 0) : 0) | (expr ? taintMask(expr, env) : 0);
    }
    if (node.type === "element_access_expression") {
      const expr = node.childForFieldName("expression") ?? node.namedChildren[0];
      return expr ? taintMask(expr, env) : 0;
    }
    if (node.type === "object_creation_expression") {
      // A constructor call is tainted if ANY of its arguments are --
      // deliberately the baseline rule from the start (unlike astTaintGo.ts,
      // which needed a later correction pass for the http.NewRequest
      // two-step pattern specifically because it lacked this as a default).
      return argListOfCSharp(node).reduce((m, a) => m | taintMask(a, env), 0);
    }
    if (node.type === "invocation_expression") {
      const fn = node.childForFieldName("function");
      const args = argListOfCSharp(node);
      const text = fn ? calleeTextCSharp(fn) : null;
      // Known sanitizer: the argument's taint passes THROUGH minus only the
      // classes it neutralizes. Checked BEFORE the propagating-fn/passthrough
      // checks below, so a sanitized value can't be re-tainted by one of
      // them in this same call.
      const calleeName = text ?? (fn?.type === "identifier" ? fn.text : null);
      if (calleeName) {
        const clears = sanitizerClears("cs", calleeName, args.map(a => a.text));
        if (clears !== null) return args[0] ? applyClears(taintMask(args[0], env), clears) : 0;
      }
      // Same-file interprocedural, bounded (see buildPropagatingMapCSharp).
      if (fn?.type === "identifier") {
        const propIdx = ctx.propagatingParams.get(fn.text);
        if (propIdx) {
          const callee = ctx.localMethods.get(fn.text);
          const shapes = callee?.paramShapes ?? [];
          let m = 0;
          for (const [i, surviving] of propIdx) {
            if (shapes[i] !== undefined && args[i] !== undefined) m |= taintMask(args[i], env) & surviving;
          }
          if (m) return m;
        }
      }
      // Generic passthrough: a method call on an already-tainted receiver
      // stays tainted (e.g. dirty.Trim(), dirty.ToLower()).
      if (fn?.type === "member_access_expression") {
        const expr = fn.childForFieldName("expression");
        if (expr) return taintMask(expr, env);
      }
      return 0;
    }
    // Generic fallback -- recurse into every named child and OR-combine.
    // Confirmed directly (via probing interpolated strings) that this alone
    // correctly reaches an interpolation's inner expression without any
    // interpolated_string_expression-specific case.
    let m = 0;
    for (const child of node.namedChildren) if (child) m |= taintMask(child, env);
    return m;
  };
  return taintMask;
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
function computeReturnTaintPropagatingCSharp(method: LocalMethod, ctx: EngineCtx): Map<number, number> {
  // param index -> sink classes that still survive to the return value
  const propagatingIdx = new Map<number, number>();
  if (!method.body) return propagatingIdx;
  for (const shape of method.paramShapes) {
    let surviving = 0;
    // Path-sensitive: the mask is taken at EACH return with the env on that
    // path; a return inside a lambda / local function is not this method's.
    // Sink checks would run against a throwaway ctx, so use a sink-free copy.
    const walker = createWalkerCS({ ...ctx, findings: [], seen: new Set(), suppressed: undefined, seededParams: new Map() },
      { descendFunctions: false, onReturn: (expr, env, mask) => { surviving |= mask(expr, env); } });
    const env: Env = new Map();
    env.set(shape.name, ALL);
    walker.walk(method.body, env);
    // Low bits only: the shadow half is per-scan bookkeeping, not a summary.
    surviving &= ALL;
    if (surviving) propagatingIdx.set(shape.index, surviving);
  }
  return propagatingIdx;
}

const MAX_PROPAGATION_ROUNDS = 3;

function buildPropagatingMapCSharp(localMethods: Map<string, LocalMethod>, baseCtx: EngineCtx): PropagatingCS {
  const propagating: PropagatingCS = new Map();
  for (let round = 0; round < MAX_PROPAGATION_ROUNDS; round++) {
    let changed = false;
    const roundCtx: EngineCtx = { ...baseCtx, propagatingParams: propagating };
    for (const [name, method] of localMethods) {
      const found = computeReturnTaintPropagatingCSharp(method, roundCtx);
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

/** Seeds ctx.seededParams from a call site whose arguments are tainted --
 * consumed by scanAstTaintCSharp's bounded second pass so a sink INSIDE a
 * local method's own body (not just its return) becomes reachable. */
function seedLocalMethodParams(calleeName: string, args: SyntaxNode[], env: Env, ctx: EngineCtx) {
  const callee = ctx.localMethods.get(calleeName);
  if (!callee) return;
  const taintMask = makeTaintMaskCSharp(ctx);
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
  fn: SyntaxNode, args: SyntaxNode[], node: SyntaxNode, env: Env, ctx: EngineCtx, taintMask: TaintMaskFnCS,
) {
  const text = calleeTextCSharp(fn);
  if (!text) return;
  const parts = text.split(".");
  const tail = parts[parts.length - 1];
  const rootVar = parts[0];
  const argMasks = args.map(a => taintMask(a, env));
  const combined = argMasks.reduce((m, x) => m | x, 0);
  const firstIdx = argMasks.findIndex(m => (m & ALL) !== 0);
  const sourceExpr = firstIdx >= 0 ? args[firstIdx].text : text;
  // Each sink is gated on ITS OWN class (an HtmlEncode no longer hides a
  // SQL/command/path sink); a value tainted-then-positively-cleared for the
  // sink's class records a suppression instead (regex-layer veto).
  const fire = (id: AstTaintCSharpId, mask: number = combined, source: string = sourceExpr) => {
    const cls = classOf(id);
    if (mask & cls) emit(ctx, id, node, source, text);
    else if (wasCleared(mask, cls)) ctx.suppressed?.push({ id, line: lineOf(node) });
  };

  // sql-injection: EF Core raw-SQL calls (arg-tainted) and ADO.NET
  // SqlCommand receiver-tainted (tracked via env at the SqlCommand-typed
  // local declaration site, mirroring astTaintJava.ts's ObjectInputStream
  // readObject pattern).
  if (tail === "FromSqlRaw" || tail === "ExecuteSqlRaw") {
    fire("sql-injection");
  } else if ((tail === "ExecuteReader" || tail === "ExecuteNonQuery" || tail === "ExecuteScalar")
             && ctx.varTypes.get(rootVar) === "SqlCommand") {
    fire("sql-injection", env.get(rootVar) ?? 0, rootVar);
  } else if (tail === "Start" && rootVar === "Process") {
    fire("command-injection");
  } else if (tail === "Raw" && rootVar === "Html") {
    fire("xss");
  } else if (tail === "Write" && rootVar === "Response") {
    fire("xss");
  } else if (tail === "Content") {
    // ControllerBase.Content(html, contentType) -- ASP.NET Core's
    // return-raw-HTML helper. Bare call (no rootVar prefix beyond
    // "Content" itself); the common real shape is a concatenated HTML
    // string, already resolved by taintMask's recursive binary_expression walk.
    fire("xss");
  } else if (tail === "GetAsync" || tail === "PostAsync" || tail === "PutAsync" || tail === "DeleteAsync" || tail === "SendAsync"
             || tail === "GetStringAsync" || tail === "GetByteArrayAsync" || tail === "GetStreamAsync"
             || tail === "PostAsJsonAsync" || tail === "PutAsJsonAsync") {
    fire("ssrf");
  } else if (tail === "Combine" && rootVar === "Path") {
    fire("path-traversal");
  } else if (FS_PATH_ROOTS.has(rootVar) && ["ReadAllText", "WriteAllText", "Open", "Create", "Delete", "ReadAllBytes", "WriteAllBytes"].includes(tail)) {
    fire("path-traversal");
  } else if (tail === "PhysicalFile") {
    // ControllerBase.PhysicalFile(path, contentType) -- ASP.NET Core's
    // file-serving helper, a distinct sink shape from the System.IO.File/
    // Path static-class checks above (an instance-method call with no
    // meaningful rootVar of its own).
    fire("path-traversal");
  } else if (tail === "Deserialize") {
    fire("insecure-deserialization");
  } else if (tail === "Redirect" || tail === "RedirectPermanent") {
    fire("open-redirect");
  } else if ((tail === "Compile" && rootVar === "XPathExpression") || (tail === "SelectNodes" || tail === "SelectSingleNode")) {
    fire("xpath-injection");
  } else if (/ldap/i.test(rootVar) && /^(?:Search|FindOne|FindAll)$/i.test(tail)) {
    // Call-shaped LDAP sink -- a custom helper (LdapHelper.Search(filter),
    // Ldap.FindOne(...)), distinct from the DirectorySearcher.Filter
    // property-assignment shape handled structurally in
    // walkForDeclarationsAndSinks below. Real System.DirectoryServices
    // code has no fixed "Search" method name to allowlist exactly, so
    // this is a rootVar-name heuristic (same reasoning as the BOLA
    // lookup-name broadening below) rather than a class allowlist.
    fire("ldap-injection");
  }
}

/** `new ClassName(taintedArg)` -- the constructor-call-itself-is-the-sink
 * shape, mirroring astTaintGo.ts's checkNewExpressionSink. */
function checkNewExpressionSink(node: SyntaxNode, env: Env, ctx: EngineCtx, taintMask: TaintMaskFnCS) {
  const typeNode = node.childForFieldName("type");
  const className = typeNode?.type === "identifier" ? typeNode.text : null;
  if (!className) return;
  const args = argListOfCSharp(node);
  const argMasks = args.map(a => taintMask(a, env));
  // Any bit (taint OR shadow) counts so a tainted-then-sanitized value
  // still reaches the suppression record below.
  const firstIdx = argMasks.findIndex(m => m !== 0);
  if (firstIdx < 0) return;
  const combined = argMasks.reduce((m, x) => m | x, 0);
  if (className === "ProcessStartInfo") {
    const cls = classOf("command-injection");
    if (combined & cls) emit(ctx, "command-injection", node, args[firstIdx].text, "new ProcessStartInfo");
    else if (wasCleared(combined, cls)) ctx.suppressed?.push({ id: "command-injection", line: lineOf(node) });
  }
}

// ── Narrow validation guards ────────────────────────────────────────────────
// Same policy as every other engine: only unambiguous proofs that a bare
// identifier is safe -- literal equality, membership in a literal collection,
// strict numeric parses (`int.TryParse`), strict numeric type tests (`x is
// int`), literal patterns (`x is "a" or "b"`). NOT recognized: regex matches,
// prefix checks, custom validators.

const STRICT_PARSE_TYPES_CS = new Set([
  "int", "long", "short", "byte", "sbyte", "uint", "ulong", "ushort", "double", "float", "decimal", "bool",
  "Int16", "Int32", "Int64", "UInt16", "UInt32", "UInt64", "Double", "Single", "Decimal", "Boolean", "Byte", "SByte", "Guid",
]);

function isLiteralCS(n: SyntaxNode): boolean {
  if (n.type === "parenthesized_expression") return !!n.namedChildren[0] && isLiteralCS(n.namedChildren[0]);
  return [
    "string_literal", "verbatim_string_literal", "raw_string_literal", "integer_literal", "real_literal",
    "character_literal", "boolean_literal",
  ].includes(n.type);
}

/** An initializer_expression whose every element is a literal. */
function isLiteralInitializerCS(n: SyntaxNode | null | undefined): boolean {
  if (!n || n.type !== "initializer_expression") return false;
  const els = n.namedChildren.filter((c): c is SyntaxNode => !!c);
  return els.length > 0 && els.every(isLiteralCS);
}

/** `new[] {"a","b"}`, `new string[] {...}`, `new List<string> {...}`, `new HashSet<string>(new[]{...})`,
 * `{ "a", "b" }` (field initializer), C# 12 `["a","b"]`, or an identifier EVERY binding of which,
 * file-wide, is such a literal (a name that is ever rebound to something else is not trusted). */
function isLiteralCollectionCS(n: SyntaxNode, root: SyntaxNode | undefined, depth = 0): boolean {
  switch (n.type) {
    case "initializer_expression":
      return isLiteralInitializerCS(n);
    case "collection_expression": {
      const els = n.namedChildren.filter((c): c is SyntaxNode => !!c);
      return els.length > 0 && els.every(isLiteralCS);
    }
    case "implicit_array_creation_expression":
    case "array_creation_expression":
      return isLiteralInitializerCS(n.namedChildren.find(c => c?.type === "initializer_expression"));
    case "object_creation_expression": {
      const init = n.namedChildren.find(c => c?.type === "initializer_expression");
      if (init) return isLiteralInitializerCS(init);
      const args = argListOfCSharp(n);
      return args.length === 1 && isLiteralCollectionCS(args[0], root, depth + 1);
    }
    case "identifier": {
      if (!root || depth > 0) return false;
      const bindings: SyntaxNode[] = [];
      let opaque = false;
      const visit = (x: SyntaxNode) => {
        if (x.type === "variable_declarator") {
          const name = x.namedChildren.find(c => c?.type === "identifier");
          if (name?.text === n.text) {
            const init = x.namedChildren.find(c => c?.type === "equals_value_clause")?.namedChildren[0];
            if (init) bindings.push(init); else opaque = true;
          }
        } else if (x.type === "assignment_expression") {
          const left = x.childForFieldName("left");
          if (left?.type === "identifier" && left.text === n.text) opaque = true; // rebound after declaration
        }
        for (const c of x.namedChildren) if (c) visit(c);
      };
      visit(root);
      return !opaque && bindings.length > 0 && bindings.every(b => isLiteralCollectionCS(b, root, depth + 1));
    }
    default:
      return false;
  }
}

/** `"a"`, `"a" or "b"`, `("a" or "b")` -- a pattern made only of literal constants. */
function isLiteralPatternCS(p: SyntaxNode): boolean {
  if (p.type === "constant_pattern") return !!p.namedChildren[0] && isLiteralCS(p.namedChildren[0]);
  if (p.type === "or_pattern") {
    const parts = p.namedChildren.filter((c): c is SyntaxNode => !!c);
    return parts.length > 0 && parts.every(isLiteralPatternCS);
  }
  if (p.type === "parenthesized_pattern") return !!p.namedChildren[0] && isLiteralPatternCS(p.namedChildren[0]);
  return false;
}

function invertCS(g: Guard): Guard {
  return { name: g.name, holds: g.holds === "true" ? "false" : "true" };
}

function guardsOfConditionCS(cond: SyntaxNode, root: SyntaxNode | undefined): Guard[] {
  switch (cond.type) {
    case "parenthesized_expression": {
      const inner = cond.namedChildren[0];
      return inner ? guardsOfConditionCS(inner, root) : [];
    }
    case "prefix_unary_expression": {
      if (cond.child(0)?.type !== "!") return [];
      const inner = cond.namedChildren[0];
      return inner ? guardsOfConditionCS(inner, root).map(invertCS) : [];
    }
    case "binary_expression": {
      const op = cond.childForFieldName("operator")?.type;
      const l = cond.childForFieldName("left");
      const r = cond.childForFieldName("right");
      if (!l || !r) return [];
      if (op === "&&") return [...guardsOfConditionCS(l, root), ...guardsOfConditionCS(r, root)].filter(g => g.holds === "true");
      if (op === "||") return [...guardsOfConditionCS(l, root), ...guardsOfConditionCS(r, root)].filter(g => g.holds === "false");
      if (op === "==" || op === "!=") {
        const holdsWhenEqual: "true" | "false" = op === "==" ? "true" : "false";
        if (l.type === "identifier" && isLiteralCS(r)) return [{ name: l.text, holds: holdsWhenEqual }];
        if (r.type === "identifier" && isLiteralCS(l)) return [{ name: r.text, holds: holdsWhenEqual }];
      }
      return [];
    }
    case "is_expression": {
      // `x is int` -- strict type test
      const l = cond.childForFieldName("left") ?? cond.namedChildren[0];
      const r = cond.childForFieldName("right") ?? cond.namedChildren[1];
      if (l?.type === "identifier" && r && CSHARP_NUMERIC_CAST_TYPES.has(r.text)) return [{ name: l.text, holds: "true" }];
      return [];
    }
    case "is_pattern_expression": {
      const l = cond.childForFieldName("expression") ?? cond.namedChildren[0];
      const p = cond.childForFieldName("pattern") ?? cond.namedChildren[1];
      if (l?.type !== "identifier" || !p) return [];
      if (p.type === "declaration_pattern") {
        const t = p.childForFieldName("type") ?? p.namedChildren[0];
        if (t && CSHARP_NUMERIC_CAST_TYPES.has(t.text)) return [{ name: l.text, holds: "true" }];
      }
      if (isLiteralPatternCS(p)) return [{ name: l.text, holds: "true" }];
      return [];
    }
    case "invocation_expression": {
      const fn = cond.childForFieldName("function");
      if (fn?.type !== "member_access_expression") return [];
      const recv = fn.childForFieldName("expression");
      const name = fn.childForFieldName("name")?.text;
      const args = argListOfCSharp(cond);
      if (!recv || !name) return [];
      // int.TryParse(x, out ...) -- x parses as a number
      if (name === "TryParse" && STRICT_PARSE_TYPES_CS.has(recv.text) && args[0]?.type === "identifier") {
        return [{ name: args[0].text, holds: "true" }];
      }
      // ALLOWED.Contains(x) / new[] {"a"}.Contains(x)
      if (name === "Contains" && args.length === 1 && args[0].type === "identifier" && isLiteralCollectionCS(recv, root)) {
        return [{ name: args[0].text, holds: "true" }];
      }
      if (name === "Equals") {
        // x.Equals("lit") / "lit".Equals(x) / string.Equals(x, "lit")
        if (args.length === 1) {
          if (recv.type === "identifier" && isLiteralCS(args[0])) return [{ name: recv.text, holds: "true" }];
          if (isLiteralCS(recv) && args[0].type === "identifier") return [{ name: args[0].text, holds: "true" }];
        }
        if (args.length === 2 && (recv.text === "string" || recv.text === "String")) {
          if (args[0].type === "identifier" && isLiteralCS(args[1])) return [{ name: args[0].text, holds: "true" }];
          if (isLiteralCS(args[0]) && args[1].type === "identifier") return [{ name: args[1].text, holds: "true" }];
        }
      }
      return [];
    }
    default:
      return [];
  }
}

// ── Path-sensitive statement walk ───────────────────────────────────────────
// One walker serves the interprocedural summary builder (no nested functions,
// collects return masks) and the main scan (sink checks, lambdas/local
// functions walked on a cloned env). Branches walk each arm on a CLONE of the
// env and join with may-taint OR (shared combinators in taint/taintCore.ts);
// an arm ending in return/throw is dropped from the join, and code after a
// terminating statement is dead and not walked.

interface WalkOptsCS {
  /** Walk lambda / local-function / anonymous-method bodies (main scan) or ignore them (summaries). */
  descendFunctions: boolean;
  /** Called for each `return expr`, with the env on that path. */
  onReturn?: (expr: SyntaxNode, env: Env, taintMask: TaintMaskFnCS) => void;
}

function statementTerminatesCS(n: SyntaxNode | null | undefined): boolean {
  if (!n) return false;
  if (n.type === "return_statement" || n.type === "throw_statement") return true;
  if (n.type === "block") return n.namedChildren.some(c => statementTerminatesCS(c));
  if (n.type === "if_statement") {
    const alt = n.childForFieldName("alternative");
    return !!alt && statementTerminatesCS(n.childForFieldName("consequence")) && statementTerminatesCS(alt);
  }
  return false;
}

/** Parameter names a lambda / local function / anonymous method introduces. */
function paramNamesOfCS(fn: SyntaxNode): string[] {
  const names: string[] = [];
  const body = fn.childForFieldName("body");
  const fromList = (list: SyntaxNode) => {
    for (const p of list.namedChildren) {
      if (!p) continue;
      if (p.type === "identifier") names.push(p.text);
      else if (p.type === "parameter") { const nm = p.childForFieldName("name"); if (nm) names.push(nm.text); }
    }
  };
  const params = fn.childForFieldName("parameters");
  if (params) fromList(params);
  for (const c of fn.namedChildren) {
    if (!c || c.id === body?.id || c.id === params?.id) continue;
    if (c.type === "identifier") names.push(c.text);          // x => ...
    else if (c.type === "parameter_list") fromList(c);
    else if (c.type === "parameter") { const nm = c.childForFieldName("name"); if (nm) names.push(nm.text); }
  }
  return names;
}

const FUNCTION_NODES_CS = new Set(["lambda_expression", "anonymous_method_expression", "local_function_statement"]);
const SEQUENCE_STATEMENTS_CS = new Set(["using_statement", "lock_statement", "fixed_statement", "checked_statement", "unsafe_statement"]);
const SWITCH_LABELS_CS = new Set(["case_switch_label", "default_switch_label", "case_pattern_switch_label"]);

function createWalkerCS(ctx: EngineCtx, opts: WalkOptsCS) {
  const taintMask = makeTaintMaskCSharp(ctx);
  const root = ctx.root;

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
    for (const p of paramNamesOfCS(fn)) fenv.set(p, 0);
    walk(body, fenv);
  };

  const walk = (node: SyntaxNode, env: Env): boolean => {
    switch (node.type) {
      case "lambda_expression":
      case "anonymous_method_expression":
      case "local_function_statement":
        if (opts.descendFunctions) walkFunction(node, env);
        return false;

      case "block":
        return walkStmts(node.namedChildren, env);

      case "if_statement": {
        const branches: Branch[] = [];
        let cur: SyntaxNode | null = node;
        while (cur && cur.type === "if_statement") {
          const cond = cur.childForFieldName("condition");
          const cons = cur.childForFieldName("consequence");
          branches.push({
            visitCond: (e) => { if (cond) walk(cond, e); },
            guards: () => (cond ? guardsOfConditionCS(cond, root) : []),
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

      case "conditional_expression": {
        // `c ? a : b` -- arms are walked on cloned envs with the condition's guards
        const cond = node.childForFieldName("condition");
        const cons = node.childForFieldName("consequence");
        const alt = node.childForFieldName("alternative");
        walkIfChain(env, [
          {
            visitCond: (e) => { if (cond) walk(cond, e); },
            guards: () => (cond ? guardsOfConditionCS(cond, root) : []),
            body: (e) => { if (cons) walk(cons, e); return false; },
          },
          { body: (e) => { if (alt) walk(alt, e); return false; } },
        ]);
        return false;
      }

      case "for_statement": {
        for (const i of node.childrenForFieldName("initializer")) if (i) walk(i, env);
        const cond = node.childForFieldName("condition");
        if (cond) walk(cond, env);
        const body = node.childForFieldName("body");
        const updates = node.childrenForFieldName("update");
        return walkLoop(env, (e) => {
          const t = body ? walk(body, e) : false;
          if (!t) for (const u of updates) if (u) walk(u, e);
          return t;
        });
      }

      case "for_each_statement": {
        const right = node.childForFieldName("right");
        if (right) walk(right, env);
        const rmask = right ? taintMask(right, env) : 0;
        const left = node.childForFieldName("left");
        const names = left ? (left.type === "identifier" ? [left] : findAllNodes(left, "identifier")) : [];
        for (const n of names) env.set(n.text, rmask);
        const body = node.childForFieldName("body");
        return walkLoop(env, (e) => (body ? walk(body, e) : false));
      }

      case "while_statement": {
        const named = node.namedChildren.filter((c): c is SyntaxNode => !!c);
        const cond = node.childForFieldName("condition") ?? named[0] ?? null;
        const body = node.childForFieldName("body") ?? named[named.length - 1] ?? null;
        if (cond && cond.id !== body?.id) walk(cond, env);
        return walkLoop(env, (e) => (body ? walk(body, e) : false));
      }

      case "do_statement": {
        const named = node.namedChildren.filter((c): c is SyntaxNode => !!c);
        const body = node.childForFieldName("body") ?? named[0] ?? null;
        const cond = node.childForFieldName("condition") ?? named[named.length - 1] ?? null;
        const term = walkLoop(env, (e) => (body ? walk(body, e) : false));
        if (cond && cond.id !== body?.id) walk(cond, env);
        return term;
      }

      case "try_statement": {
        const body = node.childForFieldName("body");
        const finallyC = node.namedChildren.find(c => c?.type === "finally_clause");
        const catches = node.namedChildren
          .filter(c => c?.type === "catch_clause")
          .map(c => {
            const decl = c!.namedChildren.find(x => x?.type === "catch_declaration");
            const nm = decl?.childForFieldName("name");
            const cbody = c!.childForFieldName("body");
            return { bind: nm ? [nm.text] : [], body: (e: Env) => (cbody ? walk(cbody, e) : false) };
          });
        return walkTry(
          env,
          (e) => (body ? walk(body, e) : false),
          catches,
          finallyC ? (e) => { const fb = finallyC.namedChildren.find(x => x?.type === "block"); return fb ? walk(fb, e) : false; } : undefined,
        );
      }

      case "switch_statement": {
        const value = node.childForFieldName("value");
        if (value) walk(value, env);
        const subject = value?.type === "identifier" ? value.text : null;
        const sections = (node.childForFieldName("body") ?? node).namedChildren.filter(c => c?.type === "switch_section");
        return walkSwitch(env, sections.map(sec => {
          const labels = sec!.namedChildren.filter((c): c is SyntaxNode => !!c && SWITCH_LABELS_CS.has(c.type));
          const stmts = sec!.namedChildren.filter(c => !!c && !SWITCH_LABELS_CS.has(c.type));
          return {
            isDefault: labels.some(l => l.type === "default_switch_label"),
            // `case "a": case "b":` -- inside, the subject IS one of the literals.
            pre: (e: Env) => {
              if (subject && labels.length > 0 && labels.every(l => l.type === "case_switch_label" && !!l.namedChildren[0] && isLiteralCS(l.namedChildren[0]))) {
                applyGuards(e, [subject]);
              }
            },
            body: (e: Env) => walkStmts(stmts, e),
          };
        }));
      }

      case "return_statement": {
        for (const c of node.namedChildren) if (c) walk(c, env);
        const v = node.namedChildren[0];
        if (v) opts.onReturn?.(v, env, taintMask);
        return true;
      }

      case "throw_statement":
        for (const c of node.namedChildren) if (c) walk(c, env);
        return true;

      default:
        break;
    }

    // using / lock / ...: a sequence of a header and a body -- terminates when its body does
    if (SEQUENCE_STATEMENTS_CS.has(node.type)) return walkStmts(node.namedChildren, env);

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
        env.set(nameTok.text, initExpr ? taintMask(initExpr, env) : 0);
        // `var cmd = new SqlCommand(sql);` -- declaredTypeSimpleName is
        // undefined for `var` (implicit_type), so the receiver-typed sink
        // check (SqlCommand.ExecuteReader) needs the type inferred from the
        // initializer's own constructor instead, when there is one.
        const inferredTypeName = declaredTypeSimpleName
          ?? (initExpr?.type === "object_creation_expression" ? initExpr.childForFieldName("type")?.text : undefined);
        if (inferredTypeName) ctx.varTypes.set(nameTok.text, inferredTypeName);
      }
    }

    // Assignment: `x = expr;`, `x += expr;`, `x ??= expr;`, `obj.Field = expr;`.
    // A compound operator keeps whatever taint the target already had (OR).
    if (node.type === "assignment_expression") {
      const opNode = node.namedChildren.find(c => c && c.type === "assignment_operator");
      const compound = !!opNode && opNode.text !== "=";
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      const rhs = right ? taintMask(right, env) : 0;
      const put = (key: string): number => {
        const mask = compound ? rhs | (env.get(key) ?? 0) : rhs;
        env.set(key, mask);
        return mask;
      };
      if (left?.type === "identifier") {
        put(left.text);
      } else if (left?.type === "member_access_expression") {
        const key = calleeTextCSharp(left);
        if (key) {
          const mask = put(key);
          // Structural sink: `xxx.Filter = tainted` (System.DirectoryServices
          // DirectorySearcher.Filter) -- an assignment-target-IS-the-sink
          // shape, since the vulnerable API here is a property setter, not
          // a method call.
          if (key.endsWith(".Filter")) {
            const cls = classOf("ldap-injection");
            if (mask & cls) emit(ctx, "ldap-injection", node, right!.text, key);
            else if (wasCleared(mask, cls)) ctx.suppressed?.push({ id: "ldap-injection", line: lineOf(node) });
          }
        }
      }
    }

    if (node.type === "invocation_expression") {
      const fn = node.childForFieldName("function");
      const args = argListOfCSharp(node);
      if (fn) {
        checkCallSink(fn, args, node, env, ctx, taintMask);
        if (fn.type === "identifier" && ctx.localMethods.has(fn.text)) {
          seedLocalMethodParams(fn.text, args, env, ctx);
        }
      }
    }
    if (node.type === "object_creation_expression") {
      checkNewExpressionSink(node, env, ctx, taintMask);
    }

    for (const child of node.namedChildren) if (child) walk(child, env);
    return false;
  };

  return { walk, taintMask };
}

/** Main-scan entry: walks one method body (or seeded re-walk) with sink checks and call-site seeding. */
function walkForDeclarationsAndSinks(node: SyntaxNode, env: Env, ctx: EngineCtx) {
  createWalkerCS(ctx, { descendFunctions: true }).walk(node, env);
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

interface BolaSinkCandidate { node: SyntaxNode; sourceExpr: string; sinkExpr: string; idNames: Set<string> }

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
  const idNames = new Set(findAllNodes(arg0, "identifier").map(n => n.text).filter(id => resourceIdParamNames.has(id)));
  if (idNames.size > 0) candidates.push({ node, sourceExpr: arg0.text, sinkExpr: text, idNames });
}

/** `new ClassName(id)` -- reuses argReferencesResourceId-equivalent logic
 * directly inline (single-hop, arg is a bare resource-id identifier). */
function checkBolaConstructorSinkCandidate(node: SyntaxNode, resourceIdParamNames: Set<string>, candidates: BolaSinkCandidate[]) {
  const typeNode = node.childForFieldName("type");
  const className = typeNode?.type === "identifier" ? typeNode.text : null;
  if (!className) return;
  const args = argListOfCSharp(node);
  if (args.length === 0) return;
  const idNames = new Set(findAllNodes(args[0], "identifier").map(n => n.text).filter(id => resourceIdParamNames.has(id)));
  if (idNames.size > 0) candidates.push({ node, sourceExpr: args[0].text, sinkExpr: `new ${className}`, idNames });
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

type SideCS = "true" | "false";

/** Which side(s) of `cond` establish that a resource id in `ids` equals the
 * authenticated principal (`==` holds on the true side, `!=` on the false
 * side; `!`/`&&`/`||` compose like validation guards do). An identifier
 * condition (`isOwner`) resolves ONE hop to its last preceding declaration
 * or assignment. */
function ownershipSidesCS(cond: SyntaxNode, ids: Set<string>, body: SyntaxNode, resolve = true): SideCS[] {
  const flip = (s: SideCS): SideCS => (s === "true" ? "false" : "true");
  switch (cond.type) {
    case "parenthesized_expression": {
      const inner = cond.namedChildren[0];
      return inner ? ownershipSidesCS(inner, ids, body, resolve) : [];
    }
    case "prefix_unary_expression": {
      if (cond.child(0)?.type !== "!") return [];
      const inner = cond.namedChildren[0];
      return inner ? ownershipSidesCS(inner, ids, body, resolve).map(flip) : [];
    }
    case "binary_expression": {
      const op = cond.childForFieldName("operator")?.type;
      const l = cond.childForFieldName("left");
      const r = cond.childForFieldName("right");
      if (!l || !r) return [];
      if (op === "==" || op === "!=") return comparisonSuppresses(l, r, ids) ? [op === "==" ? "true" : "false"] : [];
      if (op === "&&") return [...ownershipSidesCS(l, ids, body, resolve), ...ownershipSidesCS(r, ids, body, resolve)].filter(s => s === "true");
      if (op === "||") return [...ownershipSidesCS(l, ids, body, resolve), ...ownershipSidesCS(r, ids, body, resolve)].filter(s => s === "false");
      return [];
    }
    case "invocation_expression": {
      const fn = cond.childForFieldName("function");
      const args = argListOfCSharp(cond);
      if (fn?.type === "member_access_expression" && fn.childForFieldName("name")?.text === "Equals") {
        const receiver = fn.childForFieldName("expression");
        if (args.length === 1 && receiver && comparisonSuppresses(receiver, args[0], ids)) return ["true"];
        // string.Equals(a, b) / object.Equals(a, b)
        if (args.length === 2 && comparisonSuppresses(args[0], args[1], ids)) return ["true"];
      }
      return [];
    }
    case "identifier": {
      if (!resolve) return [];
      let best: { end: number; expr: SyntaxNode } | null = null;
      const consider = (end: number, expr: SyntaxNode | null | undefined) => {
        if (expr && end <= cond.startIndex && (!best || end > best.end)) best = { end, expr };
      };
      const visit = (n: SyntaxNode) => {
        if (n.type === "variable_declarator") {
          const name = n.namedChildren.find(c => c?.type === "identifier");
          if (name?.text === cond.text) consider(n.endIndex, n.namedChildren.find(c => c?.type === "equals_value_clause")?.namedChildren[0]);
        } else if (n.type === "assignment_expression") {
          const left = n.childForFieldName("left");
          if (left?.type === "identifier" && left.text === cond.text) consider(n.endIndex, n.childForFieldName("right"));
        }
        for (const c of n.namedChildren) if (c) visit(c);
      };
      visit(body);
      const found = best as { end: number; expr: SyntaxNode } | null;
      return found ? ownershipSidesCS(found.expr, ids, body, false) : [];
    }
    default:
      return [];
  }
}

/**
 * Does an ownership comparison DOMINATE `sink`? It must (a) sit in an if
 * condition (or a ternary condition) that precedes the sink in source order
 * and (b) put the sink on the continuing path: the sink is in the arm where
 * the comparison establishes ownership, or the arm where it does not always
 * terminates (return/throw) and the sink comes after the whole if. A
 * comparison that is unused, follows the lookup, or guards a different branch
 * no longer suppresses.
 */
function ownershipDominatesCS(sink: SyntaxNode, ids: Set<string>, body: SyntaxNode): boolean {
  const contains = (outer: SyntaxNode | null, inner: SyntaxNode) =>
    !!outer && outer.startIndex <= inner.startIndex && inner.endIndex <= outer.endIndex;
  let found = false;
  const visit = (n: SyntaxNode) => {
    if (found) return;
    if (n.type === "if_statement" || n.type === "conditional_expression") {
      const cond = n.childForFieldName("condition");
      const cons = n.childForFieldName("consequence");
      const alt = n.childForFieldName("alternative");
      if (cond && cond.endIndex <= sink.startIndex) {
        const sides = ownershipSidesCS(cond, ids, body);
        const afterIf = n.type === "if_statement" && sink.startIndex >= n.endIndex && contains(n.parent, sink);
        if (sides.includes("true") && (contains(cons, sink) || (afterIf && statementTerminatesCS(alt)))) found = true;
        if (sides.includes("false") && (contains(alt, sink) || (afterIf && statementTerminatesCS(cons)))) found = true;
      }
    }
    if (!found) for (const c of n.namedChildren) if (c) visit(c);
  };
  visit(body);
  return found;
}

/**
 * Per-method post-check, not per-call-site -- mirrors astTaintJava.ts's
 * collectBolaFindings: candidate sinks are collected during the body walk and
 * each is emitted unless an ownership comparison for ITS resource id
 * dominates it (see ownershipDominatesCS) -- not merely "a comparison exists
 * somewhere in the method". Purely structural (no env/taint).
 */
function collectBolaFindings(method: LocalMethod, ctx: EngineCtx) {
  if (!method.body) return;
  if (!method.authMeta.isEndpoint) return;
  if (method.authMeta.suppressedByAuthAnnotation) return;
  if (method.resourceIdParamNames.size === 0) return;

  const candidates: BolaSinkCandidate[] = [];
  for (const inv of findAllNodes(method.body, "invocation_expression")) {
    const fn = inv.childForFieldName("function");
    if (!fn) continue;
    checkBolaSinkCandidate(fn, argListOfCSharp(inv), inv, method.resourceIdParamNames, candidates);
  }
  for (const oc of findAllNodes(method.body, "object_creation_expression")) {
    checkBolaConstructorSinkCandidate(oc, method.resourceIdParamNames, candidates);
  }

  const severity: "medium" | "high" = method.authMeta.verbTier === "read" ? "medium" : "high";
  for (const c of candidates) {
    if (ownershipDominatesCS(c.node, c.idNames, method.body)) continue;
    emit(ctx, "bola-missing-ownership-check", c.node, c.sourceExpr, c.sinkExpr, severity);
  }
}

// ── Entry point ──────────────────────────────────────────────────────────

export function scanAstTaintCSharp(
  content: string, filePath: string, root: SyntaxNode,
  // Sinks whose argument was tainted for the sink's class but positively
  // cleared by a sanitizer -- see EngineCtx.suppressed.
  suppressedOut?: SuppressedSink[],
): AstTaintCSharpFinding[] {
  try {
    const lines = content.split("\n");
    const localMethods = collectLocalMethods(root);
    const ctx: EngineCtx = {
      content, lines, localMethods, propagatingParams: new Map(), seededParams: new Map(),
      varTypes: new Map(), root, findings: [], seen: new Set(), suppressed: suppressedOut,
    };

    const propagating = buildPropagatingMapCSharp(localMethods, ctx);
    for (const [name, idx] of propagating) ctx.propagatingParams.set(name, idx);

    for (const [, method] of localMethods) {
      if (!method.body) continue;
      const env: Env = new Map();
      method.sourceParamNames.forEach(p => env.set(p, ALL));
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
        const signature = `${methodName}:${[...idxSet].sort((a, b) => a[0] - b[0]).map(([i, m]) => `${i}=${m}`).join(",")}`;
        if (walkedSignatures.has(signature)) continue;
        walkedSignatures.add(signature);
        changed = true;
        const env: Env = new Map();
        for (const [idx, m] of idxSet) {
          const shape = method.paramShapes[idx];
          if (shape) env.set(shape.name, m);
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
