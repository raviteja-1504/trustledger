/**
 * Real AST-based taint engine for JavaScript/TypeScript — Phase 1 of the
 * multi-language OWASP Top 10 hardening effort.
 *
 * Every other detector in scanner.ts operates on regex over individual
 * lines. That works well for single-line code but has a structural blind
 * spot: any statement wrapped across multiple lines (common in Java, not
 * rare in JS/TS either) defeats a same-line pattern outright, since no
 * single line ever contains both the taint source/concatenation and the
 * dangerous sink call. A real parser has no concept of a line break at all,
 * so this problem disappears by construction rather than needing another
 * regex special-case per formatting style.
 *
 * Deliberately uses only `ts.createSourceFile` (a pure syntactic parse) --
 * never `ts.createProgram`/a TypeChecker, which requires binding/resolving
 * a whole project's module graph and is where real TypeScript-compiler cost
 * explodes. A syntax-only parse is fast: comparable to, or cheaper than,
 * the cumulative cost of the ~40 existing per-line regex passes already run
 * against every file.
 *
 * Runs ADDITIVELY alongside the existing JS/TS named-taint regex functions
 * in scanner.ts, not as a replacement -- see the integration point in
 * analyzeFile() for the reasoning. Reuses every existing finding id
 * (sql-injection, command-injection, xss, ssrf, path-traversal,
 * open-redirect, eval-exec), so no new UI wiring is needed anywhere.
 */

import * as ts from "typescript";
import {
  ALL, applyClears, classOf, isTaintedMask, wasCleared, type SuppressedSink, type TaintEnv,
} from "./taint/taintCore";
import { sanitizerClears } from "./taint/sanitizers";

export type AstTaintId =
  | "sql-injection" | "command-injection" | "xss" | "ssrf" | "path-traversal" | "open-redirect" | "eval-exec";

export interface AstTaintFinding {
  id:         AstTaintId;
  line:       number;
  detail:     string;
  sourceExpr: string;
  sinkExpr:   string;
}

function scriptKindFor(filePath: string): ts.ScriptKind {
  const ext = filePath.split(".").pop()?.toLowerCase();
  if (ext === "tsx") return ts.ScriptKind.TSX;
  if (ext === "ts")  return ts.ScriptKind.TS;
  if (ext === "jsx") return ts.ScriptKind.JSX;
  return ts.ScriptKind.JS;
}

export function parseSourceFile(content: string, filePath: string): ts.SourceFile {
  return ts.createSourceFile(
    filePath, content, ts.ScriptTarget.Latest,
    /* setParentNodes */ true, // required: enclosing-function lookup walks node.parent
    scriptKindFor(filePath),
  );
}

// ── Node-at-position / enclosing-function lookup (shared with reachability.ts) ──

/** Deepest AST node whose source range contains `pos`. */
export function findNodeAtPosition(root: ts.Node, pos: number): ts.Node {
  let found = root;
  const visit = (node: ts.Node) => {
    if (pos >= node.getFullStart() && pos < node.getEnd()) {
      found = node;
      ts.forEachChild(node, visit);
    }
  };
  ts.forEachChild(root, visit);
  return found;
}

/**
 * Walks up to the nearest named function/method/const-arrow declaration.
 * Must produce the SAME naming convention as callGraph.ts's regex-based
 * tryMatchFunc() (bare function/const-arrow name, no class qualification) --
 * reachability.ts looks names up against a CallGraphResult built by that
 * extractor, so any divergence here silently breaks the lookup again in a
 * different way than the bug it's meant to fix. See astTaint.test.ts for the
 * explicit cross-check.
 */
export function findEnclosingFunctionName(node: ts.Node): string {
  let cur: ts.Node | undefined = node;
  while (cur) {
    if (ts.isFunctionDeclaration(cur) && cur.name) return cur.name.text;
    if (ts.isMethodDeclaration(cur) && ts.isIdentifier(cur.name)) return cur.name.text;
    if (
      (ts.isArrowFunction(cur) || ts.isFunctionExpression(cur)) &&
      cur.parent && ts.isVariableDeclaration(cur.parent) && ts.isIdentifier(cur.parent.name)
    ) return cur.parent.name.text;
    cur = cur.parent;
  }
  return "unknown";
}

// ── Taint sources ────────────────────────────────────────────────────────────

const SOURCE_ROOTS = new Set(["req", "request"]);
const SOURCE_PROPS = new Set(["query", "body", "params", "headers", "cookies"]);

function isTaintSourceExpr(node: ts.Expression): boolean {
  if (ts.isPropertyAccessExpression(node)) {
    if (ts.isIdentifier(node.expression) && SOURCE_ROOTS.has(node.expression.text) && SOURCE_PROPS.has(node.name.text)) {
      return true;
    }
    return isTaintSourceExpr(node.expression);
  }
  if (ts.isElementAccessExpression(node)) return isTaintSourceExpr(node.expression);
  return false;
}

// ── Sink dispatch table ──────────────────────────────────────────────────────

// Sanitizers live in taint/sanitizers.ts, keyed by the sink classes each one
// actually neutralizes (an HTML escaper clears XSS, not SQL/command/path).
// The common `const clean = sanitize(dirty); sink(clean)` pattern works
// because assignment re-evaluates the initializer's mask fresh; a sticky
// in-place mutation site (the tainted-receiver passthrough in
// makeTaintMask) is still not retroactively cleaned -- a documented,
// accepted narrower gap.

const CMD_SINK_NAMES = new Set(["exec", "execSync", "spawn", "spawnSync"]);
const FS_SINK_NAMES = new Set([
  "readFile", "readFileSync", "writeFile", "writeFileSync",
  "createReadStream", "createWriteStream", "unlink", "unlinkSync", "stat", "statSync",
]);
const HTTP_SINK_NAMES = new Set(["get", "post", "put", "delete", "patch", "request"]);
const DB_SINK_METHODS = new Set(["query", "execute", "run", "prepare"]);

interface SinkMatch { id: AstTaintId; sinkExpr: string; args: readonly ts.Expression[] }

/** Resolves bare identifiers imported via `import { exec } from "child_process"` etc. */
function buildImportMap(sourceFile: ts.SourceFile): Map<string, string> {
  const map = new Map<string, string>();
  ts.forEachChild(sourceFile, node => {
    if (!ts.isImportDeclaration(node) || !ts.isStringLiteral(node.moduleSpecifier)) return;
    const moduleName = node.moduleSpecifier.text;
    const clause = node.importClause;
    if (!clause) return;
    if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
      for (const spec of clause.namedBindings.elements) map.set(spec.name.text, moduleName);
    }
    if (clause.name) map.set(clause.name.text, moduleName); // default import
  });
  return map;
}

export interface ImportBinding { localName: string; importedName: string; moduleSpecifier: string }

/**
 * Like buildImportMap, but keeps the (local name, original exported name)
 * pair instead of collapsing straight to just the module specifier --
 * needed for cross-file resolution to correctly handle
 * `import { buildQuery as bq } from "./db"`: the callee file's export-taint
 * summary is keyed by the ORIGINAL exported name ("buildQuery"), but this
 * file's own code calls it as `bq(...)` -- the local binding. buildImportMap
 * alone can't answer both "what module is this from" and "what was its
 * original exported name" at once, which is why this is a separate
 * function rather than a change to that one (which stays as-is for its own
 * existing sink-module-recognition purpose).
 *
 * Deliberately does not resolve `import * as ns from "./mod"` (a namespace
 * import) -- calls through it (`ns.foo(...)`) are property-access
 * expressions, which makeIsTainted's call-resolution branch (bare
 * identifiers only) doesn't match anyway; scoped out consistently with
 * that existing limitation, not a new one.
 */
export function buildImportBindings(sourceFile: ts.SourceFile): ImportBinding[] {
  const out: ImportBinding[] = [];
  ts.forEachChild(sourceFile, node => {
    if (!ts.isImportDeclaration(node) || !ts.isStringLiteral(node.moduleSpecifier)) return;
    const moduleSpecifier = node.moduleSpecifier.text;
    const clause = node.importClause;
    if (!clause) return;
    if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
      for (const spec of clause.namedBindings.elements) {
        out.push({ localName: spec.name.text, importedName: (spec.propertyName ?? spec.name).text, moduleSpecifier });
      }
    }
    if (clause.name) out.push({ localName: clause.name.text, importedName: "default", moduleSpecifier });
  });
  return out;
}

function calleeText(expr: ts.Expression): string | null {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) {
    const base = calleeText(expr.expression);
    return base ? `${base}.${expr.name.text}` : null;
  }
  return null;
}

function matchSink(call: ts.CallExpression, importMap: Map<string, string>): SinkMatch | null {
  const callee = call.expression;
  const text = calleeText(callee);
  if (!text) return null;
  const parts = text.split(".");
  const head = parts[0];
  const tail = parts[parts.length - 1];
  const resolvedModule = importMap.get(head);

  // eval / new Function is handled separately (NewExpression), this only
  // covers the bare eval(...) call form.
  if (text === "eval") return { id: "eval-exec", sinkExpr: text, args: call.arguments };

  if (CMD_SINK_NAMES.has(tail) && (resolvedModule === "child_process" || parts.length > 1 || CMD_SINK_NAMES.has(text))) {
    return { id: "command-injection", sinkExpr: text, args: call.arguments };
  }
  if (text === "res.send" || text === "res.write" || text === "res.end" || text === "document.write") {
    return { id: "xss", sinkExpr: text, args: call.arguments };
  }
  if (
    text === "fetch" || text.startsWith("axios") ||
    ((text === "http.get" || text === "http.request" || text === "https.get" || text === "https.request") ) ||
    (resolvedModule === "http" || resolvedModule === "https") && HTTP_SINK_NAMES.has(tail)
  ) {
    return { id: "ssrf", sinkExpr: text, args: call.arguments };
  }
  if (parts[0] === "fs" && FS_SINK_NAMES.has(tail)) {
    return { id: "path-traversal", sinkExpr: text, args: call.arguments };
  }
  if (parts[0] === "path" && (tail === "join" || tail === "resolve")) {
    return { id: "path-traversal", sinkExpr: text, args: call.arguments };
  }
  if (text === "res.redirect") {
    return { id: "open-redirect", sinkExpr: text, args: call.arguments };
  }
  if (parts.length > 1 && DB_SINK_METHODS.has(tail)) {
    return { id: "sql-injection", sinkExpr: text, args: call.arguments };
  }
  return null;
}

// ── Taint environment / propagation ──────────────────────────────────────────

type Env = TaintEnv;

/**
 * Builds the core taint evaluator as a closure over `propagating` so every
 * call site (there are several, scattered through the statement walk below)
 * doesn't need to thread an extra parameter through by hand. `propagating`
 * maps a function's CALL-SITE NAME (a local function's bare name, OR --
 * since this same map also carries cross-file entries, see
 * computeExportTaintSummary/scanAstTaint's crossFilePropagating merge --
 * the local name a cross-file import is bound to) directly to its
 * propagating ParamShape[] (not just indices -- storing the shapes
 * themselves, rather than indices that would need a second `localFns`
 * lookup to resolve, is what lets a cross-file entry work through this
 * exact map with zero special-casing: a cross-file imported name has no
 * LocalFn entry to look shapes up from at all). This is what makes
 * `exec(buildCommand(host))` resolve correctly whether buildCommand is
 * declared in this same file or imported from another one in the same scan
 * batch: buildCommand never calls a sink itself, it just returns a tainted
 * template literal, so without this the call expression
 * `buildCommand(host)` would look untainted from the outside. Per-parameter
 * (not per-function) so a call like `buildLog(safeId, taintedMessage)` where
 * only `userId` -- not `message` -- flows into buildLog's return does NOT
 * fire, even though buildLog is "propagating" for its userId parameter.
 */
function makeTaintMask(propagating: Map<string, ParamShape[]>) {
  const taintMask = (expr: ts.Expression, env: Env): number => {
    if (ts.isParenthesizedExpression(expr)) return taintMask(expr.expression, env);
    if (isTaintSourceExpr(expr)) return ALL;
    if (ts.isIdentifier(expr)) return env.get(expr.text) ?? 0;
    if (ts.isPropertyAccessExpression(expr)) {
      // Field-sensitive read: OR the composite "root.field" key (set by
      // applyDeclAndAssign's field-write branch below) with the root-object
      // mask -- pure recall gain, this can only ever ADD classes the old
      // root-collapse behavior would have missed, never remove one already
      // found that way.
      const path = calleeText(expr);
      return (path ? (env.get(path) ?? 0) : 0) | taintMask(expr.expression, env);
    }
    if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return taintMask(expr.left, env) | taintMask(expr.right, env);
    }
    if (ts.isTemplateExpression(expr)) return expr.templateSpans.reduce((m, s) => m | taintMask(s.expression, env), 0);
    if (ts.isSpreadElement(expr)) return taintMask(expr.expression, env);
    if (ts.isArrayLiteralExpression(expr)) return expr.elements.reduce((m, e) => m | taintMask(e, env), 0);
    if (ts.isObjectLiteralExpression(expr)) {
      return expr.properties.reduce((m, p) => (ts.isPropertyAssignment(p) ? m | taintMask(p.initializer, env) : m), 0);
    }
    if (ts.isCallExpression(expr)) {
      // Known sanitizer: the argument's taint passes THROUGH minus only the
      // classes this sanitizer actually neutralizes (an HTML escaper leaves
      // SQL/command/path taint intact). Opaque calls stay untainted below.
      const calleeName = calleeText(expr.expression);
      if (calleeName) {
        const clears = sanitizerClears("js", calleeName);
        if (clears !== null) return expr.arguments[0] ? applyClears(taintMask(expr.arguments[0], env), clears) : 0;
      }
      // A call to a local (or cross-file-imported) function known to
      // propagate taint from SPECIFIC params to its return value -- e.g.
      // buildCommand(host) where buildCommand(h) { return `ping -c1 ${h}`; }.
      // Only the arguments at the propagating indices are checked, and only
      // the classes that survive the callee's own body (shape.mask) count.
      if (ts.isIdentifier(expr.expression)) {
        const shapes = propagating.get(expr.expression.text);
        if (shapes) {
          let m = 0;
          for (const shape of shapes) {
            for (const a of argsForShape(expr.arguments, shape)) m |= taintMask(a, env) & (shape.mask ?? ALL);
          }
          if (m) return m;
        }
      }
      // Passthrough for a method call on an already-tainted receiver
      // (.trim()/.toLowerCase()/.toString()/etc.) -- same "propagate through
      // anything referencing a tainted value" recall bias already
      // established in extractTaintedVars' second-hop rule (scanner.ts),
      // not a claim that every such method is unsafe on its own.
      if (ts.isPropertyAccessExpression(expr.expression)) return taintMask(expr.expression.expression, env);
    }
    if (ts.isAsExpression(expr) || ts.isNonNullExpression(expr)) return taintMask(expr.expression, env);
    return 0;
  };
  return taintMask;
}

type TaintMaskFn = (e: ts.Expression, env: Env) => number;

interface LocalFn {
  params: ts.NodeArray<ts.ParameterDeclaration>;
  body: ts.Node;
  // Public names this function is exposed under (export function/const, or
  // an `export { local as public }` list entry) -- may be more than one
  // name, may be empty for a non-exported function. Used to build the
  // cross-file export-taint summary (computeExportTaintSummary below);
  // has no effect on same-file analysis.
  exportedNames: string[];
}

// `mask` (only set on entries of a `propagating` map, never on a bare
// parameter list) is the sink classes that still survive from this
// parameter to the function's return value; absent means ALL.
export interface ParamShape { name: string; index: number; isRest: boolean; mask?: number }

/** Which of `args` correspond to `shape`: exactly one arg for a fixed
 * param, every arg from `shape.index` onward for a rest param. */
function argsForShape<A>(args: readonly A[], shape: ParamShape): A[] {
  return shape.isRest ? args.slice(shape.index) : (args[shape.index] !== undefined ? [args[shape.index]] : []);
}

function paramShapesOf(fn: LocalFn): ParamShape[] {
  return fn.params
    .map((p, index) => ts.isIdentifier(p.name) ? { name: p.name.text, index, isRest: !!p.dotDotDotToken } : null)
    .filter((s): s is ParamShape => s !== null);
}

/**
 * Mutates `env` for the taint effect of ONE statement node's own local
 * variable declarations / simple reassignments (`x = expr`) -- does not do
 * sink checks, does not recurse into children (callers own that). Shared by
 * the main file walk (scanAstTaint's walkStatements, unchanged observable
 * behavior -- this is a pure extraction) and by envAfterBody below, which
 * needed the SAME logic to fix a real gap: computeReturnTaintPropagating
 * used to seed `env` with only the tested parameter, so a function that
 * assigns to a local before returning it (`const q = ...; return q;`, an
 * extremely common pattern -- query builders, sanitizer wrappers) was never
 * detected as propagating at all, since the return expression is a bare
 * identifier the old env never had a value for. Confirmed by direct trace
 * of the pre-fix code, not a hypothetical.
 */
function applyDeclAndAssign(node: ts.Node, env: Env, maskFn: TaintMaskFn): void {
  if (ts.isVariableStatement(node)) {
    for (const decl of node.declarationList.declarations) {
      if (!decl.initializer) continue;
      const mask = maskFn(decl.initializer, env);
      if (ts.isIdentifier(decl.name)) {
        env.set(decl.name.text, mask);
      } else if (ts.isObjectBindingPattern(decl.name) && isTaintedMask(mask)) {
        for (const el of decl.name.elements) {
          if (ts.isIdentifier(el.name)) env.set(el.name.text, mask);
        }
      }
    }
  } else if (
    ts.isExpressionStatement(node) && ts.isBinaryExpression(node.expression) &&
    node.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken
  ) {
    const { left, right } = node.expression;
    if (ts.isIdentifier(left)) {
      env.set(left.text, maskFn(right, env));
    } else if (ts.isPropertyAccessExpression(left)) {
      // Field-sensitive write: `obj.field = expr` -- stores under the same
      // composite "root.field" key the read side (makeTaintMask, above)
      // checks. Additive only: obj's own bare-identifier env entry (if any)
      // is left untouched, so a consumer that only ever checked obj before
      // this change sees exactly what it saw before.
      const path = calleeText(left);
      if (path) env.set(path, maskFn(right, env));
    }
  }
}

/**
 * Builds the env a function body would have right before its return(s),
 * given one seeded parameter -- a flat, non-lexically-scoped traversal (does
 * not stop at nested function/arrow boundaries; a pre-existing imprecision
 * shared with the rest of this engine, not a new one introduced here).
 * Calls inside the body stay opaque (isTaintedFn is the shallow,
 * empty-propagating evaluator), preserving computeReturnTaintPropagating's
 * documented non-recursive bound.
 */
function envAfterBody(body: ts.Node, seed: Env, maskFn: TaintMaskFn): Env {
  const env = new Map(seed);
  const visit = (n: ts.Node) => { applyDeclAndAssign(n, env, maskFn); ts.forEachChild(n, visit); };
  visit(body);
  return env;
}

/**
 * For each of `fn`'s parameters INDEPENDENTLY (seed only that one param
 * tainted, all others left untainted), does `fn`'s return value become
 * tainted? Returns the set of parameter INDICES whose taint actually
 * reaches the return -- not a single per-function boolean. This replaces an
 * earlier design that seeded ALL params tainted at once and recorded only
 * "this function propagates taint somehow," which meant a call site with
 * ANY tainted argument was treated as tainted regardless of which parameter
 * it bound to -- a real false-positive source (e.g. buildLog(userId,
 * message) only using userId in its return still fired on
 * buildLog(safeId, taintedMessage)).
 *
 * Testing each parameter independently is sound because the taint evaluator
 * (makeTaintMask) is purely OR-shaped per sink class -- every combinator is a
 * bitwise OR, and a sanitizer clears a FIXED set of classes regardless of
 * what else is tainted (`m & ~clears` distributes over OR) -- so seeding a
 * superset of params can only ever taint a superset of what seeding a subset
 * taints, class by class. No parameter whose own taint is independently
 * sufficient is missed, and no parameter is falsely required to co-occur
 * with another. The returned mask records which classes SURVIVE, so a
 * wrapper around an HTML escaper still propagates SQL/command taint.
 *
 * Nested calls inside `fn`'s own body are resolved using whatever
 * `maskFn` the caller passes in -- see buildPropagatingMap below,
 * which threads a bounded, round-capped view of the file's OWN in-progress
 * propagating map (never fully opaque, but never unbounded/recursive
 * either) rather than the always-empty map this function used to build
 * internally. Kept as an explicit parameter (not hardcoded here) so the
 * same function serves both the cheap cross-file Pass-1 summary (still
 * genuinely shallow, one file at a time) and the bounded same-file
 * fixed-point below.
 */
function computeReturnTaintPropagating(fn: LocalFn, maskFn: TaintMaskFn): Map<number, number> {
  // param index -> sink classes that still survive to the return value
  const propagatingIdx = new Map<number, number>();
  const returnExprs: ts.Expression[] = [];
  if (!ts.isBlock(fn.body)) {
    returnExprs.push(fn.body as ts.Expression); // arrow expression body
  } else {
    const collect = (n: ts.Node) => {
      if (ts.isReturnStatement(n) && n.expression) { returnExprs.push(n.expression); return; }
      ts.forEachChild(n, collect);
    };
    collect(fn.body);
  }
  for (const shape of paramShapesOf(fn)) {
    const seed: Env = new Map();
    seed.set(shape.name, ALL);
    const env = ts.isBlock(fn.body) ? envAfterBody(fn.body, seed, maskFn) : seed;
    // Only the low (still-dangerous) bits are a summary; the shadow half is
    // per-scan bookkeeping and must not leak into a stored/cross-file shape.
    const surviving = returnExprs.reduce((m, expr) => m | maskFn(expr, env), 0) & ALL;
    if (surviving) propagatingIdx.set(shape.index, surviving);
  }
  return propagatingIdx;
}

// Caps every bounded fixed-point loop below (same-file propagating-map
// convergence and the call-site-seeding worklist) -- named and shared for
// the same reason AST_TAINT_LINE_CAP is a named constant in scanner.ts:
// one clear knob, not a magic number repeated at each call site.
const MAX_PROPAGATION_ROUNDS = 3;

/**
 * Builds a same-file `propagating` map via a bounded fixed-point iteration
 * instead of one pass with every nested call opaque -- generalizes Java's
 * own already-accidental multi-hop convergence (via live Map iteration in
 * its call-site-seeding second pass) into an explicit, documented, capped
 * algorithm here too. Sound without extra cycle-breaking machinery because
 * propagation is monotonic: each round only ever ADDS propagating indices
 * (isTainted is purely OR-shaped, per computeReturnTaintPropagating's own
 * docblock), never removes one, and every function's index set is bounded
 * by its own parameter count -- so this always converges. The round cap
 * exists purely to bound worst-case cost on a large file's call graph, not
 * because convergence itself is ever in doubt.
 */
function buildPropagatingMap(localFns: Map<string, LocalFn>): Map<string, ParamShape[]> {
  const propagating = new Map<string, ParamShape[]>();
  for (let round = 0; round < MAX_PROPAGATION_ROUNDS; round++) {
    let changed = false;
    const maskRound = makeTaintMask(propagating);
    for (const [name, fn] of localFns) {
      const found = computeReturnTaintPropagating(fn, maskRound);
      // Monotonic merge: a round can only ADD parameters or ADD surviving
      // classes to an existing one, never remove -- the same convergence
      // guarantee the boolean version had (each per-class bit is monotone
      // under OR just as the single bit was).
      const merged = new Map<number, ParamShape>((propagating.get(name) ?? []).map(s => [s.index, s]));
      let grew = false;
      for (const shape of paramShapesOf(fn)) {
        const m = found.get(shape.index);
        if (!m) continue;
        const prev = merged.get(shape.index);
        const next = (prev?.mask ?? 0) | m;
        if (!prev || next !== (prev.mask ?? 0)) { merged.set(shape.index, { ...shape, mask: next }); grew = true; }
      }
      if (grew) {
        propagating.set(name, [...merged.values()].sort((a, b) => a.index - b.index));
        changed = true;
      }
    }
    if (!changed) break;
  }
  return propagating;
}

function sourceLabel(expr: ts.Expression): string {
  return expr.getText().replace(/\s+/g, " ").slice(0, 60);
}

/**
 * Real `export` detection, needed for the cross-file export-taint summary
 * (computeExportTaintSummary) -- has no bearing on same-file analysis.
 * Explicitly excludes `export default` (mods includes DefaultKeyword) since
 * a default export has no stable name a cross-file import binds to the same
 * way a named export does; that form is a deliberate, documented gap (see
 * computeExportTaintSummary's docblock), not a bug.
 */
function hasExportModifier(node: ts.Node): boolean {
  if (!ts.canHaveModifiers(node)) return false;
  const mods = ts.getModifiers(node);
  return !!mods?.some(m => m.kind === ts.SyntaxKind.ExportKeyword)
      && !mods?.some(m => m.kind === ts.SyntaxKind.DefaultKeyword);
}

function collectLocalFunctions(sourceFile: ts.SourceFile): Map<string, LocalFn> {
  const fns = new Map<string, LocalFn>();
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name && node.body) {
      const exportedNames = hasExportModifier(node) ? [node.name.text] : [];
      fns.set(node.name.text, { params: node.parameters, body: node.body, exportedNames });
    }
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const init = node.initializer;
      if ((ts.isArrowFunction(init) || ts.isFunctionExpression(init)) && init.body) {
        // The export modifier for `const x = () => {}` lives on the
        // enclosing VariableStatement (node.parent = VariableDeclarationList,
        // node.parent.parent = VariableStatement), NOT on this
        // VariableDeclaration node itself -- confirmed directly, not assumed.
        const stmt = node.parent?.parent;
        const exportedNames = stmt && ts.isVariableStatement(stmt) && hasExportModifier(stmt) ? [node.name.text] : [];
        fns.set(node.name.text, { params: init.parameters, body: init.body, exportedNames });
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sourceFile, visit);

  // `export { localName as publicName }` -- a named-export list for an
  // already-declared local function (common barrel-file style). Explicitly
  // scoped OUT: `export { x } from "./y"` (has a moduleSpecifier -- a
  // re-export, not a local declaration) and `export *`.
  ts.forEachChild(sourceFile, node => {
    if (!ts.isExportDeclaration(node) || node.moduleSpecifier || !node.exportClause) return;
    if (!ts.isNamedExports(node.exportClause)) return;
    for (const spec of node.exportClause.elements) {
      const localName = (spec.propertyName ?? spec.name).text;
      const publicName = spec.name.text;
      const fn = fns.get(localName);
      if (fn && !fn.exportedNames.includes(publicName)) fn.exportedNames.push(publicName);
    }
  });

  return fns;
}

/**
 * Cross-file taint analysis, Pass 1: a cheap sibling of scanAstTaint's full
 * walk, computed once per file in the scan batch BEFORE any file's real
 * (Pass 2) scan runs. Parses (or reuses a presparsed SourceFile), collects
 * local functions, and for each EXPORTED one computes its propagating
 * ParamShape[] via computeReturnTaintPropagating -- then stops. Skips
 * buildImportMap/matchSink/the full sink-walk/the seeded-param re-walk
 * entirely, since none of that is needed for a per-file summary; this is
 * intentionally much cheaper than a full scanAstTaint call.
 *
 * Explicitly deferred, not silently mishandled (see collectLocalFunctions'
 * export detection): `export default`, `export { x } from "./y"`
 * re-exports, `export *`, CommonJS (`module.exports.x = ...`). None of
 * these are ever added to a LocalFn's exportedNames, so they're simply
 * absent from this summary -- a false negative (a missed cross-file
 * detection), never a false positive.
 */
export function computeExportTaintSummary(
  content: string, filePath: string, presparsed?: ts.SourceFile,
): Map<string, ParamShape[]> {
  const summary = new Map<string, ParamShape[]>();
  try {
    const sourceFile = presparsed ?? parseSourceFile(content, filePath);
    const localFns = collectLocalFunctions(sourceFile);
    const propagating = buildPropagatingMap(localFns);
    for (const [fnName, fn] of localFns) {
      if (fn.exportedNames.length === 0) continue;
      const shapes = propagating.get(fnName);
      if (!shapes || shapes.length === 0) continue;
      for (const name of fn.exportedNames) summary.set(name, shapes);
    }
  } catch (err) {
    console.error(`[astTaint] threw computing export summary for ${filePath}:`, err);
  }
  return summary;
}

const SEVERITY: Record<AstTaintId, "critical" | "high" | "medium"> = {
  "sql-injection": "critical", "command-injection": "critical", "xss": "critical",
  "ssrf": "critical", "path-traversal": "critical", "eval-exec": "critical", "open-redirect": "medium",
};
const LABEL: Record<AstTaintId, string> = {
  "sql-injection": "SQL Injection", "command-injection": "Command Injection", "xss": "Reflected XSS",
  "ssrf": "Server-Side Request Forgery", "path-traversal": "Path Traversal",
  "eval-exec": "Arbitrary Code Execution", "open-redirect": "Open Redirect",
};

/**
 * Walks the whole file once: tracks taint through `env`, seeds tainted
 * parameters into same-file callees on tainted call sites (capped at one
 * hop -- not a full fixed-point interprocedural solver), and matches sink
 * call expressions / innerHTML-style assignments against a tainted argument.
 *
 * `crossFilePropagating` (optional, cross-file taint analysis Pass 2): for
 * each of THIS file's own locally-imported names that resolve to an
 * exported function elsewhere in the same scan batch with known-propagating
 * parameters, the shapes to treat it as tainted through -- merged into the
 * same local `propagating` map so an imported call is handled by the exact
 * same machinery as a local propagating-function call, no separate code
 * path. `fromModule` is carried only for finding-message attribution, never
 * consulted by the taint predicate itself. See scanner.ts's runScan() for
 * how this map is built (resolves relative imports via
 * semanticGraph.ts's resolveImportPath against the batch's own file list).
 */
export function scanAstTaint(
  content: string, filePath: string, presparsed?: ts.SourceFile,
  crossFilePropagating?: Map<string, { shapes: ParamShape[]; fromModule: string }>,
  // Sinks whose argument was tainted for the sink's class but positively
  // cleared by a sanitizer -- lets scanner.ts drop the regex layer's
  // duplicate finding for a flow this engine proved safe. Optional out-param
  // so the return type (and every existing caller) stays unchanged.
  suppressedOut?: SuppressedSink[],
): AstTaintFinding[] {
  try {
    const sourceFile = presparsed ?? parseSourceFile(content, filePath);
    const importMap = buildImportMap(sourceFile);
    const localFns = collectLocalFunctions(sourceFile);
    const propagating = buildPropagatingMap(localFns);
    if (crossFilePropagating) {
      for (const [name, info] of crossFilePropagating) propagating.set(name, info.shapes);
    }
    const taintMask = makeTaintMask(propagating);
    // fn name -> (tainted param index -> classes tainted at the call site)
    const seededParams = new Map<string, Map<number, number>>();
    // Message-attribution only (Tier 2, "assign then use downstream"): the
    // initializer expression a bare identifier was last assigned from, kept
    // in lockstep with `env` wherever a VariableStatement sets it. NOT
    // consulted by isTainted/the taint predicate at all -- purely so a
    // finding whose tainted arg is `q` (from `const q = buildQuery(x);`)
    // can note that the taint crosses a file boundary via `buildQuery`,
    // without needing a general expression-provenance system. One hop only:
    // deeper chains (`const a = crossFn(x); const b = a; sink(b)`) still
    // fire correctly (env-driven) but won't get an attribution note.
    const initializerOf = new Map<string, ts.Expression>();
    const findings: AstTaintFinding[] = [];
    const seen = new Set<string>();

    const lineOf = (node: ts.Node): number =>
      sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;

    /** If `text` mentions a cross-file-propagating call, a note for `detail` identifying the import; else "". */
    const crossFileNote = (text: string): string => {
      if (!crossFilePropagating) return "";
      for (const [name, info] of crossFilePropagating) {
        if (new RegExp(`\\b${name}\\s*\\(`).test(text)) return ` [crosses file boundary via "${name}" imported from ${info.fromModule}]`;
      }
      return "";
    };

    const emit = (id: AstTaintId, node: ts.Node, sourceExpr: string, sinkExpr: string, taintedArgExpr?: ts.Expression) => {
      const line = lineOf(node);
      const key = `${id}:${line}`;
      if (seen.has(key)) return;
      seen.add(key);
      // Tier 1: the tainted arg's own text mentions a cross-file call
      // directly (e.g. exec(buildCommand(host))). Tier 2: the tainted arg
      // is a bare identifier whose last-seen initializer mentions one
      // (e.g. const q = buildQuery(host); exec(q)).
      const note = crossFileNote(sourceExpr) ||
        (taintedArgExpr && ts.isIdentifier(taintedArgExpr)
          ? crossFileNote(initializerOf.get(taintedArgExpr.text)?.getText() ?? "")
          : "");
      findings.push({
        id, line, sinkExpr, sourceExpr,
        detail: `Tainted expression '${sourceExpr}' flows into ${sinkExpr}(...) — real data-flow match, not a line-pattern guess${note}`,
      });
    };

    const checkCallForSink = (call: ts.CallExpression, env: Env) => {
      if (ts.isIdentifier(call.expression) && call.expression.text === "eval") {
        emit("eval-exec", call, call.arguments[0] ? sourceLabel(call.arguments[0]) : "eval", "eval", call.arguments[0]);
        return;
      }
      const match = matchSink(call, importMap);
      if (!match) return;
      const cls = classOf(match.id);
      let taintedArg: ts.Expression | undefined;
      let cleared = false;
      for (const a of match.args) {
        const m = taintMask(a, env);
        if (m & cls) { taintedArg = a; break; }
        if (wasCleared(m, cls)) cleared = true;
      }
      if (taintedArg) emit(match.id, call, sourceLabel(taintedArg), match.sinkExpr, taintedArg);
      else if (cleared) suppressedOut?.push({ id: match.id, line: lineOf(call) });
    };

    const checkNewExprForSink = (node: ts.NewExpression) => {
      if (ts.isIdentifier(node.expression) && node.expression.text === "Function") {
        emit("eval-exec", node, "Function(...)", "new Function");
      }
    };

    const checkAssignmentForXSS = (node: ts.BinaryExpression, env: Env) => {
      if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return;
      if (!ts.isPropertyAccessExpression(node.left)) return;
      const prop = node.left.name.text;
      if (prop === "innerHTML" || prop === "outerHTML") {
        const m = taintMask(node.right, env);
        if (m & classOf("xss")) emit("xss", node, sourceLabel(node.right), `.${prop}`, node.right);
        else if (wasCleared(m, classOf("xss"))) suppressedOut?.push({ id: "xss", line: lineOf(node) });
      }
    };

    const walkStatements = (node: ts.Node, env: Env) => {
      // Variable declarations / destructuring / simple reassignment (x =
      // expr) -- shared with computeReturnTaintPropagating's envAfterBody
      // via applyDeclAndAssign, see that function's docblock. The
      // XSS-assignment check itself (obj.prop = expr) is handled uniformly
      // by the generic visitExpr traversal below, which visits this same
      // binary expression as a child of `node` -- no need to special-case
      // it here too.
      applyDeclAndAssign(node, env, taintMask);
      // Tier-2 message-attribution bookkeeping only (see initializerOf's
      // declaration) -- kept as a separate pass over the same statement
      // rather than folded into applyDeclAndAssign, since
      // computeReturnTaintPropagating's envAfterBody reuses that function
      // and has no use for (or access to) this file-scoped map.
      if (ts.isVariableStatement(node)) {
        for (const decl of node.declarationList.declarations) {
          if (decl.initializer && ts.isIdentifier(decl.name)) initializerOf.set(decl.name.text, decl.initializer);
        }
      }

      // Sink checks: any call/new expression anywhere in this node
      const visitExpr = (n: ts.Node) => {
        if (ts.isCallExpression(n)) {
          checkCallForSink(n, env);
          // Same-file call binding: seed callee params for tainted args, one hop.
          // Matched by INDEX (via paramShapesOf, including rest-param
          // overflow), not by re-deriving positions ad hoc here.
          if (ts.isIdentifier(n.expression) && localFns.has(n.expression.text)) {
            const fnName = n.expression.text;
            const fn = localFns.get(fnName)!;
            const shapes = paramShapesOf(fn);
            // param index -> classes tainted at THIS call site (the callee's
            // parameter is only tainted for those classes, not for ALL)
            const taintedIdx = new Map<number, number>();
            n.arguments.forEach((arg, i) => {
              const m = taintMask(arg, env) & ALL;
              if (!m) return;
              const shape = shapes.find(s => s.isRest ? i >= s.index : s.index === i);
              if (shape) taintedIdx.set(shape.index, (taintedIdx.get(shape.index) ?? 0) | m);
            });
            if (taintedIdx.size > 0) {
              const existing = seededParams.get(fnName) ?? new Map<number, number>();
              for (const [i, m] of taintedIdx) existing.set(i, (existing.get(i) ?? 0) | m);
              seededParams.set(fnName, existing);
            }
          }
        }
        if (ts.isNewExpression(n)) checkNewExprForSink(n);
        if (ts.isBinaryExpression(n)) checkAssignmentForXSS(n, env);
        ts.forEachChild(n, visitExpr);
      };
      visitExpr(node);

      ts.forEachChild(node, child => walkStatements(child, env));
    };

    walkStatements(sourceFile, new Map());

    // Second pass, bounded worklist: re-walk any local function whose
    // parameters were seeded as tainted by a call site above, so a sink
    // inside the callee's own body is reachable. Re-walking can itself seed
    // FURTHER functions (or grow an already-seeded function's own index
    // set) via the same visitExpr logic above, which is exactly how a
    // second/third hop (A calls B calls C) gets discovered -- bounded by
    // MAX_PROPAGATION_ROUNDS rather than left as an unbounded/accidental
    // side effect of Map iteration order. `walkedSignatures` skips re-
    // walking a function with a seed set identical to one already walked
    // (wasted, redundant work), while still allowing a re-walk once that
    // function's seed set has genuinely grown.
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
        const shapes = paramShapesOf(fn);
        for (const [idx, m] of idxSet) {
          const shape = shapes[idx];
          if (shape) env.set(shape.name, m);
        }
        walkStatements(fn.body, env);
      }
      if (!changed) break;
    }

    return findings;
  } catch (err) {
    console.error(`[astTaint] threw scanning ${filePath}:`, err);
    return [];
  }
}

export function astTaintSeverity(id: AstTaintId): "critical" | "high" | "medium" {
  return SEVERITY[id];
}
export function astTaintLabel(id: AstTaintId): string {
  return LABEL[id];
}
