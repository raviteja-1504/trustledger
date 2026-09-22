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
  ALL, applyClears, applyGuards, assignEnv, classOf, cloneEnv, guardedNames, isTaintedMask, joinArms, joinEnvs,
  SHADOW, wasCleared, type Arm, type Guard, type SuppressedSink, type TaintEnv,
} from "./taint/taintCore";
import { sanitizerClears } from "./taint/sanitizers";

export type AstTaintId =
  | "sql-injection" | "command-injection" | "xss" | "ssrf" | "path-traversal" | "open-redirect" | "eval-exec"
  | "header-injection" | "nosql-injection" | "mass-assignment" | "redos" | "timing-attack"
  | "prototype-pollution" | "jwt-none-alg";

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

const CMD_SINK_NAMES = new Set(["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"]);
const FS_SINK_NAMES = new Set([
  "readFile", "readFileSync", "writeFile", "writeFileSync",
  "createReadStream", "createWriteStream", "unlink", "unlinkSync", "stat", "statSync",
]);
const HTTP_SINK_NAMES = new Set(["get", "post", "put", "delete", "patch", "request"]);
const DB_SINK_METHODS = new Set(["query", "execute", "run", "prepare"]);

interface SinkMatch { id: AstTaintId; sinkExpr: string; args: readonly ts.Expression[] }

// Express/Fastify fluent response helpers that return `res` itself, so
// `res.status(200).type("html").send(x)` is still the `res.send` sink.
const FLUENT_RESPONSE_METHODS = new Set([
  "status", "type", "set", "header", "contentType", "append", "links", "vary", "attachment", "code", "cookie",
]);
const RESPONSE_ROOTS = new Set(["res", "response", "reply", "resp"]);
const NOSQL_TAILS = new Set([
  "find", "findOne", "findOneAndUpdate", "findOneAndDelete", "findOneAndReplace", "updateOne", "updateMany",
  "deleteOne", "deleteMany", "replaceOne", "aggregate", "countDocuments",
]);
const NOSQL_RECEIVER_RE = /mongo|collection|coll\b|nosql|couch|dynamo|cosmos|\bdb\b|model|users?\b|orders?\b|accounts?\b/i;
const GLOBAL_OBJECTS = new Set(["globalThis", "window", "global", "self"]);

const isFunctionExpr = (e: ts.Node): e is ts.ArrowFunction | ts.FunctionExpression =>
  ts.isArrowFunction(e) || ts.isFunctionExpression(e);

function unwrapExpr(e: ts.Expression): ts.Expression {
  while (ts.isParenthesizedExpression(e) || ts.isAsExpression(e) || ts.isNonNullExpression(e) ||
         ts.isTypeAssertionExpression(e) || ts.isSatisfiesExpression(e)) e = e.expression;
  return e;
}

/** `res.type("html").send` -> "res.send" (root must be a response-shaped identifier, every hop a fluent helper). */
function fluentResponseText(callee: ts.Expression): string | null {
  if (!ts.isPropertyAccessExpression(callee)) return null;
  let base: ts.Expression = callee.expression;
  let hops = 0;
  while (ts.isCallExpression(base) && ts.isPropertyAccessExpression(base.expression) &&
         FLUENT_RESPONSE_METHODS.has(base.expression.name.text)) {
    base = base.expression.expression;
    hops++;
  }
  return hops > 0 && ts.isIdentifier(base) && RESPONSE_ROOTS.has(base.text) ? `res.${callee.name.text}` : null;
}

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

export interface ImportBinding {
  localName: string; importedName: string; moduleSpecifier: string;
  // `import * as ns from "./mod"` / `const ns = require("./mod")` -- localName is bound to the WHOLE
  // module; call sites address a specific export as `ns.<name>`, so `importedName` here is the
  // sentinel "*" rather than one real export.
  namespace?: boolean;
}

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
    if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
      out.push({ localName: clause.namedBindings.name.text, importedName: "*", moduleSpecifier, namespace: true });
    }
    if (clause.name) out.push({ localName: clause.name.text, importedName: "default", moduleSpecifier });
  });

  // CommonJS `require(...)`: `const x = require("./y")` (whole-module, namespace-like) and
  // `const { a, b } = require("./y")` (named-like) / `const { a: c } = require("./y")`.
  const isRequireCall = (n: ts.Node): n is ts.CallExpression =>
    ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "require"
    && n.arguments.length === 1 && ts.isStringLiteral(n.arguments[0]);
  const visitRequire = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) && node.initializer && isRequireCall(node.initializer)) {
      const moduleSpecifier = (node.initializer.arguments[0] as ts.StringLiteral).text;
      if (ts.isIdentifier(node.name)) {
        out.push({ localName: node.name.text, importedName: "*", moduleSpecifier, namespace: true });
      } else if (ts.isObjectBindingPattern(node.name)) {
        for (const el of node.name.elements) {
          if (el.dotDotDotToken || !ts.isIdentifier(el.name)) continue;
          const importedName = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : el.name.text;
          out.push({ localName: el.name.text, importedName, moduleSpecifier });
        }
      }
    }
    ts.forEachChild(node, visitRequire);
  };
  ts.forEachChild(sourceFile, visitRequire);

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
  const text = calleeText(callee) ?? fluentResponseText(callee);
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
  if (text === "res.redirect" || text === "res.location") {
    return { id: "open-redirect", sinkExpr: text, args: call.arguments };
  }
  if (text === "res.setHeader" || text === "res.set" || text === "res.header" || text === "res.append") {
    return { id: "header-injection", sinkExpr: text, args: call.arguments };
  }
  if (text === "res.sendFile" || text === "res.sendfile" || text === "res.download") {
    // sendFile(name, { root }) confines the path -- only the un-rooted form is a traversal sink
    const opts = call.arguments[1];
    if (opts && ts.isObjectLiteralExpression(opts) &&
        opts.properties.some(p => (ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p)) && p.name.getText() === "root")) return null;
    return call.arguments[0] ? { id: "path-traversal", sinkExpr: text, args: [call.arguments[0]] } : null;
  }
  if (text === "RegExp" && call.arguments[0]) {
    return { id: "redos", sinkExpr: text, args: [call.arguments[0]] };
  }
  if (parts.length > 1 && NOSQL_TAILS.has(tail) && call.arguments[0] && !isFunctionExpr(call.arguments[0]) &&
      !ts.isStringLiteral(call.arguments[0]) && NOSQL_RECEIVER_RE.test(parts.slice(0, -1).join("."))) {
    return { id: "nosql-injection", sinkExpr: text, args: [call.arguments[0]] };
  }
  if (parts.length > 1 && DB_SINK_METHODS.has(tail)) {
    return { id: "sql-injection", sinkExpr: text, args: call.arguments };
  }
  return null;
}

// ── Taint environment / propagation ──────────────────────────────────────────

type Env = TaintEnv;

// Builtins whose RESULT carries the taint of their arguments (string/JSON/URL/path plumbing that
// neither validates nor neutralizes anything). Opaque calls stay untainted -- these are the curated
// exceptions, not a default flip. Decoders additionally RESTORE classes an earlier encoder cleared.
const PASSTHROUGH_CALLS = new Set([
  "String", "JSON.parse", "JSON.stringify", "Buffer.from", "Buffer.concat", "path.join", "path.resolve",
  "path.normalize", "path.format", "path.relative", "path.dirname", "Object.assign", "Object.values",
  "Object.entries", "Object.keys", "Object.fromEntries", "Array.from", "Array.of", "Promise.resolve",
  "Promise.all", "Promise.race", "Promise.allSettled", "String.raw", "structuredClone", "url.format",
  "querystring.stringify", "querystring.parse", "decodeURIComponent", "decodeURI", "unescape", "atob", "btoa",
]);
const DECODERS = new Set(["decodeURIComponent", "decodeURI", "unescape", "atob"]);
const PASSTHROUGH_NEW = new Set(["URL", "URLSearchParams", "Buffer", "String", "Array", "Set", "Map", "Error"]);
// Methods whose result also includes their ARGUMENTS (replacement text, appended strings).
const ARG_CARRYING_METHODS = new Set(["replace", "replaceAll", "concat", "padStart", "padEnd"]);
const CALLBACK_RESULT_METHODS = new Set(["then", "map", "flatMap"]);
// A local class method sharing one of these names is indistinguishable from the builtin -- not resolved by name.
const BUILTIN_METHOD_NAMES = new Set([
  "get", "set", "has", "delete", "add", "push", "pop", "shift", "unshift", "map", "filter", "reduce", "forEach", "join",
  "split", "slice", "splice", "concat", "replace", "then", "catch", "find", "includes", "indexOf", "trim", "toString",
  "send", "json", "end", "write", "next", "call", "apply", "bind",
]);
const MUTATING_METHODS = new Set(["push", "unshift", "add", "set", "append", "splice"]);

const declaredNamesCache = new WeakMap<ts.Node, Set<string>>();
/** Parameter and local-declaration names of a function-like (nested functions excluded). */
function declaredNames(fn: ts.Node): Set<string> {
  const cached = declaredNamesCache.get(fn);
  if (cached) return cached;
  const names = new Set<string>();
  const addBinding = (n: ts.BindingName) => {
    if (ts.isIdentifier(n)) names.add(n.text);
    else for (const el of n.elements) if (!ts.isOmittedExpression(el)) addBinding(el.name);
  };
  const f = fn as ts.FunctionLikeDeclaration;
  for (const p of f.parameters ?? []) addBinding(p.name);
  const visit = (n: ts.Node) => {
    if (n !== f.body && isFunctionLike(n)) { if ((ts.isFunctionDeclaration(n)) && n.name) names.add(n.name.text); return; }
    if (ts.isVariableDeclaration(n)) addBinding(n.name);
    ts.forEachChild(n, visit);
  };
  if (f.body) ts.forEachChild(f.body, visit);
  declaredNamesCache.set(fn, names);
  return names;
}

/** Is identifier `id` bound by an enclosing function's parameter/local (i.e. NOT the module-scope binding)? */
function isShadowed(id: ts.Identifier): boolean {
  for (let cur: ts.Node | undefined = id.parent; cur; cur = cur.parent) {
    if (isFunctionLike(cur) && declaredNames(cur).has(id.text)) return true;
  }
  return false;
}

/** Is `id` a PARAMETER of an enclosing function (a callback the caller supplied)? */
function isParamOfEnclosingFn(id: ts.Identifier): boolean {
  for (let cur: ts.Node | undefined = id.parent; cur; cur = cur.parent) {
    if (isFunctionLike(cur) && (cur as ts.FunctionLikeDeclaration).parameters.some(p => ts.isIdentifier(p.name) && p.name.text === id.text)) return true;
  }
  return false;
}

function rootIdentifier(e: ts.Expression): ts.Identifier | null {
  let cur: ts.Expression = e;
  while (ts.isPropertyAccessExpression(cur) || ts.isElementAccessExpression(cur) || ts.isParenthesizedExpression(cur) ||
         ts.isNonNullExpression(cur) || ts.isAsExpression(cur)) cur = cur.expression;
  return ts.isIdentifier(cur) ? cur : null;
}

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
 * LocalFn entry to look shapes up from at all). This is what makes
 * `exec(buildCommand(host))` resolve correctly whether buildCommand is
 * declared in this same file or imported from another one in the same scan
 * batch: buildCommand never calls a sink itself, it just returns a tainted
 * template literal, so without this the call expression
 * `buildCommand(host)` would look untainted from the outside. Per-parameter
 * (not per-function) so a call like `buildLog(safeId, taintedMessage)` where
 * only `userId` -- not `message` -- flows into buildLog's return does NOT
 * fire, even though buildLog is "propagating" for its userId parameter.
 *
 * `sticky` (main scan only) is module-scope container memory: taint written
 * into a module-level array/Map/object from one handler is visible when any
 * handler reads it back (stored XSS, second-order SQL).
 */
function makeTaintMask(propagating: Map<string, ParamShape[]>, sticky?: Map<string, number>) {
  let fnValueDepth = 0;
  const taintMask = (expr: ts.Expression, env: Env): number => {
    if (ts.isParenthesizedExpression(expr)) return taintMask(expr.expression, env);
    if (isTaintSourceExpr(expr)) return ALL;
    if (ts.isIdentifier(expr)) {
      let m = env.get(expr.text) ?? 0;
      const st = sticky?.get(expr.text);
      if (st && !isShadowed(expr)) m |= st;
      // a bare object also carries the fields written onto it (`u.hostname = h; u`)
      const prefix = expr.text + ".";
      for (const [k, v] of env) if (v && k.startsWith(prefix)) m |= v;
      return m;
    }
    if (ts.isPropertyAccessExpression(expr)) {
      // Field-sensitive read: OR the composite "root.field" key (set by
      // applyDeclAndAssign's field-write branch below) with the root-object
      // mask -- pure recall gain, this can only ever ADD classes the old
      // root-collapse behavior would have missed, never remove one already
      // found that way. The ROOT identifier contributes only its own mask,
      // not its other fields (that would defeat field sensitivity).
      const path = calleeText(expr);
      const base = expr.expression;
      const baseMask = ts.isIdentifier(base)
        ? (env.get(base.text) ?? 0) | (sticky && !isShadowed(base) ? (sticky.get(base.text) ?? 0) : 0)
        : taintMask(base, env);
      return (path ? (env.get(path) ?? 0) : 0) | baseMask;
    }
    // arr[i] / obj[key]: an element of a tainted container is tainted; a lookup on a global object
    // with an attacker-chosen key selects an attacker-chosen member.
    if (ts.isElementAccessExpression(expr)) {
      const obj = unwrapExpr(expr.expression);
      const viaGlobal = ts.isIdentifier(obj) && GLOBAL_OBJECTS.has(obj.text);
      return taintMask(expr.expression, env) | (viaGlobal ? taintMask(expr.argumentExpression, env) : 0);
    }
    if (ts.isAwaitExpression(expr)) return taintMask(expr.expression, env);
    if (ts.isBinaryExpression(expr)) {
      const k = expr.operatorToken.kind;
      // +, and the value-producing logical operators: `a || b` / `a ?? b` /
      // `a && b` evaluate to one of their operands, so either can carry taint.
      if (k === ts.SyntaxKind.PlusToken || k === ts.SyntaxKind.BarBarToken ||
          k === ts.SyntaxKind.QuestionQuestionToken || k === ts.SyntaxKind.AmpersandAmpersandToken) {
        return taintMask(expr.left, env) | taintMask(expr.right, env);
      }
    }
    // `c ? a : b` -- the value is one of the two arms; the CONDITION is
    // deliberately excluded (a tainted condition does not make the chosen
    // constant tainted).
    if (ts.isConditionalExpression(expr)) {
      return taintMask(expr.whenTrue, env) | taintMask(expr.whenFalse, env);
    }
    if (ts.isTemplateExpression(expr)) return expr.templateSpans.reduce((m, s) => m | taintMask(s.expression, env), 0);
    if (ts.isSpreadElement(expr)) return taintMask(expr.expression, env);
    if (ts.isArrayLiteralExpression(expr)) return expr.elements.reduce((m, e) => m | taintMask(e, env), 0);
    if (ts.isObjectLiteralExpression(expr)) {
      return expr.properties.reduce((m, p) => {
        if (ts.isPropertyAssignment(p)) return m | taintMask(p.initializer, env);
        if (ts.isShorthandPropertyAssignment(p)) return m | (env.get(p.name.text) ?? 0);
        if (ts.isSpreadAssignment(p)) return m | taintMask(p.expression, env);
        return m;
      }, 0);
    }
    // A function VALUE carries whatever it captured: `() => x` returns x when called, so `delayed(x)()`
    // and `makeRenderer(v)()` resolve. Bounded (small bodies, shallow) so route-handler arrows stay cheap.
    if (isFunctionExpr(expr)) {
      if (fnValueDepth >= 2) return 0;
      if (ts.isBlock(expr.body) && expr.body.statements.length > 8) return 0;
      fnValueDepth++;
      try { return functionResultMask(expr, [], env); } finally { fnValueDepth--; }
    }
    if (ts.isNewExpression(expr)) {
      if (ts.isIdentifier(expr.expression) && PASSTHROUGH_NEW.has(expr.expression.text) && expr.arguments) {
        return expr.arguments.reduce((m, a) => (isFunctionExpr(a) ? m : m | taintMask(a, env)), 0);
      }
      return 0;
    }
    if (ts.isCallExpression(expr)) return callMask(expr, env);
    if (ts.isAsExpression(expr) || ts.isNonNullExpression(expr) || ts.isTypeAssertionExpression(expr) || ts.isSatisfiesExpression(expr)) {
      return taintMask(expr.expression, env);
    }
    return 0;
  };

  /** Result of calling function-like `fn` when its leading parameters hold `argMasks` (captured variables come from `env`). */
  const functionResultMask = (fn: ts.ArrowFunction | ts.FunctionExpression, argMasks: readonly number[], env: Env): number => {
    const fenv = cloneEnv(env);
    fn.parameters.forEach((p, i) => { if (ts.isIdentifier(p.name)) fenv.set(p.name.text, argMasks[i] ?? 0); });
    if (!ts.isBlock(fn.body)) return taintMask(fn.body, fenv);
    let m = 0;
    createWalker({
      taintMask, sf: fn.getSourceFile(), descendFunctions: false,
      onReturn: (e, en) => { m |= taintMask(e, en); },
    }).walkNode(fn.body, fenv);
    return m;
  };

  const argsMask = (args: readonly ts.Expression[], env: Env): number =>
    args.reduce((m, a) => (isFunctionExpr(a) ? m : m | taintMask(a, env)), 0);

  const callMask = (expr: ts.CallExpression, env: Env): number => {
    // Known sanitizer: the argument's taint passes THROUGH minus only the
    // classes this sanitizer actually neutralizes (an HTML escaper leaves
    // SQL/command/path taint intact). Opaque calls stay untainted below.
    const calleeName = calleeText(expr.expression);
    if (calleeName) {
      const clears = sanitizerClears("js", calleeName);
      if (clears !== null) return expr.arguments[0] ? applyClears(taintMask(expr.arguments[0], env), clears) : 0;
    }
    // Curated passthrough builtins (String, JSON.*, Buffer.from, path.*, Object.assign, ...): the result
    // is as tainted as the arguments. A decoder re-taints what an earlier encoder cleared.
    if (calleeName && PASSTHROUGH_CALLS.has(calleeName)) {
      const m = argsMask(expr.arguments, env);
      return DECODERS.has(calleeName) ? (m & ALL) | ((m >>> SHADOW) & ALL) : m;
    }
    // A call to a local (or cross-file-imported) function known to
    // propagate taint from SPECIFIC params to its return value -- e.g.
    // buildCommand(host) where buildCommand(h) { return `ping -c1 ${h}`; }.
    // Only the arguments at the propagating indices are checked, and only
    // the classes that survive the callee's own body (shape.mask) count.
    // Also resolves `obj.method(x)` / `this.method(x)` to a local class method by name.
    const callee = expr.expression;
    const fnName = ts.isIdentifier(callee)
      ? callee.text
      : ts.isPropertyAccessExpression(callee) &&
        (callee.expression.kind === ts.SyntaxKind.ThisKeyword || !BUILTIN_METHOD_NAMES.has(callee.name.text))
        ? callee.name.text : null;
    if (fnName) {
      const shapes = propagating.get(fnName);
      if (shapes) {
        let m = 0;
        for (const shape of shapes) {
          for (const a of argsForShape(expr.arguments, shape)) m |= taintMask(a, env) & (shape.mask ?? ALL);
        }
        if (m) return m;
      }
    }
    // Calling a value: an IIFE / `f()()` / a closure held in a variable returns what it captured.
    const inner = unwrapExpr(callee);
    if (ts.isCallExpression(inner) || isFunctionExpr(inner)) return taintMask(inner, env);
    if (ts.isIdentifier(inner)) {
      // calling a callback PARAMETER: the result is (recall-biased) as tainted as what it is called with
      if (isParamOfEnclosingFn(inner) && !propagating.has(inner.text)) return argsMask(expr.arguments, env);
      const held = env.get(inner.text) ?? 0;
      if (held) return held;
    }
    if (ts.isPropertyAccessExpression(callee)) {
      const recv = taintMask(callee.expression, env);
      const name = callee.name.text;
      // promise / array plumbing with a callback: the result is what the callback makes of the element
      const cb = expr.arguments[0];
      if (CALLBACK_RESULT_METHODS.has(name) && cb && isFunctionExpr(cb)) {
        return functionResultMask(cb, [recv], env);
      }
      // Passthrough for a method call on an already-tainted receiver
      // (.trim()/.toLowerCase()/.toString()/etc.) -- same "propagate through
      // anything referencing a tainted value" recall bias already
      // established in extractTaintedVars' second-hop rule (scanner.ts),
      // not a claim that every such method is unsafe on its own.
      const withArgs = ARG_CARRYING_METHODS.has(name) ? argsMask(expr.arguments, env) : 0;
      // `Promise.resolve(x)`-style receivers are namespaces, not values: their args are handled above.
      return recv | withArgs;
    }
    return 0;
  };
  return taintMask;
}

type TaintMaskFn = (e: ts.Expression, env: Env) => number;

interface LocalFn {
  // Declared as a class/object METHOD (resolved by bare name at `obj.method(...)` call sites).
  isMethod?: boolean;
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
      } else if ((ts.isObjectBindingPattern(decl.name) || ts.isArrayBindingPattern(decl.name)) && isTaintedMask(mask)) {
        for (const el of decl.name.elements) {
          if (!ts.isOmittedExpression(el) && ts.isIdentifier(el.name)) env.set(el.name.text, mask);
        }
      }
    }
  } else if (
    ts.isExpressionStatement(node) && ts.isBinaryExpression(node.expression) &&
    (node.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken || isCompoundAssign(node.expression.operatorToken.kind))
  ) {
    const { left, right } = node.expression;
    // `x += y` / `x ||= y` / `x ??= y` keep whatever taint x already had
    // (OR), unlike plain `=`, which overwrites it.
    const compound = node.expression.operatorToken.kind !== ts.SyntaxKind.EqualsToken;
    if (ts.isIdentifier(left)) {
      env.set(left.text, maskFn(right, env) | (compound ? (env.get(left.text) ?? 0) : 0));
    } else if (ts.isPropertyAccessExpression(left)) {
      // Field-sensitive write: `obj.field = expr` -- stores under the same
      // composite "root.field" key the read side (makeTaintMask, above)
      // checks. Additive only: obj's own bare-identifier env entry (if any)
      // is left untouched, so a consumer that only ever checked obj before
      // this change sees exactly what it saw before.
      const path = calleeText(left);
      if (path) env.set(path, maskFn(right, env) | (compound ? (env.get(path) ?? 0) : 0));
    } else if (ts.isElementAccessExpression(left)) {
      // `target[key] = value` -- the container now holds the value (additive: a write never de-taints)
      const root = rootIdentifier(left.expression);
      if (root) env.set(root.text, (env.get(root.text) ?? 0) | maskFn(right, env));
    }
  } else if (ts.isExpressionStatement(node) && ts.isCallExpression(node.expression) &&
             ts.isPropertyAccessExpression(node.expression.expression) &&
             MUTATING_METHODS.has(node.expression.expression.name.text)) {
    // `list.push(x)` / `map.set(k, v)` / `set.add(x)`: the receiver container now holds the arguments
    const root = rootIdentifier(node.expression.expression.expression);
    if (root) {
      const m = node.expression.arguments.reduce((acc, a) => (isFunctionExpr(a) ? acc : acc | maskFn(a, env)), 0);
      env.set(root.text, (env.get(root.text) ?? 0) | m);
    }
  }
}

function isCompoundAssign(k: ts.SyntaxKind): boolean {
  return k === ts.SyntaxKind.PlusEqualsToken || k === ts.SyntaxKind.BarBarEqualsToken ||
    k === ts.SyntaxKind.QuestionQuestionEqualsToken || k === ts.SyntaxKind.AmpersandAmpersandEqualsToken;
}

// ── Validation guards (narrow, unambiguous only) ────────────────────────────

function isLiteralNode(e: ts.Expression): boolean {
  if (ts.isParenthesizedExpression(e)) return isLiteralNode(e.expression);
  return ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e) || ts.isNumericLiteral(e) ||
    (ts.isPrefixUnaryExpression(e) && e.operator === ts.SyntaxKind.MinusToken && ts.isNumericLiteral(e.operand)) ||
    e.kind === ts.SyntaxKind.TrueKeyword || e.kind === ts.SyntaxKind.FalseKeyword;
}

/** Is `e` a collection made ONLY of literals -- an array/Set literal, or a top-level `const` bound to one? */
function isLiteralCollection(e: ts.Expression, sf: ts.SourceFile, depth = 0): boolean {
  if (depth > 3) return false;
  if (ts.isParenthesizedExpression(e)) return isLiteralCollection(e.expression, sf, depth + 1);
  if (ts.isArrayLiteralExpression(e)) return e.elements.length > 0 && e.elements.every(el => isLiteralNode(el));
  if (ts.isNewExpression(e) && ts.isIdentifier(e.expression) && e.expression.text === "Set" && e.arguments?.length === 1) {
    return isLiteralCollection(e.arguments[0], sf, depth + 1);
  }
  if (ts.isIdentifier(e)) {
    for (const st of sf.statements) {
      if (!ts.isVariableStatement(st) || !(st.declarationList.flags & ts.NodeFlags.Const)) continue;
      for (const d of st.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && d.name.text === e.text && d.initializer) return isLiteralCollection(d.initializer, sf, depth + 1);
      }
    }
  }
  return false;
}

const invert = (g: Guard): Guard => ({ name: g.name, holds: g.holds === "true" ? "false" : "true" });

/**
 * The variables a condition PROVES safe, and on which side. Deliberately a
 * closed, unambiguous set -- literal-collection membership, strict
 * numeric/type checks, equality with a literal. Regex matches, prefix checks
 * and custom validator functions are NOT recognized: a wrongly recognized
 * guard silently hides a real finding, so anything ambiguous stays reported.
 */
function guardsOfCondition(cond: ts.Expression, sf: ts.SourceFile): Guard[] {
  if (ts.isParenthesizedExpression(cond)) return guardsOfCondition(cond.expression, sf);
  if (ts.isPrefixUnaryExpression(cond) && cond.operator === ts.SyntaxKind.ExclamationToken) {
    return guardsOfCondition(cond.operand, sf).map(invert);
  }
  if (ts.isBinaryExpression(cond)) {
    const k = cond.operatorToken.kind;
    const { left, right } = cond;
    if (k === ts.SyntaxKind.AmpersandAmpersandToken) {
      return [...guardsOfCondition(left, sf), ...guardsOfCondition(right, sf)].filter(g => g.holds === "true");
    }
    if (k === ts.SyntaxKind.BarBarToken) {
      return [...guardsOfCondition(left, sf), ...guardsOfCondition(right, sf)].filter(g => g.holds === "false");
    }
    const eq = k === ts.SyntaxKind.EqualsEqualsToken || k === ts.SyntaxKind.EqualsEqualsEqualsToken;
    const neq = k === ts.SyntaxKind.ExclamationEqualsToken || k === ts.SyntaxKind.ExclamationEqualsEqualsToken;
    if (eq || neq) {
      const holds: "true" | "false" = eq ? "true" : "false";
      // x === "admin" / "admin" === x
      if (ts.isIdentifier(left) && isLiteralNode(right)) return [{ name: left.text, holds }];
      if (ts.isIdentifier(right) && isLiteralNode(left)) return [{ name: right.text, holds }];
      // typeof x === "number" / "boolean"
      const typeofSide = ts.isTypeOfExpression(left) ? left : ts.isTypeOfExpression(right) ? right : null;
      const lit = typeofSide === left ? right : left;
      if (typeofSide && ts.isIdentifier(typeofSide.expression) && ts.isStringLiteral(lit) && (lit.text === "number" || lit.text === "boolean")) {
        return [{ name: typeofSide.expression.text, holds }];
      }
    }
    // COLL.indexOf(x) !== -1 / >= 0 / > -1   (and the negations)
    if (ts.isCallExpression(left) && ts.isPropertyAccessExpression(left.expression) && left.expression.name.text === "indexOf" &&
        left.arguments.length === 1 && ts.isIdentifier(left.arguments[0]) && isLiteralCollection(left.expression.expression, sf) &&
        isLiteralNode(right)) {
      const n = right.getText(sf);
      const found = (neq && n === "-1") || (k === ts.SyntaxKind.GreaterThanToken && n === "-1") ||
        (k === ts.SyntaxKind.GreaterThanEqualsToken && n === "0");
      const missing = (eq && n === "-1") || (k === ts.SyntaxKind.LessThanToken && n === "0");
      if (found) return [{ name: (left.arguments[0] as ts.Identifier).text, holds: "true" }];
      if (missing) return [{ name: (left.arguments[0] as ts.Identifier).text, holds: "false" }];
    }
    return [];
  }
  if (ts.isCallExpression(cond)) {
    const callee = cond.expression;
    const arg = cond.arguments.length >= 1 ? cond.arguments[0] : undefined;
    // COLL.includes(x) / COLL.has(x) against a literal-only collection
    if (ts.isPropertyAccessExpression(callee) && (callee.name.text === "includes" || callee.name.text === "has") &&
        cond.arguments.length === 1 && arg && ts.isIdentifier(arg) && isLiteralCollection(callee.expression, sf)) {
      return [{ name: arg.text, holds: "true" }];
    }
    // Number.isInteger / isFinite / isSafeInteger (x)
    if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && callee.expression.text === "Number" &&
        ["isInteger", "isFinite", "isSafeInteger"].includes(callee.name.text) && arg && ts.isIdentifier(arg)) {
      return [{ name: arg.text, holds: "true" }];
    }
    // isNaN(x) is FALSE for numeric-looking input
    if (ts.isIdentifier(callee) && callee.text === "isNaN" && arg && ts.isIdentifier(arg)) {
      return [{ name: arg.text, holds: "false" }];
    }
  }
  return [];
}

// ── Path-sensitive statement walk ───────────────────────────────────────────
// One walker serves both the interprocedural summary builder (no sink checks,
// no nested functions, collects return masks) and the main scan (sink checks,
// nested functions walked with a cloned env). Branches walk each arm on a
// CLONE of the env and join with may-taint OR; an arm ending in return/throw
// is dropped from the join, and code after a terminating statement is dead
// and not walked at all.

function isFunctionLike(n: ts.Node): boolean {
  return ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) ||
    ts.isMethodDeclaration(n) || ts.isConstructorDeclaration(n) ||
    ts.isGetAccessorDeclaration(n) || ts.isSetAccessorDeclaration(n);
}

/** Visit `root` and its descendants WITHOUT entering nested function bodies (those are collected into `fns`). */
function scanExprSkippingFunctions(root: ts.Node, visit: (n: ts.Node) => void, fns: ts.Node[]): void {
  const go = (n: ts.Node) => {
    if (n !== root && isFunctionLike(n)) { fns.push(n); return; }
    visit(n);
    ts.forEachChild(n, go);
  };
  go(root);
}

interface WalkerHooks {
  taintMask: TaintMaskFn;
  sf: ts.SourceFile;
  /** Called for every expression-level node of a statement, with the env at that point (sink checks live here). */
  onVisit?: (n: ts.Node, env: Env) => void;
  /** Called for each `return expr;` with the env at that point. */
  onReturn?: (expr: ts.Expression, env: Env) => void;
  /** Called before a statement's own assignments are applied (bookkeeping only). */
  onStatement?: (n: ts.Node) => void;
  /** Walk nested function bodies (main scan) or ignore them (summaries: their returns aren't this function's). */
  descendFunctions: boolean;
}

function createWalker(h: WalkerHooks) {
  const { taintMask, sf } = h;

  const handleExpr = (node: ts.Node, env: Env) => {
    const fns: ts.Node[] = [];
    scanExprSkippingFunctions(node, n => h.onVisit?.(n, env), fns);
    if (h.descendFunctions) for (const f of fns) walkFunction(f, env);
  };

  const walkFunction = (fn: ts.Node, env: Env) => {
    const f = fn as ts.FunctionLikeDeclaration;
    if (!f.body) return;
    // A closure sees captured outer variables (cloned env), but its own
    // parameters shadow same-named outer ones and start untainted.
    const fenv = cloneEnv(env);
    for (const prm of f.parameters) if (ts.isIdentifier(prm.name)) fenv.set(prm.name.text, 0);
    if (ts.isBlock(f.body)) walkNode(f.body, fenv);
    else handleExpr(f.body, fenv);
  };

  const bindLoopVar = (init: ts.ForInitializer | undefined, mask: number, env: Env) => {
    if (init && ts.isVariableDeclarationList(init)) {
      for (const d of init.declarations) if (ts.isIdentifier(d.name)) env.set(d.name.text, mask);
    }
  };

  const walkBlock = (stmts: readonly ts.Node[], env: Env): boolean => {
    for (const st of stmts) if (walkNode(st, env)) return true; // dead code after a terminator is not walked
    return false;
  };

  const walkNode = (node: ts.Node, env: Env): boolean => {
    if (ts.isBlock(node) || ts.isSourceFile(node) || ts.isModuleBlock(node)) return walkBlock(node.statements, env);
    if (ts.isLabeledStatement(node)) return walkNode(node.statement, env);

    if (ts.isIfStatement(node)) {
      handleExpr(node.expression, env);
      const guards = guardsOfCondition(node.expression, sf);
      const thenEnv = cloneEnv(env); applyGuards(thenEnv, guardedNames(guards, "true"));
      const elseEnv = cloneEnv(env); applyGuards(elseEnv, guardedNames(guards, "false"));
      const thenTerm = walkNode(node.thenStatement, thenEnv);
      const elseTerm = node.elseStatement ? walkNode(node.elseStatement, elseEnv) : false;
      const joined = joinArms([{ env: thenEnv, terminated: thenTerm }, { env: elseEnv, terminated: elseTerm }]);
      assignEnv(env, joined.env);
      return joined.terminated;
    }

    if (ts.isForStatement(node) || ts.isForInStatement(node) || ts.isForOfStatement(node) ||
        ts.isWhileStatement(node) || ts.isDoStatement(node)) {
      if (ts.isForStatement(node)) {
        if (node.initializer) {
          if (ts.isVariableDeclarationList(node.initializer)) {
            for (const d of node.initializer.declarations) {
              if (ts.isIdentifier(d.name) && d.initializer) env.set(d.name.text, taintMask(d.initializer, env));
            }
          }
          handleExpr(node.initializer, env);
        }
        if (node.condition) handleExpr(node.condition, env);
        if (node.incrementor) handleExpr(node.incrementor, env);
      } else if (ts.isForInStatement(node) || ts.isForOfStatement(node)) {
        handleExpr(node.expression, env);
        // the loop variable iterates the (possibly tainted) collection
        bindLoopVar(node.initializer, taintMask(node.expression, env), env);
      } else {
        handleExpr(node.expression, env);
      }
      const pre = cloneEnv(env);
      const bodyEnv = cloneEnv(env);
      // Two passes over the body so a value assigned late in iteration N
      // reaches a sink early in iteration N+1 (loop-carried flow); findings
      // dedupe by id+line, so the repeat is free of duplicates.
      let term = walkNode(node.statement, bodyEnv);
      if (!term) term = walkNode(node.statement, bodyEnv);
      assignEnv(env, joinArms([{ env: pre, terminated: false }, { env: bodyEnv, terminated: term }]).env);
      return false; // a loop may run zero times
    }

    if (ts.isSwitchStatement(node)) {
      handleExpr(node.expression, env);
      const subject = ts.isIdentifier(node.expression) ? node.expression.text : null;
      const arms: Arm[] = [];
      let hasDefault = false;
      for (const clause of node.caseBlock.clauses) {
        const cenv = cloneEnv(env);
        if (ts.isCaseClause(clause)) {
          handleExpr(clause.expression, cenv);
          // inside `case "a":` the subject IS that literal
          if (subject && isLiteralNode(clause.expression)) applyGuards(cenv, [subject]);
        } else {
          hasDefault = true;
        }
        arms.push({ env: cenv, terminated: walkBlock(clause.statements, cenv) });
      }
      if (!hasDefault) arms.push({ env: cloneEnv(env), terminated: false });
      const joined = joinArms(arms);
      assignEnv(env, joined.env);
      return joined.terminated;
    }

    if (ts.isTryStatement(node)) {
      const pre = cloneEnv(env);
      const tryEnv = cloneEnv(env);
      const arms: Arm[] = [{ env: tryEnv, terminated: walkNode(node.tryBlock, tryEnv) }];
      if (node.catchClause) {
        // an exception can be thrown from anywhere in the try body
        const catchEnv = joinEnvs([pre, tryEnv]);
        const v = node.catchClause.variableDeclaration;
        if (v && ts.isIdentifier(v.name)) catchEnv.set(v.name.text, 0);
        arms.push({ env: catchEnv, terminated: walkNode(node.catchClause.block, catchEnv) });
      }
      const joined = joinArms(arms);
      assignEnv(env, joined.env);
      let term = joined.terminated;
      if (node.finallyBlock) term = walkNode(node.finallyBlock, env) || term;
      return term;
    }

    if (ts.isReturnStatement(node) || ts.isThrowStatement(node)) {
      if (node.expression) {
        handleExpr(node.expression, env);
        if (ts.isReturnStatement(node)) h.onReturn?.(node.expression, env);
      }
      return true;
    }

    if (isFunctionLike(node)) {
      // a function DECLARATION / method as a statement: walk its body on a clone
      if (h.descendFunctions) walkFunction(node, env);
      return false;
    }

    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
      if (h.descendFunctions) for (const m of node.members) if (isFunctionLike(m)) walkFunction(m, env);
      return false;
    }

    // Everything else (expression statements, variable statements, ...):
    // apply its own declarations/assignments, then check its expressions.
    h.onStatement?.(node);
    applyDeclAndAssign(node, env, taintMask);
    handleExpr(node, env);
    return false;
  };

  return { walkNode, handleExpr };
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
  const sf = fn.body.getSourceFile();
  for (const shape of paramShapesOf(fn)) {
    const seed: Env = new Map();
    seed.set(shape.name, ALL);
    // Path-sensitive: the mask at EACH return, evaluated with the env on that
    // path (so a value sanitized on one branch and raw on another propagates
    // only what survives), and returns inside nested functions don't count.
    let surviving = 0;
    if (ts.isBlock(fn.body)) {
      const walker = createWalker({
        taintMask: maskFn, sf, descendFunctions: false,
        onReturn: (expr, env) => { surviving |= maskFn(expr, env); },
      });
      walker.walkNode(fn.body, seed);
    } else {
      surviving = maskFn(fn.body as ts.Expression, seed); // arrow expression body
    }
    // Only the low (still-dangerous) bits are a summary; the shadow half is
    // per-scan bookkeeping and must not leak into a stored/cross-file shape.
    surviving &= ALL;
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
function buildPropagatingMap(localFns: Map<string, LocalFn>, seed?: Map<string, ParamShape[]>): Map<string, ParamShape[]> {
  // `seed` (cross-file Pass 1 only): shapes already known for names THIS file imports, so a wrapper
  // around a cross-file call (`export function f(x){ return importedFn(x); }`) is seen as
  // propagating too -- the multi-hop case buildCrossFileContext's own round loop exists for.
  const propagating = new Map<string, ParamShape[]>(seed ? [...seed].map(([k, v]) => [k, [...v]]) : []);
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
 * `export default` gets exportedNames = ["default"] (a default export has no OTHER stable name a
 * cross-file import binds to; "default" is exactly the key `import x from "./y"` resolves through --
 * see collectDefaultExport below for the (unnamed-declaration / bare-identifier) forms this alone
 * can't reach.
 */
function hasExportModifier(node: ts.Node): boolean {
  if (!ts.canHaveModifiers(node)) return false;
  const mods = ts.getModifiers(node);
  return !!mods?.some(m => m.kind === ts.SyntaxKind.ExportKeyword);
}
function isDefaultModifier(node: ts.Node): boolean {
  if (!ts.canHaveModifiers(node)) return false;
  const mods = ts.getModifiers(node);
  return !!mods?.some(m => m.kind === ts.SyntaxKind.DefaultKeyword);
}
function exportedNamesOf(node: ts.Node, localName: string): string[] {
  if (!hasExportModifier(node)) return [];
  return isDefaultModifier(node) ? ["default"] : [localName];
}

// synthetic key for `export default function(){}` / `export default (x) => {...}` -- an unnamed
// declaration with no local name a same-file call site could ever reference by, but which still
// needs a LocalFn entry so its propagating shapes reach the "default" export summary slot.
const ANONYMOUS_DEFAULT_KEY = " default";

function collectLocalFunctions(sourceFile: ts.SourceFile): Map<string, LocalFn> {
  const fns = new Map<string, LocalFn>();
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.body) {
      const key = node.name?.text ?? ANONYMOUS_DEFAULT_KEY;
      fns.set(key, { params: node.parameters, body: node.body, exportedNames: exportedNamesOf(node, key) });
    }
    if (ts.isMethodDeclaration(node) && node.body && (ts.isIdentifier(node.name) || ts.isStringLiteral(node.name)) && !fns.has(node.name.text)) {
      fns.set(node.name.text, { params: node.parameters, body: node.body, exportedNames: [], isMethod: true });
    }
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const init = node.initializer;
      if ((ts.isArrowFunction(init) || ts.isFunctionExpression(init)) && init.body) {
        // The export modifier for `const x = () => {}` lives on the
        // enclosing VariableStatement (node.parent = VariableDeclarationList,
        // node.parent.parent = VariableStatement), NOT on this
        // VariableDeclaration node itself -- confirmed directly, not assumed.
        const stmt = node.parent?.parent;
        const exportedNames = stmt && ts.isVariableStatement(stmt) ? exportedNamesOf(stmt, node.name.text) : [];
        fns.set(node.name.text, { params: init.parameters, body: init.body, exportedNames });
      }
    }
    // `module.exports.foo = function/arrow` / `exports.foo = function/arrow` (CommonJS named export).
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
        && ts.isPropertyAccessExpression(node.left)) {
      const obj = node.left.expression;
      const isModuleExports = ts.isPropertyAccessExpression(obj) && ts.isIdentifier(obj.expression) && obj.expression.text === "module" && obj.name.text === "exports";
      const isExports = ts.isIdentifier(obj) && obj.text === "exports";
      if ((isModuleExports || isExports) && (ts.isFunctionExpression(node.right) || ts.isArrowFunction(node.right)) && node.right.body) {
        const publicName = node.left.name.text;
        fns.set(` cjs:${publicName}`, { params: node.right.parameters, body: node.right.body, exportedNames: [publicName] });
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sourceFile, visit);

  // `export { localName as publicName }` -- a named-export list for an
  // already-declared local function (common barrel-file style). Explicitly
  // scoped OUT here: `export { x } from "./y"` (has a moduleSpecifier -- a
  // re-export, not a local declaration) is handled by collectReexports
  // instead, and `export *` similarly.
  ts.forEachChild(sourceFile, node => {
    if (!ts.isExportDeclaration(node) || node.moduleSpecifier || !node.exportClause) return;
    if (!ts.isNamedExports(node.exportClause)) return;
    for (const spec of node.exportClause.elements) {
      const localName = (spec.propertyName ?? spec.name).text;
      const publicName = spec.name.text;
      const fn = fns.get(localName);
      if (fn && !fn.exportedNames.includes(publicName)) fn.exportedNames.push(publicName);
      // `export { foo as default }`
    }
  });

  // `export default function(){}` / `export default (x) => {...}` / `export default identifier;` --
  // an ExportAssignment node (`node.expression` is the default-exported value directly), distinct
  // from the modifier-based forms collectLocalFunctions' main visit loop already handles. `export =`
  // (CommonJS-style, node.isExportEquals) is a different, unrelated construct and is skipped.
  ts.forEachChild(sourceFile, node => {
    if (!ts.isExportAssignment(node) || node.isExportEquals) return;
    const expr = node.expression;
    if ((ts.isFunctionExpression(expr) || ts.isArrowFunction(expr)) && expr.body && !fns.has(ANONYMOUS_DEFAULT_KEY)) {
      fns.set(ANONYMOUS_DEFAULT_KEY, { params: expr.parameters, body: expr.body, exportedNames: ["default"] });
    } else if (ts.isIdentifier(expr)) {
      const fn = fns.get(expr.text);
      if (fn && !fn.exportedNames.includes("default")) fn.exportedNames.push("default");
    }
  });

  return fns;
}

export interface ReexportEdge {
  // null+null = `export * from "./mod"` -- every name the module exports, under the same name.
  publicName: string | null;
  importedName: string | null;
  moduleSpecifier: string;
}

/** `export { x } from "./y"`, `export { x as y } from "./z"`, `export * from "./w"`. */
export function collectReexports(sourceFile: ts.SourceFile): ReexportEdge[] {
  const out: ReexportEdge[] = [];
  ts.forEachChild(sourceFile, node => {
    if (!ts.isExportDeclaration(node) || !node.moduleSpecifier || !ts.isStringLiteral(node.moduleSpecifier)) return;
    const moduleSpecifier = node.moduleSpecifier.text;
    if (!node.exportClause) {
      out.push({ publicName: null, importedName: null, moduleSpecifier }); // export * from "./y"
      return;
    }
    if (ts.isNamedExports(node.exportClause)) {
      for (const spec of node.exportClause.elements) {
        out.push({ publicName: spec.name.text, importedName: (spec.propertyName ?? spec.name).text, moduleSpecifier });
      }
    }
  });
  return out;
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
 * `incoming` (optional, multi-hop): shapes already known, from an EARLIER round of
 * buildCrossFileContext's own fixed point, for names this file itself imports -- lets a wrapper
 * around a cross-file call (`export function f(x){ return importedFn(x); }`, importedFn from
 * elsewhere in the batch) be recognized as propagating too, not just wrappers around same-file calls.
 */
export function computeExportTaintSummary(
  content: string, filePath: string, presparsed?: ts.SourceFile, incoming?: Map<string, ParamShape[]>,
): Map<string, ParamShape[]> {
  const summary = new Map<string, ParamShape[]>();
  try {
    const sourceFile = presparsed ?? parseSourceFile(content, filePath);
    const localFns = collectLocalFunctions(sourceFile);
    const propagating = buildPropagatingMap(localFns, incoming);
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
  "header-injection": "high", "nosql-injection": "critical", "mass-assignment": "high", "redos": "high",
  "timing-attack": "medium", "prototype-pollution": "high", "jwt-none-alg": "critical",
};
const LABEL: Record<AstTaintId, string> = {
  "sql-injection": "SQL Injection", "command-injection": "Command Injection", "xss": "Reflected XSS",
  "ssrf": "Server-Side Request Forgery", "path-traversal": "Path Traversal",
  "eval-exec": "Arbitrary Code Execution", "open-redirect": "Open Redirect",
  "header-injection": "HTTP Header Injection", "nosql-injection": "NoSQL Injection",
  "mass-assignment": "Mass Assignment", "redos": "ReDoS — Regex DoS", "timing-attack": "Timing Attack",
  "prototype-pollution": "Prototype Pollution", "jwt-none-alg": "JWT Signature Not Verified",
};

/**
 * Function-level weaknesses that are properties of the code shape, not of a tainted flow:
 * a hand-rolled JWT payload decode that never verifies the signature, and a dotted-path
 * setter (`cursor[parts[i]] = ...`) with no __proto__/constructor guard.
 */
function structuralChecks(
  sf: ts.SourceFile, content: string,
  report: (id: AstTaintId, node: ts.Node, detail: string, sink: string) => void,
): void {
  const fileHasVerify = /\.verify\s*\(|jwtVerify|jsonwebtoken|jose\b|passport/i.test(content);
  const visit = (n: ts.Node) => {
    if (isFunctionLike(n) && (n as ts.FunctionLikeDeclaration).body) {
      const fn = n as ts.FunctionLikeDeclaration;
      const text = fn.body!.getText(sf);
      // JWT: split(".") + base64 decode + JSON.parse in one function, with no verification anywhere in the file
      if (!fileHasVerify && /\.split\(\s*["']\.["']\s*\)/.test(text) && /base64/i.test(text) && /JSON\.parse/.test(text)) {
        const nameNode = (fn as ts.FunctionDeclaration).name ?? (ts.isVariableDeclaration(fn.parent) ? fn.parent.name : undefined);
        report("jwt-none-alg", nameNode ?? fn,
          "JWT payload is base64-decoded and JSON-parsed by hand and the file never verifies a signature — claims (role, sub, ...) are attacker-controlled; use jwt.verify()/jose",
          "manual JWT decode");
      }
      // dotted-path setter without a prototype guard
      if (!/__proto__|constructor|prototype|hasOwn|Object\.create\(null\)/.test(text)) {
        const splitVars = new Set<string>();
        const collect = (m: ts.Node) => {
          if (m !== fn.body && isFunctionLike(m)) return;
          if (ts.isVariableDeclaration(m) && ts.isIdentifier(m.name) && m.initializer && ts.isCallExpression(m.initializer) &&
              ts.isPropertyAccessExpression(m.initializer.expression) && m.initializer.expression.name.text === "split" &&
              m.initializer.arguments[0] && ts.isStringLiteral(m.initializer.arguments[0]) && m.initializer.arguments[0].text === ".") {
            splitVars.add(m.name.text);
          }
          ts.forEachChild(m, collect);
        };
        collect(fn.body!);
        if (splitVars.size > 0) {
          let hit: ts.Node | null = null;
          const find = (m: ts.Node) => {
            if (hit || (m !== fn.body && isFunctionLike(m))) return;
            if (ts.isBinaryExpression(m) && ts.isElementAccessExpression(m.left) &&
                (m.operatorToken.kind === ts.SyntaxKind.EqualsToken || isCompoundAssign(m.operatorToken.kind))) {
              const ids: string[] = [];
              const grab = (x: ts.Node) => { if (ts.isIdentifier(x)) ids.push(x.text); ts.forEachChild(x, grab); };
              grab(m.left.argumentExpression);
              if (ids.some(id => splitVars.has(id))) hit = m;
            }
            ts.forEachChild(m, find);
          };
          find(fn.body!);
          if (hit) {
            report("prototype-pollution", hit,
              "Dotted-path setter walks user-supplied path segments ('a.b.c') into an object with no __proto__/constructor/prototype guard — a path like '__proto__.isAdmin' pollutes Object.prototype",
              "dotted-path assignment");
          }
        }
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
}

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
    // Module-scope container memory (stored XSS / second-order SQL): taint pushed into a module-level
    // array/Map/object by one handler is visible to every handler that reads it back.
    const sticky = new Map<string, number>();
    let stickyDirty = false;
    const moduleScopeNames = new Set<string>();
    for (const st of sourceFile.statements) {
      if (!ts.isVariableStatement(st)) continue;
      for (const d of st.declarationList.declarations) {
        if (ts.isIdentifier(d.name)) moduleScopeNames.add(d.name.text);
      }
    }
    // `const run = eval;` / `const fn = globalThis[name];` -- aliases of dangerous callees
    const evalAliases = new Set<string>();
    const dynCallAliases = new Map<string, ts.Expression>();
    const collectAliases = (n: ts.Node) => {
      if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
        const init = unwrapExpr(n.initializer);
        if (ts.isIdentifier(init) && init.text === "eval") evalAliases.add(n.name.text);
        else if (ts.isPropertyAccessExpression(init) && init.name.text === "eval" && ts.isIdentifier(init.expression) && GLOBAL_OBJECTS.has(init.expression.text)) evalAliases.add(n.name.text);
        else if (ts.isElementAccessExpression(init)) {
          const obj = unwrapExpr(init.expression);
          if (ts.isIdentifier(obj) && GLOBAL_OBJECTS.has(obj.text)) dynCallAliases.set(n.name.text, init.argumentExpression);
        }
      }
      ts.forEachChild(n, collectAliases);
    };
    collectAliases(sourceFile);
    const taintMask = makeTaintMask(propagating, sticky);
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

    const emit = (id: AstTaintId, node: ts.Node, sourceExpr: string, sinkExpr: string, taintedArgExpr?: ts.Expression, detailOverride?: string) => {
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
        detail: detailOverride ?? `Tainted expression '${sourceExpr}' flows into ${sinkExpr}(...) — real data-flow match, not a line-pattern guess${note}`,
      });
    };

    /** `\`<script>const x = '${escaped}'\``: an HTML-escaped value inside a <script> block is still injectable. */
    const escapedInScriptContext = (arg: ts.Expression, env: Env): boolean => {
      if (!ts.isTemplateExpression(arg)) return false;
      let text = arg.head.text;
      for (const span of arg.templateSpans) {
        const m = taintMask(span.expression, env);
        if (wasCleared(m, classOf("xss")) && /<script\b[^>]*>(?:(?!<\/script>)[\s\S])*$/i.test(text)) return true;
        text += "\u0000" + span.literal.text;
      }
      return false;
    };

    const checkCallForSink = (call: ts.CallExpression, env: Env) => {
      if (ts.isIdentifier(call.expression) && (call.expression.text === "eval" || evalAliases.has(call.expression.text))) {
        emit("eval-exec", call, call.arguments[0] ? sourceLabel(call.arguments[0]) : "eval", call.expression.text, call.arguments[0]);
        return;
      }
      // import(x): loading an attacker-chosen module is code execution
      if (call.expression.kind === ts.SyntaxKind.ImportKeyword && call.arguments[0]) {
        if (taintMask(call.arguments[0], env) & classOf("eval-exec")) {
          emit("eval-exec", call, sourceLabel(call.arguments[0]), "import()", call.arguments[0]);
        }
        return;
      }
      // globalThis[name](...) / const fn = globalThis[name]; fn(...): an attacker-chosen function is invoked
      {
        const callee = unwrapExpr(call.expression);
        let keyExpr: ts.Expression | undefined;
        if (ts.isElementAccessExpression(callee)) {
          const obj = unwrapExpr(callee.expression);
          if (ts.isIdentifier(obj) && GLOBAL_OBJECTS.has(obj.text)) keyExpr = callee.argumentExpression;
        } else if (ts.isIdentifier(callee)) {
          keyExpr = dynCallAliases.get(callee.text);
        }
        if (keyExpr && taintMask(keyExpr, env) & classOf("eval-exec")) {
          emit("eval-exec", call, sourceLabel(keyExpr), "dynamic global function call", keyExpr);
          return;
        }
      }
      const match = matchSink(call, importMap);
      if (!match) return;
      const cls = classOf(match.id);
      let taintedArg: ts.Expression | undefined;
      let cleared = false;
      for (const a of match.args) {
        if (isFunctionExpr(a)) continue; // a callback is not the data reaching the sink
        const m = taintMask(a, env);
        if (m & cls) { taintedArg = a; break; }
        if (wasCleared(m, cls)) cleared = true;
      }
      if (taintedArg) emit(match.id, call, sourceLabel(taintedArg), match.sinkExpr, taintedArg);
      else if (match.id === "xss" && match.args.some(a => escapedInScriptContext(a, env))) {
        const a = match.args.find(x => escapedInScriptContext(x, env))!;
        emit("xss", call, sourceLabel(a), match.sinkExpr, a,
          `HTML-escaped value '${sourceLabel(a)}' is interpolated inside a <script> block — HTML escaping does not neutralize JavaScript string context (a backslash still breaks out)`);
      } else if (cleared) suppressedOut?.push({ id: match.id, line: lineOf(call) });
    };

    const checkNewExprForSink = (node: ts.NewExpression, env: Env) => {
      if (ts.isIdentifier(node.expression) && node.expression.text === "Function") {
        emit("eval-exec", node, "Function(...)", "new Function");
      }
      // new RegExp(userInput): regex injection / ReDoS
      if (ts.isIdentifier(node.expression) && node.expression.text === "RegExp" && node.arguments?.[0]) {
        const a = node.arguments[0];
        if (taintMask(a, env) & ALL) emit("redos", node, sourceLabel(a), "new RegExp", a);
      }
    };

    // Object.assign(new Account(), req.body): the request body decides which fields the object gets
    const checkMassAssignment = (call: ts.CallExpression) => {
      if (calleeText(call.expression) !== "Object.assign" || call.arguments.length < 2) return;
      const target = unwrapExpr(call.arguments[0]);
      if (!ts.isNewExpression(target) && !ts.isIdentifier(target)) return;
      for (const a of call.arguments.slice(1)) {
        const src = unwrapExpr(a);
        if (ts.isPropertyAccessExpression(src) && ts.isIdentifier(src.expression) && SOURCE_ROOTS.has(src.expression.text) &&
            (src.name.text === "body" || src.name.text === "query")) {
          emit("mass-assignment", call, sourceLabel(a), "Object.assign", a,
            `Request object '${sourceLabel(a)}' is copied wholesale onto '${sourceLabel(call.arguments[0])}' via Object.assign — the client decides which properties (role, isAdmin, ...) get set; copy an explicit allowlist of fields`);
          return;
        }
      }
    };

    // secret === untrusted: a non-constant-time comparison is a timing oracle
    const SECRET_NAME_RE = /^(?:secret|token|password|passwd|apikey|api_key|hmac|signature|digest|csrf\w*|\w*_?secret|\w*_?token|\w*_?password|\w*api_?key)$/i;
    const nameOfOperand = (e: ts.Expression): string | null => {
      const u = unwrapExpr(e);
      if (ts.isIdentifier(u)) return u.text;
      if (ts.isPropertyAccessExpression(u)) return u.name.text;
      return null;
    };
    const checkTimingCompare = (node: ts.BinaryExpression, env: Env) => {
      const k = node.operatorToken.kind;
      if (k !== ts.SyntaxKind.EqualsEqualsEqualsToken && k !== ts.SyntaxKind.ExclamationEqualsEqualsToken &&
          k !== ts.SyntaxKind.EqualsEqualsToken && k !== ts.SyntaxKind.ExclamationEqualsToken) return;
      for (const [secretSide, otherSide] of [[node.left, node.right], [node.right, node.left]] as const) {
        const name = nameOfOperand(secretSide);
        if (!name || !SECRET_NAME_RE.test(name)) continue;
        if (isLiteralNode(unwrapExpr(otherSide))) continue;
        if (taintMask(otherSide, env) & ALL) {
          emit("timing-attack", node, sourceLabel(otherSide), "===", otherSide,
            `Secret '${sourceLabel(secretSide)}' is compared to attacker-supplied '${sourceLabel(otherSide)}' with an ordinary equality operator — use crypto.timingSafeEqual`);
          return;
        }
      }
    };

    // Taint written into module-scope containers/variables survives past the handler that wrote it
    const recordSticky = (node: ts.Node, env: Env) => {
      let target: ts.Identifier | null = null;
      let mask = 0;
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && MUTATING_METHODS.has(node.expression.name.text)) {
        target = rootIdentifier(node.expression.expression);
        mask = node.arguments.reduce((m, a) => (isFunctionExpr(a) ? m : m | taintMask(a, env)), 0);
      } else if (ts.isBinaryExpression(node) && (node.operatorToken.kind === ts.SyntaxKind.EqualsToken || isCompoundAssign(node.operatorToken.kind))) {
        target = rootIdentifier(node.left);
        mask = taintMask(node.right, env);
      }
      if (!target || !(mask & ALL) || !moduleScopeNames.has(target.text) || isShadowed(target)) return;
      // only writes made INSIDE a function are cross-request state; top-level init is ordinary flow
      let inFn = false;
      for (let cur: ts.Node | undefined = node.parent; cur; cur = cur.parent) if (isFunctionLike(cur)) { inFn = true; break; }
      if (!inFn) return;
      const next = (sticky.get(target.text) ?? 0) | (mask & ALL);
      if (next !== (sticky.get(target.text) ?? 0)) { sticky.set(target.text, next); stickyDirty = true; }
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

    // Expression-level checks for one node, with the env at that point.
    // (Statement structure, branching and nested functions are the walker's job.)
    const onVisit = (n: ts.Node, env: Env) => {
      if (ts.isCallExpression(n)) {
        checkCallForSink(n, env);
        // Same-file call binding: seed callee params for tainted args, one hop.
        // Matched by INDEX (via paramShapesOf, including rest-param
        // overflow), not by re-deriving positions ad hoc here.
        const seedName = ts.isIdentifier(n.expression) ? n.expression.text
          : ts.isPropertyAccessExpression(n.expression) && localFns.get(n.expression.name.text)?.isMethod &&
            (n.expression.expression.kind === ts.SyntaxKind.ThisKeyword || !BUILTIN_METHOD_NAMES.has(n.expression.name.text))
            ? n.expression.name.text : null;
        if (seedName && localFns.has(seedName)) {
          const fnName = seedName;
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
      if (ts.isCallExpression(n)) { checkMassAssignment(n); recordSticky(n, env); }
      if (ts.isNewExpression(n)) checkNewExprForSink(n, env);
      if (ts.isBinaryExpression(n)) { checkAssignmentForXSS(n, env); checkTimingCompare(n, env); recordSticky(n, env); }
    };

    const walker = createWalker({
      taintMask, sf: sourceFile, descendFunctions: true, onVisit,
      // Tier-2 message-attribution bookkeeping only (see initializerOf's
      // declaration) -- kept separate from applyDeclAndAssign, since the
      // summary builder reuses that function and has no access to this map.
      onStatement: (node) => {
        if (ts.isVariableStatement(node)) {
          for (const decl of node.declarationList.declarations) {
            if (decl.initializer && ts.isIdentifier(decl.name)) initializerOf.set(decl.name.text, decl.initializer);
          }
        }
      },
    });
    const walkStatements = (node: ts.Node, env: Env) => {
      if (ts.isBlock(node) || ts.isSourceFile(node) || ts.isModuleBlock(node)) walker.walkNode(node, env);
      else walker.handleExpr(node, env); // arrow expression body
    };

    walkStatements(sourceFile, new Map());
    // Module-scope containers can be written by a handler declared AFTER the one that reads them:
    // walk again with what the first pass learned (findings dedupe by id+line).
    for (let i = 0; i < 2 && stickyDirty; i++) {
      stickyDirty = false;
      walkStatements(sourceFile, new Map());
    }

    // Function-level patterns that are not source-to-sink flows.
    structuralChecks(sourceFile, content, (id, node, detail, sink) => emit(id, node, sink, sink, undefined, detail));

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
