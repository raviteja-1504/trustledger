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

type Env = Map<string, boolean>;

/**
 * Builds the core taint predicate as a closure over `localFns`/`propagating`
 * so every call site (there are several, scattered through the statement
 * walk below) doesn't need to thread two extra parameters through by hand.
 * `propagating` is the set of local function names whose return value is
 * known (from computeReturnTaintPropagating below) to be tainted whenever a
 * tainted argument is passed in -- this is what makes
 * `exec(buildCommand(host))` resolve correctly: `buildCommand` never calls a
 * sink itself, it just returns a tainted template literal, so without this
 * the call expression `buildCommand(host)` would look untainted from the
 * outside.
 */
function makeIsTainted(localFns: Map<string, LocalFn>, propagating: Set<string>) {
  const isTainted = (expr: ts.Expression, env: Env): boolean => {
    if (ts.isParenthesizedExpression(expr)) return isTainted(expr.expression, env);
    if (isTaintSourceExpr(expr)) return true;
    if (ts.isIdentifier(expr)) return env.get(expr.text) === true;
    if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return isTainted(expr.left, env) || isTainted(expr.right, env);
    }
    if (ts.isTemplateExpression(expr)) return expr.templateSpans.some(s => isTainted(s.expression, env));
    if (ts.isSpreadElement(expr)) return isTainted(expr.expression, env);
    if (ts.isArrayLiteralExpression(expr)) return expr.elements.some(e => isTainted(e, env));
    if (ts.isObjectLiteralExpression(expr)) {
      return expr.properties.some(p => ts.isPropertyAssignment(p) && isTainted(p.initializer, env));
    }
    if (ts.isCallExpression(expr)) {
      // A call to a local function known to propagate taint from its
      // params to its return value -- e.g. buildCommand(host) where
      // buildCommand(h) { return `ping -c1 ${h}`; }.
      if (ts.isIdentifier(expr.expression) && propagating.has(expr.expression.text)) {
        return expr.arguments.some(a => isTainted(a, env));
      }
      // Passthrough for a method call on an already-tainted receiver
      // (.trim()/.toLowerCase()/.toString()/etc.) -- same "propagate through
      // anything referencing a tainted value" recall bias already
      // established in extractTaintedVars' second-hop rule (scanner.ts),
      // not a claim that every such method is unsafe on its own.
      if (ts.isPropertyAccessExpression(expr.expression)) return isTainted(expr.expression.expression, env);
    }
    if (ts.isAsExpression(expr) || ts.isNonNullExpression(expr)) return isTainted(expr.expression, env);
    return false;
  };
  return isTainted;
}

/**
 * Does `fn`'s return value end up tainted whenever ALL of its parameters
 * are tainted? A deliberately simple over-approximation (real per-param
 * dependency isn't tracked) -- if the return only actually depends on a
 * subset of params, seeding all of them still correctly detects it as
 * propagating; it just can't say *which* params matter, so a call site is
 * treated as tainted if ANY argument is tainted (see makeIsTainted above).
 * Nested calls inside `fn`'s own body are deliberately treated as opaque
 * here (empty localFns/propagating) to keep this a bounded, non-recursive
 * single pass rather than a mutual-recursion risk between functions that
 * call each other.
 */
function computeReturnTaintPropagating(fn: LocalFn): boolean {
  const env: Env = new Map();
  fn.params.forEach(p => { if (ts.isIdentifier(p.name)) env.set(p.name.text, true); });
  const isTaintedShallow = makeIsTainted(new Map(), new Set());
  if (!ts.isBlock(fn.body)) return isTaintedShallow(fn.body as ts.Expression, env); // arrow expression body
  let found = false;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isReturnStatement(n) && n.expression && isTaintedShallow(n.expression, env)) { found = true; return; }
    ts.forEachChild(n, visit);
  };
  visit(fn.body);
  return found;
}

function sourceLabel(expr: ts.Expression): string {
  return expr.getText().replace(/\s+/g, " ").slice(0, 60);
}

interface LocalFn { params: ts.NodeArray<ts.ParameterDeclaration>; body: ts.Node }

function collectLocalFunctions(sourceFile: ts.SourceFile): Map<string, LocalFn> {
  const fns = new Map<string, LocalFn>();
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name && node.body) {
      fns.set(node.name.text, { params: node.parameters, body: node.body });
    }
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const init = node.initializer;
      if ((ts.isArrowFunction(init) || ts.isFunctionExpression(init)) && init.body) {
        fns.set(node.name.text, { params: init.parameters, body: init.body });
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sourceFile, visit);
  return fns;
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
 */
export function scanAstTaint(content: string, filePath: string, presparsed?: ts.SourceFile): AstTaintFinding[] {
  try {
    const sourceFile = presparsed ?? parseSourceFile(content, filePath);
    const importMap = buildImportMap(sourceFile);
    const localFns = collectLocalFunctions(sourceFile);
    const propagating = new Set<string>();
    for (const [name, fn] of localFns) if (computeReturnTaintPropagating(fn)) propagating.add(name);
    const isTainted = makeIsTainted(localFns, propagating);
    const seededParams = new Map<string, Set<string>>(); // fn name -> tainted param names
    const findings: AstTaintFinding[] = [];
    const seen = new Set<string>();

    const lineOf = (node: ts.Node): number =>
      sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;

    const emit = (id: AstTaintId, node: ts.Node, sourceExpr: string, sinkExpr: string) => {
      const line = lineOf(node);
      const key = `${id}:${line}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({
        id, line, sinkExpr, sourceExpr,
        detail: `Tainted expression '${sourceExpr}' flows into ${sinkExpr}(...) — real data-flow match, not a line-pattern guess`,
      });
    };

    const checkCallForSink = (call: ts.CallExpression, env: Env) => {
      if (ts.isIdentifier(call.expression) && call.expression.text === "eval") {
        emit("eval-exec", call, call.arguments[0] ? sourceLabel(call.arguments[0]) : "eval", "eval");
        return;
      }
      const match = matchSink(call, importMap);
      if (!match) return;
      const taintedArg = match.args.find(a => isTainted(a, env));
      if (taintedArg) emit(match.id, call, sourceLabel(taintedArg), match.sinkExpr);
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
      if ((prop === "innerHTML" || prop === "outerHTML") && isTainted(node.right, env)) {
        emit("xss", node, sourceLabel(node.right), `.${prop}`);
      }
    };

    const walkStatements = (node: ts.Node, env: Env) => {
      // Variable declarations / destructuring
      if (ts.isVariableStatement(node)) {
        for (const decl of node.declarationList.declarations) {
          if (!decl.initializer) continue;
          const tainted = isTainted(decl.initializer, env);
          if (ts.isIdentifier(decl.name)) {
            env.set(decl.name.text, tainted);
          } else if (ts.isObjectBindingPattern(decl.name) && tainted) {
            for (const el of decl.name.elements) {
              if (ts.isIdentifier(el.name)) env.set(el.name.text, true);
            }
          }
        }
      } else if (
        ts.isExpressionStatement(node) && ts.isBinaryExpression(node.expression) &&
        node.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isIdentifier(node.expression.left)
      ) {
        // Simple reassignment (x = expr) updates env before any nested sink
        // check below reads it. The XSS-assignment check itself (obj.prop =
        // expr) is handled uniformly by the generic visitExpr traversal
        // below, which visits this same binary expression as a child of
        // `node` -- no need to special-case it here too.
        env.set(node.expression.left.text, isTainted(node.expression.right, env));
      }

      // Sink checks: any call/new expression anywhere in this node
      const visitExpr = (n: ts.Node) => {
        if (ts.isCallExpression(n)) {
          checkCallForSink(n, env);
          // Same-file call binding: seed callee params for tainted args, one hop
          if (ts.isIdentifier(n.expression) && localFns.has(n.expression.text)) {
            const fnName = n.expression.text;
            const fn = localFns.get(fnName)!;
            const taintedIdx = new Set<string>();
            n.arguments.forEach((arg, i) => {
              if (isTainted(arg, env) && fn.params[i] && ts.isIdentifier(fn.params[i].name)) {
                taintedIdx.add((fn.params[i].name as ts.Identifier).text);
              }
            });
            if (taintedIdx.size > 0) {
              const existing = seededParams.get(fnName) ?? new Set<string>();
              taintedIdx.forEach(p => existing.add(p));
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

    // Second pass: re-walk any local function whose parameters were seeded
    // as tainted by a call site above, so sinks inside the callee are reachable.
    for (const [fnName, params] of seededParams) {
      const fn = localFns.get(fnName);
      if (!fn) continue;
      const env: Env = new Map();
      params.forEach(p => env.set(p, true));
      walkStatements(fn.body, env);
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
