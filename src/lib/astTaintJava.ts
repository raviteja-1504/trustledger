/**
 * Real AST-based taint engine for Java — Phase 3 (final language) of the
 * multi-language OWASP Top 10 hardening effort (see astTaint.ts for Phase 1
 * / JS-TS and astTaintPython.ts for Phase 2 / Python, whose five-stage
 * architecture -- sources, propagation, interprocedural, sinks, findings --
 * this file mirrors, adapted to java-parser's Concrete Syntax Tree).
 *
 * Uses `java-parser` (Chevrotain-based, pure JavaScript, no native/WASM
 * binary anywhere in its dependency tree -- confirmed directly against the
 * downloaded package). `parse()` is fully SYNCHRONOUS, unlike Phase 2's
 * web-tree-sitter -- there is no warm-cache pattern, no instrumentation.ts
 * hook, and no next.config.mjs tracing entry needed here, because there is
 * no binary asset to mis-bundle/mis-trace/mis-resolve in the first place.
 *
 * The one real ergonomics wrinkle (confirmed by direct parsing, not
 * assumed): a Java call chain like `sb.append(x).append(y)` or
 * `Runtime.getRuntime().exec(cmd)` is a single `primary` CST node whose
 * `primarySuffix` is a FLAT array, not a naturally-recursive structure the
 * way TypeScript's PropertyAccessExpression or tree-sitter's `attribute`
 * nodes are. The grammar also greedily absorbs a leading dotted name
 * (`Runtime.getRuntime`, `request.getParameter`, `String.format`,
 * `sb.append`) into `primaryPrefix.fqnOrRefType` itself -- the first call in
 * a chain has NO separate Dot/Identifier primarySuffix entry, only later
 * chain links do. `walkPrimaryChain` below is a left-to-right fold over
 * `primarySuffix` that threads a running taint state and an accumulated
 * dotted-name array forward, handling both cases uniformly.
 *
 * Runs ADDITIVELY alongside every existing Java regex/taint-proximity
 * detector in scanner.ts, not as a replacement. Reuses existing finding ids
 * (sql-injection, command-injection, xss, ssrf, path-traversal,
 * open-redirect, insecure-deserialization, ldap-injection, xpath-injection)
 * -- confirmed all already wired through cweMap.ts/SIGNAL_META/
 * githubComment.ts/violations page/sarif.ts, so no new UI wiring is needed.
 * Deliberately excludes (stays regex-only, same posture as Phase 2 keeping
 * pickle/yaml and BOLA regex-only): XXE, weak crypto, cookie security,
 * CSRF-disabled, weak CORS, verbose errors, insecure randomness -- all
 * flag/hardening-absence checks, not real data-flow questions. Also
 * explicitly out of scope: SpEL injection (no existing coverage or fixture
 * to validate a new regex against), Spring Boot actuator/debug misconfig
 * (a .properties/.yml flag check, a different `lang` branch entirely),
 * insecure file upload (MultipartFile), TOCTOU.
 */

import { parse } from "java-parser";
import type { CstNode, IToken, CstElement } from "java-parser";

export type AstTaintJavaId =
  | "sql-injection" | "command-injection" | "xss" | "ssrf" | "path-traversal"
  | "open-redirect" | "insecure-deserialization" | "ldap-injection" | "xpath-injection";

export interface AstTaintJavaFinding {
  id:         AstTaintJavaId;
  line:       number;
  detail:     string;
  sourceExpr: string;
  sinkExpr:   string;
}

export function parseJavaSource(content: string): CstNode | null {
  try {
    return parse(content);
  } catch (err) {
    console.error("[astTaintJava] parse threw:", err);
    return null;
  }
}

// ── Generic CST helpers ──────────────────────────────────────────────────

function isToken(el: CstElement): el is IToken {
  return "image" in el;
}
function kids(node: CstNode, key: string): CstElement[] {
  return node.children[key] ?? [];
}
// CstElement's non-token members are a discriminated union of specific,
// literal-`name`-typed *CstNode variants (MethodDeclarationCstNode etc.),
// which don't structurally widen to the generic CstNode interface used
// throughout this file -- an explicit cast is required (safe: everything
// that isn't an IToken in this CST is a node with .name/.children/.location).
function nodeKids(node: CstNode, key: string): CstNode[] {
  return kids(node, key).filter(e => !isToken(e)).map(e => e as unknown as CstNode);
}
function tokenKids(node: CstNode, key: string): IToken[] {
  return kids(node, key).filter(isToken);
}
function firstNode(node: CstNode, key: string): CstNode | undefined {
  return nodeKids(node, key)[0];
}
function firstTok(node: CstNode, key: string): IToken | undefined {
  return tokenKids(node, key)[0];
}
function allNodes(node: CstNode, key: string): CstNode[] {
  return nodeKids(node, key);
}

/** Deepest-first search for every node of a given CST production name, anywhere below `root`. */
function findAllNodes(root: CstNode, name: string, acc: CstNode[] = []): CstNode[] {
  for (const key of Object.keys(root.children)) {
    for (const el of root.children[key]) {
      if (isToken(el)) continue;
      if (el.name === name) acc.push(el);
      findAllNodes(el, name, acc);
    }
  }
  return acc;
}

/** Leftmost token anywhere under `node`, by lowest startOffset -- used to resolve a finding's line number. */
function leftmostToken(node: CstNode): IToken | null {
  let best: IToken | null = null;
  const visit = (n: CstNode) => {
    for (const key of Object.keys(n.children)) {
      for (const el of n.children[key]) {
        if (isToken(el)) {
          if (!best || el.startOffset < best.startOffset) best = el;
        } else {
          visit(el);
        }
      }
    }
  };
  visit(node);
  return best;
}
function lineOf(node: CstNode): number {
  return leftmostToken(node)?.startLine ?? 0;
}

function nodeText(node: CstNode): string {
  const tok = leftmostToken(node);
  return tok ? tok.image : "";
}

/** If `node` resolves to a bare string literal (possibly through the usual expression/primary wrapper chain), its unquoted value -- else null. */
function stringLiteralValue(node: CstNode): string | null {
  const literals = findAllNodes(node, "literal");
  for (const lit of literals) {
    const tok = firstTok(lit, "StringLiteral");
    if (tok) return tok.image.slice(1, -1);
  }
  return null;
}

// ── Taint sources ─────────────────────────────────────────────────────────

const SPRING_SOURCE_ANNOTATIONS = new Set(["PathVariable", "RequestParam", "RequestBody", "RequestHeader"]);
const SERVLET_SOURCE_CALLS = new Set(["getParameter", "getHeader", "getParameterValues", "getQueryString"]);

// ── Environment ──────────────────────────────────────────────────────────

type Env = Map<string, boolean>;
type VarTypes = Map<string, string>; // local var name -> declared type's simple name (e.g. "ObjectInputStream")

interface LocalMethod {
  name: string;
  paramNames: string[];
  springParamNames: Set<string>;
  body: CstNode | null; // methodBody
}

/**
 * Extracts a formal parameter's own declared name, threading through the
 * grammar's `variableParaRegularParameter` wrapper (varargs/receiver-param
 * forms are skipped -- a deliberate simplification, matching the
 * "over-approximation over precision" posture already established).
 */
function paramInfo(fp: CstNode): { name: string; annotations: string[] } | null {
  const vp = firstNode(fp, "variableParaRegularParameter");
  if (!vp) return null;
  const declId = firstNode(vp, "variableDeclaratorId");
  const nameTok = declId ? firstTok(declId, "Identifier") : undefined;
  if (!nameTok) return null;
  const annotations: string[] = [];
  for (const vm of allNodes(vp, "variableModifier")) {
    for (const ann of allNodes(vm, "annotation")) {
      const typeName = firstNode(ann, "typeName");
      if (!typeName) continue;
      const idToks = tokenKids(typeName, "Identifier");
      const last = idToks[idToks.length - 1];
      if (last) annotations.push(last.image);
    }
  }
  return { name: nameTok.image, annotations };
}

function extractMethodInfo(methodDecl: CstNode): LocalMethod | null {
  const header = firstNode(methodDecl, "methodHeader");
  if (!header) return null;
  const declarator = firstNode(header, "methodDeclarator");
  if (!declarator) return null;
  const nameTok = firstTok(declarator, "Identifier");
  if (!nameTok) return null;
  const paramNames: string[] = [];
  const springParamNames = new Set<string>();
  const fpl = firstNode(declarator, "formalParameterList");
  if (fpl) {
    for (const fp of allNodes(fpl, "formalParameter")) {
      const info = paramInfo(fp);
      if (!info) continue;
      paramNames.push(info.name);
      if (info.annotations.some(a => SPRING_SOURCE_ANNOTATIONS.has(a))) springParamNames.add(info.name);
    }
  }
  const body = firstNode(methodDecl, "methodBody") ?? null;
  return { name: nameTok.image, paramNames, springParamNames, body };
}

/**
 * Indexes methods by BARE NAME ONLY -- Java overload resolution (matching a
 * call site to the specific overload by argument types) is not modeled.
 * If a class declares multiple overloads sharing a name, whichever is
 * encountered last during this single top-to-bottom walk wins the map
 * entry, and every call site to that name shares its propagation profile.
 * A deliberate over-approximation, consistent with Phase 1/2's own
 * bare-name interprocedural policy (astTaint.ts's collectLocalFunctions,
 * astTaintPython.ts's collectLocalFunctionsPy) -- not a precision claim.
 */
function collectLocalMethods(root: CstNode): Map<string, LocalMethod> {
  const methods = new Map<string, LocalMethod>();
  for (const methodDecl of findAllNodes(root, "methodDeclaration")) {
    const info = extractMethodInfo(methodDecl);
    if (info) methods.set(info.name, info);
  }
  return methods;
}

// ── Sink table ───────────────────────────────────────────────────────────

const SEVERITY: Record<AstTaintJavaId, "critical" | "high" | "medium"> = {
  "sql-injection": "critical", "command-injection": "critical", "xss": "critical",
  "ssrf": "critical", "path-traversal": "critical", "insecure-deserialization": "critical",
  "ldap-injection": "critical", "xpath-injection": "critical", "open-redirect": "medium",
};
const LABEL: Record<AstTaintJavaId, string> = {
  "sql-injection": "SQL Injection", "command-injection": "Command Injection", "xss": "Reflected XSS",
  "ssrf": "Server-Side Request Forgery", "path-traversal": "Path Traversal",
  "insecure-deserialization": "Insecure Deserialization", "ldap-injection": "LDAP Injection",
  "xpath-injection": "XPath Injection", "open-redirect": "Open Redirect",
};

const HTML_TAG_RE = /<[a-z][\s\S]*?>/i;

/** Mirrors findReflectedXSSTainted's own corroboration requirement (scanner.ts) -- a bare `.body(x)` returning JSON is not itself dangerous. */
function hasHtmlTagNearby(lines: string[], line: number, window = 8): boolean {
  const start = Math.max(0, line - window);
  for (let i = start; i < Math.min(lines.length, line); i++) {
    if (HTML_TAG_RE.test(lines[i])) return true;
  }
  return false;
}

// ── Core engine ──────────────────────────────────────────────────────────

interface EngineCtx {
  content: string;
  lines: string[];
  localMethods: Map<string, LocalMethod>;
  propagating: Set<string>;
  varTypes: VarTypes;
  findings: AstTaintJavaFinding[];
  seen: Set<string>;
}

function emit(ctx: EngineCtx, id: AstTaintJavaId, node: CstNode, sourceExpr: string, sinkExpr: string) {
  const line = lineOf(node);
  const key = `${id}:${line}`;
  if (ctx.seen.has(key)) return;
  ctx.seen.add(key);
  ctx.findings.push({
    id, line, sinkExpr, sourceExpr,
    detail: `Tainted expression '${sourceExpr}' flows into ${sinkExpr}(...) — real data-flow match, not a line-pattern guess`,
  });
}

/**
 * Extracts primaryPrefix's dotted-name parts, taint basis, and (if
 * applicable) which local variable this primary's chain is rooted at --
 * needed both to seed the primarySuffix fold below and, for the
 * `.append()` idiom, to propagate taint back onto the receiver variable
 * itself so a LATER, separate `sb.toString()` statement also resolves as
 * tainted (Java commonly builds a StringBuilder across several statements,
 * not as one fluent chain).
 */
/**
 * `classOrInterfaceTypeToInstantiate` is a CST NODE (not a token) whose own
 * `Identifier` child(ren) carry the actual class name -- confirmed directly
 * by parsing `new ObjectInputStream(...)` and inspecting the real tree,
 * since this is exactly the kind of indirection that looks obvious but
 * isn't (the node's name reads as if it might just BE the identifier).
 * Takes the last Identifier for a qualified/generic name.
 */
function extractInstantiatedClassName(uc: CstNode): string | null {
  const classNode = firstNode(uc, "classOrInterfaceTypeToInstantiate");
  if (!classNode) return null;
  const ids = tokenKids(classNode, "Identifier");
  return ids[ids.length - 1]?.image ?? null;
}

function primaryPrefixInfo(prefix: CstNode, env: Env, ctx: EngineCtx):
  { parts: string[]; taint: boolean; rootVar: string | null; isNewExprOf: string | null } {
  const fqn = firstNode(prefix, "fqnOrRefType");
  if (fqn) {
    const parts: string[] = [];
    const first = firstNode(fqn, "fqnOrRefTypePartFirst");
    const firstCommon = first ? firstNode(first, "fqnOrRefTypePartCommon") : undefined;
    const firstId = firstCommon ? firstTok(firstCommon, "Identifier") : undefined;
    if (firstId) parts.push(firstId.image);
    for (const rest of allNodes(fqn, "fqnOrRefTypePartRest")) {
      const restCommon = firstNode(rest, "fqnOrRefTypePartCommon");
      const restId = restCommon ? firstTok(restCommon, "Identifier") : undefined;
      if (restId) parts.push(restId.image);
    }
    const rootVar = parts[0] ?? null;
    const taint = rootVar !== null && env.get(rootVar) === true;
    return { parts, taint, rootVar, isNewExprOf: null };
  }
  const newExpr = firstNode(prefix, "newExpression");
  if (newExpr) {
    const uc = firstNode(newExpr, "unqualifiedClassInstanceCreationExpression");
    const className = uc ? extractInstantiatedClassName(uc) : null;
    const argList = uc ? firstNode(uc, "argumentList") : undefined;
    const args = argList ? allNodes(argList, "expression") : [];
    const taint = args.some(a => isTainted(a, env, ctx));
    return { parts: className ? [className] : [], taint, rootVar: null, isNewExprOf: className };
  }
  const paren = firstNode(prefix, "parenthesisExpression");
  if (paren) {
    const inner = firstNode(paren, "expression");
    return { parts: [], taint: inner ? isTainted(inner, env, ctx) : false, rootVar: null, isNewExprOf: null };
  }
  return { parts: [], taint: false, rootVar: null, isNewExprOf: null };
}

/**
 * Left-to-right fold over `primary`'s flat `primarySuffix` array (see the
 * module docblock for why this must be a fold, not recursion). Always
 * performs its own internal taint bookkeeping (source recognition,
 * append/format propagation, generic sticky passthrough) regardless of
 * `onCall`; `onCall` is an optional side-channel for sink-matching so the
 * SAME fold serves both the pure `isTainted()` predicate and the separate
 * sink-emitting tree walk, without maintaining two parallel implementations.
 */
function walkPrimaryChain(
  primary: CstNode, env: Env, ctx: EngineCtx,
  onCall?: (info: { calleeName: string; tail: string; rootVar: string | null; args: CstNode[]; chainTaintBefore: boolean; node: CstNode; isNewURL: boolean }) => void,
): boolean {
  const prefix = firstNode(primary, "primaryPrefix");
  if (!prefix) return false;
  const { parts, taint: prefixTaint, rootVar, isNewExprOf } = primaryPrefixInfo(prefix, env, ctx);
  let chainTaint = prefixTaint;
  let nameParts = [...parts];
  const isNewURL = isNewExprOf === "URL";

  for (const suffix of allNodes(primary, "primarySuffix")) {
    const dotId = firstTok(suffix, "Identifier");
    const hasDot = tokenKids(suffix, "Dot").length > 0;
    const invocation = firstNode(suffix, "methodInvocationSuffix");

    if (hasDot && dotId && !invocation) {
      // A `.identifier` link with no immediate call -- extends the name for the NEXT call.
      nameParts = [dotId.image];
      continue;
    }
    if (invocation) {
      const argList = firstNode(invocation, "argumentList");
      const args = argList ? allNodes(argList, "expression") : [];
      const tail = nameParts[nameParts.length - 1] ?? "";
      const calleeName = nameParts.join(".");
      const chainTaintBefore = chainTaint;
      const anyArgTainted = args.some(a => isTainted(a, env, ctx));

      // Servlet API source: request.getParameter/getHeader/getParameterValues/getQueryString.
      if (rootVar === "request" && SERVLET_SOURCE_CALLS.has(tail)) {
        chainTaint = true;
      }
      // StringBuilder/StringBuffer .append() -- sticky, and propagate back onto the receiver variable.
      if (tail === "append") {
        chainTaint = chainTaint || anyArgTainted;
        if (rootVar) env.set(rootVar, (env.get(rootVar) === true) || chainTaint);
      }
      // String.format(...) / "...".formatted(...) -- closes a real, confirmed gap.
      if (tail === "format" || tail === "formatted") {
        chainTaint = chainTaint || anyArgTainted;
      }
      // Same-file interprocedural, one hop: a call to a local method whose
      // return value is known (computeReturnTaintPropagatingJava) to be
      // tainted whenever a tainted argument is passed in -- e.g.
      // executeQuery(buildQuery(uid)) where buildQuery merely returns a
      // tainted concatenation and never calls a sink itself.
      if (ctx.propagating.has(tail) && anyArgTainted) {
        chainTaint = true;
      }

      onCall?.({ calleeName, tail, rootVar, args, chainTaintBefore, node: suffix, isNewURL });

      // Generic passthrough: any other call keeps existing chain taint sticky
      // (a normal method's return isn't assumed tainted just because some
      // unrelated argument was, mirroring astTaint.ts's own passthrough rule).
      nameParts = [];
      continue;
    }
  }
  return chainTaint;
}

function isTainted(node: CstNode, env: Env, ctx: EngineCtx): boolean {
  switch (node.name) {
    case "primary":
      return walkPrimaryChain(node, env, ctx);
    case "binaryExpression": {
      const operands = allNodes(node, "unaryExpression");
      const ops = tokenKids(node, "BinaryOperator");
      // Chevrotain flattens the whole precedence chain (+, comparisons,
      // instanceof, ...) into ONE binaryExpression production -- including
      // the degenerate case of a single non-binary operand (a bare `id`
      // reference parses as binaryExpression{unaryExpression:[id]} with
      // ZERO operator tokens, confirmed directly; this is not an edge case,
      // it's the common shape for anything that isn't a real `+`/comparison
      // chain). Only a present, non-"+" operator (comparison, instanceof,
      // bitwise) should block propagation -- no operator at all means this
      // is just a wrapper and MUST still recurse into its one operand.
      if (ops.length > 0 && !ops.some(t => t.image === "+")) return false;
      return operands.some(o => isTainted(o, env, ctx));
    }
    case "literal":
      return false;
    default: {
      // Generic fallback for the many transparent wrapper productions
      // (expression, conditionalExpression, unaryExpression, argumentList's
      // own expression wrapper, etc.) -- confirmed by direct parsing that
      // these nest as `expression -> conditionalExpression -> binaryExpression
      // -> unaryExpression -> primary` with no other meaningful content, so
      // recursing into every CstNode child and OR-combining is both correct
      // and avoids hand-enumerating each wrapper type. Deliberately
      // permissive (never de-taints), matching the "accept some imprecision
      // for recall" philosophy established in astTaint.ts.
      for (const key of Object.keys(node.children)) {
        for (const el of node.children[key]) {
          if (!isToken(el) && isTainted(el, env, ctx)) return true;
        }
      }
      return false;
    }
  }
}

// ── Sink dispatch (invoked via walkPrimaryChain's onCall side-channel) ────

function checkCallSink(info: { calleeName: string; tail: string; rootVar: string | null; args: CstNode[]; chainTaintBefore: boolean; node: CstNode; isNewURL: boolean }, env: Env, ctx: EngineCtx) {
  const { tail, rootVar, args, chainTaintBefore, node, calleeName } = info;
  const taintedArg = args.find(a => isTainted(a, env, ctx));
  const tainted = chainTaintBefore || !!taintedArg;
  const sourceExpr = taintedArg ? nodeText(taintedArg) : calleeName;

  if (tainted) {
    if (tail === "executeQuery" || tail === "executeUpdate" || tail === "execute") {
      emit(ctx, "sql-injection", node, sourceExpr, calleeName);
    } else if ((tail === "query" || tail === "update") && /jdbcTemplate/i.test(rootVar ?? "")) {
      emit(ctx, "sql-injection", node, sourceExpr, calleeName);
    } else if (tail === "exec" && rootVar !== null) {
      emit(ctx, "command-injection", node, sourceExpr, calleeName);
    } else if (tail === "sendRedirect") {
      emit(ctx, "open-redirect", node, sourceExpr, calleeName);
    } else if (tail === "header" && args.length >= 2 && /^location$/i.test(stringLiteralValue(args[0]) ?? "") && isTainted(args[1], env, ctx)) {
      // Spring's fluent ResponseEntity.status(...).header("Location", next).build()
      // -- a modern REST idiom for redirects, distinct from the classic
      // Servlet response.sendRedirect(...) above but an equally real sink.
      emit(ctx, "open-redirect", node, nodeText(args[1]), calleeName);
    } else if (tail === "getForObject" || tail === "postForObject" || tail === "exchange") {
      emit(ctx, "ssrf", node, sourceExpr, calleeName);
    } else if (info.isNewURL && (tail === "openConnection" || tail === "openStream")) {
      emit(ctx, "ssrf", node, sourceExpr, calleeName);
    } else if (tail === "get" && rootVar === "Paths") {
      emit(ctx, "path-traversal", node, sourceExpr, calleeName);
    } else if (rootVar === "Files" && ["readString", "readAllBytes", "write", "newInputStream", "newOutputStream", "delete"].includes(tail)) {
      emit(ctx, "path-traversal", node, sourceExpr, calleeName);
    } else if (tail === "search") {
      emit(ctx, "ldap-injection", node, sourceExpr, calleeName);
    } else if (tail === "evaluate") {
      emit(ctx, "xpath-injection", node, sourceExpr, calleeName);
    } else if (tail === "body" && hasHtmlTagNearby(ctx.lines, lineOf(node))) {
      emit(ctx, "xss", node, sourceExpr, calleeName);
    }
  }

  // Insecure deserialization: <var>.readObject() where <var> was declared
  // ObjectInputStream-typed and its OWN construction was built from tainted
  // data (tracked via env at the localVariableDeclaration site below).
  if (tail === "readObject" && rootVar && ctx.varTypes.get(rootVar) === "ObjectInputStream" && env.get(rootVar) === true) {
    emit(ctx, "insecure-deserialization", node, rootVar, "readObject");
  }
}

/** `new ProcessBuilder(...)`/`new File(...)`/`new FileInputStream(...)`/`new FileOutputStream(...)` -- the constructor call itself is the sink, no chained method needed. */
function checkNewExpressionSink(prefix: CstNode, env: Env, ctx: EngineCtx, primaryNode: CstNode) {
  const newExpr = firstNode(prefix, "newExpression");
  if (!newExpr) return;
  const uc = firstNode(newExpr, "unqualifiedClassInstanceCreationExpression");
  if (!uc) return;
  const className = extractInstantiatedClassName(uc);
  if (!className) return;
  const argList = firstNode(uc, "argumentList");
  const args = argList ? allNodes(argList, "expression") : [];
  const taintedArg = args.find(a => isTainted(a, env, ctx));
  if (!taintedArg) return;
  const sourceExpr = nodeText(taintedArg);
  if (className === "ProcessBuilder") emit(ctx, "command-injection", primaryNode, sourceExpr, "new ProcessBuilder");
  if (className === "File" || className === "FileInputStream" || className === "FileOutputStream") {
    emit(ctx, "path-traversal", primaryNode, sourceExpr, `new ${className}`);
  }
}

/** Same-file interprocedural: does `method`'s return value end up tainted whenever ALL of its params are tainted? Mirrors computeReturnTaintPropagating(Py) exactly. */
function computeReturnTaintPropagatingJava(method: LocalMethod, ctx: EngineCtx): boolean {
  if (!method.body) return false;
  const env: Env = new Map();
  method.paramNames.forEach(p => env.set(p, true));
  const shallowCtx: EngineCtx = { ...ctx, localMethods: new Map(), propagating: new Set() };
  let found = false;
  for (const ret of findAllNodes(method.body, "returnStatement")) {
    const expr = firstNode(ret, "expression");
    if (expr && isTainted(expr, env, shallowCtx)) { found = true; break; }
  }
  return found;
}

// ── Statement-level walk (declarations + generic sink-visiting descent) ───

function walkForDeclarationsAndSinks(node: CstNode, env: Env, ctx: EngineCtx) {
  if (node.name === "localVariableDeclaration") {
    // unannType -> unannReferenceType -> unannClassOrInterfaceType ->
    // unannClassType -> Identifier[] -- the simple type name is several
    // wrapper layers deep, not a direct child of unannType.
    const typeNode = firstNode(node, "localVariableType");
    const unannType = typeNode ? firstNode(typeNode, "unannType") : undefined;
    const unannClassType = unannType ? findAllNodes(unannType, "unannClassType")[0] : undefined;
    const declaredTypeSimpleName = unannClassType
      ? tokenKids(unannClassType, "Identifier").pop()?.image
      : undefined;

    const vdl = firstNode(node, "variableDeclaratorList");
    for (const vd of vdl ? allNodes(vdl, "variableDeclarator") : []) {
      const declId = firstNode(vd, "variableDeclaratorId");
      const nameTok = declId ? firstTok(declId, "Identifier") : undefined;
      if (!nameTok) continue;
      const init = firstNode(vd, "variableInitializer");
      const initExpr = init ? firstNode(init, "expression") : undefined;
      const tainted = initExpr ? isTainted(initExpr, env, ctx) : false;
      env.set(nameTok.image, tainted);
      if (declaredTypeSimpleName) ctx.varTypes.set(nameTok.image, declaredTypeSimpleName);
    }
  }

  // Sink-visiting: every `primary` anywhere is a candidate call-chain root.
  if (node.name === "primary") {
    const prefix = firstNode(node, "primaryPrefix");
    if (prefix) checkNewExpressionSink(prefix, env, ctx, node);
    walkPrimaryChain(node, env, ctx, (info) => checkCallSink(info, env, ctx));
  }

  for (const key of Object.keys(node.children)) {
    for (const el of node.children[key]) {
      if (!isToken(el)) walkForDeclarationsAndSinks(el, env, ctx);
    }
  }
}

// ── Entry point ──────────────────────────────────────────────────────────

export function scanAstTaintJava(content: string, filePath: string, cst: CstNode): AstTaintJavaFinding[] {
  try {
    const lines = content.split("\n");
    const localMethods = collectLocalMethods(cst);
    const ctx: EngineCtx = {
      content, lines, localMethods, propagating: new Set(), varTypes: new Map(),
      findings: [], seen: new Set(),
    };
    for (const [name, method] of localMethods) {
      if (computeReturnTaintPropagatingJava(method, ctx)) ctx.propagating.add(name);
    }

    for (const [, method] of localMethods) {
      if (!method.body) continue;
      const env: Env = new Map();
      // Only Spring-annotated params are true sources at method entry --
      // an un-annotated parameter is not automatically tainted (unlike the
      // interprocedural pre-pass above, which deliberately seeds ALL params
      // to answer a different, broader question).
      method.springParamNames.forEach(p => env.set(p, true));
      walkForDeclarationsAndSinks(method.body, env, ctx);
    }
    void filePath;
    return ctx.findings;
  } catch (err) {
    console.error(`[astTaintJava] threw scanning ${filePath}:`, err);
    return [];
  }
}

export function astTaintJavaSeverity(id: AstTaintJavaId): "critical" | "high" | "medium" {
  return SEVERITY[id];
}
export function astTaintJavaLabel(id: AstTaintJavaId): string {
  return LABEL[id];
}
