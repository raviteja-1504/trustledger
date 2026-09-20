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
  | "open-redirect" | "insecure-deserialization" | "ldap-injection" | "xpath-injection"
  | "bola-missing-ownership-check";

export interface AstTaintJavaFinding {
  id:         AstTaintJavaId;
  line:       number;
  detail:     string;
  sourceExpr: string;
  sinkExpr:   string;
  // Only set for bola-missing-ownership-check (read vs write endpoint
  // severity) -- every other id keeps using the constant SEVERITY table.
  severityOverride?: "critical" | "high" | "medium";
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

// ── Sanitizer/de-taint recognition ──────────────────────────────────────
// Matched by method-name TAIL alone, same permissive-by-design posture as
// the existing `tail === "format"` check below -- any receiver. Covers the
// three real Java escaping libraries: OWASP Java Encoder (Encode.forHtml/
// forHtmlAttribute/forHtmlContent/forJavaScript/forUriComponent), ESAPI
// (encodeForHTML/encodeForJavaScript), and Commons Text/Lang
// (escapeHtml4/escapeHtml3). See astTaint.ts's SANITIZER_NAMES for the
// JS/TS equivalent this mirrors.
const JAVA_SANITIZER_TAILS = new Set([
  "forHtml", "forHtmlAttribute", "forHtmlContent", "forJavaScript", "forUriComponent",
  "encodeForHTML", "encodeForJavaScript",
  "escapeHtml4", "escapeHtml3",
]);

// ── BOLA: Spring resource-identifier / authorization-annotation classification ──

// Only PathVariable/RequestParam identify "which resource" -- RequestBody is
// the write payload (a different role: the thing being written, not the key
// selecting what's written to) and RequestHeader is rarely a resource id.
// Deliberately NOT the same set as SPRING_SOURCE_ANNOTATIONS above, which
// stays untouched to avoid touching the other 9 detectors' taint semantics.
const RESOURCE_ID_ANNOTATIONS = new Set(["PathVariable", "RequestParam"]);
const WRITE_VERB_ANNOTATIONS = new Set(["PostMapping", "PutMapping", "PatchMapping", "DeleteMapping"]);
const READ_VERB_ANNOTATIONS = new Set(["GetMapping"]);
const MAPPING_ANNOTATIONS = new Set([...WRITE_VERB_ANNOTATIONS, ...READ_VERB_ANNOTATIONS, "RequestMapping"]);
// Presence alone suppresses -- the SpEL expression inside @PreAuthorize(...)
// is never parsed. This means @PreAuthorize("hasRole('ADMIN')") (a real but
// differently-flavored access control) and @PreAuthorize("#id ==
// authentication.principal.id") (an actual ownership check) suppress
// identically. Deliberate: distinguishing them needs a SpEL parser this
// codebase doesn't have, and the annotation's mere presence is still a
// syntactically real, high-confidence fact -- a method decorated with any of
// these three really is under SOME framework-level access control, which the
// existing regex heuristics could only ever guess at via keyword proximity.
const AUTH_SUPPRESSION_ANNOTATIONS = new Set(["PreAuthorize", "Secured", "RolesAllowed"]);

type HttpVerbTier = "read" | "write" | "unknown";
interface MethodAuthMeta {
  isEndpoint: boolean;
  verbTier: HttpVerbTier;
  suppressedByAuthAnnotation: boolean;
}

function extractMethodAuthMeta(methodDecl: CstNode): MethodAuthMeta {
  const anns = annotationsFrom(methodDecl, "methodModifier");
  const isEndpoint = anns.some(a => MAPPING_ANNOTATIONS.has(a));
  const verbTier: HttpVerbTier =
    anns.some(a => WRITE_VERB_ANNOTATIONS.has(a)) ? "write" :
    anns.some(a => READ_VERB_ANNOTATIONS.has(a)) ? "read" : "unknown";
  const suppressedByAuthAnnotation = anns.some(a => AUTH_SUPPRESSION_ANNOTATIONS.has(a));
  return { isEndpoint, verbTier, suppressedByAuthAnnotation };
}

// ── Environment ──────────────────────────────────────────────────────────

type Env = Map<string, boolean>;
type VarTypes = Map<string, string>; // local var name -> declared type's simple name (e.g. "ObjectInputStream")

interface ParamShape { name: string; index: number; isRest: boolean }

/** Which of `args` correspond to `shape`: exactly one arg for a fixed
 * param, every arg from `shape.index` onward for a varargs param. */
function argsForShape<A>(args: readonly A[], shape: ParamShape): A[] {
  return shape.isRest ? args.slice(shape.index) : (args[shape.index] !== undefined ? [args[shape.index]] : []);
}

interface LocalMethod {
  name: string;
  paramShapes: ParamShape[];
  springParamNames: Set<string>;
  // BOLA-specific, additive -- neither touches springParamNames' existing
  // taint-seeding semantics for the other 9 sink categories.
  resourceIdParamNames: Set<string>;  // @PathVariable/@RequestParam subset -- "which resource"
  principalParamNames: Set<string>;   // @AuthenticationPrincipal params -- the authenticated identity, NEVER tainted
  authMeta: MethodAuthMeta;
  body: CstNode | null; // methodBody
}

/** Generalized over the modifier production name -- `variableModifier` for
 * parameters/locals, `methodModifier` for a method declaration itself
 * (confirmed identical `annotation` child shape in both, via a direct parse
 * of a two-annotation method: methodHeader carries no annotation of its
 * own in the common case, both land in methodDeclaration.methodModifier). */
function annotationsFrom(node: CstNode, modifierKey: string): string[] {
  const annotations: string[] = [];
  for (const mod of allNodes(node, modifierKey)) {
    for (const ann of allNodes(mod, "annotation")) {
      const typeName = firstNode(ann, "typeName");
      if (!typeName) continue;
      const idToks = tokenKids(typeName, "Identifier");
      const last = idToks[idToks.length - 1];
      if (last) annotations.push(last.image);
    }
  }
  return annotations;
}

/**
 * Extracts a formal parameter's declared name/annotations/rest-ness across
 * BOTH shapes the grammar produces: `variableParaRegularParameter` (the
 * normal case, name reached through `variableDeclaratorId`) and
 * `variableArityParameter` (`String... args` -- a genuinely SEPARATE
 * production, confirmed directly against a real parse, with its own
 * `Identifier` token reached directly, not through `variableDeclaratorId`).
 * Previously only the regular case was handled, so a varargs parameter was
 * silently dropped from a method's param list entirely.
 */
function paramInfo(fp: CstNode): { name: string; annotations: string[]; isRest: boolean } | null {
  const vp = firstNode(fp, "variableParaRegularParameter");
  if (vp) {
    const declId = firstNode(vp, "variableDeclaratorId");
    const nameTok = declId ? firstTok(declId, "Identifier") : undefined;
    return nameTok ? { name: nameTok.image, annotations: annotationsFrom(vp, "variableModifier"), isRest: false } : null;
  }
  const va = firstNode(fp, "variableArityParameter");
  if (va) {
    const nameTok = firstTok(va, "Identifier");
    return nameTok ? { name: nameTok.image, annotations: annotationsFrom(va, "variableModifier"), isRest: true } : null;
  }
  return null;
}

function extractMethodInfo(methodDecl: CstNode): LocalMethod | null {
  const header = firstNode(methodDecl, "methodHeader");
  if (!header) return null;
  const declarator = firstNode(header, "methodDeclarator");
  if (!declarator) return null;
  const nameTok = firstTok(declarator, "Identifier");
  if (!nameTok) return null;
  const paramShapes: ParamShape[] = [];
  const springParamNames = new Set<string>();
  const resourceIdParamNames = new Set<string>();
  const principalParamNames = new Set<string>();
  const fpl = firstNode(declarator, "formalParameterList");
  if (fpl) {
    let index = 0;
    for (const fp of allNodes(fpl, "formalParameter")) {
      const info = paramInfo(fp);
      if (!info) continue;
      paramShapes.push({ name: info.name, index, isRest: info.isRest });
      if (info.annotations.some(a => SPRING_SOURCE_ANNOTATIONS.has(a))) springParamNames.add(info.name);
      if (info.annotations.some(a => RESOURCE_ID_ANNOTATIONS.has(a))) resourceIdParamNames.add(info.name);
      if (info.annotations.includes("AuthenticationPrincipal")) principalParamNames.add(info.name);
      index++;
    }
  }
  const body = firstNode(methodDecl, "methodBody") ?? null;
  const authMeta = extractMethodAuthMeta(methodDecl);
  return { name: nameTok.image, paramShapes, springParamNames, resourceIdParamNames, principalParamNames, authMeta, body };
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
  // Fallback only -- collectBolaFindings always passes a severityOverride
  // (medium for read endpoints, high for write/unknown).
  "bola-missing-ownership-check": "high",
};
const LABEL: Record<AstTaintJavaId, string> = {
  "sql-injection": "SQL Injection", "command-injection": "Command Injection", "xss": "Reflected XSS",
  "ssrf": "Server-Side Request Forgery", "path-traversal": "Path Traversal",
  "insecure-deserialization": "Insecure Deserialization", "ldap-injection": "LDAP Injection",
  "xpath-injection": "XPath Injection", "open-redirect": "Open Redirect",
  "bola-missing-ownership-check": "Broken Object Level Authorization (AST-verified)",
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
  // Which of a local method's parameter INDICES have taint that reaches its
  // return value -- see computeReturnTaintPropagatingJava.
  propagatingParams: Map<string, Set<number>>;
  // Which of a local method's parameter INDICES were tainted at some call
  // site to it -- consumed by a second pass in scanAstTaintJava that
  // re-walks the method's own body with those params seeded, so a sink call
  // INSIDE the callee (not just in its return) becomes reachable. Java had
  // no equivalent of this mechanism at all before -- astTaint.ts's/
  // astTaintPython.ts's own versions of it were already correct and are
  // mirrored here, not just fixed.
  seededParams: Map<string, Set<number>>;
  varTypes: VarTypes;
  // Class field names, collected once per file -- used by the BOLA
  // Map-field pseudo-repository sink shape to distinguish a class-level
  // "repository" field from an unrelated local Map used inside one method.
  classFieldNames: Set<string>;
  findings: AstTaintJavaFinding[];
  seen: Set<string>;
}

function emit(
  ctx: EngineCtx, id: AstTaintJavaId, node: CstNode, sourceExpr: string, sinkExpr: string,
  severityOverride?: "critical" | "high" | "medium",
) {
  const line = lineOf(node);
  const key = `${id}:${line}`;
  if (ctx.seen.has(key)) return;
  ctx.seen.add(key);
  ctx.findings.push({
    id, line, sinkExpr, sourceExpr, severityOverride,
    detail: id === "bola-missing-ownership-check"
      ? `Resource identifier '${sourceExpr}' reaches ${sinkExpr}(...) with no @PreAuthorize/@Secured/@RolesAllowed annotation and no ownership comparison (.equals()/==/!=) against the authenticated principal anywhere in the method — real per-parameter AST evidence, not a keyword-proximity guess`
      : `Tainted expression '${sourceExpr}' flows into ${sinkExpr}(...) — real data-flow match, not a line-pattern guess`,
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
    // Field-sensitive read (Decision 1): a bare dotted reference like
    // `user.name` checks the composite "root.field" key FIRST (set by the
    // new field-assignment handling in walkForDeclarationsAndSinks), falling
    // back to the existing root-object-taint check -- pure recall gain,
    // never removes a `true` result the old root-only check already found.
    // Deliberately scoped to exactly one field level (parts[0]+parts[1]),
    // not the full dotted chain, matching the same one-level scope used on
    // the write side below.
    let taint = rootVar !== null && env.get(rootVar) === true;
    if (!taint && parts.length >= 2 && env.get(`${parts[0]}.${parts[1]}`) === true) taint = true;
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
 * Resolves an assignment LHS (`unaryExpression` operand of a `binaryExpression`
 * carrying an `AssignmentOperator` -- see walkForDeclarationsAndSinks) to its
 * env lookup key: a plain identifier for `x = ...`, or the one-level
 * composite "root.field" key for `obj.field = ...`, reusing the same
 * fqnOrRefType-chain parsing primaryPrefixInfo already does for reads.
 * Returns null for any other LHS shape (array index, parenthesized, etc.) --
 * scoped to static dotted-property access only, matching the read side.
 */
function assignmentTargetKey(lhsUnary: CstNode | undefined, env: Env, ctx: EngineCtx): string | null {
  const primary = lhsUnary ? firstNode(lhsUnary, "primary") : undefined;
  const prefix = primary ? firstNode(primary, "primaryPrefix") : undefined;
  if (!prefix || allNodes(primary!, "primarySuffix").length !== 0) return null;
  const { parts } = primaryPrefixInfo(prefix, env, ctx);
  if (parts.length === 0) return null;
  if (parts.length === 1) return parts[0];
  return `${parts[0]}.${parts[1]}`;
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

      // Sanitizer/escaping calls (Decision 2) -- de-taint at this point in
      // the chain, checked BEFORE source/append/format/propagating-param
      // checks so a sanitized value can't be re-tainted by one of those in
      // this same call. Still reports the call (onCall) for sink-matching/
      // seeding consistency, but skips every taint-increasing branch below.
      if (JAVA_SANITIZER_TAILS.has(tail)) {
        chainTaint = false;
        onCall?.({ calleeName, tail, rootVar, args, chainTaintBefore, node: suffix, isNewURL });
        nameParts = [];
        continue;
      }

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
      // return value is known (computeReturnTaintPropagatingJava) to depend
      // on SPECIFIC parameters -- e.g. executeQuery(buildQuery(uid)) where
      // buildQuery merely returns a tainted concatenation of uid and never
      // calls a sink itself. Only the arguments at the propagating indices
      // are checked, not every argument.
      const propIdx = ctx.propagatingParams.get(tail);
      if (propIdx) {
        const callee = ctx.localMethods.get(tail);
        const shapes = callee?.paramShapes ?? [];
        const matched = [...propIdx].some(i => {
          const shape = shapes[i];
          return shape ? argsForShape(args, shape).some(a => isTainted(a, env, ctx)) : false;
        });
        if (matched) chainTaint = true;
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

/**
 * For each of `method`'s parameters INDEPENDENTLY (seed only that one param
 * tainted, all others left untainted), does `method`'s return value become
 * tainted? Returns the set of parameter INDICES whose taint actually
 * reaches the return -- not a single per-method boolean (which would mean a
 * call like buildLog(safeId, taintedMessage), where only userId -- not
 * message -- flows into the return, incorrectly firing). Sound because
 * isTainted is purely OR-shaped (every combinator is `||`/`.some()`,
 * nothing de-taints), so seeding a superset of params can only ever taint a
 * superset of what seeding a subset taints. Mirrors astTaint.ts's
 * computeReturnTaintPropagating / astTaintPython.ts's
 * computeReturnTaintPropagatingPy exactly.
 *
 * Nested calls inside `method`'s own body are resolved using `ctx` AS GIVEN
 * -- no longer forced to an empty-map "shallowCtx" internally. Boundedness
 * now comes entirely from the caller (buildPropagatingMapJava's round cap),
 * matching JS/Python's own `isTaintedFn`-parameter refactor (Decision 3):
 * the same function now serves both a genuinely-shallow one-shot call (pass
 * a ctx with empty propagatingParams/localMethods) and the bounded
 * fixed-point below (pass ctx with the in-progress round map).
 */
function computeReturnTaintPropagatingJava(method: LocalMethod, ctx: EngineCtx): Set<number> {
  const propagatingIdx = new Set<number>();
  if (!method.body) return propagatingIdx;
  const returnExprs = findAllNodes(method.body, "returnStatement")
    .map(ret => firstNode(ret, "expression"))
    .filter((e): e is CstNode => !!e);
  for (const shape of method.paramShapes) {
    const env: Env = new Map();
    env.set(shape.name, true);
    if (returnExprs.some(expr => isTainted(expr, env, ctx))) propagatingIdx.add(shape.index);
  }
  return propagatingIdx;
}

// Caps every bounded fixed-point loop below (same-file propagating-map
// convergence and the call-site-seeding worklist) -- named and shared for
// the same reason astTaint.ts's own MAX_PROPAGATION_ROUNDS is, and matching
// its value exactly.
const MAX_PROPAGATION_ROUNDS = 3;

/**
 * Builds the same-file `propagatingParams` map via a bounded fixed-point
 * iteration instead of one pass with every nested call opaque -- Decision 3,
 * generalizing what was already an ACCIDENTAL multi-hop guarantee in this
 * file's call-site-seeding second pass (live Map iteration) into an
 * explicit, documented, capped algorithm here too, mirroring astTaint.ts's/
 * astTaintPython.ts's own buildPropagatingMap. Sound without extra
 * cycle-breaking machinery because propagation is monotonic (each round only
 * ever ADDS indices, never removes one, and every method's index set is
 * bounded by its own parameter count) -- convergence is never in doubt, the
 * round cap only bounds worst-case cost on a large file's call graph.
 */
function buildPropagatingMapJava(localMethods: Map<string, LocalMethod>, baseCtx: EngineCtx): Map<string, Set<number>> {
  const propagating = new Map<string, Set<number>>();
  for (let round = 0; round < MAX_PROPAGATION_ROUNDS; round++) {
    let changed = false;
    const roundCtx: EngineCtx = { ...baseCtx, propagatingParams: propagating };
    for (const [name, method] of localMethods) {
      const idx = computeReturnTaintPropagatingJava(method, roundCtx);
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

/**
 * NEW mechanism, closing a real gap: astTaint.ts/astTaintPython.ts both
 * already have a positionally-correct "seed a callee's tainted params from
 * a call site, then re-walk its body" pass so a sink call INSIDE a local
 * function/method (not just in its return expression) is reachable when
 * called with tainted arguments -- astTaintJava.ts never had this at all.
 * Records which parameter INDICES were tainted at this call site into
 * ctx.seededParams; a second full pass in scanAstTaintJava consumes it.
 */
function seedLocalMethodParams(
  info: { tail: string; args: CstNode[] }, env: Env, ctx: EngineCtx,
) {
  const callee = ctx.localMethods.get(info.tail);
  if (!callee) return;
  const taintedIdx = new Set<number>();
  info.args.forEach((arg, i) => {
    if (!isTainted(arg, env, ctx)) return;
    const shape = callee.paramShapes.find(s => s.isRest ? i >= s.index : s.index === i);
    if (shape) taintedIdx.add(shape.index);
  });
  if (taintedIdx.size === 0) return;
  const existing = ctx.seededParams.get(info.tail) ?? new Set<number>();
  taintedIdx.forEach(i => existing.add(i));
  ctx.seededParams.set(info.tail, existing);
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

  // Assignment (Decision 1, write side): `x = expr;` or `obj.field = expr;`.
  // Chevrotain flattens a plain reference AND an assignment into the SAME
  // `binaryExpression` production (see the module's other binaryExpression
  // handling) -- an assignment is the one with a present `AssignmentOperator`
  // child. Restricted to the plain `=` operator only (not `+=`/`-=`/etc,
  // confirmed as a distinct sub-alternative of the same production): a
  // compound assignment would need `env.get(key)` OR'd into the new value to
  // stay additive-only, which isn't implemented here, so recognizing it
  // would risk INCORRECTLY de-tainting an already-tainted target -- left
  // unhandled (falls through to the generic recursion below, same as
  // before) rather than risk that regression. Java had no assignment
  // handling of any kind before this (only localVariableDeclaration's own
  // initializer was tracked), so this also newly covers plain-identifier
  // reassignment, not just the field case Decision 1 targets.
  if (node.name === "binaryExpression") {
    const assignTok = tokenKids(node, "AssignmentOperator")[0];
    if (assignTok && assignTok.image === "=") {
      const lhsUnary = firstNode(node, "unaryExpression");
      const rhsExpr = firstNode(node, "expression");
      const key = assignmentTargetKey(lhsUnary, env, ctx);
      if (key) env.set(key, rhsExpr ? isTainted(rhsExpr, env, ctx) : false);
    }
  }

  // Sink-visiting: every `primary` anywhere is a candidate call-chain root.
  if (node.name === "primary") {
    const prefix = firstNode(node, "primaryPrefix");
    if (prefix) checkNewExpressionSink(prefix, env, ctx, node);
    walkPrimaryChain(node, env, ctx, (info) => { checkCallSink(info, env, ctx); seedLocalMethodParams(info, env, ctx); });
  }

  for (const key of Object.keys(node.children)) {
    for (const el of node.children[key]) {
      if (!isToken(el)) walkForDeclarationsAndSinks(el, env, ctx);
    }
  }
}

// ── BOLA: sink shapes, ownership-comparison detection, per-method emission ──

function collectClassFieldNames(root: CstNode): Set<string> {
  const fields = new Set<string>();
  for (const fd of findAllNodes(root, "fieldDeclaration")) {
    const vdl = firstNode(fd, "variableDeclaratorList");
    for (const vd of vdl ? allNodes(vdl, "variableDeclarator") : []) {
      const declId = firstNode(vd, "variableDeclaratorId");
      const nameTok = declId ? firstTok(declId, "Identifier") : undefined;
      if (nameTok) fields.add(nameTok.image);
    }
  }
  return fields;
}

/** Method-scoped declared-type / initializer index -- deliberately NOT
 * ctx.varTypes, which is a single flat map populated across the ENTIRE file
 * with no per-method clearing (an accepted imprecision for the existing
 * deserialization check that must not be extended to this new feature). */
function collectLocalDeclInfo(body: CstNode): { types: Map<string, string>; inits: Map<string, CstNode> } {
  const types = new Map<string, string>();
  const inits = new Map<string, CstNode>();
  for (const decl of findAllNodes(body, "localVariableDeclaration")) {
    const typeNode = firstNode(decl, "localVariableType");
    const unannType = typeNode ? firstNode(typeNode, "unannType") : undefined;
    const unannClassType = unannType ? findAllNodes(unannType, "unannClassType")[0] : undefined;
    const simpleName = unannClassType ? tokenKids(unannClassType, "Identifier").pop()?.image : undefined;
    const vdl = firstNode(decl, "variableDeclaratorList");
    for (const vd of vdl ? allNodes(vdl, "variableDeclarator") : []) {
      const declId = firstNode(vd, "variableDeclaratorId");
      const nameTok = declId ? firstTok(declId, "Identifier") : undefined;
      if (!nameTok) continue;
      if (simpleName) types.set(nameTok.image, simpleName);
      const init = firstNode(vd, "variableInitializer");
      const initExpr = init ? firstNode(init, "expression") : undefined;
      if (initExpr) inits.set(nameTok.image, initExpr);
    }
  }
  return { types, inits };
}

function collectTokenText(node: CstNode, out: string[]): void {
  for (const key of Object.keys(node.children)) {
    for (const el of node.children[key]) {
      if (isToken(el)) out.push(el.image); else collectTokenText(el, out);
    }
  }
}
function allTokenText(node: CstNode): string {
  const out: string[] = [];
  collectTokenText(node, out);
  // No separator -- tokens concatenate back to (whitespace-insensitive) real
  // source layout, e.g. "authentication" + "." + "getName" + "(" + ")" ->
  // "authentication.getName()", so PRINCIPAL_CALL_RE's tight patterns like
  // \.getName\s*\( actually match. A space separator would insert " " between
  // every token (including around "." and "("), breaking that match.
  return out.join("");
}
function collectIdentifiers(node: CstNode, acc: Set<string> = new Set()): Set<string> {
  for (const key of Object.keys(node.children)) {
    for (const el of node.children[key]) {
      if (isToken(el)) { if (key === "Identifier") acc.add(el.image); }
      else collectIdentifiers(el, acc);
    }
  }
  return acc;
}

const PRINCIPAL_CALL_RE = /getPrincipal|getAuthentication|SecurityContextHolder|getCurrentUser|\.getName\s*\(/;

function isResourceIdOperand(ids: Set<string>, resourceIdParamNames: Set<string>): boolean {
  return [...ids].some(id => resourceIdParamNames.has(id));
}
function isPrincipalOperand(ids: Set<string>, text: string, principalNames: Set<string>): boolean {
  return [...ids].some(id => principalNames.has(id)) || PRINCIPAL_CALL_RE.test(text);
}

/** `==`/`!=` binaryExpression operands -- both sides are real CST nodes. */
function comparisonSuppresses(
  leftNode: CstNode, rightNode: CstNode,
  resourceIdParamNames: Set<string>, principalNames: Set<string>,
): boolean {
  const lIds = collectIdentifiers(leftNode), rIds = collectIdentifiers(rightNode);
  const lTxt = allTokenText(leftNode), rTxt = allTokenText(rightNode);
  const lIsRes = isResourceIdOperand(lIds, resourceIdParamNames), lIsPrin = isPrincipalOperand(lIds, lTxt, principalNames);
  const rIsRes = isResourceIdOperand(rIds, resourceIdParamNames), rIsPrin = isPrincipalOperand(rIds, rTxt, principalNames);
  return (lIsRes && rIsPrin) || (lIsPrin && rIsRes);
}

/** `.equals(...)` -- walkPrimaryChain's onCall side-channel only exposes the
 * receiver as a bare `rootVar` string (no full CST node for the receiver
 * side), so the receiver is tested as a single-identifier/bare-text operand
 * rather than via collectIdentifiers/allTokenText. Slightly weakens
 * receiver-side call-chain detection (e.g. a chained
 * `SecurityContextHolder.getContext().getAuthentication()` receiver reduces
 * to just its root "SecurityContextHolder", which PRINCIPAL_CALL_RE still
 * matches) -- an accepted, minor simplification, not a redesign. */
function comparisonSuppressesEquals(
  rootVar: string | null, argNode: CstNode,
  resourceIdParamNames: Set<string>, principalNames: Set<string>,
): boolean {
  if (!rootVar) return false;
  const rIds = collectIdentifiers(argNode), rTxt = allTokenText(argNode);
  const lIsRes = resourceIdParamNames.has(rootVar);
  const lIsPrin = principalNames.has(rootVar) || PRINCIPAL_CALL_RE.test(rootVar);
  const rIsRes = isResourceIdOperand(rIds, resourceIdParamNames), rIsPrin = isPrincipalOperand(rIds, rTxt, principalNames);
  return (lIsRes && rIsPrin) || (lIsPrin && rIsRes);
}

/** Reduces an argument expression to its single bare identifier IFF it's
 * exactly that -- one unqualified name, zero primarySuffix entries (no
 * method call, no field access, no array index). Used only for the one-hop
 * backward check below (`.save(entity)` -> was `entity` built from the
 * resource id). */
function bareIdentifierOf(arg: CstNode): string | null {
  const primaries = findAllNodes(arg, "primary");
  if (primaries.length !== 1) return null;
  const primary = primaries[0];
  if (allNodes(primary, "primarySuffix").length !== 0) return null;
  const prefix = firstNode(primary, "primaryPrefix");
  const fqn = prefix ? firstNode(prefix, "fqnOrRefType") : undefined;
  if (!fqn) return null;
  if (allNodes(fqn, "fqnOrRefTypePartRest").length !== 0) return null; // qualified name, not bare
  const first = firstNode(fqn, "fqnOrRefTypePartFirst");
  const firstCommon = first ? firstNode(first, "fqnOrRefTypePartCommon") : undefined;
  const firstId = firstCommon ? firstTok(firstCommon, "Identifier") : undefined;
  return firstId?.image ?? null;
}

/** Does `arg` reference a resource-id param, directly or one hop back
 * through a local variable's own initializer (covers `.save(entity)` where
 * `entity` was built from the tainted id earlier in the method)? */
function argReferencesResourceId(arg: CstNode, resourceIdParamNames: Set<string>, localInits: Map<string, CstNode>): boolean {
  if ([...collectIdentifiers(arg)].some(id => resourceIdParamNames.has(id))) return true;
  const bare = bareIdentifierOf(arg);
  if (bare && localInits.has(bare)) {
    return [...collectIdentifiers(localInits.get(bare)!)].some(id => resourceIdParamNames.has(id));
  }
  return false;
}

interface BolaSinkCandidate { node: CstNode; sourceExpr: string; sinkExpr: string }

const BOLA_REPO_LOOKUP_METHODS = new Set(["findById", "getOne", "getById"]);
// deleteById/delete/save -- standard Spring Data CRUD method names. `.update(...)`
// is deliberately NOT included: ambiguous with JDBC's own unrelated
// jdbcTemplate.update SQL-injection sink, not a standard Spring Data method
// name, and no confirmed fixture to validate a bare `.update(...)` match
// against (a high false-positive-risk pattern without one).
const BOLA_REPO_WRITE_METHODS = new Set(["deleteById", "delete", "save"]);
// Map-shaped field-backed pseudo-repository access -- putAll excluded, it
// never itself carries a resource-id-shaped key argument (owasp_test_app.java's
// updateUser is still caught via its own .getOrDefault(userId,...)/.put(userId,...)
// calls on the same field, independently).
const BOLA_MAP_ACCESS_METHODS = new Set(["get", "getOrDefault", "put", "remove"]);

function checkBolaSinkCandidate(
  info: { calleeName: string; tail: string; rootVar: string | null; args: CstNode[]; node: CstNode },
  resourceIdParamNames: Set<string>, classFieldNames: Set<string>, localInits: Map<string, CstNode>,
  candidates: BolaSinkCandidate[],
) {
  const { tail, rootVar, args, node, calleeName } = info;
  if (args.length === 0) return;
  if (BOLA_REPO_LOOKUP_METHODS.has(tail) || BOLA_REPO_WRITE_METHODS.has(tail)) {
    if (argReferencesResourceId(args[0], resourceIdParamNames, localInits)) {
      candidates.push({ node, sourceExpr: nodeText(args[0]), sinkExpr: calleeName });
    }
    return;
  }
  if (BOLA_MAP_ACCESS_METHODS.has(tail) && rootVar !== null && classFieldNames.has(rootVar)) {
    if (argReferencesResourceId(args[0], resourceIdParamNames, localInits)) {
      candidates.push({ node, sourceExpr: nodeText(args[0]), sinkExpr: calleeName });
    }
  }
}

/**
 * BOLA constructor-sink candidates (Decision 4 gap-fix): `new ClassName(id)`
 * where `id` is a resource-id-sourced argument -- the confirmed WebGoat
 * IDOREditOtherProfile.java/IDORViewOtherProfile.java shape
 * (`new UserProfile(userId)`), which checkBolaSinkCandidate's method-name
 * vocabulary (findById/save/Map get-put/etc) never recognized since it's
 * not a method call at all. Not reachable via walkPrimaryChain's `onCall`
 * (which only fires on `methodInvocationSuffix`, never `newExpression`), so
 * this walks `primary` nodes directly, mirroring checkNewExpressionSink's
 * existing constructor-argument pattern instead of onCall.
 *
 * Deliberately NOT restricted to a specific class-name vocabulary -- any
 * constructor receiving a resource id, inside an endpoint method that (per
 * collectBolaFindings' existing gates, unchanged here) has no
 * @PreAuthorize/@Secured/@RolesAllowed annotation and no ownership
 * comparison anywhere in its body, is exactly the shape this phase's plan
 * approved flagging. Accepts some imprecision for recall, same posture as
 * every other check in this file (e.g. `tail === "format"` matching any
 * receiver by name alone).
 */
function checkBolaConstructorSinkCandidates(
  method: LocalMethod, resourceIdParamNames: Set<string>, localInits: Map<string, CstNode>,
  candidates: BolaSinkCandidate[],
) {
  if (!method.body) return;
  for (const primary of findAllNodes(method.body, "primary")) {
    const prefix = firstNode(primary, "primaryPrefix");
    const newExpr = prefix ? firstNode(prefix, "newExpression") : undefined;
    if (!newExpr) continue;
    const uc = firstNode(newExpr, "unqualifiedClassInstanceCreationExpression");
    if (!uc) continue;
    const className = extractInstantiatedClassName(uc);
    if (!className) continue;
    const argList = firstNode(uc, "argumentList");
    const args = argList ? allNodes(argList, "expression") : [];
    if (args.length === 0) continue;
    if (argReferencesResourceId(args[0], resourceIdParamNames, localInits)) {
      candidates.push({ node: primary, sourceExpr: nodeText(args[0]), sinkExpr: `new ${className}` });
    }
  }
}

/**
 * Per-method post-check, not per-call-site: BOLA's "is there an ownership
 * comparison ANYWHERE in this method" question needs the whole body
 * evaluated once, so candidate sinks are collected but not emitted until
 * after a full walk confirms no suppressing comparison exists. Mirrors how
 * computeReturnTaintPropagatingJava is already its own separate
 * whole-method-body pass, distinct from the per-call-site sink walk in
 * walkForDeclarationsAndSinks -- same architectural pattern, not a new one.
 * Deliberately does NOT use isTainted/env -- this is a purely structural
 * check (which annotation sourced this parameter, is it compared against a
 * principal-shaped expression), independent of the taint-propagation
 * machinery the rest of the engine uses.
 */
function collectBolaFindings(method: LocalMethod, ctx: EngineCtx) {
  if (!method.body) return;
  if (!method.authMeta.isEndpoint) return;
  if (method.authMeta.suppressedByAuthAnnotation) return;
  if (method.resourceIdParamNames.size === 0) return;

  const { types: localTypes, inits: localInits } = collectLocalDeclInfo(method.body);
  const principalNames = new Set<string>([
    ...method.principalParamNames,
    ...[...localTypes].filter(([, t]) => /Principal|Authentication|UserDetails/i.test(t)).map(([n]) => n),
  ]);

  const candidates: BolaSinkCandidate[] = [];
  let hasOwnershipComparison = false;

  for (const primary of findAllNodes(method.body, "primary")) {
    walkPrimaryChain(primary, new Map(), ctx, (info) => {
      checkBolaSinkCandidate(info, method.resourceIdParamNames, ctx.classFieldNames, localInits, candidates);
      if (info.tail === "equals" && info.args[0] &&
          comparisonSuppressesEquals(info.rootVar, info.args[0], method.resourceIdParamNames, principalNames)) {
        hasOwnershipComparison = true;
      }
    });
  }
  checkBolaConstructorSinkCandidates(method, method.resourceIdParamNames, localInits, candidates);
  for (const bin of findAllNodes(method.body, "binaryExpression")) {
    const ops = tokenKids(bin, "BinaryOperator");
    if (!ops.some(t => t.image === "==" || t.image === "!=")) continue;
    const operands = allNodes(bin, "unaryExpression");
    for (let i = 0; i < operands.length - 1; i++) {
      if (comparisonSuppresses(operands[i], operands[i + 1], method.resourceIdParamNames, principalNames)) {
        hasOwnershipComparison = true;
      }
    }
  }

  if (!hasOwnershipComparison) {
    const severity: "medium" | "high" = method.authMeta.verbTier === "read" ? "medium" : "high";
    for (const c of candidates) emit(ctx, "bola-missing-ownership-check", c.node, c.sourceExpr, c.sinkExpr, severity);
  }
}

// ── Entry point ──────────────────────────────────────────────────────────

export function scanAstTaintJava(content: string, filePath: string, cst: CstNode): AstTaintJavaFinding[] {
  try {
    const lines = content.split("\n");
    const localMethods = collectLocalMethods(cst);
    const ctx: EngineCtx = {
      content, lines, localMethods, propagatingParams: new Map(), seededParams: new Map(),
      varTypes: new Map(), classFieldNames: collectClassFieldNames(cst), findings: [], seen: new Set(),
    };
    const propagating = buildPropagatingMapJava(localMethods, ctx);
    for (const [name, idx] of propagating) ctx.propagatingParams.set(name, idx);

    for (const [, method] of localMethods) {
      if (!method.body) continue;
      const env: Env = new Map();
      // Only Spring-annotated params are true sources at method entry --
      // an un-annotated parameter is not automatically tainted (unlike the
      // interprocedural pre-pass above, which deliberately seeds each param
      // independently to answer a different, broader question).
      method.springParamNames.forEach(p => env.set(p, true));
      walkForDeclarationsAndSinks(method.body, env, ctx);
      collectBolaFindings(method, ctx);
    }

    // Second pass, bounded worklist (Decision 3): re-walk any local method
    // whose params were seeded tainted by a call site above, so a sink
    // inside the callee's own body is reachable -- Java parity with
    // astTaint.ts's/astTaintPython.ts's own second pass (see
    // seedLocalMethodParams's docblock). Re-walking can itself seed FURTHER
    // methods (or grow an already-seeded method's own index set), which is
    // how a second/third hop (A calls B calls C) gets discovered -- now
    // explicitly capped at MAX_PROPAGATION_ROUNDS instead of relying on
    // live-Map-iteration order for its multi-hop convergence (previously
    // documented here as "guaranteed" as a side effect, not as a bound).
    // `walkedSignatures` skips re-walking a method with a seed set identical
    // to one already walked, while still allowing a re-walk once that
    // method's seed set has genuinely grown.
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
