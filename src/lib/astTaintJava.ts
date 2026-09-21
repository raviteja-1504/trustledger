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
import {
  ALL, SHADOW, applyClears, applyGuards, classOf, cloneEnv, walkIfChain, walkLoop, walkSwitch, walkTry, wasCleared,
  type Branch, type Guard, type SuppressedSink, type TaintEnv,
} from "./taint/taintCore";
import { sanitizerClears } from "./taint/sanitizers";

export type AstTaintJavaId =
  | "sql-injection" | "command-injection" | "xss" | "ssrf" | "path-traversal"
  | "open-redirect" | "insecure-deserialization" | "ldap-injection" | "xpath-injection"
  | "bola-missing-ownership-check"
  | "header-injection" | "redos" | "ssti" | "mass-assignment" | "timing-attack" | "jwt-none-alg"
  | "weak-crypto" | "eval-exec" | "nosql-injection";

export interface AstTaintJavaFinding {
  id:         AstTaintJavaId;
  line:       number;
  detail:     string;
  sourceExpr: string;
  sinkExpr:   string;
  // True when the finding exists only because an un-annotated entry-point parameter was treated as untrusted input.
  entryPointSeeded?: boolean;
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

const SPRING_SOURCE_ANNOTATIONS = new Set([
  "PathVariable", "RequestParam", "RequestBody", "RequestHeader", "ModelAttribute", "CookieValue", "MatrixVariable", "RequestPart",
  // JAX-RS
  "QueryParam", "PathParam", "FormParam", "HeaderParam", "CookieParam", "BeanParam", "MatrixParam",
]);
const SERVLET_SOURCE_CALLS = new Set([
  "getParameter", "getHeader", "getParameterValues", "getQueryString", "getParameterMap", "getParameterNames",
  "getHeaders", "getCookies", "getRequestURI", "getRequestURL", "getPathInfo", "getReader", "getInputStream", "getPart",
]);

// ── Sanitizer/de-taint recognition ──────────────────────────────────────
// Matched by method-name TAIL alone, same permissive-by-design posture as
// the existing `tail === "format"` check below -- any receiver. Covers the
// three real Java escaping libraries: OWASP Java Encoder (Encode.forHtml/
// forHtmlAttribute/forHtmlContent/forJavaScript/forUriComponent), ESAPI
// (encodeForHTML/encodeForJavaScript), and Commons Text/Lang
// (escapeHtml4/escapeHtml3). Now lives in taint/sanitizers.ts, keyed by the
// sink classes each tail actually neutralizes (an HTML encoder clears XSS,
// not SQL/command/path) -- see astTaint.ts for the shared design.

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

type Env = TaintEnv;
// method name -> (param index -> sink classes that survive to its return value)
type PropagatingJava = Map<string, Map<number, number>>;
type VarTypes = Map<string, string>; // local var name -> declared type's simple name (e.g. "ObjectInputStream")

interface ParamShape { name: string; index: number; isRest: boolean; type: string; annotated: boolean }

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
  isPrivate: boolean;
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
function paramInfo(fp: CstNode): { name: string; annotations: string[]; isRest: boolean; type: string } | null {
  const vp = firstNode(fp, "variableParaRegularParameter");
  if (vp) {
    const declId = firstNode(vp, "variableDeclaratorId");
    const nameTok = declId ? firstTok(declId, "Identifier") : undefined;
    const ut = firstNode(vp, "unannType");
    return nameTok ? { name: nameTok.image, annotations: annotationsFrom(vp, "variableModifier"), isRest: false, type: ut ? tokensText(ut) : "" } : null;
  }
  const va = firstNode(fp, "variableArityParameter");
  if (va) {
    const nameTok = firstTok(va, "Identifier");
    const ut = firstNode(va, "unannType");
    return nameTok ? { name: nameTok.image, annotations: annotationsFrom(va, "variableModifier"), isRest: true, type: (ut ? tokensText(ut) : "") + "[]" } : null;
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
      paramShapes.push({ name: info.name, index, isRest: info.isRest, type: info.type, annotated: info.annotations.length > 0 });
      if (info.annotations.some(a => SPRING_SOURCE_ANNOTATIONS.has(a))) springParamNames.add(info.name);
      if (info.annotations.some(a => RESOURCE_ID_ANNOTATIONS.has(a))) resourceIdParamNames.add(info.name);
      if (info.annotations.includes("AuthenticationPrincipal")) principalParamNames.add(info.name);
      index++;
    }
  }
  const body = firstNode(methodDecl, "methodBody") ?? null;
  const authMeta = extractMethodAuthMeta(methodDecl);
  const isPrivate = allNodes(methodDecl, "methodModifier").some(m => tokenKids(m, "Private").length > 0);
  return { name: nameTok.image, paramShapes, springParamNames, resourceIdParamNames, principalParamNames, authMeta, isPrivate, body };
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

// ── Enclosing-method lookup (shared with reachability.ts's resolver) ──────
// Mirrors astTaintGo.ts's findNodeAtRowGo/findEnclosingFunctionNameGo and
// astTaintPython.ts's findNodeAtRowPy/findEnclosingFunctionNamePy, which
// scanner.ts's resolveContainingFunction() already calls per-indicator to
// classify reachability correctly (see reachability.ts's own docblock for
// why a single whole-file string was wrong). Java had no equivalent at all
// before this -- every Java finding silently fell through to the "unknown"
// default and was scored "unreachable" regardless of what was actually
// true.
//
// Chevrotain's CST has no generic "node spanning row X" API the way
// tree-sitter does (only leaf IToken values carry startLine/endLine, not
// non-terminal CstNodes), so this is ONE composite function rather than
// the two-function findNodeAtRowX + findEnclosingFunctionNameX split Go/
// Python use -- a deliberate adaptation to Chevrotain's shape, not a
// mismatch. Finds whichever local method's body token range contains the
// target row, reusing the already-collected LocalMethod map rather than
// re-walking the CST with new logic.

function collectAllTokens(node: CstNode, acc: IToken[] = []): IToken[] {
  for (const key of Object.keys(node.children)) {
    for (const el of node.children[key]) {
      if (isToken(el)) acc.push(el); else collectAllTokens(el, acc);
    }
  }
  return acc;
}

/** `row` is 0-indexed, matching findNodeAtRowGo/findNodeAtRowPy's own
 * convention (scanner.ts always calls with `Math.max(0, line - 1)`).
 * java-parser's own IToken.startLine/endLine are 1-indexed. */
export function findEnclosingFunctionNameJava(cst: CstNode, row: number): string {
  const targetLine = row + 1;
  const methods = collectLocalMethods(cst);
  for (const [name, method] of methods) {
    if (!method.body) continue;
    const tokens = collectAllTokens(method.body);
    if (tokens.length === 0) continue;
    let start = Infinity, end = -Infinity;
    for (const t of tokens) {
      if (t.startLine !== undefined && t.startLine < start) start = t.startLine;
      if (t.endLine !== undefined && t.endLine > end) end = t.endLine;
    }
    if (targetLine >= start && targetLine <= end) return name;
  }
  return "unknown";
}

// ── Sink table ───────────────────────────────────────────────────────────

const SEVERITY: Record<AstTaintJavaId, "critical" | "high" | "medium"> = {
  "sql-injection": "critical", "command-injection": "critical", "xss": "critical",
  "ssrf": "critical", "path-traversal": "critical", "insecure-deserialization": "critical",
  "ldap-injection": "critical", "xpath-injection": "critical", "open-redirect": "medium",
  // Fallback only -- collectBolaFindings always passes a severityOverride
  // (medium for read endpoints, high for write/unknown).
  "bola-missing-ownership-check": "high",
  "header-injection": "high", "redos": "high", "ssti": "critical", "mass-assignment": "high", "timing-attack": "medium",
  "jwt-none-alg": "critical", "weak-crypto": "high", "eval-exec": "critical", "nosql-injection": "critical",
};
const LABEL: Record<AstTaintJavaId, string> = {
  "sql-injection": "SQL Injection", "command-injection": "Command Injection", "xss": "Reflected XSS",
  "ssrf": "Server-Side Request Forgery", "path-traversal": "Path Traversal",
  "insecure-deserialization": "Insecure Deserialization", "ldap-injection": "LDAP Injection",
  "xpath-injection": "XPath Injection", "open-redirect": "Open Redirect",
  "bola-missing-ownership-check": "Broken Object Level Authorization (AST-verified)",
  "header-injection": "HTTP Header Injection", "redos": "ReDoS — Regex DoS", "ssti": "Server-Side Template Injection",
  "mass-assignment": "Mass Assignment", "timing-attack": "Timing Attack", "jwt-none-alg": "JWT Signature Not Verified",
  "weak-crypto": "Weak Cryptography", "eval-exec": "Arbitrary Code Execution", "nosql-injection": "NoSQL Injection",
};

// lowercase tag names only, and not glued to an identifier: `Map<String, Object>` is a generic, not markup
const HTML_TAG_RE = /(?<![\w\]>])<\/?[a-z][a-z0-9-]*(?:\s[^<>]*)?\/?>/;

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
  propagatingParams: PropagatingJava;
  // Which of a local method's parameter INDICES were tainted at some call
  // site to it (and for which sink classes) -- consumed by a second pass in
  // scanAstTaintJava that re-walks the method's own body with those params
  // seeded, so a sink call INSIDE the callee (not just in its return)
  // becomes reachable. Java had no equivalent of this mechanism at all
  // before -- astTaint.ts's/astTaintPython.ts's own versions of it were
  // already correct and are mirrored here, not just fixed.
  seededParams: Map<string, Map<number, number>>;
  // Sinks whose argument was tainted for the sink's class but positively
  // cleared by a sanitizer (see astTaint.ts) -- lets scanner.ts drop the
  // regex layer's duplicate for a flow this engine proved safe.
  suppressed?: SuppressedSink[];
  varTypes: VarTypes;
  // Class field names, collected once per file -- used by the BOLA
  // Map-field pseudo-repository sink shape to distinguish a class-level
  // "repository" field from an unrelated local Map used inside one method.
  classFieldNames: Set<string>;
  // File root -- lets guards resolve a literal-collection field/local declared elsewhere in the file.
  root?: CstNode;
  // Class-field container memory: taint written into a field by one method is visible to every method
  // that reads it (stored XSS, second-order SQL). Recorded by the main scan only (recordSticky).
  sticky: Map<string, number>;
  stickyDirty: boolean;
  recordSticky: boolean;
  // Per-method scope facts, set by the caller before it walks a body.
  localNames?: Set<string>;
  currentParams?: Set<string>;
  currentBody?: CstNode;
  // lambda variable name -> its lambda (so `f.apply(x)` resolves to the lambda's body)
  lambdas: Map<string, CstNode>;
  // iteration variables of enclosing `for (var e : tainted.entrySet())` loops
  entryLoopVars: string[];
  // local methods that are structurally HTML escapers (their body replaces "<" with an entity)
  htmlEscapers: Set<string>;
  findings: AstTaintJavaFinding[];
  seen: Set<string>;
}

function emit(
  ctx: EngineCtx, id: AstTaintJavaId, node: CstNode, sourceExpr: string, sinkExpr: string,
  severityOverride?: "critical" | "high" | "medium", detailOverride?: string,
) {
  const line = lineOf(node);
  const key = `${id}:${line}`;
  if (ctx.seen.has(key)) return;
  ctx.seen.add(key);
  ctx.findings.push({
    id, line, sinkExpr, sourceExpr, severityOverride,
    detail: detailOverride ?? (id === "bola-missing-ownership-check"
      ? `Resource identifier '${sourceExpr}' reaches ${sinkExpr}(...) with no @PreAuthorize/@Secured/@RolesAllowed annotation and no ownership comparison (.equals()/==/!=) against the authenticated principal anywhere in the method — real per-parameter AST evidence, not a keyword-proximity guess`
      : `Tainted expression '${sourceExpr}' flows into ${sinkExpr}(...) — real data-flow match, not a line-pattern guess`),
  });
}

// ── Java recall helpers (sources, carriers, string shapes) ───────────────────

const REQUEST_VAR_RE = /^(?:request|req|httpRequest|servletRequest|httpServletRequest)$/i;
const REQUEST_TYPE_RE = /^(?:Http)?ServletRequest(?:Wrapper)?$|^WebRequest$|^ServerHttpRequest$/;
/** A variable that holds the servlet request: named like one, or declared with a request type. */
function isRequestVar(v: string | null, ctx: { varTypes: Map<string, string> }): boolean {
  return !!v && (REQUEST_VAR_RE.test(v) || REQUEST_TYPE_RE.test(ctx.varTypes.get(v) ?? ""));
}

/** Source-order text of every token under `node`, joined with no separators (`Map<String,String>`). */
function tokensText(node: CstNode): string {
  const toks: IToken[] = [];
  const visit = (n: CstNode) => {
    for (const key of Object.keys(n.children)) for (const el of n.children[key]) { if (isToken(el)) toks.push(el); else visit(el as unknown as CstNode); }
  };
  visit(node);
  return toks.sort((a, b) => a.startOffset - b.startOffset).map(t => t.image).join("");
}

const STRINGY_PARAM_TYPE_RE = /^(?:String|CharSequence|StringBuilder|StringBuffer|String\[\]|List<String>|Set<String>|Collection<String>|Map<String,(?:String|Object|\?)>|byte\[\]|char\[\]|InputStream|Reader|Object\[\])$/;
const NON_ENTRY_METHOD_RE = /^(?:main|equals|hashCode|toString|compareTo|run|call|get\w*|set\w*|is\w*|close|clone|finalize|apply|accept|test)$/;

// Static/utility calls whose RESULT carries the taint of their arguments (string, path, URL, collection
// plumbing that neither validates nor neutralizes anything). Opaque calls stay untainted.
const ARG_CARRYING_TAILS = new Set([
  "replace", "replaceAll", "replaceFirst", "concat", "join", "valueOf", "copyValueOf", "of", "ofNullable", "asList",
  "resolve", "resolveSibling", "decode", "encode", "encodeToString", "decodeToString", "requireNonNull",
  "requireNonNullElse", "copyOf", "singletonList", "unmodifiableList", "unmodifiableSet", "unmodifiableMap",
  "orElse", "getOrDefault", "create", "toURI", "normalize", "strip", "trim",
]);
// Calls that store their arguments in the receiver container.
const MUTATOR_TAILS = new Set(["put", "add", "addAll", "putAll", "push", "offer", "addFirst", "addLast", "putIfAbsent", "set", "insert"]);
// Functional-interface invocations and the fluent methods that hand a value to a callback.
const FUNCTIONAL_TAILS = new Set(["apply", "accept", "test", "call", "applyAsInt", "applyAsLong", "applyAsDouble", "applyAsBoolean"]);
const CALLBACK_TAILS = new Set(["thenApply", "thenApplyAsync", "thenCompose", "thenComposeAsync", "thenAccept", "map", "flatMap", "supplyAsync", "orElseGet", "ifPresent"]);
const HTTP_HEADER_NAME_RE = /^(?:X-[\w-]+|Content-[\w-]+|Location|Set-Cookie|Refresh|Link|Cache-Control|Access-Control-[\w-]+|Authorization|Cookie|Retry-After|WWW-Authenticate|Referer|Origin|Host)$/i;
const SECRET_NAME_JAVA_RE = /^(?:[A-Za-z_]*(?:secret|token|password|passwd|apikey|api_key|hmac|signature)[A-Za-z_0-9]*)$/i;
const TEMPLATE_PLACEHOLDER_RE = /\$\{[^}]*\}|\{\{[^}]*\}\}|%\{[^}]*\}|#\{[^}]*\}|<%/;

const SQL_START_RE = /^\s*(?:select|insert|update|delete|with|call|exec(?:ute)?|merge|replace)\b/i;
const HTML_TAG_SHAPE_RE = /<\/?[a-zA-Z][\w-]*(?:\s[^<>]*)?(?:>|$)/;
const LDAP_SHAPE_RE = /\(\s*[&|!]?\s*(?:\(\s*)?[\w.-]+\s*(?:=|~=|>=|<=)\s*$/;
const XPATH_SHAPE_RE = /\/\/?[\w*@.:-]+(?:\/[\w*@.:()-]+)*\[[^\]]*=\s*['"]?$/;
const LDAP_URL_RE = /^ldaps?:\/\//i;
const SCRIPT_CONTEXT_RE = /<script\b[^>]*>(?:(?!<\/script>)[\s\S])*$/i;

/** The lambda an argument/initializer expression IS, if any. */
function soleLambda(node: CstNode | undefined): CstNode | undefined {
  if (!node) return undefined;
  if (node.name === "lambdaExpression") return node;
  return firstNode(node, "lambdaExpression");
}

/** Result of calling `lambda` with its leading parameters bound to `argMasks` (captured variables come from `env`). */
function lambdaResultMask(lambda: CstNode, argMasks: readonly number[], env: Env, ctx: EngineCtx): number {
  const lenv = cloneEnv(env);
  lambdaParamNames(lambda).forEach((p, i) => lenv.set(p, argMasks[i] ?? 0));
  const body = firstNode(lambda, "lambdaBody");
  if (!body) return 0;
  const block = firstNode(body, "block");
  if (!block) return taintMask(body, lenv, ctx);
  let m = 0;
  for (const r of findAllNodes(block, "returnStatement")) {
    const e = firstNode(r, "expression");
    if (e) m |= taintMask(e, lenv, ctx);
  }
  return m;
}

/** A string literal expression's unquoted value, or null when the operand is not just a string literal. */
function literalStringOf(node: CstNode): string | null {
  const p = soleUnaryPrimary(node);
  if (!p || allNodes(p, "primarySuffix").length > 0) return null;
  const lit = firstNode(firstNode(p, "primaryPrefix") ?? p, "literal");
  const tok = lit ? firstTok(lit, "StringLiteral") : undefined;
  return tok ? tok.image.slice(1, -1) : null;
}

const htmlEvidenceCache = new WeakMap<CstNode, boolean>();
/** Does this method contain an HTML-tag-shaped string literal (so its returned string is an HTML body)? */
function methodHasHtmlEvidence(body: CstNode): boolean {
  const cached = htmlEvidenceCache.get(body);
  if (cached !== undefined) return cached;
  const hit = collectAllTokens(body).some(t => (t as IToken).tokenType?.name === "StringLiteral" && HTML_TAG_SHAPE_RE.test(t.image));
  htmlEvidenceCache.set(body, hit);
  return hit;
}

/** A local method whose body replaces "<" with an HTML entity is an HTML escaper (recognised structurally). */
function isHtmlEscaperBody(body: CstNode): boolean {
  const images = new Set(collectAllTokens(body).map(t => t.image));
  return images.has('"<"') && (images.has('"&lt;"') || images.has('"&#60;"') || images.has('"&#x3C;"'));
}

function localNamesOfMethod(method: { paramShapes: { name: string }[]; body: CstNode | null }): Set<string> {
  const names = new Set<string>(method.paramShapes.map(p => p.name));
  if (!method.body) return names;
  for (const id of findAllNodes(method.body, "variableDeclaratorId")) {
    const t = firstTok(id, "Identifier");
    if (t) names.add(t.image);
  }
  for (const lam of findAllNodes(method.body, "lambdaExpression")) for (const p of lambdaParamNames(lam)) names.add(p);
  return names;
}

/** Record taint written into a class field (visible to other methods). Main scan only. */
function recordFieldSticky(name: string | null, mask: number, ctx: EngineCtx): void {
  if (!name || !ctx.recordSticky || !(mask & ALL) || !ctx.classFieldNames.has(name) || ctx.localNames?.has(name)) return;
  const next = (ctx.sticky.get(name) ?? 0) | (mask & ALL);
  if (next !== (ctx.sticky.get(name) ?? 0)) { ctx.sticky.set(name, next); ctx.stickyDirty = true; }
}

/**
 * A `+` chain that builds a SQL / LDAP / XPath / URL string around an untrusted operand, or drops an
 * HTML-escaped value into a <script> block. Sinks-by-shape: methods that build such strings and RETURN
 * them (instead of calling an execute API in the same method) are still where the injection happens.
 */
function checkConcatShapes(bin: CstNode, env: Env, ctx: EngineCtx): void {
  const ops = tokenKids(bin, "BinaryOperator");
  if (ops.length === 0 || !ops.every(t => t.image === "+") || tokenKids(bin, "AssignmentOperator").length > 0) return;
  let prefix = "";
  for (const operand of allNodes(bin, "unaryExpression")) {
    const lit = literalStringOf(operand);
    if (lit !== null) { prefix += lit; continue; }
    const m = taintMask(operand, env, ctx);
    const src = nodeText(operand);
    if (m & classOf("sql-injection") && SQL_START_RE.test(prefix)) {
      emit(ctx, "sql-injection", bin, src, "SQL string concatenation", undefined,
        `Untrusted '${src}' is concatenated into a SQL statement — use a PreparedStatement with bind parameters`);
    }
    if (m & classOf("ldap-injection") && (LDAP_SHAPE_RE.test(prefix) || LDAP_URL_RE.test(prefix))) {
      emit(ctx, "ldap-injection", bin, src, "LDAP filter concatenation", undefined,
        `Untrusted '${src}' is concatenated into an LDAP filter/URL — escape it (encodeForLDAP) or use parameterized filters`);
    }
    if (m & classOf("xpath-injection") && XPATH_SHAPE_RE.test(prefix)) {
      emit(ctx, "xpath-injection", bin, src, "XPath expression concatenation", undefined,
        `Untrusted '${src}' is concatenated into an XPath expression — use XPath variables/parameters`);
    }
    if (wasCleared(m, classOf("xss")) && SCRIPT_CONTEXT_RE.test(prefix)) {
      emit(ctx, "xss", bin, src, "HTML string", undefined,
        `HTML-escaped value '${src}' is placed inside a <script> block — HTML escaping does not neutralize JavaScript string context`);
    }
    prefix += "\u0000";
  }
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
  { parts: string[]; taint: number; rootVar: string | null; isNewExprOf: string | null } {
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
    let taint = rootVar !== null ? (env.get(rootVar) ?? 0) : 0;
    if (rootVar !== null && ctx.sticky.size > 0 && !ctx.localNames?.has(rootVar)) taint |= ctx.sticky.get(rootVar) ?? 0;
    if (parts.length >= 2) taint |= env.get(`${parts[0]}.${parts[1]}`) ?? 0;
    return { parts, taint, rootVar, isNewExprOf: null };
  }
  const newExpr = firstNode(prefix, "newExpression");
  if (newExpr) {
    const uc = firstNode(newExpr, "unqualifiedClassInstanceCreationExpression");
    const className = uc ? extractInstantiatedClassName(uc) : null;
    const argList = uc ? firstNode(uc, "argumentList") : undefined;
    const args = argList ? allNodes(argList, "expression") : [];
    let taint = args.reduce((m, a) => m | taintMask(a, env, ctx), 0);
    // `new String[] { a, b }` / `new byte[n]`: no class-instance-creation node; the array initializer's elements carry the taint
    if (!uc) taint = findAllNodes(newExpr, "expression").reduce((m, e) => m | taintMask(e, env, ctx), 0);
    return { parts: className ? [className] : [], taint, rootVar: null, isNewExprOf: className };
  }
  const paren = firstNode(prefix, "parenthesisExpression");
  if (paren) {
    const inner = firstNode(paren, "expression");
    return { parts: [], taint: inner ? taintMask(inner, env, ctx) : 0, rootVar: null, isNewExprOf: null };
  }
  // `switch (x) { case ... -> value; }` used as an expression
  const switchExpr = firstNode(prefix, "switchStatement");
  if (switchExpr) return { parts: [], taint: taintMask(switchExpr, env, ctx), rootVar: null, isNewExprOf: null };
  return { parts: [], taint: 0, rootVar: null, isNewExprOf: null };
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
  onCall?: (info: CallInfo) => void,
): number {
  const prefix = firstNode(primary, "primaryPrefix");
  if (!prefix) return 0;
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
      const argMasks = args.map(a => taintMask(a, env, ctx));
      const anyArgMask = argMasks.reduce((m, x) => m | x, 0);

      // Known sanitizer/escaping call -- the value passes THROUGH minus only
      // the classes this sanitizer actually neutralizes (an HTML encoder
      // leaves SQL/command/path taint intact), checked BEFORE
      // source/append/format/propagating-param so a sanitized value can't be
      // re-tainted by one of those in this same call. Still reports the call
      // (onCall) for sink-matching/seeding consistency, but skips every
      // taint-increasing branch below.
      const clears = sanitizerClears("java", calleeName || tail) ?? (ctx.htmlEscapers.has(tail) ? classOf("xss") : null);
      if (clears !== null) {
        chainTaint = applyClears(chainTaintBefore | anyArgMask, clears);
        onCall?.({ calleeName, tail, rootVar, args, chainTaintBefore, node: suffix, isNewURL, isNewOf: isNewExprOf });
        nameParts = [];
        continue;
      }

      // Servlet API source: request.getParameter/getHeader/getParameterValues/getQueryString.
      if (isRequestVar(rootVar, ctx) && SERVLET_SOURCE_CALLS.has(tail)) {
        chainTaint = ALL;
      }
      // Static/utility carriers (Path.of, String.join, URLDecoder.decode, Base64...decode, URI.create, ...)
      if (ARG_CARRYING_TAILS.has(tail) || ((tail === "get") && (rootVar === "Paths" || rootVar === "Path"))) {
        chainTaint |= anyArgMask;
        // a decoder RESTORES what an earlier encoder/sanitizer cleared
        if (tail === "decode" && /URLDecoder|Base64|Decoder/.test(calleeName || (rootVar ?? ""))) {
          chainTaint |= (anyArgMask >>> SHADOW) & ALL;
        }
      }
      // Container stores: `map.put(k, v)`, `list.add(x)` -- the receiver now holds the arguments
      if (MUTATOR_TAILS.has(tail) && rootVar) {
        const nextMask = (env.get(rootVar) ?? 0) | anyArgMask;
        env.set(rootVar, nextMask);
        recordFieldSticky(rootVar, anyArgMask, ctx);
      }
      // `f.apply(x)` on a local lambda variable: the lambda's body with its parameters bound to the arguments
      if (rootVar && FUNCTIONAL_TAILS.has(tail)) {
        const lam = ctx.lambdas.get(rootVar);
        if (lam) chainTaint |= lambdaResultMask(lam, argMasks, env, ctx);
        // calling a callback PARAMETER: (recall-biased) as tainted as what it is called with
        else if (ctx.currentParams?.has(rootVar)) chainTaint |= anyArgMask;
      }
      // fluent callbacks (thenApply / supplyAsync / map ...): the lambda sees the receiver value
      if (CALLBACK_TAILS.has(tail)) {
        for (const a of args) {
          const lam = soleLambda(a);
          if (lam) chainTaint |= lambdaResultMask(lam, [chainTaintBefore], env, ctx);
        }
      }
      // StringBuilder/StringBuffer .append() -- sticky, and propagate back onto the receiver variable.
      if (tail === "append") {
        chainTaint |= anyArgMask;
        if (rootVar) env.set(rootVar, (env.get(rootVar) ?? 0) | chainTaint);
      }
      // String.format(...) / "...".formatted(...) -- closes a real, confirmed gap.
      if (tail === "format" || tail === "formatted") {
        chainTaint |= anyArgMask;
      }
      // Same-file interprocedural, one hop: a call to a local method whose
      // return value is known (computeReturnTaintPropagatingJava) to depend
      // on SPECIFIC parameters -- e.g. executeQuery(buildQuery(uid)) where
      // buildQuery merely returns a tainted concatenation of uid and never
      // calls a sink itself. Only the arguments at the propagating indices
      // are checked, and only the classes that survive the callee's body.
      const propIdx = ctx.propagatingParams.get(tail);
      if (propIdx) {
        const callee = ctx.localMethods.get(tail);
        const shapes = callee?.paramShapes ?? [];
        let m = 0;
        for (const [i, surviving] of propIdx) {
          const shape = shapes[i];
          if (!shape) continue;
          for (const a of argsForShape(args, shape)) m |= taintMask(a, env, ctx) & surviving;
        }
        if (m) chainTaint |= m;
      }

      onCall?.({ calleeName, tail, rootVar, args, chainTaintBefore, node: suffix, isNewURL, isNewOf: isNewExprOf });

      // Generic passthrough: any other call keeps existing chain taint sticky
      // (a normal method's return isn't assumed tainted just because some
      // unrelated argument was, mirroring astTaint.ts's own passthrough rule).
      nameParts = [];
      continue;
    }
  }
  return chainTaint;
}

interface CallInfo {
  calleeName: string; tail: string; rootVar: string | null; args: CstNode[];
  chainTaintBefore: number; node: CstNode; isNewURL: boolean; isNewOf: string | null;
}

function taintMask(node: CstNode, env: Env, ctx: EngineCtx): number {
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
      if (ops.length > 0 && !ops.some(t => t.image === "+")) return 0;
      return operands.reduce((m, o) => m | taintMask(o, env, ctx), 0);
    }
    case "literal":
      return 0;
    case "conditionalExpression": {
      // `c ? a : b` -- the condition steers control and is NOT part of the value
      if (tokenKids(node, "QuestionMark").length === 0) {
        let m = 0;
        for (const key of Object.keys(node.children)) {
          for (const el of node.children[key]) {
            if (!isToken(el)) m |= taintMask(el as unknown as CstNode, env, ctx);
          }
        }
        return m;
      }
      return allNodes(node, "expression").reduce((m, e) => m | taintMask(e, env, ctx), 0);
    }
    case "switchStatement": {
      // A switch used as an EXPRESSION: value = union of the arm results, not the subject.
      let m = 0;
      const block = firstNode(node, "switchBlock");
      for (const rule of block ? allNodes(block, "switchRule") : []) {
        for (const c of allNodes(rule, "expression")) m |= taintMask(c, env, ctx);
      }
      for (const y of findAllNodes(node, "yieldStatement")) {
        const e = firstNode(y, "expression");
        if (e) m |= taintMask(e, env, ctx);
      }
      return m;
    }
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
      let m = 0;
      for (const key of Object.keys(node.children)) {
        for (const el of node.children[key]) {
          if (!isToken(el)) m |= taintMask(el, env, ctx);
        }
      }
      return m;
    }
  }
}

// ── Sink dispatch (invoked via walkPrimaryChain's onCall side-channel) ────

function checkCallSink(info: CallInfo, env: Env, ctx: EngineCtx) {
  const { tail, rootVar, args, chainTaintBefore, node, calleeName } = info;
  const argMasks = args.map(a => taintMask(a, env, ctx));
  const combined = chainTaintBefore | argMasks.reduce((m, x) => m | x, 0);
  const firstTaintedIdx = argMasks.findIndex(m => (m & ALL) !== 0);
  const sourceExpr = firstTaintedIdx >= 0 ? nodeText(args[firstTaintedIdx]) : calleeName;

  // One sink per call: a hit emits; a value that was tainted for this sink's
  // class but positively cleared by a sanitizer records a suppression
  // instead (for the regex-layer veto). Each sink is gated on ITS class, so
  // an HTML encoder no longer hides a SQL/command/path sink.
  const fire = (id: AstTaintJavaId, mask: number = combined, source: string = sourceExpr, sink: string = calleeName) => {
    const cls = classOf(id);
    if (mask & cls) emit(ctx, id, node, source, sink);
    else if (wasCleared(mask, cls)) ctx.suppressed?.push({ id, line: lineOf(node) });
  };

  if (tail === "executeQuery" || tail === "executeUpdate" || tail === "execute") {
    fire("sql-injection");
  } else if ((tail === "query" || tail === "update") && /jdbcTemplate/i.test(rootVar ?? "")) {
    fire("sql-injection");
  } else if (tail === "exec" && rootVar !== null) {
    fire("command-injection");
  } else if (tail === "sendRedirect") {
    fire("open-redirect");
  } else if (tail === "header" && args.length >= 2 && /^location$/i.test(stringLiteralValue(args[0]) ?? "")) {
    // Spring's fluent ResponseEntity.status(...).header("Location", next).build()
    // -- a modern REST idiom for redirects, distinct from the classic
    // Servlet response.sendRedirect(...) above but an equally real sink.
    fire("open-redirect", argMasks[1], nodeText(args[1]));
  } else if (tail === "getForObject" || tail === "postForObject" || tail === "exchange") {
    fire("ssrf");
  } else if (info.isNewURL && (tail === "openConnection" || tail === "openStream")) {
    fire("ssrf");
  } else if (tail === "get" && rootVar === "Paths") {
    fire("path-traversal");
  } else if (rootVar === "Files" && ["readString", "readAllBytes", "write", "newInputStream", "newOutputStream", "delete"].includes(tail)) {
    fire("path-traversal");
  } else if (tail === "search") {
    fire("ldap-injection");
  } else if (tail === "evaluate") {
    fire("xpath-injection");
  } else if (tail === "body" && hasHtmlTagNearby(ctx.lines, lineOf(node))) {
    fire("xss");
  }

  // ── Additional sinks (independent of the else-if chain above) ─────────────────
  const arg0 = args[0];
  // SQL: statement/query factories and String.format around SQL text
  if (["prepareStatement", "prepareCall", "createQuery", "createNativeQuery", "queryForObject", "queryForList", "queryForMap", "batchUpdate", "addBatch"].includes(tail) && arg0) {
    fire("sql-injection", argMasks[0], nodeText(arg0));
  }
  if (tail === "format" && rootVar === "String" && args.length >= 2 && SQL_START_RE.test(literalStringOf(arg0) ?? "")) {
    fire("sql-injection", argMasks.slice(1).reduce((m, x) => m | x, 0), nodeText(args[1]), "String.format");
  }
  // HTTP header injection: response.setHeader(name, value) and header-shaped map puts
  if (["setHeader", "addHeader", "setIntHeader", "setDateHeader", "addDateHeader"].includes(tail) && args.length >= 2) {
    fire("header-injection", argMasks[0] | argMasks[1], nodeText(args[1]));
  } else if ((tail === "put" || tail === "add" || tail === "set" || tail === "header") && args.length >= 2) {
    const key = literalStringOf(arg0);
    if (key && HTTP_HEADER_NAME_RE.test(key)) fire("header-injection", argMasks[1], nodeText(args[1]));
  }
  // path traversal: Path.of / Paths.get and the wider java.nio.file.Files surface
  if ((rootVar === "Path" || rootVar === "Paths") && (tail === "of" || tail === "get")) fire("path-traversal");
  if (rootVar === "Files" && ["writeString", "readAllLines", "lines", "copy", "move", "createFile", "createDirectories", "newBufferedReader", "newBufferedWriter", "list", "walk", "deleteIfExists", "exists"].includes(tail)) {
    fire("path-traversal");
  }
  // SSRF: java.net.http, raw sockets / name resolution
  if ((rootVar === "HttpRequest" && (tail === "uri" || tail === "newBuilder")) || (rootVar === "InetAddress" && tail === "getByName")) {
    fire("ssrf");
  }
  // deserialization: new ObjectInputStream(<tainted>).readObject(), XStream, SnakeYAML
  if ((tail === "readObject" || tail === "readUnshared") && (chainTaintBefore & ALL)) fire("insecure-deserialization", chainTaintBefore, "ObjectInputStream", tail);
  if (tail === "fromXML" && arg0) fire("insecure-deserialization", argMasks[0], nodeText(arg0));
  if ((tail === "load" || tail === "loadAs") && arg0 && (info.isNewOf === "Yaml" || ctx.varTypes.get(rootVar ?? "") === "Yaml")) {
    fire("insecure-deserialization", argMasks[0], nodeText(arg0));
  }
  // code execution: script engines, SpEL, reflection-selected classes/methods
  if ((tail === "eval" || tail === "parseExpression") && arg0) fire("eval-exec", argMasks[0], nodeText(arg0));
  if (((tail === "forName" && rootVar === "Class") || tail === "loadClass") && arg0) fire("eval-exec", argMasks[0], nodeText(arg0));
  if ((tail === "getMethod" || tail === "getDeclaredMethod") && arg0) fire("eval-exec", argMasks[0], nodeText(arg0));
  if ((tail === "getField" || tail === "getDeclaredField") && arg0) fire("mass-assignment", argMasks[0], nodeText(arg0));
  // regex built from user input
  if (arg0 && ((rootVar === "Pattern" && (tail === "compile" || tail === "matches")) ||
               (rootVar !== "Pattern" && (tail === "matches" || tail === "replaceAll" || tail === "replaceFirst" || tail === "split")))) {
    fire("redos", argMasks[0], nodeText(arg0));
  }
  // template with attacker-controlled TEXT: template.replace("${user}", user)
  if ((tail === "replace" || tail === "replaceAll") && arg0 && TEMPLATE_PLACEHOLDER_RE.test(literalStringOf(arg0) ?? "")) {
    fire("ssti", chainTaintBefore, rootVar ?? "template", tail);
  }
  // secret compared with equals(): a timing oracle
  if ((tail === "equals" || tail === "equalsIgnoreCase") && args.length === 1) {
    const argName = tokensText(arg0).split(".").pop()!.replace(/\(\)$/, "");
    const rootIsSecret = !!rootVar && SECRET_NAME_JAVA_RE.test(rootVar);
    if (((chainTaintBefore & ALL) && SECRET_NAME_JAVA_RE.test(argName)) || (rootIsSecret && (argMasks[0] & ALL))) {
      emit(ctx, "timing-attack", node, (chainTaintBefore & ALL) ? (rootVar ?? "value") : nodeText(arg0), "equals", undefined,
        "A secret is compared to attacker-supplied input with equals() — use MessageDigest.isEqual (constant time)");
    }
  }
  // weak digest
  if (tail === "getInstance" && (rootVar === "MessageDigest" || /MessageDigest\.getInstance$/.test(calleeName)) &&
      /^(?:MD5|MD2|MD4|SHA-?1)$/i.test(literalStringOf(arg0) ?? "")) {
    emit(ctx, "weak-crypto", node, literalStringOf(arg0) ?? "", "MessageDigest.getInstance", undefined,
      `MessageDigest.getInstance("${literalStringOf(arg0)}") is a broken/weak hash — use SHA-256+ (and a slow KDF such as bcrypt/Argon2 for passwords)`);
  }
  // servlet writer / print stream
  if (["println", "print", "write", "append", "printf"].includes(tail) && /^(?:response|resp|res|out|writer|pw|printWriter)$/i.test(rootVar ?? "") && arg0) {
    fire("xss", argMasks[0], nodeText(arg0));
  }
  // for (var e : tainted.entrySet()) t.put(e.getKey(), e.getValue()): the request decides which keys are set
  if (tail === "put" && args.length === 2 && ctx.entryLoopVars.some(v => tokensText(arg0) === `${v}.getKey()` && tokensText(args[1]) === `${v}.getValue()`)) {
    emit(ctx, "mass-assignment", node, nodeText(arg0), "Map.put", undefined,
      "Every entry of an attacker-controlled map is copied onto the target — the client decides which keys (role, admin, ...) get set; copy an explicit allowlist");
  }

  // Insecure deserialization: <var>.readObject() where <var> was declared
  // ObjectInputStream-typed and its OWN construction was built from tainted
  // data (tracked via env at the localVariableDeclaration site below).
  if (tail === "readObject" && rootVar && ctx.varTypes.get(rootVar) === "ObjectInputStream") {
    fire("insecure-deserialization", env.get(rootVar) ?? 0, rootVar, "readObject");
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
  const argMasks = args.map(a => taintMask(a, env, ctx));
  // Any bit (taint OR shadow) counts: a value that was tainted and then
  // sanitized must still reach `fire` so the suppression gets recorded.
  const firstIdx = argMasks.findIndex(m => m !== 0);
  if (firstIdx < 0) return;
  const sourceExpr = nodeText(args[firstIdx]);
  const fire = (id: AstTaintJavaId, sink: string) => {
    const cls = classOf(id);
    const combined = argMasks.reduce((m, x) => m | x, 0);
    if (combined & cls) emit(ctx, id, primaryNode, sourceExpr, sink);
    else if (wasCleared(combined, cls)) ctx.suppressed?.push({ id, line: lineOf(primaryNode) });
  };
  if (className === "ProcessBuilder") fire("command-injection", "new ProcessBuilder");
  if (className === "File" || className === "FileInputStream" || className === "FileOutputStream" ||
      className === "FileReader" || className === "FileWriter" || className === "RandomAccessFile") {
    fire("path-traversal", `new ${className}`);
  }
  if (className === "Socket") fire("ssrf", "new Socket");
  if (className === "BasicDBObject") fire("nosql-injection", "new BasicDBObject");
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
function computeReturnTaintPropagatingJava(method: LocalMethod, ctx: EngineCtx): Map<number, number> {
  // param index -> sink classes that still survive to the return value
  const propagatingIdx = new Map<number, number>();
  if (!method.body) return propagatingIdx;
  for (const shape of method.paramShapes) {
    let surviving = 0;
    // Path-sensitive: the mask is taken at EACH return with the env on that
    // path; a return inside a lambda is not this method's. Sink checks run
    // against a throwaway ctx copy.
    const walker = createWalkerJava({
      ...ctx, findings: [], seen: new Set(), suppressed: undefined, seededParams: new Map(), recordSticky: false,
      localNames: localNamesOfMethod(method), currentParams: new Set(method.paramShapes.map(p => p.name)),
      currentBody: method.body ?? undefined, entryLoopVars: [],
    },
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
function buildPropagatingMapJava(localMethods: Map<string, LocalMethod>, baseCtx: EngineCtx): PropagatingJava {
  const propagating: PropagatingJava = new Map();
  for (let round = 0; round < MAX_PROPAGATION_ROUNDS; round++) {
    let changed = false;
    const roundCtx: EngineCtx = { ...baseCtx, propagatingParams: propagating };
    for (const [name, method] of localMethods) {
      const found = computeReturnTaintPropagatingJava(method, roundCtx);
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
  // param index -> classes tainted at THIS call site
  const taintedIdx = new Map<number, number>();
  info.args.forEach((arg, i) => {
    const m = taintMask(arg, env, ctx) & ALL;
    if (!m) return;
    const shape = callee.paramShapes.find(s => s.isRest ? i >= s.index : s.index === i);
    if (shape) taintedIdx.set(shape.index, (taintedIdx.get(shape.index) ?? 0) | m);
  });
  if (taintedIdx.size === 0) return;
  const existing = ctx.seededParams.get(info.tail) ?? new Map<number, number>();
  for (const [i, m] of taintedIdx) existing.set(i, (existing.get(i) ?? 0) | m);
  ctx.seededParams.set(info.tail, existing);
}

// ── Location / ordering helpers (Chevrotain children are keyed by production, not source order) ──

function startOf(n: CstNode): number {
  return n.location?.startOffset ?? leftmostToken(n)?.startOffset ?? 0;
}
function endOf(n: CstNode): number {
  return n.location?.endOffset ?? startOf(n);
}
/** Every CstNode child, in SOURCE order. */
function orderedNodeKids(node: CstNode): CstNode[] {
  const out: CstNode[] = [];
  for (const key of Object.keys(node.children)) for (const el of node.children[key]) if (!isToken(el)) out.push(el as unknown as CstNode);
  return out.sort((a, b) => startOf(a) - startOf(b));
}

/**
 * Unwraps the transparent expression wrapper chain (expression ->
 * conditionalExpression -> binaryExpression -> unaryExpression -> primary) to
 * its single `primary`, or null when anything real is in the way (a ternary,
 * a binary operator, a prefix/suffix operator, a second operand).
 */
function soleUnaryPrimary(node: CstNode): CstNode | null {
  let cur: CstNode = node;
  for (let guard = 0; guard < 12; guard++) {
    if (cur.name === "primary") return cur;
    if (cur.name === "conditionalExpression" && tokenKids(cur, "QuestionMark").length > 0) return null;
    if (cur.name === "binaryExpression" && (tokenKids(cur, "BinaryOperator").length > 0 || tokenKids(cur, "Instanceof").length > 0)) return null;
    if (cur.name === "unaryExpression" && (tokenKids(cur, "UnaryPrefixOperator").length > 0 || tokenKids(cur, "UnarySuffixOperator").length > 0)) return null;
    const next = orderedNodeKids(cur);
    if (next.length !== 1) return null;
    cur = next[0];
  }
  return null;
}

/** `"a"`, `5`, `'c'`, `true` -- but never `null` (a null check proves nothing). */
function isLiteralExprJava(node: CstNode): boolean {
  const p = soleUnaryPrimary(node);
  if (!p || allNodes(p, "primarySuffix").length > 0) return false;
  const lit = firstNode(firstNode(p, "primaryPrefix") ?? p, "literal");
  return !!lit && leftmostToken(lit)?.image !== "null";
}

interface ChainEl { name: string; args?: CstNode[]; literal?: boolean }
/** A plain `a.b(x).c(y)` / `"lit".m(x)` chain as [{a},{b,args:[x]},{c,args:[y]}], or null for anything more exotic. */
function chainOfPrimary(primary: CstNode): ChainEl[] | null {
  const prefix = firstNode(primary, "primaryPrefix");
  if (!prefix) return null;
  const els: ChainEl[] = [];
  const fqn = firstNode(prefix, "fqnOrRefType");
  const lit = firstNode(prefix, "literal");
  if (fqn) {
    const first = firstNode(fqn, "fqnOrRefTypePartFirst");
    const firstId = first ? firstTok(firstNode(first, "fqnOrRefTypePartCommon") ?? first, "Identifier") : undefined;
    if (!firstId) return null;
    els.push({ name: firstId.image });
    for (const rest of allNodes(fqn, "fqnOrRefTypePartRest")) {
      const id = firstTok(firstNode(rest, "fqnOrRefTypePartCommon") ?? rest, "Identifier");
      if (id) els.push({ name: id.image });
    }
  } else if (lit) {
    els.push({ name: leftmostToken(lit)?.image ?? "", literal: leftmostToken(lit)?.image !== "null" });
  } else {
    return null;
  }
  for (const suffix of allNodes(primary, "primarySuffix")) {
    const inv = firstNode(suffix, "methodInvocationSuffix");
    const id = firstTok(suffix, "Identifier");
    if (inv) {
      const last = els[els.length - 1];
      if (!last || last.args) return null;
      const argList = firstNode(inv, "argumentList");
      last.args = argList ? allNodes(argList, "expression") : [];
    } else if (tokenKids(suffix, "Dot").length > 0 && id) {
      els.push({ name: id.image });
    } else {
      return null; // array index, method reference, ...
    }
  }
  return els;
}

// ── Narrow validation guards ────────────────────────────────────────────────
// Same policy as every other engine: only unambiguous proofs that a bare
// variable is safe -- literal equality, membership in a literal collection
// (`ALLOWED.contains(x)`, `Set.of("a","b").contains(x)`), strict numeric type
// tests (`x instanceof Integer`), `StringUtils.isNumeric(x)`. NOT recognized:
// regex matches, prefix checks, custom validators.

const NUMERIC_INSTANCEOF_JAVA = new Set([
  "Integer", "Long", "Short", "Byte", "Double", "Float", "Boolean", "BigDecimal", "BigInteger",
]);
const LITERAL_COLLECTION_FACTORIES = new Set(["List", "Set", "Arrays"]);
const COLLECTION_MUTATORS = new Set(["add", "addAll", "put", "putAll", "remove", "removeAll", "retainAll", "clear", "set"]);
const WRAPPING_COLLECTIONS = new Set(["HashSet", "LinkedHashSet", "TreeSet", "ArrayList", "LinkedList", "ImmutableSet", "ImmutableList"]);

/** `List.of("a","b")` / `Set.of(...)` / `Arrays.asList(...)` (all literal args), or `new HashSet<>(<that>)`. */
function isLiteralCollectionExprJava(expr: CstNode, depth = 0): boolean {
  const p = soleUnaryPrimary(expr);
  if (!p) return false;
  const chain = chainOfPrimary(p);
  if (chain && chain.length === 2 && LITERAL_COLLECTION_FACTORIES.has(chain[0].name) && (chain[1].name === "of" || chain[1].name === "asList")) {
    const args = chain[1].args ?? [];
    return args.length > 0 && args.every(isLiteralExprJava);
  }
  if (depth === 0) {
    const newExpr = firstNode(firstNode(p, "primaryPrefix") ?? p, "newExpression");
    const uc = newExpr ? firstNode(newExpr, "unqualifiedClassInstanceCreationExpression") : undefined;
    const cls = uc ? extractInstantiatedClassName(uc) : null;
    const argList = uc ? firstNode(uc, "argumentList") : undefined;
    const args = argList ? allNodes(argList, "expression") : [];
    return !!cls && WRAPPING_COLLECTIONS.has(cls) && args.length === 1 && isLiteralCollectionExprJava(args[0], 1);
  }
  return false;
}

/** A field/local EVERY declaration of which is a literal collection and which is never reassigned or mutated. */
function isLiteralCollectionVarJava(name: string, root: CstNode): boolean {
  const decls = findAllNodes(root, "variableDeclarator").filter(vd => {
    const id = firstNode(vd, "variableDeclaratorId");
    return (id ? firstTok(id, "Identifier")?.image : undefined) === name;
  });
  if (decls.length === 0) return false;
  for (const vd of decls) {
    const init = firstNode(vd, "variableInitializer");
    const expr = init ? firstNode(init, "expression") : undefined;
    if (!expr || !isLiteralCollectionExprJava(expr)) return false;
  }
  for (const bin of findAllNodes(root, "binaryExpression")) {
    if (tokenKids(bin, "AssignmentOperator").length === 0) continue;
    const lhs = firstNode(bin, "unaryExpression");
    if (lhs && bareIdentifierOf(lhs) === name) return false;
  }
  for (const primary of findAllNodes(root, "primary")) {
    const chain = chainOfPrimary(primary);
    if (chain && chain[0].name === name && chain[1] && COLLECTION_MUTATORS.has(chain[1].name)) return false;
  }
  return true;
}

// Chevrotain flattens a whole precedence chain into ONE binaryExpression:
// operands are `unaryExpression` children, operators are BinaryOperator /
// Instanceof tokens (in different keys, so they must be re-interleaved by
// offset). Conditions are decomposed here once, generically, for both the
// validation guards and the BOLA ownership check.

interface CondItem { off: number; key: string; node?: CstNode; tok?: IToken }
interface CondHandlers<T extends { holds: "true" | "false" }> {
  compare(l: CstNode, op: string, r: CstNode): T[];
  instanceOf(l: CstNode, typeNode: CstNode | undefined): T[];
  /** A bare method-call / identifier primary used as a condition. */
  call(primary: CstNode): T[];
}

function flipHolds<T extends { holds: "true" | "false" }>(t: T): T {
  return { ...t, holds: t.holds === "true" ? "false" : "true" };
}

function condItems(bin: CstNode): CondItem[] {
  const out: CondItem[] = [];
  for (const key of Object.keys(bin.children)) {
    for (const el of bin.children[key]) {
      if (isToken(el)) out.push({ off: el.startOffset, key, tok: el });
      else out.push({ off: startOf(el as unknown as CstNode), key, node: el as unknown as CstNode });
    }
  }
  return out.sort((a, b) => a.off - b.off);
}

function unarySides<T extends { holds: "true" | "false" }>(u: CstNode, h: CondHandlers<T>): T[] {
  const prefix = tokenKids(u, "UnaryPrefixOperator");
  if (prefix.some(t => t.image !== "!") || tokenKids(u, "UnarySuffixOperator").length > 0) return [];
  const primary = firstNode(u, "primary");
  if (!primary) return [];
  const paren = firstNode(firstNode(primary, "primaryPrefix") ?? primary, "parenthesisExpression");
  const inner = paren && allNodes(primary, "primarySuffix").length === 0 ? firstNode(paren, "expression") : undefined;
  const base = inner ? condSidesJava(inner, h) : h.call(primary);
  return prefix.length % 2 === 1 ? base.map(flipHolds) : base;
}

function segmentSides<T extends { holds: "true" | "false" }>(seg: CondItem[], h: CondHandlers<T>): T[] {
  const ops = seg.filter(i => i.tok && i.key === "BinaryOperator");
  const operands = seg.filter(i => i.node && i.key === "unaryExpression").map(i => i.node!);
  const inst = seg.find(i => i.tok && i.key === "Instanceof");
  if (inst) {
    const typeNode = seg.find(i => i.node && i.off > inst.off && i.key !== "unaryExpression")?.node;
    return operands.length === 1 && ops.length === 0 ? h.instanceOf(operands[0], typeNode) : [];
  }
  if (ops.length === 0 && operands.length === 1) return unarySides(operands[0], h);
  if (ops.length === 1 && operands.length === 2 && (ops[0].tok!.image === "==" || ops[0].tok!.image === "!=")) {
    return h.compare(operands[0], ops[0].tok!.image, operands[1]);
  }
  return [];
}

function binarySides<T extends { holds: "true" | "false" }>(bin: CstNode, h: CondHandlers<T>): T[] {
  const segs: CondItem[][] = [[]];
  const logical: string[] = [];
  for (const it of condItems(bin)) {
    if (it.tok && it.key === "BinaryOperator" && (it.tok.image === "&&" || it.tok.image === "||")) {
      logical.push(it.tok.image);
      segs.push([]);
    } else {
      segs[segs.length - 1].push(it);
    }
  }
  const per = segs.map(s => segmentSides(s, h));
  if (logical.length === 0) return per[0];
  // `a && b`: both hold when true. `a || b`: both fail when false. Mixed: no claim.
  if (logical.every(o => o === "&&")) return per.flat().filter(t => t.holds === "true");
  if (logical.every(o => o === "||")) return per.flat().filter(t => t.holds === "false");
  return [];
}

function condSidesJava<T extends { holds: "true" | "false" }>(expr: CstNode, h: CondHandlers<T>): T[] {
  let node: CstNode | undefined = expr;
  if (node.name === "expression") node = firstNode(node, "conditionalExpression");
  if (node?.name === "conditionalExpression") {
    if (tokenKids(node, "QuestionMark").length > 0) return [];
    node = firstNode(node, "binaryExpression");
  }
  return node?.name === "binaryExpression" ? binarySides(node, h) : [];
}

function guardHandlersJava(root: CstNode): CondHandlers<Guard> {
  return {
    compare(l, op, r) {
      const holds: "true" | "false" = op === "==" ? "true" : "false";
      const lName = bareIdentifierOf(l), rName = bareIdentifierOf(r);
      if (lName && isLiteralExprJava(r)) return [{ name: lName, holds }];
      if (rName && isLiteralExprJava(l)) return [{ name: rName, holds }];
      return [];
    },
    instanceOf(l, typeNode) {
      const name = bareIdentifierOf(l);
      const typeName = typeNode ? collectAllTokens(typeNode).filter(t => t.tokenType?.name === "Identifier").pop()?.image : undefined;
      return name && typeName && NUMERIC_INSTANCEOF_JAVA.has(typeName) ? [{ name, holds: "true" }] : [];
    },
    call(primary) {
      const chain = chainOfPrimary(primary);
      const m = chain?.[chain.length - 1];
      if (!chain || !m?.args) return [];
      const recv = chain.slice(0, -1);
      const arg0 = m.args[0];
      // "lit".equals(x) / x.equals("lit") / equalsIgnoreCase
      if ((m.name === "equals" || m.name === "equalsIgnoreCase") && m.args.length === 1 && recv.length === 1 && !recv[0].args) {
        if (recv[0].literal) { const n = bareIdentifierOf(arg0); if (n) return [{ name: n, holds: "true" }]; }
        else if (isLiteralExprJava(arg0)) return [{ name: recv[0].name, holds: "true" }];
      }
      // ALLOWED.contains(x) / Set.of("a","b").contains(x)
      if (m.name === "contains" && m.args.length === 1) {
        const n = bareIdentifierOf(arg0);
        if (n) {
          if (recv.length === 1 && !recv[0].args && isLiteralCollectionVarJava(recv[0].name, root)) return [{ name: n, holds: "true" }];
          if (recv.length === 2 && LITERAL_COLLECTION_FACTORIES.has(recv[0].name) && (recv[1].name === "of" || recv[1].name === "asList")
              && recv[1].args && recv[1].args.length > 0 && recv[1].args.every(isLiteralExprJava)) return [{ name: n, holds: "true" }];
        }
      }
      // StringUtils.isNumeric(x) / NumberUtils.isDigits(x) -- all-digits checks
      if (recv.length === 1 && !recv[0].args && ((recv[0].name === "StringUtils" && m.name === "isNumeric") || (recv[0].name === "NumberUtils" && m.name === "isDigits"))) {
        const n = arg0 ? bareIdentifierOf(arg0) : null;
        if (n) return [{ name: n, holds: "true" }];
      }
      return [];
    },
  };
}

// ── Path-sensitive statement walk ───────────────────────────────────────────
// One walker serves the interprocedural summary builder (no lambdas,
// collects return masks) and the main scan (sink checks, lambdas walked on a
// cloned env). Branches walk each arm on a CLONE of the env and join with
// may-taint OR (shared combinators in taint/taintCore.ts); an arm ending in
// return/throw is dropped from the join, and code after a terminating
// statement is dead and not walked.

interface WalkOptsJava {
  /** Walk lambda bodies (main scan) or ignore them (summaries). */
  descendFunctions: boolean;
  /** Called for each `return expr`, with the env on that path. */
  onReturn?: (expr: CstNode, env: Env, mask: (n: CstNode, e: Env) => number) => void;
}

const SEQ_WRAPPERS_JAVA = new Set([
  "statement", "statementWithoutTrailingSubstatement", "blockStatement", "labeledStatement", "synchronizedStatement",
]);

/** True when control cannot fall out of the end of `n` (return / throw, a block containing one, or an if whose every arm does). */
function statementTerminatesJava(n: CstNode | undefined): boolean {
  if (!n) return false;
  if (n.name === "returnStatement" || n.name === "throwStatement") return true;
  if (n.name === "blockStatements") return nodeKids(n, "blockStatement").some(statementTerminatesJava);
  if (n.name === "ifStatement") {
    const stmts = nodeKids(n, "statement");
    return stmts.length === 2 && statementTerminatesJava(stmts[0]) && statementTerminatesJava(stmts[1]);
  }
  return orderedNodeKids(n).some(statementTerminatesJava);
}

function lambdaParamNames(lambda: CstNode): string[] {
  const lp = firstNode(lambda, "lambdaParameters");
  if (!lp) return [];
  const names: string[] = [];
  const direct = firstTok(lp, "Identifier");
  if (direct) names.push(direct.image);
  for (const id of findAllNodes(lp, "variableDeclaratorId")) {
    const t = firstTok(id, "Identifier");
    if (t) names.push(t.image);
  }
  return names;
}

function createWalkerJava(ctx: EngineCtx, opts: WalkOptsJava) {
  const root = ctx.root;
  const guardHandlers = root ? guardHandlersJava(root) : undefined;
  const mask = (n: CstNode, e: Env) => taintMask(n, e, ctx);
  const guardsOf = (cond: CstNode | undefined): Guard[] => (cond && guardHandlers ? condSidesJava(cond, guardHandlers) : []);

  const walkStmts = (nodes: readonly CstNode[], env: Env): boolean => {
    for (const n of nodes) if (walk(n, env)) return true; // dead code after a terminator is not walked
    return false;
  };

  const walk = (node: CstNode, env: Env): boolean => {
    switch (node.name) {
      case "lambdaExpression": {
        if (opts.descendFunctions) {
          // A lambda sees captured outer variables (cloned env); its own
          // parameters shadow same-named outer ones and start untainted.
          const fenv = cloneEnv(env);
          for (const p of lambdaParamNames(node)) fenv.set(p, 0);
          const body = firstNode(node, "lambdaBody");
          if (body) walk(body, fenv);
        }
        return false;
      }

      case "block": {
        const bs = firstNode(node, "blockStatements");
        return bs ? walk(bs, env) : false;
      }
      case "blockStatements":
        return walkStmts(nodeKids(node, "blockStatement"), env);

      case "ifStatement": {
        const cond = firstNode(node, "expression");
        const stmts = nodeKids(node, "statement");
        const branches: Branch[] = [{
          visitCond: (e) => { if (cond) walk(cond, e); },
          guards: () => guardsOf(cond),
          body: (e) => (stmts[0] ? walk(stmts[0], e) : false),
        }];
        if (stmts[1]) branches.push({ body: (e) => walk(stmts[1], e) });
        return walkIfChain(env, branches);
      }

      case "whileStatement": {
        const cond = firstNode(node, "expression");
        if (cond) walk(cond, env);
        const body = firstNode(node, "statement");
        return walkLoop(env, (e) => (body ? walk(body, e) : false));
      }

      case "doStatement": {
        const body = firstNode(node, "statement");
        const cond = firstNode(node, "expression");
        const term = walkLoop(env, (e) => (body ? walk(body, e) : false));
        if (cond) walk(cond, env);
        return term;
      }

      case "basicForStatement": {
        const init = firstNode(node, "forInit");
        if (init) walk(init, env);
        const cond = firstNode(node, "expression");
        if (cond) walk(cond, env);
        const update = firstNode(node, "forUpdate");
        const body = firstNode(node, "statement");
        return walkLoop(env, (e) => {
          const t = body ? walk(body, e) : false;
          if (!t && update) walk(update, e);
          return t;
        });
      }

      case "enhancedForStatement": {
        const iter = firstNode(node, "expression");
        if (iter) walk(iter, env);
        const rmask = iter ? mask(iter, env) : 0;
        const decl = firstNode(node, "localVariableDeclaration");
        const vdl = decl ? firstNode(decl, "variableDeclaratorList") : undefined;
        for (const vd of vdl ? allNodes(vdl, "variableDeclarator") : []) {
          const id = firstNode(vd, "variableDeclaratorId");
          const nameTok = id ? firstTok(id, "Identifier") : undefined;
          if (nameTok) env.set(nameTok.image, rmask);
          // for (var e : tainted.entrySet()): remember the entry variable so e.getKey()/e.getValue() copies are recognised
          if (nameTok && iter && rmask & ALL && /entrySet\(\)$/.test(tokensText(iter))) ctx.entryLoopVars.push(nameTok.image);
        }
        const body = firstNode(node, "statement");
        const term = walkLoop(env, (e) => (body ? walk(body, e) : false));
        ctx.entryLoopVars.length = 0;
        return term;
      }

      case "tryStatement": {
        const t = firstNode(node, "tryWithResourcesStatement") ?? node;
        const resources = firstNode(t, "resourceSpecification");
        if (resources) walk(resources, env);
        const body = firstNode(t, "block");
        const catchesNode = firstNode(t, "catches");
        const catches = (catchesNode ? nodeKids(catchesNode, "catchClause") : []).map(c => {
          const param = firstNode(c, "catchFormalParameter");
          const id = param ? firstNode(param, "variableDeclaratorId") : undefined;
          const nameTok = id ? firstTok(id, "Identifier") : undefined;
          const cbody = firstNode(c, "block");
          return { bind: nameTok ? [nameTok.image] : [], body: (e: Env) => (cbody ? walk(cbody, e) : false) };
        });
        const fin = firstNode(t, "finally");
        const finBody = fin ? firstNode(fin, "block") : undefined;
        return walkTry(
          env,
          (e) => (body ? walk(body, e) : false),
          catches,
          finBody ? (e) => walk(finBody, e) : undefined,
        );
      }

      case "switchStatement": {
        const subject = firstNode(node, "expression");
        if (subject) walk(subject, env);
        const subjectName = subject ? bareIdentifierOf(subject) : null;
        const block = firstNode(node, "switchBlock");
        const clauses = block
          ? [...nodeKids(block, "switchBlockStatementGroup"), ...nodeKids(block, "switchRule")].sort((a, b) => startOf(a) - startOf(b))
          : [];
        return walkSwitch(env, clauses.map(cl => {
          const labels = nodeKids(cl, "switchLabel");
          const isDefault = labels.some(l => tokenKids(l, "Default").length > 0);
          const literalLabels = labels.length > 0 && labels.every(l => {
            const consts = nodeKids(l, "caseConstant");
            return consts.length > 0 && consts.every(isLiteralExprJava);
          });
          const bodyNodes = cl.name === "switchBlockStatementGroup"
            ? nodeKids(cl, "blockStatements")
            : orderedNodeKids(cl).filter(n => n.name !== "switchLabel");
          return {
            isDefault,
            // `case "a": case "b":` -- inside, the subject IS one of the literals.
            pre: (e: Env) => { if (subjectName && !isDefault && literalLabels) applyGuards(e, [subjectName]); },
            body: (e: Env) => walkStmts(bodyNodes, e),
          };
        }));
      }

      case "returnStatement": {
        const expr = firstNode(node, "expression");
        if (expr) {
          walk(expr, env);
          opts.onReturn?.(expr, env, mask);
          // a method that builds HTML and returns it hands attacker markup to whoever renders the string
          if (ctx.currentBody && methodHasHtmlEvidence(ctx.currentBody) && (mask(expr, env) & classOf("xss"))) {
            emit(ctx, "xss", node, nodeText(expr), "returned HTML string", undefined,
              `Untrusted '${nodeText(expr)}' is returned inside an HTML string built by this method — encode it (OWASP Java Encoder) before it is rendered`);
          }
        }
        return true;
      }

      case "throwStatement":
        for (const c of orderedNodeKids(node)) walk(c, env);
        return true;

      default:
        break;
    }

    // Statement wrappers: a sequence of one real child -- terminates when it does.
    if (SEQ_WRAPPERS_JAVA.has(node.name)) return walkStmts(orderedNodeKids(node), env);

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
        env.set(nameTok.image, initExpr ? taintMask(initExpr, env, ctx) : 0);
        if (declaredTypeSimpleName) ctx.varTypes.set(nameTok.image, declaredTypeSimpleName);
        // FunctionLike f = x -> ...;  remember the lambda so f.apply(v) resolves to its body
        const lam = soleLambda(init) ?? soleLambda(initExpr);
        if (lam) ctx.lambdas.set(nameTok.image, lam); else ctx.lambdas.delete(nameTok.image);
      }
    }

    // Assignment: `x = expr;`, `x += expr;`, `obj.field = expr;`. Chevrotain
    // flattens a plain reference AND an assignment into the SAME
    // `binaryExpression` production -- an assignment is the one with a
    // present `AssignmentOperator` child. A compound operator keeps whatever
    // taint the target already had (OR), unlike plain `=`.
    if (node.name === "binaryExpression") {
      const assignTok = tokenKids(node, "AssignmentOperator")[0];
      if (assignTok) {
        const lhsUnary = firstNode(node, "unaryExpression");
        const rhsExpr = firstNode(node, "expression");
        const key = assignmentTargetKey(lhsUnary, env, ctx);
        if (key) {
          const m = rhsExpr ? taintMask(rhsExpr, env, ctx) : 0;
          env.set(key, assignTok.image === "=" ? m : m | (env.get(key) ?? 0));
          // a write to a class field is visible to every method that reads it
          const parts = key.split(".");
          recordFieldSticky(parts[0] === "this" ? parts[1] ?? null : parts[0], m, ctx);
        }
      }
    }

    // a + chain that builds SQL / LDAP / XPath / URL text around an untrusted operand
    if (node.name === "binaryExpression") checkConcatShapes(node, env, ctx);

    // Sink-visiting: every `primary` anywhere is a candidate call-chain root.
    if (node.name === "primary") {
      const prefix = firstNode(node, "primaryPrefix");
      if (prefix) checkNewExpressionSink(prefix, env, ctx, node);
      walkPrimaryChain(node, env, ctx, (info) => { checkCallSink(info, env, ctx); seedLocalMethodParams(info, env, ctx); });
    }

    for (const key of Object.keys(node.children)) {
      for (const el of node.children[key]) {
        if (!isToken(el)) walk(el as unknown as CstNode, env);
      }
    }
    return false;
  };

  return { walk };
}

/** Main-scan entry: walks one method body (or a seeded re-walk) with sink checks and call-site seeding. */
function walkForDeclarationsAndSinks(node: CstNode, env: Env, ctx: EngineCtx) {
  createWalkerJava(ctx, { descendFunctions: true }).walk(node, env);
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

/** The resource-id params `arg` references, directly or one hop back through a
 * local variable's own initializer (covers `.save(entity)` where `entity` was
 * built from the tainted id earlier in the method). */
function resourceIdsIn(arg: CstNode, resourceIdParamNames: Set<string>, localInits: Map<string, CstNode>): Set<string> {
  const direct = [...collectIdentifiers(arg)].filter(id => resourceIdParamNames.has(id));
  if (direct.length > 0) return new Set(direct);
  const bare = bareIdentifierOf(arg);
  if (bare && localInits.has(bare)) {
    return new Set([...collectIdentifiers(localInits.get(bare)!)].filter(id => resourceIdParamNames.has(id)));
  }
  return new Set();
}

interface BolaSinkCandidate { node: CstNode; sourceExpr: string; sinkExpr: string; idNames: Set<string> }

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
    const idNames = resourceIdsIn(args[0], resourceIdParamNames, localInits);
    if (idNames.size > 0) candidates.push({ node, sourceExpr: nodeText(args[0]), sinkExpr: calleeName, idNames });
    return;
  }
  if (BOLA_MAP_ACCESS_METHODS.has(tail) && rootVar !== null && classFieldNames.has(rootVar)) {
    const idNames = resourceIdsIn(args[0], resourceIdParamNames, localInits);
    if (idNames.size > 0) candidates.push({ node, sourceExpr: nodeText(args[0]), sinkExpr: calleeName, idNames });
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
    const idNames = resourceIdsIn(args[0], resourceIdParamNames, localInits);
    if (idNames.size > 0) candidates.push({ node: primary, sourceExpr: nodeText(args[0]), sinkExpr: `new ${className}`, idNames });
  }
}

/** Ancestors of `target` from `root` down to (excluding) `target`, found by source-offset containment. */
function pathTo(root: CstNode, target: CstNode): CstNode[] {
  const ts = startOf(target), te = endOf(target);
  const path: CstNode[] = [];
  let cur: CstNode = root;
  for (let guard = 0; guard < 400; guard++) {
    if (cur === target) break;
    path.push(cur);
    const next = orderedNodeKids(cur).find(c => c === target || (startOf(c) <= ts && endOf(c) >= te));
    if (!next) break;
    cur = next;
  }
  return path;
}

/** blockStatement -> statement -> ifStatement, or undefined. */
function unwrapIfStatement(bs: CstNode): CstNode | undefined {
  let cur: CstNode | undefined = bs;
  for (let guard = 0; guard < 4 && cur; guard++) {
    if (cur.name === "ifStatement") return cur;
    const kidsOf = orderedNodeKids(cur);
    cur = kidsOf.length === 1 ? kidsOf[0] : undefined;
  }
  return undefined;
}

interface OwnSide { holds: "true" | "false" }

/**
 * Does an ownership comparison for one of `idNames` DOMINATE `sink`? Walks the
 * sink's ancestors: it must sit in the arm of an if (or ternary) whose
 * condition establishes ownership on that side, or come after an earlier
 * sibling if whose OTHER arm always terminates (return/throw). A comparison
 * that is unused, follows the lookup, or guards a different branch no longer
 * suppresses -- the old check was "a comparison exists anywhere in the method".
 */
function ownershipDominatesJava(
  sink: CstNode, body: CstNode, idNames: Set<string>, principalNames: Set<string>,
  localInits: Map<string, CstNode>, ctx: EngineCtx,
): boolean {
  const make = (resolve: boolean): CondHandlers<OwnSide> => ({
    compare: (l, op, r) => (comparisonSuppresses(l, r, idNames, principalNames) ? [{ holds: op === "==" ? "true" : "false" }] : []),
    instanceOf: () => [],
    call: (primary) => {
      let hit = false;
      const chain = chainOfPrimary(primary);
      // `isOwner` -- a boolean local resolved ONE hop to its initializer
      if (resolve && chain && chain.length === 1 && !chain[0].args && localInits.has(chain[0].name)) {
        return condSidesJava(localInits.get(chain[0].name)!, make(false));
      }
      walkPrimaryChain(primary, new Map(), ctx, (info) => {
        if (info.tail !== "equals") return;
        if (info.rootVar === "Objects" && info.args.length === 2) {
          if (comparisonSuppresses(info.args[0], info.args[1], idNames, principalNames)) hit = true;
        } else if (info.args[0] && comparisonSuppressesEquals(info.rootVar, info.args[0], idNames, principalNames)) {
          hit = true;
        }
      });
      return hit ? [{ holds: "true" }] : [];
    },
  });
  const own = make(true);
  const sidesOf = (cond: CstNode | undefined, isBinary = false): OwnSide[] =>
    !cond ? [] : isBinary ? binarySides(cond, own) : condSidesJava(cond, own);

  const path = pathTo(body, sink);
  for (let i = 0; i < path.length - 1; i++) {
    const a = path[i], child = path[i + 1];
    if (a.name === "ifStatement") {
      const cond = firstNode(a, "expression");
      const stmts = nodeKids(a, "statement");
      if (cond && child !== cond) {
        const sides = sidesOf(cond);
        if (child === stmts[0] && sides.some(s => s.holds === "true")) return true;
        if (child === stmts[1] && sides.some(s => s.holds === "false")) return true;
      }
    } else if (a.name === "conditionalExpression" && tokenKids(a, "QuestionMark").length > 0) {
      const condBin = firstNode(a, "binaryExpression");
      const arms = nodeKids(a, "expression");
      if (condBin && child !== condBin) {
        const sides = sidesOf(condBin, true);
        if (child === arms[0] && sides.some(s => s.holds === "true")) return true;
        if (child === arms[1] && sides.some(s => s.holds === "false")) return true;
      }
    } else if (a.name === "blockStatements") {
      const list = nodeKids(a, "blockStatement");
      const idx = list.indexOf(child);
      for (let j = 0; j < idx; j++) {
        const ifN = unwrapIfStatement(list[j]);
        if (!ifN) continue;
        const cond = firstNode(ifN, "expression");
        const stmts = nodeKids(ifN, "statement");
        const sides = sidesOf(cond);
        // the arm that does NOT establish ownership never reaches what follows
        if (sides.some(s => s.holds === "false") && statementTerminatesJava(stmts[0])) return true;
        if (sides.some(s => s.holds === "true") && stmts[1] && statementTerminatesJava(stmts[1])) return true;
      }
    }
  }
  return false;
}

/**
 * Per-method post-check, not per-call-site: candidate sinks are collected
 * during a structural pass, and each is emitted unless an ownership
 * comparison for ITS resource id dominates it (ownershipDominatesJava).
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
  for (const primary of findAllNodes(method.body, "primary")) {
    walkPrimaryChain(primary, new Map(), ctx, (info) => {
      checkBolaSinkCandidate(info, method.resourceIdParamNames, ctx.classFieldNames, localInits, candidates);
    });
  }
  checkBolaConstructorSinkCandidates(method, method.resourceIdParamNames, localInits, candidates);

  const severity: "medium" | "high" = method.authMeta.verbTier === "read" ? "medium" : "high";
  for (const c of candidates) {
    if (ownershipDominatesJava(c.node, method.body, c.idNames, principalNames, localInits, ctx)) continue;
    emit(ctx, "bola-missing-ownership-check", c.node, c.sourceExpr, c.sinkExpr, severity);
  }
}

// ── Entry point ──────────────────────────────────────────────────────────

export interface JavaScanOptions {
  /**
   * Also treat the un-annotated String/collection/byte[] parameters of public methods that nothing in the
   * file calls as untrusted input (library/handler code without framework annotations). Findings that exist
   * ONLY because of this are returned with `entryPointSeeded: true` so callers can lower their confidence.
   * Default false: only annotated parameters and request.getParameter()-style calls are sources.
   */
  entryPoints?: boolean;
}

export function scanAstTaintJava(
  content: string, filePath: string, cst: CstNode,
  // Sinks whose argument was tainted for the sink's class but positively
  // cleared by a sanitizer -- see EngineCtx.suppressed.
  suppressedOut?: SuppressedSink[],
  opts?: JavaScanOptions,
): AstTaintJavaFinding[] {
  const strict = runJavaScan(content, filePath, cst, suppressedOut, false);
  if (!opts?.entryPoints) return strict;
  const relaxed = runJavaScan(content, filePath, cst, suppressedOut, true);
  const have = new Set(strict.map(f => `${f.id}:${f.line}`));
  return [...strict, ...relaxed.filter(f => !have.has(`${f.id}:${f.line}`)).map(f => ({ ...f, entryPointSeeded: true }))];
}

function runJavaScan(
  content: string, filePath: string, cst: CstNode, suppressedOut: SuppressedSink[] | undefined, withEntryPoints: boolean,
): AstTaintJavaFinding[] {
  try {
    const lines = content.split("\n");
    const localMethods = collectLocalMethods(cst);
    const ctx: EngineCtx = {
      content, lines, localMethods, propagatingParams: new Map(), seededParams: new Map(),
      varTypes: new Map(), classFieldNames: collectClassFieldNames(cst), root: cst, findings: [], seen: new Set(),
      suppressed: suppressedOut,
      sticky: new Map(), stickyDirty: false, recordSticky: false, lambdas: new Map(), entryLoopVars: [], htmlEscapers: new Set(),
    };
    // structural HTML escapers, and parameter types (so a `HttpServletRequest r` parameter is recognised as the request)
    for (const [name, m] of localMethods) {
      if (m.body && isHtmlEscaperBody(m.body)) ctx.htmlEscapers.add(name);
      for (const p of m.paramShapes) if (!ctx.varTypes.has(p.name)) ctx.varTypes.set(p.name, p.type);
    }
    const propagating = buildPropagatingMapJava(localMethods, ctx);
    for (const [name, idx] of propagating) ctx.propagatingParams.set(name, idx);

    // Which local methods are called from elsewhere in the file? The rest are ENTRY POINTS: their
    // String/collection/byte[] parameters are the untrusted input (library/handler code without framework annotations).
    const calledNames = new Set<string>();
    for (const [, m] of localMethods) {
      if (!m.body) continue;
      for (const p of findAllNodes(m.body, "primary")) {
        walkPrimaryChain(p, new Map(), ctx, (info) => { if (info.tail !== m.name) calledNames.add(info.tail); });
      }
    }
    const isEntryPoint = (m: LocalMethod): boolean =>
      !!m.body && !m.isPrivate && m.springParamNames.size === 0 && !calledNames.has(m.name) &&
      !NON_ENTRY_METHOD_RE.test(m.name) && m.paramShapes.some(p => !p.annotated && STRINGY_PARAM_TYPE_RE.test(p.type));

    const enter = (m: LocalMethod) => {
      ctx.localNames = localNamesOfMethod(m);
      ctx.currentParams = new Set(m.paramShapes.map(p => p.name));
      ctx.currentBody = m.body ?? undefined;
      ctx.entryLoopVars.length = 0;
    };

    ctx.recordSticky = true;
    const walkAll = (withBola: boolean) => {
      for (const [, method] of localMethods) {
        if (!method.body) continue;
        enter(method);
        const env: Env = new Map();
        // Only Spring-annotated params are true sources at method entry -- an un-annotated parameter is not
        // automatically tainted (unlike the interprocedural pre-pass above, which deliberately seeds each param
        // independently to answer a different, broader question) -- EXCEPT the parameters of entry points.
        method.springParamNames.forEach(p => env.set(p, ALL));
        if (withEntryPoints && isEntryPoint(method)) {
          for (const p of method.paramShapes) if (!p.annotated && STRINGY_PARAM_TYPE_RE.test(p.type)) env.set(p.name, ALL);
        }
        walkForDeclarationsAndSinks(method.body, env, ctx);
        if (withBola) collectBolaFindings(method, ctx);
      }
    };
    walkAll(true);
    // A field written by a method declared AFTER the one that reads it: walk again with what the first pass learned.
    for (let i = 0; i < 2 && ctx.stickyDirty; i++) {
      ctx.stickyDirty = false;
      walkAll(false);
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
        const signature = `${methodName}:${[...idxSet].sort((a, b) => a[0] - b[0]).map(([i, m]) => `${i}=${m}`).join(",")}`;
        if (walkedSignatures.has(signature)) continue;
        walkedSignatures.add(signature);
        changed = true;
        enter(method);
        const env: Env = new Map();
        for (const [idx, m] of idxSet) {
          const shape = method.paramShapes[idx];
          if (shape) env.set(shape.name, m);
        }
        walkForDeclarationsAndSinks(method.body, env, ctx);
      }
      if (!changed) break;
    }

    // A hand-rolled JWT payload decode in a file that never verifies a signature
    if (!/\bJwts\b|SignedJWT|JWSVerifier|io\.jsonwebtoken|com\.auth0|nimbusds|\.verify\(/.test(content)) {
      for (const [, method] of localMethods) {
        if (!method.body) continue;
        const text = content.slice(startOf(method.body), endOf(method.body) + 1);
        if (/\.split\(\s*"(?:\\\\\.|\.)"\s*\)/.test(text) && /Base64/.test(text)) {
          emit(ctx, "jwt-none-alg", method.body, "token", "manual JWT decode", undefined,
            "JWT payload is base64-decoded by hand and the file never verifies a signature — claims (role, sub, ...) are attacker-controlled; use a JWT library's verify()");
        }
      }
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
