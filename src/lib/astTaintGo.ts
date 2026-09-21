/**
 * Real AST-based taint engine for Go — Phase 4 of the multi-language OWASP
 * Top 10 hardening effort (see astTaint.ts for Phase 1/JS-TS and
 * astTaintPython.ts for Phase 2/Python, whose five-stage architecture --
 * sources, sinks, propagation, interprocedural, findings -- this file
 * mirrors using web-tree-sitter + tree-sitter-wasms' prebuilt
 * tree-sitter-go.wasm grammar, same as Python's Phase 2 engine).
 *
 * Same warm-cache contract as astTaintPython.ts: WASM instantiation is
 * genuinely async, but analyzeFile()/runScan() in scanner.ts are used
 * synchronously from ~90 call sites -- this module fires WASM init at
 * import time and exposes a synchronous parse function that returns null
 * until the parser is warm. Production awaits warmGoTaintEngine() from
 * src/instrumentation.ts; a cold serverless instance that misses the
 * warm-up window gets regex-only results for that one request, never a
 * crash or a wrong answer.
 *
 * Runs ADDITIVELY alongside every existing Go regex/named-taint detector in
 * scanner.ts (extractTaintedVars' Go branch, findNamedTaintCommandInjectionGo,
 * findNamedTaintIDORGo, findSSRFGoNewRequest, etc.) -- none of those are
 * touched, removed, or replaced. Reuses existing finding ids (sql-injection,
 * command-injection, ssrf, path-traversal, open-redirect,
 * insecure-deserialization, idor), all already wired through cweMap.ts, so
 * no new UI wiring is needed.
 *
 * Deliberately scoped to real data-flow (source-reaches-sink) questions
 * only. Explicitly EXCLUDED, matching astTaintJava.ts's own precedent of
 * leaving "hardening-absence" checks to the regex layer: insecure-randomness,
 * weak-crypto, cookie-no-httponly/cookie-no-secure, pii-in-logs. None of
 * those ask "does tainted input reach a sink" -- they ask "is a hardening
 * flag set/absent" -- and the existing regex detectors for them
 * (findInsecureRandomnessGoFunc, the http.Cookie{} struct-literal branch,
 * etc.) are the structurally right tool, unchanged by this phase.
 *
 * Also deliberately excluded this phase (see the approved plan for the
 * reasoning): cross-file taint (same-file only, matching Python/Java) and
 * sanitizer/de-taint recognition (same "nothing ever de-taints" model as
 * every other engine here -- makeIsTaintedGo's combinators are all
 * `||`/`.some()`).
 *
 * The IDOR check is a deliberate AST-taint + line-window-context hybrid,
 * not pure AST: whether a nearby line contains an ownership-check keyword
 * is reused as-is from scanner.ts's IDOR_AUTH_CHECK_NEARBY_RE (passed in by
 * the caller), consistent with astTaintJava.ts's own BOLA detector mixing a
 * structural AST fact (a tainted id reaching a lookup sink) with a
 * non-AST suppression check (annotation/keyword presence) -- "is there an
 * ownership check nearby" is not a fact a parser alone can answer.
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { Parser, Language } = require("web-tree-sitter") as typeof import("web-tree-sitter");
import type { Node as SyntaxNode, Language as LanguageT, Parser as ParserT } from "web-tree-sitter";
import { ensureTreeSitterInit } from "./treeSitterRuntime";
import { ALL, applyClears, classOf, wasCleared, type SuppressedSink, type TaintEnv } from "./taint/taintCore";
import { sanitizerClears } from "./taint/sanitizers";

// See astTaintPython.ts's identical helper for why: require.resolve(...)
// from inside webpack-bundled code doesn't do real filesystem resolution,
// even for an externalized package -- it returns webpack's internal
// numeric module id instead of a path. __non_webpack_require__ escapes
// that, giving a real on-disk path to read raw .wasm bytes from.
declare const __non_webpack_require__: NodeJS.Require | undefined;
function nodeRequire(): NodeJS.Require {
  // eslint-disable-next-line no-undef
  return typeof __non_webpack_require__ !== "undefined" ? __non_webpack_require__ : require;
}

export type AstTaintGoId =
  | "sql-injection" | "command-injection" | "ssrf" | "path-traversal"
  | "open-redirect" | "insecure-deserialization" | "idor";

export interface AstTaintGoFinding {
  id:         AstTaintGoId;
  line:       number;
  detail:     string;
  sourceExpr: string;
  sinkExpr:   string;
}

// ── Parser lifecycle (warm-cache pattern -- see astTaintPython.ts's docblock) ──

let langPromise: Promise<LanguageT> | null = null;
let parserPool: ParserT | null = null;

function initGoParser(): Promise<LanguageT> {
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
      const wasmPath = path.join(nodeModulesDir, "tree-sitter-wasms", "out", "tree-sitter-go.wasm");
      const lang = await Language.load(new Uint8Array(fs.readFileSync(wasmPath)));
      const p = new Parser();
      p.setLanguage(lang);
      parserPool = p;
      console.log("[astTaintGo] Go AST taint engine ready");
      return lang;
    })().catch(err => {
      console.error("[astTaintGo] WASM init failed -- Go AST taint scanning disabled, regex detectors unaffected:", err);
      throw err;
    });
  }
  return langPromise;
}
// Fire at module import time, skipped under Jest for the same reason
// astTaintPython.ts skips it: dozens of unrelated test files transitively
// import this module via scanner.ts, none of which await this promise.
// astTaintGo.test.ts calls warmGoTaintEngine() explicitly in beforeAll instead.
if (!process.env.JEST_WORKER_ID) {
  void initGoParser().catch(() => { /* already logged above */ });
}

export function isGoParserReady(): boolean {
  return parserPool !== null;
}

/** Awaits WASM readiness. Call from instrumentation.ts (prod) or a test beforeAll. */
export async function warmGoTaintEngine(): Promise<void> {
  await initGoParser().catch(() => { /* already logged; callers just proceed regex-only */ });
}

export function parseGoSourceSync(content: string, filePath: string): SyntaxNode | null {
  if (!parserPool) return null;
  try {
    return parserPool.parse(content)?.rootNode ?? null;
  } catch (err) {
    console.error(`[astTaintGo] parse threw for ${filePath}:`, err);
    return null;
  }
}

// ── Enclosing-function lookup (shared with reachability.ts's resolver) ──────

/** Deepest tree-sitter node whose source range spans 0-based row `row`. */
export function findNodeAtRowGo(root: SyntaxNode, row: number): SyntaxNode {
  let node = root;
  for (;;) {
    const child = node.namedChildren.find(c => c && row >= c.startPosition.row && row <= c.endPosition.row);
    if (!child) return node;
    node = child;
  }
}

/**
 * Walks up to the nearest enclosing function_declaration (a package-level
 * `func foo(...)`) or method_declaration (a receiver method,
 * `func (s *Server) foo(...)`) and reads its `name` field -- present on
 * both node types, confirmed directly against the pinned tree-sitter-go
 * grammar (method_declaration's name field returns a field_identifier
 * rather than an identifier, but .text works identically either way).
 * Matches callGraph.ts's regex-based tryMatchFunc() naming convention
 * closely enough for reachability.ts's name-based lookup to work for both
 * shapes -- unlike Python's resolver, this is NOT restricted to
 * column-0/module-level: Go has no separate "class method" concept the way
 * Python does, so there's no equivalent ambiguity to guard against.
 */
export function findEnclosingFunctionNameGo(node: SyntaxNode): string {
  let cur: SyntaxNode | null = node;
  while (cur) {
    if (cur.type === "function_declaration" || cur.type === "method_declaration") {
      const nameNode = cur.childForFieldName("name");
      if (nameNode) return nameNode.text;
    }
    cur = cur.parent;
  }
  return "unknown";
}

// ── Taint sources ─────────────────────────────────────────────────────────
// Call-shaped, not property-shaped like JS/Python -- Go's idiom is
// r.URL.Query().Get("id"), not a bare attribute access. Matches the exact
// source vocabulary scanner.ts's TAINT_SOURCES/extractTaintedVars Go branch
// already covers, so this engine matches, never narrows, existing recall.

const GIN_ECHO_FIBER_METHODS = new Set(["Param", "Params", "Query", "QueryParam", "PostForm"]);

/** Resolves a selector_expression/identifier chain to dotted text, e.g.
 * `r.URL.Query` -> "r.URL.Query". Mirrors calleeText/calleeTextPy exactly. */
function calleeTextGo(node: SyntaxNode): string | null {
  if (node.type === "identifier" || node.type === "field_identifier") return node.text;
  if (node.type === "selector_expression") {
    const operand = node.childForFieldName("operand");
    const field = node.childForFieldName("field");
    if (!operand || !field) return null;
    const base = calleeTextGo(operand);
    return base ? `${base}.${field.text}` : null;
  }
  return null;
}

function argListOfGo(call: SyntaxNode): SyntaxNode[] {
  const args = call.childForFieldName("arguments");
  if (!args) return [];
  return args.namedChildren.filter((n): n is SyntaxNode => !!n);
}

// r.URL.Query().Get(...) / r.Header.Get(...) embed a CALL in the middle of
// their own selector chain (`.Query()` returns a url.Values, `.Get` is then
// called on THAT) -- calleeTextGo structurally can't resolve through a call
// node, so these are recognized by matching the call's own raw source text
// directly instead, the same "r." convention scanner.ts's existing
// TAINT_SOURCES regex list already relies on (Go's overwhelming handler
// convention: the *http.Request parameter is always named `r`).
const GO_CHAINED_SOURCE_CALL_RE = /^r\.(?:URL\.Query\(\)\.Get|Header\.Get|FormValue|PostFormValue)\s*\(/;

function isTaintSourceExprGo(node: SyntaxNode): boolean {
  if (node.type === "call_expression") {
    if (GO_CHAINED_SOURCE_CALL_RE.test(node.text)) return true;
    const fn = node.childForFieldName("function");
    const text = fn ? calleeTextGo(fn) : null;
    if (!text) return false;
    // chi.URLParam(r, "id")
    if (text === "chi.URLParam" || text.endsWith(".URLParam")) return true;
    // gin/echo/fiber: c.Param("id") / c.Query("id") / c.QueryParam("id") / c.PostForm("id")
    if (text.startsWith("c.")) {
      const method = text.slice(2);
      if (GIN_ECHO_FIBER_METHODS.has(method)) return true;
    }
    return false;
  }
  if (node.type === "index_expression") {
    const operand = node.childForFieldName("operand");
    // mux.Vars(r)["id"] -- operand is itself a call_expression, not a
    // resolvable dotted name; check that shape directly via raw text too
    // (same embedded-call reason as GO_CHAINED_SOURCE_CALL_RE above).
    if (operand?.type === "call_expression" && /^mux\.Vars\s*\(/.test(operand.text)) return true;
    // r.Header["X-Name"]
    const text = operand ? calleeTextGo(operand) : null;
    if (text === "r.Header" || text?.endsWith(".Header")) return true;
    return false;
  }
  return false;
}

// ── Sink dispatch table ──────────────────────────────────────────────────
// sql-injection and idor are handled as separate, independent checks (see
// scanAstTaintGo below), not through this table -- a single .QueryRow(...)
// call can legitimately be BOTH a sql-injection candidate (if its QUERY
// STRING argument, args[0], is tainted -- built via concatenation/Sprintf)
// AND an idor candidate (if its bind-parameter id argument is tainted with
// no ownership check nearby) -- two different questions about two different
// arguments of the same call, not mutually exclusive categories a single
// dispatch table entry could represent.

interface SinkMatch { id: AstTaintGoId; sinkExpr: string; args: SyntaxNode[] }

const FS_SINK_METHODS = new Set(["Open", "Create", "OpenFile", "ReadFile"]);

function matchSinkGo(call: SyntaxNode): SinkMatch | null {
  const fnNode = call.childForFieldName("function");
  if (!fnNode) return null;
  const text = calleeTextGo(fnNode);
  if (!text) return null;
  const parts = text.split(".");
  const tail = parts[parts.length - 1];
  const args = argListOfGo(call);

  if (text === "exec.Command" || text === "exec.CommandContext") {
    return { id: "command-injection", sinkExpr: text, args };
  }
  if (text === "http.Get" || text === "http.Post" || text === "http.Head") {
    return { id: "ssrf", sinkExpr: text, args };
  }
  if (parts[0] === "os" && FS_SINK_METHODS.has(tail)) {
    return { id: "path-traversal", sinkExpr: text, args };
  }
  if (text === "ioutil.ReadFile" || text === "os.ReadFile") {
    return { id: "path-traversal", sinkExpr: text, args };
  }
  if (text === "filepath.Join") {
    return { id: "path-traversal", sinkExpr: text, args };
  }
  if (text === "http.Redirect") {
    // http.Redirect(w, r, target, code) -- target is the 3rd positional arg.
    return args[2] ? { id: "open-redirect", sinkExpr: text, args: [args[2]] } : null;
  }
  return null;
}

/** SQL injection is a QUERY-TEXT question, not an any-argument one: only
 * args[0] (the query string) is checked -- a tainted bind-parameter value
 * (args[1+], the normal, safe use of parameterization) is never itself
 * "sql-injection", it's what the separate idor check below cares about. */
function matchSqlInjectionGo(call: SyntaxNode): SinkMatch | null {
  const fnNode = call.childForFieldName("function");
  const text = fnNode ? calleeTextGo(fnNode) : null;
  if (!text) return null;
  const tail = text.split(".").pop();
  if (tail !== "Query" && tail !== "QueryRow" && tail !== "Exec") return null;
  const args = argListOfGo(call);
  return args[0] ? { id: "sql-injection", sinkExpr: text, args: [args[0]] } : null;
}

/** Mirrors GO_IDOR_SINK_RE's three shapes (db.QueryRow/.First/.Where),
 * checking only the LAST argument (the id-like bind parameter), independent
 * of matchSqlInjectionGo's args[0]-only check above. */
function matchIdorGo(call: SyntaxNode): SinkMatch | null {
  const fnNode = call.childForFieldName("function");
  const text = fnNode ? calleeTextGo(fnNode) : null;
  if (!text) return null;
  const tail = text.split(".").pop();
  if (tail !== "QueryRow" && tail !== "First" && tail !== "Where") return null;
  const args = argListOfGo(call);
  const last = args[args.length - 1];
  return last ? { id: "idor", sinkExpr: text, args: [last] } : null;
}

// ── Authorization analysis (Decision 4) ─────────────────────────────────
// Real structural check mirroring astTaintJava.ts's collectBolaFindings,
// ADDED alongside (not replacing) the existing idorAuthCheckNearby regex
// callback below -- both must fail to suppress for an idor finding to fire,
// so this can only ever REDUCE false positives further, never introduce
// new ones, and needs zero scanner.ts wiring changes (the callback stays
// exactly as-is). Same scope and same documented non-goal as Java's own
// check (no branch/CFG awareness): "is there a real ownership comparison
// ANYWHERE in the enclosing function", not "does it correctly gate this
// specific sink".

/** Gin/Echo/Fiber principal-lookup vocabulary -- the same specific tokens
 * IDOR_AUTH_CHECK_NEARBY_RE (scanner.ts) already matches as line text
 * (`c.MustGet(...)`, `c.GetString("user"/"userId"/"userID"/"uid")`), now
 * matched structurally against a real call_expression instead. */
function isPrincipalShapedGo(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const fn = node.childForFieldName("function");
  const text = fn ? calleeTextGo(fn) : null;
  if (!text) return false;
  if (text.endsWith(".MustGet")) return true;
  if (text.endsWith(".GetString")) {
    const raw = argListOfGo(node)[0]?.text ?? "";
    return /^["'](?:user|userId|userID|user_id|uid)["']$/i.test(raw);
  }
  return false;
}

function findEnclosingFunctionNodeGo(node: SyntaxNode): SyntaxNode | null {
  let cur: SyntaxNode | null = node;
  while (cur) {
    if (cur.type === "function_declaration" || cur.type === "method_declaration") return cur;
    cur = cur.parent;
  }
  return null;
}

/** Does `fnBody` contain a `==`/`!=` binary_expression, or a `.Equal(...)`
 * call, comparing the bare identifier `resourceIdName` against a
 * principal-shaped expression (isPrincipalShapedGo above)? Purely
 * structural, independent of env/taint -- same posture as Java's
 * comparisonSuppresses/comparisonSuppressesEquals, which this mirrors. */
function hasStructuralOwnershipComparisonGo(resourceIdName: string, fnBody: SyntaxNode): boolean {
  let found = false;
  const isResourceId = (n: SyntaxNode | null) => !!n && n.type === "identifier" && n.text === resourceIdName;
  const visit = (n: SyntaxNode) => {
    if (found) return;
    if (n.type === "binary_expression") {
      const op = n.childForFieldName("operator")?.type;
      if (op === "==" || op === "!=") {
        const left = n.childForFieldName("left");
        const right = n.childForFieldName("right");
        if ((isResourceId(left) && right && isPrincipalShapedGo(right)) ||
            (isResourceId(right) && left && isPrincipalShapedGo(left))) {
          found = true;
        }
      }
    } else if (n.type === "call_expression") {
      const fn = n.childForFieldName("function");
      if (fn?.type === "selector_expression" && fn.childForFieldName("field")?.text === "Equal") {
        const operand = fn.childForFieldName("operand");
        const arg0 = argListOfGo(n)[0] ?? null;
        if ((isResourceId(operand) && arg0 && isPrincipalShapedGo(arg0)) ||
            (isResourceId(arg0) && operand && isPrincipalShapedGo(operand))) {
          found = true;
        }
      }
    }
    if (!found) for (const c of n.namedChildren) if (c) visit(c);
  };
  visit(fnBody);
  return found;
}

/** Only meaningful when the tainted resource-id expression fed to the sink
 * is itself a bare identifier -- a compound expression (a selector, a call)
 * has no single name a separate comparison elsewhere could reference by,
 * same "bare identifier only" scoping astTaintJava.ts's bareIdentifierOf
 * uses for its own one-hop backward check. */
function structuralOwnershipCheckSuppressesGo(sinkNode: SyntaxNode, resourceIdExpr: SyntaxNode): boolean {
  if (resourceIdExpr.type !== "identifier") return false;
  const enclosingFn = findEnclosingFunctionNodeGo(sinkNode);
  const fnBody = enclosingFn?.childForFieldName("body");
  if (!fnBody) return false;
  return hasStructuralOwnershipComparisonGo(resourceIdExpr.text, fnBody);
}

// ── Taint environment / propagation ─────────────────────────────────────────
// Flat, OR-shaped, no de-tainting -- same explicit design as astTaint.ts /
// astTaintPython.ts / astTaintJava.ts. Nothing in makeIsTaintedGo ever
// clears a taint flag once set.

type Env = TaintEnv;
// fn name -> (param index -> sink classes that survive to its return value)
type PropagatingGo = Map<string, Map<number, number>>;
interface ParamShape { name: string; index: number }
interface LocalFn { paramShapes: ParamShape[]; body: SyntaxNode }

function paramShapesOfGo(fn: SyntaxNode): ParamShape[] {
  const params = fn.childForFieldName("parameters");
  if (!params) return [];
  const shapes: ParamShape[] = [];
  let index = 0;
  for (const p of params.namedChildren) {
    if (!p || p.type !== "parameter_declaration") continue;
    const name = p.childForFieldName("name")?.text;
    if (name) shapes.push({ name, index });
    index++;
  }
  return shapes;
}

/** fmt.Sprintf / fmt.Errorf / fmt.Sprint -- any %-placeholder arg's taint
 * propagates to the call's own result, a generic "known formatting
 * function" passthrough (not sink-specific -- the SQL-injection sink match
 * happens separately, at whatever call wraps this one). */
function isFormatCall(text: string): boolean {
  return text === "fmt.Sprintf" || text === "fmt.Errorf" || text === "fmt.Sprint" || text === "fmt.Sprintln";
}

// ── Sanitizer/de-taint recognition ──────────────────────────────────────
// Sanitizers live in taint/sanitizers.ts, keyed by the sink classes each one
// actually neutralizes. strconv.Atoi/ParseInt/ParseFloat/ParseBool used to be
// deliberately taint-PRESERVING here (so an IDOR check on the converted id
// still fired); they now clear every INJECTION class (a %d into SQL is not
// injectable) while keeping the CONTROL bit, which is exactly what the IDOR
// check asks for -- no special case needed at the IDOR site beyond its class.

function makeTaintMaskGo(localFns: Map<string, LocalFn>, propagating: PropagatingGo) {
  const taintMask = (node: SyntaxNode, env: Env): number => {
    if (isTaintSourceExprGo(node)) return ALL;
    if (node.type === "identifier") return env.get(node.text) ?? 0;
    if (node.type === "binary_expression") {
      const op = node.childForFieldName("operator")?.type;
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if (op === "+" && left && right) return taintMask(left, env) | taintMask(right, env);
      return 0;
    }
    if (node.type === "call_expression") {
      const fn = node.childForFieldName("function");
      const args = argListOfGo(node);
      const text = fn ? calleeTextGo(fn) : null;
      // Known sanitizer: the argument's taint passes THROUGH minus only the
      // classes it neutralizes. Checked BEFORE the format-call passthrough
      // and every other taint-increasing branch below, so a sanitized value
      // can't be re-tainted by one of them in this same call.
      if (text) {
        const clears = sanitizerClears("go", text);
        if (clears !== null) return args[0] ? applyClears(taintMask(args[0], env), clears) : 0;
      }
      if (text && isFormatCall(text)) return args.reduce((m, a) => m | taintMask(a, env), 0);
      // A call to a local function known to propagate taint from SPECIFIC
      // params to its return value (see computeReturnTaintPropagatingGo),
      // limited to the classes that survive the callee's own body.
      if (fn?.type === "identifier") {
        const propIdx = propagating.get(fn.text);
        if (propIdx) {
          const callee = localFns.get(fn.text);
          const shapes = callee?.paramShapes ?? [];
          let m = 0;
          for (const [i, surviving] of propIdx) {
            if (shapes[i] !== undefined && args[i] !== undefined) m |= taintMask(args[i], env) & surviving;
          }
          if (m) return m;
        }
      }
      // Passthrough method call on an already-tainted receiver
      // (dec.Decode(), strings.TrimSpace(x) via selector on a tainted var).
      if (fn?.type === "selector_expression") {
        const operand = fn.childForFieldName("operand");
        if (operand) return taintMask(operand, env);
      }
      return 0;
    }
    if (node.type === "index_expression") {
      const operand = node.childForFieldName("operand");
      return operand ? taintMask(operand, env) : 0;
    }
    // Field-sensitive read: a bare selector like `user.Name` ORs the full
    // dotted-path composite key (set by the selector-expression assignment
    // handling in `walk`'s short_var_decl/assignment_statement branch below)
    // with the operand's own mask -- pure recall gain. Unlike Java, no
    // one-level scoping needed: calleeTextGo resolves the full chain.
    if (node.type === "selector_expression") {
      const path = calleeTextGo(node);
      const operand = node.childForFieldName("operand");
      return (path ? (env.get(path) ?? 0) : 0) | (operand ? taintMask(operand, env) : 0);
    }
    if (node.type === "unary_expression") {
      const operand = node.namedChildren[0];
      return operand ? taintMask(operand, env) : 0;
    }
    if (node.type === "parenthesized_expression") {
      const inner = node.namedChildren[0];
      return inner ? taintMask(inner, env) : 0;
    }
    if (node.type === "composite_literal") {
      const body = node.childForFieldName("body");
      if (!body) return 0;
      return body.namedChildren.reduce((m: number, el) => {
        if (!el) return m;
        if (el.type === "keyed_element") return el.namedChildren[1] ? m | taintMask(el.namedChildren[1], env) : m;
        return m | taintMask(el, env); // unkeyed literal element (slice/array literal entries)
      }, 0);
    }
    return 0;
  };
  return taintMask;
}

type TaintMaskFnGo = ReturnType<typeof makeTaintMaskGo>;

/**
 * For each of `fn`'s parameters INDEPENDENTLY, does `fn`'s return value
 * become tainted? Returns the set of propagating parameter INDICES, not a
 * per-function boolean -- identical reasoning to computeReturnTaintPropagating
 * (astTaint.ts) / computeReturnTaintPropagatingPy (astTaintPython.ts): sound
 * because makeIsTaintedGo is purely OR-shaped, so seeding a superset of
 * params can only ever taint a superset of what seeding a subset taints.
 * Go's multi-value returns (`return a, b`) are checked as "any returned
 * expression tainted" -- conservative, matches this engine's recall-biased
 * philosophy elsewhere.
 *
 * Nested calls inside `fn`'s own body are resolved using whatever
 * `isTaintedFn` the caller passes in (Decision 3) -- no longer hardcoded to
 * a fresh empty-map evaluator internally. See buildPropagatingMapGo below,
 * which threads a bounded, round-capped view of the file's own in-progress
 * propagating map instead.
 */
function computeReturnTaintPropagatingGo(fn: LocalFn, maskFn: TaintMaskFnGo): Map<number, number> {
  // param index -> sink classes that still survive to the return value
  const propagatingIdx = new Map<number, number>();
  const returnValues: SyntaxNode[] = [];
  const collect = (n: SyntaxNode) => {
    if (n.type === "return_statement") {
      const child = n.namedChildren[0];
      if (child?.type === "expression_list") {
        for (const v of child.namedChildren) if (v) returnValues.push(v);
      } else if (child) {
        returnValues.push(child);
      }
      return;
    }
    for (const c of n.namedChildren) if (c) collect(c);
  };
  collect(fn.body);
  for (const shape of fn.paramShapes) {
    const env: Env = new Map();
    env.set(shape.name, ALL);
    // Low bits only: the shadow half is per-scan bookkeeping, not a summary.
    const surviving = returnValues.reduce((m, v) => m | maskFn(v, env), 0) & ALL;
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
 * Builds the same-file propagating-param map via a bounded fixed-point
 * iteration instead of one pass with every nested call opaque (Decision 3),
 * mirroring astTaint.ts's/astTaintPython.ts's/astTaintJava.ts's own
 * buildPropagatingMap. Sound without extra cycle-breaking machinery because
 * propagation is monotonic (each round only ever ADDS indices, never
 * removes one, and every function's index set is bounded by its own
 * parameter count) -- convergence is never in doubt, the round cap only
 * bounds worst-case cost on a large file's call graph.
 */
function buildPropagatingMapGo(localFns: Map<string, LocalFn>): PropagatingGo {
  const propagating: PropagatingGo = new Map();
  for (let round = 0; round < MAX_PROPAGATION_ROUNDS; round++) {
    let changed = false;
    const maskRound = makeTaintMaskGo(localFns, propagating);
    for (const [name, fn] of localFns) {
      const found = computeReturnTaintPropagatingGo(fn, maskRound);
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

function sourceLabelGo(node: SyntaxNode): string {
  return node.text.replace(/\s+/g, " ").slice(0, 60);
}

function collectLocalFunctionsGo(root: SyntaxNode): Map<string, LocalFn> {
  const fns = new Map<string, LocalFn>();
  const visit = (node: SyntaxNode) => {
    if (node.type === "function_declaration" || node.type === "method_declaration") {
      const name = node.childForFieldName("name")?.text;
      const body = node.childForFieldName("body");
      if (name && body) fns.set(name, { paramShapes: paramShapesOfGo(node), body });
    }
    for (const c of node.namedChildren) if (c) visit(c);
  };
  visit(root);
  return fns;
}

const SEVERITY: Record<AstTaintGoId, "critical" | "high" | "medium"> = {
  "sql-injection": "critical", "command-injection": "critical", "ssrf": "critical",
  "path-traversal": "critical", "insecure-deserialization": "critical",
  "open-redirect": "medium", "idor": "medium",
};
const LABEL: Record<AstTaintGoId, string> = {
  "sql-injection": "SQL Injection", "command-injection": "Command Injection",
  "ssrf": "Server-Side Request Forgery", "path-traversal": "Path Traversal",
  "insecure-deserialization": "Insecure Deserialization",
  "open-redirect": "Open Redirect", "idor": "Insecure Direct Object Reference",
};

/** Unwraps short_var_declaration/assignment_statement's left/right fields,
 * both of which the grammar ALWAYS wraps in an expression_list -- even for
 * a single identifier on the left (confirmed directly: `x := ...` produces
 * `left: (expression_list (identifier))`, never a bare identifier field). */
function identifiersOf(exprList: SyntaxNode): SyntaxNode[] {
  return exprList.namedChildren.filter((n): n is SyntaxNode => !!n && n.type === "identifier");
}

/** Assignment LHS targets (Decision 1, write side): identifier OR
 * selector_expression (`obj.field`, confirmed directly: `user.Name = x`
 * parses as `left: (expression_list (selector_expression ...))`, not an
 * identifier -- previously entirely invisible to identifiersOf, so
 * `user.Name = x` silently updated no env entry at all). Any other LHS
 * shape (index_expression, etc.) stays unrecognized/untracked, same as
 * before -- scoped to static dotted-property access only. */
function assignmentTargetsOfGo(exprList: SyntaxNode): SyntaxNode[] {
  return exprList.namedChildren.filter((n): n is SyntaxNode =>
    !!n && (n.type === "identifier" || n.type === "selector_expression"));
}

/** Env lookup key for an assignment target: plain text for an identifier,
 * the full dotted path (calleeTextGo) for a selector_expression -- the same
 * key shape the new field-sensitive read case in makeIsTaintedGo checks. */
function assignmentKeyOfGo(target: SyntaxNode): string | null {
  return target.type === "identifier" ? target.text : calleeTextGo(target);
}

/**
 * Walks the whole tree once: tracks taint through env, seeds tainted
 * parameters into same-file callees on tainted call sites (one hop, mirrors
 * Phase 1/2/3), and matches sink call expressions against a tainted
 * argument (or, for insecure-deserialization, a tainted receiver).
 */
export function scanAstTaintGo(
  content: string, filePath: string, presparsed?: SyntaxNode | null,
  idorAuthCheckNearby?: (line: number) => boolean,
  // Sinks whose argument was tainted for the sink's class but positively
  // cleared by a sanitizer (see astTaint.ts) -- lets scanner.ts drop the
  // regex layer's duplicate for a flow this engine proved safe.
  suppressedOut?: SuppressedSink[],
): AstTaintGoFinding[] {
  try {
    const root = presparsed ?? parseGoSourceSync(content, filePath);
    if (!root) return [];

    const localFns = collectLocalFunctionsGo(root);
    const propagating = buildPropagatingMapGo(localFns);

    const findings: AstTaintGoFinding[] = [];
    const seen = new Set<string>();
    const lineOf = (node: SyntaxNode): number => node.startPosition.row + 1;

    const emit = (id: AstTaintGoId, node: SyntaxNode, sourceExpr: string, sinkExpr: string) => {
      const line = lineOf(node);
      const key = `${id}:${line}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({
        id, line, sinkExpr, sourceExpr,
        detail: `Tainted expression '${sourceExpr}' flows into ${sinkExpr}(...) — real data-flow match, not a line-pattern guess`,
      });
    };

    // fn name -> (tainted param index -> classes tainted at the call site)
    const seededParams = new Map<string, Map<number, number>>();

    // First argument tainted for `id`'s class, if any. When none is but one
    // was tainted-then-positively-cleared, records a suppression instead
    // (for the regex-layer veto).
    const sinkHit = (
      node: SyntaxNode, args: readonly SyntaxNode[], id: AstTaintGoId | "idor",
      env: Env, taintMask: TaintMaskFnGo,
    ): SyntaxNode | undefined => {
      const cls = classOf(id);
      let cleared = false;
      for (const a of args) {
        const m = taintMask(a, env);
        if (m & cls) return a;
        if (wasCleared(m, cls)) cleared = true;
      }
      if (cleared) suppressedOut?.push({ id, line: lineOf(node) });
      return undefined;
    };

    const walk = (node: SyntaxNode, env: Env, taintMask: TaintMaskFnGo) => {
      if (node.type === "short_var_declaration" || node.type === "assignment_statement") {
        const left = node.childForFieldName("left");
        const right = node.childForFieldName("right");
        if (left && right) {
          const leftTargets = assignmentTargetsOfGo(left);
          const rightVals = right.namedChildren.filter((n): n is SyntaxNode => !!n);
          if (leftTargets.length > 0 && rightVals.length === 1) {
            // Single RHS value (possibly Go's multi-return form binding N
            // LHS targets to one call's multiple return values) -- per the
            // approved plan's Decision 6, only the FIRST LHS target is ever
            // marked tainted, never trailing ones (by strong Go convention
            // those are typically `err`/`ok`, not real data). Deliberately
            // conservative: avoids "the error variable is attacker-
            // controlled" false positives. Also now the single-target case
            // for a plain field write (`user.Name = input`), where
            // leftTargets.length is already 1 -- assignmentKeyOfGo resolves
            // both shapes uniformly.
            const mask = taintMask(rightVals[0], env);
            const key = assignmentKeyOfGo(leftTargets[0]);
            if (key) env.set(key, mask);
          } else {
            // Positional 1:1 multi-assignment (`a, b = x, y`, including a
            // field target: `user.Name, user.Email = a, b`) -- each side has
            // the same count; assign independently.
            leftTargets.forEach((target, i) => {
              const rhs = rightVals[i];
              const key = assignmentKeyOfGo(target);
              if (rhs && key) env.set(key, taintMask(rhs, env));
            });
          }
        }
      }

      if (node.type === "call_expression") {
        const fn = node.childForFieldName("function");
        const args = argListOfGo(node);

        const match = matchSinkGo(node);
        if (match) {
          const taintedArg = sinkHit(node, match.args, match.id, env, taintMask);
          if (taintedArg) emit(match.id, node, sourceLabelGo(taintedArg), match.sinkExpr);
        }

        const sqlMatch = matchSqlInjectionGo(node);
        if (sqlMatch) {
          const hit = sinkHit(node, [sqlMatch.args[0]], "sql-injection", env, taintMask);
          if (hit) emit("sql-injection", node, sourceLabelGo(sqlMatch.args[0]), sqlMatch.sinkExpr);
        }

        // IDOR asks "is this id attacker-CONTROLLED", not "is it injectable":
        // classOf("idor") is the CONTROL bit, which numeric coercion
        // (strconv.Atoi(c.Param("id"))) deliberately does not clear.
        const idorMatch = matchIdorGo(node);
        if (idorMatch && sinkHit(node, [idorMatch.args[0]], "idor", env, taintMask)) {
          const suppressed = (idorAuthCheckNearby?.(lineOf(node)) ?? false) ||
            structuralOwnershipCheckSuppressesGo(node, idorMatch.args[0]);
          if (!suppressed) emit("idor", node, sourceLabelGo(idorMatch.args[0]), idorMatch.sinkExpr);
        }

        // dec.Decode(...) -- receiver-tainted, not arg-tainted: fires if
        // `dec` itself is tainted (built from gob.NewDecoder(r.Body) or
        // similar via the propagation rule right below), args are irrelevant.
        if (fn?.type === "selector_expression" && fn.childForFieldName("field")?.text === "Decode") {
          const operand = fn.childForFieldName("operand");
          if (operand && sinkHit(node, [operand], "insecure-deserialization", env, taintMask)) {
            emit("insecure-deserialization", node, sourceLabelGo(operand), calleeTextGo(fn) ?? "Decode");
          }
        }

        // gob.NewDecoder(EXPR) -- taints the assignment target if EXPR ends
        // in .Body/.Conn (an untrusted stream). The enclosing
        // short_var_declaration/assignment_statement's OWN top-level handling
        // (above, in this same walk call) already ran and set this target
        // to `false` via isTainted(gob.NewDecoder(...), env) -- which can
        // never recognize this call as tainted, since gob.NewDecoder isn't a
        // recognized source/format-call/local-propagating-fn/tainted-receiver
        // shape. This deeper, later visit (recursing into the RHS) corrects
        // that to `true` once we're structurally certain the source stream
        // is untrusted -- runs after and intentionally overwrites the
        // outer pass's `false`, not a race.
        if (fn) {
          const fnText = calleeTextGo(fn);
          if (fnText === "gob.NewDecoder" && args[0]) {
            const argText = calleeTextGo(args[0]) ?? "";
            if (argText.endsWith(".Body") || argText.endsWith(".Conn")) {
              const parent = node.parent?.type === "expression_list" ? node.parent.parent : node.parent;
              if (parent && (parent.type === "short_var_declaration" || parent.type === "assignment_statement")) {
                const left = parent.childForFieldName("left");
                const ids = left ? identifiersOf(left) : [];
                if (ids[0]) env.set(ids[0].text, ALL);
              }
            }
          }
          // http.NewRequest(method, url, body) / NewRequestWithContext(ctx,
          // method, url, body) -- same "correct the outer pass's false"
          // pattern as gob.NewDecoder above: taints the assignment target
          // if the URL argument is tainted, so the later client.Do(req)
          // sink (via matchSinkGo's passthrough-on-tainted-receiver, since
          // .Do's own function selector's operand `client` isn't itself
          // tainted -- `req`, its ARGUMENT, is) resolves correctly. client.Do
          // is matched generically below via the same receiver-tainted
          // shape as Decode, since neither is arg-tainted in the usual sense.
          if ((fnText === "http.NewRequest" || fnText === "http.NewRequestWithContext") && args.length > 0) {
            const urlArg = fnText === "http.NewRequestWithContext" ? args[2] : args[1];
            const urlMask = urlArg ? taintMask(urlArg, env) : 0;
            if (urlArg && (urlMask & ALL)) {
              const parent = node.parent?.type === "expression_list" ? node.parent.parent : node.parent;
              if (parent && (parent.type === "short_var_declaration" || parent.type === "assignment_statement")) {
                const left = parent.childForFieldName("left");
                const ids = left ? identifiersOf(left) : [];
                if (ids[0]) env.set(ids[0].text, urlMask);
              }
            }
          }
        }

        // client.Do(req) -- ssrf sink where the DANGER is the receiver's
        // (`client`'s) call target, but the actual taint lives on the
        // ARGUMENT (`req`), not the receiver itself -- the inverse shape
        // from Decode's receiver-tainted check above.
        if (fn?.type === "selector_expression" && fn.childForFieldName("field")?.text === "Do" && args[0]) {
          if (sinkHit(node, [args[0]], "ssrf", env, taintMask)) emit("ssrf", node, sourceLabelGo(args[0]), calleeTextGo(fn) ?? "Do");
        }

        // Same-file interprocedural seeding (one hop) -- mirrors
        // astTaint.ts/astTaintPython.ts exactly.
        if (fn?.type === "identifier" && localFns.has(fn.text)) {
          const fnName = fn.text;
          const localFn = localFns.get(fnName)!;
          const taintedIdx = new Map<number, number>();
          args.forEach((arg, i) => {
            const m = taintMask(arg, env) & ALL;
            if (!m) return;
            if (localFn.paramShapes.some(s => s.index === i)) taintedIdx.set(i, (taintedIdx.get(i) ?? 0) | m);
          });
          if (taintedIdx.size > 0) {
            const existing = seededParams.get(fnName) ?? new Map<number, number>();
            for (const [i, m] of taintedIdx) existing.set(i, (existing.get(i) ?? 0) | m);
            seededParams.set(fnName, existing);
          }
        }
      }

      for (const c of node.namedChildren) if (c) walk(c, env, taintMask);
    };

    const rootTaintMask = makeTaintMaskGo(localFns, propagating);
    walk(root, new Map(), rootTaintMask);

    // Second pass, bounded worklist (Decision 3): re-walk any local function
    // whose params were seeded tainted by a call site above, so sinks inside
    // the callee are reachable. Re-walking can itself seed FURTHER functions
    // (or grow an already-seeded function's own index set) via the same
    // seeding logic above, which is exactly how a second/third hop (A calls
    // B calls C) gets discovered -- explicitly capped at
    // MAX_PROPAGATION_ROUNDS instead of relying on live-Map-iteration order
    // for its multi-hop convergence, mirroring astTaint.ts's/
    // astTaintPython.ts's/astTaintJava.ts's own bounded worklists.
    // `walkedSignatures` skips re-walking a function with a seed set
    // identical to one already walked, while still allowing a re-walk once
    // that function's seed set has genuinely grown.
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
        for (const [idx, m] of idxSet) {
          const shape = fn.paramShapes.find(s => s.index === idx);
          if (shape) env.set(shape.name, m);
        }
        const seededTaintMask = makeTaintMaskGo(localFns, propagating);
        for (const c of fn.body.namedChildren) if (c) walk(c, env, seededTaintMask);
      }
      if (!changed) break;
    }

    return findings;
  } catch (err) {
    console.error(`[astTaintGo] threw scanning ${filePath}:`, err);
    return [];
  }
}

export function astTaintGoSeverity(id: AstTaintGoId): "critical" | "high" | "medium" {
  return SEVERITY[id];
}
export function astTaintGoLabel(id: AstTaintGoId): string {
  return LABEL[id];
}
