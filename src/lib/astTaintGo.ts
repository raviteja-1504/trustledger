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

// ── Taint environment / propagation ─────────────────────────────────────────
// Flat, OR-shaped, no de-tainting -- same explicit design as astTaint.ts /
// astTaintPython.ts / astTaintJava.ts. Nothing in makeIsTaintedGo ever
// clears a taint flag once set.

type Env = Map<string, boolean>;
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

/** strconv.Atoi/ParseInt/ParseFloat/ParseBool -- the extremely common
 * "convert a query-param string to a typed value" idiom
 * (`id, err := strconv.Atoi(q)`). Generalizes the existing regex layer's
 * narrow goStrconvAssign carve-out (scanner.ts) into the same "known
 * taint-preserving conversion" passthrough as isFormatCall above, rather
 * than reproducing its exact narrow shape. */
function isTaintPreservingConversion(text: string): boolean {
  return text === "strconv.Atoi" || text === "strconv.ParseInt" ||
         text === "strconv.ParseFloat" || text === "strconv.ParseBool";
}

function makeIsTaintedGo(localFns: Map<string, LocalFn>, propagating: Map<string, Set<number>>) {
  const isTainted = (node: SyntaxNode, env: Env): boolean => {
    if (isTaintSourceExprGo(node)) return true;
    if (node.type === "identifier") return env.get(node.text) === true;
    if (node.type === "binary_expression") {
      const op = node.childForFieldName("operator")?.type;
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if (op === "+" && left && right) return isTainted(left, env) || isTainted(right, env);
      return false;
    }
    if (node.type === "call_expression") {
      const fn = node.childForFieldName("function");
      const args = argListOfGo(node);
      const text = fn ? calleeTextGo(fn) : null;
      if (text && (isFormatCall(text) || isTaintPreservingConversion(text))) return args.some(a => isTainted(a, env));
      // A call to a local function known to propagate taint from SPECIFIC
      // params to its return value (see computeReturnTaintPropagatingGo).
      if (fn?.type === "identifier") {
        const propIdx = propagating.get(fn.text);
        if (propIdx) {
          const callee = localFns.get(fn.text);
          const shapes = callee?.paramShapes ?? [];
          const matched = [...propIdx].some(i => shapes[i] !== undefined && args[i] !== undefined && isTainted(args[i], env));
          if (matched) return true;
        }
      }
      // Passthrough method call on an already-tainted receiver
      // (dec.Decode(), strings.TrimSpace(x) via selector on a tainted var).
      if (fn?.type === "selector_expression") {
        const operand = fn.childForFieldName("operand");
        if (operand) return isTainted(operand, env);
      }
      return false;
    }
    if (node.type === "index_expression") {
      const operand = node.childForFieldName("operand");
      return operand ? isTainted(operand, env) : false;
    }
    if (node.type === "unary_expression") {
      const operand = node.namedChildren[0];
      return operand ? isTainted(operand, env) : false;
    }
    if (node.type === "parenthesized_expression") {
      const inner = node.namedChildren[0];
      return inner ? isTainted(inner, env) : false;
    }
    if (node.type === "composite_literal") {
      const body = node.childForFieldName("body");
      if (!body) return false;
      return body.namedChildren.some(el => {
        if (!el) return false;
        if (el.type === "keyed_element") return el.namedChildren[1] ? isTainted(el.namedChildren[1], env) : false;
        return isTainted(el, env); // unkeyed literal element (slice/array literal entries)
      });
    }
    return false;
  };
  return isTainted;
}

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
 */
function computeReturnTaintPropagatingGo(fn: LocalFn): Set<number> {
  const propagatingIdx = new Set<number>();
  const isTaintedShallow = makeIsTaintedGo(new Map(), new Map());
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
    env.set(shape.name, true);
    if (returnValues.some(v => isTaintedShallow(v, env))) propagatingIdx.add(shape.index);
  }
  return propagatingIdx;
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

/**
 * Walks the whole tree once: tracks taint through env, seeds tainted
 * parameters into same-file callees on tainted call sites (one hop, mirrors
 * Phase 1/2/3), and matches sink call expressions against a tainted
 * argument (or, for insecure-deserialization, a tainted receiver).
 */
export function scanAstTaintGo(
  content: string, filePath: string, presparsed?: SyntaxNode | null,
  idorAuthCheckNearby?: (line: number) => boolean,
): AstTaintGoFinding[] {
  try {
    const root = presparsed ?? parseGoSourceSync(content, filePath);
    if (!root) return [];

    const localFns = collectLocalFunctionsGo(root);
    const propagating = new Map<string, Set<number>>();
    for (const [name, fn] of localFns) {
      const idx = computeReturnTaintPropagatingGo(fn);
      if (idx.size > 0) propagating.set(name, idx);
    }

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

    const seededParams = new Map<string, Set<number>>();

    const walk = (node: SyntaxNode, env: Env, isTainted: ReturnType<typeof makeIsTaintedGo>) => {
      if (node.type === "short_var_declaration" || node.type === "assignment_statement") {
        const left = node.childForFieldName("left");
        const right = node.childForFieldName("right");
        if (left && right) {
          const leftIds = identifiersOf(left);
          const rightVals = right.namedChildren.filter((n): n is SyntaxNode => !!n);
          if (leftIds.length > 0 && rightVals.length === 1) {
            // Single RHS value (possibly Go's multi-return form binding N
            // LHS identifiers to one call's multiple return values) -- per
            // the approved plan's Decision 6, only the FIRST LHS identifier
            // is ever marked tainted, never trailing ones (by strong Go
            // convention those are typically `err`/`ok`, not real data).
            // Deliberately conservative: avoids "the error variable is
            // attacker-controlled" false positives.
            const tainted = isTainted(rightVals[0], env);
            env.set(leftIds[0].text, tainted);
          } else {
            // Positional 1:1 multi-assignment (`a, b = x, y`) -- each side
            // has the same count; assign independently.
            leftIds.forEach((idNode, i) => {
              const rhs = rightVals[i];
              if (rhs) env.set(idNode.text, isTainted(rhs, env));
            });
          }
        }
      }

      if (node.type === "call_expression") {
        const fn = node.childForFieldName("function");
        const args = argListOfGo(node);

        const match = matchSinkGo(node);
        if (match) {
          const taintedArg = match.args.find(a => isTainted(a, env));
          if (taintedArg) emit(match.id, node, sourceLabelGo(taintedArg), match.sinkExpr);
        }

        const sqlMatch = matchSqlInjectionGo(node);
        if (sqlMatch && isTainted(sqlMatch.args[0], env)) {
          emit("sql-injection", node, sourceLabelGo(sqlMatch.args[0]), sqlMatch.sinkExpr);
        }

        const idorMatch = matchIdorGo(node);
        if (idorMatch && isTainted(idorMatch.args[0], env) && !(idorAuthCheckNearby?.(lineOf(node)) ?? false)) {
          emit("idor", node, sourceLabelGo(idorMatch.args[0]), idorMatch.sinkExpr);
        }

        // dec.Decode(...) -- receiver-tainted, not arg-tainted: fires if
        // `dec` itself is tainted (built from gob.NewDecoder(r.Body) or
        // similar via the propagation rule right below), args are irrelevant.
        if (fn?.type === "selector_expression" && fn.childForFieldName("field")?.text === "Decode") {
          const operand = fn.childForFieldName("operand");
          if (operand && isTainted(operand, env)) {
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
                if (ids[0]) env.set(ids[0].text, true);
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
            if (urlArg && isTainted(urlArg, env)) {
              const parent = node.parent?.type === "expression_list" ? node.parent.parent : node.parent;
              if (parent && (parent.type === "short_var_declaration" || parent.type === "assignment_statement")) {
                const left = parent.childForFieldName("left");
                const ids = left ? identifiersOf(left) : [];
                if (ids[0]) env.set(ids[0].text, true);
              }
            }
          }
        }

        // client.Do(req) -- ssrf sink where the DANGER is the receiver's
        // (`client`'s) call target, but the actual taint lives on the
        // ARGUMENT (`req`), not the receiver itself -- the inverse shape
        // from Decode's receiver-tainted check above.
        if (fn?.type === "selector_expression" && fn.childForFieldName("field")?.text === "Do" && args[0]) {
          if (isTainted(args[0], env)) emit("ssrf", node, sourceLabelGo(args[0]), calleeTextGo(fn) ?? "Do");
        }

        // Same-file interprocedural seeding (one hop) -- mirrors
        // astTaint.ts/astTaintPython.ts exactly.
        if (fn?.type === "identifier" && localFns.has(fn.text)) {
          const fnName = fn.text;
          const localFn = localFns.get(fnName)!;
          const taintedIdx = new Set<number>();
          args.forEach((arg, i) => {
            if (!isTainted(arg, env)) return;
            if (localFn.paramShapes.some(s => s.index === i)) taintedIdx.add(i);
          });
          if (taintedIdx.size > 0) {
            const existing = seededParams.get(fnName) ?? new Set<number>();
            taintedIdx.forEach(i => existing.add(i));
            seededParams.set(fnName, existing);
          }
        }
      }

      for (const c of node.namedChildren) if (c) walk(c, env, isTainted);
    };

    const rootIsTainted = makeIsTaintedGo(localFns, propagating);
    walk(root, new Map(), rootIsTainted);

    // Second pass: re-walk any local function whose params were seeded
    // tainted by a call site above, so sinks inside the callee are reachable.
    for (const [fnName, idxSet] of seededParams) {
      const fn = localFns.get(fnName);
      if (!fn) continue;
      const env: Env = new Map();
      for (const idx of idxSet) {
        const shape = fn.paramShapes.find(s => s.index === idx);
        if (shape) env.set(shape.name, true);
      }
      const seededIsTainted = makeIsTaintedGo(localFns, propagating);
      for (const c of fn.body.namedChildren) if (c) walk(c, env, seededIsTainted);
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
