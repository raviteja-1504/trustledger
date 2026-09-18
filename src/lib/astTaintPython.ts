/**
 * Real AST-based taint engine for Python — Phase 2 of the multi-language
 * OWASP Top 10 hardening effort (see astTaint.ts for Phase 1 / JS-TS, whose
 * five-stage architecture -- sources, propagation, interprocedural,
 * sinks, findings -- this file mirrors using web-tree-sitter instead of the
 * TypeScript compiler).
 *
 * Uses web-tree-sitter (WASM bindings, no native compile step -- safe for
 * Vercel's serverless build) + tree-sitter-wasms' prebuilt
 * tree-sitter-python.wasm. Pinned to web-tree-sitter@0.25.10 specifically:
 * tree-sitter-wasms@0.1.13's grammar was built with tree-sitter-cli@0.20.8,
 * and web-tree-sitter@0.26+ has a confirmed ABI break loading WASM grammars
 * built by tree-sitter-cli 0.20.x (tree-sitter/tree-sitter#5171). These two
 * package versions must move together, not independently.
 *
 * WASM instantiation (Parser.init/Language.load) is genuinely async, but
 * analyzeFile()/runScan() in scanner.ts are used synchronously from ~90
 * call sites (API routes + tests) -- converting that whole chain to async
 * is out of scope for this phase. Instead this module fires WASM init the
 * moment it's imported and exposes a synchronous parse function that
 * returns null until the parser is warm (mirroring the existing "fall back
 * silently to regex-only" contract Phase 1 established for the
 * AST_TAINT_LINE_CAP / minified-file gates in scanner.ts). Callers that CAN
 * await should call warmPythonTaintEngine() -- see src/instrumentation.ts
 * (production) and this file's own test suite (Jest, which doesn't run
 * instrumentation.ts). On a cold serverless instance that misses the warm-up
 * window, a Python file scanned in that gap simply gets regex-only results
 * for that one request -- not a crash, not a wrong answer.
 *
 * Runs ADDITIVELY alongside every existing Python regex/named-taint
 * detector in scanner.ts, not as a replacement. Reuses existing finding ids
 * (sql-injection, command-injection, ssrf, path-traversal, open-redirect,
 * ssti) -- confirmed all already wired through cweMap.ts/SIGNAL_META/
 * githubComment.ts/violations page/sarif.ts, so no new UI wiring is needed.
 * Deliberately excludes: pickle/yaml (already covered by the existing
 * insecure-deserialization regex detector -- would duplicate, not add
 * coverage) and BOLA (.filter_by-style authorization-absence bugs are a
 * business-logic judgment, not a data-flow-reachability fact -- the
 * existing regex+proximity approach is structurally the right tool there).
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { Parser, Language } = require("web-tree-sitter") as typeof import("web-tree-sitter");
import type { Node as SyntaxNode, Language as LanguageT, Parser as ParserT } from "web-tree-sitter";

// webpack provides this global on Node.js targets specifically to escape its
// own require() interception. Needed here because require.resolve(...) from
// INSIDE webpack-bundled code doesn't do real filesystem resolution at all --
// even for an externalized package -- it returns webpack's internal numeric
// module id instead of a real path (confirmed directly against a real
// production failure: "path.dirname received type number (90625)"). The
// real Node require's .resolve() is needed here specifically because we want
// an actual on-disk path to read raw .wasm bytes from, not a module to
// require() through webpack's own resolution.
declare const __non_webpack_require__: NodeJS.Require | undefined;
function nodeRequire(): NodeJS.Require {
  // eslint-disable-next-line no-undef
  return typeof __non_webpack_require__ !== "undefined" ? __non_webpack_require__ : require;
}

export type AstTaintPyId =
  | "sql-injection" | "command-injection" | "ssrf" | "path-traversal" | "open-redirect" | "ssti";

export interface AstTaintPyFinding {
  id:         AstTaintPyId;
  line:       number;
  detail:     string;
  sourceExpr: string;
  sinkExpr:   string;
}

// ── Parser lifecycle (warm-cache pattern -- see docblock above) ─────────────

let langPromise: Promise<LanguageT> | null = null;
let parserPool: ParserT | null = null;

function initPythonParser(): Promise<LanguageT> {
  if (!langPromise) {
    langPromise = (async () => {
      await Parser.init();
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const fs = require("fs") as typeof import("fs");
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const path = require("path") as typeof import("path");
      // Deliberately NOT require.resolve("tree-sitter-wasms/...") at all --
      // even via nodeRequire(), that would need tree-sitter-wasms itself to
      // be resolvable at runtime, which it isn't: it's never require()'d in
      // a webpack-visible way anywhere (only read as raw bytes), so
      // @vercel/nft's build tracer has no signal it's used and won't include
      // even its package.json (confirmed directly against a real production
      // MODULE_NOT_FOUND failure). Instead, anchor on web-tree-sitter's own
      // main entry point (".", the only guaranteed-resolvable subpath its
      // package.json "exports" map allows -- "./package.json" is NOT in that
      // map and throws MODULE_NOT_FOUND under both Node's real exports
      // enforcement and Jest's resolver, confirmed directly) and reach the
      // sibling tree-sitter-wasms package with plain path joins. The actual
      // .wasm binary still needs its own outputFileTracingIncludes entry in
      // next.config.mjs (next to web-tree-sitter's own tree-sitter.wasm)
      // since neither is ever really require()'d.
      const webTreeSitterEntry = nodeRequire().resolve("web-tree-sitter");
      const nodeModulesDir = path.dirname(path.dirname(webTreeSitterEntry));
      const wasmPath = path.join(nodeModulesDir, "tree-sitter-wasms", "out", "tree-sitter-python.wasm");
      // Read the bytes ourselves and pass a Uint8Array rather than a path
      // string: Language.load(path) internally does `await import("fs/promises")`
      // in Node, a dynamic ESM import that Jest's CJS VM can't execute without
      // --experimental-vm-modules (confirmed directly against tree-sitter.cjs's
      // source). Passing bytes takes the Uint8Array branch instead, which has
      // no such dependency -- more robust in the Vercel bundle too, not just
      // a test-environment workaround.
      const lang = await Language.load(new Uint8Array(fs.readFileSync(wasmPath)));
      const p = new Parser();
      p.setLanguage(lang);
      parserPool = p;
      console.log("[astTaintPython] Python AST taint engine ready");
      return lang;
    })().catch(err => {
      console.error("[astTaintPython] WASM init failed -- Python AST taint scanning disabled, regex detectors unaffected:", err);
      throw err;
    });
  }
  return langPromise;
}
// Fire at module import time -- don't wait for the first scan to start the
// clock. Skipped under Jest: this module is imported transitively (via
// scanner.ts) by dozens of unrelated test files, none of which await this
// promise -- it would dangle past each file's own teardown, causing
// "require after environment torn down" noise across the whole suite. Tests
// that actually need the parser warm (astTaintPython.test.ts) call
// warmPythonTaintEngine() explicitly in beforeAll instead. Production is
// unaffected -- instrumentation.ts calls warmPythonTaintEngine() itself.
if (!process.env.JEST_WORKER_ID) {
  void initPythonParser().catch(() => { /* already logged above */ });
}

export function isPythonParserReady(): boolean {
  return parserPool !== null;
}

/** Awaits WASM readiness. Call from instrumentation.ts (prod) or a test beforeAll. */
export async function warmPythonTaintEngine(): Promise<void> {
  await initPythonParser().catch(() => { /* already logged; callers just proceed regex-only */ });
}

export function parsePythonSourceSync(content: string, filePath: string): SyntaxNode | null {
  if (!parserPool) return null;
  try {
    return parserPool.parse(content)?.rootNode ?? null;
  } catch (err) {
    console.error(`[astTaintPython] parse threw for ${filePath}:`, err);
    return null;
  }
}

// ── Enclosing-function lookup (shared with reachability.ts's resolver) ──────

/** Deepest tree-sitter node whose source range spans 0-based row `row`. */
export function findNodeAtRowPy(root: SyntaxNode, row: number): SyntaxNode {
  let node = root;
  for (;;) {
    const child = node.namedChildren.find(c => c && row >= c.startPosition.row && row <= c.endPosition.row);
    if (!child) return node;
    node = child;
  }
}

/**
 * Walks up to the nearest enclosing `function_definition`. Restricted to the
 * SAME naming convention as callGraph.ts's regex-based tryMatchFunc()
 * (`^(async\s+)?def\s+(\w+)\s*\(`, anchored at column 0 -- i.e. module-level
 * defs only, never a class method) -- reachability.ts's resolver looks names
 * up against a CallGraphResult built by that extractor, so returning a class
 * method's name here would look up a name the call graph never had a chance
 * to be right or wrong about, silently reintroducing the "always unreachable"
 * bug class in a different shape. This means Django/Flask class-based-view
 * handlers get conservative ("unknown" -> unreachable-biased) exploitability
 * scoring -- a pre-existing callGraph.ts limitation (it never indexes class
 * methods at all), not something this phase introduces or fixes.
 */
export function findEnclosingFunctionNamePy(node: SyntaxNode): string {
  let cur: SyntaxNode | null = node;
  while (cur) {
    if (cur.type === "function_definition" && cur.startPosition.column === 0) {
      const nameNode = cur.childForFieldName("name");
      if (nameNode) return nameNode.text;
    }
    cur = cur.parent;
  }
  return "unknown";
}

// ── Taint sources ─────────────────────────────────────────────────────────

const FLASK_ATTR_SOURCES = new Set(["args", "form", "json", "data", "values", "cookies", "headers"]);
const FLASK_CALL_SOURCES = new Set(["get_json", "get_data"]);
const DJANGO_DICT_SOURCES = new Set(["GET", "POST"]);
const FASTAPI_DECORATOR_RE = /^@(?:\w+\.)?(?:router|app)\.(?:get|post|put|delete|patch|options|head)\s*\(/;

function attributeParts(node: SyntaxNode): { object: SyntaxNode | null; attribute: string | null } {
  return { object: node.childForFieldName("object"), attribute: node.childForFieldName("attribute")?.text ?? null };
}

/**
 * Extracts a parameter node's bound name across every shape the grammar
 * produces: a bare `identifier`; `default_parameter`/`typed_default_parameter`
 * (which DO expose a `name` field); and `typed_parameter`/`list_splat_pattern`
 * (*args)/`dictionary_splat_pattern` (**kwargs), which do NOT expose a `name`
 * field at all -- confirmed directly against the pinned tree-sitter-python
 * grammar, not assumed -- so those fall back to their first named child.
 */
function paramNameOf(p: SyntaxNode): string | null {
  if (p.type === "identifier") return p.text;
  const nameField = p.childForFieldName("name");
  if (nameField?.type === "identifier") return nameField.text;
  const first = p.namedChildren[0];
  return first?.type === "identifier" ? first.text : null;
}

interface ParamShape { name: string; index: number; isRest: boolean }

/** Which of `args` correspond to `shape`: exactly one arg for a fixed
 * param, every arg from `shape.index` onward for a *args/**kwargs param
 * (kwargs is a deliberate over-approximation -- real name-based keyword
 * matching isn't tracked, this never under-taints, consistent with this
 * engine's recall-biased philosophy elsewhere). */
function argsForShape<A>(args: readonly A[], shape: ParamShape): A[] {
  return shape.isRest ? args.slice(shape.index) : (args[shape.index] !== undefined ? [args[shape.index]] : []);
}

function paramShapesOfPy(fn: SyntaxNode): ParamShape[] {
  const params = fn.childForFieldName("parameters");
  if (!params) return [];
  const shapes: ParamShape[] = [];
  let index = 0;
  for (const p of params.namedChildren) {
    if (!p) continue;
    const name = paramNameOf(p);
    if (!name) continue;
    const isRest = p.type === "list_splat_pattern" || p.type === "dictionary_splat_pattern";
    shapes.push({ name, index, isRest });
    index++;
  }
  return shapes;
}

function paramNamesOf(fn: SyntaxNode): string[] {
  return paramShapesOfPy(fn).map(s => s.name);
}

/** Is this function_definition's own parameter list carrying a param literally named `request`? (Django view-function convention -- scopes the request.GET/.POST source so an unrelated local/import named `request` never false-positives.) */
function hasRequestParam(fn: SyntaxNode): boolean {
  return paramNamesOf(fn).includes("request");
}

function isTaintSourceExprPy(node: SyntaxNode, inDjangoRequestFn: boolean): boolean {
  if (node.type === "attribute") {
    const { object, attribute } = attributeParts(node);
    if (object?.type === "identifier" && object.text === "request" && attribute && FLASK_ATTR_SOURCES.has(attribute)) {
      return true;
    }
    return object ? isTaintSourceExprPy(object, inDjangoRequestFn) : false;
  }
  if (node.type === "call") {
    const fn = node.childForFieldName("function");
    if (fn?.type === "attribute") {
      const { object, attribute } = attributeParts(fn);
      if (object?.type === "identifier" && object.text === "request" && attribute && FLASK_CALL_SOURCES.has(attribute)) {
        return true;
      }
      // Django's dict-.get() convenience form: request.GET.get("x") /
      // request.POST.get("x") -- same scoping as the subscript form below.
      if (inDjangoRequestFn && attribute === "get" && object?.type === "attribute") {
        const inner = attributeParts(object);
        if (inner.object?.type === "identifier" && inner.object.text === "request" &&
            inner.attribute && DJANGO_DICT_SOURCES.has(inner.attribute)) {
          return true;
        }
      }
    }
    return false;
  }
  if (node.type === "subscript") {
    const value = node.childForFieldName("value");
    if (inDjangoRequestFn && value?.type === "attribute") {
      const { object, attribute } = attributeParts(value);
      if (object?.type === "identifier" && object.text === "request" && attribute && DJANGO_DICT_SOURCES.has(attribute)) {
        return true;
      }
    }
    return value ? isTaintSourceExprPy(value, inDjangoRequestFn) : false;
  }
  return false;
}

// ── Sink dispatch table ──────────────────────────────────────────────────

interface SinkMatch { id: AstTaintPyId; sinkExpr: string; args: SyntaxNode[] }

function calleeTextPy(node: SyntaxNode): string | null {
  if (node.type === "identifier") return node.text;
  if (node.type === "attribute") {
    const { object, attribute } = attributeParts(node);
    if (!object || !attribute) return null;
    const base = calleeTextPy(object);
    return base ? `${base}.${attribute}` : null;
  }
  return null;
}

/** Resolves bare names imported via `from subprocess import run` / `import subprocess as sp` etc. */
function buildImportMapPy(root: SyntaxNode): Map<string, string> {
  const map = new Map<string, string>();
  const visit = (node: SyntaxNode) => {
    if (node.type === "import_from_statement") {
      const moduleName = node.childForFieldName("module_name")?.text ?? null;
      if (moduleName) {
        for (const child of node.namedChildren) {
          if (child && (child.type === "dotted_name" || child.type === "identifier") && child !== node.childForFieldName("module_name")) {
            map.set(child.text, moduleName);
          }
          if (child?.type === "aliased_import") {
            const alias = child.childForFieldName("alias")?.text;
            const orig = child.childForFieldName("name")?.text;
            if (alias && orig) map.set(alias, moduleName);
          }
        }
      }
    }
    if (node.type === "import_statement") {
      for (const child of node.namedChildren) {
        if (child?.type === "aliased_import") {
          const alias = child.childForFieldName("alias")?.text;
          const orig = child.childForFieldName("name")?.text;
          if (alias && orig) map.set(alias, orig);
        }
      }
    }
    for (const child of node.namedChildren) if (child) visit(child);
  };
  visit(root);
  return map;
}

function argListOf(call: SyntaxNode): SyntaxNode[] {
  const args = call.childForFieldName("arguments");
  if (!args) return [];
  return args.namedChildren.filter((n): n is SyntaxNode => !!n && n.type !== "comment");
}

function hasShellTrue(args: SyntaxNode[]): boolean {
  return args.some(a => a.type === "keyword_argument" &&
    a.childForFieldName("name")?.text === "shell" &&
    a.childForFieldName("value")?.text === "True");
}

function matchSinkPy(call: SyntaxNode, importMap: Map<string, string>): SinkMatch | null {
  const fnNode = call.childForFieldName("function");
  if (!fnNode) return null;
  const text = calleeTextPy(fnNode);
  if (!text) return null;
  const parts = text.split(".");
  const head = parts[0];
  const tail = parts[parts.length - 1];
  const resolvedModule = importMap.get(head) ?? head;
  const args = argListOf(call);

  if (text === "os.system" || text === "os.popen" ||
      (resolvedModule === "os" && (tail === "system" || tail === "popen"))) {
    return { id: "command-injection", sinkExpr: text, args };
  }
  if ((parts[0] === "subprocess" || resolvedModule === "subprocess") &&
      ["call", "run", "Popen", "check_output", "check_call"].includes(tail)) {
    // subprocess.run([tainted, ...]) with a list arg (shell=False default) is
    // the safe idiom -- only flag when shell=True is present, or the first
    // positional arg is not a list/tuple literal (a plain tainted string).
    const firstArg = args.find(a => a.type !== "keyword_argument");
    const firstArgIsListForm = firstArg?.type === "list" || firstArg?.type === "tuple";
    if (hasShellTrue(args) || !firstArgIsListForm) {
      return { id: "command-injection", sinkExpr: text, args };
    }
    return null;
  }
  if ((parts[0] === "requests" || resolvedModule === "requests") &&
      ["get", "post", "put", "delete", "patch", "request"].includes(tail)) {
    return { id: "ssrf", sinkExpr: text, args };
  }
  if (text === "urllib.request.urlopen" || (resolvedModule === "urllib.request" && tail === "urlopen") ||
      (resolvedModule === "urllib" && text.endsWith("urlopen"))) {
    return { id: "ssrf", sinkExpr: text, args };
  }
  if (text === "open" || (resolvedModule === "os.path" && tail === "join") || text === "os.path.join") {
    return { id: "path-traversal", sinkExpr: text, args };
  }
  if (text === "redirect" || text === "flask.redirect" || text === "HttpResponseRedirect" ||
      text.endsWith(".HttpResponseRedirect")) {
    return { id: "open-redirect", sinkExpr: text, args };
  }
  if (tail === "execute" || tail === "executemany" ||
      (parts.length > 1 && (tail === "raw" || tail === "extra"))) {
    return { id: "sql-injection", sinkExpr: text, args };
  }
  if (text === "render_template_string" || tail === "from_string") {
    return { id: "ssti", sinkExpr: text, args };
  }
  return null;
}

// ── Taint environment / propagation ─────────────────────────────────────────

type Env = Map<string, boolean>;
interface LocalFn { paramShapes: ParamShape[]; body: SyntaxNode }

function makeIsTaintedPy(localFns: Map<string, LocalFn>, propagating: Map<string, Set<number>>, inDjangoRequestFn: boolean) {
  const isTainted = (node: SyntaxNode, env: Env): boolean => {
    if (isTaintSourceExprPy(node, inDjangoRequestFn)) return true;
    if (node.type === "identifier") return env.get(node.text) === true;
    if (node.type === "binary_operator") {
      const op = node.childForFieldName("operator")?.text;
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if ((op === "+" || op === "%") && left && right) return isTainted(left, env) || isTainted(right, env);
      return false;
    }
    if (node.type === "string") {
      // f-string interpolations -- direct analogue of Phase 1's template literal handling.
      return node.namedChildren.some(c =>
        c?.type === "interpolation" && !!c.childForFieldName("expression") &&
        isTainted(c.childForFieldName("expression")!, env));
    }
    if (node.type === "call") {
      const fn = node.childForFieldName("function");
      const args = argListOf(node);
      // "...{}...".format(x) -- closes the confirmed .format() gap.
      if (fn?.type === "attribute" && attributeParts(fn).attribute === "format") {
        return args.some(a => isTainted(a, env));
      }
      // A call to a local function known to propagate taint from SPECIFIC
      // params to return value (see computeReturnTaintPropagatingPy below).
      // Only the arguments at the propagating indices are checked, not
      // every argument.
      if (fn?.type === "identifier") {
        const propIdx = propagating.get(fn.text);
        if (propIdx) {
          const callee = localFns.get(fn.text);
          const shapes = callee?.paramShapes ?? [];
          const matched = [...propIdx].some(i => {
            const shape = shapes[i];
            return shape ? argsForShape(args, shape).some(a => isTainted(a, env)) : false;
          });
          if (matched) return true;
        }
      }
      // Passthrough method call on an already-tainted receiver (.strip()/.lower()/etc).
      if (fn?.type === "attribute") {
        const object = attributeParts(fn).object;
        if (object) return isTainted(object, env);
      }
      return false;
    }
    if (node.type === "list" || node.type === "tuple" || node.type === "set") {
      return node.namedChildren.some(c => c && isTainted(c, env));
    }
    if (node.type === "dictionary") {
      return node.namedChildren.some(c => c?.type === "pair" &&
        (isTainted(c.childForFieldName("key")!, env) || isTainted(c.childForFieldName("value")!, env)));
    }
    if (node.type === "parenthesized_expression") {
      const inner = node.namedChildren[0];
      return inner ? isTainted(inner, env) : false;
    }
    return false;
  };
  return isTainted;
}

/**
 * For each of `fn`'s parameters INDEPENDENTLY (seed only that one param
 * tainted, all others left untainted), does `fn`'s return value become
 * tainted? Returns the set of parameter INDICES whose taint actually
 * reaches the return -- not a single per-function boolean (which would mean
 * a call like build_log(safe_id, tainted_message), where only user_id --
 * not message -- flows into the return, incorrectly firing). Sound because
 * makeIsTaintedPy is purely OR-shaped (every combinator is `||`/`.some()`,
 * nothing de-taints), so seeding a superset of params can only ever taint a
 * superset of what seeding a subset taints. Mirrors astTaint.ts's
 * computeReturnTaintPropagating exactly, genuinely simpler here since
 * Python has only function_definition (def/async def), no separate
 * arrow/expression function forms to special-case.
 */
function computeReturnTaintPropagatingPy(fn: LocalFn): Set<number> {
  const propagatingIdx = new Set<number>();
  const isTaintedShallow = makeIsTaintedPy(new Map(), new Map(), false);
  const returnValues: SyntaxNode[] = [];
  const collect = (n: SyntaxNode) => {
    if (n.type === "return_statement") {
      const value = n.namedChildren[0];
      if (value) { returnValues.push(value); return; }
    }
    for (const child of n.namedChildren) if (child) collect(child);
  };
  collect(fn.body);
  for (const shape of fn.paramShapes) {
    const env: Env = new Map();
    env.set(shape.name, true);
    if (returnValues.some(v => isTaintedShallow(v, env))) propagatingIdx.add(shape.index);
  }
  return propagatingIdx;
}

function sourceLabelPy(node: SyntaxNode): string {
  return node.text.replace(/\s+/g, " ").slice(0, 60);
}

/** Collects every function_definition (module-level and class methods -- more real coverage for the interprocedural/sink engine's own purposes; only findEnclosingFunctionNamePy restricts to module-level for callGraph.ts compatibility). */
function collectLocalFunctionsPy(root: SyntaxNode): Map<string, LocalFn> {
  const fns = new Map<string, LocalFn>();
  const visit = (node: SyntaxNode) => {
    if (node.type === "function_definition") {
      const name = node.childForFieldName("name")?.text;
      const body = node.childForFieldName("body");
      if (name && body) fns.set(name, { paramShapes: paramShapesOfPy(node), body });
    }
    for (const child of node.namedChildren) if (child) visit(child);
  };
  visit(root);
  return fns;
}

const SEVERITY: Record<AstTaintPyId, "critical" | "high" | "medium"> = {
  "sql-injection": "critical", "command-injection": "critical", "ssrf": "critical",
  "path-traversal": "critical", "ssti": "critical", "open-redirect": "medium",
};
const LABEL: Record<AstTaintPyId, string> = {
  "sql-injection": "SQL Injection", "command-injection": "Command Injection",
  "ssrf": "Server-Side Request Forgery", "path-traversal": "Path Traversal",
  "ssti": "Server-Side Template Injection", "open-redirect": "Open Redirect",
};

function isFastApiHandler(fn: SyntaxNode): boolean {
  const parent = fn.parent;
  if (!parent || parent.type !== "decorated_definition") return false;
  return parent.namedChildren.some(c => c?.type === "decorator" && FASTAPI_DECORATOR_RE.test(c.text));
}

/**
 * Walks the whole tree once: tracks taint through `env`, seeds tainted
 * parameters into same-file callees on tainted call sites (one hop, mirrors
 * Phase 1), and matches sink call expressions against a tainted argument.
 */
export function scanAstTaintPython(content: string, filePath: string, presparsed?: SyntaxNode | null): AstTaintPyFinding[] {
  try {
    const root = presparsed ?? parsePythonSourceSync(content, filePath);
    if (!root) return [];

    const importMap = buildImportMapPy(root);
    const localFns = collectLocalFunctionsPy(root);
    const propagating = new Map<string, Set<number>>();
    for (const [name, fn] of localFns) {
      const idx = computeReturnTaintPropagatingPy(fn);
      if (idx.size > 0) propagating.set(name, idx);
    }

    const findings: AstTaintPyFinding[] = [];
    const seen = new Set<string>();
    const lineOf = (node: SyntaxNode): number => node.startPosition.row + 1;

    const emit = (id: AstTaintPyId, node: SyntaxNode, sourceExpr: string, sinkExpr: string) => {
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

    const walk = (node: SyntaxNode, env: Env, inDjangoRequestFn: boolean, isTainted: ReturnType<typeof makeIsTaintedPy>) => {
      if (node.type === "assignment") {
        const left = node.childForFieldName("left");
        const right = node.childForFieldName("right");
        if (left && right) {
          const tainted = isTainted(right, env);
          if (left.type === "identifier") {
            env.set(left.text, tainted);
          } else if ((left.type === "pattern_list" || left.type === "tuple_pattern") && tainted) {
            for (const el of left.namedChildren) if (el?.type === "identifier") env.set(el.text, true);
          }
        }
      }

      if (node.type === "call") {
        const match = matchSinkPy(node, importMap);
        if (match) {
          const taintedArg = match.args.find(a => isTainted(a, env));
          if (taintedArg) emit(match.id, node, sourceLabelPy(taintedArg), match.sinkExpr);
        }
        const fnNode = node.childForFieldName("function");
        if (fnNode?.type === "identifier" && localFns.has(fnNode.text)) {
          const fnName = fnNode.text;
          const fn = localFns.get(fnName)!;
          const args = argListOf(node);
          const taintedIdx = new Set<number>();
          args.forEach((arg, i) => {
            if (!isTainted(arg, env)) return;
            const shape = fn.paramShapes.find(s => s.isRest ? i >= s.index : s.index === i);
            if (shape) taintedIdx.add(shape.index);
          });
          if (taintedIdx.size > 0) {
            const existing = seededParams.get(fnName) ?? new Set<number>();
            taintedIdx.forEach(i => existing.add(i));
            seededParams.set(fnName, existing);
          }
        }
      }

      // FastAPI parameter-injection: taint every param of a route-decorated
      // handler at entry, then walk its body with that seeded env.
      if (node.type === "function_definition" && isFastApiHandler(node)) {
        const fnEnv: Env = new Map(env);
        for (const p of paramNamesOf(node)) fnEnv.set(p, true);
        const body = node.childForFieldName("body");
        if (body) for (const child of body.namedChildren) if (child) walk(child, fnEnv, false, isTainted);
        return; // don't also walk with the outer (untainted) env below
      }

      // Django view-function scoping: request.GET/.POST only treated as a
      // source while inside a function whose own param is literally `request`.
      if (node.type === "function_definition") {
        const nextInDjango = hasRequestParam(node);
        if (nextInDjango !== inDjangoRequestFn) {
          const scopedIsTainted = makeIsTaintedPy(localFns, propagating, nextInDjango);
          for (const child of node.namedChildren) if (child) walk(child, env, nextInDjango, scopedIsTainted);
          return;
        }
      }

      for (const child of node.namedChildren) if (child) walk(child, env, inDjangoRequestFn, isTainted);
    };

    const rootIsTainted = makeIsTaintedPy(localFns, propagating, false);
    walk(root, new Map(), false, rootIsTainted);

    // Second pass: re-walk any local function whose params were seeded as
    // tainted by a call site above, so sinks inside the callee are reachable.
    for (const [fnName, idxSet] of seededParams) {
      const fn = localFns.get(fnName);
      if (!fn) continue;
      const env: Env = new Map();
      for (const idx of idxSet) {
        const shape = fn.paramShapes[idx];
        if (shape) env.set(shape.name, true);
      }
      const seededIsTainted = makeIsTaintedPy(localFns, propagating, false);
      for (const child of fn.body.namedChildren) if (child) walk(child, env, false, seededIsTainted);
    }

    return findings;
  } catch (err) {
    console.error(`[astTaintPython] threw scanning ${filePath}:`, err);
    return [];
  }
}

export function astTaintPySeverity(id: AstTaintPyId): "critical" | "high" | "medium" {
  return SEVERITY[id];
}
export function astTaintPyLabel(id: AstTaintPyId): string {
  return LABEL[id];
}
