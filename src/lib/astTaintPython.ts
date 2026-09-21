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
import { ensureTreeSitterInit } from "./treeSitterRuntime";
import {
  ALL, applyClears, applyGuards, classOf, cloneEnv, walkIfChain, walkLoop, walkSwitch, walkTry, wasCleared,
  type Branch, type Guard, type SuppressedSink, type TaintEnv,
} from "./taint/taintCore";
import { sanitizerClears } from "./taint/sanitizers";

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
      // Never call Parser.init() directly here -- see treeSitterRuntime.ts's
      // docblock for the concurrent-init race this sidesteps (this file
      // used to call Parser.init() itself; that was safe only as long as it
      // was the sole tree-sitter-based engine in the codebase -- adding
      // astTaintGo.ts's own independent Parser.init() call made the two
      // race, confirmed directly).
      await ensureTreeSitterInit();
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

// Sanitizers live in taint/sanitizers.ts, keyed by the sink classes each one
// actually neutralizes -- see astTaint.ts for the shared design/limitations
// (handles the common `clean = sanitize(x)` assignment pattern, doesn't
// retroactively clean through a sticky in-place mutation site -- documented,
// accepted gap).

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

type Env = TaintEnv;
interface LocalFn { paramShapes: ParamShape[]; body: SyntaxNode }
// fn name -> (param index -> sink classes that survive to its return value)
type PropagatingPy = Map<string, Map<number, number>>;

function makeTaintMaskPy(localFns: Map<string, LocalFn>, propagating: PropagatingPy, inDjangoRequestFn: boolean) {
  const taintMask = (node: SyntaxNode, env: Env): number => {
    const orAll = (nodes: (SyntaxNode | null | undefined)[]) =>
      nodes.reduce((m: number, c) => (c ? m | taintMask(c, env) : m), 0);
    if (isTaintSourceExprPy(node, inDjangoRequestFn)) return ALL;
    if (node.type === "identifier") return env.get(node.text) ?? 0;
    if (node.type === "attribute") {
      // Field-sensitive read: OR the composite "root.field" key (set by the
      // assignment-handling branch in scanAstTaintPython's walk below) with
      // the root-object mask -- pure recall gain, same reasoning as
      // astTaint.ts's identical addition.
      const path = calleeTextPy(node);
      const object = attributeParts(node).object;
      return (path ? (env.get(path) ?? 0) : 0) | (object ? taintMask(object, env) : 0);
    }
    if (node.type === "binary_operator") {
      const op = node.childForFieldName("operator")?.text;
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if ((op === "+" || op === "%") && left && right) return taintMask(left, env) | taintMask(right, env);
      return 0;
    }
    if (node.type === "string") {
      // f-string interpolations -- direct analogue of Phase 1's template literal handling.
      return node.namedChildren.reduce((m: number, c) =>
        (c?.type === "interpolation" && c.childForFieldName("expression")
          ? m | taintMask(c.childForFieldName("expression")!, env) : m), 0);
    }
    if (node.type === "call") {
      const fn = node.childForFieldName("function");
      const args = argListOf(node);
      const calleeName = fn ? calleeTextPy(fn) : null;
      if (calleeName) {
        // Known sanitizer: the argument's taint passes THROUGH minus only
        // the classes it actually neutralizes; opaque calls stay untainted.
        const clears = sanitizerClears("py", calleeName);
        if (clears !== null) return args[0] ? applyClears(taintMask(args[0], env), clears) : 0;
      }
      // "...{}...".format(x) -- closes the confirmed .format() gap.
      if (fn?.type === "attribute" && attributeParts(fn).attribute === "format") {
        return orAll(args);
      }
      // A call to a local function known to propagate taint from SPECIFIC
      // params to return value (see computeReturnTaintPropagatingPy below).
      // Only the arguments at the propagating indices are checked, and only
      // the classes that survive the callee's own body count.
      if (fn?.type === "identifier") {
        const propIdx = propagating.get(fn.text);
        if (propIdx) {
          const callee = localFns.get(fn.text);
          const shapes = callee?.paramShapes ?? [];
          let m = 0;
          for (const [i, surviving] of propIdx) {
            const shape = shapes[i];
            if (!shape) continue;
            for (const a of argsForShape(args, shape)) m |= taintMask(a, env) & surviving;
          }
          if (m) return m;
        }
      }
      // Passthrough method call on an already-tainted receiver (.strip()/.lower()/etc).
      if (fn?.type === "attribute") {
        const object = attributeParts(fn).object;
        if (object) return taintMask(object, env);
      }
      return 0;
    }
    if (node.type === "list" || node.type === "tuple" || node.type === "set") {
      return orAll(node.namedChildren);
    }
    if (node.type === "dictionary") {
      return node.namedChildren.reduce((m: number, c) =>
        (c?.type === "pair" ? m | taintMask(c.childForFieldName("key")!, env) | taintMask(c.childForFieldName("value")!, env) : m), 0);
    }
    if (node.type === "parenthesized_expression") {
      const inner = node.namedChildren[0];
      return inner ? taintMask(inner, env) : 0;
    }
    // `a if c else b` -- children are positional [a, c, b]; the value is one
    // of the two arms, the CONDITION is deliberately excluded.
    if (node.type === "conditional_expression") {
      const parts = node.namedChildren;
      return (parts[0] ? taintMask(parts[0], env) : 0) | (parts[2] ? taintMask(parts[2], env) : 0);
    }
    // `a or b` / `a and b` evaluate to one of their operands.
    if (node.type === "boolean_operator") {
      return orAll([node.childForFieldName("left"), node.childForFieldName("right")]);
    }
    return 0;
  };
  return taintMask;
}

type TaintMaskFnPy = ReturnType<typeof makeTaintMaskPy>;

// ── Validation guards (narrow, unambiguous only) ────────────────────────────

function isLiteralPy(n: SyntaxNode): boolean {
  if (n.type === "string") return !n.namedChildren.some(c => c?.type === "interpolation");
  return n.type === "integer" || n.type === "float" || n.type === "true" || n.type === "false" || n.type === "none";
}

/** A tuple/list/set made ONLY of literals, or a module-level name bound to one. */
function isLiteralCollectionPy(n: SyntaxNode, root: SyntaxNode, depth = 0): boolean {
  if (depth > 3) return false;
  if (n.type === "tuple" || n.type === "list" || n.type === "set") {
    return n.namedChildren.length > 0 && n.namedChildren.every(c => !!c && isLiteralPy(c));
  }
  if (n.type === "identifier") {
    for (const st of root.namedChildren) {
      const asg = st?.type === "expression_statement" ? st.namedChildren[0] : null;
      if (asg?.type !== "assignment") continue;
      const l = asg.childForFieldName("left");
      const r = asg.childForFieldName("right");
      if (l?.type === "identifier" && l.text === n.text && r) return isLiteralCollectionPy(r, root, depth + 1);
    }
  }
  return false;
}

const invertPy = (g: Guard): Guard => ({ name: g.name, holds: g.holds === "true" ? "false" : "true" });

/**
 * The variables a condition PROVES safe, and on which side -- a closed set:
 * literal-collection membership, equality with a literal, isinstance(x, int/
 * float/bool), and x.isdigit()/isnumeric()/isdecimal(). Regex matches,
 * startswith and custom validator calls are deliberately NOT recognized.
 */
function guardsOfConditionPy(cond: SyntaxNode, root: SyntaxNode): Guard[] {
  switch (cond.type) {
    case "parenthesized_expression": {
      const inner = cond.namedChildren[0];
      return inner ? guardsOfConditionPy(inner, root) : [];
    }
    case "not_operator": {
      const inner = cond.childForFieldName("argument");
      return inner ? guardsOfConditionPy(inner, root).map(invertPy) : [];
    }
    case "boolean_operator": {
      const op = cond.childForFieldName("operator")?.text;
      const l = cond.childForFieldName("left");
      const r = cond.childForFieldName("right");
      if (!l || !r) return [];
      const all = [...guardsOfConditionPy(l, root), ...guardsOfConditionPy(r, root)];
      return op === "and" ? all.filter(g => g.holds === "true") : op === "or" ? all.filter(g => g.holds === "false") : [];
    }
    case "comparison_operator": {
      const [l, r] = cond.namedChildren;
      if (cond.namedChildren.length !== 2 || !l || !r) return [];
      const op = cond.text.slice(l.endIndex - cond.startIndex, r.startIndex - cond.startIndex).trim();
      if (l.type === "identifier") {
        if (op === "in" && isLiteralCollectionPy(r, root)) return [{ name: l.text, holds: "true" }];
        if (op === "not in" && isLiteralCollectionPy(r, root)) return [{ name: l.text, holds: "false" }];
        if (op === "==" && isLiteralPy(r)) return [{ name: l.text, holds: "true" }];
        if (op === "!=" && isLiteralPy(r)) return [{ name: l.text, holds: "false" }];
      }
      if (r.type === "identifier" && isLiteralPy(l)) {
        if (op === "==") return [{ name: r.text, holds: "true" }];
        if (op === "!=") return [{ name: r.text, holds: "false" }];
      }
      return [];
    }
    case "call": {
      const fn = cond.childForFieldName("function");
      const args = argListOf(cond);
      if (fn?.type === "identifier" && fn.text === "isinstance" && args.length === 2 && args[0].type === "identifier") {
        const t = args[1];
        const okType = (n: SyntaxNode) => n.type === "identifier" && ["int", "float", "bool"].includes(n.text);
        if (okType(t) || (t.type === "tuple" && t.namedChildren.length > 0 && t.namedChildren.every(c => !!c && okType(c)))) {
          return [{ name: args[0].text, holds: "true" }];
        }
      }
      if (fn?.type === "attribute" && args.length === 0) {
        const { object, attribute } = attributeParts(fn);
        if (object?.type === "identifier" && ["isdigit", "isnumeric", "isdecimal"].includes(attribute ?? "")) {
          return [{ name: object.text, holds: "true" }];
        }
      }
      return [];
    }
    default:
      return [];
  }
}

// ── Path-sensitive statement walk ───────────────────────────────────────────
// One walker serves the interprocedural summary builder (no sink checks, no
// nested functions, collects return masks) and the main scan (sink checks,
// nested functions walked on a cloned env). Branches walk each arm on a CLONE
// of the env and join with may-taint OR (shared combinators in
// taint/taintCore.ts); an arm ending in return/raise is dropped from the
// join, and code after a terminating statement is dead and not walked.

interface WalkHooksPy {
  localFns: Map<string, LocalFn>;
  propagating: PropagatingPy;
  root: SyntaxNode;
  /** Sink checks / call-site seeding for one `call` node, with the env at that point. */
  onCall?: (node: SyntaxNode, env: Env, taintMask: TaintMaskFnPy) => void;
  /** Called for each `return expr`, with the env on that path. */
  onReturn?: (expr: SyntaxNode, env: Env, taintMask: TaintMaskFnPy) => void;
  /** Walk nested function bodies (main scan) or ignore them (summaries). */
  descendFunctions: boolean;
}

function createWalkerPy(h: WalkHooksPy) {
  const masks = new Map<boolean, TaintMaskFnPy>();
  const maskFor = (django: boolean): TaintMaskFnPy => {
    let m = masks.get(django);
    if (!m) { m = makeTaintMaskPy(h.localFns, h.propagating, django); masks.set(django, m); }
    return m;
  };

  const identifiersIn = (n: SyntaxNode | null): string[] => {
    if (!n) return [];
    if (n.type === "identifier") return [n.text];
    return n.namedChildren.flatMap(c => (c ? identifiersIn(c) : []));
  };

  const walkStmts = (nodes: readonly (SyntaxNode | null)[], env: Env, django: boolean): boolean => {
    for (const c of nodes) if (c && walk(c, env, django)) return true; // dead code after a terminator is not walked
    return false;
  };

  const walkFunction = (fn: SyntaxNode, env: Env) => {
    const body = fn.childForFieldName("body");
    if (!body) return;
    // A nested function sees captured outer variables (cloned env); its own
    // parameters shadow same-named outer ones and start untainted -- except a
    // FastAPI route handler, whose parameters ARE the request input.
    const django = hasRequestParam(fn);
    const fenv = cloneEnv(env);
    const seeded = isFastApiHandler(fn);
    for (const prm of paramNamesOf(fn)) fenv.set(prm, seeded ? ALL : 0);
    walk(body, fenv, django);
  };

  const walk = (node: SyntaxNode, env: Env, django: boolean): boolean => {
    const taintMask = maskFor(django);
    switch (node.type) {
      case "function_definition":
        if (h.descendFunctions) walkFunction(node, env);
        return false;

      case "block":
      case "module":
        return walkStmts(node.namedChildren, env, django);

      case "if_statement": {
        const branches: Branch[] = [];
        const addCond = (condNode: SyntaxNode | null, bodyNode: SyntaxNode | null) => {
          branches.push({
            visitCond: (e) => { if (condNode) walk(condNode, e, django); },
            guards: () => (condNode ? guardsOfConditionPy(condNode, h.root) : []),
            body: (e) => (bodyNode ? walk(bodyNode, e, django) : false),
          });
        };
        addCond(node.childForFieldName("condition"), node.childForFieldName("consequence"));
        for (const alt of node.childrenForFieldName("alternative")) {
          if (!alt) continue;
          if (alt.type === "elif_clause") {
            addCond(alt.childForFieldName("condition"), alt.childForFieldName("consequence"));
          } else if (alt.type === "else_clause") {
            const body = alt.childForFieldName("body");
            branches.push({ body: (e) => (body ? walk(body, e, django) : false) });
          }
        }
        return walkIfChain(env, branches);
      }

      case "for_statement": {
        const right = node.childForFieldName("right");
        if (right) walk(right, env, django);
        const rmask = right ? taintMask(right, env) : 0;
        for (const name of identifiersIn(node.childForFieldName("left"))) env.set(name, rmask);
        const body = node.childForFieldName("body");
        return walkLoop(env, (e) => (body ? walk(body, e, django) : false));
      }

      case "while_statement": {
        const cond = node.childForFieldName("condition");
        if (cond) walk(cond, env, django);
        const body = node.childForFieldName("body");
        return walkLoop(env, (e) => (body ? walk(body, e, django) : false));
      }

      case "try_statement": {
        const body = node.childForFieldName("body");
        const elseB = node.namedChildren.find(c => c?.type === "else_clause");
        const finallyC = node.namedChildren.find(c => c?.type === "finally_clause");
        const lastBlock = (c: SyntaxNode) => [...c.namedChildren].reverse().find(x => x?.type === "block") ?? null;
        const catches = node.namedChildren
          .filter(c => c?.type === "except_clause" || c?.type === "except_group_clause")
          .map(c => ({
            // `except E as e:` -- the handler binds `e`, shadowing any outer `e`
            bind: [c!.text.match(/^\s*except\*?[^:\n]*?\bas\s+(\w+)/)?.[1]].filter((n): n is string => !!n),
            body: (e: Env) => { const b = lastBlock(c!); return b ? walk(b, e, django) : false; },
          }));
        return walkTry(
          env,
          (e) => {
            let t = body ? walk(body, e, django) : false;
            if (!t && elseB) { const eb = elseB.childForFieldName("body") ?? lastBlock(elseB); if (eb) t = walk(eb, e, django); }
            return t;
          },
          catches,
          finallyC ? (e) => { const fb = lastBlock(finallyC); return fb ? walk(fb, e, django) : false; } : undefined,
        );
      }

      case "match_statement": {
        const subject = node.childForFieldName("subject");
        if (subject) walk(subject, env, django);
        const subjectName = subject?.type === "identifier" ? subject.text : null;
        const cases = (node.childForFieldName("body")?.namedChildren ?? []).filter(c => c?.type === "case_clause");
        return walkSwitch(env, cases.map(cl => {
          const pattern = cl!.namedChildren.find(x => x?.type === "case_pattern");
          const patText = pattern?.text.trim() ?? "";
          const body = cl!.childForFieldName("consequence");
          return {
            isDefault: patText === "_",
            // inside `case "a":` / `case 5:` the subject IS that literal
            pre: (e: Env) => { if (subjectName && /^(?:["'0-9-]|True$|False$|None$)/.test(patText)) applyGuards(e, [subjectName]); },
            body: (e: Env) => (body ? walk(body, e, django) : false),
          };
        }));
      }

      case "return_statement": {
        const v = node.namedChildren[0];
        if (v) { walk(v, env, django); h.onReturn?.(v, env, taintMask); }
        return true;
      }

      case "raise_statement":
        for (const c of node.namedChildren) if (c) walk(c, env, django);
        return true;

      default:
        break;
    }

    if (node.type === "assignment") {
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if (left && right) {
        const mask = taintMask(right, env);
        if (left.type === "identifier") {
          env.set(left.text, mask);
        } else if ((left.type === "pattern_list" || left.type === "tuple_pattern") && (mask & ALL)) {
          for (const el of left.namedChildren) if (el?.type === "identifier") env.set(el.text, mask);
        } else if (left.type === "attribute") {
          // Field-sensitive write: `obj.field = expr` -- stores under the same
          // composite "root.field" key the read side (makeTaintMaskPy) checks.
          // Additive only: obj's own bare-identifier env entry is untouched.
          const path = calleeTextPy(left);
          if (path) env.set(path, mask);
        }
      }
    }
    // `x += y` keeps whatever taint x already had (OR), unlike plain `=`.
    if (node.type === "augmented_assignment") {
      const left = node.childForFieldName("left");
      const right = node.childForFieldName("right");
      if (left && right) {
        const mask = taintMask(right, env);
        if (left.type === "identifier") env.set(left.text, mask | (env.get(left.text) ?? 0));
        else if (left.type === "attribute") {
          const path = calleeTextPy(left);
          if (path) env.set(path, mask | (env.get(path) ?? 0));
        }
      }
    }

    if (node.type === "call") h.onCall?.(node, env, taintMask);

    for (const child of node.namedChildren) if (child) walk(child, env, django);
    return false;
  };

  return { walk };
}

/**
 * For each of `fn`'s parameters INDEPENDENTLY (seed only that one param
 * tainted, all others left untainted), does `fn`'s return value become
 * tainted? Returns the parameter INDICES whose taint actually reaches a
 * return, with the sink classes that survive. Path-sensitive: the mask is
 * taken at EACH return with the env on that path (so a value coerced on one
 * branch and raw on another propagates only what survives), assignments
 * before the return are applied (`q = "SELECT " + x; return q` propagates --
 * the old flat version seeded only the parameter, so it never did), and a
 * return inside a nested function is not this function's return. Sound
 * because every combinator is a bitwise OR and a sanitizer clears a FIXED
 * set of classes, so seeding a superset of params can only taint a superset.
 */
function computeReturnTaintPropagatingPy(
  fn: LocalFn, localFns: Map<string, LocalFn>, propagating: PropagatingPy, root: SyntaxNode,
): Map<number, number> {
  // param index -> sink classes that still survive to the return value
  const propagatingIdx = new Map<number, number>();
  for (const shape of fn.paramShapes) {
    let surviving = 0;
    const walker = createWalkerPy({
      localFns, propagating, root, descendFunctions: false,
      onReturn: (expr, env, mask) => { surviving |= mask(expr, env); },
    });
    const env: Env = new Map();
    env.set(shape.name, ALL);
    walker.walk(fn.body, env, false);
    // Low bits only: the shadow half is per-scan bookkeeping, not a summary.
    surviving &= ALL;
    if (surviving) propagatingIdx.set(shape.index, surviving);
  }
  return propagatingIdx;
}

// See astTaint.ts's identical constant/function for the full rationale --
// mirrored here rather than shared, matching this codebase's existing
// per-engine-file convention (no shared taint-engine base module).
const MAX_PROPAGATION_ROUNDS_PY = 3;

function buildPropagatingMapPy(localFns: Map<string, LocalFn>, root: SyntaxNode): PropagatingPy {
  const propagating: PropagatingPy = new Map();
  for (let round = 0; round < MAX_PROPAGATION_ROUNDS_PY; round++) {
    let changed = false;
    for (const [name, fn] of localFns) {
      const found = computeReturnTaintPropagatingPy(fn, localFns, propagating, root);
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
export function scanAstTaintPython(
  content: string, filePath: string, presparsed?: SyntaxNode | null,
  // Sinks whose argument was tainted for the sink's class but positively
  // cleared by a sanitizer (see astTaint.ts) -- lets scanner.ts drop the
  // regex layer's duplicate for a flow this engine proved safe.
  suppressedOut?: SuppressedSink[],
): AstTaintPyFinding[] {
  try {
    const root = presparsed ?? parsePythonSourceSync(content, filePath);
    if (!root) return [];

    const importMap = buildImportMapPy(root);
    const localFns = collectLocalFunctionsPy(root);
    const propagating = buildPropagatingMapPy(localFns, root);

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

    // fn name -> (tainted param index -> classes tainted at the call site)
    const seededParams = new Map<string, Map<number, number>>();

    // Sink checks and same-file call-site seeding for one `call` node, with
    // the env at that point. Statement structure, branching, assignments and
    // nested functions are the shared walker's job (createWalkerPy).
    const onCall = (node: SyntaxNode, env: Env, taintMask: TaintMaskFnPy) => {
      const match = matchSinkPy(node, importMap);
      if (match) {
        const cls = classOf(match.id);
        let taintedArg: SyntaxNode | undefined;
        let cleared = false;
        for (const a of match.args) {
          const m = taintMask(a, env);
          if (m & cls) { taintedArg = a; break; }
          if (wasCleared(m, cls)) cleared = true;
        }
        if (taintedArg) emit(match.id, node, sourceLabelPy(taintedArg), match.sinkExpr);
        else if (cleared) suppressedOut?.push({ id: match.id, line: lineOf(node) });
      }
      const fnNode = node.childForFieldName("function");
      if (fnNode?.type === "identifier" && localFns.has(fnNode.text)) {
        const fnName = fnNode.text;
        const fn = localFns.get(fnName)!;
        const args = argListOf(node);
        const taintedIdx = new Map<number, number>();
        args.forEach((arg, i) => {
          const m = taintMask(arg, env) & ALL;
          if (!m) return;
          const shape = fn.paramShapes.find(s => s.isRest ? i >= s.index : s.index === i);
          if (shape) taintedIdx.set(shape.index, (taintedIdx.get(shape.index) ?? 0) | m);
        });
        if (taintedIdx.size > 0) {
          const existing = seededParams.get(fnName) ?? new Map<number, number>();
          for (const [i, m] of taintedIdx) existing.set(i, (existing.get(i) ?? 0) | m);
          seededParams.set(fnName, existing);
        }
      }
    };

    const walker = createWalkerPy({ localFns, propagating, root, descendFunctions: true, onCall });
    const walk = (node: SyntaxNode, env: Env, django: boolean) => walker.walk(node, env, django);

    walk(root, new Map(), false);

    // Second pass, bounded worklist (see astTaint.ts's identical structure
    // for the full rationale): re-walking a seeded function can itself seed
    // FURTHER functions via the same call-site logic above, discovering a
    // second/third hop -- bounded by MAX_PROPAGATION_ROUNDS_PY rather than
    // left as an unbounded/accidental side effect of Map iteration order.
    const walkedSignaturesPy = new Set<string>();
    for (let round = 0; round < MAX_PROPAGATION_ROUNDS_PY; round++) {
      const toWalk = Array.from(seededParams.entries());
      let changed = false;
      for (const [fnName, idxSet] of toWalk) {
        const fn = localFns.get(fnName);
        if (!fn) continue;
        const signature = `${fnName}:${[...idxSet].sort((a, b) => a[0] - b[0]).map(([i, m]) => `${i}=${m}`).join(",")}`;
        if (walkedSignaturesPy.has(signature)) continue;
        walkedSignaturesPy.add(signature);
        changed = true;
        const env: Env = new Map();
        for (const [idx, m] of idxSet) {
          const shape = fn.paramShapes[idx];
          if (shape) env.set(shape.name, m);
        }
        walk(fn.body, env, false);
      }
      if (!changed) break;
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
