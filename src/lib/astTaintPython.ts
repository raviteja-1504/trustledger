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
 * Also covers (added with the Python recall phase): XSS (Response/make_response
 * and a request handler's returned string), header injection, NoSQL, LDAP,
 * XPath, ReDoS, eval/dynamic import, pickle/yaml deserialization (taint-
 * conditioned, so it does not duplicate the regex layer's untainted matches),
 * setattr/dict-merge mass assignment, timing-unsafe secret comparison and
 * hand-rolled JWT decoding. Request objects are recognised by name shape
 * (request, req, request_obj, ...), not only the Flask global.
 * Deliberately excludes BOLA (.filter_by-style authorization-absence bugs are a
 * business-logic judgment, not a data-flow-reachability fact -- the
 * existing regex+proximity approach is structurally the right tool there).
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { Parser, Language } = require("web-tree-sitter") as typeof import("web-tree-sitter");
import type { Node as SyntaxNode, Language as LanguageT, Parser as ParserT } from "web-tree-sitter";
import { ensureTreeSitterInit } from "./treeSitterRuntime";
import {
  ALL, SHADOW, applyClears, applyGuards, classOf, cloneEnv, walkIfChain, walkLoop, walkSwitch, walkTry, wasCleared,
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
  | "sql-injection" | "command-injection" | "ssrf" | "path-traversal" | "open-redirect" | "ssti"
  | "xss" | "header-injection" | "nosql-injection" | "ldap-injection" | "xpath-injection" | "redos" | "eval-exec"
  | "insecure-deserialization" | "mass-assignment" | "timing-attack" | "jwt-none-alg";

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

const FLASK_ATTR_SOURCES = new Set(["args", "form", "json", "data", "values", "cookies", "headers", "view_args", "files", "query_params", "path_params"]);
/** `request`, `req`, `request_obj`, `http_request`, ... -- a request object passed as a parameter is as attacker-controlled as the Flask global. */
const REQUEST_NAME_RE = /^(?:\w+_)?(?:request|req)(?:_\w+)?$/i;
const isRequestName = (name: string): boolean => REQUEST_NAME_RE.test(name);
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
  return paramNamesOf(fn).some(isRequestName);
}

function isTaintSourceExprPy(node: SyntaxNode, inDjangoRequestFn: boolean): boolean {
  if (node.type === "attribute") {
    const { object, attribute } = attributeParts(node);
    if (object?.type === "identifier" && isRequestName(object.text) && attribute && FLASK_ATTR_SOURCES.has(attribute)) {
      return true;
    }
    return object ? isTaintSourceExprPy(object, inDjangoRequestFn) : false;
  }
  if (node.type === "call") {
    const fn = node.childForFieldName("function");
    if (fn?.type === "attribute") {
      const { object, attribute } = attributeParts(fn);
      if (object?.type === "identifier" && isRequestName(object.text) && attribute && FLASK_CALL_SOURCES.has(attribute)) {
        return true;
      }
      // Django's dict-.get() convenience form: request.GET.get("x") /
      // request.POST.get("x") -- same scoping as the subscript form below.
      if (inDjangoRequestFn && attribute === "get" && object?.type === "attribute") {
        const inner = attributeParts(object);
        if (inner.object?.type === "identifier" && isRequestName(inner.object.text) &&
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
      if (object?.type === "identifier" && isRequestName(object.text) && attribute && DJANGO_DICT_SOURCES.has(attribute)) {
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
  if (args.type === "generator_expression") return [args]; // a call like sep-join over a generator expression
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

function keywordArg(args: SyntaxNode[], name: string): SyntaxNode | null {
  for (const a of args) {
    if (a.type === "keyword_argument" && a.childForFieldName("name")?.text === name) return a.childForFieldName("value");
  }
  return null;
}

const NOSQL_TAILS_PY = new Set([
  "find", "find_one", "find_one_and_update", "find_one_and_delete", "find_one_and_replace", "update_one", "update_many",
  "delete_one", "delete_many", "replace_one", "aggregate", "count_documents",
]);
const NOSQL_RECEIVER_RE_PY = /mongo|collection|coll\b|nosql|couch|dynamo|cosmos|\bdb\b|model|users?\b|orders?\b|accounts?\b/i;
const LDAP_TAILS_PY = new Set(["search_s", "search_st", "search_ext_s", "search_ext"]);
const REGEX_TAILS_PY = new Set(["search", "match", "fullmatch", "findall", "finditer", "sub", "subn", "split", "compile"]);
const DESERIALIZERS_PY = new Set([
  "pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "dill.loads", "dill.load", "marshal.loads", "marshal.load",
  "jsonpickle.decode", "shelve.open", "yaml.unsafe_load", "yaml.full_load", "yaml.load_all",
]);
const XSS_RESPONSES_PY = new Set(["Response", "flask.Response", "make_response", "flask.make_response", "HttpResponse", "HTMLResponse", "Markup", "markupsafe.Markup", "mark_safe"]);
const PATH_FUNCS_PY = new Set([
  "send_file", "os.remove", "os.unlink", "os.rename", "os.listdir", "os.rmdir", "os.makedirs", "os.mkdir", "os.chmod",
  "shutil.copy", "shutil.copyfile", "shutil.copy2", "shutil.move", "shutil.rmtree", "shutil.copytree",
]);

function matchSinkPy(call: SyntaxNode, importMap: Map<string, string>, evalAliases?: ReadonlySet<string>): SinkMatch | null {
  const fnNode = call.childForFieldName("function");
  if (!fnNode) return null;
  const text = calleeTextPy(fnNode);
  if (!text) return null;
  const parts = text.split(".");
  const head = parts[0];
  const tail = parts[parts.length - 1];
  const resolvedModule = importMap.get(head) ?? head;
  const args = argListOf(call);
  const positional = args.filter(a => a.type !== "keyword_argument");
  const first = positional[0];

  // eval / exec (and aliases of them), __import__ / importlib.import_module: attacker-chosen code or module
  if (text === "eval" || text === "exec" || evalAliases?.has(text)) return first ? { id: "eval-exec", sinkExpr: text, args: [first] } : null;
  if (text === "__import__" || text === "importlib.import_module" || (resolvedModule === "importlib" && tail === "import_module")) {
    return first ? { id: "eval-exec", sinkExpr: text, args: [first] } : null;
  }

  if (text === "os.system" || text === "os.popen" ||
      (resolvedModule === "os" && (tail === "system" || tail === "popen"))) {
    return { id: "command-injection", sinkExpr: text, args };
  }
  if ((parts[0] === "os" || resolvedModule === "os") && /^(?:exec[lv]p?e?|spawn[lv]p?e?)$/.test(tail)) {
    return { id: "command-injection", sinkExpr: text, args: positional };
  }
  if ((parts[0] === "subprocess" || resolvedModule === "subprocess") &&
      ["call", "run", "Popen", "check_output", "check_call"].includes(tail)) {
    // A list/tuple argv (shell=False) is the safe idiom for the ARGUMENTS, but an attacker-chosen
    // EXECUTABLE (first element) is still command execution. shell=True or a plain string flags everything.
    const firstIsList = first?.type === "list" || first?.type === "tuple";
    if (hasShellTrue(args) || !firstIsList) {
      return { id: "command-injection", sinkExpr: text, args };
    }
    const exe = first!.namedChildren.find(c => !!c) ?? null;
    return exe ? { id: "command-injection", sinkExpr: text, args: [exe] } : null;
  }
  if (((parts[0] === "requests" || resolvedModule === "requests") &&
       ["get", "post", "put", "delete", "patch", "request", "head"].includes(tail)) ||
      ((parts[0] === "httpx" || resolvedModule === "httpx") &&
       ["get", "post", "put", "delete", "patch", "request", "head", "stream"].includes(tail))) {
    return { id: "ssrf", sinkExpr: text, args };
  }
  if (text === "urllib.request.urlopen" || (resolvedModule === "urllib.request" && tail === "urlopen") ||
      (resolvedModule === "urllib" && text.endsWith("urlopen")) || text === "urllib.request.Request" ||
      (resolvedModule === "urllib.request" && tail === "Request")) {
    return { id: "ssrf", sinkExpr: text, args };
  }
  if (text === "open" || (resolvedModule === "os.path" && tail === "join") || text === "os.path.join" ||
      PATH_FUNCS_PY.has(text) || (PATH_FUNCS_PY.has(tail) && (resolvedModule === "os" || resolvedModule === "shutil" || tail === "send_file"))) {
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
  // deserialization: pickle & friends always; yaml.load unless a Safe loader is named
  if (DESERIALIZERS_PY.has(text)) return first ? { id: "insecure-deserialization", sinkExpr: text, args: [first] } : null;
  if (text === "yaml.load" || (resolvedModule === "yaml" && tail === "load")) {
    const loader = keywordArg(args, "Loader") ?? positional[1] ?? null;
    if (loader && /Safe/.test(loader.text)) return null;
    return first ? { id: "insecure-deserialization", sinkExpr: text, args: [first] } : null;
  }
  // HTML responses: Flask's Response/make_response default to text/html
  if (XSS_RESPONSES_PY.has(text)) {
    const mime = keywordArg(args, "mimetype") ?? keywordArg(args, "content_type");
    if (mime && isLiteralPy(mime) && !/html/i.test(mime.text)) return null;
    return first ? { id: "xss", sinkExpr: text, args: [first] } : null;
  }
  // response.headers.add/set(name, value)
  if (/\.headers\.(?:add|set|extend|update|setdefault)$/.test(text)) {
    return { id: "header-injection", sinkExpr: text, args: positional };
  }
  // setattr(obj, attacker_chosen_name, value) / obj.__dict__.update(attacker_dict)
  if (text === "setattr" && positional[1]) return { id: "mass-assignment", sinkExpr: text, args: [positional[1]] };
  if (text.endsWith(".__dict__.update") && first) return { id: "mass-assignment", sinkExpr: text, args: [first] };
  // NoSQL (pymongo-style) with an operator-capable filter document
  if (parts.length > 1 && NOSQL_TAILS_PY.has(tail) && first && NOSQL_RECEIVER_RE_PY.test(parts.slice(0, -1).join("."))) {
    return { id: "nosql-injection", sinkExpr: text, args: [first] };
  }
  if (parts.length === 1 && /^(?:\w*mongo\w*)$/i.test(tail) && /(?:find|query|update|delete|aggregate)/i.test(tail) && first) {
    return { id: "nosql-injection", sinkExpr: text, args: [first] };
  }
  // LDAP
  if (parts.length > 1 && (LDAP_TAILS_PY.has(tail) || (tail === "search" && /ldap|conn/i.test(parts.slice(0, -1).join("."))))) {
    return { id: "ldap-injection", sinkExpr: text, args: positional };
  }
  if (parts.length === 1 && /^ldap_(?:search|query|find|filter\w*)$/i.test(tail) && first) {
    return { id: "ldap-injection", sinkExpr: text, args: [first] };
  }
  // XPath
  if (parts.length > 1 && tail === "xpath" && first) return { id: "xpath-injection", sinkExpr: text, args: [first] };
  if ((tail === "XPath" || tail === "XPathEvaluator") && first) return { id: "xpath-injection", sinkExpr: text, args: [first] };
  if (parts.length === 1 && /^(?:select_xpath|xpath_query|evaluate_xpath|run_xpath|xpath_search)$/i.test(tail) && first) {
    return { id: "xpath-injection", sinkExpr: text, args: [first] };
  }
  // user-controlled regular expression
  if ((parts[0] === "re" || parts[0] === "regex" || resolvedModule === "re" || resolvedModule === "regex") &&
      parts.length === 2 && REGEX_TAILS_PY.has(tail) && first) {
    return { id: "redos", sinkExpr: text, args: [first] };
  }
  return null;
}

// ── Taint environment / propagation ─────────────────────────────────────────

type Env = TaintEnv;
interface LocalFn { paramShapes: ParamShape[]; body: SyntaxNode }
// fn name -> (param index -> sink classes that survive to its return value)
type PropagatingPy = Map<string, Map<number, number>>;

// Builtins/stdlib whose RESULT carries the taint of their arguments (string, path, URL, JSON and
// container plumbing that neither validates nor neutralizes anything). Opaque calls stay untainted --
// these are curated exceptions, not a default flip. Decoders also RESTORE classes an encoder cleared.
const PY_PASSTHROUGH = new Set([
  "str", "bytes", "bytearray", "repr", "ascii", "list", "tuple", "set", "frozenset", "dict", "sorted", "reversed",
  "enumerate", "zip", "map", "filter", "iter", "next", "getattr", "copy.copy", "copy.deepcopy",
  "json.loads", "json.dumps", "json.load",
  "base64.b64decode", "base64.b64encode", "base64.urlsafe_b64decode", "base64.urlsafe_b64encode",
  "b64decode", "b64encode", "urlsafe_b64decode", "urlsafe_b64encode",
  "urllib.parse.unquote", "urllib.parse.unquote_plus", "urllib.parse.unquote_to_bytes", "urllib.parse.urljoin",
  "urllib.parse.urlparse", "urllib.parse.urlunparse", "urllib.parse.urlsplit", "urllib.parse.urlunsplit",
  "urllib.parse.parse_qs", "urllib.parse.parse_qsl", "urllib.parse.urlencode",
  "unquote", "unquote_plus", "urljoin", "urlparse", "urlunparse", "urlsplit", "urlunsplit", "parse_qs", "parse_qsl",
  "os.path.join", "os.path.abspath", "os.path.normpath", "os.path.realpath", "os.path.expanduser", "os.path.dirname",
  "os.fspath", "pathlib.Path", "Path", "PurePath", "html.unescape", "textwrap.dedent", "shlex.split",
]);
const PY_DECODERS = new Set([
  "urllib.parse.unquote", "urllib.parse.unquote_plus", "urllib.parse.unquote_to_bytes", "unquote", "unquote_plus",
  "base64.b64decode", "base64.urlsafe_b64decode", "b64decode", "urlsafe_b64decode", "html.unescape",
]);
// Methods whose result also includes their ARGUMENTS (joined items, replacement text, defaults).
const PY_ARG_CARRYING_METHODS = new Set(["join", "replace", "format", "ljust", "rjust", "center", "removeprefix", "removesuffix"]);
// d.get(key, default) / d.pop(key, default): only the DEFAULT can be the result besides the receiver's own contents
const PY_DEFAULT_CARRYING_METHODS = new Set(["get", "pop", "setdefault"]);
// A local class method sharing one of these names is indistinguishable from the builtin -- not resolved by name.
const PY_BUILTIN_METHOD_NAMES = new Set([
  "get", "set", "add", "append", "extend", "update", "pop", "items", "keys", "values", "join", "split", "strip", "format",
  "replace", "read", "write", "run", "execute", "find", "search", "match", "encode", "decode", "lower", "upper",
  "startswith", "endswith", "copy", "clear", "insert", "remove", "sort", "index", "count", "close", "open",
]);
/** Parameter positions to skip when a method is called through an instance (`obj.m(x)` -> x binds after `self`/`cls`). */
function selfShift(callee: LocalFn | undefined, viaAttribute: boolean): number {
  const first = callee?.paramShapes[0]?.name;
  return viaAttribute && (first === "self" || first === "cls") ? 1 : 0;
}
const PY_MUTATING_METHODS = new Set(["append", "extend", "insert", "add", "update", "setdefault", "appendleft", "extendleft", "put"]);
const PY_GLOBAL_LOOKUPS = new Set(["globals", "locals", "vars"]);

/** Every identifier bound inside an assignment target / loop target pattern. */
function bindingIdentifiersPy(n: SyntaxNode | null): string[] {
  if (!n) return [];
  if (n.type === "identifier") return [n.text];
  if (n.type === "attribute" || n.type === "subscript") return [];
  return n.namedChildren.flatMap(c => bindingIdentifiersPy(c));
}

const localNamesCachePy = new WeakMap<SyntaxNode, Set<string>>();
/** Names local to a function (parameters and anything assigned in it), minus `global` declarations. */
function localNamesOfPy(fn: SyntaxNode): Set<string> {
  const cached = localNamesCachePy.get(fn);
  if (cached) return cached;
  const names = new Set<string>();
  const globals = new Set<string>();
  for (const p of paramNamesOf(fn)) names.add(p);
  const visit = (n: SyntaxNode) => {
    if (n.type === "function_definition" || n.type === "class_definition") {
      const nm = n.childForFieldName("name")?.text;
      if (nm) names.add(nm);
      if (n !== fn) return; // nested scope: its own locals are not ours
    }
    if (n.type === "lambda") return;
    if (n.type === "assignment" || n.type === "augmented_assignment") for (const id of bindingIdentifiersPy(n.childForFieldName("left"))) names.add(id);
    else if (n.type === "for_statement" || n.type === "for_in_clause") for (const id of bindingIdentifiersPy(n.childForFieldName("left"))) names.add(id);
    else if (n.type === "named_expression") { const nm = n.childForFieldName("name")?.text; if (nm) names.add(nm); }
    else if (n.type === "as_pattern") { const al = n.childForFieldName("alias") ?? n.namedChildren[n.namedChildren.length - 1]; for (const id of bindingIdentifiersPy(al ?? null)) names.add(id); }
    else if (n.type === "global_statement" || n.type === "nonlocal_statement") for (const c of n.namedChildren) if (c?.type === "identifier") globals.add(c.text);
    for (const c of n.namedChildren) if (c) visit(c);
  };
  visit(fn);
  for (const g of globals) names.delete(g);
  localNamesCachePy.set(fn, names);
  return names;
}

function enclosingFunctionPy(node: SyntaxNode): SyntaxNode | null {
  for (let cur: SyntaxNode | null = node.parent; cur; cur = cur.parent) if (cur.type === "function_definition") return cur;
  return null;
}

/** Is identifier `node` bound in an enclosing function scope (a parameter or local) rather than at module scope? */
function isLocalNamePy(node: SyntaxNode): boolean {
  for (let cur: SyntaxNode | null = node.parent; cur; cur = cur.parent) {
    if (cur.type === "function_definition" && localNamesOfPy(cur).has(node.text)) return true;
    if (cur.type === "lambda" && paramNamesOfLambda(cur).includes(node.text)) return true;
  }
  return false;
}

function paramNamesOfLambda(fn: SyntaxNode): string[] {
  const params = fn.childForFieldName("parameters");
  if (!params) return [];
  return params.namedChildren.map(p => (p ? paramNameOf(p) : null)).filter((n): n is string => !!n);
}

/** Is `id` a PARAMETER of an enclosing function (a callback the caller supplied)? */
function isParamOfEnclosingFnPy(id: SyntaxNode): boolean {
  for (let cur: SyntaxNode | null = id.parent; cur; cur = cur.parent) {
    if (cur.type === "function_definition" && paramNamesOf(cur).includes(id.text)) return true;
  }
  return false;
}

function rootIdentifierPy(n: SyntaxNode | null): SyntaxNode | null {
  let cur = n;
  while (cur && (cur.type === "attribute" || cur.type === "subscript" || cur.type === "parenthesized_expression" || cur.type === "call")) {
    cur = cur.type === "attribute" ? cur.childForFieldName("object")
      : cur.type === "subscript" ? cur.childForFieldName("value")
      : cur.type === "call" ? cur.childForFieldName("function")
      : cur.namedChildren[0] ?? null;
  }
  return cur?.type === "identifier" ? cur : null;
}

/** `globals()` / `locals()` / `vars()` -- a dynamic-name lookup table. */
function isGlobalsLookupPy(n: SyntaxNode | null): boolean {
  if (n?.type !== "call") return false;
  const fn = n.childForFieldName("function");
  return fn?.type === "identifier" && PY_GLOBAL_LOOKUPS.has(fn.text);
}

function makeTaintMaskPy(localFns: Map<string, LocalFn>, propagating: PropagatingPy, inDjangoRequestFn: boolean, sticky?: Map<string, number>) {
  let fnValueDepth = 0;
  const taintMask = (node: SyntaxNode, env: Env): number => {
    const orAll = (nodes: (SyntaxNode | null | undefined)[]) =>
      nodes.reduce((m: number, c) => (c ? m | taintMask(c, env) : m), 0);
    if (isTaintSourceExprPy(node, inDjangoRequestFn)) return ALL;
    if (node.type === "identifier") {
      let m = env.get(node.text) ?? 0;
      const st = sticky?.get(node.text);
      if (st && !isLocalNamePy(node)) m |= st;
      // a bare object also carries the fields written onto it (`u.host = h; u`)
      const prefix = node.text + ".";
      for (const [k, v] of env) if (v && k.startsWith(prefix)) m |= v;
      return m;
    }
    if (node.type === "attribute") {
      // Field-sensitive read: OR the composite "root.field" key with the root-object mask; the ROOT
      // identifier contributes only its own mask (not its other fields), keeping field sensitivity.
      const path = calleeTextPy(node);
      const object = attributeParts(node).object;
      const objMask = object?.type === "identifier"
        ? (env.get(object.text) ?? 0) | (sticky && !isLocalNamePy(object) ? (sticky.get(object.text) ?? 0) : 0)
        : object ? taintMask(object, env) : 0;
      return (path ? (env.get(path) ?? 0) : 0) | objMask;
    }
    if (node.type === "subscript") {
      // obj["k"] / arr[i]: an element of a tainted container is tainted; a lookup in globals() with an
      // attacker-chosen key selects an attacker-chosen member.
      const value = node.childForFieldName("value");
      const index = node.childForFieldName("subscript");
      return (value ? taintMask(value, env) : 0) | (isGlobalsLookupPy(value) && index ? taintMask(index, env) : 0);
    }
    if (node.type === "await") return node.namedChildren[0] ? taintMask(node.namedChildren[0], env) : 0;
    if (node.type === "list_splat" || node.type === "dictionary_splat" || node.type === "named_expression" ||
        node.type === "keyword_argument" || node.type === "concatenated_string") {
      return node.type === "named_expression" ? orAll([node.childForFieldName("value")])
        : node.type === "keyword_argument" ? orAll([node.childForFieldName("value")])
        : orAll(node.namedChildren);
    }
    if (node.type === "pair") return orAll([node.childForFieldName("key"), node.childForFieldName("value")]);
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
    // comprehensions / generator expressions: the element expression with each loop variable bound to its iterable
    if (node.type === "list_comprehension" || node.type === "set_comprehension" || node.type === "generator_expression" ||
        node.type === "dictionary_comprehension") {
      const cenv = cloneEnv(env);
      for (const c of node.namedChildren) {
        if (c?.type !== "for_in_clause") continue;
        const right = c.childForFieldName("right");
        const rm = right ? taintMask(right, cenv) : 0;
        for (const id of bindingIdentifiersPy(c.childForFieldName("left"))) cenv.set(id, rm);
      }
      const body = node.childForFieldName("body");
      return body ? taintMask(body, cenv) : 0;
    }
    // A function VALUE carries whatever it captured: `lambda: v` returns v when called, so
    // `delayed(x)()` and `make_renderer(v)()` resolve. Bounded so nested lambdas stay cheap.
    if (node.type === "lambda") {
      if (fnValueDepth >= 2) return 0;
      const body = node.childForFieldName("body");
      if (!body) return 0;
      const lenv = cloneEnv(env);
      for (const p of paramNamesOfLambda(node)) lenv.set(p, 0);
      fnValueDepth++;
      try { return taintMask(body, lenv); } finally { fnValueDepth--; }
    }
    if (node.type === "call") return callMask(node, env);
    if (node.type === "list" || node.type === "tuple" || node.type === "set") {
      return orAll(node.namedChildren);
    }
    if (node.type === "dictionary") {
      return node.namedChildren.reduce((m: number, c) =>
        (c?.type === "pair" ? m | taintMask(c.childForFieldName("key")!, env) | taintMask(c.childForFieldName("value")!, env)
          : c?.type === "dictionary_splat" ? m | taintMask(c, env) : m), 0);
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

  const argsMask = (args: SyntaxNode[], env: Env): number =>
    args.reduce((m, a) => (a.type === "lambda" ? m : m | taintMask(a, env)), 0);

  const callMask = (node: SyntaxNode, env: Env): number => {
    const fn = node.childForFieldName("function");
    const args = argListOf(node);
    const calleeName = fn ? calleeTextPy(fn) : null;
    if (calleeName) {
      // Known sanitizer: the argument's taint passes THROUGH minus only
      // the classes it actually neutralizes; opaque calls stay untainted.
      const clears = sanitizerClears("py", calleeName);
      if (clears !== null) return args[0] ? applyClears(taintMask(args[0], env), clears) : 0;
      // Curated passthrough builtins; a decoder re-taints what an earlier encoder cleared.
      if (PY_PASSTHROUGH.has(calleeName)) {
        const m = argsMask(args, env);
        return PY_DECODERS.has(calleeName) ? (m & ALL) | ((m >>> SHADOW) & ALL) : m;
      }
    }
    // globals().get(key) / globals()[key]: an attacker-chosen member is selected
    if (fn?.type === "attribute" && isGlobalsLookupPy(attributeParts(fn).object) && attributeParts(fn).attribute === "get" && args[0]) {
      return taintMask(args[0], env);
    }
    const attr = fn?.type === "attribute" ? attributeParts(fn) : null;
    // A call to a local function known to propagate taint from SPECIFIC
    // params to return value (see computeReturnTaintPropagatingPy below).
    // Only the arguments at the propagating indices are checked, and only
    // the classes that survive the callee's own body count. Also resolves
    // `obj.method(x)` / `self.method(x)` to a local class method by name.
    const fnName = fn?.type === "identifier" ? fn.text
      : attr?.attribute && (attr.object?.text === "self" || !PY_BUILTIN_METHOD_NAMES.has(attr.attribute)) ? attr.attribute : null;
    if (fnName) {
      const propIdx = propagating.get(fnName);
      if (propIdx) {
        const callee = localFns.get(fnName);
        const shapes = callee?.paramShapes ?? [];
        const shift = selfShift(callee, fn?.type === "attribute");
        let m = 0;
        for (const [i, surviving] of propIdx) {
          const shape = shapes[i];
          if (!shape || shape.index < shift) continue;
          for (const a of argsForShape(args, { ...shape, index: shape.index - shift })) m |= taintMask(a, env) & surviving;
        }
        if (m) return m;
      }
    }
    // Calling a value: an IIFE / `f()()` / a closure held in a variable returns what it captured;
    // calling a callback PARAMETER is (recall-biased) as tainted as what it is called with.
    if (fn && (fn.type === "call" || fn.type === "lambda" || fn.type === "parenthesized_expression")) {
      const inner = fn.type === "parenthesized_expression" ? fn.namedChildren[0] : fn;
      if (inner) return taintMask(inner, env);
    }
    if (fn?.type === "identifier" && !propagating.has(fn.text)) {
      if (isParamOfEnclosingFnPy(fn)) return argsMask(args, env);
      const held = env.get(fn.text) ?? 0;
      if (held) return held;
    }
    if (attr) {
      const recv = attr.object ? taintMask(attr.object, env) : 0;
      // "...{}...".format(x) / sep.join(items) / d.get(k, default): the result also includes the arguments
      const withArgs = attr.attribute && PY_ARG_CARRYING_METHODS.has(attr.attribute) ? argsMask(args, env)
        : attr.attribute && PY_DEFAULT_CARRYING_METHODS.has(attr.attribute) && args[1] ? taintMask(args[1], env) : 0;
      // Passthrough method call on an already-tainted receiver (.strip()/.lower()/etc).
      return recv | withArgs;
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
  /** Module-scope container memory shared across functions (main scan only). */
  sticky?: Map<string, number>;
  /** Called for every visited node with the env at that point (assignment / comparison / mutation checks). */
  onNode?: (node: SyntaxNode, env: Env, taintMask: TaintMaskFnPy) => void;
}

function createWalkerPy(h: WalkHooksPy) {
  const masks = new Map<boolean, TaintMaskFnPy>();
  const maskFor = (django: boolean): TaintMaskFnPy => {
    let m = masks.get(django);
    if (!m) { m = makeTaintMaskPy(h.localFns, h.propagating, django, h.sticky); masks.set(django, m); }
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

      case "lambda": {
        // a lambda sees captured variables; its own parameters shadow outer ones and start untainted
        if (h.descendFunctions) {
          const body = node.childForFieldName("body");
          if (body) {
            const lenv = cloneEnv(env);
            for (const p of paramNamesOfLambda(node)) lenv.set(p, 0);
            walk(body, lenv, django);
          }
        }
        return false;
      }

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
        } else if (left.type === "subscript") {
          // `d[k] = v` -- the container now holds the value (additive: a write never de-taints).
          // `obj.field[k] = v` taints the FIELD (`obj.field`), not the whole object.
          const target = left.childForFieldName("value");
          if (target?.type === "attribute") {
            const path = calleeTextPy(target);
            if (path) env.set(path, (env.get(path) ?? 0) | mask);
          } else {
            const root = rootIdentifierPy(left);
            if (root) env.set(root.text, (env.get(root.text) ?? 0) | mask);
          }
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
        else if (left.type === "subscript") {
          const root = rootIdentifierPy(left);
          if (root) env.set(root.text, (env.get(root.text) ?? 0) | mask);
        } else if (left.type === "attribute") {
          const path = calleeTextPy(left);
          if (path) env.set(path, mask | (env.get(path) ?? 0));
        }
      }
    }

    if (node.type === "call") {
      h.onCall?.(node, env, taintMask);
      // `items.append(x)` / `d.update(y)`: the receiver container now holds the arguments
      const fnNode = node.childForFieldName("function");
      if (fnNode?.type === "attribute" && PY_MUTATING_METHODS.has(attributeParts(fnNode).attribute ?? "")) {
        const root = rootIdentifierPy(attributeParts(fnNode).object);
        if (root) {
          const m = argListOf(node).reduce((acc, a) => (a.type === "lambda" ? acc : acc | taintMask(a, env)), 0);
          env.set(root.text, (env.get(root.text) ?? 0) | m);
        }
      }
    }
    h.onNode?.(node, env, taintMask);

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
  "xss": "critical", "header-injection": "high", "nosql-injection": "critical", "ldap-injection": "critical",
  "xpath-injection": "critical", "redos": "high", "eval-exec": "critical", "insecure-deserialization": "critical",
  "mass-assignment": "high", "timing-attack": "medium", "jwt-none-alg": "critical",
};
const LABEL: Record<AstTaintPyId, string> = {
  "sql-injection": "SQL Injection", "command-injection": "Command Injection",
  "ssrf": "Server-Side Request Forgery", "path-traversal": "Path Traversal",
  "ssti": "Server-Side Template Injection", "open-redirect": "Open Redirect",
  "xss": "Reflected XSS", "header-injection": "HTTP Header Injection", "nosql-injection": "NoSQL Injection",
  "ldap-injection": "LDAP Injection", "xpath-injection": "XPath Injection", "redos": "ReDoS — Regex DoS",
  "eval-exec": "Arbitrary Code Execution", "insecure-deserialization": "Insecure Deserialization",
  "mass-assignment": "Mass Assignment", "timing-attack": "Timing Attack", "jwt-none-alg": "JWT Signature Not Verified",
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

    // Module-scope container memory: taint appended/stored into a module-level list/dict by one function
    // is visible to every function that reads it back (stored XSS, second-order SQL).
    const sticky = new Map<string, number>();
    let stickyDirty = false;
    const modulePyNames = new Set<string>();
    for (const st of root.namedChildren) {
      if (st?.type !== "expression_statement") continue;
      const a = st.namedChildren[0];
      if (a?.type === "assignment") for (const id of bindingIdentifiersPy(a.childForFieldName("left"))) modulePyNames.add(id);
    }
    // `run = eval` / `fn = globals().get(name)` -- aliases of dangerous callees
    const evalAliases = new Set<string>();
    const dynDispatch = new Map<string, SyntaxNode>();
    const collectAliases = (n: SyntaxNode) => {
      if (n.type === "assignment") {
        const left = n.childForFieldName("left");
        const right = n.childForFieldName("right");
        if (left?.type === "identifier" && right) {
          if (right.type === "identifier" && (right.text === "eval" || right.text === "exec")) evalAliases.add(left.text);
          else if (right.type === "subscript" && isGlobalsLookupPy(right.childForFieldName("value"))) {
            const idx = right.childForFieldName("subscript");
            if (idx) dynDispatch.set(left.text, idx);
          } else if (right.type === "call") {
            const f = right.childForFieldName("function");
            if (f?.type === "attribute" && isGlobalsLookupPy(attributeParts(f).object) && attributeParts(f).attribute === "get") {
              const a0 = argListOf(right)[0];
              if (a0) dynDispatch.set(left.text, a0);
            }
          }
        }
      }
      for (const c of n.namedChildren) if (c) collectAliases(c);
    };
    collectAliases(root);
    // variables holding a Response object (returning one is not returning attacker HTML as a string)
    const responseObjects = new Set<string>();
    const hasResponseCtor = (n: SyntaxNode): boolean => {
      if (n.type === "call") {
        const f = n.childForFieldName("function");
        if (f && XSS_RESPONSES_PY.has(calleeTextPy(f) ?? "")) return true;
      }
      return n.namedChildren.some(c => !!c && hasResponseCtor(c));
    };
    const collectResponseObjects = (n: SyntaxNode) => {
      if (n.type === "assignment") {
        const left = n.childForFieldName("left");
        const right = n.childForFieldName("right");
        if (left?.type === "identifier" && right && hasResponseCtor(right)) responseObjects.add(left.text);
      }
      for (const c of n.namedChildren) if (c) collectResponseObjects(c);
    };
    collectResponseObjects(root);

    const STR_METHODS = new Set(["join", "format", "strip", "lstrip", "rstrip", "lower", "upper", "title", "replace", "capitalize", "decode", "removeprefix", "removesuffix", "center", "ljust", "rjust", "zfill"]);
    /** Could this returned expression be a STRING body (as opposed to a dict/list/object that Flask would serialize)? */
    const isStringyReturn = (e: SyntaxNode, depth = 0): boolean => {
      switch (e.type) {
        case "string": case "concatenated_string": case "binary_operator": return true;
        case "identifier": return depth === 0 && !responseObjects.has(e.text);
        case "attribute": case "subscript": case "await": return depth === 0;
        case "parenthesized_expression": return !!e.namedChildren[0] && isStringyReturn(e.namedChildren[0], depth);
        case "conditional_expression": return [e.namedChildren[0], e.namedChildren[2]].some(a => !!a && isStringyReturn(a, depth));
        case "boolean_operator": return [e.childForFieldName("left"), e.childForFieldName("right")].some(a => !!a && isStringyReturn(a, depth));
        case "call": {
          const f = e.childForFieldName("function");
          if (!f) return false;
          if (f.type === "attribute") return STR_METHODS.has(attributeParts(f).attribute ?? "");
          const name = f.type === "identifier" ? f.text : null;
          if (name === "str" || name === "repr") return true;
          // a local helper whose every return is string-shaped
          const callee = name ? localFns.get(name) : null;
          if (callee && depth < 2) {
            const rets: SyntaxNode[] = [];
            const find = (n: SyntaxNode) => {
              if (n.type === "function_definition" || n.type === "lambda") return;
              if (n.type === "return_statement" && n.namedChildren[0]) rets.push(n.namedChildren[0]);
              for (const c of n.namedChildren) if (c) find(c);
            };
            find(callee.body);
            return rets.length > 0 && rets.every(r => isStringyReturn(r, depth + 1));
          }
          return false;
        }
        default: return false;
      }
    };

    // the initializer an identifier was last assigned from (lets an f-string held in a variable be inspected at the sink)
    const lastAssigned = new Map<string, SyntaxNode>();
    /** An HTML-escaped value interpolated inside a <script> block is still injectable (escaping is context-blind). */
    const escapedInScriptContext = (arg: SyntaxNode, env: Env, mask: TaintMaskFnPy): boolean => {
      let node: SyntaxNode | undefined = arg;
      if (node.type === "identifier") node = lastAssigned.get(node.text);
      if (!node || node.type !== "string") return false;
      let text = "";
      for (const c of node.namedChildren) {
        if (!c) continue;
        if (c.type === "string_content") text += c.text;
        else if (c.type === "interpolation") {
          const e = c.childForFieldName("expression");
          if (e && wasCleared(mask(e, env), classOf("xss")) && /<script\b[^>]*>(?:(?!<\/script>)[\s\S])*$/i.test(text)) return true;
          text += "\u0000";
        }
      }
      return false;
    };

    const findings: AstTaintPyFinding[] = [];
    const seen = new Set<string>();
    const lineOf = (node: SyntaxNode): number => node.startPosition.row + 1;

    const emit = (id: AstTaintPyId, node: SyntaxNode, sourceExpr: string, sinkExpr: string, detailOverride?: string) => {
      const line = lineOf(node);
      const key = `${id}:${line}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({
        id, line, sinkExpr, sourceExpr,
        detail: detailOverride ?? `Tainted expression '${sourceExpr}' flows into ${sinkExpr}(...) — real data-flow match, not a line-pattern guess`,
      });
    };

    // fn name -> (tainted param index -> classes tainted at the call site)
    const seededParams = new Map<string, Map<number, number>>();

    // Sink checks and same-file call-site seeding for one `call` node, with
    // the env at that point. Statement structure, branching, assignments and
    // nested functions are the shared walker's job (createWalkerPy).
    const onCall = (node: SyntaxNode, env: Env, taintMask: TaintMaskFnPy) => {
      const fnCallee = node.childForFieldName("function");
      // a function chosen from globals() by an attacker-supplied name is then called
      if (fnCallee?.type === "identifier" && dynDispatch.has(fnCallee.text)) {
        const key = dynDispatch.get(fnCallee.text)!;
        if (taintMask(key, env) & classOf("eval-exec")) emit("eval-exec", node, sourceLabelPy(key), "dynamic globals() function call");
      }
      // attacker-controlled FORMAT STRING: "{user.__class__...}".format(...)
      if (fnCallee?.type === "attribute" && attributeParts(fnCallee).attribute === "format") {
        const recvNode = attributeParts(fnCallee).object;
        if (recvNode && taintMask(recvNode, env) & classOf("ssti")) {
          emit("ssti", node, sourceLabelPy(recvNode), "str.format",
            `Attacker-controlled format string '${sourceLabelPy(recvNode)}' is passed to str.format — replacement fields like {user.__class__.__init__.__globals__} read arbitrary attributes`);
        }
      }
      const match = matchSinkPy(node, importMap, evalAliases);
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
        else if (match.id === "xss" && match.args.some(a => escapedInScriptContext(a, env, taintMask))) {
          const a = match.args.find(x => escapedInScriptContext(x, env, taintMask))!;
          emit("xss", node, sourceLabelPy(a), match.sinkExpr,
            "HTML-escaped value is interpolated inside a <script> block — HTML escaping does not neutralize JavaScript string context (a backslash still breaks out)");
        } else if (cleared) suppressedOut?.push({ id: match.id, line: lineOf(node) });
      }
      const fnNode = node.childForFieldName("function");
      const seedAttr = fnNode?.type === "attribute" ? attributeParts(fnNode) : null;
      const seedName = fnNode?.type === "identifier" ? fnNode.text
        : seedAttr?.attribute && (seedAttr.object?.text === "self" || !PY_BUILTIN_METHOD_NAMES.has(seedAttr.attribute)) ? seedAttr.attribute : null;
      if (seedName && localFns.has(seedName)) {
        const fnName = seedName;
        const fn = localFns.get(fnName)!;
        const shift = selfShift(fn, fnNode?.type === "attribute");
        const args = argListOf(node);
        const taintedIdx = new Map<number, number>();
        args.forEach((arg, i) => {
          const m = taintMask(arg, env) & ALL;
          if (!m) return;
          const pos = i + shift;
          const shape = fn.paramShapes.find(s => s.isRest ? pos >= s.index : s.index === pos);
          if (shape) taintedIdx.set(shape.index, (taintedIdx.get(shape.index) ?? 0) | m);
        });
        if (taintedIdx.size > 0) {
          const existing = seededParams.get(fnName) ?? new Map<number, number>();
          for (const [i, m] of taintedIdx) existing.set(i, (existing.get(i) ?? 0) | m);
          seededParams.set(fnName, existing);
        }
      }
    };

    const SECRET_NAME_RE_PY = /^(?:secret|token|password|passwd|api_?key|hmac|signature|digest|csrf\w*|\w*_?secret|\w*_?token|\w*_?password|\w*_?api_?key)$/i;
    const nameOfOperandPy = (n: SyntaxNode): string | null => {
      if (n.type === "identifier") return n.text;
      if (n.type === "attribute") return attributeParts(n).attribute;
      return null;
    };
    const isRequestHandler = (fn: SyntaxNode): boolean => {
      const deco = fn.parent?.type === "decorated_definition"
        ? fn.parent.namedChildren.filter(c => c?.type === "decorator").map(c => c!.text) : [];
      if (deco.some(t => FASTAPI_DECORATOR_RE.test(t))) return false; // FastAPI serializes returns as JSON
      return deco.some(t => /^@\s*\w+(?:\.\w+)*\.route\s*\(/.test(t)) || paramNamesOf(fn).some(isRequestName);
    };
    const NON_HTML_RETURNS = new Set([
      "dictionary", "list", "tuple", "set", "list_comprehension", "dictionary_comprehension", "set_comprehension",
      "generator_expression", "integer", "float", "true", "false", "none",
    ]);
    const NON_HTML_CALLEES = new Set(["jsonify", "json.dumps", "redirect", "render_template", "send_file", "abort", "Response", "make_response", "HttpResponse", "HTMLResponse", "JsonResponse"]);

    const recordSticky = (n: SyntaxNode, env: Env, taintMask: TaintMaskFnPy) => {
      let target: SyntaxNode | null = null;
      let mask = 0;
      if (n.type === "call") {
        const f = n.childForFieldName("function");
        if (f?.type === "attribute" && PY_MUTATING_METHODS.has(attributeParts(f).attribute ?? "")) {
          target = rootIdentifierPy(attributeParts(f).object);
          mask = argListOf(n).reduce((m, a) => (a.type === "lambda" ? m : m | taintMask(a, env)), 0);
        }
      } else if (n.type === "assignment" || n.type === "augmented_assignment") {
        const left = n.childForFieldName("left");
        const right = n.childForFieldName("right");
        if (left && right && (left.type === "subscript" || left.type === "attribute" || left.type === "identifier")) {
          target = rootIdentifierPy(left);
          mask = taintMask(right, env);
        }
      }
      if (!target || !(mask & ALL) || !modulePyNames.has(target.text) || isLocalNamePy(target)) return;
      if (!enclosingFunctionPy(n)) return; // only writes made INSIDE a function are cross-request state
      const next = (sticky.get(target.text) ?? 0) | (mask & ALL);
      if (next !== (sticky.get(target.text) ?? 0)) { sticky.set(target.text, next); stickyDirty = true; }
    };

    const onNode = (n: SyntaxNode, env: Env, taintMask: TaintMaskFnPy) => {
      if (n.type === "assignment") {
        const left = n.childForFieldName("left");
        const right = n.childForFieldName("right");
        if (left?.type === "subscript" && right) {
          const target = left.childForFieldName("value");
          const targetText = target ? calleeTextPy(target) : null;
          // response.headers["X"] = tainted
          if (targetText && (targetText === "headers" || targetText.endsWith(".headers"))) {
            const m = taintMask(right, env);
            if (m & classOf("header-injection")) emit("header-injection", n, sourceLabelPy(right), "response.headers[...]");
            else if (wasCleared(m, classOf("header-injection"))) suppressedOut?.push({ id: "header-injection", line: lineOf(n) });
          }
          // for k, v in tainted.items(): target[k] = v  -- the request decides which keys the object gets
          const idx = left.childForFieldName("subscript");
          if (idx?.type === "identifier" && right.type === "identifier") {
            for (let cur: SyntaxNode | null = n.parent; cur && cur.type !== "function_definition"; cur = cur.parent) {
              if (cur.type !== "for_statement") continue;
              const names = bindingIdentifiersPy(cur.childForFieldName("left"));
              const iter = cur.childForFieldName("right");
              if (names.includes(idx.text) && names.includes(right.text) && iter?.type === "call" &&
                  attributeParts(iter.childForFieldName("function") ?? iter).attribute === "items" &&
                  (taintMask(idx, env) & ALL) && (taintMask(right, env) & ALL)) {
                emit("mass-assignment", n, sourceLabelPy(iter), "dict merge",
                  `Attacker-controlled dictionary '${sourceLabelPy(iter)}' is copied key-by-key onto '${target ? sourceLabelPy(target) : "target"}' — the client decides which keys (role, is_admin, ...) get set; copy an explicit allowlist`);
                break;
              }
            }
          }
        }
      }
      if (n.type === "comparison_operator") {
        const [l, r] = n.namedChildren;
        const opText = l && r ? n.text.slice(l.endIndex - n.startIndex, r.startIndex - n.startIndex).trim() : "";
        if (l && r && (opText === "==" || opText === "!=")) {
          for (const [secretSide, other] of [[l, r], [r, l]] as const) {
            const name = nameOfOperandPy(secretSide);
            if (!name || !SECRET_NAME_RE_PY.test(name) || isLiteralPy(other)) continue;
            if (taintMask(other, env) & ALL) {
              emit("timing-attack", n, sourceLabelPy(other), "==",
                `Secret '${sourceLabelPy(secretSide)}' is compared to attacker-supplied '${sourceLabelPy(other)}' with an ordinary equality operator — use hmac.compare_digest`);
              break;
            }
          }
        }
      }
      if (n.type === "assignment") {
        const l = n.childForFieldName("left");
        const r = n.childForFieldName("right");
        if (l?.type === "identifier" && r) lastAssigned.set(l.text, r);
      }
      if (n.type === "call" || n.type === "assignment" || n.type === "augmented_assignment") recordSticky(n, env, taintMask);
    };

    // A request handler's returned string IS the HTML response body (Flask): tainted -> reflected XSS
    const onReturn = (expr: SyntaxNode, env: Env, taintMask: TaintMaskFnPy) => {
      const fn = enclosingFunctionPy(expr);
      if (!fn || !isRequestHandler(fn) || NON_HTML_RETURNS.has(expr.type) || !isStringyReturn(expr)) return;
      if (expr.type === "call") {
        const callee = expr.childForFieldName("function");
        if (callee && NON_HTML_CALLEES.has(calleeTextPy(callee) ?? "")) return;
      }
      const m = taintMask(expr, env);
      if (m & classOf("xss")) emit("xss", expr, sourceLabelPy(expr), "handler return value");
    };

    const walker = createWalkerPy({ localFns, propagating, root, descendFunctions: true, onCall, onNode, onReturn, sticky });
    const walk = (node: SyntaxNode, env: Env, django: boolean) => walker.walk(node, env, django);

    walk(root, new Map(), false);
    // A container written by a function declared AFTER the one that reads it: walk again with what the
    // first pass learned (findings dedupe by id+line).
    for (let i = 0; i < 2 && stickyDirty; i++) {
      stickyDirty = false;
      walk(root, new Map(), false);
    }

    // A hand-rolled JWT payload decode in a file that never verifies a signature
    if (!/\bimport jwt\b|\bfrom jwt\b|jwt\.decode|\bfrom jose\b|\bimport jose\b|authlib|itsdangerous/.test(content)) {
      const fns: SyntaxNode[] = [];
      const findFns = (n: SyntaxNode) => { if (n.type === "function_definition") fns.push(n); for (const c of n.namedChildren) if (c) findFns(c); };
      findFns(root);
      for (const fn of fns) {
        const t = fn.text;
        if (/\.split\(\s*["']\.["']\s*\)/.test(t) && /b64decode/.test(t) && /json\.loads|\bloads\(/.test(t)) {
          emit("jwt-none-alg", fn.childForFieldName("name") ?? fn, "token", "manual JWT decode",
            "JWT payload is base64-decoded and JSON-parsed by hand and the file never verifies a signature — claims (role, sub, ...) are attacker-controlled; use jwt.decode(..., algorithms=[...]) with a key");
        }
      }
    }

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
