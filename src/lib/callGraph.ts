/**
 * TrustLedger Call Graph Engine
 *
 * Builds a function-level call graph from source text using regex-based parsing,
 * then performs interprocedural taint tracking and SSA-lite data-flow analysis.
 * No external parser required — runs entirely in the V8 runtime.
 *
 * Stages:
 *   1. Function extraction  — identify all function definitions and their source spans
 *   2. Call site extraction — find all call expressions within each function body
 *   3. Graph construction   — adjacency list: caller → callees
 *   4. Entry point detection — exported / route-handler / event-listener functions
 *   5. Reachability BFS     — which functions are reachable from entry points?
 *   6. Taint propagation    — if a tainted variable flows into a call arg, the callee receives taint
 *   7. SSA-lite assignments — track the latest definition of each name per function
 *   8. Data-flow summary    — which external inputs reach which sinks?
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export interface FunctionNode {
  name:       string;
  start_line: number;
  end_line:   number;
  params:     string[];
  is_exported: boolean;
  is_async:    boolean;
  body:        string;
}

export interface CallEdge {
  caller:     string;   // function name
  callee:     string;   // function name (may be unresolved external)
  line:       number;
  args:       string[];  // argument expressions at call site
  is_tainted: boolean;   // true if any arg was tainted at call time
}

export interface TaintFact {
  variable: string;
  source:   "user-input" | "env" | "network" | "file" | "database" | "arg";
  function: string;  // function where taint originated
  line:     number;
}

export interface DataFlowPath {
  source:    TaintFact;
  sink_name: string;
  sink_line: number;
  path:      string[];  // function call chain from source to sink
}

export interface SSADef {
  name:     string;
  version:  number;
  line:     number;
  rhs:      string;  // right-hand side expression (abbreviated)
  tainted:  boolean;
}

export interface CallGraphResult {
  functions:       FunctionNode[];
  edges:           CallEdge[];
  entry_points:    string[];
  reachable:       Set<string>;
  taint_facts:     TaintFact[];
  taint_paths:     DataFlowPath[];
  ssa_defs:        Map<string, SSADef[]>;  // function name → defs
  max_call_depth:  number;
}

// ── Function extraction ───────────────────────────────────────────────────────
// Each pattern returns [fullMatch, exported?, async?, name, params]
// Positional groups: (1)=export (2)=async (3)=name (4)=params

interface FuncMatch { name: string; params: string; isExported: boolean; isAsync: boolean }

function tryMatchFunc(line: string): FuncMatch | null {
  let m: RegExpMatchArray | null;
  // function foo(a, b) {  /  export async function foo(a, b) {
  m = line.match(/^(export\s+)?(async\s+)?function\s+(\w+)\s*\(([^)]*)\)/);
  if (m) return { isExported: !!m[1], isAsync: !!m[2], name: m[3], params: m[4] };
  // const foo = (a, b) => {  /  export const foo = async (a, b) => {
  m = line.match(/^(export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(async\s+)?\(?([^)=>{]*?)\)?\s*=>/);
  if (m) return { isExported: !!m[1], isAsync: !!m[3], name: m[2], params: m[4] };
  // const foo = function(a, b) {
  m = line.match(/^(export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(async\s+)?function\s*\(([^)]*)\)/);
  if (m) return { isExported: !!m[1], isAsync: !!m[3], name: m[2], params: m[4] };
  // class method:   async foo(a, b) {
  m = line.match(/^\s+(async\s+)?(\w+)\s*\(([^)]*)\)\s*\{/);
  if (m && m[2] !== "if" && m[2] !== "for" && m[2] !== "while" && m[2] !== "switch")
    return { isExported: false, isAsync: !!m[1], name: m[2], params: m[3] };
  // def foo(a, b):  (Python) -- leading whitespace allowed (unlike the JS
  // patterns above) since Python class methods are ALWAYS indented under
  // their class; a bare `^` anchor here would silently never match any
  // class method, module-level functions being the only Python shape ever
  // recognized. Confirmed as a real, separate gap from extractFunctions'
  // own indent-mode fix (Decision 1) -- this widens WHICH lines are
  // recognized as a def at all; extractFunctions' indent mode is what
  // correctly closes the body once one is.
  m = line.match(/^\s*(async\s+)?def\s+(\w+)\s*\(([^)]*)\)/);
  if (m) return { isExported: false, isAsync: !!m[1], name: m[2], params: m[3] };
  // public ResponseEntity<X> getUser(String id) {  (Java) -- anchored on an
  // explicit public/private/protected modifier (constructors and
  // package-private methods with no modifier are a documented, accepted
  // miss) since a return type is an arbitrary generic token sequence with
  // no reliable way to distinguish it from a control-flow keyword
  // otherwise -- the same "explicit anchor" precedent the JS class-method
  // pattern above uses its if/for/while/switch exclusion list for, just
  // via a positive anchor instead of a negative one. Once this recognizes
  // the signature line, the existing brace-depth body-consuming loop below
  // needs no Java-specific changes at all -- Java is brace-delimited
  // exactly like JS/Go.
  m = line.match(/^\s*(?:@\w+(?:\([^)]*\))?\s+)*(public|private|protected)\s+(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?(?:abstract\s+)?[\w<>[\],.\s]+?\s+(\w+)\s*\(([^)]*)\)/);
  if (m) return { isExported: m[1] === "public", isAsync: false, name: m[2], params: m[3] };
  // public async Task<IActionResult> DeleteUser(string id) {  (C#) -- same
  // "explicit access-modifier anchor" precedent as Java's pattern above,
  // adapted for C#'s [Attribute] bracket syntax instead of @Annotation and
  // its own modifier vocabulary. Unlike Java, C# idiom always puts the
  // access modifier first (an access modifier after static/etc isn't valid
  // C#), so a fixed modifier order after the anchor is sufficient, not an
  // arbitrary-order match.
  m = line.match(/^\s*(?:\[\w+(?:\([^)]*\))?\]\s*)*(public|private|protected|internal)\s+(?:static\s+)?(?:async\s+)?(?:override\s+)?(?:virtual\s+)?(?:sealed\s+)?(?:abstract\s+)?(?:new\s+)?[\w<>[\],.\s]+?\s+(\w+)\s*\(([^)]*)\)/);
  if (m) return { isExported: m[1] === "public", isAsync: /\basync\b/.test(line), name: m[2], params: m[3] };
  // func foo(a int) {  (Go)
  m = line.match(/^func\s+(\w+)\s*\(([^)]*)\)/);
  if (m) return { isExported: /^[A-Z]/.test(m[1]), isAsync: false, name: m[1], params: m[2] };
  // function foo($a, $b) {  /  public static function foo($a, $b) {  (PHP)
  // -- unlike C#'s fixed modifier order, PHP idiom allows `public static`
  // OR `static public` (both legal), so this matches any order/repetition
  // of the modifier keywords rather than anchoring on a single first one.
  // No explicit visibility modifier at all means implicitly public for a
  // class method, and a top-level (non-class) function is always globally
  // callable -- both cases correctly resolve isExported=true here since
  // the check is "no private/protected present", not "public present".
  m = line.match(/^\s*((?:(?:public|private|protected|static|final|abstract)\s+)*)function\s+(\w+)\s*\(([^)]*)\)/);
  if (m) {
    const modifiers = m[1];
    const isExported = !/\b(?:private|protected)\b/.test(modifiers);
    return { isExported, isAsync: false, name: m[2], params: m[3] };
  }
  return null;
}

function parseParams(raw: string): string[] {
  // The trailing .replace(/^\$/, "") strips PHP's `$` parameter sigil --
  // purely additive for every other language (no other language's param
  // names start with a literal `$`), so this is safe to apply universally
  // rather than needing a PHP-specific branch here.
  return raw.split(",").map(p => p.trim().split(/[\s:=]/)[0].replace(/^\.\.\./, "").replace(/^\$/, "")).filter(Boolean);
}

const PY_DEF_RE = /^\s*(?:async\s+)?def\s+\w+\s*\(/;

function indentOf(line: string): number {
  return line.length - line.trimStart().length;
}

interface Pending extends FunctionNode { mode: "brace" | "indent"; baseIndent: number }

/**
 * Python has no braces at all, so the ORIGINAL brace-depth closing rule
 * (`depth <= 0` closes the function) never left 0 for a `def` match --
 * the function closed on the SAME line it opened, before any body was
 * consumed, and was silently dropped by the `end_line > start_line` guard
 * below. A prior comment here claimed "Python handled by indent heuristic
 * below" -- confirmed by direct reading to be dead/aspirational, no such
 * heuristic existed. Net effect: graph.entry_points/graph.reachable were
 * effectively always empty for Python, so every Python finding fell
 * through to "unreachable" regardless of the real, correctly-resolved
 * enclosing function name from resolveContainingFunction's tree-sitter
 * branch (scanner.ts) -- the same visible bug as Java's missing resolver,
 * from a completely different root cause.
 *
 * Fixed by giving each pending function an explicit mode, decided at match
 * time: "indent" for a `def` line, "brace" (the original, unchanged logic)
 * for everything else. Indent mode's body continues while a non-blank
 * line's indentation stays strictly greater than the `def` line's own
 * indentation; the moment a non-blank line dedents to <= that baseline,
 * the function closes and that line is REPROCESSED (not consumed) as a
 * potential new function start -- standard, well-established line-based
 * Python function-boundary heuristic. Doesn't handle a multi-line string
 * literal containing a dedented-looking line -- an accepted, documented
 * imprecision, the same "no external parser" posture this whole file's
 * docblock commits to, and the same kind of accepted gap
 * iacTerraform.ts's brace-depth block extractor documents for braces
 * inside string literals/comments.
 */
export function extractFunctions(content: string): FunctionNode[] {
  const lines = content.split("\n");
  const funcs: FunctionNode[] = [];
  let current: Pending | null = null;
  let depth = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (!current) {
      const fm = tryMatchFunc(line);
      if (fm) {
        current = {
          name:        fm.name,
          start_line:  i + 1,
          end_line:    i + 1,
          params:      parseParams(fm.params ?? ""),
          is_exported: fm.isExported,
          is_async:    fm.isAsync,
          body:        "",
          mode:        PY_DEF_RE.test(line) ? "indent" : "brace",
          baseIndent:  indentOf(line),
        };
        depth = 0;
      }
    }

    if (!current) continue;

    if (current.mode === "indent") {
      // The `def` line itself is always consumed regardless of its own
      // indentation (it IS the baseline) -- only lines AFTER it are
      // subject to the dedent check below.
      const isSignatureLine = current.body === "";
      const trimmed = line.trim();
      if (isSignatureLine || trimmed === "" || indentOf(line) > current.baseIndent) {
        current.body += line + "\n";
        // Blank lines are consumed (so trailing blanks between two
        // functions don't break the dedent scan) but don't advance
        // end_line -- otherwise a function immediately followed by a
        // blank line (or, for the file's last function, the trailing ""
        // element content.split("\n") always produces for a
        // newline-terminated file) would report an end_line one past its
        // real last line of code.
        if (isSignatureLine || trimmed !== "") current.end_line = i + 1;
        continue;
      }
      // Dedented back to <= baseIndent: the function ends BEFORE this
      // line. Reprocess it (i--) since it may itself be the next def.
      if (current.end_line > current.start_line) funcs.push({ ...current });
      current = null;
      i--;
      continue;
    }

    // Brace mode -- original, unchanged logic (JS/TS/Go/Java). Runs in the
    // SAME iteration a function is matched (not deferred to the next loop
    // pass), so a true single-line function (`function foo() {}`) closes
    // and is correctly excluded (end_line === start_line, per the guard
    // below) without bleeding the following line into its body.
    current.body += line + "\n";
    for (const ch of line) {
      if (ch === "{") depth++;
      if (ch === "}") depth--;
    }
    if (depth <= 0 && current.body.trim().length > 0 && current.body.includes("\n")) {
      current.end_line = i + 1;
      // Only register if body has at least 2 lines (avoid false single-line matches)
      if (current.end_line > current.start_line) {
        funcs.push({ ...current });
      }
      current = null;
      depth   = 0;
    }
  }

  // Flush a trailing indent-mode function still open at EOF (brace mode
  // never leaves an unclosed `current` dangling in well-formed source --
  // an unclosed brace is itself a real syntax error, not a boundary case
  // worth silently completing).
  if (current && current.mode === "indent" && current.end_line > current.start_line) {
    funcs.push({ ...current });
  }

  return funcs;
}

// ── Call site extraction ──────────────────────────────────────────────────────

const CALL_RE = /\b(\w[\w.]*)\s*\(([^)]*)\)/g;

export function extractCallSites(
  fn: FunctionNode,
  taintedVars: Set<string>,
): CallEdge[] {
  const edges: CallEdge[] = [];
  const bodyLines = fn.body.split("\n");
  const BUILTINS  = new Set([
    "console","Math","JSON","Object","Array","String","Number","Boolean","Promise",
    "parseInt","parseFloat","isNaN","isFinite","encodeURIComponent","decodeURIComponent",
    "setTimeout","setInterval","clearTimeout","clearInterval","require","import",
    "if","while","for","switch","return","throw","new","typeof","instanceof",
  ]);

  for (let li = 0; li < bodyLines.length; li++) {
    const line = bodyLines[li];
    let m: RegExpExecArray | null;
    const re = new RegExp(CALL_RE.source, "g");
    while ((m = re.exec(line)) !== null) {
      const callee = m[1].split(".").pop() ?? m[1];
      if (BUILTINS.has(callee) || callee.length <= 1) continue;
      const args = m[2].split(",").map(a => a.trim()).filter(Boolean);
      const is_tainted = args.some(a => taintedVars.has(a.replace(/[^a-zA-Z0-9_]/g, "")));
      edges.push({
        caller: fn.name, callee,
        line:   fn.start_line + li,
        args,   is_tainted,
      });
    }
  }
  return edges;
}

// ── Entry point detection ─────────────────────────────────────────────────────

const ENTRY_PATTERNS: RegExp[] = [
  /export\s+(?:default\s+)?(?:async\s+)?function/,
  /export\s+(?:const|let)\s+\w+\s*=\s*(?:async\s+)?\(?/,
  /app\.(?:get|post|put|delete|patch|use|all)\s*\(/,
  /router\.(?:get|post|put|delete|patch|use|all)\s*\(/,
  /addEventListener\s*\(/,
  /exports\.\w+\s*=/,
  /module\.exports\s*=/,
  /handler\s*=\s*(?:async\s+)?function/,
];

// Java: @GetMapping/@PostMapping/etc sit on a line ABOVE the method
// signature, not inside fn.body's first line (which IS the signature line
// itself) -- ENTRY_PATTERNS' "check fn.body.split('\n')[0]" approach
// structurally can't see them, so a genuinely new lookup against the raw
// source lines preceding start_line is needed (hasEntryMarkerAbove below).
// Same vocabulary astTaintJava.ts's MAPPING_ANNOTATIONS already uses for
// the same purpose (there, seeding BOLA taint sources; here, entry-point
// classification).
const JAVA_ENTRY_ANNOTATION_RE = /^\s*@(?:Get|Post|Put|Patch|Delete|Request)Mapping\b/;
// Python: Flask/FastAPI route decorators -- same structural "line above
// the def" placement. Mirrors astTaintPython.ts's FASTAPI_DECORATOR_RE
// vocabulary plus Flask's @app.route(...).
const PY_ENTRY_DECORATOR_RE = /^\s*@(?:\w+\.)?(?:app|router)\.(?:route|get|post|put|delete|patch|options|head)\s*\(/;
// C#: ASP.NET Core route attributes -- same "line above the signature"
// placement (confirmed directly via tree-sitter probing), matching
// astTaintCSharp.ts's own HTTP_VERB_ATTRIBUTES/isEndpoint vocabulary.
const CSHARP_ENTRY_ANNOTATION_RE = /^\s*\[(?:Http(?:Get|Post|Put|Delete|Patch)|Route)\b/;

/** Checks the few raw source lines immediately above a matched function's
 * start_line for a Java annotation, Python decorator, or C# attribute
 * marking it an HTTP entry point. */
function hasEntryMarkerAbove(content: string, startLine: number): boolean {
  const lines = content.split("\n");
  const windowStart = Math.max(0, startLine - 1 - 5);
  for (let i = windowStart; i < startLine - 1; i++) {
    if (JAVA_ENTRY_ANNOTATION_RE.test(lines[i]) || PY_ENTRY_DECORATOR_RE.test(lines[i]) || CSHARP_ENTRY_ANNOTATION_RE.test(lines[i])) return true;
  }
  return false;
}

export function detectEntryPoints(funcs: FunctionNode[], content: string): string[] {
  const entries = new Set<string>();
  for (const fn of funcs) {
    if (fn.is_exported) { entries.add(fn.name); continue; }
    for (const re of ENTRY_PATTERNS) {
      if (re.test(fn.body.split("\n")[0])) { entries.add(fn.name); break; }
    }
    if (hasEntryMarkerAbove(content, fn.start_line)) entries.add(fn.name);
    // Main / top-level handler names
    if (/^(?:main|handler|index|server|app|init|start|bootstrap|run)$/i.test(fn.name)) {
      entries.add(fn.name);
    }
  }
  // Also check global scope for exported assignments referencing known function names
  const funcNames = new Set(funcs.map(f => f.name));
  const globalExportRe = /exports\.(\w+)\s*=\s*(\w+)/g;
  let gm: RegExpExecArray | null;
  while ((gm = globalExportRe.exec(content)) !== null) {
    if (funcNames.has(gm[2])) entries.add(gm[2]);
  }
  // Go: no decorator/annotation syntax exists -- an HTTP handler is
  // identified by NAME at a separate route-registration call site
  // elsewhere in the file (Gin/Echo/chi/net-http-mux idioms), not by
  // anything on or above its own signature. Mirrors globalExportRe's own
  // "scan the whole file for a registration site referencing a known
  // function name" shape immediately above, just for a different
  // framework family. A fresh regex literal per call (not a shared
  // module-level /g one) -- same reason globalExportRe is declared here
  // and not at module scope: a global-flagged regex carries lastIndex
  // state across .exec() calls, which would go stale across repeated
  // detectEntryPoints() calls on different files if shared.
  const goRouteRe = /\b(?:router|r|e|app|mux)\.(?:GET|POST|PUT|DELETE|PATCH|Handle(?:Func)?)\s*\(\s*(?:"[^"]*"|`[^`]*`)\s*,\s*(\w+)/g;
  let rm: RegExpExecArray | null;
  while ((rm = goRouteRe.exec(content)) !== null) {
    if (funcNames.has(rm[1])) entries.add(rm[1]);
  }
  // PHP: same registration-site shape as Go above, not Java/Python/C#'s
  // marker-above-signature convention -- confirmed directly that Laravel
  // registers routes centrally (Route::get('/x', [Controller::class,
  // 'method']) or the older 'Controller@method' string form) and
  // WordPress registers hooks the same way (add_action('init',
  // 'my_handler')), neither as a decorator on the handler itself. Handles
  // both the array-callable and "Class@method"/bare-string callable
  // shapes; capture group 1 is the string form, group 2 the array form.
  const phpRouteRe = /\b(?:Route::(?:get|post|put|delete|patch|any|match)|add_action|add_filter)\s*\(\s*['"][^'"]*['"]\s*,\s*(?:['"](?:[\w\\]+@)?(\w+)['"]|\[\s*(?:[\w\\]+::class|\$\w+|['"][\w\\]+['"])\s*,\s*['"](\w+)['"]\s*\])/g;
  let pm: RegExpExecArray | null;
  while ((pm = phpRouteRe.exec(content)) !== null) {
    const name = pm[1] ?? pm[2];
    if (name && funcNames.has(name)) entries.add(name);
  }
  return Array.from(entries);
}

// ── BFS reachability ──────────────────────────────────────────────────────────

export function computeReachability(
  entries: string[],
  edges:   CallEdge[],
): Set<string> {
  const adj = new Map<string, Set<string>>();
  for (const e of edges) {
    if (!adj.has(e.caller)) adj.set(e.caller, new Set());
    adj.get(e.caller)!.add(e.callee);
  }
  const visited = new Set<string>(entries);
  const queue   = [...entries];
  while (queue.length > 0) {
    const fn = queue.shift()!;
    for (const callee of Array.from(adj.get(fn) ?? [])) {
      if (!visited.has(callee)) {
        visited.add(callee);
        queue.push(callee);
      }
    }
  }
  return visited;
}

// ── Taint source detection ────────────────────────────────────────────────────

const TAINT_SOURCES: Array<{ re: RegExp; source: TaintFact["source"] }> = [
  { re: /req\.(?:body|params|query|headers|cookies|files)\b/,             source: "user-input" },
  { re: /request\.(?:body|params|query|headers|cookies)\b/,               source: "user-input" },
  { re: /process\.env\.\w+/,                                               source: "env" },
  { re: /(?:fetch|axios|http|https|got|request)\s*\(/,                     source: "network" },
  { re: /fs\.(?:readFile|readFileSync|createReadStream)\s*\(/,             source: "file" },
  { re: /(?:db|pool|client|connection)\.(?:query|execute|find|findOne)\s*\(/, source: "database" },
  { re: /JSON\.parse\s*\(/,                                                source: "user-input" },
  { re: /decodeURIComponent\s*\(/,                                         source: "user-input" },
  { re: /document\.(?:getElementById|querySelector|cookie|location)/,     source: "user-input" },
  { re: /window\.location\.(?:search|hash|href|pathname)/,                source: "user-input" },
  { re: /event\.(?:data|target\.value|detail)/,                           source: "user-input" },
];

function extractTaintedVarsFromLine(line: string, lineNo: number, fnName: string): TaintFact[] {
  const facts: TaintFact[] = [];
  for (const { re, source } of TAINT_SOURCES) {
    if (!re.test(line)) continue;
    // Find assigned variable: const x = req.body  →  x
    const assignMatch = line.match(/(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=/);
    if (assignMatch) {
      const vars = assignMatch[1]
        ? assignMatch[1].split(",").map(v => v.trim().split(":")[0].trim())
        : [assignMatch[2]];
      for (const v of vars.filter(Boolean)) {
        facts.push({ variable: v, source, function: fnName, line: lineNo });
      }
    } else {
      // No assignment — mark a synthetic "inline" taint
      facts.push({ variable: "__inline__", source, function: fnName, line: lineNo });
    }
  }
  return facts;
}

// ── SSA-lite definition tracking ──────────────────────────────────────────────

const ASSIGN_RE = /(?:const|let|var)\s+(\w+)\s*=\s*(.{0,80})/;
const MUTATE_RE = /(\w+)\s*(?:\+=|-=|\*=|\/=|=)\s*(.{0,80})/;

function buildSSA(fn: FunctionNode): SSADef[] {
  const defs: SSADef[] = [];
  const versions: Record<string, number> = {};
  const taintedNames = new Set<string>();

  for (const { re, source: _ } of TAINT_SOURCES) {
    // Pre-scan to identify tainted variables
    const matches = fn.body.match(re);
    if (!matches) continue;
    const assignM = fn.body.match(/(?:const|let|var)\s+(\w+)\s*=.*?(?:req\.|request\.|JSON\.parse|process\.env)/);
    if (assignM) taintedNames.add(assignM[1]);
  }

  fn.body.split("\n").forEach((line, idx) => {
    const lineNo  = fn.start_line + idx;
    const am = line.match(ASSIGN_RE) ?? line.match(MUTATE_RE);
    if (am) {
      const name = am[1];
      versions[name] = (versions[name] ?? 0) + 1;
      defs.push({
        name,
        version: versions[name],
        line:    lineNo,
        rhs:     am[2].trim().slice(0, 60),
        tainted: taintedNames.has(name) || TAINT_SOURCES.some(s => s.re.test(am[2])),
      });
    }
  });
  return defs;
}

// ── Interprocedural taint propagation ─────────────────────────────────────────

const DATA_FLOW_SINKS: Array<{ re: RegExp; name: string }> = [
  { re: /(?:db|pool|client)\.(?:query|execute)\s*\(/,                  name: "sql-sink" },
  { re: /res\.(?:send|json|write|end)\s*\(/,                           name: "http-response-sink" },
  { re: /eval\s*\(/,                                                   name: "eval-sink" },
  { re: /exec(?:Sync)?\s*\(/,                                          name: "exec-sink" },
  { re: /innerHTML\s*=/,                                               name: "dom-sink" },
  { re: /document\.write\s*\(/,                                        name: "dom-sink" },
  { re: /fs\.(?:writeFile|appendFile|createWriteStream)\s*\(/,        name: "file-write-sink" },
  { re: /(?:fetch|axios\.(?:get|post|put))\s*\(/,                     name: "network-sink" },
  { re: /logger\.(?:info|warn|error|debug|log)\s*\(/,                 name: "log-sink" },
  { re: /require\s*\(\s*(?:\w+|`[^`]*`)/,                             name: "dynamic-require-sink" },
];

function propagateTaint(
  funcs:    FunctionNode[],
  edges:    CallEdge[],
  entries:  string[],
): { facts: TaintFact[]; paths: DataFlowPath[] } {
  const funcMap = new Map(funcs.map(f => [f.name, f]));
  const allFacts: TaintFact[] = [];
  const paths: DataFlowPath[] = [];

  // Seed taint from entry-point functions
  for (const ep of entries) {
    const fn = funcMap.get(ep);
    if (!fn) continue;
    fn.body.split("\n").forEach((line, idx) => {
      const lineNo = fn.start_line + idx;
      allFacts.push(...extractTaintedVarsFromLine(line, lineNo, fn.name));
    });
  }

  // BFS over call edges propagating taint
  const taintedFunctions = new Set<string>(entries);
  const queue = [...entries];
  while (queue.length > 0) {
    const callerName = queue.shift()!;
    const callerFacts = allFacts.filter(f => f.function === callerName);
    const taintedVars = new Set(callerFacts.map(f => f.variable));

    const outEdges = edges.filter(e => e.caller === callerName && e.is_tainted);
    for (const edge of outEdges) {
      const callee = funcMap.get(edge.callee);
      if (!callee) continue;
      // Mark callee params as tainted
      edge.args.forEach((arg, idx) => {
        if (taintedVars.has(arg) && callee.params[idx]) {
          allFacts.push({
            variable: callee.params[idx],
            source:   "arg",
            function: callee.name,
            line:     callee.start_line,
          });
        }
      });
      if (!taintedFunctions.has(callee.name)) {
        taintedFunctions.add(callee.name);
        queue.push(callee.name);
      }
    }

    // Check for sinks in this function
    const fn = funcMap.get(callerName);
    if (!fn) continue;
    fn.body.split("\n").forEach((line, idx) => {
      const lineNo = fn.start_line + idx;
      for (const { re, name } of DATA_FLOW_SINKS) {
        if (!re.test(line)) continue;
        for (const fact of callerFacts) {
          if (line.includes(fact.variable) || fact.variable === "__inline__") {
            paths.push({
              source:    fact,
              sink_name: name,
              sink_line: lineNo,
              path:      [...queue, callerName],
            });
          }
        }
      }
    });
  }

  return { facts: allFacts, paths };
}

// ── Max call depth ─────────────────────────────────────────────────────────────

function computeMaxDepth(entries: string[], edges: CallEdge[]): number {
  const adj = new Map<string, string[]>();
  for (const e of edges) {
    if (!adj.has(e.caller)) adj.set(e.caller, []);
    adj.get(e.caller)!.push(e.callee);
  }
  let max = 0;
  function dfs(fn: string, depth: number, visited: Set<string>) {
    if (depth > max) max = depth;
    if (visited.has(fn) || depth > 20) return;
    visited.add(fn);
    for (const callee of adj.get(fn) ?? []) dfs(callee, depth + 1, new Set(visited));
  }
  for (const ep of entries) dfs(ep, 0, new Set());
  return max;
}

// ── Main entry point ──────────────────────────────────────────────────────────

export function buildCallGraph(content: string): CallGraphResult {
  const funcs   = extractFunctions(content);
  const allEdges: CallEdge[] = [];
  const ssaMap  = new Map<string, SSADef[]>();

  for (const fn of funcs) {
    const taintedVars = new Set<string>();
    // Seed taint for this function's params if they appear in taint sources
    TAINT_SOURCES.forEach(({ re }) => {
      if (re.test(fn.body)) fn.params.forEach(p => taintedVars.add(p));
    });
    allEdges.push(...extractCallSites(fn, taintedVars));
    ssaMap.set(fn.name, buildSSA(fn));
  }

  const entries  = detectEntryPoints(funcs, content);
  const reachable = computeReachability(entries, allEdges);
  const { facts: taint_facts, paths: taint_paths } = propagateTaint(funcs, allEdges, entries);
  const max_call_depth = computeMaxDepth(entries, allEdges);

  return { functions: funcs, edges: allEdges, entry_points: entries,
           reachable, taint_facts, taint_paths, ssa_defs: ssaMap, max_call_depth };
}
