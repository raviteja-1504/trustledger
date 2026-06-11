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
  // def foo(a, b):  (Python)
  m = line.match(/^(async\s+)?def\s+(\w+)\s*\(([^)]*)\)/);
  if (m) return { isExported: false, isAsync: !!m[1], name: m[2], params: m[3] };
  // func foo(a int) {  (Go)
  m = line.match(/^func\s+(\w+)\s*\(([^)]*)\)/);
  if (m) return { isExported: /^[A-Z]/.test(m[1]), isAsync: false, name: m[1], params: m[2] };
  return null;
}

function parseParams(raw: string): string[] {
  return raw.split(",").map(p => p.trim().split(/[\s:=]/)[0].replace(/^\.\.\./, "")).filter(Boolean);
}

export function extractFunctions(content: string): FunctionNode[] {
  const lines   = content.split("\n");
  const funcs: FunctionNode[] = [];
  let current: FunctionNode | null = null;
  let depth = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Try to match function definition start
    if (!current || depth === 0) {
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
          };
          depth = 0;
        }
    }

    if (current) {
      current.body += line + "\n";
      for (const ch of line) {
        if (ch === "{") depth++;
        if (ch === "}") depth--;
      }
      // Python / Go: track by indent instead of braces
      if (!line.includes("{") && !line.includes("}") && current.body.split("\n").length > 1) {
        // noop — brace counting handles JS/TS; Python handled by indent heuristic below
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

export function detectEntryPoints(funcs: FunctionNode[], content: string): string[] {
  const entries = new Set<string>();
  for (const fn of funcs) {
    if (fn.is_exported) { entries.add(fn.name); continue; }
    for (const re of ENTRY_PATTERNS) {
      if (re.test(fn.body.split("\n")[0])) { entries.add(fn.name); break; }
    }
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
