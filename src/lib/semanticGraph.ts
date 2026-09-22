/**
 * TrustLedger Semantic Graph Engine
 *
 * Builds a repository-wide module dependency graph from the import/export
 * tables produced by ast.ts. Enables:
 *   - Cross-file symbol resolution (which file exports X that file A imports)
 *   - Dead export detection (exported symbols never imported anywhere)
 *   - Circular dependency detection
 *   - Cross-file taint propagation (tainted export ⇒ tainted import site)
 *   - AI contamination spread analysis (AI-generated file exports infect callers)
 */

import type { ImportInfo, ExportInfo, ParseResult } from "./ast";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ModuleNode {
  path:        string;
  imports:     ImportInfo[];
  exports:     ExportInfo[];
  aiScore?:    number;   // 0–1 from scanner, if available
  isTainted?:  boolean;  // has security taint sources
}

export interface SymbolRef {
  name:       string;
  sourceFile: string;
  kind:       ExportInfo["kind"];
  line:       number;
}

export interface CrossFileCall {
  callerFile:  string;
  calleeFile:  string;
  symbolName:  string;
  importLine:  number;
}

export interface TaintSpread {
  sourceFile:   string;
  symbol:       string;
  reachesFiles: string[];
  riskScore:    number;  // 0–1: how broadly taint spreads
}

// AI risk radiating OUTWARD from an AI-heavy file to the files (within this
// PR's changeset) that import it -- the opposite direction from
// aiContamination below, which propagates INWARD from a file's own
// dependencies. Powers "blast radius" scoring: an AI-heavy file matters
// more when other changed files in the same PR actually depend on it.
export interface BlastRadius {
  sourceFile:   string;
  aiPercentage: number;
  reachesFiles: string[];   // direct + transitive importers within this PR's changeset
  blastScore:   number;     // 0–1: aiPercentage compounded with fan-out
}

export interface SemanticGraph {
  modules:          Map<string, ModuleNode>;
  edges:            Map<string, Set<string>>;   // file → files it imports from
  reverseEdges:     Map<string, Set<string>>;   // file → files that import it
  symbolTable:      Map<string, SymbolRef>;     // "file::symbol" → SymbolRef
  crossFileCalls:   CrossFileCall[];
  deadExports:      SymbolRef[];
  circularDeps:     string[][];                 // each inner array is a cycle
  taintSpreads:     TaintSpread[];
  aiContamination:  Map<string, number>;        // file → max AI score of its dependencies
  blastRadius:      BlastRadius[];
}

// ── Graph builder ─────────────────────────────────────────────────────────────

export function buildSemanticGraph(
  filePaths:  string[],
  parseMap:   Map<string, ParseResult>,
  aiScores?:  Map<string, number>,
  taintFiles?: Set<string>,
): SemanticGraph {
  const modules      = new Map<string, ModuleNode>();
  const edges        = new Map<string, Set<string>>();
  const reverseEdges = new Map<string, Set<string>>();
  const symbolTable  = new Map<string, SymbolRef>();

  // Build module nodes
  for (const path of filePaths) {
    const pr = parseMap.get(path);
    if (!pr) continue;
    modules.set(path, {
      path,
      imports:    pr.imports,
      exports:    pr.exports,
      aiScore:    aiScores?.get(path),
      isTainted:  taintFiles?.has(path) ?? false,
    });
    edges.set(path, new Set());
    reverseEdges.set(path, new Set());
  }

  // Populate symbol table from exports
  for (const [path, mod] of Array.from(modules.entries())) {
    for (const exp of mod.exports) {
      const key = `${path}::${exp.name}`;
      symbolTable.set(key, { name: exp.name, sourceFile: path, kind: exp.kind, line: exp.line });
    }
  }

  // Resolve imports → edges
  for (const [callerPath, mod] of Array.from(modules.entries())) {
    for (const imp of mod.imports) {
      const resolvedPath = resolveImportPath(callerPath, imp.from, filePaths);
      if (resolvedPath) {
        edges.get(callerPath)?.add(resolvedPath);
        reverseEdges.get(resolvedPath)?.add(callerPath);
      }
    }
  }

  // Cross-file calls: each import of a specific symbol is a cross-file call
  const crossFileCalls: CrossFileCall[] = [];
  for (const [callerPath, mod] of Array.from(modules.entries())) {
    for (const imp of mod.imports) {
      const resolvedPath = resolveImportPath(callerPath, imp.from, filePaths);
      if (!resolvedPath) continue;
      for (const sym of imp.symbols) {
        crossFileCalls.push({ callerFile: callerPath, calleeFile: resolvedPath, symbolName: sym, importLine: imp.line });
      }
    }
  }

  // Dead export detection: exports never referenced in any import
  const importedSymbols = new Set<string>();
  for (const mod of Array.from(modules.values())) {
    for (const imp of mod.imports) {
      const resolvedPath = resolveImportPath(mod.path, imp.from, filePaths);
      if (!resolvedPath) continue;
      for (const sym of imp.symbols) {
        importedSymbols.add(`${resolvedPath}::${sym}`);
      }
    }
  }
  const deadExports: SymbolRef[] = [];
  for (const [key, ref] of Array.from(symbolTable.entries())) {
    if (ref.kind !== "re-export" && ref.name !== "default" && !importedSymbols.has(key)) {
      deadExports.push(ref);
    }
  }

  // Circular dependency detection via DFS
  const circularDeps = detectCycles(edges);

  // Taint spread analysis
  const taintSpreads = computeTaintSpreads(modules, edges, reverseEdges);

  // AI contamination: for each file, what's the max AI score of its transitive dependencies?
  const aiContamination = computeAIContamination(modules, edges);

  // Blast radius: for each AI-heavy file, how far does its own risk radiate
  // outward to files (in this PR) that import it?
  const blastRadius = computeAIBlastRadius(modules, reverseEdges);

  return { modules, edges, reverseEdges, symbolTable, crossFileCalls, deadExports, circularDeps, taintSpreads, aiContamination, blastRadius };
}

// ── Import path resolver ──────────────────────────────────────────────────────

// Path -> real file, built once per distinct `allFiles` ARRAY (not per call) so repeatedly resolving
// many import edges against the same batch -- the normal case, every caller below builds one file list
// and resolves every edge against it -- is O(files) once instead of O(imports × files). Keyed by
// reference (a WeakMap, so a stale index for a batch that's gone out of scope is simply garbage
// collected, never manually invalidated) rather than by content, since every real call site passes a
// single list built once per graph/scan and reused across all its own resolveImportPath calls.
const pathIndexCache = new WeakMap<string[], Map<string, string>>();
function pathIndexFor(allFiles: string[]): Map<string, string> {
  let idx = pathIndexCache.get(allFiles);
  if (!idx) {
    idx = new Map();
    for (const f of allFiles) idx.set(normPath(f), f);
    pathIndexCache.set(allFiles, idx);
  }
  return idx;
}

// `@/` -> `src/` (root-relative alias), the one convention common enough across real TS codebases
// (and used throughout this very repo's own imports) to hardcode as a heuristic. A real
// tsconfig.json/jsconfig.json `paths`/`baseUrl` read is a deliberate, documented gap -- resolving one
// would need this function to read FILE CONTENT, not just paths, a signature change left for its own
// pass rather than rushed in here.
const ROOT_ALIAS_RE = /^@\//;

export function resolveImportPath(fromFile: string, importSpec: string, allFiles: string[]): string | null {
  const isRelative = importSpec.startsWith(".");
  const isAliased = ROOT_ALIAS_RE.test(importSpec);
  if (!isRelative && !isAliased) return null; // external package — not in our graph

  const fromDir  = fromFile.replace(/[\\/][^\\/]+$/, "");
  const resolved = isAliased ? normPath("src/" + importSpec.replace(ROOT_ALIAS_RE, "")) : normPath(fromDir + "/" + importSpec);
  const index = pathIndexFor(allFiles);

  const exact = index.get(resolved);
  if (exact) return exact;

  // A `./x.js`/`./x.mjs`/`./x.cjs` specifier (real ESM-with-TS-sources convention) resolves against
  // the TS source, not a literal .js file that was never in the batch to begin with.
  const tsCounterpart = resolved.replace(/\.(mjs|cjs|js)x?$/, m => (m.startsWith(".mjs") ? ".mts" : m.startsWith(".cjs") ? ".cts" : m.endsWith("x") ? ".tsx" : ".ts"));
  if (tsCounterpart !== resolved) {
    const hit = index.get(tsCounterpart);
    if (hit) return hit;
  }

  // Try with common extensions (bare specifier with no extension at all -- the common case).
  const exts = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", "/index.ts", "/index.tsx", "/index.js"];
  for (const ext of exts) {
    const hit = index.get(resolved + ext);
    if (hit) return hit;
  }
  return null;
}

function normPath(p: string): string {
  // Collapse . and .. segments
  const parts = p.replace(/\\/g, "/").split("/");
  const out: string[] = [];
  for (const part of parts) {
    if (part === "..") { out.pop(); }
    else if (part !== ".") { out.push(part); }
  }
  return out.join("/");
}

// ── Python import path resolver ────────────────────────────────────────────────
//
// Python's own module system has no `.`-relative-specifier convention the way JS/TS's does --
// `from .helpers import x` (1 dot = current package), `from ..pkg.mod import x` (2 dots = one
// package up), and `from pkg.mod import x` (0 dots = an ABSOLUTE import, resolved against
// sys.path -- a repo's real source root, which this scanner never knows for certain) are three
// genuinely different resolution rules, not variations on one relative-path join.

/** For a relative import (`dots` >= 1): walk `dots - 1` directories up from the importing file's OWN
 * directory (1 dot = the current package, i.e. that same directory), then join the dotted remainder. */
function resolvePythonRelative(fromFile: string, dots: number, remainder: string, index: Map<string, string>): string | null {
  let dir = fromFile.replace(/[\\/][^\\/]+$/, "");
  for (let i = 0; i < dots - 1; i++) dir = dir.replace(/[\\/][^\\/]+$/, "");
  const base = remainder ? normPath(`${dir}/${remainder.replace(/\./g, "/")}`) : normPath(dir);
  return index.get(`${base}.py`) ?? index.get(`${base}/__init__.py`) ?? null;
}

/** For an absolute import (`import pkg.mod`, `from pkg.mod import x`): the real source root (`src/`,
 * `app/`, a `src-layout` package dir, ...) isn't knowable from paths alone, so this tries the
 * importing file's own ancestor directories first (the common case: siblings under the same
 * source root), then falls back to a longest-dotted-suffix match against the whole batch. */
function resolvePythonAbsolute(fromFile: string, dotted: string, index: Map<string, string>): string | null {
  const segments = dotted.split(".");
  const rel = segments.join("/");
  let dir = fromFile.replace(/[\\/][^\\/]+$/, "");
  for (;;) {
    const base = normPath(`${dir}/${rel}`);
    const hit = index.get(`${base}.py`) ?? index.get(`${base}/__init__.py`);
    if (hit) return hit;
    const parent = dir.replace(/[\\/][^\\/]+$/, "");
    if (parent === dir || !dir.includes("/")) break;
    dir = parent;
  }
  // Longest-suffix fallback: does any batch file END with these path segments? (source root unknown,
  // so a full match isn't possible -- this is a best-effort heuristic, consistent with this module's
  // own "external/unresolvable = out of graph, never throws" posture elsewhere.)
  const suffix = `/${rel}.py`;
  const suffixInit = `/${rel}/__init__.py`;
  let best: string | null = null;
  for (const [norm, real] of index) {
    if (norm.endsWith(suffix) || norm.endsWith(suffixInit) || norm === `${rel}.py`) {
      if (!best || norm.length > best.length) best = real;
    }
  }
  return best;
}

/** Resolves a Python import specifier (as tree-sitter-python gives it -- see astTaintPython.ts's
 * collectImportEdgesPy) to a batch file path, or null (external package / unresolvable -- out of
 * graph, exactly like resolveImportPath's own boundary). `dots` is the number of leading dots
 * (0 = absolute); `dotted` is the module path with the dots already stripped. */
export function resolvePythonImportPath(fromFile: string, dots: number, dotted: string, allFiles: string[]): string | null {
  const index = pathIndexFor(allFiles);
  return dots > 0 ? resolvePythonRelative(fromFile, dots, dotted, index) : resolvePythonAbsolute(fromFile, dotted, index);
}

// ── Cycle detection (DFS) ─────────────────────────────────────────────────────

function detectCycles(edges: Map<string, Set<string>>): string[][] {
  const cycles: string[][] = [];
  const WHITE = 0, GRAY = 1, BLACK = 2;
  const color = new Map<string, number>();
  const stack: string[] = [];

  const dfs = (node: string) => {
    color.set(node, GRAY);
    stack.push(node);
    for (const neighbor of Array.from(edges.get(node) ?? [])) {
      if (color.get(neighbor) === GRAY) {
        // Found a cycle — extract it from the stack
        const cycleStart = stack.indexOf(neighbor);
        if (cycleStart >= 0) {
          const cycle = stack.slice(cycleStart).concat(neighbor);
          // Only add if not already present
          const cycleKey = [...cycle].sort().join("|");
          if (!cycles.some(c => [...c].sort().join("|") === cycleKey)) {
            cycles.push(cycle);
          }
        }
      } else if (color.get(neighbor) !== BLACK) {
        dfs(neighbor);
      }
    }
    stack.pop();
    color.set(node, BLACK);
  };

  for (const node of Array.from(edges.keys())) {
    if (!color.has(node)) dfs(node);
  }

  return cycles;
}

// ── Taint spread computation ──────────────────────────────────────────────────

function computeTaintSpreads(
  modules:      Map<string, ModuleNode>,
  edges:        Map<string, Set<string>>,
  reverseEdges: Map<string, Set<string>>,
): TaintSpread[] {
  const spreads: TaintSpread[] = [];

  for (const [path, mod] of Array.from(modules.entries())) {
    if (!mod.isTainted) continue;

    // BFS through reverse edges to find all files that import (transitively) from this tainted file
    const reachable = new Set<string>();
    const queue = [path];
    while (queue.length > 0) {
      const cur = queue.shift()!;
      for (const consumer of Array.from(reverseEdges.get(cur) ?? [])) {
        if (!reachable.has(consumer)) {
          reachable.add(consumer);
          queue.push(consumer);
        }
      }
    }
    reachable.delete(path);

    if (reachable.size > 0) {
      const total = modules.size || 1;
      spreads.push({
        sourceFile:   path,
        symbol:       "*",
        reachesFiles: Array.from(reachable),
        riskScore:    Math.min(1, reachable.size / total),
      });
    }
  }

  void edges;
  return spreads;
}

// ── AI blast-radius propagation ─────────────────────────────────────────────
// Structural sibling of computeTaintSpreads above (same BFS-outward-through-
// reverseEdges shape), rooted at high-AI-score files instead of tainted
// ones -- "how many other files in this changeset import (transitively)
// from this AI-heavy file."

function computeAIBlastRadius(
  modules:      Map<string, ModuleNode>,
  reverseEdges: Map<string, Set<string>>,
  threshold = 0.4,
): BlastRadius[] {
  const result: BlastRadius[] = [];

  for (const [path, mod] of Array.from(modules.entries())) {
    const aiScore = mod.aiScore ?? 0;
    if (aiScore < threshold) continue;

    const reachable = new Set<string>();
    const queue = [path];
    while (queue.length > 0) {
      const cur = queue.shift()!;
      for (const consumer of Array.from(reverseEdges.get(cur) ?? [])) {
        if (!reachable.has(consumer)) {
          reachable.add(consumer);
          queue.push(consumer);
        }
      }
    }
    reachable.delete(path);

    if (reachable.size > 0) {
      const total = modules.size || 1;
      result.push({
        sourceFile:   path,
        aiPercentage: aiScore,
        reachesFiles: Array.from(reachable),
        blastScore:   Math.min(1, aiScore * (reachable.size / total) * 1.5),
      });
    }
  }

  return result;
}

// ── AI contamination propagation ──────────────────────────────────────────────

function computeAIContamination(
  modules: Map<string, ModuleNode>,
  edges:   Map<string, Set<string>>,
): Map<string, number> {
  const contamination = new Map<string, number>();

  // Topological sort (Kahn's algorithm)
  const inDegree = new Map<string, number>();
  for (const node of Array.from(modules.keys())) inDegree.set(node, 0);
  for (const [, deps] of Array.from(edges.entries())) {
    for (const dep of Array.from(deps)) {
      inDegree.set(dep, (inDegree.get(dep) ?? 0) + 1);
    }
  }

  const queue = Array.from(inDegree.entries()).filter(([, d]) => d === 0).map(([n]) => n);

  while (queue.length > 0) {
    const node = queue.shift()!;
    const mod  = modules.get(node);
    const own  = mod?.aiScore ?? 0;

    // Max contamination = own AI score vs max dep contamination
    let maxDep = 0;
    for (const dep of Array.from(edges.get(node) ?? [])) {
      maxDep = Math.max(maxDep, contamination.get(dep) ?? 0);
    }
    contamination.set(node, Math.max(own, maxDep * 0.7)); // decay factor 0.7 per hop

    // Reduce in-degree for reverse (consumers of this node)
    // Note: we iterate modules to find who depends on `node`
    for (const [consumer, deps] of Array.from(edges.entries())) {
      if (deps.has(node)) {
        const d = (inDegree.get(consumer) ?? 1) - 1;
        inDegree.set(consumer, d);
        if (d === 0) queue.push(consumer);
      }
    }
  }

  return contamination;
}

// ── Query helpers ─────────────────────────────────────────────────────────────

/** Return all files that file `path` depends on (transitively). */
export function transitiveImports(graph: SemanticGraph, path: string): Set<string> {
  const visited = new Set<string>();
  const queue   = [path];
  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const dep of Array.from(graph.edges.get(cur) ?? [])) {
      if (!visited.has(dep)) { visited.add(dep); queue.push(dep); }
    }
  }
  visited.delete(path);
  return visited;
}

/** Resolve a symbol name to its source definition. */
export function resolveSymbol(graph: SemanticGraph, callerFile: string, symbolName: string): SymbolRef | null {
  const mod = graph.modules.get(callerFile);
  if (!mod) return null;
  for (const imp of mod.imports) {
    if (!imp.symbols.includes(symbolName)) continue;
    const calleePath = resolveImportPath(callerFile, imp.from, Array.from(graph.modules.keys()));
    if (!calleePath) continue;
    return graph.symbolTable.get(`${calleePath}::${symbolName}`) ?? null;
  }
  return null;
}
