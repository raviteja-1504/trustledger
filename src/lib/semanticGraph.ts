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

  return { modules, edges, reverseEdges, symbolTable, crossFileCalls, deadExports, circularDeps, taintSpreads, aiContamination };
}

// ── Import path resolver ──────────────────────────────────────────────────────

function resolveImportPath(fromFile: string, importSpec: string, allFiles: string[]): string | null {
  if (!importSpec.startsWith(".")) return null; // external package — not in our graph

  const fromDir  = fromFile.replace(/[\\/][^\\/]+$/, "");
  const resolved = normPath(fromDir + "/" + importSpec);

  // Try exact match first
  for (const f of allFiles) {
    if (normPath(f) === resolved) return f;
  }
  // Try with common extensions
  const exts = [".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.js"];
  for (const ext of exts) {
    const candidate = resolved + ext;
    for (const f of allFiles) {
      if (normPath(f) === candidate) return f;
    }
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
