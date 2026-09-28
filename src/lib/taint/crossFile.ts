/**
 * Language-agnostic cross-file taint resolution: named/namespace/CommonJS imports, default exports,
 * and re-exports (`export { x } from`, `export * from`), resolved as a bounded multi-hop fixed point
 * so A -> B -> C converges (not just one hop, the old scanner.ts inline block's real limit -- B's own
 * summary computation could not previously see that one of ITS calls was itself cross-file-tainted).
 *
 * Each engine keeps its OWN parsing/AST/mask machinery (astTaint.ts for JS/TS, astTaintPython.ts for
 * Python); this module only orchestrates the cross-FILE graph over the shared shape below. Wired into
 * both from scanner.ts's runScan via a per-language `FileGraph` adapter -- see astTaint.ts's own
 * cross-file docblocks for what each adapter actually parses.
 *
 * Explicitly out of scope, matching this repo's own "documented gap, not a silent miss" convention:
 * Java/Go/C#/PHP cross-file (their visibility model is package/namespace-keyed, a genuinely different
 * mechanism than relative-import resolution); dynamic `import()`/`getattr`; class-method summaries;
 * cross-repo resolution.
 *
 * Two kinds of fact flow through the SAME import/re-export graph and the SAME bounded round loop:
 *   - shapes: which parameters' taint survives to a function's RETURN value (`computeSummary`);
 *   - sink facts (ParamSinkFact, see taintCore.ts): which parameters reach a SINK inside the function or,
 *     transitively, inside something it calls -- including in other files (`computeSinks`, optional, so an
 *     engine without sink summaries yet is unaffected). This is what lets `runQuery(req.query.id)` be
 *     flagged when runQuery's body sinks its parameter and returns nothing.
 */

/** A parameter shape used only to describe a cross-file summary entry -- structurally identical to
 * (and freely interchangeable with) each engine's own ParamShape; `name` is never read by this module,
 * only `index`/`isRest`/`mask`. */
export interface CrossFileShape { name: string; index: number; isRest: boolean; mask?: number }

export interface ImportEdge {
  /** The name call sites in the importing file use. */
  localName: string;
  /** The name as exported by the source file ("default" for a default export). Ignored (any value is
   * fine) when `namespace` is true. */
  importedName: string;
  /** Raw specifier as written -- resolved to a batch file path via `resolvePath`; attribution only. */
  moduleSpecifier: string;
  /** `import * as ns from "./mod"` / `const ns = require("./mod")` -- localName is bound to every
   * export of the module, addressed as `ns.<name>` at call sites. Each engine's own call-resolution
   * already matches a property-access call by its LAST identifier (see astTaint.ts's calleeName
   * resolution), so the bridge this module builds registers every export under its OWN bare name --
   * exactly what a `ns.foo(...)` call site's own resolution already looks up. */
  namespace?: boolean;
}

export interface ReexportEdge {
  /** null+null = `export * from "./mod"` -- every name the module exports, under the same name. */
  publicName: string | null;
  importedName: string | null;
  moduleSpecifier: string;
}

export interface FileGraph {
  path: string;
  imports: ImportEdge[];
  reexports: ReexportEdge[];
  /**
   * Recomputes this file's OWN export summary given what's currently known, THIS round, about the
   * names it imports (local call-site name -> shapes). Called once per round; must be safe to call
   * repeatedly and must be monotonic (only ever adds entries/classes as `incoming` grows across
   * rounds) for the fixed point to terminate -- the same argument astTaint.ts's own
   * buildPropagatingMap docblock makes, one level up.
   */
  computeSummary: (incoming: Map<string, CrossFileShape[]>) => Map<string, CrossFileShape[]>;
  /**
   * Optional. Recomputes which parameters of this file's exports reach a sink, given the shapes AND sink
   * facts currently known for the names it imports. Same contract as computeSummary: called once per
   * round, must be monotonic (only ever adds facts as its inputs grow) for the fixed point to settle.
   */
  computeSinks?: (
    incomingShapes: Map<string, CrossFileShape[]>,
    incomingSinks: Map<string, ParamSinkFact[]>,
  ) => Map<string, ParamSinkFact[]>;
}

export interface CrossFileBridge {
  /** file path -> local call-site name -> { shapes, fromModule, resolvedPath } -- fed directly into
   * each engine's OWN same-file propagating map, so a cross-file call is handled by the exact same
   * machinery as a local one. `resolvedPath` (the batch file this name actually came from) is carried
   * only for trace-generation attribution -- never consulted by the taint predicate itself. Only
   * files with at least one resolved entry appear. */
  propagatingByFile: Map<string, Map<string, BridgeEntry>>;
  /** file path -> its own fully-resolved export summary (incl. re-exports), after the fixed point. */
  summaries: Map<string, Map<string, CrossFileShape[]>>;
  /** Same, for sink facts. */
  sinkSummaries: Map<string, Map<string, ParamSinkFact[]>>;
}

/** One imported name as the importing file sees it: return-propagation shapes plus sink facts. */
export interface BridgeEntry {
  shapes: CrossFileShape[];
  sinks: ParamSinkFact[];
  fromModule: string;
  resolvedPath: string;
}

import { ALL, mergeSinkFacts } from "./taintCore";
import type { ParamSinkFact } from "./taintCore";

// Bounded for the same reason astTaint.ts's MAX_PROPAGATION_ROUNDS is: convergence is guaranteed
// (every merge below is monotonic OR), the cap only bounds worst-case cost on a large batch.
const MAX_CROSS_FILE_ROUNDS = 3;

/** Per-parameter-index OR-merge of `shapes` into `target.get(name)`. Returns whether anything grew. */
function mergeShapesInto(target: Map<string, CrossFileShape[]>, name: string, shapes: CrossFileShape[]): boolean {
  if (shapes.length === 0) return false;
  const existing = target.get(name);
  if (!existing) { target.set(name, shapes); return true; }
  let grew = false;
  const byIndex = new Map(existing.map(s => [s.index, s]));
  for (const s of shapes) {
    const cur = byIndex.get(s.index);
    const incomingMask = s.mask ?? ALL;
    if (!cur) { byIndex.set(s.index, s); grew = true; continue; }
    const nextMask = (cur.mask ?? ALL) | incomingMask;
    if (nextMask !== (cur.mask ?? ALL)) { byIndex.set(s.index, { ...cur, mask: nextMask }); grew = true; }
  }
  if (grew) target.set(name, [...byIndex.values()]);
  return grew;
}

/**
 * The summary keys one import binding brings in, as [exporter key, local key] pairs: the imported name
 * itself, plus its QUALIFIED member keys (`UserService.find`, `userService.find`, `repo.find` -- methods of
 * an exported class, instance or object) renamed to the local binding, so `import { UserService as Svc }`
 * makes `Svc.find` resolvable at call sites.
 */
function bindingKeys(exporterKeys: Iterable<string>, importedName: string, localName: string): Array<[string, string]> {
  const out: Array<[string, string]> = [[importedName, localName]];
  const prefix = `${importedName}.`;
  for (const k of exporterKeys) if (k.startsWith(prefix)) out.push([k, `${localName}.${k.slice(prefix.length)}`]);
  return out;
}

/** Union `facts` into `target.get(name)`, creating the entry. Returns whether anything grew. */
function mergeSinksInto(target: Map<string, ParamSinkFact[]>, name: string, facts: readonly ParamSinkFact[]): boolean {
  if (facts.length === 0) return false;
  let list = target.get(name);
  if (!list) { list = []; target.set(name, list); }
  return mergeSinkFacts(list, facts);
}

/**
 * Resolves the full cross-file import/re-export graph for one batch of files into a per-file bridge
 * every engine's own same-file propagating map merges in directly. See this module's own docblock for
 * the round-based multi-hop algorithm and what's explicitly out of scope.
 */
export function resolveCrossFile(
  files: readonly FileGraph[],
  resolvePath: (fromFile: string, moduleSpecifier: string) => string | null,
): CrossFileBridge {
  const summaries = new Map<string, Map<string, CrossFileShape[]>>(files.map(f => [f.path, new Map()]));
  const sinkSummaries = new Map<string, Map<string, ParamSinkFact[]>>(files.map(f => [f.path, new Map()]));

  for (let round = 0; round < MAX_CROSS_FILE_ROUNDS; round++) {
    let changed = false;

    // 1) Resolve re-exports using the summaries as they stand at the START of this round -- a
    // re-export CHAIN (A re-exports B which re-exports C) converges over successive rounds, same as
    // any other propagation here. Sink facts travel through re-exports exactly like shapes do.
    for (const f of files) {
      const target = summaries.get(f.path)!;
      const sinkTarget = sinkSummaries.get(f.path)!;
      for (const re of f.reexports) {
        const calleePath = resolvePath(f.path, re.moduleSpecifier);
        if (!calleePath) continue; // external package / unresolvable -- out of graph, never throws
        const calleeSummary = summaries.get(calleePath);
        const calleeSinks = sinkSummaries.get(calleePath);
        if (!calleeSummary || !calleeSinks) continue;
        if (re.publicName === null) {
          for (const [name, shapes] of calleeSummary) if (mergeShapesInto(target, name, shapes)) changed = true;
          for (const [name, facts] of calleeSinks) if (mergeSinksInto(sinkTarget, name, facts)) changed = true;
        } else if (re.importedName) {
          for (const [from, to] of bindingKeys(calleeSummary.keys(), re.importedName, re.publicName)) {
            if (mergeShapesInto(target, to, calleeSummary.get(from) ?? [])) changed = true;
          }
          for (const [from, to] of bindingKeys(calleeSinks.keys(), re.importedName, re.publicName)) {
            if (mergeSinksInto(sinkTarget, to, calleeSinks.get(from) ?? [])) changed = true;
          }
        }
      }
    }

    // 2) Build each file's `incoming` (its own import edges resolved against the CURRENT summaries)
    // and recompute its own summary -- this is what makes a wrapper around a cross-file call
    // recognized as propagating, closing the one-hop cap (A -> B -> C).
    for (const f of files) {
      const incoming = new Map<string, CrossFileShape[]>();
      const incomingSinks = new Map<string, ParamSinkFact[]>();
      for (const imp of f.imports) {
        const calleePath = resolvePath(f.path, imp.moduleSpecifier);
        if (!calleePath) continue;
        const calleeSummary = summaries.get(calleePath);
        const calleeSinks = sinkSummaries.get(calleePath);
        if (!calleeSummary || !calleeSinks) continue;
        if (imp.namespace) {
          for (const [name, shapes] of calleeSummary) mergeShapesInto(incoming, name, shapes);
          for (const [name, facts] of calleeSinks) mergeSinksInto(incomingSinks, name, facts);
        } else {
          for (const [from, to] of bindingKeys(calleeSummary.keys(), imp.importedName, imp.localName)) {
            mergeShapesInto(incoming, to, calleeSummary.get(from) ?? []);
          }
          for (const [from, to] of bindingKeys(calleeSinks.keys(), imp.importedName, imp.localName)) {
            mergeSinksInto(incomingSinks, to, calleeSinks.get(from) ?? []);
          }
        }
      }
      const recomputed = f.computeSummary(incoming);
      const target = summaries.get(f.path)!;
      for (const [name, shapes] of recomputed) if (mergeShapesInto(target, name, shapes)) changed = true;

      if (f.computeSinks) {
        const sinkTarget = sinkSummaries.get(f.path)!;
        for (const [name, facts] of f.computeSinks(incoming, incomingSinks)) {
          if (mergeSinksInto(sinkTarget, name, facts)) changed = true;
        }
      }
    }

    if (!changed) break;
  }

  // Final bridge from the converged summaries.
  const propagatingByFile = new Map<string, Map<string, BridgeEntry>>();
  for (const f of files) {
    const local = new Map<string, BridgeEntry>();
    for (const imp of f.imports) {
      const calleePath = resolvePath(f.path, imp.moduleSpecifier);
      if (!calleePath) continue;
      const calleeSummary = summaries.get(calleePath);
      const calleeSinks = sinkSummaries.get(calleePath);
      if (!calleeSummary || !calleeSinks) continue;
      const entryFor = (exportName: string, localName: string) => {
        const shapes = calleeSummary.get(exportName) ?? [];
        const sinks = calleeSinks.get(exportName) ?? [];
        if (shapes.length > 0 || sinks.length > 0) {
          local.set(localName, { shapes, sinks, fromModule: imp.moduleSpecifier, resolvedPath: calleePath });
        }
      };
      if (imp.namespace) {
        for (const name of new Set([...calleeSummary.keys(), ...calleeSinks.keys()])) entryFor(name, name);
      } else {
        const exporterKeys = new Set([...calleeSummary.keys(), ...calleeSinks.keys()]);
        for (const [from, to] of bindingKeys(exporterKeys, imp.importedName, imp.localName)) entryFor(from, to);
      }
    }
    if (local.size > 0) propagatingByFile.set(f.path, local);
  }

  return { propagatingByFile, summaries, sinkSummaries };
}
