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
 * mechanism than relative-import resolution); a cross-file callee-body sink re-walk (today's summaries
 * only capture RETURN-value propagation -- a call `importedFn(tainted)` where importedFn's body sinks
 * on that param directly with no return is still same-file-only; the same-file "seededParams" second
 * pass every engine already has would need a cross-file-seeds analog, a distinct, larger feature left
 * for its own pass); dynamic `import()`/`getattr`; class-method summaries; cross-repo resolution.
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
}

export interface CrossFileBridge {
  /** file path -> local call-site name -> { shapes, fromModule } -- fed directly into each engine's
   * OWN same-file propagating map, so a cross-file call is handled by the exact same machinery as a
   * local one. Only files with at least one resolved entry appear. */
  propagatingByFile: Map<string, Map<string, { shapes: CrossFileShape[]; fromModule: string }>>;
  /** file path -> its own fully-resolved export summary (incl. re-exports), after the fixed point. */
  summaries: Map<string, Map<string, CrossFileShape[]>>;
}

import { ALL } from "./taintCore";

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
 * Resolves the full cross-file import/re-export graph for one batch of files into a per-file bridge
 * every engine's own same-file propagating map merges in directly. See this module's own docblock for
 * the round-based multi-hop algorithm and what's explicitly out of scope.
 */
export function resolveCrossFile(
  files: readonly FileGraph[],
  resolvePath: (fromFile: string, moduleSpecifier: string) => string | null,
): CrossFileBridge {
  const summaries = new Map<string, Map<string, CrossFileShape[]>>(files.map(f => [f.path, new Map()]));

  for (let round = 0; round < MAX_CROSS_FILE_ROUNDS; round++) {
    let changed = false;

    // 1) Resolve re-exports using the summaries as they stand at the START of this round -- a
    // re-export CHAIN (A re-exports B which re-exports C) converges over successive rounds, same as
    // any other propagation here.
    for (const f of files) {
      const target = summaries.get(f.path)!;
      for (const re of f.reexports) {
        const calleePath = resolvePath(f.path, re.moduleSpecifier);
        if (!calleePath) continue; // external package / unresolvable -- out of graph, never throws
        const calleeSummary = summaries.get(calleePath);
        if (!calleeSummary) continue;
        if (re.publicName === null) {
          for (const [name, shapes] of calleeSummary) if (mergeShapesInto(target, name, shapes)) changed = true;
        } else if (re.importedName && mergeShapesInto(target, re.publicName, calleeSummary.get(re.importedName) ?? [])) {
          changed = true;
        }
      }
    }

    // 2) Build each file's `incoming` (its own import edges resolved against the CURRENT summaries)
    // and recompute its own summary -- this is what makes a wrapper around a cross-file call
    // recognized as propagating, closing the one-hop cap (A -> B -> C).
    for (const f of files) {
      const incoming = new Map<string, CrossFileShape[]>();
      for (const imp of f.imports) {
        const calleePath = resolvePath(f.path, imp.moduleSpecifier);
        if (!calleePath) continue;
        const calleeSummary = summaries.get(calleePath);
        if (!calleeSummary) continue;
        if (imp.namespace) {
          for (const [name, shapes] of calleeSummary) mergeShapesInto(incoming, name, shapes);
        } else {
          mergeShapesInto(incoming, imp.localName, calleeSummary.get(imp.importedName) ?? []);
        }
      }
      const recomputed = f.computeSummary(incoming);
      const target = summaries.get(f.path)!;
      for (const [name, shapes] of recomputed) if (mergeShapesInto(target, name, shapes)) changed = true;
    }

    if (!changed) break;
  }

  // Final bridge from the converged summaries.
  const propagatingByFile = new Map<string, Map<string, { shapes: CrossFileShape[]; fromModule: string }>>();
  for (const f of files) {
    const local = new Map<string, { shapes: CrossFileShape[]; fromModule: string }>();
    for (const imp of f.imports) {
      const calleePath = resolvePath(f.path, imp.moduleSpecifier);
      if (!calleePath) continue;
      const calleeSummary = summaries.get(calleePath);
      if (!calleeSummary) continue;
      if (imp.namespace) {
        for (const [name, shapes] of calleeSummary) {
          if (shapes.length > 0) local.set(name, { shapes, fromModule: imp.moduleSpecifier });
        }
      } else {
        const shapes = calleeSummary.get(imp.importedName);
        if (shapes && shapes.length > 0) local.set(imp.localName, { shapes, fromModule: imp.moduleSpecifier });
      }
    }
    if (local.size > 0) propagatingByFile.set(f.path, local);
  }

  return { propagatingByFile, summaries };
}
