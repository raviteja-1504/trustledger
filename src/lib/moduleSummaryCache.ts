/**
 * Cross-scan cache for the CROSS-FILE summary/reachability stage of runScan -- a different stage from
 * incrementalCache.ts's per-file `file_cache`, and a real gap that one left open: `file_cache` lets
 * analyzeFile() skip an unchanged file's OWN taint walk, but every scan still re-parses EVERY file and
 * reruns computeExportTaintSummary/computeExportSinkSummary/buildCallGraph for ALL of them, every time,
 * to rebuild the cross-file bridge (taint/crossFile.ts) and the reachability graph
 * (crossFileReachability.ts) -- work whose cost scales with the whole batch, not with what changed. On a
 * large, mostly-unchanged repo this dominates scan time even when file_cache skips almost every
 * analyzeFile() call.
 *
 * The insight that makes reuse SOUND, not approximate: computeExportTaintSummary/computeExportSinkSummary
 * and buildCallGraph are pure functions of one file's own content, batch composition (for import
 * resolution) and -- for the summary functions only -- the CONVERGED cross-file facts of whatever it
 * imports. So a file's cached summary/sinks/call-graph are STILL CORRECT, with no approximation, as long
 * as: (a) its own content hash is unchanged, (b) every import/re-export specifier still resolves to the
 * SAME path it did last time (the batch composition hasn't shifted underneath it), and (c) recursively,
 * everything it (transitively) imports from is ALSO still valid by this same test. computeCacheValidity
 * below is exactly that fixed point -- a graph-invalidation pass over cached metadata alone (no parsing),
 * cheap enough to run every scan even on a large batch.
 */

import crypto from "crypto";
import type { CrossFileShape } from "./taint/crossFile";
import type { ParamSinkFact } from "./taint/taintCore";

/**
 * Bump when computeExportTaintSummary/computeExportSinkSummary/buildCallGraph/resolveCrossFile's output
 * semantics change (a bug fix, a new cross-file shape recognized). Separate from incrementalCache.ts's
 * own SCAN_CACHE_VERSION -- that one covers analyzeFile()'s output, a different stage with a different
 * change cadence; bumping one should not force a maintainer to reason about whether the other stage was
 * ALSO affected. Without this, a cached summary from before a fix here would keep being treated as
 * "provably still correct" forever, for any file whose own content never changes again -- exactly the
 * silent-stale-cache failure mode SCAN_CACHE_VERSION exists to rule out for the other cache.
 */
export const MODULE_CACHE_VERSION = 4;

/**
 * The value to compare (and to store going forward) in place of a bare content hash -- folds in
 * MODULE_CACHE_VERSION and the caller's own namespace (e.g. the deploy's commit SHA, mirroring
 * ScanInput.cache_namespace) so a code change or a release boundary invalidates every cached entry
 * at once, the same total-invalidation guarantee incrementalCache.ts's computeFileCacheKey gives
 * file_cache. computeCacheValidity itself stays a pure string comparison; this is the ONE place that
 * decides what "the content hasn't changed" actually means.
 */
export function computeModuleCacheContentHash(namespace: string, rawContentHash: string): string {
  return crypto.createHash("sha256").update(JSON.stringify([MODULE_CACHE_VERSION, namespace, rawContentHash])).digest("hex");
}

export interface CachedImportEdge {
  localName: string;
  importedName: string;
  moduleSpecifier: string;
  namespace?: boolean;
  /** What `moduleSpecifier` resolved to AT CACHE TIME -- re-checked against a fresh resolution every
   * scan; a mismatch (a file added/removed elsewhere in the batch changed where this points) invalidates
   * the file that cached it, even though its own content didn't change. */
  resolvedPath: string | null;
}

export interface CachedReexportEdge {
  publicName: string | null;
  importedName: string | null;
  moduleSpecifier: string;
  resolvedPath: string | null;
}

/** One file's cross-file contribution, as it stood after the LAST scan's fixed point converged. */
export interface CachedModuleSummary {
  contentHash: string;
  imports: CachedImportEdge[];
  reexports: CachedReexportEdge[];
  /** computeExportTaintSummary's/computeExportTaintSummaryPy's final, converged output. */
  summary: Array<[string, CrossFileShape[]]>;
  /** computeExportSinkSummary's/computeExportSinkSummaryPy's final, converged output. */
  sinks: Array<[string, ParamSinkFact[]]>;
  /** buildCallGraph(content)'s reachability-relevant output -- JS/TS only (Python isn't yet part of
   * cross-file reachability at all, a separate, pre-existing, documented gap). Content-determined alone
   * (no incoming), so it needs none of the transitive validity check below -- valid whenever the file's
   * own content hash matches. Kept alongside the rest for one round-trip, not a second cache. */
  callGraphEdges?: Array<{ caller: string; callee: string; line: number }>;
  callGraphReachable?: string[];
  /** isModelFile()'s/isModelFilePy()'s verdict for this file, cached so a scan that reuses this entry
   * (no re-parse) can still contribute to the batch-wide stored-provenance model registry -- see
   * taintCore.ts's StoredProvenanceIO docblock. Content-determined alone, so it needs none of the
   * transitive validity check the summary/sinks fields get: valid whenever the content hash matches. */
  isModelFile?: boolean;
}

/** Structural subset of callGraph.ts's own CallEdge -- decoupled so this module doesn't import callGraph.ts
 * just for a type. */
export interface CallEdgeLike { caller: string; callee: string; line: number }

/**
 * Which cached files are still exactly correct, with no re-parsing: a fixed point over CACHED metadata
 * only (import/re-export edges, their cached resolution), never the file content itself beyond the hash
 * comparison. Monotonically shrinks a candidate set (content-unchanged files) by dropping any file whose
 * cached edge resolution no longer matches a fresh resolution, or that imports/re-exports from a file that
 * didn't survive -- so it always terminates (each round removes at least one file, or the loop ends) and
 * never over-approximates: a file only stays valid if BOTH it and everything it transitively depends on
 * are provably identical to last scan.
 */
export function computeCacheValidity(
  files: readonly { path: string; contentHash: string }[],
  prevCache: Readonly<Record<string, CachedModuleSummary>>,
  resolvePath: (fromFile: string, moduleSpecifier: string) => string | null,
): Set<string> {
  const currentHashByPath = new Map(files.map(f => [f.path, f.contentHash]));
  const valid = new Set<string>();
  for (const f of files) {
    const cached = prevCache[f.path];
    if (cached && cached.contentHash === f.contentHash) valid.add(f.path);
  }

  const edgesOf = (path: string): Array<{ moduleSpecifier: string; resolvedPath: string | null }> => {
    const cached = prevCache[path]!;
    return [...cached.imports, ...cached.reexports];
  };

  for (let round = 0; round < files.length && valid.size > 0; round++) {
    let shrunk = false;
    for (const path of valid) {
      for (const e of edgesOf(path)) {
        const resolvedNow = resolvePath(path, e.moduleSpecifier);
        if (resolvedNow !== e.resolvedPath) { valid.delete(path); shrunk = true; break; }
        // A target still in THIS batch must itself be valid (transitively unchanged); a target outside
        // the batch (external package, or resolution legitimately returns the same null/path either way)
        // needs no further check -- `resolvedNow !== e.resolvedPath` above already caught any drift.
        if (resolvedNow !== null && currentHashByPath.has(resolvedNow) && !valid.has(resolvedNow)) {
          valid.delete(path); shrunk = true; break;
        }
      }
    }
    if (!shrunk) break;
  }
  return valid;
}

/** Serialize a Map<string, T[]> the way CachedModuleSummary stores it (plain arrays survive JSON; a
 * Map does not round-trip through JSON.parse/stringify at all). */
export function mapToEntries<T>(m: ReadonlyMap<string, T[]>): Array<[string, T[]]> {
  return [...m.entries()];
}
