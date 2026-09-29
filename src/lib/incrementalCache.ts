// ── Incremental scan result reuse ────────────────────────────────────────────
//
// runScan() used to accept `prev_hashes` (path -> previous content hash) and simply DROP any file whose
// hash matched. Two problems with that, both fixed by this module + runScan's use of it:
//
//  1. Dropped, not reused: an unchanged file vanished from ScanOutput.files, so every aggregate computed
//     over `files` (overall risk, AI %, distribution, compliance, trust chain) silently covered only the
//     changed subset. It also vanished from the cross-file import graph, so a changed file importing an
//     unchanged one could no longer resolve the import.
//  2. Hash-equality is not sufficient for reuse: a file's findings are a function of MORE than its own
//     bytes. analyzeFile() also consumes (a) the incoming cross-file taint summaries of files it imports,
//     (b) the cross-file reachable-name set, (c) the callee file's own content (a source->sink trace
//     continues one real hop into it), and (d) the PR-level AI prior bias. An unchanged caller whose
//     CALLEE changed must be re-analyzed even though its own hash is identical -- a hash-only skip would
//     keep reporting (or keep suppressing) a cross-file flow that no longer exists.
//
// So a cached result is keyed by a digest of every input analyzeFile() reads, not just the content hash.
// The caller persists ScanOutput.file_cache and hands it back as ScanInput.prev_results next time.

import crypto from "crypto";
import type { FileAnalysis } from "./scanner";
import type { ParamSinkFact } from "./taint/taintCore";

/**
 * Bump when analyzeFile()'s output semantics change (a detector added/removed/retuned). A stale cache
 * from before that change would otherwise keep serving old findings for unchanged files forever.
 * A deploy can also namespace its own cache via ScanInput.cache_namespace (e.g. the commit SHA) so a
 * forgotten bump here can never silently serve stale results across releases.
 */
export const SCAN_CACHE_VERSION = 4;

/** One file's reusable result. `analysis` is the post-analyzeFile, PRE-PR-level-post-pass snapshot. */
export interface CachedFileResult {
  cache_key: string;
  analysis: FileAnalysis;
}

export function sha256Hex(s: string): string {
  return crypto.createHash("sha256").update(s).digest("hex");
}

/** Structural subset of an engine's ParamShape (JS/TS `ParamShape`, Python `PyParamShape`). */
interface ShapeLike { index: number; isRest?: boolean; mask?: number; name?: string }

export interface CacheKeyInputs {
  namespace: string;
  path: string;
  contentHash: string;
  prPriorBias: number;
  /** JS/TS incoming cross-file entries: local name -> propagating shapes + sink facts + where they came from. */
  jsCrossFile?: Map<string, { shapes: ShapeLike[]; sinks?: readonly ParamSinkFact[]; fromModule: string; resolvedPath?: string }>;
  /** Content hash of a resolved callee path (a trace hops into the callee's body, so its bytes matter). */
  contentHashOf: (path: string) => string | undefined;
  /** JS/TS cross-file reachable names in this file. */
  crossFileReachable?: Set<string>;
  /** Python incoming cross-file shapes: local name -> shapes. */
  pyCrossFile?: Map<string, ShapeLike[]>;
  /** Python incoming parameter -> sink facts: local name -> facts (their location/expression reach the emitted finding). */
  pySinks?: Map<string, { sinks: readonly ParamSinkFact[] }>;
  /** Stored/second-order provenance (see taintCore.ts's StoredProvenanceIO): THIS file's own model keys
   * (from its modelReceivers) paired with their batch-converged mask -- not the whole batch-wide map, so
   * a write to a model this file never touches can't cause a spurious cache miss. */
  storedProvenanceIncoming?: Array<[string, number]>;
  /** Digest of the batch's cross-file service-layer facts for this file's language (Java/C#): any change to
   * a service's summary may change a controller's findings, so it invalidates this file's cached result. */
  serviceFactsDigest?: string;
}

/** Every field of a sink fact that reaches the emitted finding (its location, expression and via-path all
 * appear in the detail/trace), so a callee whose sink MOVED, changed or vanished invalidates the caller even
 * when the callee's own return shapes are identical. */
function canonSinks(sinks: readonly ParamSinkFact[]): unknown[] {
  return sinks
    .map(f => [f.index, f.isRest ? 1 : 0, f.id, f.sinkClass, f.sinkExpr, f.file, f.line, f.via.join(">"),
      (f.steps ?? []).map(s => `${s.file}:${s.line}:${s.kind}:${s.label}`).join(">")])
    .sort((a, b) => { const x = JSON.stringify(a), y = JSON.stringify(b); return x < y ? -1 : x > y ? 1 : 0; });
}

function canonShapes(shapes: ShapeLike[]): unknown[] {
  return [...shapes]
    .sort((a, b) => a.index - b.index)
    .map(s => [s.index, s.isRest ? 1 : 0, s.mask ?? -1, s.name ?? ""]);
}

/**
 * Digest of everything analyzeFile() reads for one file. Deterministic: every collection is sorted, so
 * Map/Set insertion order (which follows filesystem/API ordering) can never cause a spurious miss.
 */
export function computeFileCacheKey(inp: CacheKeyInputs): string {
  const js = inp.jsCrossFile
    ? [...inp.jsCrossFile.entries()]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([name, e]) => [
          name, e.fromModule, e.resolvedPath ?? "",
          e.resolvedPath ? (inp.contentHashOf(e.resolvedPath) ?? "") : "",
          canonShapes(e.shapes), canonSinks(e.sinks ?? []),
        ])
    : [];
  const py = inp.pyCrossFile
    ? [...inp.pyCrossFile.entries()]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([name, shapes]) => [name, canonShapes(shapes)])
    : [];
  const pySinks = inp.pySinks
    ? [...inp.pySinks.entries()]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([name, e]) => [name, canonSinks(e.sinks)])
    : [];
  const reachable = inp.crossFileReachable ? [...inp.crossFileReachable].sort() : [];
  const storedProvenance = inp.storedProvenanceIncoming
    ? [...inp.storedProvenanceIncoming].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    : [];
  return sha256Hex(JSON.stringify([
    SCAN_CACHE_VERSION, inp.namespace, inp.path, inp.contentHash,
    // toFixed: prPriorBias is a float derived from PR metadata; 6 places is far below any effect on a
    // file's AI% but keeps 0.08 vs 0.0800000000001 (float noise) from causing a spurious miss.
    inp.prPriorBias.toFixed(6),
    js, reachable, py, pySinks, storedProvenance, inp.serviceFactsDigest ?? "",
  ]));
}

/**
 * Deep-copies through JSON. FileAnalysis is plain data (no Map/Set/Date -- verified), and going through
 * JSON on BOTH the store and reuse side means an in-memory cache behaves identically to one that was
 * round-tripped through a database, so a test against this can't pass on object identity alone.
 * (Not structuredClone: jest's jsdom environment doesn't provide it.)
 */
export function cloneAnalysis(a: FileAnalysis): FileAnalysis {
  return JSON.parse(JSON.stringify(a)) as FileAnalysis;
}
