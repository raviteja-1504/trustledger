import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { analyzeFile, getFixSuggestions, CURRENT_ENGINE_VERSION, isNonAuthoredFile } from "@/lib/scanner";
import { summarizeAIAttribution } from "@/lib/aiAttributionSummary";
import { ensureTaintEngines } from "@/lib/engineWarmup";
import { loadTriage } from "@/lib/findingTriageStore";
import { findingStatus, fixedSincePrevious, summarize, type FindingStatus, type PrHistory } from "@/lib/findingLifecycle";
import type { ScanHealth, ScanTelemetry } from "@/lib/scanHealth";
import { toStoredIndicators } from "@/lib/indicatorStorage";
import { fetchContentByHash } from "@/lib/contentByHash";
import { allRows } from "@/lib/allRows";
import { filesWithCrossFileContext } from "@/lib/findingCorrelation";
import { memoryCached, cacheGet, cacheSet, TTL } from "@/lib/cache";
import type { AttributionResult } from "@/lib/aiAttribution";
import type { FileIndicator } from "@/types";
import { CAPS } from "@/lib/limits";

// Hard bound on worst-case execution time. analyzeFile() is fully
// synchronous (regex/string analysis, no I/O) -- if one file's content
// ever triggers catastrophic regex backtracking in any of the dozens of
// patterns it runs, nothing in-process can interrupt that call once it
// starts (JS timers can't preempt a running synchronous call on the same
// thread). This is the platform-level backstop: without it, a genuine
// hang here runs (and bills) indefinitely instead of failing cleanly.
export const maxDuration = 60;

// Live re-analysis (see the comment below) is only worth its cost for a
// bounded number of files per request -- beyond this, fall back to the
// snapshot already persisted at scan time rather than growing worst-case
// latency linearly with scan size (some scans in this org have 1000+ files).
const MAX_LIVE_REANALYSIS_FILES = CAPS.liveReanalysisFiles.value;

interface ReanalysisResult {
  indicators: FileIndicator[];
  attribution: AttributionResult;
}

// Part of the cache key: bump whenever toStoredIndicators() starts carrying new fields, so entries cached
// before a deploy (which lack them) are not served for the rest of their TTL.
const REANALYSIS_CACHE_VERSION = 2;

// Re-running analyzeFile() (AST/SSA/semantic-graph/ML-classifier/47-signal
// analysis) on every page load showed up as sustained high Active CPU for
// this route in Vercel's fluid-compute metrics -- the "cheap" assumption in
// the comment below didn't hold once real traffic hit it. The result is a
// pure function of (file content, scanner logic): for the same content_hash
// it's identical every time, so there's no reason to pay that CPU cost more
// than once per (content, scanner-behavior-at-time-of-caching) pair.
// Cached for TTL.SCAN (1h) -- long enough to absorb repeat views of the same
// PR (by the same or different reviewers) and unchanged files reused across
// incremental scans (same content_hash), short enough that a scanner
// false-positive fix still reaches the page within the hour without a new
// scan needing to run.
async function reanalyze(filePath: string, content: string, contentHash: string): Promise<ReanalysisResult> {
  // This instance's memory, NOT Redis: a first view of a scan re-analyses every file, and as a Redis entry each one cost a read AND a write
  // (two commands per file: thousands for one page open). The scan-level result is cached as ONE key below (scanlive:...), which is what
  // repeat views use; this layer only saves CPU when files repeat within one instance.
  return memoryCached(`reanalysis:v${REANALYSIS_CACHE_VERSION}:${contentHash}`, TTL.SCAN, async () => {
    const analysis = analyzeFile(filePath, content);
    return {
      indicators: toStoredIndicators(analysis.indicators),
      attribution: analysis.attribution,
    };
  });
}

interface ScanFileRow {
  file_path: string; language: string | null; ai_percentage: number; risk_score: string;
  risk_indicators: string[] | null; content_hash: string; line_count: number;
  content: string | null; indicators: unknown; attribution: unknown;
}

/** A scan's file rows, with the source of files inherited across incremental scans (stored without their
 * own `content`, see api/scan-worker/route.ts) backfilled by content_hash -- one copy per hash. */
async function loadScanFiles(db: ReturnType<typeof createServiceClient>, orgId: string, scanId: string): Promise<ScanFileRow[]> {
  // Paged: a 1,242-file scan was cut to 1000 files by the per-request row cap (lib/allRows.ts).
  const { data } = await allRows<ScanFileRow>((from, to) => db
    .from("scan_files")
    .select("file_path, language, ai_percentage, risk_score, risk_indicators, content_hash, line_count, content, indicators, attribution")
    .eq("scan_id", scanId)
    .eq("org_id", orgId)
    .order("ai_percentage", { ascending: false })
    .order("file_path", { ascending: true })
    .range(from, to) as unknown as PromiseLike<{ data: ScanFileRow[] | null; error: unknown }>);
  const rows = data;
  const missing = rows.filter(f => !f.content && f.content_hash).map(f => f.content_hash);
  if (missing.length > 0) {
    const byHash = await fetchContentByHash(db, orgId, missing);
    for (const f of rows) if (!f.content && f.content_hash) f.content = byHash.get(f.content_hash) ?? null;
  }
  return rows;
}

const MAX_HISTORY_SCANS = 6;

type StoredIndicatorLite = { id: string; label: string; line?: number; fingerprint?: string };

/** Fingerprints from this PR's earlier scans (see findingLifecycle.ts PrHistory): the scan just before this
 * one, and the few before that. Only `file_path` and `indicators` are read -- never file content. */
async function loadPrHistoryFromDb(
  db: ReturnType<typeof createServiceClient>, orgId: string, repo: string, prNumber: number, createdAt: string, scanId: string,
): Promise<PrHistory & { previousFiles: Array<{ file_path: string; indicators: StoredIndicatorLite[] }> | null; previousScan: { scan_id: string; commit_sha: string; created_at: string } | null }> {
  const empty = { previous: null, earlier: new Set<string>(), previousFiles: null, previousScan: null };
  try {
    const { data: prior } = await db
      .from("scans")
      .select("id, commit_sha, created_at")
      .eq("org_id", orgId)
      .eq("repo_full_name", repo)
      .eq("pr_number", prNumber)
      .lt("created_at", createdAt)
      .neq("id", scanId)
      .order("created_at", { ascending: false })
      .limit(MAX_HISTORY_SCANS);
    if (!prior?.length) return empty;
    const { data: rows } = await allRows((from, to) => db
      .from("scan_files")
      .select("scan_id, file_path, indicators")
      .eq("org_id", orgId)
      .in("scan_id", prior.map(s => s.id))
      .order("scan_id", { ascending: true })
      .order("file_path", { ascending: true })
      .range(from, to));
    const byScan = new Map<string, Array<{ file_path: string; indicators: StoredIndicatorLite[] }>>();
    for (const r of rows ?? []) {
      const list = byScan.get(r.scan_id) ?? [];
      list.push({ file_path: r.file_path, indicators: Array.isArray(r.indicators) ? r.indicators as StoredIndicatorLite[] : [] });
      byScan.set(r.scan_id, list);
    }
    const fps = (files: Array<{ indicators: StoredIndicatorLite[] }>) => new Set(files.flatMap(f => f.indicators.map(i => i.fingerprint).filter((x): x is string => !!x)));
    const previousFiles = byScan.get(prior[0].id) ?? [];
    const earlier = new Set<string>();
    for (const s of prior.slice(1)) for (const fp of fps(byScan.get(s.id) ?? [])) earlier.add(fp);
    // Which scan the lifecycle compares with, so the page can say so ("compared with abc1234 from 3 Nov").
    // Only the fields the lifecycle reads are kept (not each finding's trace), which is what keeps this small enough to cache.
    const slimFiles = previousFiles.map(f => ({ file_path: f.file_path, indicators: f.indicators.filter(i => i.fingerprint).map(i => ({ id: i.id, label: i.label, line: i.line, fingerprint: i.fingerprint })) }));
    return { previous: fps(previousFiles), earlier, previousFiles: slimFiles, previousScan: { scan_id: prior[0].id, commit_sha: prior[0].commit_sha, created_at: prior[0].created_at } };
  } catch {
    return empty;
  }
}

type PrHistoryResult = Awaited<ReturnType<typeof loadPrHistoryFromDb>>;
type PrHistoryStored = { previous: string[]; earlier: string[]; previousFiles: PrHistoryResult["previousFiles"]; previousScan: PrHistoryResult["previousScan"] };

/** This scan's PR history. It is fixed once the scan exists (the earlier scans and their findings never change), but
 * reading it meant loading every file's findings from up to six earlier scans on EVERY view -- megabytes each time for
 * a large PR -- so the result is cached per scan. */
async function loadPrHistory(
  db: ReturnType<typeof createServiceClient>, orgId: string, repo: string, prNumber: number, createdAt: string, scanId: string,
): Promise<PrHistoryResult> {
  const key = `prhist:v1:${scanId}`;
  const hit = await cacheGet<PrHistoryStored>(key);
  if (hit) return { previous: new Set(hit.previous), earlier: new Set(hit.earlier), previousFiles: hit.previousFiles, previousScan: hit.previousScan };
  const result = await loadPrHistoryFromDb(db, orgId, repo, prNumber, createdAt, scanId);
  // An empty history is cheap to rebuild and also what a failed read returns, so only a real one is kept.
  if (result.previousScan) {
    await cacheSet<PrHistoryStored>(key, { previous: [...(result.previous ?? [])], earlier: [...result.earlier], previousFiles: result.previousFiles, previousScan: result.previousScan }, TTL.SCAN);
  }
  return result;
}

/** The scan's health and telemetry columns -- a separate, best-effort read so a database without them yet
 * (migration 20260930) still serves the scan. */
async function loadHealth(db: ReturnType<typeof createServiceClient>, scanId: string): Promise<{ health: ScanHealth | null; telemetry: ScanTelemetry | null }> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data, error } = await (db.from("scans") as any).select("health, telemetry").eq("id", scanId).single();
    if (error || !data) return { health: null, telemetry: null };
    return { health: (data.health as ScanHealth) ?? null, telemetry: (data.telemetry as ScanTelemetry) ?? null };
  } catch {
    return { health: null, telemetry: null };
  }
}

export async function GET(
  req: NextRequest,
  ctx: { params: Promise<{ id: string }> },
) {
  const params = await ctx.params;
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const db = createServiceClient();

  const { data: scan } = await db
    .from("scans")
    .select("id, repo_full_name, pr_number, commit_sha, branch, overall_risk, total_ai_percentage, created_at, evidence_breakdown, ai_tooling, check_run_sync_error")
    .eq("id", params.id)
    .eq("org_id", org_id)
    .single();

  if (!scan) return NextResponse.json({ error: "scan_not_found" }, { status: 404 });

  // A scan's file rows never change after the scan is written (attestation state comes from the
  // attestations table below, not from these rows), so repeat views of the same PR are served from the
  // cache instead of re-downloading every file's source from the database each time.
  // Never caches an empty result: the scan row is written before its files, and a view in between must
  // not pin an empty file list for the whole TTL.
  // v2: v1 entries could hold a list cut to 1000 rows (before lib/allRows.ts paging).
  const filesKey = `scanfiles:v2:${params.id}`;
  let files = await cacheGet<ScanFileRow[]>(filesKey);
  if (!files) {
    files = await loadScanFiles(db, org_id, params.id);
    if (files.length > 0) await cacheSet(filesKey, files, TTL.SCAN);
  }

  const { data: attests } = await allRows((from, to) => db
    .from("attestations")
    .select("file_path")
    .eq("scan_id", params.id)
    .order("file_path", { ascending: true })
    .range(from, to));

  const attestedSet = new Set(attests.map(a => a.file_path));

  // Files whose stored findings depend on other files (a flow crosses them, a backlink, a folded duplicate):
  // they must not be re-analysed in isolation below.
  const crossFileContext = filesWithCrossFileContext(files.map(f => ({
    file_path: f.file_path,
    indicators: Array.isArray(f.indicators) ? f.indicators as FileIndicator[] : [],
  })));

  // Live re-analysis below needs the data-flow engines loaded, or a cold instance would show fewer findings
  // than the scan stored (see engineWarmup.ts).
  // The re-analysed findings of this scan, computed once per (scan, scanner version) and reused: without this every
  // view loaded the data-flow engines (WASM parsers, on each cold instance) and walked the top files again, which was
  // this route's sustained Active CPU. A scanner change is a new CURRENT_ENGINE_VERSION, so it is a new key at once.
  const liveTargets = files.filter((f, i) => f.content && i < MAX_LIVE_REANALYSIS_FILES && !crossFileContext.has(f.file_path));
  const liveKey = `scanlive:v1:${CURRENT_ENGINE_VERSION}:${params.id}`;
  let live: Record<string, ReanalysisResult> | null = liveTargets.length > 0 ? await cacheGet<Record<string, ReanalysisResult>>(liveKey) : {};
  if (!live) {
    const fresh: Record<string, ReanalysisResult> = {};
    await ensureTaintEngines();
    await Promise.all(liveTargets.map(async f => {
      try { fresh[f.file_path] = await reanalyze(f.file_path, f.content as string, f.content_hash); }
      catch { /* re-analysis threw: this file falls back to its stored snapshot below */ }
    }));
    live = fresh;
    // Only a complete result is kept: one with a failed file would pin that file to its snapshot for the whole TTL.
    if (Object.keys(fresh).length === liveTargets.length) await cacheSet(liveKey, fresh, TTL.SCAN);
  }

  const outFiles = await Promise.all((files ?? []).map(async (f, i) => {
      // Prefer freshly re-analysed indicators (current scanner logic) over
      // the snapshot written at scan time — if detection patterns improve
      // later (false-positive fixes, new signals), files scanned before that
      // change would otherwise keep showing stale/incorrect highlighted
      // lines forever until a brand-new PR scan happens to run. reanalyze()
      // caches the actual analyzeFile() call by content_hash (see above),
      // so this is a cache lookup, not a full re-analysis, for any file
      // that's been viewed before.
      //
      // Capped to the first MAX_LIVE_REANALYSIS_FILES (query already orders
      // by ai_percentage desc, so this keeps the highest-signal files live
      // and lets large scans fall back to the persisted snapshot beyond
      // that, rather than paying analysis cost per file with no bound).
      const content = f.content ?? null;
      const storedIndicators = Array.isArray(f.indicators) && f.indicators.length > 0
        ? f.indicators as FileIndicator[]
        : null;
      const liveResult = live![f.file_path];
      let freshIndicators: FileIndicator[] | null = liveResult?.indicators ?? null;
      const freshAttribution: AttributionResult | null = liveResult?.attribution ?? null;
      // Facts only the scan itself knew (the PR diff behind `introduced`) survive live re-analysis: carried over
      // from the stored finding with the same fingerprint, or failing that the same rule on the same line.
      if (freshIndicators && storedIndicators) {
        const byFp = new Map(storedIndicators.filter(s => s.fingerprint).map(s => [s.fingerprint!, s]));
        const byLoc = new Map(storedIndicators.map(s => [`${s.id}:${s.line}`, s]));
        freshIndicators = freshIndicators.map(fi => {
          const prev = (fi.fingerprint && byFp.get(fi.fingerprint)) || byLoc.get(`${fi.id}:${fi.line}`);
          return prev?.introduced != null && fi.introduced == null ? { ...fi, introduced: prev.introduced } : fi;
        });
      }
      const indicators = freshIndicators ?? storedIndicators ?? [];
      return {
        file_path:       f.file_path,
        language:        f.language ?? "text",
        ai_percentage:   f.ai_percentage,
        risk_score:      f.risk_score,
        risk_indicators: f.risk_indicators ?? [],
        // Prefer freshly-computed indicators (current scanner logic, possibly
        // an empty array if a false positive was since fixed — that's a valid
        // result, not a failure). Only fall back to the stored snapshot if
        // content was unavailable or re-analysis threw (freshIndicators is
        // null in both cases, distinct from a legitimate empty array).
        indicators,
        fix_suggestions: getFixSuggestions(indicators),
        // Same freshness preference as indicators above -- attributeCode()'s
        // patterns can improve over time (see the requiresCoSignal hardening),
        // and this comes free from the same reanalyze() call.
        attribution:     freshAttribution ?? (f.attribution as AttributionResult | null) ?? undefined,
        attested:        attestedSet.has(f.file_path),
        content:         content ?? undefined,
      };
    }));

  // ── Lifecycle and triage (findingLifecycle.ts) ──────────────────────────────
  // Each finding's status from this PR's own scan history plus the repo's triage decisions, and the findings
  // the previous push had that this one no longer does.
  const [history, triage, extra] = await Promise.all([
    loadPrHistory(db, org_id, scan.repo_full_name, scan.pr_number, scan.created_at, scan.id),
    loadTriage(db, org_id, scan.repo_full_name),
    loadHealth(db, scan.id),
  ]);
  const now = new Date();
  const statuses: FindingStatus[] = [];
  const currentFps = new Set<string>();
  const filesWithStatus = outFiles.map(f => ({
    ...f,
    indicators: f.indicators.map(ind => {
      if (ind.fingerprint) currentFps.add(ind.fingerprint);
      const status = findingStatus(ind.fingerprint, history, triage, now);
      statuses.push(status);
      const decision = ind.fingerprint ? triage.get(ind.fingerprint) : undefined;
      return { ...ind, lifecycle_status: status, ...(decision ? { triage: decision } : {}) };
    }),
  }));
  const fixed = history.previousFiles
    ? fixedSincePrevious(history.previousFiles, currentFps, new Set(outFiles.map(f => f.file_path)))
    : [];

  return NextResponse.json({
    lifecycle: { summary: summarize(statuses, fixed.length), fixed: fixed.slice(0, CAPS.fixedFindingsListed.value), has_previous_scan: !!history.previous, previous_scan: history.previousScan },
    health: extra.health,
    telemetry: extra.telemetry,
    current_engine_version: CURRENT_ENGINE_VERSION,
    scan_id:             scan.id,
    repo:                scan.repo_full_name,
    pr_number:           scan.pr_number,
    commit_sha:          scan.commit_sha,
    overall_risk:        scan.overall_risk,
    total_ai_percentage: scan.total_ai_percentage,
    // By code volume, from the stored per-file scores (not live-re-analysed, so it matches what was recorded): see
    // aiAttributionSummary.ts. The confidence bands are not stored, so they stay 0 here.
    ai_attribution:      summarizeAIAttribution((files ?? []).map(f => ({ file_path: f.file_path, line_count: f.line_count, ai_percentage: f.ai_percentage })), isNonAuthoredFile),
    timestamp:           scan.created_at,
    evidence_breakdown:  scan.evidence_breakdown ?? null,
    ai_tooling:          scan.ai_tooling ?? [],
    check_run_sync_error: scan.check_run_sync_error ?? null,
    files: filesWithStatus,
  });
}
