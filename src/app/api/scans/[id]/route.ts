import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { analyzeFile, getFixSuggestions } from "@/lib/scanner";
import { toStoredIndicators } from "@/lib/indicatorStorage";
import { fetchContentByHash } from "@/lib/contentByHash";
import { filesWithCrossFileContext } from "@/lib/findingCorrelation";
import { cached, cacheGet, cacheSet, TTL } from "@/lib/cache";
import type { AttributionResult } from "@/lib/aiAttribution";
import type { FileIndicator } from "@/types";

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
const MAX_LIVE_REANALYSIS_FILES = 60;

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
  return cached(`reanalysis:v${REANALYSIS_CACHE_VERSION}:${contentHash}`, TTL.SCAN, async () => {
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
  const { data } = await db
    .from("scan_files")
    .select("file_path, language, ai_percentage, risk_score, risk_indicators, content_hash, line_count, content, indicators, attribution")
    .eq("scan_id", scanId)
    .eq("org_id", orgId)
    .order("ai_percentage", { ascending: false });
  const rows = (data ?? []) as ScanFileRow[];
  const missing = rows.filter(f => !f.content && f.content_hash).map(f => f.content_hash);
  if (missing.length > 0) {
    const byHash = await fetchContentByHash(db, orgId, missing);
    for (const f of rows) if (!f.content && f.content_hash) f.content = byHash.get(f.content_hash) ?? null;
  }
  return rows;
}

export async function GET(
  req: NextRequest,
  { params }: { params: { id: string } },
) {
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
  const filesKey = `scanfiles:v1:${params.id}`;
  let files = await cacheGet<ScanFileRow[]>(filesKey);
  if (!files) {
    files = await loadScanFiles(db, org_id, params.id);
    if (files.length > 0) await cacheSet(filesKey, files, TTL.SCAN);
  }

  const { data: attests } = await db
    .from("attestations")
    .select("file_path")
    .eq("scan_id", params.id);

  const attestedSet = new Set((attests ?? []).map(a => a.file_path));

  // Files whose stored findings depend on other files (a flow crosses them, a backlink, a folded duplicate):
  // they must not be re-analysed in isolation below.
  const crossFileContext = filesWithCrossFileContext(files.map(f => ({
    file_path: f.file_path,
    indicators: Array.isArray(f.indicators) ? f.indicators as FileIndicator[] : [],
  })));

  return NextResponse.json({
    scan_id:             scan.id,
    repo:                scan.repo_full_name,
    pr_number:           scan.pr_number,
    commit_sha:          scan.commit_sha,
    overall_risk:        scan.overall_risk,
    total_ai_percentage: scan.total_ai_percentage,
    timestamp:           scan.created_at,
    evidence_breakdown:  scan.evidence_breakdown ?? null,
    ai_tooling:          scan.ai_tooling ?? [],
    check_run_sync_error: scan.check_run_sync_error ?? null,
    files: await Promise.all((files ?? []).map(async (f, i) => {
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
      let freshIndicators: FileIndicator[] | null = null;
      let freshAttribution: AttributionResult | null = null;
      // A file tied to other files by a data flow keeps its stored result: re-analysed alone it would lose the
      // cross-file finding (or re-report a duplicate the scan folded into another file's finding).
      if (content && i < MAX_LIVE_REANALYSIS_FILES && !crossFileContext.has(f.file_path)) {
        try {
          const result = await reanalyze(f.file_path, content, f.content_hash);
          freshIndicators = result.indicators;
          freshAttribution = result.attribution;
        } catch { /* re-analysis threw — freshIndicators/freshAttribution stay null, falls back below */ }
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
    })),
  });
}
