import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { analyzeFile, type FunctionAIScore } from "@/lib/scanner";
import { cached, TTL } from "@/lib/cache";

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
  indicators: { id: string; label: string; severity: string; line?: number; detail?: string }[];
  function_scores: FunctionAIScore[];
}

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
  return cached(`reanalysis:${contentHash}`, TTL.SCAN, async () => {
    const analysis = analyzeFile(filePath, content);
    return {
      indicators: analysis.indicators
        .filter(i2 => i2.line != null)
        .map(i2 => ({ id: i2.id, label: i2.label, severity: i2.severity, line: i2.line, detail: i2.detail })),
      function_scores: analysis.function_scores,
    };
  });
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
    .select("id, repo_full_name, pr_number, commit_sha, branch, overall_risk, total_ai_percentage, created_at, evidence_breakdown, repository_trust")
    .eq("id", params.id)
    .eq("org_id", org_id)
    .single();

  if (!scan) return NextResponse.json({ error: "scan_not_found" }, { status: 404 });

  const { data: files } = await db
    .from("scan_files")
    .select("file_path, language, ai_percentage, risk_score, risk_indicators, content_hash, line_count, content, indicators")
    .eq("scan_id", params.id)
    .order("ai_percentage", { ascending: false });

  // Unchanged files carried forward across an incremental (delta) scan don't
  // store their own copy of `content` -- see api/scan-worker/route.ts's
  // "inherited files" comment -- so backfill it here from whichever row for
  // this org still has it under the same content_hash. One extra query,
  // only when needed, instead of storing the same source text N times over
  // for a file untouched across N pushes to the same PR.
  const missingHashes = [...new Set(
    (files ?? []).filter(f => !f.content && f.content_hash).map(f => f.content_hash as string),
  )];
  const contentByHash = new Map<string, string>();
  if (missingHashes.length > 0) {
    const { data: rows } = await db
      .from("scan_files")
      .select("content_hash, content")
      .eq("org_id", org_id)
      .in("content_hash", missingHashes)
      .not("content", "is", null);
    for (const r of rows ?? []) {
      if (!contentByHash.has(r.content_hash) && r.content) contentByHash.set(r.content_hash, r.content);
    }
  }

  const { data: attests } = await db
    .from("attestations")
    .select("file_path")
    .eq("scan_id", params.id);

  const attestedSet = new Set((attests ?? []).map(a => a.file_path));

  return NextResponse.json({
    scan_id:             scan.id,
    repo:                scan.repo_full_name,
    pr_number:           scan.pr_number,
    commit_sha:          scan.commit_sha,
    overall_risk:        scan.overall_risk,
    total_ai_percentage: scan.total_ai_percentage,
    timestamp:           scan.created_at,
    evidence_breakdown:  scan.evidence_breakdown ?? null,
    repository_trust:    scan.repository_trust ?? null,
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
      const content = f.content ?? (f.content_hash ? contentByHash.get(f.content_hash) : undefined) ?? null;
      const storedIndicators = Array.isArray(f.indicators) && f.indicators.length > 0
        ? f.indicators as { id: string; label: string; severity: string; line?: number; detail?: string }[]
        : null;
      let freshIndicators: { id: string; label: string; severity: string; line?: number; detail?: string }[] | null = null;
      // function_scores was never persisted at scan time (added after this
      // re-analysis-on-read pattern already existed), so it's only available
      // for files that get live re-analysis; empty beyond the cap.
      let functionScores: FunctionAIScore[] = [];
      if (content && i < MAX_LIVE_REANALYSIS_FILES) {
        try {
          const result = await reanalyze(f.file_path, content, f.content_hash);
          freshIndicators = result.indicators;
          functionScores  = result.function_scores;
        } catch { /* re-analysis threw — freshIndicators stays null, falls back below */ }
      }
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
        indicators:      freshIndicators ?? storedIndicators ?? [],
        function_scores: functionScores,
        attested:        attestedSet.has(f.file_path),
        content:         content ?? undefined,
      };
    })),
  });
}
