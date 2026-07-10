import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { analyzeFile, type FunctionAIScore } from "@/lib/scanner";

export async function GET(
  req: NextRequest,
  { params }: { params: { id: string } },
) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const db = createServiceClient();

  const { data: scan } = await db
    .from("scans")
    .select("id, repo_full_name, pr_number, commit_sha, branch, overall_risk, total_ai_percentage, created_at, evidence_breakdown")
    .eq("id", params.id)
    .eq("org_id", org_id)
    .single();

  if (!scan) return NextResponse.json({ error: "scan_not_found" }, { status: 404 });

  const { data: files } = await db
    .from("scan_files")
    .select("file_path, language, ai_percentage, risk_score, risk_indicators, content_hash, line_count, content, indicators")
    .eq("scan_id", params.id)
    .order("ai_percentage", { ascending: false });

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
    files: (files ?? []).map(f => {
      // Always re-run analyzeFile() on stored content when available, rather
      // than trusting scan_files.indicators as-is. Indicators are written once
      // at scan time — if the scanner's detection patterns are improved later
      // (false-positive fixes, new signals), files scanned before that change
      // would otherwise keep showing stale/incorrect highlighted lines forever
      // until a brand-new PR scan happens to run. Re-analysing on every page
      // load is cheap (in-memory regex, no network calls) and guarantees the
      // PR page always reflects the current scanner logic immediately.
      const storedIndicators = Array.isArray(f.indicators) && f.indicators.length > 0
        ? f.indicators as { id: string; label: string; severity: string; line?: number; detail?: string }[]
        : null;
      let freshIndicators: { id: string; label: string; severity: string; line?: number; detail?: string }[] | null = null;
      // function_scores was never persisted at scan time (added after this
      // re-analysis-on-read pattern already existed), so it's always
      // recomputed here rather than having a stored-snapshot fallback.
      let functionScores: FunctionAIScore[] = [];
      if (f.content) {
        try {
          const analysis = analyzeFile(f.file_path, f.content);
          freshIndicators = analysis.indicators
            .filter(i => i.line != null)
            .map(i => ({ id: i.id, label: i.label, severity: i.severity, line: i.line, detail: i.detail }));
          functionScores = analysis.function_scores;
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
        content:         f.content ?? undefined,
      };
    }),
  });
}
