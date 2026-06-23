import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { analyzeFile } from "@/lib/scanner";

export async function GET(
  req: NextRequest,
  { params }: { params: { id: string } },
) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const db = createServiceClient();

  const { data: scan } = await db
    .from("scans")
    .select("*")
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
    files: (files ?? []).map(f => {
      // Use stored indicators (with line numbers) if available; fall back to
      // re-analysing from content for older scans that predate the indicators column.
      const storedIndicators = Array.isArray(f.indicators) && f.indicators.length > 0
        ? f.indicators as { id: string; label: string; severity: string; line?: number; detail?: string }[]
        : null;
      const analysis = !storedIndicators && f.content ? analyzeFile(f.file_path, f.content) : null;
      return {
        file_path:       f.file_path,
        language:        f.language ?? "text",
        ai_percentage:   f.ai_percentage,
        risk_score:      f.risk_score,
        risk_indicators: f.risk_indicators ?? [],
        indicators:      storedIndicators
          ?? analysis?.indicators?.map(i => ({
            id: i.id, label: i.label, severity: i.severity, line: i.line, detail: i.detail,
          }))
          ?? [],
        attested:        attestedSet.has(f.file_path),
        content:         f.content ?? undefined,
      };
    }),
  });
}
