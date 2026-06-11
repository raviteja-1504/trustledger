/**
 * Scan Comparison API
 * Compares two scans and returns a diff of risk changes.
 * GET /api/scans/compare?scan_a=<id>&scan_b=<id>
 *
 * Returns:
 *   - Files that worsened (risk increased)
 *   - Files that improved (risk decreased or attested)
 *   - New files (in scan_b not in scan_a)
 *   - Resolved files (in scan_a not in scan_b)
 *   - Overall risk change
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";

const RISK_RANK: Record<string, number> = {
  LOW:0, MEDIUM:1, HIGH:2, CRITICAL:3, UNKNOWN:-1,
};

type FileRow = { file_path: string; risk_score: string; ai_percentage: number; risk_indicators: string[] };

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url    = new URL(req.url);
  const scanA  = url.searchParams.get("scan_a");
  const scanB  = url.searchParams.get("scan_b");

  if (!scanA || !scanB) {
    return NextResponse.json({ error: "scan_a and scan_b required" }, { status: 400 });
  }

  const db = createServiceClient();

  // Fetch both scans + their files in parallel
  const [rA, rB, rFA, rFB] = await Promise.all([
    db.from("scans").select("id, repo_full_name, pr_number, commit_sha, overall_risk, total_ai_percentage, created_at").eq("id", scanA).eq("org_id", org_id).single(),
    db.from("scans").select("id, repo_full_name, pr_number, commit_sha, overall_risk, total_ai_percentage, created_at").eq("id", scanB).eq("org_id", org_id).single(),
    db.from("scan_files").select("file_path, risk_score, ai_percentage, risk_indicators").eq("scan_id", scanA),
    db.from("scan_files").select("file_path, risk_score, ai_percentage, risk_indicators").eq("scan_id", scanB),
  ]);

  const scanAMeta = rA.data as Record<string, unknown> | null;
  const scanBMeta = rB.data as Record<string, unknown> | null;
  const filesA    = rFA.data as FileRow[] | null;
  const filesB    = rFB.data as FileRow[] | null;

  if (!scanAMeta || !scanBMeta) {
    return NextResponse.json({ error: "one or both scans not found" }, { status: 404 });
  }

  const mapA = new Map((filesA ?? []).map(f => [f.file_path, f]));
  const mapB = new Map((filesB ?? []).map(f => [f.file_path, f]));

  const worsened:  Array<{ file: FileRow & { prev_risk: string }; prev: FileRow }> = [];
  const improved:  Array<{ file: FileRow; prev: FileRow & { prev_risk: string } }> = [];
  const unchanged: FileRow[] = [];
  const newFiles:  FileRow[] = [];
  const resolved:  FileRow[] = [];

  // Compare files in B against A
  for (const [path, fileB] of Array.from(mapB.entries())) {
    const fileA = mapA.get(path);
    if (!fileA) {
      newFiles.push(fileB);
      continue;
    }
    const rankA = RISK_RANK[fileA.risk_score] ?? -1;
    const rankB = RISK_RANK[fileB.risk_score] ?? -1;
    if (rankB > rankA) {
      worsened.push({ file: { ...fileB, prev_risk: fileA.risk_score }, prev: fileA });
    } else if (rankB < rankA) {
      improved.push({ file: fileB, prev: { ...fileA, prev_risk: fileA.risk_score } });
    } else {
      unchanged.push(fileB);
    }
  }

  // Files in A but not B (resolved/removed)
  for (const [path, fileA] of Array.from(mapA.entries())) {
    if (!mapB.has(path)) resolved.push(fileA);
  }

  // Overall risk delta
  const rankA = RISK_RANK[(scanAMeta.overall_risk as string) ?? "LOW"] ?? 0;
  const rankB = RISK_RANK[(scanBMeta.overall_risk as string) ?? "LOW"] ?? 0;
  const riskDelta = rankB - rankA; // positive = worse, negative = better

  return NextResponse.json({
    scan_a: { id: scanA, ...scanAMeta, file_count: (filesA ?? []).length },
    scan_b: { id: scanB, ...scanBMeta, file_count: (filesB ?? []).length },
    diff: {
      worsened:    worsened.sort((a, b) => RISK_RANK[b.file.risk_score] - RISK_RANK[a.file.risk_score]),
      improved:    improved.sort((a, b) => RISK_RANK[b.file.risk_score] - RISK_RANK[a.file.risk_score]),
      new_files:   newFiles,
      resolved:    resolved,
      unchanged:   unchanged.length,
    },
    summary: {
      risk_delta:      riskDelta,
      risk_direction:  riskDelta > 0 ? "worse" : riskDelta < 0 ? "better" : "same",
      files_worsened:  worsened.length,
      files_improved:  improved.length,
      files_added:     newFiles.length,
      files_resolved:  resolved.length,
      ai_pct_delta:    ((scanBMeta.total_ai_percentage as number) ?? 0) - ((scanAMeta.total_ai_percentage as number) ?? 0),
    },
  });
}
