/**
 * SARIF Export API
 * GET /api/export/sarif?scan_id=<uuid>
 *
 * Returns scan findings as a SARIF 2.1.0 log for upload to GitHub Code
 * Scanning (github/codeql-action/upload-sarif) or GitLab's Security
 * Dashboard. See src/lib/sarif.ts for the conversion logic.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../_middleware";
import { buildSarifReport, type SarifSourceFile } from "@/lib/sarif";
import { loadTriage } from "@/lib/findingTriageStore";
import { attachTriage } from "@/lib/findingLifecycle";
import { getFixSuggestions } from "@/lib/scanner";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = await requirePermission(auth, "can_export_data");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });
  const { org_id } = auth;

  const scanId = new URL(req.url).searchParams.get("scan_id");
  if (!scanId) return NextResponse.json({ error: "scan_id_required" }, { status: 400 });

  const db = createServiceClient();

  const { data: scan } = await db
    .from("scans")
    .select("id, repo_full_name")
    .eq("id", scanId)
    .eq("org_id", org_id)
    .maybeSingle() as { data: { id: string; repo_full_name: string } | null };

  if (!scan) return NextResponse.json({ error: "scan_not_found" }, { status: 404 });

  const { data: files } = await db
    .from("scan_files")
    .select("file_path, indicators")
    .eq("scan_id", scanId) as { data: SarifSourceFile[] | null };

  // Same triage decisions the dashboard and Trust Record apply, as SARIF suppressions.
  const withTriage = attachTriage(files ?? [], await loadTriage(db, org_id, scan.repo_full_name));
  const allIndicators = withTriage.flatMap(f => f.indicators ?? []);
  const fixesById = new Map(getFixSuggestions(allIndicators).map(fix => [fix.vuln_id, fix]));
  const sarif = buildSarifReport(withTriage, {
    name:           "TrustLedger",
    informationUri: process.env.NEXT_PUBLIC_APP_URL ?? "https://github.com/trustledger",
  }, fixesById);

  return new NextResponse(JSON.stringify(sarif, null, 2), {
    headers: {
      "Content-Type":        "application/sarif+json",
      "Content-Disposition": `attachment; filename="trustledger-${scanId}.sarif"`,
    },
  });
}
