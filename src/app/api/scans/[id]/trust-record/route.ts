/**
 * Trust Record export (see lib/trustRecord.ts)
 *
 * GET /api/scans/:id/trust-record → a signed JSON document for this scan: the change, the engine and
 * coverage, every security finding (confidence, introduced-by-PR, triage decision), AI share per file,
 * reviewer attestations and the merge-gate outcome. Signed over the canonical JSON of `record`: Ed25519
 * (public-key, independently verifiable) when configured, else legacy HMAC-SHA256 -- see lib/trustRecord.ts.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";
import { loadTriage } from "@/lib/findingTriageStore";
import { buildTrustRecord, buildTrustRecordSignature } from "@/lib/trustRecord";
import type { ScanHealth } from "@/lib/scanHealth";
import type { FileIndicator } from "@/types";

export async function GET(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const params = await ctx.params;
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const db = createServiceClient();

  try {
    const { data: scan } = await db
      .from("scans")
      .select("id, repo_full_name, pr_number, commit_sha, created_at, overall_risk, total_ai_percentage, triggered_by, duration_ms")
      .eq("id", params.id).eq("org_id", auth.org_id).single();
    if (!scan) return NextResponse.json({ error: "scan_not_found" }, { status: 404 });

    const [{ data: files }, { data: atts }, { count: blocking }, { data: org }, triage, health] = await Promise.all([
      db.from("scan_files").select("file_path, risk_score, ai_percentage, indicators").eq("scan_id", scan.id).eq("org_id", auth.org_id),
      db.from("attestations").select("file_path, reviewer_email, reviewer_github, payload_hash, created_at").eq("scan_id", scan.id),
      db.from("violations").select("id", { count: "exact", head: true }).eq("scan_id", scan.id).neq("status", "resolved").in("risk_score", ["CRITICAL", "HIGH"]),
      db.from("organizations").select("name").eq("id", auth.org_id).single(),
      loadTriage(db, auth.org_id, scan.repo_full_name),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (db.from("scans") as any).select("health").eq("id", scan.id).single().then((r: { data?: { health?: ScanHealth | null } | null }) => r?.data?.health ?? null, () => null),
    ]);

    const generated_at = new Date().toISOString();
    const record = buildTrustRecord({
      org_name: (org as { name?: string } | null)?.name ?? null,
      scan: {
        id: scan.id, repo: scan.repo_full_name, pr_number: scan.pr_number, commit_sha: scan.commit_sha, created_at: scan.created_at,
        overall_risk: scan.overall_risk, total_ai_percentage: scan.total_ai_percentage ?? 0,
        triggered_by: scan.triggered_by ?? null, duration_ms: scan.duration_ms ?? null,
      },
      engine_version: (health as ScanHealth | null)?.engine_version ?? null,
      health: health as ScanHealth | null,
      files: (files ?? []).map(f => ({
        file_path: f.file_path, risk_score: f.risk_score, ai_percentage: f.ai_percentage ?? 0,
        indicators: Array.isArray(f.indicators) ? f.indicators as FileIndicator[] : [],
      })),
      attestations: (atts ?? []).map(a => ({
        file_path: a.file_path, reviewer_email: a.reviewer_email ?? null, reviewer_github: a.reviewer_github ?? null,
        payload_hash: a.payload_hash ?? null, created_at: a.created_at ?? null,
      })),
      triage,
      open_blocking_violations: blocking ?? 0,
      generated_at,
    });

    // Public-key (Ed25519) when EXPORT_SIGNING_PRIVATE_KEY is set, so auditors verify independently; otherwise
    // the legacy HMAC scheme, or unsigned when no key is configured (see lib/trustRecord.ts).
    const signature = buildTrustRecordSignature(record, process.env.EXPORT_SIGNING_KEY ?? process.env.CRON_SECRET);

    await writeAuditLog(db, {
      org_id: auth.org_id, event_type: "report_generated",
      actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
      resource_type: "scan", resource_id: scan.id,
      payload: { kind: "trust_record", repo: scan.repo_full_name, pr_number: scan.pr_number, commit: scan.commit_sha, signed: !!signature },
    });

    const filename = `trust-record-${scan.repo_full_name.replace(/[^\w.-]+/g, "-")}-pr${scan.pr_number}-${scan.commit_sha.slice(0, 8)}.json`;
    return new NextResponse(JSON.stringify({ record, signature }, null, 2), {
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="${filename}"`,
        ...(signature ? { "X-TrustLedger-Signature": signature.value } : {}),
      },
    });
  } catch (err) {
    return safeError(err, { code: "trust_record_failed", message: "We couldn't build the Trust Record for this scan. Please try again." });
  }
}
