/**
 * Baseline API
 *
 * POST /api/findings/baseline { scan_id, reason? } → accept every finding in that scan that has no decision
 * yet, as "accepted" with the given reason ("Baseline" by default). From then on only findings that are new
 * relative to the baseline count toward merge gating -- the usual way to adopt a scanner on an existing
 * code base without blocking every PR on old debt. Each baselined finding can still be reopened one by one.
 *
 * Requires security_reviewer or admin; written to the audit log as one event with the count.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { validateBody, FindingBaselineSchema } from "@/lib/validation";
import { safeError } from "@/lib/errors";
import { loadTriage } from "@/lib/findingTriageStore";

const MAX_BASELINE = 5000;

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = await requirePermission(auth, "can_resolve_violations");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const v = await validateBody(req, FindingBaselineSchema);
  if (!v.ok) return v.response;
  const db = createServiceClient();

  const { data: scan } = await db.from("scans").select("id, repo_full_name").eq("id", v.data.scan_id).eq("org_id", auth.org_id).single();
  if (!scan) return NextResponse.json({ error: "scan_not_found" }, { status: 404 });

  const { data: files } = await db.from("scan_files").select("file_path, indicators").eq("scan_id", scan.id).eq("org_id", auth.org_id);
  const existing = await loadTriage(db, auth.org_id, scan.repo_full_name);
  const reason = v.data.reason ?? "Baseline";
  const now = new Date().toISOString();
  const rows = new Map<string, Record<string, unknown>>();
  for (const f of files ?? []) {
    for (const i of (Array.isArray(f.indicators) ? f.indicators : []) as Array<{ id: string; fingerprint?: string }>) {
      if (!i.fingerprint || existing.has(i.fingerprint) || rows.has(i.fingerprint)) continue;
      rows.set(i.fingerprint, {
        org_id: auth.org_id, repo_full_name: scan.repo_full_name, fingerprint: i.fingerprint, rule_id: i.id, file_path: f.file_path,
        status: "accepted", reason, expires_at: null, set_by_email: auth.actor_email ?? null, set_at: now,
      });
      if (rows.size >= MAX_BASELINE) break;
    }
  }
  if (rows.size === 0) return NextResponse.json({ ok: true, baselined: 0 });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error } = await (db.from("finding_triage" as any) as any).upsert([...rows.values()], { onConflict: "org_id,repo_full_name,fingerprint" });
  if (error) return safeError(error, { code: "finding_baseline_failed", message: "We couldn't save the baseline. Finding triage may not be set up on this database yet (migration 20260930_finding_triage_scan_health)." });

  await writeAuditLog(db, {
    org_id: auth.org_id, event_type: "findings_baselined",
    actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "scan", resource_id: scan.id,
    payload: { repo: scan.repo_full_name, count: rows.size, reason },
  });
  return NextResponse.json({ ok: true, baselined: rows.size });
}
