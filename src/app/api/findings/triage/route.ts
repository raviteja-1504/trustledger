/**
 * Finding triage API (see lib/findingLifecycle.ts)
 *
 * GET    /api/findings/triage?repo=owner/name → every decision for the repo, keyed by fingerprint
 * POST   /api/findings/triage                 → accept a finding's risk, or mark it a false positive
 * DELETE /api/findings/triage                 → reopen: remove the decision
 *
 * A decision is keyed by the finding's stable fingerprint, so it follows the finding across pushes and PRs.
 * It takes effect on the next scan (merge gating and annotations); the PR page offers a rescan.
 * Writing requires security_reviewer or admin, and every change is written to the audit log.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { validateBody, FindingTriageSchema, FindingReopenSchema } from "@/lib/validation";
import { safeError } from "@/lib/errors";
import { loadTriage } from "@/lib/findingTriageStore";

const MIGRATION_HINT = "Finding triage isn't set up on this database yet (migration 20260930_finding_triage_scan_health).";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const repo = req.nextUrl.searchParams.get("repo");
  if (!repo) return NextResponse.json({ error: "repo_required" }, { status: 400 });
  const triage = await loadTriage(createServiceClient(), auth.org_id, repo);
  return NextResponse.json({ triage: Object.fromEntries(triage) });
}

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "security_reviewer");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const v = await validateBody(req, FindingTriageSchema);
  if (!v.ok) return v.response;
  const body = v.data;
  const db = createServiceClient();
  const expires_at = body.expires_in_days ? new Date(Date.now() + body.expires_in_days * 86_400_000).toISOString() : null;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error } = await (db.from("finding_triage" as any) as any).upsert({
    org_id: auth.org_id, repo_full_name: body.repo, fingerprint: body.fingerprint,
    rule_id: body.rule_id, file_path: body.file_path ?? null,
    status: body.status, reason: body.reason, expires_at,
    set_by_email: auth.actor_email ?? null, set_at: new Date().toISOString(),
  }, { onConflict: "org_id,repo_full_name,fingerprint" });
  if (error) return safeError(error, { code: "finding_triage_failed", message: `We couldn't save that decision. ${MIGRATION_HINT}` });

  await writeAuditLog(db, {
    org_id: auth.org_id, event_type: "finding_triaged",
    actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "finding", resource_id: body.fingerprint,
    payload: { repo: body.repo, rule_id: body.rule_id, file_path: body.file_path ?? null, status: body.status, reason: body.reason, expires_at },
  });
  return NextResponse.json({ ok: true, decision: { status: body.status, reason: body.reason, expires_at, set_by_email: auth.actor_email ?? null } });
}

export async function DELETE(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "security_reviewer");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const v = await validateBody(req, FindingReopenSchema);
  if (!v.ok) return v.response;
  const db = createServiceClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error } = await (db.from("finding_triage" as any) as any).delete()
    .eq("org_id", auth.org_id).eq("repo_full_name", v.data.repo).eq("fingerprint", v.data.fingerprint);
  if (error) return safeError(error, { code: "finding_reopen_failed", message: `We couldn't reopen that finding. ${MIGRATION_HINT}` });

  await writeAuditLog(db, {
    org_id: auth.org_id, event_type: "finding_reopened",
    actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "finding", resource_id: v.data.fingerprint,
    payload: { repo: v.data.repo },
  });
  return NextResponse.json({ ok: true });
}
