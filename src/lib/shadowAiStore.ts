/**
 * Server-side reads for Shadow AI, shared by /api/shadow-ai and the Trust Score (governanceScoreLoader.ts).
 * Every read is best-effort: before migration 20261020_shadow_ai.sql, policy reads as null and triage as empty.
 * Server-only (service-role client).
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { normalizePolicy } from "./aiTools";
import { deliverAlert } from "./alertDelivery";
import { buildDetections, summarize, type ScanRow, type FileRow, type TriageRow, type ShadowStatus, type Detection, type ShadowSummary } from "./shadowAi";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

export interface StoredPolicy { allowed: string[]; updated_at?: string; updated_by?: string | null }

export async function loadPolicy(db: Db, orgId: string): Promise<StoredPolicy | null> {
  const { data, error } = await db.from("organizations").select("ai_tool_policy").eq("id", orgId).maybeSingle() as
    { data: { ai_tool_policy?: { allowed?: unknown; updated_at?: string; updated_by?: string | null } | null } | null; error: unknown };
  if (error || !data?.ai_tool_policy) return null;
  const p = data.ai_tool_policy;
  return { allowed: normalizePolicy(p.allowed), updated_at: p.updated_at, updated_by: p.updated_by };
}

export async function loadTriage(db: Db, orgId: string): Promise<Map<string, TriageRow>> {
  const { data, error } = await db.from("shadow_ai_triage").select("detection_key, status, notes, updated_at").eq("org_id", orgId) as
    { data: Array<{ detection_key: string; status: ShadowStatus; notes: TriageRow["notes"] | null; updated_at: string }> | null; error: unknown };
  if (error || !data) return new Map();
  return new Map(data.map(r => [r.detection_key, { status: r.status, notes: Array.isArray(r.notes) ? r.notes : [], updated_at: r.updated_at }]));
}

/**
 * Tell the org about unapproved AI tools in a pull request: one in-app alert, delivered through the org's own
 * alert channels (Slack, Teams), like SLA alerts. Once per (repo, PR, set of tools), so repeated pushes of the same
 * PR don't repeat it; a NEW unapproved tool in a later push is a new alert. Returns whether an alert was raised.
 */
export async function notifyUnapprovedTools(
  db: Db, orgId: string,
  pr: { repo: string; pr_number: number; scan_id: string; author: string | null },
  found: ReadonlyArray<{ tool: string; label: string }>,
): Promise<boolean> {
  if (found.length === 0) return false;
  const tools = [...found].map(f => f.label).sort();
  const title = `Unapproved AI tool${tools.length > 1 ? "s" : ""} in ${pr.repo.split("/").pop()} #${pr.pr_number}: ${tools.join(", ")}`;
  const { data: existing } = await db.from("alerts").select("id").eq("org_id", orgId).eq("alert_type", "shadow_ai").eq("repo", pr.repo).eq("title", title).limit(1);
  if (existing && existing.length > 0) return false;

  const body = `Pull request #${pr.pr_number} in ${pr.repo}${pr.author ? ` by ${pr.author}` : ""} shows evidence of ${tools.join(", ")}, which ${tools.length > 1 ? "are" : "is"} not on your approved AI tools list. The merge is not blocked. Review it in Shadow AI.`;
  const { data: alert } = await db.from("alerts").insert({
    org_id: orgId, alert_type: "shadow_ai", severity: "P3", status: "firing",
    title, body, repo: pr.repo, scan_id: pr.scan_id, fired_at: new Date().toISOString(), escalation_emails: [],
  }).select("id").single() as { data: { id: string } | null };
  if (!alert) return false;

  const { data: org } = await db.from("organizations").select("name, slack_webhook, teams_webhook").eq("id", orgId).maybeSingle() as
    { data: { name?: string; slack_webhook?: string | null; teams_webhook?: string | null } | null };
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "";
  try {
    await deliverAlert(
      { slack_webhook: org?.slack_webhook || undefined, teams_webhook: org?.teams_webhook || undefined },
      { alert_id: alert.id, severity: "P3", title, body, repo: pr.repo, scan_id: pr.scan_id, pr_number: pr.pr_number, org_name: org?.name ?? orgId, app_url: appUrl, href: appUrl ? `${appUrl}/shadow-ai` : undefined },
    );
  } catch { /* the in-app alert stands even if a channel fails */ }
  return true;
}

/** Repositories with no open (or investigating) unapproved-tool detection left -- whose Shadow AI alerts are done. */
export function clearedRepos(detections: readonly Detection[], repos: readonly string[]): string[] {
  const open = new Set(detections.filter(d => d.violation && (d.status === "open" || d.status === "investigating")).map(d => d.repo));
  return repos.filter(r => !open.has(r));
}

/**
 * Resolve firing Shadow AI alerts of repositories that no longer have an open unapproved-tool detection -- after a
 * reviewer accepts or resolves them, or the tool is approved. They used to stay firing forever. Best-effort.
 */
export async function resolveClearedShadowAlerts(db: Db, orgId: string): Promise<string[]> {
  try {
    const { data: firing } = await db.from("alerts").select("repo").eq("org_id", orgId).eq("alert_type", "shadow_ai")
      .in("status", ["firing", "acknowledged", "snoozed"]) as { data: Array<{ repo: string | null }> | null };
    const repos = [...new Set((firing ?? []).map(a => a.repo).filter((r): r is string => !!r))];
    if (repos.length === 0) return [];
    const { detections } = await loadShadowAi(db, orgId, 180);
    const done = clearedRepos(detections, repos);
    if (done.length > 0) {
      await db.from("alerts").update({ status: "resolved", resolved_at: new Date().toISOString() })
        .eq("org_id", orgId).eq("alert_type", "shadow_ai").in("repo", done).in("status", ["firing", "acknowledged", "snoozed"]);
    }
    return done;
  } catch { return []; }
}

const IN_CHUNK = 200;
export const MAX_SHADOW_SCANS = 1000;

/** Detections and summary for an org over the last `days`, optionally limited to one PR author. */
export async function loadShadowAi(db: Db, orgId: string, days: number, prAuthor?: string | null): Promise<{
  policy: StoredPolicy | null; detections: Detection[]; summary: ShadowSummary; truncated: boolean;
}> {
  const since = new Date(Date.now() - days * 86400_000).toISOString();
  let q = db.from("scans")
    .select("id, repo_full_name, pr_number, pr_author, created_at, ai_tooling")
    .eq("org_id", orgId).gte("created_at", since)
    .order("created_at", { ascending: false }).limit(MAX_SHADOW_SCANS);
  if (prAuthor) q = q.eq("pr_author", prAuthor);
  const { data: scans, error } = await q as { data: ScanRow[] | null; error: unknown };
  if (error) throw new Error("db_error");

  const ids = (scans ?? []).map(s => s.id);
  const files: FileRow[] = [];
  for (let i = 0; i < ids.length; i += IN_CHUNK) {
    const { data } = await db.from("scan_files").select("scan_id, file_path, attribution").eq("org_id", orgId).in("scan_id", ids.slice(i, i + IN_CHUNK)) as { data: FileRow[] | null };
    files.push(...(data ?? []));
  }
  const [policy, triage] = await Promise.all([loadPolicy(db, orgId), loadTriage(db, orgId)]);
  const detections = buildDetections(scans ?? [], files, policy?.allowed ?? null, triage);
  return { policy, detections, summary: summarize(detections, policy?.allowed ?? null), truncated: (scans ?? []).length >= MAX_SHADOW_SCANS };
}
