/**
 * Shadow AI (see lib/shadowAi.ts)
 *
 * GET   /api/shadow-ai?days=30            → { policy, detections, summary, window_days }
 * PUT   /api/shadow-ai { allowed: [...] }  → set the approved-tools policy       (can_manage_policies)
 * PATCH /api/shadow-ai { key, status?, note? } → triage one detection           (can_resolve_violations)
 *
 * Detections come from what scans already store (scans.ai_tooling, scan_files.attribution). Developers see only
 * detections from their own pull requests, as on /api/scans -- this data names people.
 * Before migration 20261020_shadow_ai.sql is applied, GET still works (no policy, no triage) and writes 503.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { normalizePolicy, AI_TOOLS } from "@/lib/aiTools";
import { summarize, type ShadowStatus } from "@/lib/shadowAi";
import { loadPolicy, loadTriage, loadShadowAi, resolveClearedShadowAlerts } from "@/lib/shadowAiStore";

const STATUSES: readonly ShadowStatus[] = ["open", "investigating", "acceptable", "resolved"];

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const { org_id, role, user_id } = auth;
  const days = Math.min(Math.max(parseInt(req.nextUrl.searchParams.get("days") ?? "30") || 30, 1), 180);
  const db = createServiceClient();

  let ownLogin: string | null = null;
  if (role === "developer" && user_id) {
    const { data: me } = await db.from("org_members").select("github_login").eq("org_id", org_id).eq("user_id", user_id).maybeSingle() as { data: { github_login?: string | null } | null };
    ownLogin = me?.github_login ?? null;
    if (!ownLogin) {
      const policy = await loadPolicy(db, org_id);
      return NextResponse.json({ policy, tools: AI_TOOLS, detections: [], summary: summarize([], policy?.allowed ?? null), window_days: days, scope: "own" });
    }
  }

  let loaded;
  try { loaded = await loadShadowAi(db, org_id, days, ownLogin); }
  catch { return NextResponse.json({ error: "db_error" }, { status: 500 }); }
  return NextResponse.json({
    policy: loaded.policy, tools: AI_TOOLS, detections: loaded.detections, summary: loaded.summary,
    window_days: days, scope: ownLogin ? "own" : "org", truncated: loaded.truncated,
  });
}

export async function PUT(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_manage_policies");
  if (permErr) return NextResponse.json({ error: permErr, message: "Only people who can manage policies can change approved AI tools." }, { status: 403 });

  const body = await req.json().catch(() => ({})) as { allowed?: unknown };
  if (!Array.isArray(body.allowed)) return NextResponse.json({ error: "invalid_policy", message: "Send { allowed: [tool ids] }." }, { status: 400 });
  const allowed = normalizePolicy(body.allowed);
  const db = createServiceClient();
  const previous = await loadPolicy(db, auth.org_id);
  const value = { allowed, updated_at: new Date().toISOString(), updated_by: auth.actor_email ?? null };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error } = await (db.from("organizations") as any).update({ ai_tool_policy: value }).eq("id", auth.org_id);
  if (error) return NextResponse.json({ error: "not_available", message: "Saving the AI tool policy needs the 20261020_shadow_ai migration." }, { status: 503 });

  await writeAuditLog(db, {
    org_id: auth.org_id, event_type: "ai_tool_policy_changed", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "ai_tool_policy", resource_id: auth.org_id,
    payload: { allowed, previous: previous?.allowed ?? null },
  });
  // Approving a tool can leave a repository with nothing open: its Shadow AI alerts are done.
  await resolveClearedShadowAlerts(db, auth.org_id);
  return NextResponse.json({ policy: value });
}

export async function PATCH(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_resolve_violations");
  if (permErr) return NextResponse.json({ error: permErr, message: "Only reviewers can triage Shadow AI detections." }, { status: 403 });

  const body = await req.json().catch(() => ({})) as { key?: unknown; status?: unknown; note?: unknown };
  const key = typeof body.key === "string" ? body.key : "";
  if (!key || key.length > 600 || key.split("|").length < 3) return NextResponse.json({ error: "invalid_key" }, { status: 400 });
  const status = body.status === undefined ? undefined : STATUSES.find(s => s === body.status);
  if (body.status !== undefined && !status) return NextResponse.json({ error: "invalid_status" }, { status: 400 });
  const note = typeof body.note === "string" ? body.note.trim().slice(0, 2000) : "";
  if (!status && !note) return NextResponse.json({ error: "nothing_to_change" }, { status: 400 });

  const db = createServiceClient();
  const existing = (await loadTriage(db, auth.org_id)).get(key);
  const now = new Date().toISOString();
  const row = {
    org_id: auth.org_id, detection_key: key,
    status: status ?? existing?.status ?? "open",
    notes: note ? [...(existing?.notes ?? []), { at: now, by: auth.actor_email ?? null, text: note }] : existing?.notes ?? [],
    updated_by_email: auth.actor_email ?? null, updated_at: now,
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error } = await (db.from("shadow_ai_triage") as any).upsert({ ...row, org_id: auth.org_id }, { onConflict: "org_id,detection_key" });
  if (error) return NextResponse.json({ error: "not_available", message: "Saving triage needs the 20261020_shadow_ai migration." }, { status: 503 });

  await writeAuditLog(db, {
    org_id: auth.org_id, event_type: "shadow_ai_triaged", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "shadow_ai_detection", resource_id: key,
    payload: { status: row.status, previous_status: existing?.status ?? null, note_added: !!note },
  });
  // Accepting or resolving the last open detection in a repository ends its Shadow AI alerts.
  if (status === "acceptable" || status === "resolved") await resolveClearedShadowAlerts(db, auth.org_id);
  return NextResponse.json({ key, status: row.status, notes: row.notes, updated_at: now });
}
