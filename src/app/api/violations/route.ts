import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { validateBody, ViolationUpdateSchema } from "@/lib/validation";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const { org_id, role, user_id } = auth;

  const url    = new URL(req.url);
  const status = url.searchParams.get("status");
  const repo   = url.searchParams.get("repo");
  const limit  = parseInt(url.searchParams.get("limit") ?? "100");

  const db = createServiceClient();

  // Developers see only violations from their own PR scans
  let prAuthorFilter: string | null = null;
  if (role === "developer" && user_id) {
    const { data: member } = await db
      .from("org_members")
      .select("github_login")
      .eq("user_id", user_id)
      .single();
    prAuthorFilter = member?.github_login ?? null;
  }

  const dedupe = status === "open" || status === "in_review";

  // Filter violations through their parent scan's pr_author when scoped
  let query = db
    .from("violations")
    .select("*, scans!inner(repo_full_name, pr_number, commit_sha, pr_author)")
    .eq("org_id", org_id)
    .order("created_at", { ascending: false })
    .limit(limit);

  if (status && !dedupe) query = query.eq("status", status);
  if (repo)              query = query.eq("scans.repo_full_name", repo);
  if (prAuthorFilter)    query = query.eq("scans.pr_author", prAuthorFilter);

  const { data, error: qErr } = await query;
  if (qErr) return NextResponse.json({ error: qErr.message }, { status: 500 });

  let violations = data ?? [];

  // Dedupe by repo+file_path, keeping only the most recent scan's violation
  // (rows are already ordered created_at desc, so the first one seen per key
  // is the latest), then keep it only if it still matches the requested status.
  if (dedupe) {
    const latestByFile = new Map<string, typeof violations[number]>();
    violations.forEach(v => {
      const scans = v.scans as { repo_full_name?: string } | { repo_full_name?: string }[] | null;
      const scan  = Array.isArray(scans) ? scans[0] : scans;
      const key   = `${scan?.repo_full_name ?? ""}::${v.file_path}`;
      if (!latestByFile.has(key)) latestByFile.set(key, v);
    });
    violations = Array.from(latestByFile.values()).filter(v => v.status === status);
  }

  return NextResponse.json({ violations });
}

export async function PATCH(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const validation = await validateBody(req, ViolationUpdateSchema);
  if (!validation.ok) return validation.response;
  const body = validation.data;

  const db  = createServiceClient();
  const now = new Date().toISOString();

  const updates: Record<string, unknown> = { status: body.status };
  if (body.status === "resolved") {
    updates.resolved_at = now;
    updates.resolved_by = user_id ?? null;
  }
  if (body.assigned_email) updates.assigned_email = body.assigned_email;

  const { data, error: upErr } = await db
    .from("violations")
    .update(updates)
    .eq("id", body.id)
    .eq("org_id", org_id)
    .select("id, file_path, risk_score, scan_id")
    .single();

  if (upErr || !data) return NextResponse.json({ error: "update_failed" }, { status: 500 });

  // Append note if provided
  if (body.note) {
    const { data: current } = await db
      .from("violations")
      .select("notes")
      .eq("id", body.id)
      .single();

    const notes = (Array.isArray(current?.notes) ? current.notes : []) as unknown[];
    notes.push({ text: body.note, by: actor_email ?? "reviewer", at: now });
    await db.from("violations").update({ notes }).eq("id", body.id);
  }

  await writeAuditLog(db, {
    org_id,
    event_type:    "violation_resolved",
    actor_id:      user_id ?? null,
    actor_email:   actor_email ?? null,
    resource_type: "violation",
    resource_id:   body.id,
    payload: { status: body.status, file_path: data.file_path, risk_score: data.risk_score },
  });

  return NextResponse.json({ ok: true, violation: data });
}
