/**
 * Secret Findings API
 *
 * GET   /api/secrets                → list findings for the org (real DB read)
 * PATCH /api/secrets                → resolve/reopen a finding (real DB write)
 *
 * Previously the Secrets page had no server-backed read or write at all: it
 * re-derived "findings" client-side by re-fetching each repo's latest scan
 * and re-scanning file content for secret-shaped indicators, and stored
 * resolved/open status ONLY in localStorage. Since secret_findings rows are
 * already written at scan time (see api/scans/route.ts and scan-worker) with
 * a real status/resolved_by/resolved_at column set, none of that
 * re-derivation was necessary -- and the localStorage-only status is exactly
 * why resolving a secret on one device never showed up on another: the
 * "resolved" flag never left that one browser's storage.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { validateBody, SecretUpdateSchema } from "@/lib/validation";
import { safeError } from "@/lib/errors";

interface ScanJoin { repo_full_name: string; pr_number: number; pr_author: string | null }

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const { org_id, role, user_id } = auth;

  const url    = new URL(req.url);
  const status = url.searchParams.get("status"); // "open" | "resolved" | null (all)
  const limit  = Math.min(parseInt(url.searchParams.get("limit") ?? "500"), 1000);

  const db = createServiceClient();

  // Developers see only secrets from their own PRs, same scoping as violations.
  let prAuthorFilter: string | null = null;
  if (role === "developer" && user_id) {
    const { data: member } = await db
      .from("org_members")
      .select("github_login")
      .eq("user_id", user_id)
      .single();
    prAuthorFilter = member?.github_login ?? null;
  }

  let query = db
    .from("secret_findings")
    .select("id, scan_id, file_path, secret_type, severity, label, masked_value, line_number, status, resolved_by, resolved_email, resolved_at, created_at, scans!inner(repo_full_name, pr_number, pr_author)")
    .eq("org_id", org_id)
    .order("created_at", { ascending: false })
    .limit(limit);

  if (status)         query = query.eq("status", status);
  if (prAuthorFilter) query = query.eq("scans.pr_author", prAuthorFilter);

  const { data, error } = await query;
  if (error) return safeError(error, { code: "secrets_fetch_failed", message: "We couldn't load secrets right now. Please try again." });

  const findings = (data ?? []).map(f => {
    const scanRaw = f.scans as unknown as ScanJoin | ScanJoin[] | null;
    const scan    = Array.isArray(scanRaw) ? scanRaw[0] : scanRaw;
    return {
      id:            f.id,
      severity:      f.severity,
      type:          f.secret_type,
      label:         f.label,
      file_path:     f.file_path,
      repo:          scan?.repo_full_name ?? "",
      pr_number:     scan?.pr_number ?? 0,
      line_number:   f.line_number,
      masked_value:  f.masked_value,
      scan_id:       f.scan_id,
      detected_at:   f.created_at,
      status:        f.status,
      resolved_by:   f.resolved_email ?? undefined,
      resolved_at:   f.resolved_at ?? undefined,
    };
  });

  return NextResponse.json({ findings });
}

export async function PATCH(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const validation = await validateBody(req, SecretUpdateSchema);
  if (!validation.ok) return validation.response;
  const body = validation.data;

  const db  = createServiceClient();
  const now = new Date().toISOString();

  const updates: Record<string, unknown> = body.status === "resolved"
    ? { status: "resolved", resolved_at: now, resolved_by: user_id ?? null, resolved_email: actor_email ?? null }
    : { status: "open", resolved_at: null, resolved_by: null, resolved_email: null };

  const { data, error: upErr } = await db
    .from("secret_findings")
    .update(updates)
    .eq("id", body.id)
    .eq("org_id", org_id)
    .select("id, file_path, severity")
    .single();

  if (upErr || !data) {
    return safeError(upErr, { code: "secret_update_failed", message: "We couldn't update that finding. Please try again." });
  }

  if (body.status === "resolved") {
    await writeAuditLog(db, {
      org_id,
      event_type:    "secret_resolved",
      actor_id:      user_id ?? null,
      actor_email:   actor_email ?? null,
      resource_type: "secret_finding",
      resource_id:   body.id,
      payload: { file_path: data.file_path, severity: data.severity },
    });
  }

  return NextResponse.json({ ok: true, finding: data });
}
