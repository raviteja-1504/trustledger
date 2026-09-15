/**
 * Risk Register — real workflow-state persistence, replacing what was
 * previously localStorage-only state (`tl_risk_register`): status changes,
 * treatment, owner, notes, and manually-added risks are now visible to
 * every reviewer in the org and survive a device change, backed by the
 * (previously unused) `risk_register` table.
 *
 * GET    /api/risk-register/state                           → all rows for the org
 * POST   /api/risk-register/state                            → create a manually-added risk
 * PATCH  /api/risk-register/state { external_id, patch }      → update workflow fields
 * DELETE /api/risk-register/state { external_id }             → remove a manually-added risk
 *
 * Write methods require security_reviewer+ -- these are compliance-
 * consequential actions, same tier as attestation/violation resolution
 * elsewhere in the app. GET is readable by any authenticated org member.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";

interface RiskRow {
  external_id:          string | null;
  auto_derived:         boolean;
  title:                string;
  description:          string | null;
  category:             string;
  likelihood:           number;
  impact:               number;
  residual_likelihood:  number | null;
  residual_impact:      number | null;
  status:               string;
  treatment:            string;
  owner_email:          string | null;
  due_date:             string | null;
  mitigation:           string | null;
  related_cve:          string | null;
  related_link:         string | null;
  repo:                 string | null;
  notes:                string[];
  created_at:           string;
}

const SELECT_COLS = "external_id, auto_derived, title, description, category, likelihood, impact, residual_likelihood, residual_impact, status, treatment, owner_email, due_date, mitigation, related_cve, related_link, repo, notes, created_at";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const db = createServiceClient();
  const { data, error } = await db
    .from("risk_register")
    .select(SELECT_COLS)
    .eq("org_id", auth.org_id)
    .order("created_at", { ascending: false }) as { data: RiskRow[] | null; error: unknown };

  if (error) return safeError(error, { code: "risk_register_fetch_failed", message: "We couldn't load the risk register right now. Please try again." });

  return NextResponse.json({ risks: data ?? [] });
}

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "security_reviewer");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const body = await req.json() as {
    external_id:  string;
    title:        string;
    description?: string;
    category:     string;
    likelihood:   number;
    impact:       number;
    treatment?:   string;
    owner_email?: string;
    due_date?:    string;
    mitigation?:  string;
    related_cve?: string;
    related_link?: string;
  };

  if (!body.external_id || !body.title || !body.category) {
    return NextResponse.json({ error: "missing_fields" }, { status: 400 });
  }

  const db = createServiceClient();
  const { data, error } = await db
    .from("risk_register")
    .insert({
      org_id:       auth.org_id,
      external_id:  body.external_id,
      auto_derived: false,
      title:        body.title,
      description:  body.description ?? null,
      category:     body.category,
      likelihood:   body.likelihood,
      impact:       body.impact,
      treatment:    body.treatment ?? "mitigate",
      owner_id:     auth.user_id ?? null,
      owner_email:  body.owner_email ?? null,
      due_date:     body.due_date || null,
      mitigation:   body.mitigation ?? null,
      related_cve:  body.related_cve ?? null,
      related_link: body.related_link ?? null,
    })
    .select(SELECT_COLS)
    .single() as { data: RiskRow | null; error: unknown };

  if (error || !data) return safeError(error, { code: "risk_create_failed", message: "We couldn't add that risk. Please try again." });

  await writeAuditLog(db, {
    org_id: auth.org_id!, event_type: "risk_updated",
    actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "risk_register", resource_id: body.external_id,
    payload: { action: "created", title: data.title },
  });

  return NextResponse.json({ risk: data });
}

export async function PATCH(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "security_reviewer");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const body = await req.json() as {
    external_id: string;
    patch: {
      status?:               string;
      treatment?:            string;
      owner_email?:          string;
      due_date?:             string | null;
      mitigation?:           string;
      residual_likelihood?:  number;
      residual_impact?:      number;
      notes?:                string[];
    };
  };

  if (!body.external_id || !body.patch) return NextResponse.json({ error: "missing_fields" }, { status: 400 });

  const db = createServiceClient();
  const { data, error } = await db
    .from("risk_register")
    .update({ ...body.patch, updated_at: new Date().toISOString(), updated_by: auth.user_id ?? null })
    .eq("org_id", auth.org_id)
    .eq("external_id", body.external_id)
    .select(SELECT_COLS)
    .single() as { data: RiskRow | null; error: unknown };

  if (error || !data) return safeError(error, { code: "risk_update_failed", message: "We couldn't update that risk. Please try again." });

  await writeAuditLog(db, {
    org_id: auth.org_id!, event_type: "risk_updated",
    actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "risk_register", resource_id: body.external_id,
    payload: { action: "updated", title: data.title, patch: body.patch },
  });

  return NextResponse.json({ risk: data });
}

export async function DELETE(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "security_reviewer");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const body = await req.json() as { external_id: string };
  if (!body.external_id) return NextResponse.json({ error: "missing_external_id" }, { status: 400 });

  const db = createServiceClient();
  const { data, error } = await db
    .from("risk_register")
    .delete()
    .eq("org_id", auth.org_id)
    .eq("external_id", body.external_id)
    .eq("auto_derived", false) // only ever delete manually-added risks
    .select("id, title")
    .maybeSingle() as { data: { id: string; title: string } | null; error: unknown };

  if (error) return safeError(error, { code: "risk_delete_failed", message: "We couldn't remove that risk. Please try again." });

  if (data) {
    await writeAuditLog(db, {
      org_id: auth.org_id!, event_type: "risk_updated",
      actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
      resource_type: "risk_register", resource_id: body.external_id,
      payload: { action: "deleted", title: data.title },
    });
  }

  return NextResponse.json({ ok: true });
}
