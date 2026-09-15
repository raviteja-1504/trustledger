/**
 * Compliance Exception Register — real persistence for the Compliance
 * page's Exceptions tab, replacing what was previously localStorage-only
 * state (invisible to other reviewers, lost on a new device, no audit
 * trail). Backed by the existing `compliance_exceptions` table.
 *
 * GET   /api/compliance-exceptions                → list all exceptions for the org
 * POST  /api/compliance-exceptions                 → log a new exception
 * PATCH /api/compliance-exceptions { id, status }  → update an exception's status
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";

interface ExceptionRow {
  id:             string;
  control_id:     string;
  framework_id:   string;
  title:          string;
  description:    string | null;
  risk_accepted:  boolean;
  owner_email:    string | null;
  due_date:       string | null;
  remediation:    string | null;
  status:         string;
  created_at:     string;
}

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const db = createServiceClient();
  const { data, error } = await db
    .from("compliance_exceptions")
    .select("id, control_id, framework_id, title, description, risk_accepted, owner_email, due_date, remediation, status, created_at")
    .eq("org_id", auth.org_id)
    .order("created_at", { ascending: false }) as { data: ExceptionRow[] | null; error: unknown };

  if (error) return safeError(error, { code: "exceptions_fetch_failed", message: "We couldn't load exceptions right now. Please try again." });

  return NextResponse.json({ exceptions: data ?? [] });
}

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "security_reviewer");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const body = await req.json() as {
    control_id:    string;
    framework_id:  string;
    title:         string;
    description?:  string;
    risk_accepted?: boolean;
    owner_email?:  string;
    due_date?:     string;
    remediation?:  string;
  };

  if (!body.title || !body.control_id || !body.framework_id) {
    return NextResponse.json({ error: "missing_fields" }, { status: 400 });
  }

  const db = createServiceClient();
  const { data, error } = await db
    .from("compliance_exceptions")
    .insert({
      org_id:        auth.org_id,
      framework_id:  body.framework_id,
      control_id:    body.control_id,
      title:         body.title,
      description:   body.description ?? null,
      risk_accepted: body.risk_accepted ?? false,
      owner_id:      auth.user_id ?? null,
      owner_email:   body.owner_email ?? auth.actor_email ?? null,
      due_date:      body.due_date || null,
      remediation:   body.remediation ?? null,
      status:        "open",
    })
    .select("id, control_id, framework_id, title, description, risk_accepted, owner_email, due_date, remediation, status, created_at")
    .single() as { data: ExceptionRow | null; error: unknown };

  if (error || !data) return safeError(error, { code: "exception_create_failed", message: "We couldn't log that exception. Please try again." });

  await writeAuditLog(db, {
    org_id: auth.org_id!, event_type: "exception_created",
    actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "compliance_exception", resource_id: data.id,
    payload: { title: data.title, framework_id: data.framework_id, control_id: data.control_id },
  });

  return NextResponse.json({ exception: data });
}

export async function PATCH(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "security_reviewer");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const body = await req.json() as { id: string; status: string };
  if (!body.id || !body.status) return NextResponse.json({ error: "missing_fields" }, { status: 400 });

  const db = createServiceClient();
  const { data, error } = await db
    .from("compliance_exceptions")
    .update({ status: body.status })
    .eq("id", body.id)
    .eq("org_id", auth.org_id)
    .select("id, title, framework_id, control_id, status")
    .single() as { data: { id: string; title: string; framework_id: string; control_id: string; status: string } | null; error: unknown };

  if (error || !data) return safeError(error, { code: "exception_update_failed", message: "We couldn't update that exception. Please try again." });

  await writeAuditLog(db, {
    org_id: auth.org_id!, event_type: "exception_resolved",
    actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "compliance_exception", resource_id: data.id,
    payload: { title: data.title, framework_id: data.framework_id, control_id: data.control_id, status: data.status },
  });

  return NextResponse.json({ exception: data });
}
