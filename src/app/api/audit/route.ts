import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../_middleware";
import { verifyAuditChain } from "@/lib/audit";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  const { org_id, error } = auth;
  if (error) return NextResponse.json({ error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_view_audit_log");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });

  const url   = new URL(req.url);
  const limit = parseInt(url.searchParams.get("limit") ?? "100");
  const page  = parseInt(url.searchParams.get("page") ?? "0");

  const db = createServiceClient();
  const { data, count } = await db
    .from("audit_log")
    .select("*", { count: "exact" })
    .eq("org_id", org_id)
    .order("id", { ascending: false })
    .range(page * limit, page * limit + limit - 1);

  return NextResponse.json({ events: data ?? [], total: count ?? 0 });
}

/** Verify the audit log hash chain integrity */
export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  const { org_id, error } = auth;
  if (error) return NextResponse.json({ error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_view_audit_log");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });

  const db = createServiceClient();
  const result = await verifyAuditChain(db, org_id);

  return NextResponse.json(result);
}
