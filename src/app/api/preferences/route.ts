import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";

const DEFAULTS = {
  email_enabled:        true,
  slack_enabled:        true,
  in_app_enabled:       true,
  min_severity:         "P2",
  scan_completed:       false,
  violation_opened:     true,
  alert_fired:          true,
  attestation_reminder: true,
  weekly_digest:        true,
};

export async function GET(req: NextRequest) {
  const { org_id, user_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });
  if (!user_id) return NextResponse.json({ error: "user_required" }, { status: 400 });

  const db = createServiceClient();
  const { data } = await db
    .from("notification_preferences")
    .select("*")
    .eq("user_id", user_id)
    .eq("org_id", org_id)
    .single() as { data: Record<string, unknown> | null };

  return NextResponse.json({ preferences: data ?? { ...DEFAULTS, user_id, org_id } });
}

export async function PATCH(req: NextRequest) {
  const { org_id, user_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });
  if (!user_id) return NextResponse.json({ error: "user_required" }, { status: 400 });

  const body = await req.json() as Partial<typeof DEFAULTS>;

  const db = createServiceClient();
  await db
    .from("notification_preferences")
    .upsert({ user_id, org_id, ...body, updated_at: new Date().toISOString() },
      { onConflict: "user_id,org_id" });

  return NextResponse.json({ ok: true });
}
